// SPDX-License-Identifier: GPL-2.0

//! Verifier state management
//!
//! This module implements the overall verification state, including
//! function frames, register states, and tracking of verification progress.

use alloc::{boxed::Box, format, vec::Vec};
use core::mem::MaybeUninit;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::lock_state::LockState;
use crate::state::reference::ReferenceManager;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::StackManager;

/// State of a single function frame
#[derive(Debug)]
pub struct BpfFuncState {
    /// Register states
    pub regs: [BpfRegState; MAX_BPF_REG],
    /// Stack state
    pub stack: StackManager,
    /// Call site instruction index (-1 for main)
    pub callsite: i32,
    /// Frame number in call chain
    pub frameno: u32,
    /// Subprogram number
    pub subprogno: u32,
    /// Expected callback return value range
    pub callback_ret_range: BpfRetvalRange,
}

impl Default for BpfFuncState {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl BpfFuncState {
    /// Create a new function state
    pub fn new(callsite: i32, frameno: u32, subprogno: u32) -> Self {
        let mut state = Self {
            regs: Default::default(),
            stack: StackManager::new(),
            callsite,
            frameno,
            subprogno,
            callback_ret_range: BpfRetvalRange::new(0, 0),
        };
        state.init_regs();
        state
    }

    /// Create a new function state directly on the heap
    ///
    /// This avoids creating a large temporary on the stack before boxing.
    pub fn new_boxed(callsite: i32, frameno: u32, subprogno: u32) -> Box<Self> {
        let mut uninit: Box<MaybeUninit<Self>> = Box::new_uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: We're writing to allocated but uninitialized memory,
        // and we initialize all fields before assuming_init()
        unsafe {
            let regs_ptr = core::ptr::addr_of_mut!((*ptr).regs);
            for i in 0..MAX_BPF_REG {
                core::ptr::write((*regs_ptr).as_mut_ptr().add(i), BpfRegState::new_not_init());
            }

            core::ptr::write(core::ptr::addr_of_mut!((*ptr).stack), StackManager::new());
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).callsite), callsite);
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).frameno), frameno);
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).subprogno), subprogno);
            core::ptr::write(
                core::ptr::addr_of_mut!((*ptr).callback_ret_range),
                BpfRetvalRange::new(0, 0),
            );

            let mut boxed = uninit.assume_init();
            boxed.init_regs();
            boxed
        }
    }

    /// Initialize register state for function entry
    fn init_regs(&mut self) {
        for (i, reg) in self.regs.iter_mut().enumerate() {
            reg.mark_not_init(false);
            reg.subreg_def = 0;

            if i == BPF_REG_FP {
                reg.mark_known_zero();
                reg.reg_type = BpfRegType::PtrToStack;
                reg.frameno = self.frameno;
            }
        }
    }

    /// Get a register state by index
    pub fn reg(&self, regno: usize) -> Option<&BpfRegState> {
        self.regs.get(regno)
    }

    /// Get a mutable register state by index
    pub fn reg_mut(&mut self, regno: usize) -> Option<&mut BpfRegState> {
        self.regs.get_mut(regno)
    }

    /// Copy state from another function state
    pub fn copy_from(&mut self, other: &BpfFuncState) -> Result<()> {
        self.regs = other.regs.clone();
        self.stack = other.stack.clone();
        self.callsite = other.callsite;
        self.frameno = other.frameno;
        self.subprogno = other.subprogno;
        self.callback_ret_range = other.callback_ret_range;
        Ok(())
    }

    /// Clone into a new boxed allocation
    pub fn clone_boxed(&self) -> Box<Self> {
        let mut uninit: Box<MaybeUninit<Self>> = Box::new_uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: Writing to allocated but uninitialized memory. All fields
        // are initialized exactly once via ptr::write before assume_init().
        // The memory layout is guaranteed by Box<MaybeUninit<Self>>.
        unsafe {
            let regs_ptr = core::ptr::addr_of_mut!((*ptr).regs);
            for i in 0..MAX_BPF_REG {
                core::ptr::write((*regs_ptr).as_mut_ptr().add(i), self.regs[i].clone());
            }

            core::ptr::write(core::ptr::addr_of_mut!((*ptr).stack), self.stack.clone());
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).callsite), self.callsite);
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).frameno), self.frameno);
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).subprogno), self.subprogno);
            core::ptr::write(
                core::ptr::addr_of_mut!((*ptr).callback_ret_range),
                self.callback_ret_range,
            );

            uninit.assume_init()
        }
    }
}

impl Clone for BpfFuncState {
    fn clone(&self) -> Self {
        Self {
            regs: self.regs.clone(),
            stack: self.stack.clone(),
            callsite: self.callsite,
            frameno: self.frameno,
            subprogno: self.subprogno,
            callback_ret_range: self.callback_ret_range,
        }
    }
}

/// Jump history entry for tracking path through the program
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfJmpHistoryEntry {
    /// Instruction index
    pub idx: u32,
    /// Previous instruction index
    pub prev_idx: u32,
    /// Flags
    pub flags: u32,
}

/// Main verifier state
#[derive(Debug)]
pub struct BpfVerifierState {
    /// Function call frames (stack of frames)
    pub frame: Vec<Option<Box<BpfFuncState>>>,
    /// Current frame index
    pub curframe: usize,
    /// Reference tracking
    pub refs: ReferenceManager,
    /// Spin lock state tracking
    pub lock_state: LockState,
    /// Whether this is a speculative state
    pub speculative: bool,
    /// Whether in sleepable context
    pub in_sleepable: bool,
    /// Jump history for this state
    pub jmp_history: Vec<BpfJmpHistoryEntry>,
    /// Number of branches to explore from this state
    pub branches: u32,
    /// Current instruction index
    pub insn_idx: usize,
    /// First instruction index in this state
    pub first_insn_idx: usize,
    /// Last instruction index processed
    pub last_insn_idx: usize,
    /// DFS depth for exploration
    pub dfs_depth: u32,
    /// Callback unroll depth
    pub callback_unroll_depth: u32,
    /// May-goto depth
    pub may_goto_depth: u32,
    /// Parent state (for state exploration tree)
    pub parent_idx: Option<usize>,
    /// Whether this state has been cleaned (precision propagated)
    pub cleaned: bool,
}

impl Default for BpfVerifierState {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for BpfVerifierState {
    fn clone(&self) -> Self {
        let mut frames = Vec::with_capacity(MAX_BPF_STACK_FRAMES);
        for frame_opt in &self.frame {
            frames.push(frame_opt.as_ref().map(|f| f.clone_boxed()));
        }

        Self {
            frame: frames,
            curframe: self.curframe,
            refs: self.refs.clone(),
            lock_state: self.lock_state.clone(),
            speculative: self.speculative,
            in_sleepable: self.in_sleepable,
            jmp_history: self.jmp_history.clone(),
            branches: self.branches,
            insn_idx: self.insn_idx,
            first_insn_idx: self.first_insn_idx,
            last_insn_idx: self.last_insn_idx,
            dfs_depth: self.dfs_depth,
            callback_unroll_depth: self.callback_unroll_depth,
            may_goto_depth: self.may_goto_depth,
            parent_idx: self.parent_idx,
            cleaned: self.cleaned,
        }
    }
}

impl BpfVerifierState {
    /// Create a new verifier state
    pub fn new() -> Self {
        let mut frames = Vec::with_capacity(MAX_BPF_STACK_FRAMES);
        frames.push(Some(BpfFuncState::new_boxed(-1, 0, 0)));
        for _ in 1..MAX_BPF_STACK_FRAMES {
            frames.push(None);
        }

        Self {
            frame: frames,
            curframe: 0,
            refs: ReferenceManager::new(),
            lock_state: LockState::new(),
            speculative: false,
            in_sleepable: false,
            jmp_history: Vec::new(),
            branches: 1,
            insn_idx: 0,
            first_insn_idx: 0,
            last_insn_idx: 0,
            dfs_depth: 0,
            callback_unroll_depth: 0,
            may_goto_depth: 0,
            parent_idx: None,
            cleaned: false,
        }
    }

    /// Create a new verifier state directly on the heap
    pub fn new_boxed() -> Box<Self> {
        let mut frames = Vec::with_capacity(MAX_BPF_STACK_FRAMES);
        frames.push(Some(BpfFuncState::new_boxed(-1, 0, 0)));
        for _ in 1..MAX_BPF_STACK_FRAMES {
            frames.push(None);
        }

        Box::new(Self {
            frame: frames,
            curframe: 0,
            refs: ReferenceManager::new(),
            lock_state: LockState::new(),
            speculative: false,
            in_sleepable: false,
            jmp_history: Vec::new(),
            branches: 1,
            insn_idx: 0,
            first_insn_idx: 0,
            last_insn_idx: 0,
            dfs_depth: 0,
            callback_unroll_depth: 0,
            may_goto_depth: 0,
            parent_idx: None,
            cleaned: false,
        })
    }

    /// Clone this state into a new boxed allocation
    pub fn clone_boxed(&self) -> Box<Self> {
        Box::new(self.clone())
    }

    /// Get the current function state
    pub fn cur_func(&self) -> Option<&BpfFuncState> {
        self.frame
            .get(self.curframe)
            .and_then(|f| f.as_ref().map(|b| b.as_ref()))
    }

    /// Get the current function state mutably
    pub fn cur_func_mut(&mut self) -> Option<&mut BpfFuncState> {
        self.frame
            .get_mut(self.curframe)
            .and_then(|f| f.as_mut().map(|b| b.as_mut()))
    }

    /// Get a function state by frame number
    pub fn func(&self, frameno: usize) -> Option<&BpfFuncState> {
        self.frame
            .get(frameno)
            .and_then(|f| f.as_ref().map(|b| b.as_ref()))
    }

    /// Get a register from the current frame
    pub fn reg(&self, regno: usize) -> Option<&BpfRegState> {
        self.cur_func().and_then(|f| f.reg(regno))
    }

    /// Get a mutable register from the current frame
    pub fn reg_mut(&mut self, regno: usize) -> Option<&mut BpfRegState> {
        self.cur_func_mut().and_then(|f| f.reg_mut(regno))
    }

    /// Push a new function frame (for calls)
    pub fn push_frame(&mut self, callsite: i32, subprogno: u32) -> Result<()> {
        if self.curframe + 1 >= MAX_BPF_STACK_FRAMES {
            return Err(VerifierError::TooComplex(
                "function call stack too deep".into(),
            ));
        }

        self.curframe += 1;
        let frameno = self.curframe as u32;
        self.frame[self.curframe] = Some(BpfFuncState::new_boxed(callsite, frameno, subprogno));
        Ok(())
    }

    /// Pop a function frame (for returns)
    pub fn pop_frame(&mut self) -> Result<()> {
        if self.curframe == 0 {
            return Err(VerifierError::Internal(
                "cannot pop main function frame".into(),
            ));
        }

        self.frame[self.curframe] = None;
        self.curframe -= 1;
        Ok(())
    }

    /// Copy state from another verifier state
    pub fn copy_from(&mut self, other: &BpfVerifierState) -> Result<()> {
        for i in 0..=other.curframe {
            if let Some(ref other_frame) = other.frame[i] {
                if self.frame[i].is_none() {
                    self.frame[i] = Some(BpfFuncState::new_boxed(0, 0, 0));
                }
                if let Some(ref mut self_frame) = self.frame[i] {
                    self_frame.copy_from(other_frame)?;
                }
            }
        }

        for i in (other.curframe + 1)..MAX_BPF_STACK_FRAMES {
            self.frame[i] = None;
        }

        self.curframe = other.curframe;
        self.refs.copy_from(&other.refs);
        self.speculative = other.speculative;
        self.in_sleepable = other.in_sleepable;
        self.jmp_history = other.jmp_history.clone();
        self.branches = other.branches;
        self.insn_idx = other.insn_idx;
        self.first_insn_idx = other.first_insn_idx;
        self.last_insn_idx = other.last_insn_idx;
        self.dfs_depth = other.dfs_depth;
        self.callback_unroll_depth = other.callback_unroll_depth;
        self.may_goto_depth = other.may_goto_depth;
        self.parent_idx = other.parent_idx;
        self.cleaned = other.cleaned;

        Ok(())
    }

    /// Check if in RCU read-side critical section
    pub fn in_rcu_cs(&self) -> bool {
        self.refs.in_rcu()
    }

    /// Push jump history entry
    pub fn push_jmp_history(&mut self, idx: u32, prev_idx: u32, flags: u32) {
        self.jmp_history.push(BpfJmpHistoryEntry {
            idx,
            prev_idx,
            flags,
        });
    }

    /// Clear jump history
    pub fn clear_jmp_history(&mut self) {
        self.jmp_history.clear();
    }

    /// Get the previous instruction index from history
    pub fn get_prev_insn_idx(&self, insn_idx: usize) -> Option<usize> {
        if insn_idx == 0 {
            return None;
        }

        for entry in self.jmp_history.iter().rev() {
            if entry.idx as usize == insn_idx {
                return Some(entry.prev_idx as usize);
            }
        }

        Some(insn_idx - 1)
    }

    /// Mark caller-saved registers as unknown after a call
    pub fn clear_caller_saved_regs(&mut self) {
        if let Some(func) = self.cur_func_mut() {
            for &regno in &CALLER_SAVED {
                func.regs[regno].mark_not_init(false);
            }
        }
    }

    /// Check for resource leaks at exit
    pub fn check_resource_leak(&self) -> Result<()> {
        self.refs.check_all_released()
    }

    /// Invalidate non-owning references
    pub fn invalidate_non_owning_refs(&mut self) {
        self.refs.invalidate_non_owning_refs();
    }
}

/// Stack element for DFS exploration
#[derive(Debug)]
pub struct BpfVerifierStackElem {
    /// Verifier state at this point
    pub st: BpfVerifierState,
    /// Instruction index to process
    pub insn_idx: usize,
    /// Previous instruction index
    pub prev_insn_idx: usize,
    /// Log position at push time
    pub log_pos: usize,
}

impl BpfVerifierStackElem {
    /// Create a new stack element
    pub fn new(st: BpfVerifierState, insn_idx: usize, prev_insn_idx: usize) -> Self {
        Self {
            st,
            insn_idx,
            prev_insn_idx,
            log_pos: 0,
        }
    }
}

/// Verifier exploration stack
#[derive(Debug, Default)]
pub struct ExplorationStack {
    stack: Vec<BpfVerifierStackElem>,
}

impl ExplorationStack {
    /// Create a new exploration stack
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Push a new state onto the stack
    pub fn push(&mut self, elem: BpfVerifierStackElem) -> Result<()> {
        if self.stack.len() >= BPF_COMPLEXITY_LIMIT_JMP_SEQ {
            return Err(VerifierError::TooComplex(format!(
                "jump sequence of {} is too complex",
                self.stack.len()
            )));
        }
        self.stack.push(elem);
        Ok(())
    }

    /// Pop a state from the stack
    pub fn pop(&mut self) -> Option<BpfVerifierStackElem> {
        self.stack.pop()
    }

    /// Get the current stack size
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Check if stack is empty
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

/// State list for explored states at an instruction
#[derive(Debug, Clone)]
pub struct BpfVerifierStateList {
    /// The state
    pub state: BpfVerifierState,
    /// Whether this state is in the free list
    pub in_free_list: bool,
}

impl BpfVerifierStateList {
    /// Create a new state list entry
    pub fn new(state: BpfVerifierState) -> Self {
        Self {
            state,
            in_free_list: false,
        }
    }
}
