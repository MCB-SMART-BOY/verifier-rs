// SPDX-License-Identifier: GPL-2.0

//! Verifier state management
//! 验证器状态管理
//!
//! This module implements the overall verification state, including
//! function frames, register states, and tracking of verification progress.
//! 本模块实现整体验证状态，包括函数帧、寄存器状态以及验证进度跟踪。

use alloc::{boxed::Box, format, vec::Vec};
use core::mem::MaybeUninit;

use crate::core::error::{Result, VerifierError};
use crate::core::types::*;
use crate::state::lock_state::LockState;
use crate::state::reference::ReferenceManager;
use crate::state::reg_state::BpfRegState;
use crate::state::stack_state::StackManager;

/// State of a single function frame
/// 单个函数帧的状态
///
/// Each function call in BPF creates a new frame with its own registers
/// and stack space. Frames are organized in a call chain.
/// BPF 中的每个函数调用都会创建一个新帧，拥有自己的寄存器和栈空间。
/// 帧按调用链组织。
#[derive(Debug)]
pub struct BpfFuncState {
    /// Register states
    /// 寄存器状态
    pub regs: [BpfRegState; MAX_BPF_REG],
    /// Stack state
    /// 栈状态
    pub stack: StackManager,
    /// Call site instruction index (-1 for main)
    /// 调用点指令索引（主函数为 -1）
    pub callsite: i32,
    /// Frame number in call chain
    /// 调用链中的帧编号
    pub frameno: u32,
    /// Subprogram number
    /// 子程序编号
    pub subprogno: u32,
    /// Expected callback return value range
    /// 预期的回调返回值范围
    pub callback_ret_range: BpfRetvalRange,
}

impl Default for BpfFuncState {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

impl BpfFuncState {
    /// Create a new function state
    /// 创建新的函数状态
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
    /// 直接在堆上创建新的函数状态
    ///
    /// This avoids creating a large temporary on the stack before boxing.
    /// 这避免了在装箱前在栈上创建大型临时对象。
    pub fn new_boxed(callsite: i32, frameno: u32, subprogno: u32) -> Box<Self> {
        let mut uninit: Box<MaybeUninit<Self>> = Box::new_uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: We're writing to allocated but uninitialized memory,
        // and we initialize all fields before assuming_init()
        // 安全性：我们写入已分配但未初始化的内存，
        // 在调用 assume_init() 前初始化所有字段
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
    /// 初始化函数入口的寄存器状态
    fn init_regs(&mut self) {
        for (i, reg) in self.regs.iter_mut().enumerate() {
            reg.mark_not_init(false);
            reg.subreg_def = 0;

            // R10 (FP) is special - it's the frame pointer
            // R10 (FP) 是特殊的 - 它是帧指针
            if i == BPF_REG_FP {
                reg.mark_known_zero();
                reg.reg_type = BpfRegType::PtrToStack;
                reg.frameno = self.frameno;
            }
        }
    }

    /// Get a register state by index
    /// 通过索引获取寄存器状态
    pub fn reg(&self, regno: usize) -> Option<&BpfRegState> {
        self.regs.get(regno)
    }

    /// Get a mutable register state by index
    /// 通过索引获取可变寄存器状态
    pub fn reg_mut(&mut self, regno: usize) -> Option<&mut BpfRegState> {
        self.regs.get_mut(regno)
    }

    /// Copy state from another function state
    /// 从另一个函数状态复制
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
    /// 克隆到新的堆分配
    pub fn clone_boxed(&self) -> Box<Self> {
        let mut uninit: Box<MaybeUninit<Self>> = Box::new_uninit();
        let ptr = uninit.as_mut_ptr();

        // SAFETY: Writing to allocated but uninitialized memory. All fields
        // are initialized exactly once via ptr::write before assume_init().
        // The memory layout is guaranteed by Box<MaybeUninit<Self>>.
        // 安全性：写入已分配但未初始化的内存。在 assume_init() 前
        // 通过 ptr::write 恰好初始化所有字段一次。
        // 内存布局由 Box<MaybeUninit<Self>> 保证。
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
/// 跳转历史条目，用于跟踪程序中的路径
///
/// Used to reconstruct the execution path for error messages and debugging.
/// 用于为错误消息和调试重建执行路径。
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfJmpHistoryEntry {
    /// Instruction index
    /// 指令索引
    pub idx: u32,
    /// Previous instruction index
    /// 前一条指令索引
    pub prev_idx: u32,
    /// Flags
    /// 标志
    pub flags: u32,
}

/// Main verifier state
/// 主验证器状态
///
/// This is the central state structure used during verification.
/// It tracks all verification-relevant information including registers,
/// stack, references, locks, and exploration progress.
/// 这是验证期间使用的核心状态结构。
/// 它跟踪所有与验证相关的信息，包括寄存器、栈、引用、锁和探索进度。
#[derive(Debug)]
pub struct BpfVerifierState {
    /// Function call frames (stack of frames)
    /// 函数调用帧（帧栈）
    pub frame: Vec<Option<Box<BpfFuncState>>>,
    /// Current frame index
    /// 当前帧索引
    pub curframe: usize,
    /// Reference tracking
    /// 引用跟踪
    pub refs: ReferenceManager,
    /// Spin lock state tracking
    /// 自旋锁状态跟踪
    pub lock_state: LockState,
    /// Whether this is a speculative state
    /// 是否为推测性状态
    pub speculative: bool,
    /// Whether in sleepable context
    /// 是否在可睡眠上下文中
    pub in_sleepable: bool,
    /// Jump history for this state
    /// 此状态的跳转历史
    pub jmp_history: Vec<BpfJmpHistoryEntry>,
    /// Number of branches to explore from this state
    /// 从此状态需要探索的分支数
    pub branches: u32,
    /// Current instruction index
    /// 当前指令索引
    pub insn_idx: usize,
    /// First instruction index in this state
    /// 此状态中的第一条指令索引
    pub first_insn_idx: usize,
    /// Last instruction index processed
    /// 已处理的最后一条指令索引
    pub last_insn_idx: usize,
    /// DFS depth for exploration
    /// 探索的 DFS 深度
    pub dfs_depth: u32,
    /// Callback unroll depth
    /// 回调展开深度
    pub callback_unroll_depth: u32,
    /// May-goto depth
    /// may_goto 深度
    pub may_goto_depth: u32,
    /// Parent state (for state exploration tree)
    /// 父状态（用于状态探索树）
    pub parent_idx: Option<usize>,
    /// Whether this state has been cleaned (precision propagated)
    /// 此状态是否已清理（精度已传播）
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
    /// 创建新的验证器状态
    pub fn new() -> Self {
        let mut frames = Vec::with_capacity(MAX_BPF_STACK_FRAMES);
        // Initialize with main function frame (frame 0)
        // 用主函数帧初始化（帧 0）
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
    /// 直接在堆上创建新的验证器状态
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
    /// 将此状态克隆到新的堆分配
    pub fn clone_boxed(&self) -> Box<Self> {
        Box::new(self.clone())
    }

    /// Get the current function state
    /// 获取当前函数状态
    pub fn cur_func(&self) -> Option<&BpfFuncState> {
        self.frame
            .get(self.curframe)
            .and_then(|f| f.as_ref().map(|b| b.as_ref()))
    }

    /// Get the current function state mutably
    /// 获取当前函数状态的可变引用
    pub fn cur_func_mut(&mut self) -> Option<&mut BpfFuncState> {
        self.frame
            .get_mut(self.curframe)
            .and_then(|f| f.as_mut().map(|b| b.as_mut()))
    }

    /// Get a function state by frame number
    /// 通过帧编号获取函数状态
    pub fn func(&self, frameno: usize) -> Option<&BpfFuncState> {
        self.frame
            .get(frameno)
            .and_then(|f| f.as_ref().map(|b| b.as_ref()))
    }

    /// Get a register from the current frame
    /// 从当前帧获取寄存器
    pub fn reg(&self, regno: usize) -> Option<&BpfRegState> {
        self.cur_func().and_then(|f| f.reg(regno))
    }

    /// Get a mutable register from the current frame
    /// 从当前帧获取可变寄存器
    pub fn reg_mut(&mut self, regno: usize) -> Option<&mut BpfRegState> {
        self.cur_func_mut().and_then(|f| f.reg_mut(regno))
    }

    /// Push a new function frame (for calls)
    /// 压入新的函数帧（用于函数调用）
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
    /// 弹出函数帧（用于函数返回）
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
    /// 从另一个验证器状态复制
    pub fn copy_from(&mut self, other: &BpfVerifierState) -> Result<()> {
        // Copy all active frames
        // 复制所有活动帧
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

        // Clear inactive frames
        // 清除非活动帧
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
    /// 检查是否在 RCU 读侧临界区
    pub fn in_rcu_cs(&self) -> bool {
        self.refs.in_rcu()
    }

    /// Push jump history entry
    /// 压入跳转历史条目
    pub fn push_jmp_history(&mut self, idx: u32, prev_idx: u32, flags: u32) {
        self.jmp_history.push(BpfJmpHistoryEntry {
            idx,
            prev_idx,
            flags,
        });
    }

    /// Clear jump history
    /// 清除跳转历史
    pub fn clear_jmp_history(&mut self) {
        self.jmp_history.clear();
    }

    /// Get the previous instruction index from history
    /// 从历史中获取前一条指令索引
    pub fn get_prev_insn_idx(&self, insn_idx: usize) -> Option<usize> {
        if insn_idx == 0 {
            return None;
        }

        // Search history in reverse for this instruction
        // 反向搜索此指令的历史
        for entry in self.jmp_history.iter().rev() {
            if entry.idx as usize == insn_idx {
                return Some(entry.prev_idx as usize);
            }
        }

        // If not in history, assume sequential execution
        // 如果不在历史中，假设顺序执行
        Some(insn_idx - 1)
    }

    /// Mark caller-saved registers as unknown after a call
    /// 在调用后将调用者保存的寄存器标记为未知
    pub fn clear_caller_saved_regs(&mut self) {
        if let Some(func) = self.cur_func_mut() {
            for &regno in &CALLER_SAVED {
                func.regs[regno].mark_not_init(false);
            }
        }
    }

    /// Check for resource leaks at exit
    /// 在退出时检查资源泄漏
    pub fn check_resource_leak(&self) -> Result<()> {
        self.refs.check_all_released()
    }

    /// Invalidate non-owning references
    /// 使非拥有引用失效
    pub fn invalidate_non_owning_refs(&mut self) {
        self.refs.invalidate_non_owning_refs();
    }
}

/// Stack element for DFS exploration
/// DFS 探索的栈元素
///
/// Used to implement the verifier's depth-first state exploration.
/// 用于实现验证器的深度优先状态探索。
#[derive(Debug)]
pub struct BpfVerifierStackElem {
    /// Verifier state at this point
    /// 此时刻的验证器状态
    pub st: BpfVerifierState,
    /// Instruction index to process
    /// 要处理的指令索引
    pub insn_idx: usize,
    /// Previous instruction index
    /// 前一条指令索引
    pub prev_insn_idx: usize,
    /// Log position at push time
    /// 压入时的日志位置
    pub log_pos: usize,
}

impl BpfVerifierStackElem {
    /// Create a new stack element
    /// 创建新的栈元素
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
/// 验证器探索栈
///
/// Manages the stack of states to explore during verification.
/// 管理验证期间要探索的状态栈。
#[derive(Debug, Default)]
pub struct ExplorationStack {
    stack: Vec<BpfVerifierStackElem>,
}

impl ExplorationStack {
    /// Create a new exploration stack
    /// 创建新的探索栈
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Push a new state onto the stack
    /// 将新状态压入栈
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
    /// 从栈中弹出状态
    pub fn pop(&mut self) -> Option<BpfVerifierStackElem> {
        self.stack.pop()
    }

    /// Get the current stack size
    /// 获取当前栈大小
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Check if stack is empty
    /// 检查栈是否为空
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

/// State list for explored states at an instruction
/// 指令处已探索状态的列表
///
/// Used for state pruning - if we've seen an equivalent state before,
/// we don't need to explore it again.
/// 用于状态剪枝 - 如果我们之前见过等效状态，就不需要再次探索。
#[derive(Debug, Clone)]
pub struct BpfVerifierStateList {
    /// The state
    /// 状态
    pub state: BpfVerifierState,
    /// Whether this state is in the free list
    /// 此状态是否在空闲列表中
    pub in_free_list: bool,
}

impl BpfVerifierStateList {
    /// Create a new state list entry
    /// 创建新的状态列表条目
    pub fn new(state: BpfVerifierState) -> Self {
        Self {
            state,
            in_free_list: false,
        }
    }
}
