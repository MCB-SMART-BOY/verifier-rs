// SPDX-License-Identifier: GPL-2.0

//! Core BPF types and constants
//!
//! This module defines the fundamental types used throughout the BPF verifier,
//! including register types, pointer types, and various flags.

use bitflags::bitflags;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of BPF registers
pub const MAX_BPF_REG: usize = 11;

/// Frame pointer register
pub const BPF_REG_FP: usize = 10;

/// Return value register
pub const BPF_REG_0: usize = 0;

/// First argument register
pub const BPF_REG_1: usize = 1;
/// Second argument register
pub const BPF_REG_2: usize = 2;
/// Third argument register
pub const BPF_REG_3: usize = 3;
/// Fourth argument register
pub const BPF_REG_4: usize = 4;
/// Fifth argument register
pub const BPF_REG_5: usize = 5;

/// Callee-saved register 6
pub const BPF_REG_6: usize = 6;
/// Callee-saved register 7
pub const BPF_REG_7: usize = 7;
/// Callee-saved register 8
pub const BPF_REG_8: usize = 8;
/// Callee-saved register 9
pub const BPF_REG_9: usize = 9;

/// Size of a BPF register in bytes
pub const BPF_REG_SIZE: usize = 8;

/// Maximum number of stack frames
pub const MAX_BPF_STACK_FRAMES: usize = 8;

/// Maximum BPF stack size per frame
pub const MAX_BPF_STACK: usize = 512;

/// Maximum number of instructions
pub const BPF_MAX_INSNS: usize = 1_000_000;

/// Complexity limit for jump sequences
pub const BPF_COMPLEXITY_LIMIT_JMP_SEQ: usize = 8192;

/// Complexity limit for verification states
pub const BPF_COMPLEXITY_LIMIT_STATES: usize = 64;

/// Maximum number of subprograms
pub const BPF_MAX_SUBPROGS: usize = 256;

/// Number of slots for a dynptr
pub const BPF_DYNPTR_NR_SLOTS: usize = 2;

/// Poison marker for map key
pub const BPF_MAP_KEY_POISON: u64 = 1 << 63;

/// Seen marker for map key
pub const BPF_MAP_KEY_SEEN: u64 = 1 << 62;

/// Maximum size for global percpu memory allocator
pub const BPF_GLOBAL_PERCPU_MA_MAX_SIZE: usize = 512;

/// Minimum size for private stack
pub const BPF_PRIV_STACK_MIN_SIZE: usize = 64;

/// Caller saved registers count
pub const CALLER_SAVED_REGS: usize = 6;

/// Caller saved register indices
pub const CALLER_SAVED: [usize; CALLER_SAVED_REGS] = [
    BPF_REG_0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5,
];

// ============================================================================
// Register Types
// ============================================================================

/// Base register types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[derive(Default)]
pub enum BpfRegType {
    /// Register is not initialized
    #[default]
    NotInit = 0,
    /// Scalar value (not a pointer)
    ScalarValue = 1,
    /// Pointer to BPF context
    PtrToCtx = 2,
    /// Constant pointer to map
    ConstPtrToMap = 3,
    /// Pointer to map value
    PtrToMapValue = 4,
    /// Pointer to map key
    PtrToMapKey = 5,
    /// Pointer to stack
    PtrToStack = 6,
    /// Pointer to packet metadata
    PtrToPacketMeta = 7,
    /// Pointer to packet data
    PtrToPacket = 8,
    /// Pointer to packet end
    PtrToPacketEnd = 9,
    /// Pointer to flow keys
    PtrToFlowKeys = 10,
    /// Pointer to socket
    PtrToSocket = 11,
    /// Pointer to socket common
    PtrToSockCommon = 12,
    /// Pointer to TCP socket
    PtrToTcpSock = 13,
    /// Pointer to XDP socket
    PtrToXdpSock = 14,
    /// Pointer to BTF ID
    PtrToBtfId = 15,
    /// Pointer to memory
    PtrToMem = 16,
    /// Pointer to arena
    PtrToArena = 17,
    /// Pointer to buffer
    PtrToBuf = 18,
    /// Constant pointer to dynptr
    ConstPtrToDynptr = 19,
    /// Pointer to read-only buffer
    PtrToRdOnlyBuf = 20,
    /// Pointer to read-write buffer
    PtrToRdWrBuf = 21,
}

impl BpfRegType {
    /// Get the base type (without flags)
    pub fn base_type(self) -> Self {
        self
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        !matches!(self, BpfRegType::NotInit | BpfRegType::ScalarValue)
    }

    /// Check if this is a packet pointer type
    pub fn is_pkt_pointer(&self) -> bool {
        matches!(self, BpfRegType::PtrToPacket | BpfRegType::PtrToPacketMeta)
    }
}

// ============================================================================
// Type Flags
// ============================================================================

bitflags! {
    /// Flags that can be combined with register types
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct BpfTypeFlag: u32 {
        /// Pointer may be null
        const PTR_MAYBE_NULL = 1 << 0;
        /// Memory is read-only
        const MEM_RDONLY = 1 << 1;
        /// Memory is allocated
        const MEM_ALLOC = 1 << 2;
        /// Memory is user-provided
        const MEM_USER = 1 << 3;
        /// Memory is percpu
        const MEM_PERCPU = 1 << 4;
        /// Pointer is untrusted
        const PTR_UNTRUSTED = 1 << 5;
        /// Pointer is trusted (from kernel, not user-controlled)
        const PTR_TRUSTED = 1 << 16;
        /// Memory is uninitialized
        const MEM_UNINIT = 1 << 6;
        /// Dynptr type: local
        const DYNPTR_TYPE_LOCAL = 1 << 7;
        /// Dynptr type: ringbuf
        const DYNPTR_TYPE_RINGBUF = 1 << 8;
        /// Dynptr type: SKB
        const DYNPTR_TYPE_SKB = 1 << 9;
        /// Dynptr type: XDP
        const DYNPTR_TYPE_XDP = 1 << 10;
        /// Memory is fixed size
        const MEM_FIXED_SIZE = 1 << 11;
        /// In RCU read side critical section
        const MEM_RCU = 1 << 12;
        /// Non-owning reference
        const NON_OWN_REF = 1 << 13;
        /// Dynptr type: SKB meta
        const DYNPTR_TYPE_SKB_META = 1 << 14;
        /// Dynptr type: file
        const DYNPTR_TYPE_FILE = 1 << 15;
    }
}

impl BpfTypeFlag {
    /// Check if this type may be null
    pub fn may_be_null(&self) -> bool {
        self.contains(BpfTypeFlag::PTR_MAYBE_NULL)
    }

    /// Mask for dynptr type flags
    pub const DYNPTR_TYPE_MASK: BpfTypeFlag = BpfTypeFlag::from_bits_truncate(
        BpfTypeFlag::DYNPTR_TYPE_LOCAL.bits()
            | BpfTypeFlag::DYNPTR_TYPE_RINGBUF.bits()
            | BpfTypeFlag::DYNPTR_TYPE_SKB.bits()
            | BpfTypeFlag::DYNPTR_TYPE_XDP.bits()
            | BpfTypeFlag::DYNPTR_TYPE_SKB_META.bits()
            | BpfTypeFlag::DYNPTR_TYPE_FILE.bits(),
    );
}

// ============================================================================
// Stack Slot Types
// ============================================================================

/// Type of a stack slot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum BpfStackSlotType {
    /// Slot is invalid/uninitialized
    #[default]
    Invalid = 0,
    /// Slot contains spilled register
    Spill = 1,
    /// Slot contains miscellaneous data
    Misc = 2,
    /// Slot contains zero
    Zero = 3,
    /// Slot is part of a dynptr
    Dynptr = 4,
    /// Slot is part of an iterator
    Iter = 5,
    /// Slot contains IRQ flag
    IrqFlag = 6,
}

impl BpfStackSlotType {
    /// Check if this is a special slot type
    pub fn is_special(&self) -> bool {
        matches!(
            self,
            BpfStackSlotType::Spill
                | BpfStackSlotType::Dynptr
                | BpfStackSlotType::Iter
                | BpfStackSlotType::IrqFlag
        )
    }
}

// ============================================================================
// Dynptr Types
// ============================================================================

/// Type of dynamic pointer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BpfDynptrType {
    /// Invalid or uninitialized dynptr
    #[default]
    Invalid = 0,
    /// Local memory dynptr
    Local = 1,
    /// Ringbuf dynptr
    Ringbuf = 2,
    /// SKB (socket buffer) dynptr
    Skb = 3,
    /// XDP dynptr
    Xdp = 4,
    /// SKB metadata dynptr
    SkbMeta = 5,
    /// File dynptr
    File = 6,
}

impl BpfDynptrType {
    /// Check if this dynptr type is refcounted
    pub fn is_refcounted(&self) -> bool {
        matches!(self, BpfDynptrType::Ringbuf | BpfDynptrType::File)
    }

    /// Convert to type flag
    pub fn to_type_flag(&self) -> BpfTypeFlag {
        match self {
            BpfDynptrType::Local => BpfTypeFlag::DYNPTR_TYPE_LOCAL,
            BpfDynptrType::Ringbuf => BpfTypeFlag::DYNPTR_TYPE_RINGBUF,
            BpfDynptrType::Skb => BpfTypeFlag::DYNPTR_TYPE_SKB,
            BpfDynptrType::Xdp => BpfTypeFlag::DYNPTR_TYPE_XDP,
            BpfDynptrType::SkbMeta => BpfTypeFlag::DYNPTR_TYPE_SKB_META,
            BpfDynptrType::File => BpfTypeFlag::DYNPTR_TYPE_FILE,
            BpfDynptrType::Invalid => BpfTypeFlag::empty(),
        }
    }
}

// ============================================================================
// Iterator State
// ============================================================================

/// State of an iterator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum BpfIterState {
    /// Invalid or uninitialized iterator
    #[default]
    Invalid = 0,
    /// Iterator is active and can produce values
    Active = 1,
    /// Iterator has been fully consumed
    Drained = 2,
}

// ============================================================================
// Reference Types
// ============================================================================

/// Type of reference held by a register
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RefStateType {
    /// Pointer reference
    Ptr = 1 << 0,
    /// Lock reference (spin lock or mutex)
    Lock = 1 << 1,
    /// Resource spin lock reference
    ResLock = 1 << 2,
    /// RCU lock reference
    RcuLock = 1 << 3,
    /// Preempt disable reference
    PreemptLock = 1 << 4,
    /// IRQ state reference
    Irq = 1 << 5,
}

impl RefStateType {
    /// Mask for lock types
    pub const LOCK_MASK: u32 = RefStateType::Lock as u32 | RefStateType::ResLock as u32;
}

// ============================================================================
// IRQ Kfunc Class
// ============================================================================

/// Class of IRQ kfunc
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IrqKfuncClass {
    /// Native IRQ handling kfuncs
    #[default]
    Native = 0,
    /// Lock-related IRQ kfuncs
    Lock = 1,
}

// ============================================================================
// Argument Types
// ============================================================================

/// Type of helper function argument
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfArgType {
    /// Unused argument
    DontCare = 0,
    /// Anything
    Anything = 1,
    /// Constant pointer to map
    ConstMapPtr = 2,
    /// Pointer to map key
    PtrToMapKey = 3,
    /// Pointer to map value
    PtrToMapValue = 4,
    /// Pointer to uninitialized memory
    PtrToUninitMem = 5,
    /// Constant size
    ConstSize = 6,
    /// Constant size or zero
    ConstSizeOrZero = 7,
    /// Pointer to context
    PtrToCtx = 8,
    /// Pointer to memory
    PtrToMem = 9,
    /// Pointer to memory (read-only)
    PtrToMemRdonly = 10,
    /// Pointer to stack
    PtrToStack = 11,
    /// Pointer to socket
    PtrToSocket = 12,
    /// Pointer to BTF ID
    PtrToBtfId = 13,
    /// Pointer to alloc memory
    PtrToAllocMem = 14,
    /// Constant alloc size or zero
    ConstAllocSizeOrZero = 15,
    /// Pointer to dynptr
    PtrToDynptr = 16,
    /// Pointer to timer
    PtrToTimer = 17,
    /// Pointer to kptr
    PtrToKptr = 18,
    /// Pointer to iterator
    PtrToIter = 19,
    /// Pointer to arena
    PtrToArena = 20,
}

// ============================================================================
// Return Types
// ============================================================================

/// Type of helper function return value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfRetType {
    /// Integer return
    Integer = 0,
    /// Void (no return)
    Void = 1,
    /// Pointer to map value or null
    PtrToMapValueOrNull = 2,
    /// Pointer to map value
    PtrToMapValue = 3,
    /// Pointer to socket or null
    PtrToSocketOrNull = 4,
    /// Pointer to TCP socket or null
    PtrToTcpSockOrNull = 5,
    /// Pointer to socket
    PtrToSocket = 6,
    /// Pointer to memory or null
    PtrToMemOrNull = 7,
    /// Pointer to BTF ID or null
    PtrToBtfIdOrNull = 8,
    /// Pointer to alloc memory or null
    PtrToAllocMemOrNull = 9,
    /// Pointer to dynptr memory or null
    PtrToDynptrMemOrNull = 10,
    /// Pointer to sock_common or null
    PtrToSockCommonOrNull = 11,
    /// Pointer to BTF ID (non-null)
    PtrToBtfId = 12,
    /// Pointer to memory (non-null, with known size)
    PtrToMem = 13,
    /// Pointer to memory or BTF ID (based on BTF type)
    PtrToMemOrBtfId = 14,
}

// ============================================================================
// Return Value Range
// ============================================================================

/// Range of valid return values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BpfRetvalRange {
    /// Minimum allowed return value
    pub minval: i32,
    /// Maximum allowed return value
    pub maxval: i32,
}

impl BpfRetvalRange {
    /// Create a new return value range
    pub fn new(minval: i32, maxval: i32) -> Self {
        Self { minval, maxval }
    }

    /// Check if a value is within this range
    pub fn contains(&self, val: i32) -> bool {
        val >= self.minval && val <= self.maxval
    }

    /// Check if this range is within another range
    pub fn is_within(&self, other: &Self) -> bool {
        self.minval >= other.minval && self.maxval <= other.maxval
    }
}

// ============================================================================
// BPF Instruction
// ============================================================================

/// A single BPF instruction
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfInsn {
    /// Opcode
    pub code: u8,
    /// Destination register
    pub dst_reg: u8,
    /// Source register
    pub src_reg: u8,
    /// Offset
    pub off: i16,
    /// Immediate value
    pub imm: i32,
}

impl BpfInsn {
    /// Create a new instruction
    pub fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg,
            src_reg,
            off,
            imm,
        }
    }

    /// Get instruction class
    pub fn class(&self) -> u8 {
        self.code & 0x07
    }

    /// Get instruction size
    pub fn size(&self) -> u8 {
        (self.code >> 3) & 0x03
    }

    /// Get instruction mode
    pub fn mode(&self) -> u8 {
        self.code & 0xe0
    }

    /// Check if this is a helper call
    pub fn is_helper_call(&self) -> bool {
        self.code == (BPF_JMP | BPF_CALL) && self.src_reg == 0
    }

    /// Check if this is a pseudo call (to subprogram)
    pub fn is_pseudo_call(&self) -> bool {
        self.code == (BPF_JMP | BPF_CALL) && self.src_reg == BPF_PSEUDO_CALL
    }

    /// Check if this is a kfunc call
    pub fn is_kfunc_call(&self) -> bool {
        self.code == (BPF_JMP | BPF_CALL) && self.src_reg == BPF_PSEUDO_KFUNC_CALL
    }

    /// Check if this is a cmpxchg instruction
    pub fn is_cmpxchg(&self) -> bool {
        self.class() == BPF_STX && self.mode() == BPF_ATOMIC && self.imm == BPF_CMPXCHG as i32
    }

    /// Check if this is an atomic load instruction
    pub fn is_atomic_load(&self) -> bool {
        self.class() == BPF_STX && self.mode() == BPF_ATOMIC && self.imm == BPF_LOAD_ACQ as i32
    }

    /// Check if this is a may_goto instruction
    pub fn is_may_goto(&self) -> bool {
        self.code == (BPF_JMP | BPF_JCOND) && self.src_reg == BPF_MAY_GOTO
    }
}

/// BPF instruction class: load from immediate
pub const BPF_LD: u8 = 0x00;
/// BPF instruction class: load from register
pub const BPF_LDX: u8 = 0x01;
/// BPF instruction class: store immediate
pub const BPF_ST: u8 = 0x02;
/// BPF instruction class: store register
pub const BPF_STX: u8 = 0x03;
/// BPF instruction class: 32-bit ALU operation
pub const BPF_ALU: u8 = 0x04;
/// BPF instruction class: 64-bit jump
pub const BPF_JMP: u8 = 0x05;
/// BPF instruction class: 32-bit jump
pub const BPF_JMP32: u8 = 0x06;
/// BPF instruction class: 64-bit ALU operation
pub const BPF_ALU64: u8 = 0x07;

/// BPF size: 32-bit word
pub const BPF_W: u8 = 0x00;
/// BPF size: 16-bit half-word
pub const BPF_H: u8 = 0x08;
/// BPF size: 8-bit byte
pub const BPF_B: u8 = 0x10;
/// BPF size: 64-bit double-word
pub const BPF_DW: u8 = 0x18;

/// BPF mode: immediate value
pub const BPF_IMM: u8 = 0x00;
/// BPF mode: absolute address (packet access)
pub const BPF_ABS: u8 = 0x20;
/// BPF mode: indirect address (packet access)
pub const BPF_IND: u8 = 0x40;
/// BPF mode: memory access
pub const BPF_MEM: u8 = 0x60;
/// BPF mode: sign-extended memory load
pub const BPF_MEMSX: u8 = 0x80;
/// BPF mode: atomic operation
pub const BPF_ATOMIC: u8 = 0xc0;

/// BPF ALU op: addition
pub const BPF_ADD: u8 = 0x00;
/// BPF ALU op: subtraction
pub const BPF_SUB: u8 = 0x10;
/// BPF ALU op: multiplication
pub const BPF_MUL: u8 = 0x20;
/// BPF ALU op: division
pub const BPF_DIV: u8 = 0x30;
/// BPF ALU op: bitwise OR
pub const BPF_OR: u8 = 0x40;
/// BPF ALU op: bitwise AND
pub const BPF_AND: u8 = 0x50;
/// BPF ALU op: left shift
pub const BPF_LSH: u8 = 0x60;
/// BPF ALU op: right shift (logical)
pub const BPF_RSH: u8 = 0x70;
/// BPF ALU op: negation
pub const BPF_NEG: u8 = 0x80;
/// BPF ALU op: modulo
pub const BPF_MOD: u8 = 0x90;
/// BPF ALU op: bitwise XOR
pub const BPF_XOR: u8 = 0xa0;
/// BPF ALU op: move
pub const BPF_MOV: u8 = 0xb0;
/// BPF ALU op: arithmetic right shift
pub const BPF_ARSH: u8 = 0xc0;
/// BPF ALU op: endianness conversion
pub const BPF_END: u8 = 0xd0;

/// BPF jump op: unconditional jump
pub const BPF_JA: u8 = 0x00;
/// BPF jump op: jump if equal
pub const BPF_JEQ: u8 = 0x10;
/// BPF jump op: jump if greater than (unsigned)
pub const BPF_JGT: u8 = 0x20;
/// BPF jump op: jump if greater or equal (unsigned)
pub const BPF_JGE: u8 = 0x30;
/// BPF jump op: jump if bits set
pub const BPF_JSET: u8 = 0x40;
/// BPF jump op: jump if not equal
pub const BPF_JNE: u8 = 0x50;
/// BPF jump op: jump if greater than (signed)
pub const BPF_JSGT: u8 = 0x60;
/// BPF jump op: jump if greater or equal (signed)
pub const BPF_JSGE: u8 = 0x70;
/// BPF op: function call
pub const BPF_CALL: u8 = 0x80;
/// BPF op: program exit
pub const BPF_EXIT: u8 = 0x90;
/// BPF jump op: jump if less than (unsigned)
pub const BPF_JLT: u8 = 0xa0;
/// BPF jump op: jump if less or equal (unsigned)
pub const BPF_JLE: u8 = 0xb0;
/// BPF jump op: jump if less than (signed)
pub const BPF_JSLT: u8 = 0xc0;
/// BPF jump op: jump if less or equal (signed)
pub const BPF_JSLE: u8 = 0xd0;
/// BPF jump op: conditional (may_goto)
pub const BPF_JCOND: u8 = 0xe0;

/// BPF source: immediate constant
pub const BPF_K: u8 = 0x00;
/// BPF source: register
pub const BPF_X: u8 = 0x08;

/// BPF endian: convert to little-endian
pub const BPF_TO_LE: u8 = 0x00;
/// BPF endian: convert to big-endian
pub const BPF_TO_BE: u8 = 0x08;

/// Pseudo call type: BPF-to-BPF function call
pub const BPF_PSEUDO_CALL: u8 = 1;
/// Pseudo call type: kernel function call
pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
/// Pseudo call type: may_goto instruction
pub const BPF_MAY_GOTO: u8 = 3;
/// Pseudo LD_IMM64: subprog function pointer (for LD_IMM64 loading function address)
pub const BPF_PSEUDO_FUNC: u8 = 4;

/// Pseudo map: file descriptor reference
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
/// Pseudo map: direct map value access
pub const BPF_PSEUDO_MAP_VALUE: u8 = 2;
/// Pseudo LD_IMM64: BTF type ID (for CO-RE relocation)
pub const BPF_PSEUDO_BTF_ID: u8 = 3;
/// Pseudo map: map index reference
pub const BPF_PSEUDO_MAP_IDX: u8 = 5;
/// Pseudo map: map index value access
pub const BPF_PSEUDO_MAP_IDX_VALUE: u8 = 6;

/// BPF atomic: compare and exchange
pub const BPF_CMPXCHG: u32 = 0xf1;
/// BPF atomic: exchange
pub const BPF_XCHG: u32 = 0xe1;
/// BPF atomic: load-acquire (Linux 6.13+)
pub const BPF_LOAD_ACQ: u32 = 0xc1;
/// BPF atomic: store-release (Linux 6.13+)
pub const BPF_STORE_REL: u32 = 0xc2;
/// BPF atomic: fetch flag
pub const BPF_FETCH: u32 = 0x01;

// ============================================================================
// Helper Function IDs
// ============================================================================

/// BPF helper function IDs (from linux/bpf.h)
///
/// These are the standard kernel helper functions available to BPF programs.
/// Each variant corresponds to a `bpf_func_id` value in the kernel.
/// The numeric values match those defined in `include/uapi/linux/bpf.h`.
#[expect(missing_docs, reason = "Helper IDs are self-documenting and match kernel definitions")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum BpfFuncId {
    #[default]
    Unspec = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    ProbeRead = 4,
    KtimeGetNs = 5,
    TracePrintk = 6,
    GetPrandomU32 = 7,
    GetSmpProcessorId = 8,
    SkbStoreBytes = 9,
    L3CsumReplace = 10,
    L4CsumReplace = 11,
    TailCall = 12,
    CloneRedirect = 13,
    GetCurrentPidTgid = 14,
    GetCurrentUidGid = 15,
    GetCurrentComm = 16,
    GetCgroupClassid = 17,
    SkbVlanPush = 18,
    SkbVlanPop = 19,
    SkbGetTunnelKey = 20,
    SkbSetTunnelKey = 21,
    PerfEventRead = 22,
    Redirect = 23,
    GetRouteRealm = 24,
    PerfEventOutput = 25,
    SkbLoadBytes = 26,
    GetStackid = 27,
    CsumDiff = 28,
    SkbGetTunnelOpt = 29,
    SkbSetTunnelOpt = 30,
    SkbChangeProto = 31,
    SkbChangeType = 32,
    SkbUnderCgroup = 33,
    GetHashRecalc = 34,
    GetCurrentTask = 35,
    ProbeWriteUser = 36,
    CurrentTaskUnderCgroup = 37,
    SkbChangeTail = 38,
    SkbPullData = 39,
    CsumUpdate = 40,
    SetHashInvalid = 41,
    GetNumaNodeId = 42,
    SkbChangeHead = 43,
    XdpAdjustHead = 44,
    ProbeReadStr = 45,
    GetSocketCookie = 46,
    GetSocketUid = 47,
    SetHash = 48,
    Setsockopt = 49,
    SkbAdjustRoom = 50,
    RedirectMap = 51,
    SkRedirectMap = 52,
    SockMapUpdate = 53,
    XdpAdjustMeta = 54,
    PerfEventReadValue = 55,
    PerfProgReadValue = 56,
    Getsockopt = 57,
    OverrideReturn = 58,
    SockOpsCbFlagsSet = 59,
    MsgRedirectMap = 60,
    MsgApplyBytes = 61,
    MsgCorkBytes = 62,
    MsgPullData = 63,
    Bind = 64,
    XdpAdjustTail = 65,
    SkbGetXfrmState = 66,
    GetStack = 67,
    SkbLoadBytesRelative = 68,
    FibLookup = 69,
    SockHashUpdate = 70,
    MsgRedirectHash = 71,
    SkRedirectHash = 72,
    LwtPushEncap = 73,
    LwtSeg6StoreBytes = 74,
    LwtSeg6AdjustSrh = 75,
    LwtSeg6Action = 76,
    RcRepeat = 77,
    RcKeydown = 78,
    SkbCgroupId = 79,
    GetCurrentCgroupId = 80,
    GetLocalStorage = 81,
    SkSelectReuseport = 82,
    SkbAncestorCgroupId = 83,
    SkLookupTcp = 84,
    SkLookupUdp = 85,
    SkRelease = 86,
    MapPushElem = 87,
    MapPopElem = 88,
    MapPeekElem = 89,
    MsgPushData = 90,
    MsgPopData = 91,
    RcPointerRel = 92,
    SpinLock = 93,
    SpinUnlock = 94,
    SkFullsock = 95,
    TcpSock = 96,
    SkbEcnSetCe = 97,
    GetListenerSock = 98,
    SkcLookupTcp = 99,
    TcpCheckSyncookie = 100,
    SysctlGetName = 101,
    SysctlGetCurrentValue = 102,
    SysctlGetNewValue = 103,
    SysctlSetNewValue = 104,
    Strtol = 105,
    Strtoul = 106,
    SkStorageGet = 107,
    SkStorageDelete = 108,
    SendSignal = 109,
    TcpGenSyncookie = 110,
    SkbOutput = 111,
    ProbeReadUser = 112,
    ProbeReadKernel = 113,
    ProbeReadUserStr = 114,
    ProbeReadKernelStr = 115,
    TcpSendAck = 116,
    SendSignalThread = 117,
    Jiffies64 = 118,
    ReadBranchRecords = 119,
    GetNsCurrentPidTgid = 120,
    XdpOutput = 121,
    GetNetnsCookie = 122,
    GetCurrentAncestorCgroupId = 123,
    SkAssign = 124,
    KtimeGetBootNs = 125,
    SeqPrintf = 126,
    SeqWrite = 127,
    SkCgroupId = 128,
    SkAncestorCgroupId = 129,
    RingbufOutput = 130,
    RingbufReserve = 131,
    RingbufSubmit = 132,
    RingbufDiscard = 133,
    RingbufQuery = 134,
    CsumLevel = 135,
    SkcToTcp6Sock = 136,
    SkcToTcpSock = 137,
    SkcToTcpTimewaitSock = 138,
    SkcToTcpRequestSock = 139,
    SkcToUdp6Sock = 140,
    GetTaskStack = 141,
    LoadHdrOpt = 142,
    StoreHdrOpt = 143,
    ReserveHdrOpt = 144,
    InodeStorageGet = 145,
    InodeStorageDelete = 146,
    DPath = 147,
    CopyFromUser = 148,
    SnprintfBtf = 149,
    SeqPrintfBtf = 150,
    SkbCgroupClassid = 151,
    RedirectNeigh = 152,
    PerCpuPtr = 153,
    ThisCpuPtr = 154,
    RedirectPeer = 155,
    TaskStorageGet = 156,
    TaskStorageDelete = 157,
    GetCurrentTaskBtf = 158,
    BprmOptsSet = 159,
    KtimeGetCoarseNs = 160,
    ImaInodeHash = 161,
    SockFromFile = 162,
    CheckMtu = 163,
    ForEachMapElem = 164,
    Snprintf = 165,
    SysBpf = 166,
    BtfFindByNameKind = 167,
    SysClose = 168,
    TimerInit = 169,
    TimerSetCallback = 170,
    TimerStart = 171,
    TimerCancel = 172,
    GetFuncIp = 173,
    GetAttachCookie = 174,
    TaskPtRegs = 175,
    GetBranchSnapshot = 176,
    TraceVprintk = 177,
    SkcToUnixSock = 178,
    KallsymsLookupName = 179,
    FindVma = 180,
    Loop = 181,
    Strncmp = 182,
    GetFuncArg = 183,
    GetFuncRet = 184,
    GetFuncArgCnt = 185,
    GetRetval = 186,
    SetRetval = 187,
    XdpGetBuffLen = 188,
    XdpLoadBytes = 189,
    XdpStoreBytes = 190,
    CopyFromUserTask = 191,
    SkbSetTstamp = 192,
    ImaFileHash = 193,
    KptrXchg = 194,
    MapLookupPercpuElem = 195,
    SkcToMptcpSock = 196,
    DynptrFromMem = 197,
    RingbufReserveDynptr = 198,
    RingbufSubmitDynptr = 199,
    RingbufDiscardDynptr = 200,
    DynptrRead = 201,
    DynptrWrite = 202,
    DynptrData = 203,
    TcpRawGenSyncookieIpv4 = 204,
    TcpRawGenSyncookieIpv6 = 205,
    TcpRawCheckSyncookieIpv4 = 206,
    TcpRawCheckSyncookieIpv6 = 207,
    KtimeGetTaiNs = 208,
    UserRingbufDrain = 209,
    CgrpStorageGet = 210,
    CgrpStorageDelete = 211,
}

impl BpfFuncId {
    /// Create a BpfFuncId from an instruction immediate value
    ///
    /// Returns Unspec for unknown/invalid function IDs.
    pub fn from_imm(imm: i32) -> Self {
        if imm < 0 {
            return BpfFuncId::Unspec;
        }
        let id = imm as u32;
        // Match against all known function IDs
        match id {
            0 => BpfFuncId::Unspec,
            1 => BpfFuncId::MapLookupElem,
            2 => BpfFuncId::MapUpdateElem,
            3 => BpfFuncId::MapDeleteElem,
            4 => BpfFuncId::ProbeRead,
            5 => BpfFuncId::KtimeGetNs,
            6 => BpfFuncId::TracePrintk,
            7 => BpfFuncId::GetPrandomU32,
            8 => BpfFuncId::GetSmpProcessorId,
            9 => BpfFuncId::SkbStoreBytes,
            10 => BpfFuncId::L3CsumReplace,
            11 => BpfFuncId::L4CsumReplace,
            12 => BpfFuncId::TailCall,
            13 => BpfFuncId::CloneRedirect,
            14 => BpfFuncId::GetCurrentPidTgid,
            15 => BpfFuncId::GetCurrentUidGid,
            16 => BpfFuncId::GetCurrentComm,
            17 => BpfFuncId::GetCgroupClassid,
            18 => BpfFuncId::SkbVlanPush,
            19 => BpfFuncId::SkbVlanPop,
            20 => BpfFuncId::SkbGetTunnelKey,
            21 => BpfFuncId::SkbSetTunnelKey,
            22 => BpfFuncId::PerfEventRead,
            23 => BpfFuncId::Redirect,
            24 => BpfFuncId::GetRouteRealm,
            25 => BpfFuncId::PerfEventOutput,
            26 => BpfFuncId::SkbLoadBytes,
            27 => BpfFuncId::GetStackid,
            28 => BpfFuncId::CsumDiff,
            29 => BpfFuncId::SkbGetTunnelOpt,
            30 => BpfFuncId::SkbSetTunnelOpt,
            31 => BpfFuncId::SkbChangeProto,
            32 => BpfFuncId::SkbChangeType,
            33 => BpfFuncId::SkbUnderCgroup,
            34 => BpfFuncId::GetHashRecalc,
            35 => BpfFuncId::GetCurrentTask,
            36 => BpfFuncId::ProbeWriteUser,
            37 => BpfFuncId::CurrentTaskUnderCgroup,
            38 => BpfFuncId::SkbChangeTail,
            39 => BpfFuncId::SkbPullData,
            40 => BpfFuncId::CsumUpdate,
            41 => BpfFuncId::SetHashInvalid,
            42 => BpfFuncId::GetNumaNodeId,
            43 => BpfFuncId::SkbChangeHead,
            44 => BpfFuncId::XdpAdjustHead,
            45 => BpfFuncId::ProbeReadStr,
            46 => BpfFuncId::GetSocketCookie,
            47 => BpfFuncId::GetSocketUid,
            48 => BpfFuncId::SetHash,
            49 => BpfFuncId::Setsockopt,
            50 => BpfFuncId::SkbAdjustRoom,
            51 => BpfFuncId::RedirectMap,
            52 => BpfFuncId::SkRedirectMap,
            53 => BpfFuncId::SockMapUpdate,
            54 => BpfFuncId::XdpAdjustMeta,
            55 => BpfFuncId::PerfEventReadValue,
            56 => BpfFuncId::PerfProgReadValue,
            57 => BpfFuncId::Getsockopt,
            58 => BpfFuncId::OverrideReturn,
            59 => BpfFuncId::SockOpsCbFlagsSet,
            60 => BpfFuncId::MsgRedirectMap,
            61 => BpfFuncId::MsgApplyBytes,
            62 => BpfFuncId::MsgCorkBytes,
            63 => BpfFuncId::MsgPullData,
            64 => BpfFuncId::Bind,
            65 => BpfFuncId::XdpAdjustTail,
            66 => BpfFuncId::SkbGetXfrmState,
            67 => BpfFuncId::GetStack,
            68 => BpfFuncId::SkbLoadBytesRelative,
            69 => BpfFuncId::FibLookup,
            70 => BpfFuncId::SockHashUpdate,
            71 => BpfFuncId::MsgRedirectHash,
            72 => BpfFuncId::SkRedirectHash,
            73 => BpfFuncId::LwtPushEncap,
            74 => BpfFuncId::LwtSeg6StoreBytes,
            75 => BpfFuncId::LwtSeg6AdjustSrh,
            76 => BpfFuncId::LwtSeg6Action,
            77 => BpfFuncId::RcRepeat,
            78 => BpfFuncId::RcKeydown,
            79 => BpfFuncId::SkbCgroupId,
            80 => BpfFuncId::GetCurrentCgroupId,
            81 => BpfFuncId::GetLocalStorage,
            82 => BpfFuncId::SkSelectReuseport,
            83 => BpfFuncId::SkbAncestorCgroupId,
            84 => BpfFuncId::SkLookupTcp,
            85 => BpfFuncId::SkLookupUdp,
            86 => BpfFuncId::SkRelease,
            87 => BpfFuncId::MapPushElem,
            88 => BpfFuncId::MapPopElem,
            89 => BpfFuncId::MapPeekElem,
            90 => BpfFuncId::MsgPushData,
            91 => BpfFuncId::MsgPopData,
            92 => BpfFuncId::RcPointerRel,
            93 => BpfFuncId::SpinLock,
            94 => BpfFuncId::SpinUnlock,
            95 => BpfFuncId::SkFullsock,
            96 => BpfFuncId::TcpSock,
            97 => BpfFuncId::SkbEcnSetCe,
            98 => BpfFuncId::GetListenerSock,
            99 => BpfFuncId::SkcLookupTcp,
            100 => BpfFuncId::TcpCheckSyncookie,
            101 => BpfFuncId::SysctlGetName,
            102 => BpfFuncId::SysctlGetCurrentValue,
            103 => BpfFuncId::SysctlGetNewValue,
            104 => BpfFuncId::SysctlSetNewValue,
            105 => BpfFuncId::Strtol,
            106 => BpfFuncId::Strtoul,
            107 => BpfFuncId::SkStorageGet,
            108 => BpfFuncId::SkStorageDelete,
            109 => BpfFuncId::SendSignal,
            110 => BpfFuncId::TcpGenSyncookie,
            111 => BpfFuncId::SkbOutput,
            112 => BpfFuncId::ProbeReadUser,
            113 => BpfFuncId::ProbeReadKernel,
            114 => BpfFuncId::ProbeReadUserStr,
            115 => BpfFuncId::ProbeReadKernelStr,
            116 => BpfFuncId::TcpSendAck,
            117 => BpfFuncId::SendSignalThread,
            118 => BpfFuncId::Jiffies64,
            119 => BpfFuncId::ReadBranchRecords,
            120 => BpfFuncId::GetNsCurrentPidTgid,
            121 => BpfFuncId::XdpOutput,
            122 => BpfFuncId::GetNetnsCookie,
            123 => BpfFuncId::GetCurrentAncestorCgroupId,
            124 => BpfFuncId::SkAssign,
            125 => BpfFuncId::KtimeGetBootNs,
            126 => BpfFuncId::SeqPrintf,
            127 => BpfFuncId::SeqWrite,
            128 => BpfFuncId::SkCgroupId,
            129 => BpfFuncId::SkAncestorCgroupId,
            130 => BpfFuncId::RingbufOutput,
            131 => BpfFuncId::RingbufReserve,
            132 => BpfFuncId::RingbufSubmit,
            133 => BpfFuncId::RingbufDiscard,
            134 => BpfFuncId::RingbufQuery,
            135 => BpfFuncId::CsumLevel,
            136 => BpfFuncId::SkcToTcp6Sock,
            137 => BpfFuncId::SkcToTcpSock,
            138 => BpfFuncId::SkcToTcpTimewaitSock,
            139 => BpfFuncId::SkcToTcpRequestSock,
            140 => BpfFuncId::SkcToUdp6Sock,
            141 => BpfFuncId::GetTaskStack,
            142 => BpfFuncId::LoadHdrOpt,
            143 => BpfFuncId::StoreHdrOpt,
            144 => BpfFuncId::ReserveHdrOpt,
            145 => BpfFuncId::InodeStorageGet,
            146 => BpfFuncId::InodeStorageDelete,
            147 => BpfFuncId::DPath,
            148 => BpfFuncId::CopyFromUser,
            149 => BpfFuncId::SnprintfBtf,
            150 => BpfFuncId::SeqPrintfBtf,
            151 => BpfFuncId::SkbCgroupClassid,
            152 => BpfFuncId::RedirectNeigh,
            153 => BpfFuncId::PerCpuPtr,
            154 => BpfFuncId::ThisCpuPtr,
            155 => BpfFuncId::RedirectPeer,
            156 => BpfFuncId::TaskStorageGet,
            157 => BpfFuncId::TaskStorageDelete,
            158 => BpfFuncId::GetCurrentTaskBtf,
            159 => BpfFuncId::BprmOptsSet,
            160 => BpfFuncId::KtimeGetCoarseNs,
            161 => BpfFuncId::ImaInodeHash,
            162 => BpfFuncId::SockFromFile,
            163 => BpfFuncId::CheckMtu,
            164 => BpfFuncId::ForEachMapElem,
            165 => BpfFuncId::Snprintf,
            166 => BpfFuncId::SysBpf,
            167 => BpfFuncId::BtfFindByNameKind,
            168 => BpfFuncId::SysClose,
            169 => BpfFuncId::TimerInit,
            170 => BpfFuncId::TimerSetCallback,
            171 => BpfFuncId::TimerStart,
            172 => BpfFuncId::TimerCancel,
            173 => BpfFuncId::GetFuncIp,
            174 => BpfFuncId::GetAttachCookie,
            175 => BpfFuncId::TaskPtRegs,
            176 => BpfFuncId::GetBranchSnapshot,
            177 => BpfFuncId::TraceVprintk,
            178 => BpfFuncId::SkcToUnixSock,
            179 => BpfFuncId::KallsymsLookupName,
            180 => BpfFuncId::FindVma,
            181 => BpfFuncId::Loop,
            182 => BpfFuncId::Strncmp,
            183 => BpfFuncId::GetFuncArg,
            184 => BpfFuncId::GetFuncRet,
            185 => BpfFuncId::GetFuncArgCnt,
            186 => BpfFuncId::GetRetval,
            187 => BpfFuncId::SetRetval,
            188 => BpfFuncId::XdpGetBuffLen,
            189 => BpfFuncId::XdpLoadBytes,
            190 => BpfFuncId::XdpStoreBytes,
            191 => BpfFuncId::CopyFromUserTask,
            192 => BpfFuncId::SkbSetTstamp,
            193 => BpfFuncId::ImaFileHash,
            194 => BpfFuncId::KptrXchg,
            195 => BpfFuncId::MapLookupPercpuElem,
            196 => BpfFuncId::SkcToMptcpSock,
            197 => BpfFuncId::DynptrFromMem,
            198 => BpfFuncId::RingbufReserveDynptr,
            199 => BpfFuncId::RingbufSubmitDynptr,
            200 => BpfFuncId::RingbufDiscardDynptr,
            201 => BpfFuncId::DynptrRead,
            202 => BpfFuncId::DynptrWrite,
            203 => BpfFuncId::DynptrData,
            204 => BpfFuncId::TcpRawGenSyncookieIpv4,
            205 => BpfFuncId::TcpRawGenSyncookieIpv6,
            206 => BpfFuncId::TcpRawCheckSyncookieIpv4,
            207 => BpfFuncId::TcpRawCheckSyncookieIpv6,
            208 => BpfFuncId::KtimeGetTaiNs,
            209 => BpfFuncId::UserRingbufDrain,
            210 => BpfFuncId::CgrpStorageGet,
            211 => BpfFuncId::CgrpStorageDelete,
            _ => BpfFuncId::Unspec,
        }
    }

    /// Check if this is a sync callback calling function
    pub fn is_sync_callback_calling(&self) -> bool {
        matches!(
            self,
            BpfFuncId::ForEachMapElem
                | BpfFuncId::FindVma
                | BpfFuncId::Loop
                | BpfFuncId::UserRingbufDrain
        )
    }

    /// Check if this is an async callback calling function
    pub fn is_async_callback_calling(&self) -> bool {
        matches!(self, BpfFuncId::TimerSetCallback)
    }

    /// Check if this is any callback calling function
    pub fn is_callback_calling(&self) -> bool {
        self.is_sync_callback_calling() || self.is_async_callback_calling()
    }

    /// Check if this is a storage get function
    pub fn is_storage_get(&self) -> bool {
        matches!(
            self,
            BpfFuncId::SkStorageGet
                | BpfFuncId::InodeStorageGet
                | BpfFuncId::TaskStorageGet
                | BpfFuncId::CgrpStorageGet
        )
    }

    /// Check if this is an acquire function
    pub fn is_acquire(&self) -> bool {
        matches!(
            self,
            BpfFuncId::SkLookupTcp
                | BpfFuncId::SkLookupUdp
                | BpfFuncId::SkcLookupTcp
                | BpfFuncId::RingbufReserve
                | BpfFuncId::KptrXchg
        )
    }

    /// Check if this is a pointer cast function
    pub fn is_ptr_cast(&self) -> bool {
        matches!(
            self,
            BpfFuncId::TcpSock
                | BpfFuncId::SkFullsock
                | BpfFuncId::SkcToTcpSock
                | BpfFuncId::SkcToTcp6Sock
                | BpfFuncId::SkcToUdp6Sock
                | BpfFuncId::SkcToMptcpSock
                | BpfFuncId::SkcToTcpTimewaitSock
                | BpfFuncId::SkcToTcpRequestSock
        )
    }
}

// ============================================================================
// Subprogram Info
// ============================================================================

/// Information about a subprogram
#[derive(Debug, Clone, Default)]
pub struct BpfSubprogInfo {
    /// Start instruction index
    pub start: usize,
    /// Stack depth in bytes
    pub stack_depth: usize,
    /// Whether this is a callback
    pub is_cb: bool,
    /// Whether this is an async callback
    pub is_async_cb: bool,
    /// Whether this is an exception callback
    pub is_exception_cb: bool,
    /// Whether this subprogram changes packet data
    pub changes_pkt_data: bool,
    /// Whether this subprogram might sleep
    pub might_sleep: bool,
}

// ============================================================================
// Map Types
// ============================================================================

/// BPF map types (from linux/bpf.h)
///
/// These map types correspond to `enum bpf_map_type` in the kernel.
#[expect(missing_docs, reason = "Map types are self-documenting and match kernel definitions")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfMapType {
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PercpuHash = 5,
    PercpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPercpuHash = 10,
    LpmTrie = 11,
    ArrayOfMaps = 12,
    HashOfMaps = 13,
    Devmap = 14,
    Sockmap = 15,
    Cpumap = 16,
    Xskmap = 17,
    Sockhash = 18,
    CgroupStorage = 19,
    ReuseportSockarray = 20,
    PercpuCgroupStorage = 21,
    Queue = 22,
    Stack = 23,
    SkStorage = 24,
    DevmapHash = 25,
    StructOps = 26,
    Ringbuf = 27,
    InodeStorage = 28,
    TaskStorage = 29,
    BloomFilter = 30,
    UserRingbuf = 31,
    CgrpStorage = 32,
    Arena = 33,
}

// ============================================================================
// Program Types
// ============================================================================

/// BPF program types (from linux/bpf.h)
///
/// These program types correspond to `enum bpf_prog_type` in the kernel.
#[expect(missing_docs, reason = "Program types are self-documenting and match kernel definitions")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfProgType {
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
    Netfilter = 32,
}

impl BpfProgType {
    /// Check if this is a tracing program type
    pub fn is_tracing(&self) -> bool {
        matches!(
            self,
            BpfProgType::Kprobe
                | BpfProgType::Tracepoint
                | BpfProgType::PerfEvent
                | BpfProgType::RawTracepoint
                | BpfProgType::RawTracepointWritable
                | BpfProgType::Tracing
        )
    }

    /// Check if this program type allows legacy packet access (LD_ABS/LD_IND)
    pub fn allows_legacy_pkt_access(&self) -> bool {
        matches!(
            self,
            BpfProgType::SocketFilter
                | BpfProgType::SchedCls
                | BpfProgType::SchedAct
                | BpfProgType::Xdp
                | BpfProgType::CgroupSkb
                | BpfProgType::SkSkb
                | BpfProgType::LwtIn
                | BpfProgType::LwtOut
                | BpfProgType::LwtXmit
                | BpfProgType::LwtSeg6local
        )
    }

    /// Check if this is a networking program type
    pub fn is_networking(&self) -> bool {
        matches!(
            self,
            BpfProgType::SocketFilter
                | BpfProgType::SchedCls
                | BpfProgType::SchedAct
                | BpfProgType::Xdp
                | BpfProgType::CgroupSkb
                | BpfProgType::SkSkb
                | BpfProgType::SkMsg
                | BpfProgType::LwtIn
                | BpfProgType::LwtOut
                | BpfProgType::LwtXmit
                | BpfProgType::LwtSeg6local
                | BpfProgType::SockOps
                | BpfProgType::CgroupSock
                | BpfProgType::CgroupSockAddr
                | BpfProgType::CgroupSockopt
                | BpfProgType::FlowDissector
                | BpfProgType::SkReuseport
        )
    }
}

// ============================================================================
// BPF Features (Linux 6.13+)
// ============================================================================

bitflags! {
    /// BPF feature flags
    ///
    /// These flags indicate which optional BPF features are enabled
    /// in the verifier environment.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct BpfFeatures: u32 {
        /// Support readonly cast to void
        ///
        /// Allows casting read-only pointers to void for compatibility
        const RDONLY_CAST_TO_VOID = 1 << 0;

        /// Streams support
        ///
        /// Enable BPF streams feature (new in Linux 6.13)
        const STREAMS = 1 << 1;
    }
}

impl BpfFeatures {
    /// Create a default feature set (all features enabled)
    pub fn default_features() -> Self {
        Self::all()
    }

    /// Check if a specific feature is enabled
    pub fn has_feature(&self, feature: BpfFeatures) -> bool {
        self.contains(feature)
    }

    /// Enable a specific feature
    pub fn enable(&mut self, feature: BpfFeatures) {
        self.insert(feature);
    }

    /// Disable a specific feature
    pub fn disable(&mut self, feature: BpfFeatures) {
        self.remove(feature);
    }
}
