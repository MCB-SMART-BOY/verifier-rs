// SPDX-License-Identifier: GPL-2.0

//! Error types for the BPF verifier
//! BPF 验证器的错误类型

use crate::stdlib::String;
use core::fmt;

/// Result type alias for verifier operations
/// 验证器操作的 Result 类型别名
pub type Result<T> = core::result::Result<T, VerifierError>;

/// Errors that can occur during BPF program verification
/// BPF 程序验证过程中可能发生的错误
#[derive(Debug, Clone)]
pub enum VerifierError {
    /// Program contains no instructions
    /// 程序不包含任何指令
    EmptyProgram,
    /// Program exceeds maximum instruction count
    /// 程序超过最大指令数限制
    ProgramTooLarge(usize),
    /// Instruction index out of bounds
    /// 指令索引越界
    InvalidInsnIdx(usize),
    /// Jump target outside program bounds (target, prog_len)
    /// 跳转目标超出程序边界 (目标地址, 程序长度)
    JumpOutOfRange(usize, usize),
    /// Jump lands on invalid instruction boundary
    /// 跳转落在无效的指令边界上
    InvalidJumpTarget(usize),
    /// Execution falls through exit instruction
    /// 执行流穿过了退出指令
    FallThroughExit,
    /// Verification complexity limit exceeded
    /// 超过验证复杂度限制
    VerificationLimitExceeded(String),
    /// Invalid or malformed instruction
    /// 无效或格式错误的指令
    InvalidInstruction(usize),
    /// Register number out of range
    /// 寄存器编号超出范围
    InvalidRegister(u8),
    /// Register used before initialization
    /// 寄存器在初始化之前被使用
    UninitializedRegister(u8),
    /// Invalid memory access (stack, map, context, etc.)
    /// 无效的内存访问（栈、映射表、上下文等）
    InvalidMemoryAccess(String),
    /// Stack access out of bounds
    /// 栈访问越界
    StackOutOfBounds(i32),
    /// Pointer offset exceeds valid range
    /// 指针偏移量超出有效范围
    InvalidOffset(i64),
    /// Resource reference not released before exit
    /// 资源引用在退出前未释放
    UnreleasedReference(u32),
    /// Invalid pointer arithmetic operation
    /// 无效的指针算术运算
    InvalidPointerArithmetic(String),
    /// Program logic too complex to verify
    /// 程序逻辑过于复杂，无法验证
    TooComplex(String),
    /// Jump destination is invalid
    /// 跳转目标无效
    InvalidJumpDestination(i32),
    /// Unbounded loop detected (back edge)
    /// 检测到无界循环（后向边）
    BackEdgeDetected,
    /// Dead code detected
    /// 检测到死代码
    UnreachableInstruction(usize),
    /// Invalid helper function call
    /// 无效的辅助函数调用
    InvalidHelperCall(String),
    /// Unknown helper function ID
    /// 未知的辅助函数 ID
    UnknownHelper(u32),
    /// Helper not allowed for program type
    /// 该程序类型不允许使用此辅助函数
    HelperNotAllowedForProgType {
        /// Helper function ID
        /// 辅助函数 ID
        helper_id: u32,
        /// Program type
        /// 程序类型
        prog_type: u32,
    },
    /// Unknown kfunc BTF ID
    /// 未知的 kfunc BTF ID
    UnknownKfunc(u32),
    /// Kfunc not allowed for program type
    /// 该程序类型不允许使用此 kfunc
    KfuncNotAllowedForProgType {
        /// Kfunc BTF ID
        /// Kfunc BTF ID
        kfunc_id: u32,
        /// Program type
        /// 程序类型
        prog_type: u32,
    },
    /// Invalid map operation
    /// 无效的映射表操作
    InvalidMapOperation(String),
    /// Type mismatch in operation
    /// 操作中的类型不匹配
    TypeMismatch {
        /// Expected type
        /// 期望的类型
        expected: String,
        /// Actual type found
        /// 实际发现的类型
        got: String,
    },
    /// Invalid pointer type or state
    /// 无效的指针类型或状态
    InvalidPointer(String),
    /// Operation not permitted for this program type
    /// 此程序类型不允许该操作
    PermissionDenied(String),
    /// Invalid map access
    /// 无效的映射表访问
    InvalidMapAccess(String),
    /// Invalid context access
    /// 无效的上下文访问
    InvalidContextAccess(String),
    /// Pointer value may be leaked to user space
    /// 指针值可能泄漏到用户空间
    PointerLeak,
    /// Division or modulo by zero
    /// 除以零或模零
    DivisionByZero,
    /// Invalid dynptr operation
    /// 无效的动态指针操作
    InvalidDynptr(String),
    /// Invalid iterator state or operation
    /// 无效的迭代器状态或操作
    InvalidIterator(String),
    /// Invalid lock state
    /// 无效的锁状态
    InvalidLock(String),
    /// Invalid IRQ state
    /// 无效的中断请求状态
    InvalidIrq(String),
    /// Resource limit exceeded
    /// 超过资源限制
    ResourceLimitExceeded(String),
    /// Complexity limit exceeded
    /// 超过复杂度限制
    ComplexityLimitExceeded(String),
    /// Internal verifier error
    /// 验证器内部错误
    Internal(String),
    /// Memory allocation failed
    /// 内存分配失败
    OutOfMemory,
    /// Invalid BTF data
    /// 无效的 BTF 数据
    InvalidBtf(String),
    /// Invalid kfunc call
    /// 无效的 kfunc 调用
    InvalidKfunc(String),
    /// Operation not allowed for program type
    /// 该程序类型不允许此操作
    InvalidProgramType(String),
    /// Speculative execution safety violation
    /// 推测执行安全违规
    SpeculativeViolation,
    /// Bounds check failed
    /// 边界检查失败
    BoundsCheckFailed(String),
    /// Too many subprograms
    /// 子程序过多
    TooManySubprogs,
    /// Function call stack too deep
    /// 函数调用栈过深
    CallStackOverflow,
    /// Stack usage exceeds limit
    /// 栈使用量超过限制
    StackOverflow(i32),
    /// Invalid subprogram
    /// 无效的子程序
    InvalidSubprog(String),
    /// Expected pointer type in register
    /// 期望寄存器中为指针类型
    ExpectedPointer(u8),
    /// Invalid instruction encoding size
    /// 无效的指令编码大小
    InvalidInsnSize(usize),
    /// Invalid atomic operation
    /// 无效的原子操作
    InvalidAtomicOp(u32),
    /// Invalid verifier state
    /// 无效的验证器状态
    InvalidState(String),
    /// Invalid function call
    /// 无效的函数调用
    InvalidFunctionCall(String),
    /// Memory access out of bounds
    /// 内存访问越界
    OutOfBounds {
        /// Access offset
        /// 访问偏移量
        offset: i32,
        /// Access size
        /// 访问大小
        size: i32,
    },
    /// Infinite loop detected at instruction
    /// 在指令处检测到无限循环
    InfiniteLoop(usize),
    /// Invalid pointer comparison
    /// 无效的指针比较
    InvalidPointerComparison(String),
    /// Invalid return value
    /// 无效的返回值
    InvalidReturnValue(String),
    /// Program attach failed
    /// 程序附加失败
    AttachFailed(String),
    /// Too many linked registers
    /// 链接的寄存器过多
    TooManyLinkedRegisters,
    /// Invalid value
    /// 无效的值
    InvalidValue(String),
    /// Program too complex
    /// 程序过于复杂
    ProgramTooComplex,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierError::EmptyProgram => write!(f, "empty program"),
            VerifierError::ProgramTooLarge(n) => write!(f, "program too large: {} instructions", n),
            VerifierError::InvalidInsnIdx(i) => write!(f, "invalid instruction index {}", i),
            VerifierError::JumpOutOfRange(t, l) => {
                write!(f, "jump out of range: target {}, prog_len {}", t, l)
            }
            VerifierError::InvalidJumpTarget(t) => write!(f, "invalid jump target {}", t),
            VerifierError::FallThroughExit => write!(f, "fall through exit"),
            VerifierError::VerificationLimitExceeded(s) => {
                write!(f, "verification limit exceeded: {}", s)
            }
            VerifierError::InvalidInstruction(i) => write!(f, "invalid instruction at index {}", i),
            VerifierError::InvalidRegister(r) => write!(f, "invalid register {}", r),
            VerifierError::UninitializedRegister(r) => write!(f, "register {} not initialized", r),
            VerifierError::InvalidMemoryAccess(s) => write!(f, "invalid memory access: {}", s),
            VerifierError::StackOutOfBounds(o) => {
                write!(f, "out of bounds stack access at offset {}", o)
            }
            VerifierError::InvalidOffset(o) => write!(f, "invalid offset {}", o),
            VerifierError::UnreleasedReference(id) => {
                write!(f, "unreleased reference with id {}", id)
            }
            VerifierError::InvalidPointerArithmetic(s) => {
                write!(f, "invalid pointer arithmetic: {}", s)
            }
            VerifierError::TooComplex(s) => write!(f, "program too complex: {}", s),
            VerifierError::InvalidJumpDestination(d) => write!(f, "invalid jump destination {}", d),
            VerifierError::BackEdgeDetected => write!(f, "back-edge detected, loops not allowed"),
            VerifierError::UnreachableInstruction(i) => {
                write!(f, "unreachable instruction at index {}", i)
            }
            VerifierError::InvalidHelperCall(s) => write!(f, "invalid helper call: {}", s),
            VerifierError::UnknownHelper(id) => write!(f, "unknown helper function {}", id),
            VerifierError::HelperNotAllowedForProgType { helper_id, prog_type } => {
                write!(f, "helper {} not allowed for program type {}", helper_id, prog_type)
            }
            VerifierError::UnknownKfunc(id) => write!(f, "unknown kfunc BTF ID {}", id),
            VerifierError::KfuncNotAllowedForProgType { kfunc_id, prog_type } => {
                write!(f, "kfunc {} not allowed for program type {}", kfunc_id, prog_type)
            }
            VerifierError::InvalidMapOperation(s) => write!(f, "invalid map operation: {}", s),
            VerifierError::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected {}, got {}", expected, got)
            }
            VerifierError::InvalidPointer(s) => write!(f, "invalid pointer: {}", s),
            VerifierError::PermissionDenied(s) => write!(f, "permission denied: {}", s),
            VerifierError::InvalidMapAccess(s) => write!(f, "invalid map access: {}", s),
            VerifierError::InvalidContextAccess(s) => write!(f, "invalid context access: {}", s),
            VerifierError::PointerLeak => write!(f, "pointer leak in unprivileged mode"),
            VerifierError::DivisionByZero => write!(f, "division by zero"),
            VerifierError::InvalidDynptr(s) => write!(f, "invalid dynptr operation: {}", s),
            VerifierError::InvalidIterator(s) => write!(f, "invalid iterator operation: {}", s),
            VerifierError::InvalidLock(s) => write!(f, "invalid lock operation: {}", s),
            VerifierError::InvalidIrq(s) => write!(f, "invalid IRQ operation: {}", s),
            VerifierError::ResourceLimitExceeded(s) => write!(f, "resource limit exceeded: {}", s),
            VerifierError::ComplexityLimitExceeded(s) => {
                write!(f, "complexity limit exceeded: {}", s)
            }
            VerifierError::Internal(s) => write!(f, "internal error: {}", s),
            VerifierError::OutOfMemory => write!(f, "out of memory"),
            VerifierError::InvalidBtf(s) => write!(f, "invalid BTF: {}", s),
            VerifierError::InvalidKfunc(s) => write!(f, "invalid kfunc: {}", s),
            VerifierError::InvalidProgramType(s) => write!(f, "invalid program type: {}", s),
            VerifierError::SpeculativeViolation => write!(f, "speculative execution violation"),
            VerifierError::BoundsCheckFailed(s) => write!(f, "bounds check failed: {}", s),
            VerifierError::TooManySubprogs => write!(f, "too many subprograms"),
            VerifierError::CallStackOverflow => write!(f, "call stack overflow"),
            VerifierError::StackOverflow(n) => write!(f, "stack overflow: {} bytes", n),
            VerifierError::InvalidSubprog(s) => write!(f, "invalid subprogram: {}", s),
            VerifierError::ExpectedPointer(r) => write!(f, "expected pointer in register {}", r),
            VerifierError::InvalidInsnSize(i) => write!(f, "invalid instruction size at {}", i),
            VerifierError::InvalidAtomicOp(op) => write!(f, "invalid atomic operation {:#x}", op),
            VerifierError::InvalidState(s) => write!(f, "invalid state: {}", s),
            VerifierError::InvalidFunctionCall(s) => write!(f, "invalid function call: {}", s),
            VerifierError::OutOfBounds { offset, size } => write!(
                f,
                "out of bounds access at offset {} with size {}",
                offset, size
            ),
            VerifierError::InfiniteLoop(i) => {
                write!(f, "infinite loop detected at instruction {}", i)
            }
            VerifierError::InvalidPointerComparison(s) => {
                write!(f, "invalid pointer comparison: {}", s)
            }
            VerifierError::InvalidReturnValue(s) => write!(f, "invalid return value: {}", s),
            VerifierError::AttachFailed(s) => write!(f, "attach failed: {}", s),
            VerifierError::TooManyLinkedRegisters => write!(f, "too many linked registers"),
            VerifierError::InvalidValue(s) => write!(f, "invalid value: {}", s),
            VerifierError::ProgramTooComplex => write!(f, "program too complex to verify"),
        }
    }
}

impl VerifierError {
    /// Check if this error is recoverable with speculation barrier
    /// 检查此错误是否可通过推测屏障恢复
    pub fn is_recoverable_with_nospec(&self) -> bool {
        matches!(
            self,
            VerifierError::PermissionDenied(_)
                | VerifierError::InvalidMemoryAccess(_)
                | VerifierError::TypeMismatch { .. }
        )
    }

    /// Convert to kernel errno value
    /// 转换为内核错误码值
    ///
    /// These correspond to Linux kernel error codes:
    /// 这些对应于 Linux 内核错误码：
    /// - EINVAL (22): Invalid argument / 无效参数
    /// - ENOMEM (12): Out of memory / 内存不足
    /// - EACCES (13): Permission denied / 权限被拒绝
    /// - E2BIG (7): Argument list too long (used for complexity limits) / 参数列表过长（用于复杂度限制）
    /// - EPERM (1): Operation not permitted / 操作不允许
    pub fn to_kernel_errno(&self) -> i32 {
        match self {
            // Memory errors / 内存错误
            VerifierError::OutOfMemory => -12, // ENOMEM

            // Permission/access errors / 权限/访问错误
            VerifierError::PermissionDenied(_) => -1, // EPERM
            VerifierError::PointerLeak => -1,         // EPERM
            VerifierError::InvalidMemoryAccess(_) => -13, // EACCES
            VerifierError::InvalidMapAccess(_) => -13, // EACCES
            VerifierError::InvalidContextAccess(_) => -13, // EACCES

            // Complexity/size limits / 复杂度/大小限制
            VerifierError::ProgramTooLarge(_) => -7, // E2BIG
            VerifierError::TooComplex(_) => -7,      // E2BIG
            VerifierError::VerificationLimitExceeded(_) => -7, // E2BIG
            VerifierError::ResourceLimitExceeded(_) => -7, // E2BIG
            VerifierError::ComplexityLimitExceeded(_) => -7, // E2BIG
            VerifierError::TooManySubprogs => -7,    // E2BIG
            VerifierError::CallStackOverflow => -7,  // E2BIG
            VerifierError::StackOverflow(_) => -7,   // E2BIG

            // All other errors are EINVAL / 所有其他错误均为 EINVAL
            _ => -22, // EINVAL
        }
    }
}
