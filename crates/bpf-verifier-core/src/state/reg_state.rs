// SPDX-License-Identifier: GPL-2.0

//! Register state tracking
//! 寄存器状态跟踪
//!
//! This module implements the core register state tracking for the BPF verifier.
//! Each register tracks its type, bounds (for scalars), and other metadata.
//!
//! 本模块实现 BPF 验证器的核心寄存器状态跟踪。
//! 每个寄存器跟踪其类型、边界（对于标量）和其他元数据。

use alloc::{format, vec::Vec};

use crate::bounds::scalar::ScalarBounds;
use crate::bounds::tnum::Tnum;
use crate::core::error::{Result, VerifierError};
use crate::core::types::*;

// ============================================================================
// Linked Register Constants / 链接寄存器常量
// ============================================================================

/// Upper bit of ID marks linked registers with constant delta
/// ID 的高位标记具有常量增量的链接寄存器
///
/// Example / 示例:
///   r1 = r2;        both have r1->id == r2->id == N
///                   两者都有 r1->id == r2->id == N
///   r1 += 10;       r1->id == N | BPF_ADD_CONST and r1->off == 10
///                   r1->id == N | BPF_ADD_CONST 且 r1->off == 10
pub const BPF_ADD_CONST: u32 = 1 << 31;

/// Maximum number of linked registers to track
/// 要跟踪的链接寄存器的最大数量
pub const MAX_LINKED_REGS: usize = MAX_BPF_REG;

/// State of a single BPF register
/// 单个 BPF 寄存器的状态
#[derive(Debug, Clone)]
pub struct BpfRegState {
    /// Type of the register
    /// 寄存器的类型
    pub reg_type: BpfRegType,
    /// Type flags (nullable, rdonly, etc.)
    /// 类型标志（可空、只读等）
    pub type_flags: BpfTypeFlag,
    /// Offset from pointer base
    /// 相对于指针基址的偏移量
    pub off: i32,
    /// Unique ID for this register value
    /// 此寄存器值的唯一 ID
    pub id: u32,
    /// Reference object ID (for acquired references)
    /// 引用对象 ID（用于获取的引用）
    pub ref_obj_id: u32,
    /// Tracked number for known/unknown bits
    /// 已知/未知位的追踪数值
    pub var_off: Tnum,
    /// Minimum signed 64-bit value
    /// 最小有符号 64 位值
    pub smin_value: i64,
    /// Maximum signed 64-bit value
    /// 最大有符号 64 位值
    pub smax_value: i64,
    /// Minimum unsigned 64-bit value
    /// 最小无符号 64 位值
    pub umin_value: u64,
    /// Maximum unsigned 64-bit value
    /// 最大无符号 64 位值
    pub umax_value: u64,
    /// Minimum signed 32-bit value
    /// 最小有符号 32 位值
    pub s32_min_value: i32,
    /// Maximum signed 32-bit value
    /// 最大有符号 32 位值
    pub s32_max_value: i32,
    /// Minimum unsigned 32-bit value
    /// 最小无符号 32 位值
    pub u32_min_value: u32,
    /// Maximum unsigned 32-bit value
    /// 最大无符号 32 位值
    pub u32_max_value: u32,
    /// Frame number for PTR_TO_STACK
    /// PTR_TO_STACK 的帧编号
    pub frameno: u32,
    /// Subreg definition instruction index
    /// 子寄存器定义指令索引
    pub subreg_def: u32,
    /// Whether this register requires precise tracking
    /// 此寄存器是否需要精确跟踪
    pub precise: bool,
    /// Live state flags
    /// 活跃状态标志
    pub live: RegLiveness,
    /// For PTR_TO_MAP_VALUE: pointer to map
    /// 对于 PTR_TO_MAP_VALUE：指向映射表的指针
    pub map_ptr: Option<MapInfo>,
    /// For PTR_TO_BTF_ID: BTF info
    /// 对于 PTR_TO_BTF_ID：BTF 信息
    pub btf_info: Option<BtfInfo>,
    /// For CONST_PTR_TO_DYNPTR: dynptr info
    /// 对于 CONST_PTR_TO_DYNPTR：动态指针信息
    pub dynptr: DynptrInfo,
    /// For iterator slots
    /// 用于迭代器槽位
    pub iter: IterInfo,
    /// For IRQ flag slots
    /// 用于中断请求标志槽位
    pub irq: IrqInfo,
    /// Memory size (for PTR_TO_MEM)
    /// 内存大小（用于 PTR_TO_MEM）
    pub mem_size: u32,
    /// Dynptr ID for slices
    /// 用于切片的动态指针 ID
    pub dynptr_id: u32,
    /// Map UID for timer/workqueue
    /// 用于定时器/工作队列的映射表 UID
    pub map_uid: u32,
}

/// Liveness tracking for registers
/// 寄存器的活跃性跟踪
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegLiveness {
    /// Register was read on this path
    /// 寄存器在此路径上被读取
    pub read: bool,
    /// Register was written on this path
    /// 寄存器在此路径上被写入
    pub written: bool,
    /// Liveness analysis complete for this register
    /// 此寄存器的活跃性分析已完成
    pub done: bool,
}

/// Map information for PTR_TO_MAP_VALUE
/// PTR_TO_MAP_VALUE 的映射表信息
#[derive(Debug, Clone)]
pub struct MapInfo {
    /// Type of the BPF map
    /// BPF 映射表的类型
    pub map_type: BpfMapType,
    /// Size of map keys in bytes
    /// 映射表键的大小（字节）
    pub key_size: u32,
    /// Size of map values in bytes
    /// 映射表值的大小（字节）
    pub value_size: u32,
    /// Maximum number of entries
    /// 最大条目数
    pub max_entries: u32,
}

/// BTF information for PTR_TO_BTF_ID
/// PTR_TO_BTF_ID 的 BTF 信息
#[derive(Debug, Clone, Default)]
pub struct BtfInfo {
    /// The BTF type ID
    /// BTF 类型 ID
    pub btf_id: u32,
    /// Cached pointer field offsets within this type
    /// 此类型内缓存的指针字段偏移量
    pub ptr_field_offsets: Vec<u32>,
    /// Cached nullable field offsets (fields that may be NULL)
    /// 缓存的可空字段偏移量（可能为 NULL 的字段）
    pub nullable_field_offsets: Vec<u32>,
}

impl BtfInfo {
    /// Create new BtfInfo with just the type ID
    /// 仅使用类型 ID 创建新的 BtfInfo
    pub fn new(btf_id: u32) -> Self {
        Self {
            btf_id,
            ptr_field_offsets: Vec::new(),
            nullable_field_offsets: Vec::new(),
        }
    }

    /// Check if the given offset is a pointer field
    /// 检查给定偏移量是否为指针字段
    pub fn is_ptr_field(&self, offset: u32) -> bool {
        self.ptr_field_offsets.contains(&offset)
    }

    /// Check if the given offset is a nullable field
    /// 检查给定偏移量是否为可空字段
    pub fn is_nullable_field(&self, offset: u32) -> bool {
        self.nullable_field_offsets.contains(&offset)
    }

    /// Add a pointer field at the given offset
    /// 在给定偏移量添加指针字段
    pub fn add_ptr_field(&mut self, offset: u32, nullable: bool) {
        if !self.ptr_field_offsets.contains(&offset) {
            self.ptr_field_offsets.push(offset);
        }
        if nullable && !self.nullable_field_offsets.contains(&offset) {
            self.nullable_field_offsets.push(offset);
        }
    }
}

/// Dynptr information
/// 动态指针信息
#[derive(Debug, Clone, Copy, Default)]
pub struct DynptrInfo {
    /// Type of the dynamic pointer
    /// 动态指针的类型
    pub dynptr_type: BpfDynptrType,
    /// Whether this is the first slot of a two-slot dynptr
    /// 是否为两槽位动态指针的第一个槽位
    pub first_slot: bool,
}

/// Iterator information
/// 迭代器信息
#[derive(Debug, Clone, Copy, Default)]
pub struct IterInfo {
    /// BTF type ID for the iterator
    /// 迭代器的 BTF 类型 ID
    pub btf_id: u32,
    /// Current state of the iterator
    /// 迭代器的当前状态
    pub state: BpfIterState,
    /// Nesting depth for nested iterators
    /// 嵌套迭代器的嵌套深度
    pub depth: u32,
}

/// IRQ flag information
/// 中断请求标志信息
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqInfo {
    /// Class of IRQ kfunc that created this state
    /// 创建此状态的中断请求 kfunc 类别
    pub kfunc_class: IrqKfuncClass,
}

impl Default for BpfRegState {
    fn default() -> Self {
        Self::new_not_init()
    }
}

impl BpfRegState {
    /// Create an uninitialized register state
    /// 创建未初始化的寄存器状态
    pub fn new_not_init() -> Self {
        Self {
            reg_type: BpfRegType::NotInit,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::unknown(),
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
            s32_min_value: i32::MIN,
            s32_max_value: i32::MAX,
            u32_min_value: 0,
            u32_max_value: u32::MAX,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a context pointer register
    /// 创建上下文指针寄存器
    pub fn new_ctx_ptr(_prog_type: BpfProgType) -> Self {
        Self {
            reg_type: BpfRegType::PtrToCtx,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::const_value(0),
            smin_value: 0,
            smax_value: 0,
            umin_value: 0,
            umax_value: 0,
            s32_min_value: 0,
            s32_max_value: 0,
            u32_min_value: 0,
            u32_max_value: 0,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a frame pointer register (R10)
    /// 创建帧指针寄存器（R10）
    pub fn new_fp() -> Self {
        Self {
            reg_type: BpfRegType::PtrToStack,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::const_value(0),
            smin_value: 0,
            smax_value: 0,
            umin_value: 0,
            umax_value: 0,
            s32_min_value: 0,
            s32_max_value: 0,
            u32_min_value: 0,
            u32_max_value: 0,
            frameno: 0,
            subreg_def: 0,
            precise: false,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Create a scalar register with unknown value
    /// 创建具有未知值的标量寄存器
    pub fn new_scalar_unknown(precise: bool) -> Self {
        Self {
            reg_type: BpfRegType::ScalarValue,
            type_flags: BpfTypeFlag::empty(),
            off: 0,
            id: 0,
            ref_obj_id: 0,
            var_off: Tnum::unknown(),
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
            s32_min_value: i32::MIN,
            s32_max_value: i32::MAX,
            u32_min_value: 0,
            u32_max_value: u32::MAX,
            frameno: 0,
            subreg_def: 0,
            precise,
            live: RegLiveness::default(),
            map_ptr: None,
            btf_info: None,
            dynptr: DynptrInfo::default(),
            iter: IterInfo::default(),
            irq: IrqInfo::default(),
            mem_size: 0,
            dynptr_id: 0,
            map_uid: 0,
        }
    }

    /// Mark register as known zero (scalar)
    /// 将寄存器标记为已知的零值（标量）
    pub fn mark_known_zero(&mut self) {
        self.mark_known(0);
    }

    /// Mark register as known constant value
    /// 将寄存器标记为已知的常量值
    pub fn mark_known(&mut self, imm: u64) {
        self.reg_type = BpfRegType::ScalarValue;
        self.type_flags = BpfTypeFlag::empty();
        self.var_off = Tnum::const_value(imm);
        self.smin_value = imm as i64;
        self.smax_value = imm as i64;
        self.umin_value = imm;
        self.umax_value = imm;
        self.s32_min_value = imm as i32;
        self.s32_max_value = imm as i32;
        self.u32_min_value = imm as u32;
        self.u32_max_value = imm as u32;
        self.id = 0;
        self.ref_obj_id = 0;
        self.off = 0;
    }

    /// Mark register as completely unknown scalar
    /// 将寄存器标记为完全未知的标量
    pub fn mark_unknown(&mut self, precise: bool) {
        self.reg_type = BpfRegType::ScalarValue;
        self.type_flags = BpfTypeFlag::empty();
        self.off = 0;
        self.id = 0;
        self.ref_obj_id = 0;
        self.var_off = Tnum::unknown();
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
        self.precise = precise;
        self.frameno = 0;
    }

    /// Mark register as uninitialized
    /// 将寄存器标记为未初始化
    pub fn mark_not_init(&mut self, precise: bool) {
        self.mark_unknown(precise);
        self.reg_type = BpfRegType::NotInit;
    }

    /// Mark register as const zero scalar
    /// 将寄存器标记为零常量标量
    pub fn mark_const_zero(&mut self, precise: bool) {
        self.mark_known(0);
        self.reg_type = BpfRegType::ScalarValue;
        self.precise = precise;
    }

    /// Mark the 32-bit subreg as known
    /// 将 32 位子寄存器标记为已知
    pub fn mark_32_known(&mut self, imm: u64) {
        self.var_off = Tnum::const_subreg(self.var_off, imm);
        self.s32_min_value = imm as i32;
        self.s32_max_value = imm as i32;
        self.u32_min_value = imm as u32;
        self.u32_max_value = imm as u32;
    }

    /// Reset min/max bounds to unbounded
    /// 将最小/最大边界重置为无界
    pub fn mark_unbounded(&mut self) {
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
    }

    /// Reset 64-bit bounds only
    /// 仅重置 64 位边界
    pub fn mark_64_unbounded(&mut self) {
        self.smin_value = i64::MIN;
        self.smax_value = i64::MAX;
        self.umin_value = 0;
        self.umax_value = u64::MAX;
    }

    /// Reset 32-bit bounds only
    /// 仅重置 32 位边界
    pub fn mark_32_unbounded(&mut self) {
        self.s32_min_value = i32::MIN;
        self.s32_max_value = i32::MAX;
        self.u32_min_value = 0;
        self.u32_max_value = u32::MAX;
    }

    /// Check if this register is null
    /// 检查此寄存器是否为空
    pub fn is_null(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue && self.var_off.equals_const(0)
    }

    /// Check if this register is a scalar value
    /// 检查此寄存器是否为标量值
    pub fn is_scalar(&self) -> bool {
        self.reg_type == BpfRegType::ScalarValue
    }

    /// Check if this is a constant register
    /// 检查此寄存器是否为常量
    pub fn is_const(&self) -> bool {
        self.var_off.is_const()
    }

    /// Get the constant value (only valid if is_const() returns true)
    /// 获取常量值（仅在 is_const() 返回 true 时有效）
    pub fn const_value(&self) -> u64 {
        self.var_off.value
    }

    /// Check if this register is definitely not null
    /// 检查此寄存器是否确定不为空
    pub fn is_not_null(&self) -> bool {
        if self.type_flags.may_be_null() {
            return false;
        }
        match self.reg_type {
            BpfRegType::PtrToSocket
            | BpfRegType::PtrToTcpSock
            | BpfRegType::PtrToMapValue
            | BpfRegType::PtrToMapKey
            | BpfRegType::PtrToSockCommon
            | BpfRegType::ConstPtrToMap => true,
            BpfRegType::PtrToBtfId => self.is_trusted(),
            BpfRegType::PtrToMem => !self.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED),
            _ => false,
        }
    }

    /// Check if this is a trusted pointer
    /// 检查是否为可信指针
    pub fn is_trusted(&self) -> bool {
        if self.type_flags.contains(BpfTypeFlag::PTR_UNTRUSTED) {
            return false;
        }
        if self.type_flags.contains(BpfTypeFlag::PTR_MAYBE_NULL) {
            return false;
        }
        match self.reg_type {
            BpfRegType::PtrToBtfId => !self.type_flags.contains(BpfTypeFlag::NON_OWN_REF),
            _ => false,
        }
    }

    /// Check if this is an RCU-protected pointer
    /// 检查是否为 RCU 保护的指针
    pub fn is_rcu(&self) -> bool {
        self.type_flags.contains(BpfTypeFlag::MEM_RCU)
    }

    /// Check if type may be null
    /// 检查类型是否可能为空
    pub fn may_be_null(&self) -> bool {
        self.type_flags.may_be_null()
    }

    /// Check if this is a pointer type
    /// 检查是否为指针类型
    pub fn is_pointer(&self) -> bool {
        self.reg_type.is_pointer()
    }

    /// Alias for is_pointer (shorter name)
    /// is_pointer 的别名（更短的名称）
    pub fn is_ptr(&self) -> bool {
        self.is_pointer()
    }

    /// Get BTF ID for typed pointers
    /// 获取类型化指针的 BTF ID
    pub fn btf_id(&self) -> u32 {
        self.btf_info.as_ref().map(|b| b.btf_id).unwrap_or(0)
    }

    /// Set BTF ID for typed pointers
    /// 设置类型化指针的 BTF ID
    pub fn set_btf_id(&mut self, btf_id: u32) {
        if let Some(ref mut info) = self.btf_info {
            info.btf_id = btf_id;
        } else {
            self.btf_info = Some(BtfInfo::new(btf_id));
        }
    }

    /// Check if this is a packet pointer
    /// 检查是否为数据包指针
    pub fn is_pkt_pointer(&self) -> bool {
        self.reg_type.is_pkt_pointer()
    }

    /// Check if this may point to a spin lock
    /// 检查是否可能指向自旋锁
    pub fn may_point_to_spin_lock(&self) -> bool {
        // Would need BTF record check in full implementation
        // 完整实现需要 BTF 记录检查
        false
    }

    /// Update bounds from var_off
    /// 从 var_off 更新边界
    pub fn update_bounds(&mut self) {
        self.update_32_bounds();
        self.update_64_bounds();
    }

    /// Update 32-bit bounds from var_off
    /// 从 var_off 更新 32 位边界
    pub fn update_32_bounds(&mut self) {
        let var32_off = self.var_off.subreg();

        // min signed is max(sign bit) | min(other bits)
        // 最小有符号值是 max(符号位) | min(其他位)
        let smin = (var32_off.value | (var32_off.mask & 0x8000_0000)) as i32;
        self.s32_min_value = self.s32_min_value.max(smin);

        // max signed is min(sign bit) | max(other bits)
        // 最大有符号值是 min(符号位) | max(其他位)
        let smax = (var32_off.value | (var32_off.mask & 0x7FFF_FFFF)) as i32;
        self.s32_max_value = self.s32_max_value.min(smax);

        self.u32_min_value = self.u32_min_value.max(var32_off.value as u32);
        self.u32_max_value = self
            .u32_max_value
            .min((var32_off.value | var32_off.mask) as u32);
    }

    /// Update 64-bit bounds from var_off
    /// 从 var_off 更新 64 位边界
    pub fn update_64_bounds(&mut self) {
        // min signed is max(sign bit) | min(other bits)
        // 最小有符号值是 max(符号位) | min(其他位)
        let smin = (self.var_off.value | (self.var_off.mask & (1u64 << 63))) as i64;
        self.smin_value = self.smin_value.max(smin);

        // max signed is min(sign bit) | max(other bits)
        // 最大有符号值是 min(符号位) | max(其他位)
        let smax = (self.var_off.value | (self.var_off.mask & !(1u64 << 63))) as i64;
        self.smax_value = self.smax_value.min(smax);

        self.umin_value = self.umin_value.max(self.var_off.value);
        self.umax_value = self.umax_value.min(self.var_off.value | self.var_off.mask);
    }

    /// Deduce bounds from signed/unsigned relationships
    /// 从有符号/无符号关系推导边界
    pub fn deduce_bounds(&mut self) {
        self.deduce_32_bounds();
        self.deduce_64_bounds();
        self.deduce_mixed_bounds();
    }

    /// Deduce 32-bit bounds
    /// 推导 32 位边界
    fn deduce_32_bounds(&mut self) {
        // If upper 32 bits of u64 range are same, we can use lower 32 for u32/s32
        // 如果 u64 范围的高 32 位相同，我们可以使用低 32 位作为 u32/s32
        if (self.umin_value >> 32) == (self.umax_value >> 32) {
            self.u32_min_value = self.u32_min_value.max(self.umin_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.umax_value as u32);

            if (self.umin_value as i32) <= (self.umax_value as i32) {
                self.s32_min_value = self.s32_min_value.max(self.umin_value as i32);
                self.s32_max_value = self.s32_max_value.min(self.umax_value as i32);
            }
        }

        // Similar for s64 range
        // 对 s64 范围同理
        if (self.smin_value >> 32) == (self.smax_value >> 32) {
            if (self.smin_value as u32) <= (self.smax_value as u32) {
                self.u32_min_value = self.u32_min_value.max(self.smin_value as u32);
                self.u32_max_value = self.u32_max_value.min(self.smax_value as u32);
            }
            if (self.smin_value as i32) <= (self.smax_value as i32) {
                self.s32_min_value = self.s32_min_value.max(self.smin_value as i32);
                self.s32_max_value = self.s32_max_value.min(self.smax_value as i32);
            }
        }

        // If u32 range forms valid s32 range, tighten s32
        // 如果 u32 范围形成有效的 s32 范围，收紧 s32
        if (self.u32_min_value as i32) <= (self.u32_max_value as i32) {
            self.s32_min_value = self.s32_min_value.max(self.u32_min_value as i32);
            self.s32_max_value = self.s32_max_value.min(self.u32_max_value as i32);
        }

        // If s32 range forms valid u32 range, tighten u32
        // 如果 s32 范围形成有效的 u32 范围，收紧 u32
        if (self.s32_min_value as u32) <= (self.s32_max_value as u32) {
            self.u32_min_value = self.u32_min_value.max(self.s32_min_value as u32);
            self.u32_max_value = self.u32_max_value.min(self.s32_max_value as u32);
        }
    }

    /// Deduce 64-bit bounds
    /// 推导 64 位边界
    fn deduce_64_bounds(&mut self) {
        // If u64 range forms valid s64 range (same sign), tighten s64
        // 如果 u64 范围形成有效的 s64 范围（相同符号），收紧 s64
        if (self.umin_value as i64) <= (self.umax_value as i64) {
            self.smin_value = self.smin_value.max(self.umin_value as i64);
            self.smax_value = self.smax_value.min(self.umax_value as i64);
        }

        // If s64 range forms valid u64 range, tighten u64
        // 如果 s64 范围形成有效的 u64 范围，收紧 u64
        if (self.smin_value as u64) <= (self.smax_value as u64) {
            self.umin_value = self.umin_value.max(self.smin_value as u64);
            self.umax_value = self.umax_value.min(self.smax_value as u64);
        }
    }

    /// Deduce mixed 32/64 bounds
    /// 推导混合 32/64 位边界
    fn deduce_mixed_bounds(&mut self) {
        // Try to tighten 64-bit bounds from 32-bit knowledge
        // 尝试从 32 位知识收紧 64 位边界
        let new_umin = (self.umin_value & !0xFFFF_FFFF) | self.u32_min_value as u64;
        let new_umax = (self.umax_value & !0xFFFF_FFFF) | self.u32_max_value as u64;
        self.umin_value = self.umin_value.max(new_umin);
        self.umax_value = self.umax_value.min(new_umax);

        let new_smin = (self.smin_value & !0xFFFF_FFFF_i64) | self.u32_min_value as i64;
        let new_smax = (self.smax_value & !0xFFFF_FFFF_i64) | self.u32_max_value as i64;
        self.smin_value = self.smin_value.max(new_smin);
        self.smax_value = self.smax_value.min(new_smax);
    }

    /// Update var_off based on bounds
    /// 根据边界更新 var_off
    pub fn bound_offset(&mut self) {
        let var64_off = self
            .var_off
            .intersect(Tnum::range(self.umin_value, self.umax_value));
        let var32_off = var64_off.subreg().intersect(Tnum::range(
            self.u32_min_value as u64,
            self.u32_max_value as u64,
        ));
        self.var_off = var64_off.clear_subreg() | var32_off;
    }

    /// Synchronize all bounds
    /// 同步所有边界
    pub fn sync_bounds(&mut self) {
        self.update_bounds();
        self.deduce_bounds();
        self.deduce_bounds();
        self.deduce_bounds();
        self.bound_offset();
        self.update_bounds();
    }

    /// Sanity check bounds consistency
    /// 边界一致性健全性检查
    pub fn bounds_sanity_check(&self) -> Result<()> {
        if self.umin_value > self.umax_value
            || self.smin_value > self.smax_value
            || self.u32_min_value > self.u32_max_value
            || self.s32_min_value > self.s32_max_value
        {
            return Err(VerifierError::BoundsCheckFailed(
                "range bounds violation".into(),
            ));
        }

        if self.var_off.is_const() {
            let uval = self.var_off.value;
            let sval = uval as i64;
            if self.umin_value != uval
                || self.umax_value != uval
                || self.smin_value != sval
                || self.smax_value != sval
            {
                return Err(VerifierError::BoundsCheckFailed(
                    "const tnum out of sync with range bounds".into(),
                ));
            }
        }

        if self.var_off.subreg_is_const() {
            let uval32 = self.var_off.subreg().value as u32;
            let sval32 = uval32 as i32;
            if self.u32_min_value != uval32
                || self.u32_max_value != uval32
                || self.s32_min_value != sval32
                || self.s32_max_value != sval32
            {
                return Err(VerifierError::BoundsCheckFailed(
                    "const subreg tnum out of sync".into(),
                ));
            }
        }

        Ok(())
    }

    /// Assign 32-bit bounds into 64-bit bounds (for zero-extension)
    /// 将 32 位边界赋值到 64 位边界（用于零扩展）
    pub fn assign_32_into_64(&mut self) {
        self.umin_value = self.u32_min_value as u64;
        self.umax_value = self.u32_max_value as u64;

        // Try to use 32-bit signed bounds for 64-bit if they're non-negative
        // (can be safely zero-extended to 64-bit)
        // 如果 32 位有符号边界非负，尝试将其用于 64 位
        // （可以安全地零扩展到 64 位）
        if self.s32_min_value >= 0 {
            self.smin_value = self.s32_min_value as i64;
            self.smax_value = self.s32_max_value as i64;
        } else {
            self.smin_value = 0;
            self.smax_value = u32::MAX as i64;
        }
    }

    /// Check if offset is sane for this pointer type
    /// 检查偏移量对于此指针类型是否合理
    pub fn check_sane_offset(&self) -> Result<()> {
        if !self.is_pointer() {
            return Ok(());
        }

        // Check for obviously bad offsets
        // 检查明显不良的偏移量
        if self.off < -1_000_000 || self.off > 1_000_000 {
            return Err(VerifierError::InvalidPointerArithmetic(format!(
                "offset {} is out of sane range",
                self.off
            )));
        }

        // Check var_off bounds
        // 检查 var_off 边界
        if self.var_off.value as i64 > 1_000_000
            || (self.var_off.value | self.var_off.mask) > 1_000_000_000
        {
            return Err(VerifierError::InvalidPointerArithmetic(
                "variable offset out of sane range".into(),
            ));
        }

        Ok(())
    }

    /// Clear the nullable/trusted flags
    /// 清除可空/可信标志
    pub fn clear_trusted_flags(&mut self) {
        self.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);
    }

    /// Mark pointer as not null (after null check)
    /// 将指针标记为非空（在空检查之后）
    pub fn mark_ptr_not_null(&mut self) {
        self.type_flags.remove(BpfTypeFlag::PTR_MAYBE_NULL);

        // Handle special map value cases would go here
        // 特殊映射表值情况的处理将在这里
        // For now, just clear the flag
        // 目前只清除标志
    }

    /// Set up register as a dynptr
    /// 将寄存器设置为动态指针
    pub fn mark_dynptr(&mut self, dynptr_type: BpfDynptrType, first_slot: bool, dynptr_id: u32) {
        self.mark_known_zero();
        self.reg_type = BpfRegType::ConstPtrToDynptr;
        self.id = dynptr_id;
        self.dynptr.dynptr_type = dynptr_type;
        self.dynptr.first_slot = first_slot;
    }

    /// Convert register bounds to ScalarBounds
    /// 将寄存器边界转换为 ScalarBounds
    pub fn to_scalar_bounds(&self) -> ScalarBounds {
        ScalarBounds {
            var_off: self.var_off,
            umin_value: self.umin_value,
            umax_value: self.umax_value,
            smin_value: self.smin_value,
            smax_value: self.smax_value,
            u32_min_value: self.u32_min_value,
            u32_max_value: self.u32_max_value,
            s32_min_value: self.s32_min_value,
            s32_max_value: self.s32_max_value,
        }
    }

    /// Apply ScalarBounds to this register
    /// 将 ScalarBounds 应用到此寄存器
    pub fn apply_scalar_bounds(&mut self, bounds: &ScalarBounds) {
        self.var_off = bounds.var_off;
        self.umin_value = bounds.umin_value;
        self.umax_value = bounds.umax_value;
        self.smin_value = bounds.smin_value;
        self.smax_value = bounds.smax_value;
        self.u32_min_value = bounds.u32_min_value;
        self.u32_max_value = bounds.u32_max_value;
        self.s32_min_value = bounds.s32_min_value;
        self.s32_max_value = bounds.s32_max_value;
    }

    /// Apply ALU operation and update bounds
    /// 应用 ALU 操作并更新边界
    pub fn scalar_alu_op(&mut self, op: u8, other: &BpfRegState, is_64bit: bool) -> Result<()> {
        let dst_bounds = self.to_scalar_bounds();
        let src_bounds = other.to_scalar_bounds();

        let result = dst_bounds.alu_op(op, &src_bounds, is_64bit)?;
        self.apply_scalar_bounds(&result);

        if !is_64bit {
            self.subreg_def = 1;
        }

        Ok(())
    }

    // ========================================================================
    // Linked Register Support (Linux 6.13+)
    // 链接寄存器支持（Linux 6.13+）
    // ========================================================================

    /// Check if this register is linked (has BPF_ADD_CONST bit set)
    /// 检查此寄存器是否被链接（设置了 BPF_ADD_CONST 位）
    ///
    /// A linked register has a constant offset from another register.
    /// 链接的寄存器与另一个寄存器有常量偏移。
    ///
    /// Example / 示例:
    ///   r1 = r2; r1 += 10; -> r1 is linked to r2 with offset 10
    ///                      -> r1 与 r2 链接，偏移量为 10
    pub fn is_linked(&self) -> bool {
        (self.id & BPF_ADD_CONST) != 0
    }

    /// Get the base ID (without BPF_ADD_CONST bit)
    /// 获取基础 ID（不含 BPF_ADD_CONST 位）
    ///
    /// This returns the ID of the register this one is linked to.
    /// 返回此寄存器链接到的寄存器的 ID。
    pub fn base_id(&self) -> u32 {
        self.id & !BPF_ADD_CONST
    }

    /// Mark this register as linked to another register
    /// 将此寄存器标记为链接到另一个寄存器
    ///
    /// Sets the BPF_ADD_CONST bit in the ID to indicate this register
    /// has a constant offset from another register with the same base_id.
    /// 设置 ID 中的 BPF_ADD_CONST 位，表示此寄存器与具有相同 base_id 的
    /// 另一个寄存器有常量偏移。
    pub fn mark_linked(&mut self, base_id: u32) {
        self.id = base_id | BPF_ADD_CONST;
    }

    /// Clear the linked register status
    /// 清除链接寄存器状态
    pub fn clear_linked(&mut self) {
        if self.is_linked() {
            self.id = self.base_id();
        }
    }

    /// Check if two registers are linked to the same base
    /// 检查两个寄存器是否链接到相同的基址
    pub fn linked_to_same_base(&self, other: &BpfRegState) -> bool {
        if !self.is_linked() || !other.is_linked() {
            return false;
        }
        self.base_id() == other.base_id()
    }

    /// Get the constant delta between linked registers
    /// 获取链接寄存器之间的常量增量
    ///
    /// If both registers are linked to the same base, returns the difference
    /// in their offsets. Otherwise returns None.
    /// 如果两个寄存器链接到相同的基址，返回它们偏移量的差值。否则返回 None。
    pub fn linked_delta(&self, other: &BpfRegState) -> Option<i32> {
        if self.linked_to_same_base(other) {
            Some(self.off.wrapping_sub(other.off))
        } else {
            None
        }
    }
}

/// Check if a value would be a pointer in unprivileged context
/// 检查值在非特权上下文中是否为指针
pub fn is_pointer_value(allow_ptr_leaks: bool, reg: &BpfRegState) -> bool {
    if allow_ptr_leaks {
        return false;
    }
    reg.is_pointer()
}

// ============================================================================
// Linked Register Tracking / 链接寄存器跟踪
// ============================================================================

/// Represents a single linked register
/// 表示单个链接的寄存器
#[derive(Debug, Clone, Copy)]
pub struct LinkedReg {
    /// Register number
    /// 寄存器编号
    pub reg: u8,
    /// Subreg flag (for 32-bit operations)
    /// 子寄存器标志（用于 32 位操作）
    pub subreg: bool,
}

/// Tracks a set of linked registers that share the same base ID
/// 跟踪共享相同基础 ID 的链接寄存器集合
///
/// This structure is used to efficiently track which registers are linked
/// together and propagate bounds information between them.
/// 此结构用于高效跟踪哪些寄存器链接在一起，并在它们之间传播边界信息。
#[derive(Debug, Clone)]
pub struct LinkedRegs {
    /// Number of linked registers in this set
    /// 此集合中链接寄存器的数量
    pub cnt: u8,
    /// Array of linked registers
    /// 链接寄存器数组
    pub regs: [LinkedReg; MAX_LINKED_REGS],
}

impl Default for LinkedRegs {
    fn default() -> Self {
        Self {
            cnt: 0,
            regs: [LinkedReg {
                reg: 0,
                subreg: false,
            }; MAX_LINKED_REGS],
        }
    }
}

impl LinkedRegs {
    /// Create a new empty linked register set
    /// 创建新的空链接寄存器集合
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a register to the linked set
    /// 将寄存器添加到链接集合
    pub fn add(&mut self, reg: u8, subreg: bool) -> Result<()> {
        if self.cnt >= MAX_LINKED_REGS as u8 {
            return Err(VerifierError::TooManyLinkedRegisters);
        }

        // Check if already present
        // 检查是否已存在
        for i in 0..self.cnt as usize {
            if self.regs[i].reg == reg && self.regs[i].subreg == subreg {
                return Ok(()); // Already in set / 已在集合中
            }
        }

        self.regs[self.cnt as usize] = LinkedReg { reg, subreg };
        self.cnt += 1;
        Ok(())
    }

    /// Check if a register is in the linked set
    /// 检查寄存器是否在链接集合中
    pub fn contains(&self, reg: u8) -> bool {
        for i in 0..self.cnt as usize {
            if self.regs[i].reg == reg {
                return true;
            }
        }
        false
    }

    /// Clear the linked register set
    /// 清除链接寄存器集合
    pub fn clear(&mut self) {
        self.cnt = 0;
    }

    /// Iterate over linked registers
    /// 迭代链接的寄存器
    pub fn iter(&self) -> impl Iterator<Item = &LinkedReg> {
        self.regs[0..self.cnt as usize].iter()
    }
}
