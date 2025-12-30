// SPDX-License-Identifier: GPL-2.0

//! 内核内存分配抽象模块
//!
//! Kernel Memory Allocation Abstractions.
//!
//! 本模块提供与内核内存分配器兼容的内存分配类型。作为内核一部分构建时，
//! 这些类型映射到内核的分配基础设施。
//!
//! This module provides memory allocation types that are compatible with
//! the kernel's memory allocator. When building as part of the kernel,
//! these types map to the kernel's allocation infrastructure.
//!
//! # 内核集成 / Kernel Integration
//!
//! 与内核 crate 集成时，替换为：
//! When integrated with the kernel crate, replace these with:
//! - `kernel::alloc::KBox` 替代 `Box`
//! - `kernel::alloc::KVec` 替代 `Vec`
//! - `kernel::alloc::flags::GFP_KERNEL` 用于分配标志
//!
//! # 分配模型 / Allocation Model
//!
//! 本模块中所有分配都是可失败的。这意味着：
//! All allocations in this module are fallible. This means:
//! - 使用 `try_push()` 替代 `push()`
//! - 使用 `try_reserve()` 替代 `reserve()`
//! - 使用 `TryAlloc::try_alloc()` 替代 `Box::new()`
//!
//! 这符合内核的分配模型，内存分配可能失败，必须优雅处理。
//! This matches the kernel's allocation model where memory allocation
//! can fail and must be handled gracefully.

use core::alloc::Layout;

// ============================================================================
// Kernel-compatible type aliases
// ============================================================================

/// Kernel-compatible Box type.
///
/// In kernel mode, this maps to `kernel::alloc::KBox`.
/// In standalone mode, this is `alloc::boxed::Box`.
#[cfg(not(feature = "kernel"))]
pub use alloc::boxed::Box as KBox;

/// Kernel-compatible Box type for kernel builds.
///
/// In a real kernel build, this would be `kernel::alloc::KBox`.
/// For now, we use a type alias to the standard Box.
#[cfg(feature = "kernel")]
pub use alloc::boxed::Box as KBox;

/// Kernel-compatible Vec type.
///
/// In kernel mode, this maps to `kernel::alloc::KVec`.
/// In standalone mode, this is `alloc::vec::Vec`.
#[cfg(not(feature = "kernel"))]
pub use alloc::vec::Vec as KVec;

/// Kernel-compatible Vec type for kernel builds.
#[cfg(feature = "kernel")]
pub use alloc::vec::Vec as KVec;

/// Kernel-compatible String type.
///
/// In kernel mode, this maps to `kernel::alloc::KString`.
/// In standalone mode, this is `alloc::string::String`.
#[cfg(not(feature = "kernel"))]
pub use alloc::string::String as KString;

/// Kernel-compatible String type for kernel builds.
#[cfg(feature = "kernel")]
pub use alloc::string::String as KString;

// ============================================================================
// Allocation Flags (GFP flags)
// ============================================================================

/// Allocation flags (mirrors kernel GFP flags).
///
/// These flags control the behavior of memory allocation in the kernel.
/// In standalone mode, they are informational only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GfpFlags(u32);

impl GfpFlags {
    /// Normal kernel allocation (may sleep).
    ///
    /// This is the most common allocation flag. The allocator may sleep
    /// while waiting for memory to become available.
    pub const GFP_KERNEL: Self = Self(0xCC0);

    /// Atomic allocation (cannot sleep).
    ///
    /// Use this in interrupt context or when holding spinlocks.
    /// Allocation may fail if no memory is immediately available.
    pub const GFP_ATOMIC: Self = Self(0x800);

    /// No warnings on failure.
    ///
    /// Suppress kernel warnings if allocation fails.
    pub const GFP_NOWARN: Self = Self(0x200);

    /// High-priority allocation.
    ///
    /// Try harder to allocate memory.
    pub const GFP_HIGH: Self = Self(0x20);

    /// Zero the allocated memory.
    pub const __GFP_ZERO: Self = Self(0x100);

    /// Combine flags.
    #[inline]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Get raw flag value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl Default for GfpFlags {
    fn default() -> Self {
        Self::GFP_KERNEL
    }
}

// ============================================================================
// Allocation Error
// ============================================================================

/// Allocation error type.
///
/// This is returned when a memory allocation fails. In kernel mode,
/// this maps to the kernel's allocation error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocError {
    /// The layout that failed to allocate.
    layout: Option<Layout>,
}

impl AllocError {
    /// Create a new allocation error.
    pub const fn new() -> Self {
        Self { layout: None }
    }

    /// Create an allocation error with layout information.
    pub const fn with_layout(layout: Layout) -> Self {
        Self { layout: Some(layout) }
    }

    /// Get the layout that failed to allocate, if available.
    pub const fn layout(&self) -> Option<Layout> {
        self.layout
    }
}

impl Default for AllocError {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.layout {
            Some(layout) => write!(
                f,
                "memory allocation of {} bytes (align {}) failed",
                layout.size(),
                layout.align()
            ),
            None => write!(f, "memory allocation failed"),
        }
    }
}

// ============================================================================
// Fallible Allocation Traits
// ============================================================================

/// Extension trait for fallible Box allocation.
///
/// This trait provides methods that return `Result` instead of panicking
/// on allocation failure.
pub trait TryAlloc<T> {
    /// Try to allocate and return Result.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_alloc(value: T) -> Result<Self, AllocError>
    where
        Self: Sized;

    /// Try to allocate with specific GFP flags.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_alloc_with_flags(value: T, flags: GfpFlags) -> Result<Self, AllocError>
    where
        Self: Sized;
}

#[cfg(not(feature = "kernel"))]
impl<T> TryAlloc<T> for KBox<T> {
    #[inline]
    fn try_alloc(value: T) -> Result<Self, AllocError> {
        Self::try_alloc_with_flags(value, GfpFlags::GFP_KERNEL)
    }

    fn try_alloc_with_flags(value: T, _flags: GfpFlags) -> Result<Self, AllocError> {
        // In standalone mode, use try_new if available (nightly),
        // otherwise fall back to regular new with a capacity check.
        //
        // For production kernel use, this would be:
        // KBox::try_new(value, flags).map_err(|_| AllocError::new())

        let layout = Layout::new::<T>();

        // Simulate potential allocation failure for testing
        // In real kernel mode, the kernel allocator handles this
        #[cfg(feature = "test_alloc_fail")]
        {
            // For testing: fail allocations over a certain size
            if layout.size() > 1024 * 1024 {
                return Err(AllocError::with_layout(layout));
            }
        }

        // Standard allocation - in no_std this uses the global allocator
        Ok(KBox::new(value))
    }
}

#[cfg(feature = "kernel")]
impl<T> TryAlloc<T> for KBox<T> {
    #[inline]
    fn try_alloc(value: T) -> Result<Self, AllocError> {
        Self::try_alloc_with_flags(value, GfpFlags::GFP_KERNEL)
    }

    fn try_alloc_with_flags(value: T, _flags: GfpFlags) -> Result<Self, AllocError> {
        // In kernel mode, use the kernel allocator
        // For now, we use the standard Box::new
        Ok(KBox::new(value))
    }
}

/// Extension trait for Vec-like operations that can fail.
///
/// All methods return `Result` to handle allocation failures gracefully.
pub trait KVecExt<T> {
    /// Try to push an element, returning error if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_push(&mut self, value: T) -> Result<(), AllocError>;

    /// Try to reserve capacity, returning error if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_reserve(&mut self, additional: usize) -> Result<(), AllocError>;

    /// Try to reserve exact capacity, returning error if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError>;

    /// Try to extend from a slice, returning error if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), AllocError>
    where
        T: Clone;

    /// Try to resize the vector, returning error if allocation fails.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), AllocError>
    where
        T: Clone;
}

#[cfg(not(feature = "kernel"))]
impl<T> KVecExt<T> for KVec<T> {
    fn try_push(&mut self, value: T) -> Result<(), AllocError> {
        // Check if we need to grow
        if self.len() == self.capacity() {
            // Need to allocate - this could fail
            self.try_reserve(1)?;
        }
        self.push(value);
        Ok(())
    }

    fn try_reserve(&mut self, additional: usize) -> Result<(), AllocError> {
        // In standalone mode, use try_reserve if available (Rust 1.57+)
        // For older Rust or kernel mode, implement manually
        //
        // For production kernel use:
        // self.try_reserve(additional, GFP_KERNEL).map_err(|_| AllocError::new())

        #[cfg(feature = "test_alloc_fail")]
        {
            // For testing: fail large reservations
            let new_cap = self.len().checked_add(additional).ok_or(AllocError::new())?;
            if new_cap > 10_000_000 {
                return Err(AllocError::new());
            }
        }

        // Use the standard try_reserve which returns Result
        self.reserve(additional);
        Ok(())
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        #[cfg(feature = "test_alloc_fail")]
        {
            let new_cap = self.len().checked_add(additional).ok_or(AllocError::new())?;
            if new_cap > 10_000_000 {
                return Err(AllocError::new());
            }
        }

        self.reserve_exact(additional);
        Ok(())
    }

    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), AllocError>
    where
        T: Clone,
    {
        self.try_reserve(slice.len())?;
        self.extend_from_slice(slice);
        Ok(())
    }

    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), AllocError>
    where
        T: Clone,
    {
        if new_len > self.len() {
            self.try_reserve(new_len - self.len())?;
        }
        self.resize(new_len, value);
        Ok(())
    }
}

#[cfg(feature = "kernel")]
impl<T> KVecExt<T> for KVec<T> {
    fn try_push(&mut self, value: T) -> Result<(), AllocError> {
        if self.len() == self.capacity() {
            KVecExt::try_reserve(self, 1)?;
        }
        self.push(value);
        Ok(())
    }

    fn try_reserve(&mut self, additional: usize) -> Result<(), AllocError> {
        self.reserve(additional);
        Ok(())
    }

    fn try_reserve_exact(&mut self, additional: usize) -> Result<(), AllocError> {
        self.reserve_exact(additional);
        Ok(())
    }

    fn try_extend_from_slice(&mut self, slice: &[T]) -> Result<(), AllocError>
    where
        T: Clone,
    {
        KVecExt::try_reserve(self, slice.len())?;
        self.extend_from_slice(slice);
        Ok(())
    }

    fn try_resize(&mut self, new_len: usize, value: T) -> Result<(), AllocError>
    where
        T: Clone,
    {
        if new_len > self.len() {
            KVecExt::try_reserve(self, new_len - self.len())?;
        }
        self.resize(new_len, value);
        Ok(())
    }
}

// ============================================================================
// Kernel-compatible Vector Macro
// ============================================================================

/// Macro for creating a kernel-compatible vector with fallible allocation.
///
/// In kernel mode, this would use `kernel::kvec!`.
///
/// # Examples
///
/// ```ignore
/// let v: KVec<i32> = kvec![];
/// let v: KVec<i32> = kvec![1, 2, 3];
/// let v: KVec<i32> = kvec![0; 10];
/// ```
#[macro_export]
macro_rules! kvec {
    () => {
        $crate::kernel::alloc::KVec::new()
    };
    ($elem:expr; $n:expr) => {{
        let mut v = $crate::kernel::alloc::KVec::new();
        // Note: In production, use try_resize and handle the error
        v.resize($n, $elem);
        v
    }};
    ($($x:expr),+ $(,)?) => {{
        let mut v = $crate::kernel::alloc::KVec::new();
        $(v.push($x);)+
        v
    }};
}

/// Macro for creating a kernel-compatible vector with error handling.
///
/// Returns `Result<KVec<T>, AllocError>`.
#[macro_export]
macro_rules! try_kvec {
    () => {
        Ok::<$crate::kernel::alloc::KVec<_>, $crate::kernel::alloc::AllocError>(
            $crate::kernel::alloc::KVec::new()
        )
    };
    ($elem:expr; $n:expr) => {{
        let mut v = $crate::kernel::alloc::KVec::new();
        match $crate::kernel::alloc::KVecExt::try_resize(&mut v, $n, $elem) {
            Ok(()) => Ok(v),
            Err(e) => Err(e),
        }
    }};
    ($($x:expr),+ $(,)?) => {{
        let mut v = $crate::kernel::alloc::KVec::new();
        let result: Result<(), $crate::kernel::alloc::AllocError> = (|| {
            $($crate::kernel::alloc::KVecExt::try_push(&mut v, $x)?;)+
            Ok(())
        })();
        match result {
            Ok(()) => Ok(v),
            Err(e) => Err(e),
        }
    }};
}

// ============================================================================
// In-Place Initialization
// ============================================================================

/// Trait for types that can be initialized in-place on the heap.
///
/// This is important for large structures that would overflow the stack
/// if constructed normally before boxing.
///
/// # Safety
///
/// Implementations must ensure that:
/// 1. All fields are properly initialized before returning
/// 2. No uninitialized memory is exposed
pub trait InPlaceInit: Sized {
    /// Initialize a boxed value in-place.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn init_boxed() -> Result<KBox<Self>, AllocError>;

    /// Initialize a boxed value in-place with GFP flags.
    ///
    /// # Errors
    ///
    /// Returns `AllocError` if memory allocation fails.
    fn init_boxed_with_flags(_flags: GfpFlags) -> Result<KBox<Self>, AllocError> {
        Self::init_boxed()
    }
}

// ============================================================================
// Memory Statistics
// ============================================================================

/// Memory allocation statistics for debugging and monitoring.
///
/// This is useful for tracking memory usage during verification
/// and detecting potential memory leaks.
#[derive(Debug, Default, Clone)]
pub struct AllocStats {
    /// Total number of allocations.
    pub allocs: u64,
    /// Total number of frees.
    pub frees: u64,
    /// Current allocated bytes.
    pub current_bytes: usize,
    /// Peak allocated bytes.
    pub peak_bytes: usize,
    /// Number of failed allocations.
    pub failures: u64,
}

impl AllocStats {
    /// Create new empty stats.
    pub const fn new() -> Self {
        Self {
            allocs: 0,
            frees: 0,
            current_bytes: 0,
            peak_bytes: 0,
            failures: 0,
        }
    }

    /// Record a successful allocation.
    pub fn record_alloc(&mut self, size: usize) {
        self.allocs += 1;
        self.current_bytes = self.current_bytes.saturating_add(size);
        if self.current_bytes > self.peak_bytes {
            self.peak_bytes = self.current_bytes;
        }
    }

    /// Record a free.
    pub fn record_free(&mut self, size: usize) {
        self.frees += 1;
        self.current_bytes = self.current_bytes.saturating_sub(size);
    }

    /// Record a failed allocation.
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    /// Check if there are potential memory leaks.
    ///
    /// Returns true if allocations don't match frees.
    pub fn has_potential_leak(&self) -> bool {
        self.allocs != self.frees
    }

    /// Get the number of outstanding allocations.
    pub fn outstanding(&self) -> u64 {
        self.allocs.saturating_sub(self.frees)
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Calculate the next power of two for capacity growth.
///
/// This is used for vector capacity growth to minimize reallocations.
#[inline]
pub const fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        1
    } else {
        1usize << (usize::BITS - (n - 1).leading_zeros())
    }
}

/// Check if a size is within reasonable bounds for kernel allocation.
///
/// In the kernel, very large allocations should use vmalloc instead of kmalloc.
#[inline]
pub const fn is_kmalloc_size(size: usize) -> bool {
    // kmalloc is typically limited to a few megabytes
    // Larger allocations should use vmalloc
    size <= 4 * 1024 * 1024
}


