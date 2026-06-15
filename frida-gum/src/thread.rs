use core::ffi::{CStr, c_void};
use core::fmt::{self, Debug};
use core::ptr;

use bitflags::bitflags;
use frida_gum_sys::{
    self as gum_sys, GumCpuContext, GumThreadFlags, GumThreadFlags_GUM_THREAD_FLAGS_ALL,
    GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT,
    GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER,
    GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE, GumThreadFlags_GUM_THREAD_FLAGS_NAME,
    GumThreadFlags_GUM_THREAD_FLAGS_NONE, GumThreadFlags_GUM_THREAD_FLAGS_STATE, GumThreadId,
    GumThreadState_GUM_THREAD_HALTED, GumThreadState_GUM_THREAD_STOPPED,
    GumThreadState_GUM_THREAD_UNINTERRUPTIBLE, GumThreadState_GUM_THREAD_WAITING,
};
use frida_gum_sys::{GumThreadDetails, GumThreadState_GUM_THREAD_RUNNING};
use num::FromPrimitive;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::string::String;

use crate::MemoryRange;

#[cfg(feature = "backtrace")]
use crate::Backtracer;
use crate::{CpuContext, CpuContextAccess, NativePointer};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ThreadFlags: GumThreadFlags {
        const NAME                 = GumThreadFlags_GUM_THREAD_FLAGS_NAME;
        const STATE                = GumThreadFlags_GUM_THREAD_FLAGS_STATE;
        const CPU_CONTEXT          = GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT;
        const ENTRYPOINT_ROUTINE   = GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE;
        const ENTRYPOINT_PARAMETER = GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER;

        const NONE = GumThreadFlags_GUM_THREAD_FLAGS_NONE;
        const ALL = GumThreadFlags_GUM_THREAD_FLAGS_ALL;
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u32)] // Repr GumThreadState (c_uint) not available
pub enum ThreadState {
    Running = GumThreadState_GUM_THREAD_RUNNING as _,
    Stopped = GumThreadState_GUM_THREAD_STOPPED as _,
    Waiting = GumThreadState_GUM_THREAD_WAITING as _,
    Uninterruptible = GumThreadState_GUM_THREAD_UNINTERRUPTIBLE as _,
    Halted = GumThreadState_GUM_THREAD_HALTED as _,
}

#[derive(Debug)]
pub struct Entrypoint {
    pub routine: NativePointer,
    pub parameter: NativePointer,
}

pub struct Thread {
    thread: *mut GumThreadDetails,
}

impl Thread {
    pub(crate) fn from_raw(thread: *const GumThreadDetails) -> Self {
        // I'm not sure if copying the threads details is needed, but it looks like that threads are not refcounted, so
        // there is no guarantee that they won't be freed
        let thread = unsafe { gum_sys::gum_thread_details_copy(thread) };

        Self { thread }
    }

    pub fn flags(&self) -> ThreadFlags {
        ThreadFlags::from_bits_truncate((unsafe { &*self.thread }).flags)
    }

    pub fn id(&self) -> GumThreadId {
        unsafe { &*self.thread }.id
    }

    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(({ *self.thread }).name) }
    }

    pub fn state(&self) -> ThreadState {
        ThreadState::from_u32(unsafe { ({ *self.thread }).state } as _).unwrap()
    }

    fn gum_cpu_context(&self) -> &GumCpuContext {
        unsafe { &(*self.thread).cpu_context }
    }

    pub fn cpu_context(&self) -> CpuContext {
        CpuContext::from_raw(
            self.gum_cpu_context() as *const _ as *mut GumCpuContext,
            CpuContextAccess::CpuContextReadOnly,
        )
    }

    pub fn entrypoint(&self) -> Entrypoint {
        let entrypoint = unsafe { &(*self.thread).entrypoint };
        Entrypoint {
            routine: NativePointer(entrypoint.routine as *mut _),
            parameter: NativePointer(entrypoint.parameter as *mut _),
        }
    }

    #[cfg(feature = "backtrace")]
    pub fn backtrace_accurate(&self) -> Vec<usize> {
        Backtracer::accurate_with_context(self.gum_cpu_context())
    }

    #[cfg(feature = "backtrace")]
    pub fn backtrace_fuzzy(&self) -> Vec<usize> {
        Backtracer::fuzzy_with_context(self.gum_cpu_context())
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_thread_details_free(self.thread) };
    }
}

/// OS-level thread operations.
///
/// These wrap Frida's process-wide thread manipulation primitives. They do
/// not require an existing [`Thread`] instance because they operate on raw
/// thread IDs.
pub struct ThreadOps;

impl ThreadOps {
    /// Get the calling thread's last system error code.
    ///
    /// On Windows this is `GetLastError()`; on POSIX systems this is `errno`.
    pub fn get_system_error() -> i32 {
        unsafe { gum_sys::gum_thread_get_system_error() }
    }

    /// Set the calling thread's last system error code.
    pub fn set_system_error(value: i32) {
        unsafe { gum_sys::gum_thread_set_system_error(value) };
    }

    /// Try to retrieve up to `max` ranges associated with the calling thread.
    ///
    /// Returns the ranges actually populated (which may be fewer than `max`).
    pub fn try_get_ranges(max: u32) -> Vec<MemoryRange> {
        let mut buffer: Vec<gum_sys::GumMemoryRange> = Vec::with_capacity(max as usize);
        let count = unsafe {
            let n = gum_sys::gum_thread_try_get_ranges(buffer.as_mut_ptr(), max);
            buffer.set_len(n as usize);
            n as usize
        };
        let mut out = Vec::with_capacity(count);
        for raw in buffer.iter().take(count) {
            out.push(MemoryRange::new(
                NativePointer(raw.base_address as *mut c_void),
                raw.size as usize,
            ));
        }
        out
    }

    /// Suspend the specified thread.
    ///
    /// Returns `true` on success. On failure, `error_message` (if any) will
    /// contain a description of what went wrong.
    pub fn suspend(thread_id: usize) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_suspend(thread_id as GumThreadId, &mut err) != 0;
            check_error(ok, err)
        }
    }

    /// Resume the specified thread.
    pub fn resume(thread_id: usize) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_resume(thread_id as GumThreadId, &mut err) != 0;
            check_error(ok, err)
        }
    }

    /// Set a hardware breakpoint at `address` on the specified thread.
    ///
    /// `breakpoint_id` selects which of the CPU's breakpoint registers to
    /// use (typically 0..=3 on x86 and 0..=15 on AArch64).
    pub fn set_hardware_breakpoint(
        thread_id: usize,
        breakpoint_id: u32,
        address: NativePointer,
    ) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_set_hardware_breakpoint(
                thread_id as GumThreadId,
                breakpoint_id,
                address.0 as gum_sys::GumAddress,
                &mut err,
            ) != 0;
            check_error(ok, err)
        }
    }

    /// Clear a previously installed hardware breakpoint.
    pub fn unset_hardware_breakpoint(
        thread_id: usize,
        breakpoint_id: u32,
    ) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_unset_hardware_breakpoint(
                thread_id as GumThreadId,
                breakpoint_id,
                &mut err,
            ) != 0;
            check_error(ok, err)
        }
    }

    /// Set a hardware watchpoint at `address` of `size` bytes.
    ///
    /// `conditions` controls whether reads, writes, or both fire the
    /// watchpoint.
    pub fn set_hardware_watchpoint(
        thread_id: usize,
        watchpoint_id: u32,
        address: NativePointer,
        size: usize,
        conditions: WatchConditions,
    ) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_set_hardware_watchpoint(
                thread_id as GumThreadId,
                watchpoint_id,
                address.0 as gum_sys::GumAddress,
                size as u64,
                conditions.bits(),
                &mut err,
            ) != 0;
            check_error(ok, err)
        }
    }

    /// Clear a previously installed hardware watchpoint.
    pub fn unset_hardware_watchpoint(
        thread_id: usize,
        watchpoint_id: u32,
    ) -> Result<(), ThreadError> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_thread_unset_hardware_watchpoint(
                thread_id as GumThreadId,
                watchpoint_id,
                &mut err,
            ) != 0;
            check_error(ok, err)
        }
    }
}

bitflags! {
    /// Conditions under which a hardware watchpoint fires.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WatchConditions: i32 {
        /// Fire on reads.
        const READ = gum_sys::GumWatchConditions_GUM_WATCH_READ;
        /// Fire on writes.
        const WRITE = gum_sys::GumWatchConditions_GUM_WATCH_WRITE;
    }
}

/// Error returned by [`ThreadOps`] when an operation fails.
#[derive(Debug)]
pub struct ThreadError {
    /// Optional human-readable description of the failure.
    pub message: Option<String>,
}

unsafe fn check_error(ok: bool, err: *mut gum_sys::GError) -> Result<(), ThreadError> {
    unsafe {
        if ok {
            if !err.is_null() {
                gum_sys::g_error_free(err);
            }
            return Ok(());
        }
        let message = if !err.is_null() {
            let msg = if !(*err).message.is_null() {
                Some(
                    CStr::from_ptr((*err).message)
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                None
            };
            gum_sys::g_error_free(err);
            msg
        } else {
            None
        };
        Err(ThreadError { message })
    }
}

impl Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thread")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("state", &self.state())
            .field("context", &self.cpu_context())
            .finish()
    }
}
