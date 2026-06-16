/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Watch a set of memory ranges and run a callback whenever they are read,
//! written, or executed.

use {
    crate::{MemoryRange, NativePointer, PageProtection, error::Error},
    core::{ffi::c_void, ptr},
    frida_gum_sys as gum_sys,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

/// Kind of memory access that triggered a notification.
#[derive(FromPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryOperation {
    /// Operation could not be determined.
    Invalid = gum_sys::_GumMemoryOperation_GUM_MEMOP_INVALID as u32,
    /// Read access.
    Read = gum_sys::_GumMemoryOperation_GUM_MEMOP_READ as u32,
    /// Write access.
    Write = gum_sys::_GumMemoryOperation_GUM_MEMOP_WRITE as u32,
    /// Execute access.
    Execute = gum_sys::_GumMemoryOperation_GUM_MEMOP_EXECUTE as u32,
}

/// Details about a memory access reported by [`MemoryAccessMonitor`].
#[derive(Debug, Clone)]
pub struct MemoryAccessDetails {
    /// Thread that performed the access.
    pub thread_id: usize,
    /// Kind of access.
    pub operation: MemoryOperation,
    /// Address of the instruction that performed the access.
    pub from: NativePointer,
    /// Address that was accessed.
    pub address: NativePointer,
    /// Index of the matched range in the slice passed to [`MemoryAccessMonitor::new`].
    pub range_index: usize,
    /// Index of the accessed page within the matched range.
    pub page_index: usize,
    /// Number of pages already accessed (and no longer monitored).
    pub pages_completed: usize,
    /// Total number of pages originally monitored.
    pub pages_total: usize,
}

impl core::fmt::Display for MemoryAccessDetails {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let op = match self.operation {
            MemoryOperation::Invalid => "invalid",
            MemoryOperation::Read => "read",
            MemoryOperation::Write => "write",
            MemoryOperation::Execute => "execute",
        };
        write!(
            f,
            "MemoryAccessDetails {{ operation: {}, from: {:#x}, address: {:#x}, range_index: {}, page_index: {}, pages_completed: {}, pages_total: {} }}",
            op,
            self.from.0 as usize,
            self.address.0 as usize,
            self.range_index,
            self.page_index,
            self.pages_completed,
            self.pages_total,
        )
    }
}

impl From<&gum_sys::GumMemoryAccessDetails> for MemoryAccessDetails {
    fn from(details: &gum_sys::GumMemoryAccessDetails) -> Self {
        Self {
            thread_id: details.thread_id as usize,
            operation: num::FromPrimitive::from_u32(details.operation)
                .unwrap_or(MemoryOperation::Invalid),
            from: NativePointer(details.from),
            address: NativePointer(details.address),
            range_index: details.range_index as usize,
            page_index: details.page_index as usize,
            pages_completed: details.pages_completed as usize,
            pages_total: details.pages_total as usize,
        }
    }
}

type Callback = Box<dyn FnMut(&MemoryAccessDetails) + 'static>;

/// Watch one or more memory ranges and invoke a callback on access.
///
/// The monitor takes ownership of the callback closure. Dropping the monitor
/// releases the closure and unregisters Frida's signal/exception hooks.
pub struct MemoryAccessMonitor {
    monitor: *mut gum_sys::GumMemoryAccessMonitor,
    // Kept boxed and alive for the lifetime of the monitor; the C side
    // holds a *mut c_void into this allocation.
    _callback: Box<Callback>,
}

impl MemoryAccessMonitor {
    /// Create a new monitor watching the supplied ranges.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges to watch.
    /// * `mask` - Which protection bits to react to (e.g. `Read`, `Write`,
    ///   `ReadWrite`, `Execute`).
    /// * `auto_reset` - If `true`, the watch on a page is rearmed after each
    ///   access; otherwise each page only fires once.
    /// * `callback` - Closure invoked on every access.
    pub fn new<F>(
        _gum: &crate::Gum,
        ranges: &[MemoryRange],
        mask: PageProtection,
        auto_reset: bool,
        callback: F,
    ) -> Self
    where
        F: FnMut(&MemoryAccessDetails) + 'static,
    {
        unsafe extern "C" fn trampoline(
            _monitor: *mut gum_sys::GumMemoryAccessMonitor,
            details: *const gum_sys::GumMemoryAccessDetails,
            user_data: gum_sys::gpointer,
        ) {
            let cb = unsafe { &mut *(user_data as *mut Callback) };
            let details = MemoryAccessDetails::from(unsafe { &*details });
            (cb)(&details);
        }

        // Frida copies the ranges array internally, so a stack-allocated Vec is fine.
        let raw_ranges: Vec<gum_sys::GumMemoryRange> =
            ranges.iter().map(|r| r.memory_range).collect();

        let mut boxed: Box<Callback> = Box::new(Box::new(callback));
        let user_data = &mut *boxed as *mut Callback as *mut c_void;

        let monitor = unsafe {
            gum_sys::gum_memory_access_monitor_new(
                raw_ranges.as_ptr(),
                raw_ranges.len() as u32,
                mask as gum_sys::GumPageProtection,
                auto_reset as gum_sys::gboolean,
                Some(trampoline),
                user_data,
                None,
            )
        };

        MemoryAccessMonitor {
            monitor,
            _callback: boxed,
        }
    }

    /// Arm the monitor.
    ///
    /// Returns an error if the underlying VM probes could not be installed
    /// (e.g. the requested ranges overlap memory that cannot be probed).
    pub fn enable(&self) -> Result<(), Error> {
        unsafe {
            let mut err: *mut gum_sys::GError = ptr::null_mut();
            let ok = gum_sys::gum_memory_access_monitor_enable(self.monitor, &mut err) != 0;
            if !err.is_null() {
                crate::glib_compat::g_error_free(err);
            }
            if ok {
                Ok(())
            } else {
                Err(Error::MemoryAccessError)
            }
        }
    }

    /// Disarm the monitor without destroying it.
    pub fn disable(&self) {
        unsafe { gum_sys::gum_memory_access_monitor_disable(self.monitor) };
    }
}

impl Drop for MemoryAccessMonitor {
    fn drop(&mut self) {
        unsafe {
            gum_sys::gum_memory_access_monitor_disable(self.monitor);
            gum_sys::g_object_unref(self.monitor as *mut c_void);
        }
    }
}

unsafe impl Send for MemoryAccessMonitor {}
