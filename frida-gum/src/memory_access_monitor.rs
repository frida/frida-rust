use super::{memory_range::MemoryRange, range_details::PageProtection};
use crate::{error::GumResult, NativePointer};
use core::{ffi::c_void, ptr::null_mut};
use frida_gum_sys::{
    _GumMemoryRange, false_, gum_memory_access_monitor_disable, gum_memory_access_monitor_enable,
    gum_memory_access_monitor_new, GError, GumMemoryAccessDetails, GumMemoryAccessMonitor,
    GumPageProtection, _GumMemoryOperation_GUM_MEMOP_EXECUTE,
    _GumMemoryOperation_GUM_MEMOP_INVALID, _GumMemoryOperation_GUM_MEMOP_READ,
    _GumMemoryOperation_GUM_MEMOP_WRITE,
};

pub trait CallbackFn: Fn(&mut MemoryAccessMonitor, &MemoryAccessDetails) {}

impl<F> CallbackFn for F where F: Fn(&mut MemoryAccessMonitor, &MemoryAccessDetails) {}

pub struct CallbackWrapper<F>
where
    F: CallbackFn,
{
    callback: F,
}

extern "C" fn c_callback<F>(
    monitor: *mut GumMemoryAccessMonitor,
    details: *const GumMemoryAccessDetails,
    user_data: *mut c_void,
) where
    F: CallbackFn,
{
    let details = unsafe { &*(details as *const GumMemoryAccessDetails) };
    let details = MemoryAccessDetails::from(details);
    let mut monitor = MemoryAccessMonitor { monitor };
    let cw: &mut CallbackWrapper<F> = unsafe { &mut *(user_data as *mut _) };
    (cw.callback)(&mut monitor, &details);
}

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum MemoryOperation {
    Invalid = _GumMemoryOperation_GUM_MEMOP_INVALID as _,
    Read = _GumMemoryOperation_GUM_MEMOP_READ as _,
    Write = _GumMemoryOperation_GUM_MEMOP_WRITE as _,
    Execute = _GumMemoryOperation_GUM_MEMOP_EXECUTE as _,
}

pub struct MemoryAccessDetails {
    pub operation: MemoryOperation,
    pub from: NativePointer,
    pub address: NativePointer,
    pub range_index: usize,
    pub page_index: usize,
    pub pages_completed: usize,
    pub pages_total: usize,
}

impl std::fmt::Display for MemoryAccessDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match self.operation {
            MemoryOperation::Invalid => "invalid",
            MemoryOperation::Read => "read",
            MemoryOperation::Write => "write",
            MemoryOperation::Execute => "execute",
        };
        write!(
            f,
            "MemoryAccessDetails {{ operation: {}, from: {:#x}, address: {:#x}, range_index: {}, page_index: {}, pages_completed: {}, pages_total: {} }}",
            operation,
            self.from.0 as usize,
            self.address.0 as usize,
            self.range_index,
            self.page_index,
            self.pages_completed,
            self.pages_total,
        )
    }
}

impl From<&GumMemoryAccessDetails> for MemoryAccessDetails {
    fn from(details: &GumMemoryAccessDetails) -> Self {
        Self {
            operation: num::FromPrimitive::from_u32(details.operation).unwrap(),
            from: NativePointer(details.from),
            address: NativePointer(details.address),
            range_index: details.range_index as _,
            page_index: details.page_index as _,
            pages_completed: details.pages_completed as _,
            pages_total: details.pages_total as _,
        }
    }
}

pub struct MemoryAccessMonitor {
    monitor: *mut GumMemoryAccessMonitor,
}

impl MemoryAccessMonitor {
    pub fn new<F>(
        _gum: &crate::Gum,
        ranges: Vec<MemoryRange>,
        mask: PageProtection,
        auto_reset: bool,
        callback: F,
    ) -> Self
    where
        F: CallbackFn,
    {
        let mut cw = CallbackWrapper { callback };
        let monitor = unsafe {
            let size = std::mem::size_of::<_GumMemoryRange>() * ranges.len();
            let block = std::alloc::alloc(std::alloc::Layout::from_size_align_unchecked(
                size,
                std::mem::align_of::<_GumMemoryRange>(),
            )) as *mut _GumMemoryRange;
            // copy ranges into the buffer
            for i in 0..ranges.len() {
                let range = &ranges[i];
                let ptr = block.add(i * std::mem::size_of::<_GumMemoryRange>());
                std::ptr::write(ptr as *mut _GumMemoryRange, range.memory_range);
            }
            let num_ranges = ranges.len() as u32;
            let monitor = gum_memory_access_monitor_new(
                block,
                num_ranges,
                mask as GumPageProtection,
                auto_reset as _,
                Some(c_callback::<F>),
                &mut cw as *mut _ as *mut c_void,
                None,
            );
            monitor
        };
        Self { monitor }
    }

    pub fn enable(&self) -> GumResult<()> {
        let mut error: *mut GError = null_mut();
        if unsafe { gum_memory_access_monitor_enable(self.monitor, &mut error) } == false_ as _ {
            Err(crate::error::Error::MemoryAccessError)
        } else {
            Ok(())
        }
    }

    pub fn disable(&self) {
        if self.monitor.is_null() {
            return;
        }
        unsafe { gum_memory_access_monitor_disable(self.monitor) };
    }
}
