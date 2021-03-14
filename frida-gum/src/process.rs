//! Process helpers.
//!

use frida_gum_sys as gum_sys;
use std::ffi::CString;
use std::os::raw::c_void;

use crate::{PageProtection, RangeDetails};

extern "C" fn enumerate_ranges_callout(
    range_details: *const gum_sys::_GumRangeDetails,
    user_data: *mut c_void,
) -> gum_sys::gboolean {
    let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>) };
    let r = f(RangeDetails::from_raw(range_details));
    Box::leak(f);
    r as gum_sys::gboolean
}

pub struct Process;

impl Process {
    /// Enumerates memory ranges satisfying protection given.
    pub fn enumerate_ranges(
        module_name: &str,
        prot: PageProtection,
        callout: impl FnMut(RangeDetails) -> bool,
    ) {
        let module_name = CString::new(module_name).unwrap();

        unsafe {
            let user_data = Box::leak(Box::new(
                Box::new(callout) as Box<dyn FnMut(RangeDetails) -> bool>
            )) as *mut _ as *mut c_void;

            gum_sys::gum_module_enumerate_ranges(
                module_name.as_ptr(),
                prot as u32,
                Some(enumerate_ranges_callout),
                user_data,
            );

            let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(RangeDetails) -> bool>);
        }
    }
}
