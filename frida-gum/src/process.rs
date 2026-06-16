//! Process helpers.
//!

#![cfg_attr(
    any(target_arch = "x86_64", target_arch = "x86"),
    allow(clippy::unnecessary_cast)
)]

use crate::{FileMapping, Module, NativePointer, Thread};

use {
    crate::{Gum, PageProtection, RangeDetails},
    core::ffi::{CStr, c_char, c_void},
    core::{fmt, fmt::Debug},
    frida_gum_sys as gum_sys,
    frida_gum_sys::{gboolean, gpointer},
};

#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use cstr_core::CString;
use frida_gum_sys::GumThreadFlags_GUM_THREAD_FLAGS_ALL;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
unsafe extern "C" {
    pub fn _frida_g_get_home_dir() -> *const c_char;
    pub fn _frida_g_get_current_dir() -> *const c_char;
    pub fn _frida_g_get_tmp_dir() -> *const c_char;
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
unsafe extern "C" {
    pub fn g_get_home_dir() -> *const c_char;
    pub fn g_get_current_dir() -> *const c_char;
    pub fn g_get_tmp_dir() -> *const c_char;
}

#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum CodeSigningPolicy {
    CodeSigningOptional = gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_OPTIONAL as u32,
    CodeSigningRequired = gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_REQUIRED as u32,
}

/// How thoroughly Gum should clean up its state when shutting down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TeardownRequirement {
    /// Complete teardown of all internal state.
    Full = gum_sys::GumTeardownRequirement_GUM_TEARDOWN_REQUIREMENT_FULL as _,
    /// Minimal teardown, intended for short-lived processes.
    Minimal = gum_sys::GumTeardownRequirement_GUM_TEARDOWN_REQUIREMENT_MINIMAL as _,
}

#[derive(Clone, FromPrimitive, Debug)]
#[repr(u32)]
pub enum Os {
    Windows = gum_sys::_GumOS_GUM_OS_WINDOWS as u32,
    Macos = gum_sys::_GumOS_GUM_OS_MACOS as u32,
    Linux = gum_sys::_GumOS_GUM_OS_LINUX as u32,
    Ios = gum_sys::_GumOS_GUM_OS_IOS as u32,
    Watchos = gum_sys::_GumOS_GUM_OS_WATCHOS as u32,
    Tvos = gum_sys::_GumOS_GUM_OS_TVOS as u32,
    Android = gum_sys::_GumOS_GUM_OS_ANDROID as u32,
    Freebsd = gum_sys::_GumOS_GUM_OS_FREEBSD as u32,
    Qnx = gum_sys::_GumOS_GUM_OS_QNX as u32,
}

pub struct Range<'a> {
    /// Base address
    pub base: NativePointer,
    /// Size in bytes
    pub size: usize,
    /// Protection flag (e.g., Read, Write, Execute)
    pub protection: PageProtection,
    /// When available, file mapping details.
    pub file: Option<FileMapping<'a>>,
}

pub struct Process<'a> {
    // This is to verify that Gum is initialized before using any Module methods which requires
    // intialization.
    // Note that Gum is expected to be initialized via OnceCell which provides &Gum for every
    // instance.
    _gum: &'a Gum,
}

impl<'a> Process<'a> {
    /// Initialize a new process
    pub fn obtain(gum: &'a Gum) -> Process<'a> {
        Process { _gum: gum }
    }

    /// Property containing the PID as a number
    pub fn id(&self) -> u32 {
        unsafe { gum_sys::gum_process_get_id() }
    }

    /// Properly specifying the current platform.
    pub fn platform(&self) -> Os {
        num::FromPrimitive::from_u32(unsafe { gum_sys::gum_process_get_native_os() }).unwrap()
    }

    /// Returns property which can be `optional` or `required`, where the latter means Frida will avoid modifying
    /// existing code in memory and will not try to run unsigned code.
    pub fn code_signing_policy(&self) -> CodeSigningPolicy {
        num::FromPrimitive::from_u32(unsafe {
            gum_sys::gum_process_get_code_signing_policy() as u32
        })
        .unwrap()
    }

    /// Returns a Module representing the main executable of the process.
    pub fn main_module(&self) -> Module {
        unsafe { Module::from_raw(gum_sys::gum_process_get_main_module()) }
    }

    /// Returns the libc / system C runtime module if available.
    pub fn libc_module(&self) -> Option<Module> {
        unsafe {
            let module = gum_sys::gum_process_get_libc_module();
            if module.is_null() {
                None
            } else {
                Some(Module::from_raw(module))
            }
        }
    }

    /// Check whether the specified thread exists.
    pub fn has_thread(&self, thread_id: usize) -> bool {
        unsafe { gum_sys::gum_process_has_thread(thread_id as gum_sys::GumThreadId) != 0 }
    }

    /// Set the process-wide code signing policy.
    pub fn set_code_signing_policy(&self, policy: CodeSigningPolicy) {
        let raw: gum_sys::GumCodeSigningPolicy = match policy {
            CodeSigningPolicy::CodeSigningOptional => {
                gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_OPTIONAL
            }
            CodeSigningPolicy::CodeSigningRequired => {
                gum_sys::GumCodeSigningPolicy_GUM_CODE_SIGNING_REQUIRED
            }
        };
        unsafe { gum_sys::gum_process_set_code_signing_policy(raw) };
    }

    /// Get the current teardown requirement.
    pub fn teardown_requirement(&self) -> TeardownRequirement {
        let raw = unsafe { gum_sys::gum_process_get_teardown_requirement() };
        if raw == gum_sys::GumTeardownRequirement_GUM_TEARDOWN_REQUIREMENT_FULL {
            TeardownRequirement::Full
        } else {
            TeardownRequirement::Minimal
        }
    }

    /// Set the process teardown requirement.
    pub fn set_teardown_requirement(&self, requirement: TeardownRequirement) {
        unsafe {
            gum_sys::gum_process_set_teardown_requirement(
                requirement as gum_sys::GumTeardownRequirement,
            );
        }
    }

    /// Suspend the specified thread, run `callback` with its CPU context,
    /// then resume.
    ///
    /// The callback runs synchronously on the calling thread; you may
    /// inspect or modify the suspended thread's registers via the supplied
    /// `*mut GumCpuContext`.
    ///
    /// Set `abort_safely` to `true` to allow Frida to terminate the request
    /// at safe points if the suspended thread is in a critical region.
    ///
    /// Returns `true` on success.
    pub fn modify_thread<F>(&self, thread_id: usize, mut callback: F, abort_safely: bool) -> bool
    where
        F: FnMut(usize, *mut gum_sys::GumCpuContext),
    {
        unsafe extern "C" fn trampoline<F>(
            thread_id: gum_sys::GumThreadId,
            cpu_context: *mut gum_sys::GumCpuContext,
            user_data: gpointer,
        ) where
            F: FnMut(usize, *mut gum_sys::GumCpuContext),
        {
            unsafe {
                let cb = &mut *(user_data as *mut F);
                cb(thread_id as usize, cpu_context);
            }
        }

        let flags = if abort_safely {
            gum_sys::GumModifyThreadFlags_GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY
        } else {
            gum_sys::GumModifyThreadFlags_GUM_MODIFY_THREAD_FLAGS_NONE
        };

        unsafe {
            gum_sys::gum_process_modify_thread(
                thread_id as gum_sys::GumThreadId,
                Some(trampoline::<F>),
                &mut callback as *mut _ as *mut c_void,
                flags,
            ) != 0
        }
    }

    pub fn find_module_by_name(&self, module_name: &str) -> Option<Module> {
        let module_name = CString::new(module_name).unwrap();
        unsafe {
            let module = gum_sys::gum_process_find_module_by_name(module_name.as_ptr().cast());
            if !module.is_null() {
                Some(Module::from_raw(module))
            } else {
                None
            }
        }
    }

    pub fn find_module_by_address(&self, address: usize) -> Option<Module> {
        unsafe {
            let module = gum_sys::gum_process_find_module_by_address(address as u64);
            if !module.is_null() {
                Some(Module::from_raw(module))
            } else {
                None
            }
        }
    }

    /// Find the contiguous code range of the function containing `address`.
    ///
    /// Works on stripped binaries without symbol information, by following the
    /// platform's unwind data. Returns `None` if no function range could be
    /// determined for the address.
    ///
    /// # Safety
    ///
    /// `address` must point into executable code (typically the entry or body
    /// of a function) in a readable memory region.
    pub unsafe fn find_function_range(&self, address: NativePointer) -> Option<crate::MemoryRange> {
        unsafe {
            let mut raw: gum_sys::GumMemoryRange = core::mem::zeroed();
            if gum_sys::gum_process_find_function_range(address.0, &mut raw) != 0 {
                Some(crate::MemoryRange::new(
                    NativePointer(raw.base_address as *mut c_void),
                    raw.size as usize,
                ))
            } else {
                None
            }
        }
    }

    /// Returns a string specifying the filesystem path to the current working directory
    pub fn current_dir(&self) -> String {
        unsafe {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            let dir = _frida_g_get_current_dir();
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            let dir = g_get_current_dir();

            let owned = CStr::from_ptr(dir).to_string_lossy().to_string();
            // `g_get_current_dir` returns a newly-allocated string (transfer-full);
            // unlike `g_get_home_dir`/`g_get_tmp_dir` it must be freed by the caller.
            gum_sys::g_free(dir as *mut c_void);
            owned
        }
    }

    /// Returns a string specifying the filesystem path to the directory to use for temporary files
    pub fn tmp_dir(&self) -> String {
        unsafe {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            let dir = _frida_g_get_tmp_dir();
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            let dir = g_get_tmp_dir();

            CStr::from_ptr(dir).to_string_lossy().to_string()
        }
    }

    /// Returns a string specifying the filesystem path to the current user’s home directory
    pub fn home_dir(&self) -> String {
        unsafe {
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            let dir = _frida_g_get_home_dir();
            #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
            let dir = g_get_home_dir();

            CStr::from_ptr(dir).to_string_lossy().to_string()
        }
    }

    /// Returns a boolean indicating whether a debugger is currently attached
    pub fn is_debugger_attached(&self) -> bool {
        unsafe { gum_sys::gum_process_is_debugger_attached() == 1 }
    }

    /// Get this thread’s OS-specific id as a number
    pub fn current_thread_id(&self) -> u32 {
        unsafe { gum_sys::gum_process_get_current_thread_id() as u32 }
    }

    /// Enumerates memory ranges satisfying `protection` given
    pub fn enumerate_ranges(&self, protection: PageProtection) -> Vec<Range<'a>> {
        struct CallbackData<'a> {
            ranges: Vec<Range<'a>>,
            protection: PageProtection,
        }

        unsafe extern "C" fn enumerate_ranges_callback(
            details: *const gum_sys::GumRangeDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut CallbackData);
                let r_details = RangeDetails::from_raw(details);

                let prot = r_details.protection();
                if res.protection == prot {
                    let m_range = r_details.memory_range();
                    let file_map = r_details.file_mapping();

                    res.ranges.push(Range {
                        base: m_range.base_address(),
                        size: m_range.size(),
                        protection: prot,
                        file: file_map,
                    });
                }

                1
            }
        }

        let mut callback_data = CallbackData {
            ranges: Vec::new(),
            protection: protection.clone(),
        };

        unsafe {
            gum_sys::gum_process_enumerate_ranges(
                protection as u32,
                Some(enumerate_ranges_callback),
                &mut callback_data as *mut _ as *mut c_void,
            );
        }

        callback_data.ranges
    }

    /// Enumerate ranges that the libc allocator is currently using.
    ///
    /// Each entry is the [`crate::MemoryRange`] of a heap chunk reported by
    /// the host's malloc implementation (Windows heap, glibc, jemalloc, etc.).
    /// The set of returned ranges is a snapshot — concurrent allocations
    /// may invalidate it.
    pub fn enumerate_malloc_ranges(&self) -> Vec<crate::MemoryRange> {
        let mut result: Vec<crate::MemoryRange> = Vec::new();

        unsafe extern "C" fn callback(
            details: *const gum_sys::GumMallocRangeDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<crate::MemoryRange>);
                let r = *(*details).range;
                res.push(crate::MemoryRange::new(
                    NativePointer(r.base_address as *mut c_void),
                    r.size as usize,
                ));
                1
            }
        }

        unsafe {
            gum_sys::gum_process_enumerate_malloc_ranges(
                Some(callback),
                &mut result as *mut _ as *mut c_void,
            );
        }

        result
    }

    /// Enumerates loaded modules
    pub fn enumerate_modules(&self) -> Vec<Module> {
        struct CallbackData {
            modules: Vec<Module>,
        }

        unsafe extern "C" fn enumerate_modules_callback(
            details: *mut gum_sys::GumModule,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut CallbackData);
                res.modules.push(Module::from_raw(details));

                1
            }
        }

        let mut callback_data = CallbackData {
            modules: Vec::new(),
        };

        unsafe {
            gum_sys::gum_process_enumerate_modules(
                Some(enumerate_modules_callback),
                &mut callback_data as *mut _ as *mut c_void,
            );
        }

        callback_data.modules
    }

    /// Enumerates process threads. May crash the application if called too early (if there are no non-frida threads)
    pub fn enumerate_threads(&self) -> Vec<Thread> {
        unsafe extern "C" fn enumerate_threads_callback(
            details: *const gum_sys::GumThreadDetails,
            user_data: gpointer,
        ) -> gboolean {
            unsafe {
                let res = &mut *(user_data as *mut Vec<Thread>);
                res.push(Thread::from_raw(details));

                // if this value is zero, the iteration ends
                // subprojects/frida-gum/gum/gumthreadregistry.c
                1
            }
        }

        let mut callback_data = Vec::new();

        unsafe {
            gum_sys::gum_process_enumerate_threads(
                Some(enumerate_threads_callback),
                &mut callback_data as *mut _ as *mut c_void,
                GumThreadFlags_GUM_THREAD_FLAGS_ALL,
            )
        };

        callback_data
    }
}

impl Debug for Range<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Range")
            .field("base", &self.base)
            .field("size", &self.size)
            .field("protection", &self.protection)
            .field("file", &self.file)
            .finish()
    }
}
