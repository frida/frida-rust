/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
use {
    core::{ffi::c_void, fmt},
    frida_gum_sys as gum_sys,
    gum_sys::GumCpuContext,
    paste::paste,
};

#[cfg(target_arch = "x86_64")]
macro_rules! REG_LIST {
    ($mac:ident) => {
        $mac!(
            u64, rip, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax
        );
    };
}

#[cfg(target_arch = "x86")]
macro_rules! REG_LIST {
    ($mac:ident) => {
        $mac!(u32, eip, edi, esi, ebp, esp, ebx, edx, ecx, eax);
    };
}

#[cfg(target_arch = "arm")]
// TODO(meme) uint32_t r[8];
macro_rules! REG_LIST {
    ($mac:ident) => {
        $mac!(u32, cpsr, pc, sp, r8, r9, r10, r11, r12, lr);
    };
}

#[cfg(target_arch = "aarch64")]
// TODO(meme) uint8_t q[128]; uint64_t x[29];
macro_rules! REG_LIST {
    ($mac:ident) => {
        $mac!(u64, pc, sp, fp, lr);
    };
}

macro_rules! cpu_accesors {
    ($reg:ty,$($name:ident),*) => {
        $(
            pub fn $name(&self) -> $reg {
                unsafe {(*self.as_ptr()).$name}
            }

            paste! {
                pub fn [<set_ $name>](&mut self, $name: $reg) {
                    let ctx = self.as_mut_ptr();
                    unsafe {(*ctx).$name = $name}
                }
            }
        )*
    }
}

macro_rules! gen_debug {
    ($reg:ty,$($name:ident),*) => {
        impl fmt::Debug for CpuContext {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut ds = f.debug_struct("CpuContext");
                $(
                    ds.field(stringify!($name), &format_args!("0x{:x}", &self.$name()));
                )*
                ds.finish()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuContextError {
    ReadOnly,
}

pub enum CpuContextAccess {
    CpuContextReadOnly = 1,
    CpuCcontextReadWrite,
}

pub enum CpuContextType {
    ReadOnly(GumCpuContext),
    ReadWrite(*mut GumCpuContext),
}

/// Platform-dependent access to processor state.
pub struct CpuContext {
    cpu_context: CpuContextType,
}

impl CpuContext {
    pub(crate) fn from_raw(
        cpu_context: *mut GumCpuContext,
        access: CpuContextAccess,
    ) -> CpuContext {
        unsafe {
            match access {
                CpuContextAccess::CpuContextReadOnly => {
                    let snapshot = *cpu_context;

                    CpuContext {
                        cpu_context: CpuContextType::ReadOnly(snapshot),
                    }
                }
                CpuContextAccess::CpuCcontextReadWrite => CpuContext {
                    cpu_context: CpuContextType::ReadWrite(cpu_context),
                },
            }
        }
    }

    fn as_ptr(&self) -> *const GumCpuContext {
        match self.cpu_context {
            CpuContextType::ReadOnly(ctx) => &ctx as *const GumCpuContext,
            CpuContextType::ReadWrite(ctx) => ctx as *const GumCpuContext,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut GumCpuContext {
        match self.cpu_context {
            CpuContextType::ReadOnly(_) => {
                panic!("Error: trying to write a read only CPU context.")
            }
            CpuContextType::ReadWrite(ctx) => ctx as *mut GumCpuContext,
        }
    }

    /// Get a numbered argument from the processor context, determined by the platform calling convention.
    pub fn arg(&self, n: u32) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_nth_argument(self.as_ptr() as *mut _, n) as usize }
    }

    /// Set a numbered argument in the processor context, determined by the platform calling convention.
    pub fn set_arg(&mut self, n: u32, value: usize) -> Result<(), CpuContextError> {
        match self.cpu_context {
            CpuContextType::ReadOnly(_) => Err(CpuContextError::ReadOnly),
            CpuContextType::ReadWrite(_) => {
                unsafe {
                    gum_sys::gum_cpu_context_replace_nth_argument(
                        self.as_mut_ptr(),
                        n,
                        value as *mut c_void,
                    )
                };

                Ok(())
            }
        }
    }

    /// Get the value of the register used for the platform calling convention's return value.
    pub fn return_value(&self) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_return_value(self.as_ptr() as *mut _) as usize }
    }

    /// Set the value of the register used for the platform calling convention's return value.
    pub fn set_return_value(&mut self, value: usize) -> Result<(), CpuContextError> {
        match self.cpu_context {
            CpuContextType::ReadOnly(_) => Err(CpuContextError::ReadOnly),
            CpuContextType::ReadWrite(_) => {
                unsafe {
                    gum_sys::gum_cpu_context_replace_return_value(
                        self.as_mut_ptr(),
                        value as *mut c_void,
                    )
                };
                Ok(())
            }
        }
    }

    REG_LIST!(cpu_accesors);

    #[cfg(target_arch = "aarch64")]
    /// Get the value of the specified general purpose register.
    pub fn reg(&self, index: usize) -> u64 {
        assert!(index < 29);
        unsafe { (*self.as_ptr()).x[index] }
    }

    #[cfg(target_arch = "aarch64")]
    /// Set the value of the specified general purpose register.
    pub fn set_reg(&mut self, index: usize, value: u64) -> Result<(), CpuContextError> {
        match self.cpu_context {
            CpuContextType::ReadOnly(_) => Err(CpuContextError::ReadOnly),
            CpuContextType::ReadWrite(_) => {
                assert!(index < 29);
                unsafe { (*self.as_mut_ptr()).x[index] = value };
                Ok(())
            }
        }
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get an accurate backtrace from this CPU context.
    pub fn backtrace_accurate(&self) -> Vec<usize> {
        crate::Backtracer::accurate_with_context(unsafe { &*self.as_ptr() })
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get a fuzzy backtrace from this CPU context.
    pub fn backtrace_fuzzy(&self) -> Vec<usize> {
        crate::Backtracer::fuzzy_with_context(unsafe { &*self.as_ptr() })
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get an accurate backtrace from this CPU context.
    pub fn backtrace_accurate_with_limit(&self, limit: u32) -> Vec<usize> {
        crate::Backtracer::accurate_with_context_and_limit(unsafe { &*self.as_ptr() }, limit)
    }

    #[cfg(feature = "backtrace")]
    #[cfg_attr(docsrs, doc(cfg(feature = "backtrace")))]
    /// Get a fuzzy backtrace from this CPU context.
    pub fn backtrace_fuzzy_with_limit(&self, limit: u32) -> Vec<usize> {
        crate::Backtracer::fuzzy_with_context_and_limit(unsafe { &*self.as_ptr() }, limit)
    }
}

REG_LIST!(gen_debug);
