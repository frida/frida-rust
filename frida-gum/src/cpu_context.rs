use frida_gum_sys as gum_sys;
use gum_sys::GumCpuContext;
use paste::paste;
use std::marker::PhantomData;
use std::os::raw::c_void;

macro_rules! cpu_accesors {
    ($reg:ty,$($name:ident),*) => {
        $(
            pub fn $name(&self) -> $reg {
                unsafe { (*self.cpu_context).$name }
            }

            paste! {
                pub fn [<set_ $name>](&mut self, $name: $reg) {
                    unsafe { (*self.cpu_context).$name = $name }
                }
            }
        )*
    }
}

pub struct CpuContext<'a> {
    cpu_context: *mut GumCpuContext,
    phantom: PhantomData<&'a GumCpuContext>,
}

impl<'a> CpuContext<'a> {
    pub(crate) fn from_raw(cpu_context: *mut GumCpuContext) -> CpuContext<'a> {
        CpuContext {
            cpu_context: cpu_context,
            phantom: PhantomData,
        }
    }

    pub fn get_arg(&self, n: u32) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_nth_argument(self.cpu_context, n) as usize }
    }

    pub fn replace_arg(&mut self, n: u32, value: usize) {
        unsafe {
            gum_sys::gum_cpu_context_replace_nth_argument(self.cpu_context, n, value as *mut c_void)
        };
    }

    pub fn get_return(&self) -> usize {
        unsafe { gum_sys::gum_cpu_context_get_return_value(self.cpu_context) as usize }
    }

    pub fn replace_return(&mut self, value: usize) {
        unsafe {
            gum_sys::gum_cpu_context_replace_return_value(self.cpu_context, value as *mut c_void)
        };
    }

    #[cfg(target_arch = "x86_64")]
    cpu_accesors!(
        u64, rip, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax
    );

    #[cfg(target_arch = "x86")]
    cpu_accesors!(u32, eip, edi, esi, ebp, esp, ebx, edx, ecx, eax);

    #[cfg(target_arch = "arm")]
    cpu_accesors!(u32, cpsr, pc, sp, r8, r9, r10, r11, r12, lr);
    // TODO(meme) uint32_t r[8];

    #[cfg(target_arch = "arm64")]
    cpu_accesors!(u64, pc, sp, fp, lr);
    // TODO(meme) uint8_t q[128]; uint64_t x[29];
}
