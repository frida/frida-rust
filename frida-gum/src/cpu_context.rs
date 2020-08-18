use frida_gum_sys::GumCpuContext;
use std::marker::PhantomData;

pub struct CpuContext<'a> {
    cpu_context: *mut GumCpuContext,
    phantom: PhantomData<&'a GumCpuContext>,
}

impl<'a> CpuContext<'a> {
    pub(crate) fn from_raw(cpu_context: *mut GumCpuContext) -> CpuContext<'a> {
        CpuContext {
            cpu_context,
            phantom: PhantomData,
        }
    }
}
