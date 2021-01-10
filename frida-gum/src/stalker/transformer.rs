use crate::{CpuContext, Gum};
use std::marker::PhantomData;
use std::os::raw::c_void;

pub struct StalkerIterator<'a> {
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerIterator>,
}

unsafe extern "C" fn spring1<F>(
    cpu_context: *mut frida_gum_sys::GumCpuContext,
    user_data: *mut c_void,
) where
    F: FnMut(CpuContext),
{
    let user_data = &mut *(user_data as *mut F);
    user_data(CpuContext::from_raw(cpu_context));
}

fn get_trampoline1<F>(_closure: &F) -> frida_gum_sys::GumStalkerCallout
where
    F: FnMut(CpuContext),
{
    Some(spring1::<F>)
}

// IntoIterator is what you want to implement !!!
impl<'a> StalkerIterator<'a> {
    fn from_raw(iterator: *mut frida_gum_sys::GumStalkerIterator) -> StalkerIterator<'a> {
        StalkerIterator {
            iterator,
            phantom: PhantomData,
        }
    }

    pub fn keep_instr(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.iterator) };
    }

    pub fn put_callout(&self, mut callout: impl FnMut(CpuContext)) {
        unsafe {
            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.iterator,
                get_trampoline1(&callout),
                &mut callout as *mut _ as *mut c_void,
                None,
            )
        };
    }
}

use frida_gum_sys::cs_insn;

pub struct Instruction<'a> {
    parent: *mut frida_gum_sys::GumStalkerIterator,
    _instr: *const cs_insn,
    phantom: PhantomData<&'a *const cs_insn>,
}

impl<'a> Instruction<'a> {
    fn from_raw(
        parent: *mut frida_gum_sys::GumStalkerIterator,
        instr: *const cs_insn,
    ) -> Instruction<'a> {
        Instruction {
            parent,
            _instr: instr,
            phantom: PhantomData,
        }
    }

    pub fn keep(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.parent) };
    }

    pub fn put_callout(&self, mut callout: impl FnMut(CpuContext)) {
        unsafe {
            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.parent,
                get_trampoline1(&callout),
                &mut callout as *mut _ as *mut c_void,
                None,
            )
        };
    }
}

impl<'a> Iterator for StalkerIterator<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Instruction<'a>> {
        let mut instr: *const cs_insn = std::ptr::null();
        if unsafe { frida_gum_sys::gum_stalker_iterator_next(self.iterator, &mut instr as *mut _) }
            != 0
        {
            Some(Instruction::from_raw(self.iterator, instr))
        } else {
            None
        }
    }
}

pub struct StalkerOutput<'a> {
    pub output: *mut frida_gum_sys::GumStalkerOutput,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerOutput>,
}

impl<'a> StalkerOutput<'a> {
    fn from_raw(output: *mut frida_gum_sys::GumStalkerOutput) -> StalkerOutput<'a> {
        StalkerOutput {
            output,
            phantom: PhantomData,
        }
    }
}

unsafe extern "C" fn spring<F>(
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    output: *mut frida_gum_sys::GumStalkerOutput,
    user_data: *mut c_void,
) where
    F: FnMut(StalkerIterator, StalkerOutput),
{
    let user_data = &mut *(user_data as *mut F);
    user_data(
        StalkerIterator::from_raw(iterator),
        StalkerOutput::from_raw(output),
    );
}

fn get_trampoline<F>(_closure: &F) -> frida_gum_sys::GumStalkerTransformerCallback
where
    F: FnMut(StalkerIterator, StalkerOutput),
{
    Some(spring::<F>)
}

pub struct Transformer<'a> {
    pub(crate) transformer: *mut frida_gum_sys::GumStalkerTransformer,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerTransformer>,
}

// FIXME(keegan) the FnMut should be Send + Sync and have a lifetime of the
// Transformer
impl<'a> Transformer<'a> {
    pub fn from_callback<'b>(
        _gum: &'b Gum,
        mut callback: impl FnMut(StalkerIterator, StalkerOutput),
    ) -> Transformer<'a>
    where
        'b: 'a,
    {
        Transformer {
            transformer: unsafe {
                frida_gum_sys::gum_stalker_transformer_make_from_callback(
                    get_trampoline(&callback),
                    &mut callback as *mut _ as *mut c_void,
                    None,
                )
            },
            phantom: PhantomData,
        }
    }
}

impl<'a> Drop for Transformer<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::_frida_g_object_unref(self.transformer as *mut c_void) }
    }
}
