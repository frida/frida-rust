pub use frida_gum_sys;
use std::marker::PhantomData;
use std::os::raw::c_void;

use crate::Gum;

// GumStalkerTransformerCallback(GumstalkerIterator * iterator, GumStalkerOutput * output, gpointer
// user_data)

pub struct StalkerIterator<'a> {
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerIterator>,
}

impl<'a> StalkerIterator<'a> {
    fn from_raw(iterator: *mut frida_gum_sys::GumStalkerIterator) -> StalkerIterator<'a> {
        StalkerIterator {
            iterator,
            phantom: PhantomData,
        }
    }
}

pub struct StalkerOutput<'a> {
    output: *mut frida_gum_sys::GumStalkerOutput,
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

pub fn get_trampoline<F>(_closure: &F) -> frida_gum_sys::GumStalkerTransformerCallback
where
    F: FnMut(StalkerIterator, StalkerOutput),
{
    Some(spring::<F>)
}

pub struct Transformer<'a> {
    transformer: *mut frida_gum_sys::GumStalkerTransformer,
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

pub struct Stalker<'a> {
    stalker: *mut frida_gum_sys::GumStalker,
    phantom: PhantomData<&'a frida_gum_sys::GumStalker>,
}

impl<'a> Stalker<'a> {
    pub fn is_supported(_gum: &Gum) -> bool {
        unsafe { frida_gum_sys::gum_stalker_is_supported() != 0 }
    }

    pub fn new<'b>(_gum: &'b Gum) -> Stalker
    where
        'b: 'a,
    {
        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new() },
            phantom: PhantomData,
        }
    }

    pub fn set_trust_threshold(&mut self, threshold: i32) {
        unsafe { frida_gum_sys::gum_stalker_set_trust_threshold(self.stalker, threshold) };
    }

    pub fn get_trust_threshold(&self) -> i32 {
        unsafe { frida_gum_sys::gum_stalker_get_trust_threshold(self.stalker) }
    }

    pub fn flush(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_flush(self.stalker) }
    }

    pub fn stop(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_stop(self.stalker) }
    }

    pub fn garbage_collect(&mut self) -> bool {
        unsafe { frida_gum_sys::gum_stalker_garbage_collect(self.stalker) != 0 }
    }
}

impl<'a> Drop for Stalker<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.stalker as *mut c_void) };
    }
}
