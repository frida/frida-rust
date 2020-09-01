use std::marker::PhantomData;
use std::os::raw::c_void;

use crate::Gum;
use frida_gum_sys;

#[cfg(feature = "event-sink")]
mod event_sink;
#[cfg(feature = "event-sink")]
pub use event_sink::*;

mod transformer;
pub use transformer::*;

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

    // GUM_API void gum_stalker_exclude (GumStalker * self,
    //     const GumMemoryRange * range);

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

    #[cfg(feature = "event-sink")]
    pub fn follow_me<S: EventSink>(&mut self, transformer: Transformer, event_sink: &mut S) {
        unsafe {
            frida_gum_sys::gum_stalker_follow_me(
                self.stalker,
                transformer.transformer,
                event_sink_transform(event_sink),
            );
        }
    }

    #[cfg(not(feature = "event-sink"))]
    pub fn follow_me(&mut self, transformer: Transformer) {
        unsafe {
            frida_gum_sys::gum_stalker_follow_me(
                self.stalker,
                transformer.transformer,
                std::ptr::null_mut(),
            );
        }
    }

    pub fn unfollow_me(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_unfollow_me(self.stalker) };
    }

    // GUM_API void gum_stalker_follow_me (GumStalker * self,
    //     GumStalkerTransformer * transformer, GumEventSink * sink);
    // GUM_API void gum_stalker_unfollow_me (GumStalker * self);
    // GUM_API gboolean gum_stalker_is_following_me (GumStalker * self);
}

impl<'a> Drop for Stalker<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.stalker as *mut c_void) };
    }
}
