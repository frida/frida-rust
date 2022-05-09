/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Code tracing engine.
//!
//! More details about the Frida Stalker can be found on the [Stalker page](https://frida.re/docs/stalker/)
//! of the Frida documentation.
//!
//! The Rust interface to the Stalker provides a best-effort "safe" interface,
//! but naturally runtime code modification takes great caution and
//! these bindings cannot prevent all types of misbehaviour resulting in misuse
//! of the Stalker interface.
//!
//! # Examples
//! To trace the current thread with the Stalker, create a new [`Stalker`] and [`Transformer`] and call
//! [`Stalker::follow_me()`]:
//! ```
//! # use frida_gum::Gum;
//! # use frida_gum::stalker::{Stalker, Transformer};
//! #[cfg(feature = "event-sink")]
//! use frida_gum::stalker::NoneEventSink;
//! let gum = unsafe { Gum::obtain() };
//! let mut stalker = Stalker::new(&gum);
//!
//! let transformer = Transformer::from_callback(&gum, |basic_block, _output| {
//!     for instr in basic_block {
//!         instr.keep();
//!     }
//! });
//!
//! #[cfg(feature = "event-sink")]
//! stalker.follow_me::<NoneEventSink>(&transformer, None);
//!
//! #[cfg(not(feature = "event-sink"))]
//! stalker.follow_me(&transformer);
//!
//! stalker.unfollow_me();
//! ```

use frida_gum_sys as gum_sys;
use std::marker::PhantomData;
use std::os::raw::c_void;

use crate::{Gum, MemoryRange, NativePointer};

#[cfg(feature = "event-sink")]
mod event_sink;
#[cfg(feature = "event-sink")]
pub use event_sink::*;

mod transformer;
pub use transformer::*;

#[cfg(feature = "event-sink")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "event-sink")))]
pub struct NoneEventSink;

#[cfg(feature = "event-sink")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "event-sink")))]
impl EventSink for NoneEventSink {
    fn query_mask(&mut self) -> EventMask {
        unreachable!()
    }

    fn start(&mut self) {
        unreachable!()
    }

    fn process(&mut self, _event: &Event) {
        unreachable!()
    }

    fn flush(&mut self) {
        unreachable!()
    }

    fn stop(&mut self) {
        unreachable!()
    }
}

/// Code tracing engine interface.
pub struct Stalker<'a> {
    stalker: *mut frida_gum_sys::GumStalker,
    phantom: PhantomData<&'a frida_gum_sys::GumStalker>,
}

impl<'a> Stalker<'a> {
    /// Checks if the Stalker is supported on the current platform.
    pub fn is_supported(_gum: &Gum) -> bool {
        unsafe { frida_gum_sys::gum_stalker_is_supported() != 0 }
    }

    /// Create a new Stalker.
    ///
    /// This call has the overhead of checking if the Stalker is
    /// available on the current platform, as creating a Stalker on an
    /// unsupported platform results in unwanted behaviour.
    pub fn new<'b>(gum: &'b Gum) -> Stalker
    where
        'b: 'a,
    {
        assert!(Self::is_supported(gum));

        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new() },
            phantom: PhantomData,
        }
    }

    /// Exclude a range of address from the Stalker engine.
    ///
    /// This exclusion will prevent the Stalker from tracing into the memory range,
    /// reducing instrumentation overhead as well as potential noise from the [`EventSink`].
    pub fn exclude(&mut self, range: &MemoryRange) {
        unsafe { gum_sys::gum_stalker_exclude(self.stalker, &range.memory_range as *const _) };
    }

    /// Set how many times a piece of code needs to be executed before it is assumed it can be
    /// trusted to not mutate.
    ///
    /// Specify -1 for no trust (slow), 0 to trust code from the get-go,
    /// and N to trust code after it has been executed N times. Defaults to 1.
    pub fn set_trust_threshold(&mut self, threshold: i32) {
        unsafe { gum_sys::gum_stalker_set_trust_threshold(self.stalker, threshold) };
    }

    /// Get the Stalker trust treshold, see [`Stalker::set_trust_threshold()`] for more details.
    pub fn get_trust_threshold(&self) -> i32 {
        unsafe { gum_sys::gum_stalker_get_trust_threshold(self.stalker) }
    }

    /// Flush all buffered events.
    pub fn flush(&mut self) {
        unsafe { gum_sys::gum_stalker_flush(self.stalker) }
    }

    pub fn stop(&mut self) {
        unsafe { gum_sys::gum_stalker_stop(self.stalker) }
    }

    /// Free accumulated memory at a safe point after [`Stalker::unfollow_me()`].
    ///
    /// This is needed to avoid race-conditions where the thread just unfollowed is executing its last instructions.
    pub fn garbage_collect(&mut self) -> bool {
        unsafe { gum_sys::gum_stalker_garbage_collect(self.stalker) != 0 }
    }

    /// Begin the Stalker on the current thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    ///
    /// If reusing an existing [`Transformer`], make sure to call [`Stalker::garbage_collect()`]
    /// periodically.
    #[cfg(feature = "event-sink")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "event-sink")))]
    pub fn follow_me<S: EventSink>(
        &mut self,
        transformer: &Transformer,
        event_sink: Option<&mut S>,
    ) {
        let sink = if let Some(sink) = event_sink {
            event_sink_transform(sink)
        } else {
            std::ptr::null_mut()
        };

        unsafe { gum_sys::gum_stalker_follow_me(self.stalker, transformer.transformer, sink) };
    }

    /// Begin the Stalker on the current thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    ///
    /// If reusing an existing [`Transformer`], make sure to call [`Stalker::garbage_collect()`]
    /// periodically.
    #[cfg(not(feature = "event-sink"))]
    #[cfg_attr(doc_cfg, doc(cfg(not(feature = "event-sink"))))]
    pub fn follow_me(&mut self, transformer: &Transformer) {
        unsafe {
            gum_sys::gum_stalker_follow_me(
                self.stalker,
                transformer.transformer,
                std::ptr::null_mut(),
            )
        };
    }

    /// Stop stalking the current thread.
    pub fn unfollow_me(&mut self) {
        unsafe { gum_sys::gum_stalker_unfollow_me(self.stalker) };
    }

    /// Check if the Stalker is running on the current thread.
    pub fn is_following_me(&mut self) -> bool {
        unsafe { gum_sys::gum_stalker_is_following_me(self.stalker) != 0 }
    }

    /// Re-activate the Stalker at the specified start point.
    pub fn activate(&mut self, start: NativePointer) {
        unsafe { gum_sys::gum_stalker_activate(self.stalker, start.0) }
    }

    /// Pause the Stalker.
    pub fn deactivate(&mut self) {
        unsafe { gum_sys::gum_stalker_deactivate(self.stalker) }
    }

    /// Enable (experimental) unwind hooking
    pub fn enable_unwind_hooking(&mut self) {
        unsafe { gum_sys::gum_stalker_activate_experimental_unwind_support() }
    }
}

impl<'a> Drop for Stalker<'a> {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.stalker as *mut c_void) };
    }
}
