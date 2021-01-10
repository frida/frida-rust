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
//! let gum = Gum::obtain();
//! let stalker = Stalker::new(&gum);
//!
//! let transformer = Transformer::from_callback(&gum, |basic_block, _output| {
//!     for instr in basic_block {
//!         instr.keep();
//!     }
//! });
//!
//! #[cfg(feature = "event-sink")]
//! stalker.follow_me(transformer, None);
//!
//! #[cfg(not(feature = "event-sink"))]
//! stalker.follow_me(transformer);
//! ```

use frida_gum_sys as gum_sys;
use std::marker::PhantomData;
use std::os::raw::c_void;

use crate::{Gum, MemoryRange};

#[cfg(feature = "event-sink")]
mod event_sink;
#[cfg(feature = "event-sink")]
pub use event_sink::*;

mod transformer;
pub use transformer::*;

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
    /// An [`EventSink`] may be optionally specified, but this is **feature-gated** and must
    /// be specified with the `features = ["event-sink"]` as it is not provided by default.
    #[cfg(feature = "event-sink")]
    pub fn follow_me<S: EventSink>(
        &mut self,
        transformer: Transformer,
        event_sink: Option<&mut S>,
    ) {
        unsafe {
            let sink = if let Some(sink) = event_sink {
                event_sink_transform(sink)
            } else {
                std::ptr::null_mut()
            };

            gum_sys::gum_stalker_follow_me(self.stalker, transformer.transformer, sink);
        }
    }

    /// Begin the Stalker on the current thread.
    ///
    /// A [`Transformer`] must be specified, and will be updated with all events.
    #[cfg(not(feature = "event-sink"))]
    pub fn follow_me(&mut self, transformer: Transformer) {
        unsafe {
            gum_sys::gum_stalker_follow_me(
                self.stalker,
                transformer.transformer,
                std::ptr::null_mut(),
            );
        }
    }

    /// Stop stalking the current thread.
    pub fn unfollow_me(&mut self) {
        unsafe { gum_sys::gum_stalker_unfollow_me(self.stalker) };
    }

    /// Check if the Stalker is running on the current thread.
    pub fn is_following_me(&mut self) -> bool {
        unsafe { gum_sys::gum_stalker_is_following_me(self.stalker) != 0 }
    }
}

impl<'a> Drop for Stalker<'a> {
    fn drop(&mut self) {
        unsafe { gum_sys::_frida_g_object_unref(self.stalker as *mut c_void) };
    }
}
