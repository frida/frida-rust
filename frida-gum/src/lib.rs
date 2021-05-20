/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Gum bindings for Rust
//!
//! Gum provides a number of utilities for instrumenting binary applications,
//! and traditionally is consumed via the JavaScript API known as GumJS.
//! This crate aims to provide a complete interface to the instrumentation
//! API provided by Gum, rather than GumJS (s.t. these bindings exclude the `Java` and `ObjC`
//! modules).
//!
//! # Quick Start
//! First, ensure that your platform is supported by Gum. You can find a listing of
//! development kits on the [Frida releases page](https://github.com/frida/frida/releases).
//! To get started using Gum, you need to obtain a global [`Gum`] object; this is required
//! to safely ensure that Gum has been properly initialized as required. Next, you are
//! free to use any available APIs, such as the [`stalker::Stalker`]:
//! ```
//! use frida_gum::{Gum, stalker::{Stalker, Transformer, NoneEventSink}};
//! use lazy_static::lazy_static;
//!
//! lazy_static! {
//!     static ref GUM: Gum = unsafe { Gum::obtain() };
//! }
//!
//! fn main() {
//!     let mut stalker = Stalker::new(&GUM);
//!
//!     let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
//!         for instr in basic_block {
//!             instr.keep();
//!         }
//!     });
//!
//!     stalker.follow_me::<NoneEventSink>(&transformer, None);
//!     stalker.unfollow_me();
//! }
//! ```

#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![deny(warnings)]
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::missing_safety_doc)]

extern crate num;
#[allow(unused_imports)]
#[macro_use]
extern crate num_derive;

use std::os::raw::c_void;

pub mod stalker;

pub mod interceptor;

pub mod instruction_writer;

mod module;
pub use module::*;

mod module_map;
pub use module_map::*;

mod cpu_context;
pub use cpu_context::*;

mod memory_range;
pub use memory_range::*;

mod range_details;
pub use range_details::*;

#[cfg(feature = "backtrace")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "backtrace")))]
mod backtracer;
#[cfg(feature = "backtrace")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "backtrace")))]
pub use backtracer::*;

/// Context required for instantiation of all structures under the Gum namespace.
pub struct Gum;

impl Gum {
    /// Obtain a Gum handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Gum runtime is
    /// already initialized.
    pub unsafe fn obtain() -> Gum {
        frida_gum_sys::gum_init_embedded();
        Gum {}
    }
}

impl Drop for Gum {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::gum_deinit_embedded() };
    }
}

pub struct NativePointer(pub *mut c_void);

impl NativePointer {
    /// Check if the pointer is NULL.
    pub fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
