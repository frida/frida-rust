/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Stack-unwinding broker for dynamically generated code.
//!
//! The [`UnwindBroker`] is a process-wide singleton that lets unwinders make
//! sense of code that has no static unwind information — for example, the
//! trampolines and relocated code produced by the [`crate::stalker::Stalker`]
//! and [`crate::interceptor::Interceptor`]. Frida registers its own providers
//! and translators automatically; this wrapper exposes the broker so that
//! additional [`GumUnwindSectionsProvider`]/[`GumUnwindPcTranslator`]
//! implementations can be (de)registered, and the provider/translator vtable
//! entries can be invoked directly.
//!
//! [`GumUnwindSectionsProvider`]: gum_sys::GumUnwindSectionsProvider
//! [`GumUnwindPcTranslator`]: gum_sys::GumUnwindPcTranslator
//!
//! Implementing a *custom* provider or translator from Rust requires a C-side
//! GObject that conforms to the interface vtable; the devkit ships no generic
//! constructor for these, so the registration methods here take raw
//! `*mut Gum…` handles obtained elsewhere (e.g. from Frida internals or a
//! bespoke `frida-gum-sys` shim).

use {
    crate::{MemoryRange, NativePointer},
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
};

/// Process-wide broker coordinating unwind information for generated code.
pub struct UnwindBroker {
    inner: *mut gum_sys::GumUnwindBroker,
}

impl UnwindBroker {
    /// Obtain the global unwind broker.
    pub fn obtain() -> Self {
        Self {
            inner: unsafe { gum_sys::gum_unwind_broker_obtain() },
        }
    }

    /// Register a sections provider with the broker.
    ///
    /// # Safety
    ///
    /// `provider` must be a valid `GumUnwindSectionsProvider` that outlives its
    /// registration (remove it with
    /// [`UnwindBroker::remove_sections_provider`] before it is destroyed).
    pub unsafe fn add_sections_provider(&self, provider: *mut gum_sys::GumUnwindSectionsProvider) {
        unsafe { gum_sys::gum_unwind_broker_add_sections_provider(self.inner, provider) };
    }

    /// Deregister a previously added sections provider.
    ///
    /// # Safety
    ///
    /// `provider` must have been registered with
    /// [`UnwindBroker::add_sections_provider`] on this broker.
    pub unsafe fn remove_sections_provider(
        &self,
        provider: *mut gum_sys::GumUnwindSectionsProvider,
    ) {
        unsafe { gum_sys::gum_unwind_broker_remove_sections_provider(self.inner, provider) };
    }

    /// Register a program-counter translator with the broker.
    ///
    /// # Safety
    ///
    /// `translator` must be a valid `GumUnwindPcTranslator` that outlives its
    /// registration (remove it with [`UnwindBroker::remove_pc_translator`]
    /// before it is destroyed).
    pub unsafe fn add_pc_translator(&self, translator: *mut gum_sys::GumUnwindPcTranslator) {
        unsafe { gum_sys::gum_unwind_broker_add_pc_translator(self.inner, translator) };
    }

    /// Deregister a previously added program-counter translator.
    ///
    /// # Safety
    ///
    /// `translator` must have been registered with
    /// [`UnwindBroker::add_pc_translator`] on this broker.
    pub unsafe fn remove_pc_translator(&self, translator: *mut gum_sys::GumUnwindPcTranslator) {
        unsafe { gum_sys::gum_unwind_broker_remove_pc_translator(self.inner, translator) };
    }
}

impl Drop for UnwindBroker {
    fn drop(&mut self) {
        unsafe { gum_sys::g_object_unref(self.inner as *mut c_void) };
    }
}

/// Query the memory range covered by a sections provider.
///
/// # Safety
///
/// `provider` must be a valid `GumUnwindSectionsProvider`.
pub unsafe fn sections_provider_range(
    provider: *mut gum_sys::GumUnwindSectionsProvider,
) -> Option<MemoryRange> {
    let range = unsafe { gum_sys::gum_unwind_sections_provider_get_range(provider) };
    if range.is_null() {
        None
    } else {
        Some(MemoryRange::from_raw(range))
    }
}

/// Fill `info` with the unwind sections covering `address`.
///
/// Returns `true` if the provider supplied sections for the address.
///
/// # Safety
///
/// `provider` must be a valid `GumUnwindSectionsProvider` and `info` must point
/// to storage of the layout the provider expects for the host platform.
pub unsafe fn sections_provider_fill(
    provider: *mut gum_sys::GumUnwindSectionsProvider,
    address: u64,
    info: NativePointer,
) -> bool {
    unsafe { gum_sys::gum_unwind_sections_provider_fill(provider, address, info.0) != 0 }
}

/// Translate a code address through a PC translator.
///
/// # Safety
///
/// `translator` must be a valid `GumUnwindPcTranslator`.
pub unsafe fn pc_translator_translate(
    translator: *mut gum_sys::GumUnwindPcTranslator,
    code_address: u64,
) -> u64 {
    unsafe { gum_sys::gum_unwind_pc_translator_translate(translator, code_address) }
}

/// Install a resume context for a translated address.
///
/// Returns `true` if the translator installed the context.
///
/// # Safety
///
/// `translator` must be a valid `GumUnwindPcTranslator` and `unwind_context`
/// must point to a valid host unwind context.
pub unsafe fn pc_translator_install_resume_context(
    translator: *mut gum_sys::GumUnwindPcTranslator,
    unwind_context: NativePointer,
    real_resume_ip: u64,
) -> bool {
    unsafe {
        gum_sys::gum_unwind_pc_translator_install_resume_context(
            translator,
            unwind_context.0,
            real_resume_ip,
        ) != 0
    }
}
