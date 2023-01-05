/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_gum_sys as gum_sys;
use std::os::raw::c_void;

#[cfg_attr(doc_cfg, doc(cfg(feature = "stalker-observer")))]
pub trait StalkerObserver {
    fn notify_backpatch(&mut self, backpatch: *const gum_sys::GumBackpatch, size: gum_sys::gsize);
    fn switch_callback(
        &mut self,
        from_address: gum_sys::gpointer,
        start_address: gum_sys::gpointer,
        from_insn: gum_sys::gpointer,
        target: &mut gum_sys::gpointer,
    );
}

unsafe extern "C" fn notify_backpatch<S: StalkerObserver>(
    user_data: *mut c_void,
    backpatch: *const gum_sys::GumBackpatch,
    size: gum_sys::gsize,
) {
    let stalker_observer: &mut S = &mut *(user_data as *mut S);
    stalker_observer.notify_backpatch(backpatch, size);
}

unsafe extern "C" fn switch_callback<S: StalkerObserver>(
    user_data: *mut c_void,
    from_address: gum_sys::gpointer,
    start_address: gum_sys::gpointer,
    from_insn: gum_sys::gpointer,
    target: *mut gum_sys::gpointer,
) {
    let stalker_observer: &mut S = &mut *(user_data as *mut S);
    stalker_observer.switch_callback(from_address, start_address, from_insn, &mut *target);
}

pub(crate) fn stalker_observer_transform<S: StalkerObserver>(
    mut stalker_observer: &S,
) -> *mut frida_gum_sys::GumStalkerObserver {
    let rust = frida_gum_sys::RustStalkerObserverVTable {
        user_data: &mut stalker_observer as *mut _ as *mut c_void,
        notify_backpatch: Some(notify_backpatch::<S>),
        switch_callback: Some(switch_callback::<S>),
    };

    unsafe { frida_gum_sys::gum_rust_stalker_observer_new(rust) }
}
