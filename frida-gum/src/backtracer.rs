/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Backtracer helpers.
//!

use {core::mem::MaybeUninit, frida_gum_sys as gum_sys};

// The following function is not exposed through the `frida-gum.h` header, so we don't have an
// auto-generated binding for it. This may change in a future version.
extern "C" {
    // On some platforms `ucontext` contains a u128 which does not have a defined ABI. In this case,
    // we disable the error as we assume the behaviour is correct (all other platforms are unaffected).
    #[cfg(target_os = "linux")]
    #[allow(improper_ctypes)]
    fn gum_linux_parse_ucontext(
        context: *const libc::ucontext_t,
        cpu_context: *mut gum_sys::GumCpuContext,
    );

    #[cfg(target_os = "freebsd")]
    #[allow(improper_ctypes)]
    fn gum_freebsd_parse_ucontext(
        context: *const libc::ucontext_t,
        cpu_context: *mut gum_sys::GumCpuContext,
    );
}

pub struct Backtracer;

impl Backtracer {
    /// Generate a backtrace stopping after 'limit' entries
    fn generate_with_limit(
        backtracer: *mut gum_sys::GumBacktracer,
        context: *const gum_sys::GumCpuContext,
        limit: gum_sys::guint,
    ) -> Vec<usize> {
        let mut return_address_array = MaybeUninit::<gum_sys::_GumReturnAddressArray>::uninit();

        unsafe {
            gum_sys::gum_backtracer_generate_with_limit(
                backtracer,
                context,
                return_address_array.as_mut_ptr(),
                limit,
            );
            let return_address_array = return_address_array.assume_init();
            let mut result = vec![];
            for i in 0..return_address_array.len {
                result.push(*return_address_array.items.get(i as usize).unwrap() as usize);
            }
            result
        }
    }

    /// Generate an accurate backtrace as a list of return addresses from the current context
    pub fn accurate() -> Vec<usize> {
        Self::accurate_with_limit(gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate an accurate backtrace as a list of return addresses from the current context
    /// stopping after 'limit' entries
    pub fn accurate_with_limit(limit: u32) -> Vec<usize> {
        Self::generate_with_limit(
            unsafe { gum_sys::gum_backtracer_make_accurate() },
            core::ptr::null(),
            limit,
        )
    }

    /// Generate a fuzzy backtrace as a list of return addresses from the current context
    pub fn fuzzy() -> Vec<usize> {
        Self::fuzzy_with_limit(gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate a fuzzy backtrace as a list of return addresses from the current context stopping
    /// after 'limit' entries.
    pub fn fuzzy_with_limit(limit: u32) -> Vec<usize> {
        Self::generate_with_limit(
            unsafe { gum_sys::gum_backtracer_make_fuzzy() },
            core::ptr::null(),
            limit,
        )
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied cpu
    /// context.
    pub fn accurate_with_context(context: &gum_sys::GumCpuContext) -> Vec<usize> {
        Self::accurate_with_context_and_limit(context, gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied cpu
    /// context stopping after 'limit' entries.
    pub fn accurate_with_context_and_limit(
        context: &gum_sys::GumCpuContext,
        limit: u32,
    ) -> Vec<usize> {
        Self::generate_with_limit(
            unsafe { gum_sys::gum_backtracer_make_accurate() },
            context as *const gum_sys::GumCpuContext,
            limit,
        )
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied cpu
    /// context.
    pub fn fuzzy_with_context(context: &gum_sys::GumCpuContext) -> Vec<usize> {
        Self::fuzzy_with_context_and_limit(&context, gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied cpu
    /// context stopping after 'limit' entries.
    pub fn fuzzy_with_context_and_limit(
        context: &gum_sys::GumCpuContext,
        limit: u32,
    ) -> Vec<usize> {
        Self::generate_with_limit(
            unsafe { gum_sys::gum_backtracer_make_fuzzy() },
            context as *const gum_sys::GumCpuContext,
            limit,
        )
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied signal
    /// context.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn accurate_with_signal_context(context: &libc::ucontext_t) -> Vec<usize> {
        Self::accurate_with_signal_context_and_limit(context, gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate an accurate backtrace as a list of return addresses for the supplied signal
    /// context stopping after 'limit' entries.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn accurate_with_signal_context_and_limit(
        context: &libc::ucontext_t,
        limit: u32,
    ) -> Vec<usize> {
        let mut cpu_context = MaybeUninit::<gum_sys::GumCpuContext>::uninit();

        unsafe {
            #[cfg(target_os = "linux")]
            gum_linux_parse_ucontext(context as *const libc::ucontext_t, cpu_context.as_mut_ptr());
            #[cfg(target_os = "freebsd")]
            gum_freebsd_parse_ucontext(
                context as *const libc::ucontext_t,
                cpu_context.as_mut_ptr(),
            );
            Self::accurate_with_context_and_limit(&cpu_context.assume_init(), limit)
        }
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied signal
    /// context.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]

    pub fn fuzzy_with_signal_context(context: &libc::ucontext_t) -> Vec<usize> {
        Self::fuzzy_with_signal_context_and_limit(context, gum_sys::GUM_MAX_BACKTRACE_DEPTH)
    }

    /// Generate a fuzzy backtrace as a list of return addresses for the supplied signal
    /// context stopping after 'limit' entries
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub fn fuzzy_with_signal_context_and_limit(
        context: &libc::ucontext_t,
        limit: u32,
    ) -> Vec<usize> {
        let mut cpu_context = MaybeUninit::<gum_sys::GumCpuContext>::uninit();

        unsafe {
            #[cfg(target_os = "linux")]
            gum_linux_parse_ucontext(context as *const libc::ucontext_t, cpu_context.as_mut_ptr());
            #[cfg(target_os = "freebsd")]
            gum_freebsd_parse_ucontext(
                context as *const libc::ucontext_t,
                cpu_context.as_mut_ptr(),
            );
            Self::fuzzy_with_context_and_limit(&cpu_context.assume_init(), limit)
        }
    }
}
