/*
 * Copyright © 2020-2021 Keegan Saunders
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Runtime queries about the host CPU and memory subsystem.

use {
    crate::{MemoryRange, NativePointer},
    bitflags::bitflags,
    frida_gum_sys as gum_sys,
};

bitflags! {
    /// Bit flags describing optional CPU features detected at runtime.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct CpuFeatures: u32 {
        /// AVX2 extensions (Intel/AMD).
        const AVX2 = gum_sys::_GumCpuFeatures_GUM_CPU_AVX2 as u32;
        /// Control-flow Enforcement Technology — Shadow Stack.
        const CET_SS = gum_sys::_GumCpuFeatures_GUM_CPU_CET_SS as u32;
        /// ARM Thumb interworking support.
        const THUMB_INTERWORK = gum_sys::_GumCpuFeatures_GUM_CPU_THUMB_INTERWORK as u32;
        /// ARM VFPv2.
        const VFP2 = gum_sys::_GumCpuFeatures_GUM_CPU_VFP2 as u32;
        /// ARM VFPv3.
        const VFP3 = gum_sys::_GumCpuFeatures_GUM_CPU_VFP3 as u32;
        /// 32 double-precision floating-point registers.
        const VFPD32 = gum_sys::_GumCpuFeatures_GUM_CPU_VFPD32 as u32;
        /// Pointer authentication (ARMv8.3-A).
        const PTRAUTH = gum_sys::_GumCpuFeatures_GUM_CPU_PTRAUTH as u32;
    }
}

/// Pointer authentication support level (ARMv8.3-A).
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PtrauthSupport {
    /// Could not be determined.
    Invalid = gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_INVALID as u32,
    /// Pointer authentication is not supported.
    Unsupported = gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_UNSUPPORTED as u32,
    /// Pointer authentication is supported.
    Supported = gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_SUPPORTED as u32,
}

/// Level of support for pages mapped read-write-execute.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RwxSupport {
    /// RWX pages are not allowed at all.
    None = gum_sys::_GumRwxSupport_GUM_RWX_NONE as u32,
    /// RWX is only permitted for newly allocated pages.
    AllocationsOnly = gum_sys::_GumRwxSupport_GUM_RWX_ALLOCATIONS_ONLY as u32,
    /// Full RWX including existing pages.
    Full = gum_sys::_GumRwxSupport_GUM_RWX_FULL as u32,
}

/// Static interface to Frida's runtime queries.
pub struct Query;

impl Query {
    /// Get the CPU feature bits detected at runtime.
    pub fn cpu_features() -> CpuFeatures {
        CpuFeatures::from_bits_truncate(unsafe { gum_sys::gum_query_cpu_features() })
    }

    /// Get the host's pointer authentication support level.
    pub fn ptrauth_support() -> PtrauthSupport {
        let raw = unsafe { gum_sys::gum_query_ptrauth_support() };
        match raw {
            x if x == gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_SUPPORTED as u32 => {
                PtrauthSupport::Supported
            }
            x if x == gum_sys::_GumPtrauthSupport_GUM_PTRAUTH_UNSUPPORTED as u32 => {
                PtrauthSupport::Unsupported
            }
            _ => PtrauthSupport::Invalid,
        }
    }

    /// Get the system page size.
    pub fn page_size() -> u32 {
        unsafe { gum_sys::gum_query_page_size() }
    }

    /// Check whether RWX memory is supported on this host.
    pub fn is_rwx_supported() -> bool {
        unsafe { gum_sys::gum_query_is_rwx_supported() != 0 }
    }

    /// Get the RWX support level on this host.
    pub fn rwx_support() -> RwxSupport {
        let raw = unsafe { gum_sys::gum_query_rwx_support() };
        match raw {
            x if x == gum_sys::_GumRwxSupport_GUM_RWX_FULL as u32 => RwxSupport::Full,
            x if x == gum_sys::_GumRwxSupport_GUM_RWX_ALLOCATIONS_ONLY as u32 => {
                RwxSupport::AllocationsOnly
            }
            _ => RwxSupport::None,
        }
    }

    /// Find the allocation range containing the specified memory.
    ///
    /// Returns the [`MemoryRange`] describing the allocation that contains
    /// the given pointer, or `None` if the pointer does not belong to any
    /// known allocation.
    ///
    /// # Safety
    ///
    /// `mem` must point to a region of at least `size` bytes that is part of
    /// a single allocation visible to Frida.
    pub unsafe fn page_allocation_range(mem: NativePointer, size: u32) -> Option<MemoryRange> {
        let mut raw: gum_sys::GumMemoryRange = core::mem::zeroed();
        gum_sys::gum_query_page_allocation_range(mem.0, size, &mut raw);
        if raw.size == 0 {
            None
        } else {
            Some(MemoryRange::new(
                NativePointer(raw.base_address as *mut core::ffi::c_void),
                raw.size as usize,
            ))
        }
    }
}
