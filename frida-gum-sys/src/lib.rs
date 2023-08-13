/*
 * Copyright © 2020-2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

#[cfg(not(any(target_os = "windows", target_os = "android", target_vendor = "apple",)))]
pub use _frida_g_object_unref as g_object_unref;

/// A single disassembled CPU instruction.
#[repr(transparent)]
pub struct Insn {
    /// Inner `cs_insn`
    pub(crate) insn: cs_insn,
}

#[allow(clippy::len_without_is_empty)]
impl Insn {
    /// Create an `Insn` from a raw pointer to a [`capstone_sys::cs_insn`].
    ///
    /// This function serves to allow integration with libraries which generate `capstone_sys::cs_insn`'s internally.
    ///
    /// # Safety
    ///
    /// Note that this function is unsafe, and assumes that you know what you are doing. In
    /// particular, it generates a lifetime for the `Insn` from nothing, and that lifetime is in
    /// no-way actually tied to the cs_insn itself. It is the responsibility of the caller to
    /// ensure that the resulting `Insn` lives only as long as the `cs_insn`. This function
    /// assumes that the pointer passed is non-null and a valid `cs_insn` pointer.
    ///
    /// The caller is fully responsible for the backing allocations lifetime, including freeing.
    pub unsafe fn from_raw(insn: *const cs_insn) -> Self {
        Self {
            insn: core::ptr::read(insn),
        }
    }

    /// Size of instruction (in bytes)
    #[inline]
    #[allow(clippy::unnecessary_cast)]
    pub fn len(&self) -> usize {
        self.insn.size as usize
    }

    /// Instruction address
    #[inline]
    #[allow(clippy::unnecessary_cast)]
    pub fn address(&self) -> u64 {
        self.insn.address as u64
    }

    /// Byte-level representation of the instruction
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.insn.bytes[..self.len()]
    }
}
