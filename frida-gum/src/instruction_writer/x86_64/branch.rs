#![allow(clippy::unnecessary_cast)]

use frida_gum_sys as gum_sys;

#[repr(u32)]
pub enum X86BranchCondition {
    Jo = gum_sys::x86_insn_X86_INS_JO as u32,
    Jno = gum_sys::x86_insn_X86_INS_JNO as u32,
    Jb = gum_sys::x86_insn_X86_INS_JB as u32,
    Jae = gum_sys::x86_insn_X86_INS_JAE as u32,
    Je = gum_sys::x86_insn_X86_INS_JE as u32,
    Jne = gum_sys::x86_insn_X86_INS_JNE as u32,
    Jbe = gum_sys::x86_insn_X86_INS_JBE as u32,
    Ja = gum_sys::x86_insn_X86_INS_JA as u32,
    Js = gum_sys::x86_insn_X86_INS_JS as u32,
    Jns = gum_sys::x86_insn_X86_INS_JNS as u32,
    Jp = gum_sys::x86_insn_X86_INS_JP as u32,
    Jnp = gum_sys::x86_insn_X86_INS_JNP as u32,
    Jl = gum_sys::x86_insn_X86_INS_JL as u32,
    Jge = gum_sys::x86_insn_X86_INS_JGE as u32,
    Jle = gum_sys::x86_insn_X86_INS_JLE as u32,
    Jg = gum_sys::x86_insn_X86_INS_JG as u32,
    Jcxz = gum_sys::x86_insn_X86_INS_JCXZ as u32,
    Jecxz = gum_sys::x86_insn_X86_INS_JECXZ as u32,
    Jrcxz = gum_sys::x86_insn_X86_INS_JRCXZ as u32,
}
