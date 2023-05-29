#![allow(clippy::unnecessary_cast)]
use frida_gum_sys as gum_sys;

#[repr(u32)]
pub enum X86BranchCondition {
    Jo = gum_sys::x86_insn::X86_INS_JO as u32,
    Jno = gum_sys::x86_insn::X86_INS_JNO as u32,
    Jb = gum_sys::x86_insn::X86_INS_JB as u32,
    Jae = gum_sys::x86_insn::X86_INS_JAE as u32,
    Je = gum_sys::x86_insn::X86_INS_JE as u32,
    Jne = gum_sys::x86_insn::X86_INS_JNE as u32,
    Jbe = gum_sys::x86_insn::X86_INS_JBE as u32,
    Ja = gum_sys::x86_insn::X86_INS_JA as u32,
    Js = gum_sys::x86_insn::X86_INS_JS as u32,
    Jns = gum_sys::x86_insn::X86_INS_JNS as u32,
    Jp = gum_sys::x86_insn::X86_INS_JP as u32,
    Jnp = gum_sys::x86_insn::X86_INS_JNP as u32,
    Jl = gum_sys::x86_insn::X86_INS_JL as u32,
    Jge = gum_sys::x86_insn::X86_INS_JGE as u32,
    Jle = gum_sys::x86_insn::X86_INS_JLE as u32,
    Jg = gum_sys::x86_insn::X86_INS_JG as u32,
    Jcxz = gum_sys::x86_insn::X86_INS_JCXZ as u32,
    Jecxz = gum_sys::x86_insn::X86_INS_JECXZ as u32,
    Jrcxz = gum_sys::x86_insn::X86_INS_JRCXZ as u32,
}

impl From<X86BranchCondition> for gum_sys::x86_insn {
    fn from(cond: X86BranchCondition) -> gum_sys::x86_insn {
        match cond {
            X86BranchCondition::Jo => gum_sys::x86_insn::X86_INS_JO,
            X86BranchCondition::Jno => gum_sys::x86_insn::X86_INS_JNO,
            X86BranchCondition::Jb => gum_sys::x86_insn::X86_INS_JB,
            X86BranchCondition::Jae => gum_sys::x86_insn::X86_INS_JAE,
            X86BranchCondition::Je => gum_sys::x86_insn::X86_INS_JE,
            X86BranchCondition::Jne => gum_sys::x86_insn::X86_INS_JNE,
            X86BranchCondition::Jbe => gum_sys::x86_insn::X86_INS_JBE,
            X86BranchCondition::Ja => gum_sys::x86_insn::X86_INS_JA,
            X86BranchCondition::Js => gum_sys::x86_insn::X86_INS_JS,
            X86BranchCondition::Jns => gum_sys::x86_insn::X86_INS_JNS,
            X86BranchCondition::Jp => gum_sys::x86_insn::X86_INS_JP,
            X86BranchCondition::Jnp => gum_sys::x86_insn::X86_INS_JNP,
            X86BranchCondition::Jl => gum_sys::x86_insn::X86_INS_JL,
            X86BranchCondition::Jge => gum_sys::x86_insn::X86_INS_JGE,
            X86BranchCondition::Jle => gum_sys::x86_insn::X86_INS_JLE,
            X86BranchCondition::Jg => gum_sys::x86_insn::X86_INS_JG,
            X86BranchCondition::Jcxz => gum_sys::x86_insn::X86_INS_JCXZ,
            X86BranchCondition::Jecxz => gum_sys::x86_insn::X86_INS_JECXZ,
            X86BranchCondition::Jrcxz => gum_sys::x86_insn::X86_INS_JRCXZ,
        }
    }
}
