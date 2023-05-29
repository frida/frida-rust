#![allow(clippy::unnecessary_cast)]

use frida_gum_sys as gum_sys;

#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum X86Register {
    Eax = gum_sys::_GumX86Reg::GUM_X86_EAX as u32,
    Ecx = gum_sys::_GumX86Reg::GUM_X86_ECX as u32,
    Edx = gum_sys::_GumX86Reg::GUM_X86_EDX as u32,
    Ebx = gum_sys::_GumX86Reg::GUM_X86_EBX as u32,
    Esp = gum_sys::_GumX86Reg::GUM_X86_ESP as u32,
    Ebp = gum_sys::_GumX86Reg::GUM_X86_EBP as u32,
    Esi = gum_sys::_GumX86Reg::GUM_X86_ESI as u32,
    Edi = gum_sys::_GumX86Reg::GUM_X86_EDI as u32,

    R8d = gum_sys::_GumX86Reg::GUM_X86_R8D as u32,
    R9d = gum_sys::_GumX86Reg::GUM_X86_R9D as u32,
    R10d = gum_sys::_GumX86Reg::GUM_X86_R10D as u32,
    R11d = gum_sys::_GumX86Reg::GUM_X86_R11D as u32,
    R12d = gum_sys::_GumX86Reg::GUM_X86_R12D as u32,
    R13d = gum_sys::_GumX86Reg::GUM_X86_R13D as u32,
    R14d = gum_sys::_GumX86Reg::GUM_X86_R14D as u32,
    R15d = gum_sys::_GumX86Reg::GUM_X86_R15D as u32,

    Eip = gum_sys::_GumX86Reg::GUM_X86_EIP as u32,

    // 64-bit
    Rax = gum_sys::_GumX86Reg::GUM_X86_RAX as u32,
    Rcx = gum_sys::_GumX86Reg::GUM_X86_RCX as u32,
    Rdx = gum_sys::_GumX86Reg::GUM_X86_RDX as u32,
    Rbx = gum_sys::_GumX86Reg::GUM_X86_RBX as u32,
    Rsp = gum_sys::_GumX86Reg::GUM_X86_RSP as u32,
    Rbp = gum_sys::_GumX86Reg::GUM_X86_RBP as u32,
    Rsi = gum_sys::_GumX86Reg::GUM_X86_RSI as u32,
    Rdi = gum_sys::_GumX86Reg::GUM_X86_RDI as u32,

    R8 = gum_sys::_GumX86Reg::GUM_X86_R8 as u32,
    R9 = gum_sys::_GumX86Reg::GUM_X86_R9 as u32,
    R10 = gum_sys::_GumX86Reg::GUM_X86_R10 as u32,
    R11 = gum_sys::_GumX86Reg::GUM_X86_R11 as u32,
    R12 = gum_sys::_GumX86Reg::GUM_X86_R12 as u32,
    R13 = gum_sys::_GumX86Reg::GUM_X86_R13 as u32,
    R14 = gum_sys::_GumX86Reg::GUM_X86_R14 as u32,
    R15 = gum_sys::_GumX86Reg::GUM_X86_R15 as u32,

    Rip = gum_sys::_GumX86Reg::GUM_X86_RIP as u32,

    // Meta
    Xax = gum_sys::_GumX86Reg::GUM_X86_XAX as u32,
    Xcx = gum_sys::_GumX86Reg::GUM_X86_XCX as u32,
    Xdx = gum_sys::_GumX86Reg::GUM_X86_XDX as u32,
    Xbx = gum_sys::_GumX86Reg::GUM_X86_XBX as u32,
    Xsp = gum_sys::_GumX86Reg::GUM_X86_XSP as u32,
    Xbp = gum_sys::_GumX86Reg::GUM_X86_XBP as u32,
    Xsi = gum_sys::_GumX86Reg::GUM_X86_XSI as u32,
    Xdi = gum_sys::_GumX86Reg::GUM_X86_XDI as u32,

    Xip = gum_sys::_GumX86Reg::GUM_X86_XIP as u32,

    None = gum_sys::_GumX86Reg::GUM_X86_NONE as u32,
}
