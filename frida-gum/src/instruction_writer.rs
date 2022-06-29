/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Instruction writer interface.
use frida_gum_sys as gum_sys;
use gum_sys::GumArgument;
#[cfg(target_arch = "x86_64")]
use gum_sys::GumBranchHint;
#[allow(unused_imports)]
use std::convert::TryInto;
use std::ffi::c_void;

use capstone::Insn;
use capstone_sys::cs_insn;

#[cfg(target_arch = "x86_64")]
pub type TargetInstructionWriter = X86InstructionWriter;
#[cfg(target_arch = "x86_64")]
pub type TargetRelocator = X86Relocator;

#[cfg(target_arch = "aarch64")]
pub type TargetInstructionWriter = Aarch64InstructionWriter;
#[cfg(target_arch = "aarch64")]
pub type TargetRelocator = Aarch64Relocator;

#[cfg(target_arch = "x86_64")]
pub type TargetRegister = X86Register;
#[cfg(target_arch = "aarch64")]
pub type TargetRegister = Aarch64Register;
pub enum Argument {
    Register(TargetRegister),
    Address(u64),
}

#[derive(FromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum X86Register {
    Eax = gum_sys::_GumX86Reg_GUM_X86_EAX as u32,
    Ecx = gum_sys::_GumX86Reg_GUM_X86_ECX as u32,
    Edx = gum_sys::_GumX86Reg_GUM_X86_EDX as u32,
    Ebx = gum_sys::_GumX86Reg_GUM_X86_EBX as u32,
    Esp = gum_sys::_GumX86Reg_GUM_X86_ESP as u32,
    Ebp = gum_sys::_GumX86Reg_GUM_X86_EBP as u32,
    Esi = gum_sys::_GumX86Reg_GUM_X86_ESI as u32,
    Edi = gum_sys::_GumX86Reg_GUM_X86_EDI as u32,

    R8d = gum_sys::_GumX86Reg_GUM_X86_R8D as u32,
    R9d = gum_sys::_GumX86Reg_GUM_X86_R9D as u32,
    R10d = gum_sys::_GumX86Reg_GUM_X86_R10D as u32,
    R11d = gum_sys::_GumX86Reg_GUM_X86_R11D as u32,
    R12d = gum_sys::_GumX86Reg_GUM_X86_R12D as u32,
    R13d = gum_sys::_GumX86Reg_GUM_X86_R13D as u32,
    R14d = gum_sys::_GumX86Reg_GUM_X86_R14D as u32,
    R15d = gum_sys::_GumX86Reg_GUM_X86_R15D as u32,

    Eip = gum_sys::_GumX86Reg_GUM_X86_EIP as u32,

    // 64-bit
    Rax = gum_sys::_GumX86Reg_GUM_X86_RAX as u32,
    Rcx = gum_sys::_GumX86Reg_GUM_X86_RCX as u32,
    Rdx = gum_sys::_GumX86Reg_GUM_X86_RDX as u32,
    Rbx = gum_sys::_GumX86Reg_GUM_X86_RBX as u32,
    Rsp = gum_sys::_GumX86Reg_GUM_X86_RSP as u32,
    Rbp = gum_sys::_GumX86Reg_GUM_X86_RBP as u32,
    Rsi = gum_sys::_GumX86Reg_GUM_X86_RSI as u32,
    Rdi = gum_sys::_GumX86Reg_GUM_X86_RDI as u32,

    R8 = gum_sys::_GumX86Reg_GUM_X86_R8 as u32,
    R9 = gum_sys::_GumX86Reg_GUM_X86_R9 as u32,
    R10 = gum_sys::_GumX86Reg_GUM_X86_R10 as u32,
    R11 = gum_sys::_GumX86Reg_GUM_X86_R11 as u32,
    R12 = gum_sys::_GumX86Reg_GUM_X86_R12 as u32,
    R13 = gum_sys::_GumX86Reg_GUM_X86_R13 as u32,
    R14 = gum_sys::_GumX86Reg_GUM_X86_R14 as u32,
    R15 = gum_sys::_GumX86Reg_GUM_X86_R15 as u32,

    Rip = gum_sys::_GumX86Reg_GUM_X86_RIP as u32,

    // Meta
    Xax = gum_sys::_GumX86Reg_GUM_X86_XAX as u32,
    Xcx = gum_sys::_GumX86Reg_GUM_X86_XCX as u32,
    Xdx = gum_sys::_GumX86Reg_GUM_X86_XDX as u32,
    Xbx = gum_sys::_GumX86Reg_GUM_X86_XBX as u32,
    Xsp = gum_sys::_GumX86Reg_GUM_X86_XSP as u32,
    Xbp = gum_sys::_GumX86Reg_GUM_X86_XBP as u32,
    Xsi = gum_sys::_GumX86Reg_GUM_X86_XSI as u32,
    Xdi = gum_sys::_GumX86Reg_GUM_X86_XDI as u32,

    Xip = gum_sys::_GumX86Reg_GUM_X86_XIP as u32,

    None = gum_sys::_GumX86Reg_GUM_X86_NONE as u32,
}

#[derive(FromPrimitive, PartialEq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum Aarch64Register {
    Ffr = gum_sys::arm64_reg_ARM64_REG_FFR as u32,
    Fp = gum_sys::arm64_reg_ARM64_REG_FP as u32,
    Lr = gum_sys::arm64_reg_ARM64_REG_LR as u32,
    Nzcv = gum_sys::arm64_reg_ARM64_REG_NZCV as u32,
    Sp = gum_sys::arm64_reg_ARM64_REG_SP as u32,
    Wsp = gum_sys::arm64_reg_ARM64_REG_WSP as u32,
    Wzr = gum_sys::arm64_reg_ARM64_REG_WZR as u32,
    Xzr = gum_sys::arm64_reg_ARM64_REG_XZR as u32,

    X0 = gum_sys::arm64_reg_ARM64_REG_X0 as u32,
    X1 = gum_sys::arm64_reg_ARM64_REG_X1 as u32,
    X2 = gum_sys::arm64_reg_ARM64_REG_X2 as u32,
    X3 = gum_sys::arm64_reg_ARM64_REG_X3 as u32,
    X4 = gum_sys::arm64_reg_ARM64_REG_X4 as u32,
    X5 = gum_sys::arm64_reg_ARM64_REG_X5 as u32,
    X6 = gum_sys::arm64_reg_ARM64_REG_X6 as u32,
    X7 = gum_sys::arm64_reg_ARM64_REG_X7 as u32,
    X8 = gum_sys::arm64_reg_ARM64_REG_X8 as u32,
    X9 = gum_sys::arm64_reg_ARM64_REG_X9 as u32,
    X10 = gum_sys::arm64_reg_ARM64_REG_X10 as u32,
    X11 = gum_sys::arm64_reg_ARM64_REG_X11 as u32,
    X12 = gum_sys::arm64_reg_ARM64_REG_X12 as u32,
    X13 = gum_sys::arm64_reg_ARM64_REG_X13 as u32,
    X14 = gum_sys::arm64_reg_ARM64_REG_X14 as u32,
    X15 = gum_sys::arm64_reg_ARM64_REG_X15 as u32,
    X16 = gum_sys::arm64_reg_ARM64_REG_X16 as u32,
    X17 = gum_sys::arm64_reg_ARM64_REG_X17 as u32,
    X18 = gum_sys::arm64_reg_ARM64_REG_X18 as u32,
    X19 = gum_sys::arm64_reg_ARM64_REG_X19 as u32,
    X20 = gum_sys::arm64_reg_ARM64_REG_X20 as u32,
    X21 = gum_sys::arm64_reg_ARM64_REG_X21 as u32,
    X22 = gum_sys::arm64_reg_ARM64_REG_X22 as u32,
    X23 = gum_sys::arm64_reg_ARM64_REG_X23 as u32,
    X24 = gum_sys::arm64_reg_ARM64_REG_X24 as u32,
    X25 = gum_sys::arm64_reg_ARM64_REG_X25 as u32,
    X26 = gum_sys::arm64_reg_ARM64_REG_X26 as u32,
    X27 = gum_sys::arm64_reg_ARM64_REG_X27 as u32,
    X28 = gum_sys::arm64_reg_ARM64_REG_X28 as u32,

    W0 = gum_sys::arm64_reg_ARM64_REG_W0 as u32,
    W1 = gum_sys::arm64_reg_ARM64_REG_W1 as u32,
    W2 = gum_sys::arm64_reg_ARM64_REG_W2 as u32,
    W3 = gum_sys::arm64_reg_ARM64_REG_W3 as u32,
    W4 = gum_sys::arm64_reg_ARM64_REG_W4 as u32,
    W5 = gum_sys::arm64_reg_ARM64_REG_W5 as u32,
    W6 = gum_sys::arm64_reg_ARM64_REG_W6 as u32,
    W7 = gum_sys::arm64_reg_ARM64_REG_W7 as u32,
    W8 = gum_sys::arm64_reg_ARM64_REG_W8 as u32,
    W9 = gum_sys::arm64_reg_ARM64_REG_W9 as u32,
    W10 = gum_sys::arm64_reg_ARM64_REG_W10 as u32,
    W11 = gum_sys::arm64_reg_ARM64_REG_W11 as u32,
    W12 = gum_sys::arm64_reg_ARM64_REG_W12 as u32,
    W13 = gum_sys::arm64_reg_ARM64_REG_W13 as u32,
    W14 = gum_sys::arm64_reg_ARM64_REG_W14 as u32,
    W15 = gum_sys::arm64_reg_ARM64_REG_W15 as u32,
    W16 = gum_sys::arm64_reg_ARM64_REG_W16 as u32,
    W17 = gum_sys::arm64_reg_ARM64_REG_W17 as u32,
    W18 = gum_sys::arm64_reg_ARM64_REG_W18 as u32,
    W19 = gum_sys::arm64_reg_ARM64_REG_W19 as u32,
    W20 = gum_sys::arm64_reg_ARM64_REG_W20 as u32,
    W21 = gum_sys::arm64_reg_ARM64_REG_W21 as u32,
    W22 = gum_sys::arm64_reg_ARM64_REG_W22 as u32,
    W23 = gum_sys::arm64_reg_ARM64_REG_W23 as u32,
    W24 = gum_sys::arm64_reg_ARM64_REG_W24 as u32,
    W25 = gum_sys::arm64_reg_ARM64_REG_W25 as u32,
    W26 = gum_sys::arm64_reg_ARM64_REG_W26 as u32,
    W27 = gum_sys::arm64_reg_ARM64_REG_W27 as u32,
    W28 = gum_sys::arm64_reg_ARM64_REG_W28 as u32,
    W29 = gum_sys::arm64_reg_ARM64_REG_W29 as u32,
    W30 = gum_sys::arm64_reg_ARM64_REG_W30 as u32,

    S0 = gum_sys::arm64_reg_ARM64_REG_S0 as u32,
    S1 = gum_sys::arm64_reg_ARM64_REG_S1 as u32,
    S2 = gum_sys::arm64_reg_ARM64_REG_S2 as u32,
    S3 = gum_sys::arm64_reg_ARM64_REG_S3 as u32,
    S4 = gum_sys::arm64_reg_ARM64_REG_S4 as u32,
    S5 = gum_sys::arm64_reg_ARM64_REG_S5 as u32,
    S6 = gum_sys::arm64_reg_ARM64_REG_S6 as u32,
    S7 = gum_sys::arm64_reg_ARM64_REG_S7 as u32,
    S8 = gum_sys::arm64_reg_ARM64_REG_S8 as u32,
    S9 = gum_sys::arm64_reg_ARM64_REG_S9 as u32,
    S10 = gum_sys::arm64_reg_ARM64_REG_S10 as u32,
    S11 = gum_sys::arm64_reg_ARM64_REG_S11 as u32,
    S12 = gum_sys::arm64_reg_ARM64_REG_S12 as u32,
    S13 = gum_sys::arm64_reg_ARM64_REG_S13 as u32,
    S14 = gum_sys::arm64_reg_ARM64_REG_S14 as u32,
    S15 = gum_sys::arm64_reg_ARM64_REG_S15 as u32,
    S16 = gum_sys::arm64_reg_ARM64_REG_S16 as u32,
    S17 = gum_sys::arm64_reg_ARM64_REG_S17 as u32,
    S18 = gum_sys::arm64_reg_ARM64_REG_S18 as u32,
    S19 = gum_sys::arm64_reg_ARM64_REG_S19 as u32,
    S20 = gum_sys::arm64_reg_ARM64_REG_S20 as u32,
    S21 = gum_sys::arm64_reg_ARM64_REG_S21 as u32,
    S22 = gum_sys::arm64_reg_ARM64_REG_S22 as u32,
    S23 = gum_sys::arm64_reg_ARM64_REG_S23 as u32,
    S24 = gum_sys::arm64_reg_ARM64_REG_S24 as u32,
    S25 = gum_sys::arm64_reg_ARM64_REG_S25 as u32,
    S26 = gum_sys::arm64_reg_ARM64_REG_S26 as u32,
    S27 = gum_sys::arm64_reg_ARM64_REG_S27 as u32,
    S28 = gum_sys::arm64_reg_ARM64_REG_S28 as u32,
    S29 = gum_sys::arm64_reg_ARM64_REG_S29 as u32,
    S30 = gum_sys::arm64_reg_ARM64_REG_S30 as u32,
    S31 = gum_sys::arm64_reg_ARM64_REG_S31 as u32,

    H0 = gum_sys::arm64_reg_ARM64_REG_H0 as u32,
    H1 = gum_sys::arm64_reg_ARM64_REG_H1 as u32,
    H2 = gum_sys::arm64_reg_ARM64_REG_H2 as u32,
    H3 = gum_sys::arm64_reg_ARM64_REG_H3 as u32,
    H4 = gum_sys::arm64_reg_ARM64_REG_H4 as u32,
    H5 = gum_sys::arm64_reg_ARM64_REG_H5 as u32,
    H6 = gum_sys::arm64_reg_ARM64_REG_H6 as u32,
    H7 = gum_sys::arm64_reg_ARM64_REG_H7 as u32,
    H8 = gum_sys::arm64_reg_ARM64_REG_H8 as u32,
    H9 = gum_sys::arm64_reg_ARM64_REG_H9 as u32,
    H10 = gum_sys::arm64_reg_ARM64_REG_H10 as u32,
    H11 = gum_sys::arm64_reg_ARM64_REG_H11 as u32,
    H12 = gum_sys::arm64_reg_ARM64_REG_H12 as u32,
    H13 = gum_sys::arm64_reg_ARM64_REG_H13 as u32,
    H14 = gum_sys::arm64_reg_ARM64_REG_H14 as u32,
    H15 = gum_sys::arm64_reg_ARM64_REG_H15 as u32,
    H16 = gum_sys::arm64_reg_ARM64_REG_H16 as u32,
    H17 = gum_sys::arm64_reg_ARM64_REG_H17 as u32,
    H18 = gum_sys::arm64_reg_ARM64_REG_H18 as u32,
    H19 = gum_sys::arm64_reg_ARM64_REG_H19 as u32,
    H20 = gum_sys::arm64_reg_ARM64_REG_H20 as u32,
    H21 = gum_sys::arm64_reg_ARM64_REG_H21 as u32,
    H22 = gum_sys::arm64_reg_ARM64_REG_H22 as u32,
    H23 = gum_sys::arm64_reg_ARM64_REG_H23 as u32,
    H24 = gum_sys::arm64_reg_ARM64_REG_H24 as u32,
    H25 = gum_sys::arm64_reg_ARM64_REG_H25 as u32,
    H26 = gum_sys::arm64_reg_ARM64_REG_H26 as u32,
    H27 = gum_sys::arm64_reg_ARM64_REG_H27 as u32,
    H28 = gum_sys::arm64_reg_ARM64_REG_H28 as u32,
    H29 = gum_sys::arm64_reg_ARM64_REG_H29 as u32,
    H30 = gum_sys::arm64_reg_ARM64_REG_H30 as u32,
    H31 = gum_sys::arm64_reg_ARM64_REG_H31 as u32,

    B0 = gum_sys::arm64_reg_ARM64_REG_B0 as u32,
    B1 = gum_sys::arm64_reg_ARM64_REG_B1 as u32,
    B2 = gum_sys::arm64_reg_ARM64_REG_B2 as u32,
    B3 = gum_sys::arm64_reg_ARM64_REG_B3 as u32,
    B4 = gum_sys::arm64_reg_ARM64_REG_B4 as u32,
    B5 = gum_sys::arm64_reg_ARM64_REG_B5 as u32,
    B6 = gum_sys::arm64_reg_ARM64_REG_B6 as u32,
    B7 = gum_sys::arm64_reg_ARM64_REG_B7 as u32,
    B8 = gum_sys::arm64_reg_ARM64_REG_B8 as u32,
    B9 = gum_sys::arm64_reg_ARM64_REG_B9 as u32,
    B10 = gum_sys::arm64_reg_ARM64_REG_B10 as u32,
    B11 = gum_sys::arm64_reg_ARM64_REG_B11 as u32,
    B12 = gum_sys::arm64_reg_ARM64_REG_B12 as u32,
    B13 = gum_sys::arm64_reg_ARM64_REG_B13 as u32,
    B14 = gum_sys::arm64_reg_ARM64_REG_B14 as u32,
    B15 = gum_sys::arm64_reg_ARM64_REG_B15 as u32,
    B16 = gum_sys::arm64_reg_ARM64_REG_B16 as u32,
    B17 = gum_sys::arm64_reg_ARM64_REG_B17 as u32,
    B18 = gum_sys::arm64_reg_ARM64_REG_B18 as u32,
    B19 = gum_sys::arm64_reg_ARM64_REG_B19 as u32,
    B20 = gum_sys::arm64_reg_ARM64_REG_B20 as u32,
    B21 = gum_sys::arm64_reg_ARM64_REG_B21 as u32,
    B22 = gum_sys::arm64_reg_ARM64_REG_B22 as u32,
    B23 = gum_sys::arm64_reg_ARM64_REG_B23 as u32,
    B24 = gum_sys::arm64_reg_ARM64_REG_B24 as u32,
    B25 = gum_sys::arm64_reg_ARM64_REG_B25 as u32,
    B26 = gum_sys::arm64_reg_ARM64_REG_B26 as u32,
    B27 = gum_sys::arm64_reg_ARM64_REG_B27 as u32,
    B28 = gum_sys::arm64_reg_ARM64_REG_B28 as u32,
    B29 = gum_sys::arm64_reg_ARM64_REG_B29 as u32,
    B30 = gum_sys::arm64_reg_ARM64_REG_B30 as u32,
    B31 = gum_sys::arm64_reg_ARM64_REG_B31 as u32,

    D0 = gum_sys::arm64_reg_ARM64_REG_D0 as u32,
    D1 = gum_sys::arm64_reg_ARM64_REG_D1 as u32,
    D2 = gum_sys::arm64_reg_ARM64_REG_D2 as u32,
    D3 = gum_sys::arm64_reg_ARM64_REG_D3 as u32,
    D4 = gum_sys::arm64_reg_ARM64_REG_D4 as u32,
    D5 = gum_sys::arm64_reg_ARM64_REG_D5 as u32,
    D6 = gum_sys::arm64_reg_ARM64_REG_D6 as u32,
    D7 = gum_sys::arm64_reg_ARM64_REG_D7 as u32,
    D8 = gum_sys::arm64_reg_ARM64_REG_D8 as u32,
    D9 = gum_sys::arm64_reg_ARM64_REG_D9 as u32,
    D10 = gum_sys::arm64_reg_ARM64_REG_D10 as u32,
    D11 = gum_sys::arm64_reg_ARM64_REG_D11 as u32,
    D12 = gum_sys::arm64_reg_ARM64_REG_D12 as u32,
    D13 = gum_sys::arm64_reg_ARM64_REG_D13 as u32,
    D14 = gum_sys::arm64_reg_ARM64_REG_D14 as u32,
    D15 = gum_sys::arm64_reg_ARM64_REG_D15 as u32,
    D16 = gum_sys::arm64_reg_ARM64_REG_D16 as u32,
    D17 = gum_sys::arm64_reg_ARM64_REG_D17 as u32,
    D18 = gum_sys::arm64_reg_ARM64_REG_D18 as u32,
    D19 = gum_sys::arm64_reg_ARM64_REG_D19 as u32,
    D20 = gum_sys::arm64_reg_ARM64_REG_D20 as u32,
    D21 = gum_sys::arm64_reg_ARM64_REG_D21 as u32,
    D22 = gum_sys::arm64_reg_ARM64_REG_D22 as u32,
    D23 = gum_sys::arm64_reg_ARM64_REG_D23 as u32,
    D24 = gum_sys::arm64_reg_ARM64_REG_D24 as u32,
    D25 = gum_sys::arm64_reg_ARM64_REG_D25 as u32,
    D26 = gum_sys::arm64_reg_ARM64_REG_D26 as u32,
    D27 = gum_sys::arm64_reg_ARM64_REG_D27 as u32,
    D28 = gum_sys::arm64_reg_ARM64_REG_D28 as u32,
    D29 = gum_sys::arm64_reg_ARM64_REG_D29 as u32,
    D30 = gum_sys::arm64_reg_ARM64_REG_D30 as u32,
    D31 = gum_sys::arm64_reg_ARM64_REG_D31 as u32,

    Q0 = gum_sys::arm64_reg_ARM64_REG_Q0 as u32,
    Q1 = gum_sys::arm64_reg_ARM64_REG_Q1 as u32,
    Q2 = gum_sys::arm64_reg_ARM64_REG_Q2 as u32,
    Q3 = gum_sys::arm64_reg_ARM64_REG_Q3 as u32,
    Q4 = gum_sys::arm64_reg_ARM64_REG_Q4 as u32,
    Q5 = gum_sys::arm64_reg_ARM64_REG_Q5 as u32,
    Q6 = gum_sys::arm64_reg_ARM64_REG_Q6 as u32,
    Q7 = gum_sys::arm64_reg_ARM64_REG_Q7 as u32,
    Q8 = gum_sys::arm64_reg_ARM64_REG_Q8 as u32,
    Q9 = gum_sys::arm64_reg_ARM64_REG_Q9 as u32,
    Q10 = gum_sys::arm64_reg_ARM64_REG_Q10 as u32,
    Q11 = gum_sys::arm64_reg_ARM64_REG_Q11 as u32,
    Q12 = gum_sys::arm64_reg_ARM64_REG_Q12 as u32,
    Q13 = gum_sys::arm64_reg_ARM64_REG_Q13 as u32,
    Q14 = gum_sys::arm64_reg_ARM64_REG_Q14 as u32,
    Q15 = gum_sys::arm64_reg_ARM64_REG_Q15 as u32,
    Q16 = gum_sys::arm64_reg_ARM64_REG_Q16 as u32,
    Q17 = gum_sys::arm64_reg_ARM64_REG_Q17 as u32,
    Q18 = gum_sys::arm64_reg_ARM64_REG_Q18 as u32,
    Q19 = gum_sys::arm64_reg_ARM64_REG_Q19 as u32,
    Q20 = gum_sys::arm64_reg_ARM64_REG_Q20 as u32,
    Q21 = gum_sys::arm64_reg_ARM64_REG_Q21 as u32,
    Q22 = gum_sys::arm64_reg_ARM64_REG_Q22 as u32,
    Q23 = gum_sys::arm64_reg_ARM64_REG_Q23 as u32,
    Q24 = gum_sys::arm64_reg_ARM64_REG_Q24 as u32,
    Q25 = gum_sys::arm64_reg_ARM64_REG_Q25 as u32,
    Q26 = gum_sys::arm64_reg_ARM64_REG_Q26 as u32,
    Q27 = gum_sys::arm64_reg_ARM64_REG_Q27 as u32,
    Q28 = gum_sys::arm64_reg_ARM64_REG_Q28 as u32,
    Q29 = gum_sys::arm64_reg_ARM64_REG_Q29 as u32,
    Q30 = gum_sys::arm64_reg_ARM64_REG_Q30 as u32,
    Q31 = gum_sys::arm64_reg_ARM64_REG_Q31 as u32,

    Z0 = gum_sys::arm64_reg_ARM64_REG_Z0 as u32,
    Z1 = gum_sys::arm64_reg_ARM64_REG_Z1 as u32,
    Z2 = gum_sys::arm64_reg_ARM64_REG_Z2 as u32,
    Z3 = gum_sys::arm64_reg_ARM64_REG_Z3 as u32,
    Z4 = gum_sys::arm64_reg_ARM64_REG_Z4 as u32,
    Z5 = gum_sys::arm64_reg_ARM64_REG_Z5 as u32,
    Z6 = gum_sys::arm64_reg_ARM64_REG_Z6 as u32,
    Z7 = gum_sys::arm64_reg_ARM64_REG_Z7 as u32,
    Z8 = gum_sys::arm64_reg_ARM64_REG_Z8 as u32,
    Z9 = gum_sys::arm64_reg_ARM64_REG_Z9 as u32,
    Z10 = gum_sys::arm64_reg_ARM64_REG_Z10 as u32,
    Z11 = gum_sys::arm64_reg_ARM64_REG_Z11 as u32,
    Z12 = gum_sys::arm64_reg_ARM64_REG_Z12 as u32,
    Z13 = gum_sys::arm64_reg_ARM64_REG_Z13 as u32,
    Z14 = gum_sys::arm64_reg_ARM64_REG_Z14 as u32,
    Z15 = gum_sys::arm64_reg_ARM64_REG_Z15 as u32,
    Z16 = gum_sys::arm64_reg_ARM64_REG_Z16 as u32,
    Z17 = gum_sys::arm64_reg_ARM64_REG_Z17 as u32,
    Z18 = gum_sys::arm64_reg_ARM64_REG_Z18 as u32,
    Z19 = gum_sys::arm64_reg_ARM64_REG_Z19 as u32,
    Z20 = gum_sys::arm64_reg_ARM64_REG_Z20 as u32,
    Z21 = gum_sys::arm64_reg_ARM64_REG_Z21 as u32,
    Z22 = gum_sys::arm64_reg_ARM64_REG_Z22 as u32,
    Z23 = gum_sys::arm64_reg_ARM64_REG_Z23 as u32,
    Z24 = gum_sys::arm64_reg_ARM64_REG_Z24 as u32,
    Z25 = gum_sys::arm64_reg_ARM64_REG_Z25 as u32,
    Z26 = gum_sys::arm64_reg_ARM64_REG_Z26 as u32,
    Z27 = gum_sys::arm64_reg_ARM64_REG_Z27 as u32,
    Z28 = gum_sys::arm64_reg_ARM64_REG_Z28 as u32,
    Z29 = gum_sys::arm64_reg_ARM64_REG_Z29 as u32,
    Z30 = gum_sys::arm64_reg_ARM64_REG_Z30 as u32,
    Z31 = gum_sys::arm64_reg_ARM64_REG_Z31 as u32,

    V0 = gum_sys::arm64_reg_ARM64_REG_V0 as u32,
    V1 = gum_sys::arm64_reg_ARM64_REG_V1 as u32,
    V2 = gum_sys::arm64_reg_ARM64_REG_V2 as u32,
    V3 = gum_sys::arm64_reg_ARM64_REG_V3 as u32,
    V4 = gum_sys::arm64_reg_ARM64_REG_V4 as u32,
    V5 = gum_sys::arm64_reg_ARM64_REG_V5 as u32,
    V6 = gum_sys::arm64_reg_ARM64_REG_V6 as u32,
    V7 = gum_sys::arm64_reg_ARM64_REG_V7 as u32,
    V8 = gum_sys::arm64_reg_ARM64_REG_V8 as u32,
    V9 = gum_sys::arm64_reg_ARM64_REG_V9 as u32,
    V10 = gum_sys::arm64_reg_ARM64_REG_V10 as u32,
    V11 = gum_sys::arm64_reg_ARM64_REG_V11 as u32,
    V12 = gum_sys::arm64_reg_ARM64_REG_V12 as u32,
    V13 = gum_sys::arm64_reg_ARM64_REG_V13 as u32,
    V14 = gum_sys::arm64_reg_ARM64_REG_V14 as u32,
    V15 = gum_sys::arm64_reg_ARM64_REG_V15 as u32,
    V16 = gum_sys::arm64_reg_ARM64_REG_V16 as u32,
    V17 = gum_sys::arm64_reg_ARM64_REG_V17 as u32,
    V18 = gum_sys::arm64_reg_ARM64_REG_V18 as u32,
    V19 = gum_sys::arm64_reg_ARM64_REG_V19 as u32,
    V20 = gum_sys::arm64_reg_ARM64_REG_V20 as u32,
    V21 = gum_sys::arm64_reg_ARM64_REG_V21 as u32,
    V22 = gum_sys::arm64_reg_ARM64_REG_V22 as u32,
    V23 = gum_sys::arm64_reg_ARM64_REG_V23 as u32,
    V24 = gum_sys::arm64_reg_ARM64_REG_V24 as u32,
    V25 = gum_sys::arm64_reg_ARM64_REG_V25 as u32,
    V26 = gum_sys::arm64_reg_ARM64_REG_V26 as u32,
    V27 = gum_sys::arm64_reg_ARM64_REG_V27 as u32,
    V28 = gum_sys::arm64_reg_ARM64_REG_V28 as u32,
    V29 = gum_sys::arm64_reg_ARM64_REG_V29 as u32,
    V30 = gum_sys::arm64_reg_ARM64_REG_V30 as u32,
    V31 = gum_sys::arm64_reg_ARM64_REG_V31 as u32,
}

#[cfg(target_arch = "aarch64")]
#[derive(FromPrimitive)]
#[repr(u32)]
pub enum IndexMode {
    PostAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_POST_ADJUST,
    SignedOffset = gum_sys::_GumArm64IndexMode_GUM_INDEX_SIGNED_OFFSET,
    PreAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_PRE_ADJUST,
}

/// A trait all [`InstructionWriter`]s share.
pub trait InstructionWriter {
    /// Create a new [`InstructionWriter`] to write code to the given address
    fn new(code_address: u64) -> Self;

    /// Retrieve the writer's current program counter.
    fn pc(&self) -> u64;

    /// Retrieve the writer's current code offset.
    fn code_offset(&self) -> u64;

    /// Check if we can branch directly between the given source and target addresses.
    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool;

    /// Check if we can branch directly to the target address from the current
    /// program counter.
    fn can_branch_directly_to(&self, target: u64) -> bool {
        self.can_branch_directly_between(self.pc(), target)
    }

    /// Add the bytes specified to the instruction stream.
    fn put_bytes(&self, bytes: &[u8]) -> bool;

    /// Add a label at the curent point in the instruction stream.
    fn put_label(&self, id: u64) -> bool;

    /// Reset the writer to the given code address
    fn reset(&self, code_address: u64);

    /// Add a branch to an immediate address
    fn put_branch_address(&self, address: u64) -> bool;

    /// Flush the writer, outputing any pending ldr-immediates
    fn flush(&self) -> bool;
}

/// The x86/x86_64 instruction writer.
#[cfg(target_arch = "x86_64")]
pub struct X86InstructionWriter {
    writer: *mut gum_sys::_GumX86Writer,
    is_from_new: bool,
}

#[cfg(target_arch = "x86_64")]
impl InstructionWriter for X86InstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_x86_writer_new(code_address as *mut c_void) },
            is_from_new: true,
        }
    }

    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_can_branch_directly_between(source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32);
            true
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_x86_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_x86_writer_flush(self.writer) != 0 }
    }
}

#[cfg(target_arch = "x86_64")]
impl X86InstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumX86Writer) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    pub fn put_leave(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_leave(self.writer);
        }
        true
    }

    pub fn put_ret(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_ret(self.writer);
        }
        true
    }

    pub fn put_ret_imm(&self, imm: u16) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_ret_imm(self.writer, imm);
        }
        true
    }

    pub fn put_jmp_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    pub fn put_jmp_short_label(&self, id: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_short_label(self.writer, id as *const c_void);
        }
        true
    }

    /// Insert a `jmp` near to a label. The label is specified by `id`.
    pub fn put_jmp_near_label(&self, id: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_near_label(self.writer, id as *const c_void);
        }
        true
    }

    pub fn put_jmp_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_ptr(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg_ptr(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_offset_ptr(&self, reg: X86Register, offset: i64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_reg_offset_ptr(self.writer, reg as u32, offset) != 0
        }
    }

    pub fn put_jmp_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_near_ptr(self.writer, address) != 0 }
    }

    pub fn put_jcc_short_label(
        &self,
        instruction_mnemonic: &str,
        label_id: u64,
        hint: GumBranchHint,
    ) {
        let instruction_id = match instruction_mnemonic {
            "jo" => gum_sys::x86_insn_X86_INS_JO,
            "jno" => gum_sys::x86_insn_X86_INS_JNO,
            "jb" => gum_sys::x86_insn_X86_INS_JB,
            "jae" => gum_sys::x86_insn_X86_INS_JAE,
            "je" => gum_sys::x86_insn_X86_INS_JE,
            "jne" => gum_sys::x86_insn_X86_INS_JNE,
            "jbe" => gum_sys::x86_insn_X86_INS_JBE,
            "ja" => gum_sys::x86_insn_X86_INS_JA,
            "js" => gum_sys::x86_insn_X86_INS_JS,
            "jns" => gum_sys::x86_insn_X86_INS_JNS,
            "jp" => gum_sys::x86_insn_X86_INS_JP,
            "jnp" => gum_sys::x86_insn_X86_INS_JNP,
            "jl" => gum_sys::x86_insn_X86_INS_JL,
            "jge" => gum_sys::x86_insn_X86_INS_JGE,
            "jle" => gum_sys::x86_insn_X86_INS_JLE,
            "jg" => gum_sys::x86_insn_X86_INS_JG,
            "jcxz" => gum_sys::x86_insn_X86_INS_JCXZ,
            "jecxz" => gum_sys::x86_insn_X86_INS_JECXZ,
            "jrcxz" => gum_sys::x86_insn_X86_INS_JRCXZ,
            _ => {
                unimplemented!();
            }
        };

        unsafe {
            gum_sys::gum_x86_writer_put_jcc_short_label(
                self.writer,
                instruction_id,
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_jcc_near_label(
        &self,
        instruction_mnemonic: &str,
        label_id: u64,
        hint: GumBranchHint,
    ) {
        let instruction_id = match instruction_mnemonic {
            "jo" => gum_sys::x86_insn_X86_INS_JO,
            "jno" => gum_sys::x86_insn_X86_INS_JNO,
            "jb" => gum_sys::x86_insn_X86_INS_JB,
            "jae" => gum_sys::x86_insn_X86_INS_JAE,
            "je" => gum_sys::x86_insn_X86_INS_JE,
            "jne" => gum_sys::x86_insn_X86_INS_JNE,
            "jbe" => gum_sys::x86_insn_X86_INS_JBE,
            "ja" => gum_sys::x86_insn_X86_INS_JA,
            "js" => gum_sys::x86_insn_X86_INS_JS,
            "jns" => gum_sys::x86_insn_X86_INS_JNS,
            "jp" => gum_sys::x86_insn_X86_INS_JP,
            "jnp" => gum_sys::x86_insn_X86_INS_JNP,
            "jl" => gum_sys::x86_insn_X86_INS_JL,
            "jge" => gum_sys::x86_insn_X86_INS_JGE,
            "jle" => gum_sys::x86_insn_X86_INS_JLE,
            "jg" => gum_sys::x86_insn_X86_INS_JG,
            "jcxz" => gum_sys::x86_insn_X86_INS_JCXZ,
            "jecxz" => gum_sys::x86_insn_X86_INS_JECXZ,
            "jrcxz" => gum_sys::x86_insn_X86_INS_JRCXZ,
            _ => {
                unimplemented!();
            }
        };

        unsafe {
            gum_sys::gum_x86_writer_put_jcc_near_label(
                self.writer,
                instruction_id,
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_mov_reg_gs_u32_ptr(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_gs_u32_ptr(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_add_reg_imm(&self, reg: X86Register, imm: i64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_add_reg_imm(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_add_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_add_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_add_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_add_reg_near_ptr(self.writer, dst_reg as u32, address) != 0
        }
    }

    pub fn put_sub_reg_imm(&self, dst_reg: X86Register, imm: i64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_sub_reg_imm(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_sub_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_sub_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_sub_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_sub_reg_near_ptr(self.writer, dst_reg as u32, address) != 0
        }
    }

    pub fn put_inc_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_inc_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_dec_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_dec_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_and_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_and_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_and_reg_u32(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_and_reg_u32(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_shl_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shl_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_shr_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shr_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_xor_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_xor_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_mov_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_mov_reg_u32(&self, dst_reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u32(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_u64(&self, dst_reg: X86Register, imm: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u64(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_address(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_address(self.writer, dst_reg as u32, address);
        }
        true
    }

    pub fn put_mov_reg_ptr_u32(&self, dst_reg: X86Register, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_u32(self.writer, dst_reg as u32, imm);
        }
        true
    }

    pub fn put_mov_reg_offset_ptr_u32(&self, dst_reg: X86Register, offset: i64, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_u32(
                self.writer,
                dst_reg as u32,
                offset,
                imm,
            ) != 0
        }
    }

    pub fn put_mov_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
        true
    }

    pub fn put_mov_reg_offset_ptr_reg(
        &self,
        dst_reg: X86Register,
        offset: i64,
        src_reg: X86Register,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_reg(
                self.writer,
                dst_reg as u32,
                offset,
                src_reg as u32,
            ) != 0
        }
    }

    pub fn put_mov_reg_reg_ptr(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg_ptr(self.writer, dst_reg as u32, src_reg as u32)
        }
        true
    }

    pub fn put_mov_reg_reg_offset_ptr(
        &self,
        dst_reg: X86Register,
        src_reg: X86Register,
        offset: i64,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg_offset_ptr(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                offset,
            ) != 0
        }
    }

    pub fn put_mov_reg_base_index_scale_offset_ptr(
        &self,
        dst_reg: X86Register,
        base_reg: X86Register,
        index_reg: X86Register,
        scale: u8,
        offset: i64,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr(
                self.writer,
                dst_reg as u32,
                base_reg as u32,
                index_reg as u32,
                scale,
                offset,
            ) != 0
        }
    }

    /// Insert a `lea d, [s + o]` instruction.
    pub fn put_lea_reg_reg_offset(
        &self,
        dst_reg: X86Register,
        src_reg: X86Register,
        src_offset: i64,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_lea_reg_reg_offset(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                src_offset,
            ) != 0
        }
    }

    pub fn put_push_u32(&self, imm: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_push_u32(self.writer, imm);
        }
        true
    }

    pub fn put_push_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_near_ptr(self.writer, address) != 0 }
    }

    /// Insert a `push R` instruction.
    pub fn put_push_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a `pop R` instruction.
    pub fn put_pop_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_pop_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a call address instruction.
    pub fn put_call_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_call_address(self.writer, address) != 0 }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_arguments(&self, address: u64, arguments: &[Argument]) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 {
                            reg: *register as i32,
                        },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_x86_writer_put_call_address_with_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI.into(),
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_aligned_arguments(
        &self,
        address: u64,
        arguments: &[Argument],
    ) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 {
                            reg: *register as i32,
                        },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_x86_writer_put_call_address_with_aligned_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI,
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    pub fn put_test_reg_reg(&self, reg_a: X86Register, reg_b: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_test_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }
    pub fn put_nop(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_nop(self.writer);
        }
        true
    }

    pub fn put_pushfx(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_pushfx(self.writer);
        }
        true
    }

    pub fn put_popfx(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_popfx(self.writer);
        }
        true
    }

    pub fn put_pushax(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_pushax(self.writer);
        }
        true
    }

    pub fn put_popax(&self) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_popax(self.writer);
        }
        true
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for X86InstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_x86_writer_unref(self.writer) }
        }
    }
}

/// The Aarch64 instruction writer.
#[cfg(target_arch = "aarch64")]
pub struct Aarch64InstructionWriter {
    writer: *mut gum_sys::_GumArm64Writer,
    is_from_new: bool,
}

#[cfg(target_arch = "aarch64")]
impl InstructionWriter for Aarch64InstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_arm64_writer_new(code_address as *mut c_void) },
            is_from_new: true,
        }
    }

    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_can_branch_directly_between(self.writer, source, target) != 0
        }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32)
                != 0
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_arm64_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_b_imm(self.writer, address) != 0 }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_arm64_writer_flush(self.writer) != 0 }
    }
}

#[cfg(target_arch = "aarch64")]
impl Aarch64InstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumArm64Writer) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Insert a `b` to a label. The label is specified by `id`.
    pub fn put_b_label(&self, id: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_b_label(self.writer, id as *const c_void) }
    }

    /// Insert a `brk #i` instruction.
    pub fn put_brk_imm(&self, imm: u16) {
        unsafe { gum_sys::gum_arm64_writer_put_brk_imm(self.writer, imm) }
    }

    /// Insert a `sub d, l, r` instruction.
    pub fn put_sub_reg_reg_imm(
        &self,
        dst_reg: Aarch64Register,
        left_reg: Aarch64Register,
        right_value: u64,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_sub_reg_reg_imm(
                self.writer,
                dst_reg as u32,
                left_reg as u32,
                right_value,
            ) != 0
        }
    }

    /// Insert a `add d, l, r` instruction.
    pub fn put_add_reg_reg_imm(
        &self,
        dst_reg: Aarch64Register,
        left_reg: Aarch64Register,
        right_value: u64,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_add_reg_reg_imm(
                self.writer,
                dst_reg as u32,
                left_reg as u32,
                right_value,
            ) != 0
        }
    }

    /// Insert a `add d, l, r` instruction.
    pub fn put_add_reg_reg_reg(
        &self,
        dst_reg: Aarch64Register,
        left_reg: Aarch64Register,
        right_reg: Aarch64Register,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_add_reg_reg_reg(
                self.writer,
                dst_reg as u32,
                left_reg as u32,
                right_reg as u32,
            ) != 0
        }
    }

    /// Insert a `mov d, s` instruction.
    pub fn put_mov_reg_reg(&self, dst_reg: Aarch64Register, src_reg: Aarch64Register) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_mov_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    /// Insert a `stp reg, reg, [reg + o]` instruction.
    pub fn put_stp_reg_reg_reg_offset(
        &self,
        reg_a: Aarch64Register,
        reg_b: Aarch64Register,
        reg_dst: Aarch64Register,
        offset: i64,
        mode: IndexMode,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_stp_reg_reg_reg_offset(
                self.writer,
                reg_a as u32,
                reg_b as u32,
                reg_dst as u32,
                offset,
                mode as u32,
            ) != 0
        }
    }

    /// Insert a `ldr reg, [reg + o]` instruction.
    pub fn put_ldr_reg_reg_offset(
        &self,
        reg_a: Aarch64Register,
        reg_src: Aarch64Register,
        offset: u64,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_ldr_reg_reg_offset(
                self.writer,
                reg_a as u32,
                reg_src as u32,
                offset,
            ) != 0
        }
    }

    pub fn put_str_reg_reg_offset(
        &self,
        reg_src: Aarch64Register,
        reg_dst: Aarch64Register,
        offset: u64,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_str_reg_reg_offset(
                self.writer,
                reg_src as u32,
                reg_dst as u32,
                offset,
            ) != 0
        }
    }

    pub fn put_cmp_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_cmp_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }

    /// Insert a `ldp reg, reg, [reg + o]` instruction.
    pub fn put_ldp_reg_reg_reg_offset(
        &self,
        reg_a: Aarch64Register,
        reg_b: Aarch64Register,
        reg_src: Aarch64Register,
        offset: i64,
        mode: IndexMode,
    ) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_ldp_reg_reg_reg_offset(
                self.writer,
                reg_a as u32,
                reg_b as u32,
                reg_src as u32,
                offset,
                mode as u32,
            ) != 0
        }
    }

    /// Insert a `mov reg, u64` instruction.
    pub fn put_ldr_reg_u64(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_ldr_reg_u64(self.writer, reg as u32, address) != 0 }
    }

    pub fn put_push_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_push_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }
    pub fn put_pop_reg_reg(&self, reg_a: Aarch64Register, reg_b: Aarch64Register) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_pop_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }

    pub fn put_br_reg(&self, reg: Aarch64Register) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_br_reg(self.writer, reg as u32) != 0 }
    }
    pub fn put_ldr_reg_address(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_ldr_reg_address(self.writer, reg as u32, address) != 0
        }
    }
    pub fn put_adrp_reg_address(&self, reg: Aarch64Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_arm64_writer_put_adrp_reg_address(self.writer, reg as u32, address) != 0
        }
    }

    pub fn put_bcond_label(&self, instruction_mnemonic: &str, label_id: u64) {
        let instruction_id = match instruction_mnemonic {
            "eq" => gum_sys::arm64_cc_ARM64_CC_EQ,
            "ne" => gum_sys::arm64_cc_ARM64_CC_NE,
            "hs" => gum_sys::arm64_cc_ARM64_CC_HS,
            "lo" => gum_sys::arm64_cc_ARM64_CC_LO,
            "mi" => gum_sys::arm64_cc_ARM64_CC_MI,
            "pl" => gum_sys::arm64_cc_ARM64_CC_PL,
            "vs" => gum_sys::arm64_cc_ARM64_CC_VS,
            "vc" => gum_sys::arm64_cc_ARM64_CC_VC,
            "hi" => gum_sys::arm64_cc_ARM64_CC_HI,
            "ls" => gum_sys::arm64_cc_ARM64_CC_LS,
            "ge" => gum_sys::arm64_cc_ARM64_CC_GE,
            "lt" => gum_sys::arm64_cc_ARM64_CC_LT,
            "gt" => gum_sys::arm64_cc_ARM64_CC_GT,
            "le" => gum_sys::arm64_cc_ARM64_CC_LE,
            "al" => gum_sys::arm64_cc_ARM64_CC_AL,
            "nv" => gum_sys::arm64_cc_ARM64_CC_NV,
            _ => {
                unimplemented!();
            }
        };

        unsafe {
            gum_sys::gum_arm64_writer_put_b_cond_label(
                self.writer,
                instruction_id,
                label_id as *const c_void,
            )
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_arguments(&self, address: u64, arguments: &[Argument]) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 {
                            reg: *register as i32,
                        },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.into(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_arm64_writer_put_call_address_with_arguments_array(
                self.writer,
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            );
            true
        }
    }

    /// Insert a `bl imm` instruction.
    pub fn put_bl_imm(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_arm64_writer_put_bl_imm(self.writer, address) != 0 }
    }
}

#[cfg(target_arch = "aarch64")]
impl Drop for Aarch64InstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_arm64_writer_unref(self.writer) }
        }
    }
}

pub trait Relocator {
    /// Create a new [`Relocator`] for the input code address, outputting to the specified
    /// [`InstructionWriter`]
    fn new(input_code: u64, output: &mut TargetInstructionWriter) -> Self;

    /// Read one instruction from the input stream
    fn read_one(&mut self) -> (u32, Insn);

    /// Check if the relocator has reached the end of input
    fn eoi(&mut self) -> bool;

    /// Relocate and write all instructions to the output [`InstructionWriter`]
    fn write_all(&mut self);

    /// Relocate and write one instruction to the output [`InstructionWriter`]
    fn write_one(&mut self) -> bool;

    /// Skip one instruction
    fn skip_one(&mut self) -> bool;
}

#[cfg(target_arch = "x86_64")]
pub struct X86Relocator {
    inner: *mut c_void,
}

#[cfg(target_arch = "x86_64")]
impl Relocator for X86Relocator {
    fn new(input_code: u64, output: &mut X86InstructionWriter) -> Self {
        extern "C" {
            fn gum_x86_relocator_new(input_code: *const c_void, output: *mut c_void)
                -> *mut c_void;
        }
        Self {
            inner: unsafe {
                gum_x86_relocator_new(input_code as *const c_void, output.writer as *mut c_void)
            },
        }
    }

    fn read_one(&mut self) -> (u32, Insn) {
        extern "C" {
            fn gum_x86_relocator_read_one(
                relocator: *mut c_void,
                instruction: *mut *const cs_insn,
            ) -> u32;
        }

        let mut insn_addr: *const cs_insn = std::ptr::null_mut();
        let ret = unsafe { gum_x86_relocator_read_one(self.inner, &mut insn_addr as *mut _) };
        (ret, unsafe { Insn::from_raw(insn_addr) })
    }

    fn eoi(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_eoi(relocator: *mut c_void) -> u32;
        }

        unsafe { gum_x86_relocator_eoi(self.inner) != 0 }
    }

    fn write_all(&mut self) {
        extern "C" {
            fn gum_x86_relocator_write_all(relocator: *mut c_void);
        }

        unsafe { gum_x86_relocator_write_all(self.inner) }
    }

    fn write_one(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_write_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_x86_relocator_write_one(self.inner) != 0 }
    }

    fn skip_one(&mut self) -> bool {
        extern "C" {
            fn gum_x86_relocator_skip_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_x86_relocator_skip_one(self.inner) != 0 }
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for X86Relocator {
    fn drop(&mut self) {
        extern "C" {
            fn gum_x86_relocator_unref(relocator: *mut c_void);
        }

        unsafe { gum_x86_relocator_unref(self.inner) }
    }
}

#[cfg(target_arch = "aarch64")]
pub struct Aarch64Relocator {
    inner: *mut c_void,
}

#[cfg(target_arch = "aarch64")]
impl Relocator for Aarch64Relocator {
    fn new(input_code: u64, output: &mut Aarch64InstructionWriter) -> Self {
        extern "C" {
            fn gum_arm64_relocator_new(
                input_code: *const c_void,
                output: *mut c_void,
            ) -> *mut c_void;
        }
        Self {
            inner: unsafe {
                gum_arm64_relocator_new(input_code as *const c_void, output.writer as *mut c_void)
            },
        }
    }

    fn read_one(&mut self) -> (u32, Insn) {
        extern "C" {
            fn gum_arm64_relocator_read_one(
                relocator: *mut c_void,
                instruction: *mut *const cs_insn,
            ) -> u32;
        }

        let mut insn_addr: *const cs_insn = std::ptr::null_mut();
        let ret = unsafe { gum_arm64_relocator_read_one(self.inner, &mut insn_addr as *mut _) };
        (ret, unsafe { Insn::from_raw(insn_addr) })
    }

    fn eoi(&mut self) -> bool {
        extern "C" {
            fn gum_arm64_relocator_eoi(relocator: *mut c_void) -> u32;
        }

        unsafe { gum_arm64_relocator_eoi(self.inner) != 0 }
    }

    fn write_all(&mut self) {
        extern "C" {
            fn gum_arm64_relocator_write_all(relocator: *mut c_void);
        }

        unsafe { gum_arm64_relocator_write_all(self.inner) }
    }

    fn write_one(&mut self) -> bool {
        extern "C" {
            fn gum_arm64_relocator_write_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_arm64_relocator_write_one(self.inner) != 0 }
    }

    fn skip_one(&mut self) -> bool {
        extern "C" {
            fn gum_arm64_relocator_skip_one(relocator: *mut c_void) -> i32;
        }

        unsafe { gum_arm64_relocator_skip_one(self.inner) != 0 }
    }
}

#[cfg(target_arch = "aarch64")]
impl Drop for Aarch64Relocator {
    fn drop(&mut self) {
        extern "C" {
            fn gum_arm64_relocator_unref(relocator: *mut c_void);
        }

        unsafe { gum_arm64_relocator_unref(self.inner) }
    }
}
