use frida_gum_sys as gum_sys;
use std::ffi::c_void;

#[cfg(target_arch = "x86_64")]
pub type TargetInstructionWriter = X86InstructionWriter;

#[cfg(target_arch = "aarch64")]
pub type TargetInstructionWriter = Aarch64InstructionWriter;

#[cfg(target_arch = "x86_64")]
#[derive(FromPrimitive)]
#[repr(u32)]
pub enum Register {
  EAX = gum_sys::_GumCpuReg_GUM_REG_EAX,
  ECX = gum_sys::_GumCpuReg_GUM_REG_ECX,
  EDX = gum_sys::_GumCpuReg_GUM_REG_EDX,
  EBX = gum_sys::_GumCpuReg_GUM_REG_EBX,
  ESP = gum_sys::_GumCpuReg_GUM_REG_ESP,
  EBP = gum_sys::_GumCpuReg_GUM_REG_EBP,
  ESI = gum_sys::_GumCpuReg_GUM_REG_ESI,
  EDI = gum_sys::_GumCpuReg_GUM_REG_EDI,

  R8D = gum_sys::_GumCpuReg_GUM_REG_R8D,
  R9D = gum_sys::_GumCpuReg_GUM_REG_R9D,
  R10D = gum_sys::_GumCpuReg_GUM_REG_R10D,
  R11D = gum_sys::_GumCpuReg_GUM_REG_R11D,
  R12D = gum_sys::_GumCpuReg_GUM_REG_R12D,
  R13D = gum_sys::_GumCpuReg_GUM_REG_R13D,
  R14D = gum_sys::_GumCpuReg_GUM_REG_R14D,
  R15D = gum_sys::_GumCpuReg_GUM_REG_R15D,

  EIP = gum_sys::_GumCpuReg_GUM_REG_EIP,

  /* 64 bit */
  RAX = gum_sys::_GumCpuReg_GUM_REG_RAX,
  RCX = gum_sys::_GumCpuReg_GUM_REG_RCX,
  RDX = gum_sys::_GumCpuReg_GUM_REG_RDX,
  RBX = gum_sys::_GumCpuReg_GUM_REG_RBX,
  RSP = gum_sys::_GumCpuReg_GUM_REG_RSP,
  RBP = gum_sys::_GumCpuReg_GUM_REG_RBP,
  RSI = gum_sys::_GumCpuReg_GUM_REG_RSI,
  RDI = gum_sys::_GumCpuReg_GUM_REG_RDI,

  R8 = gum_sys::_GumCpuReg_GUM_REG_R8,
  R9 = gum_sys::_GumCpuReg_GUM_REG_R9,
  R10 = gum_sys::_GumCpuReg_GUM_REG_R10,
  R11 = gum_sys::_GumCpuReg_GUM_REG_R11,
  R12 = gum_sys::_GumCpuReg_GUM_REG_R12,
  R13 = gum_sys::_GumCpuReg_GUM_REG_R13,
  R14 = gum_sys::_GumCpuReg_GUM_REG_R14,
  R15 = gum_sys::_GumCpuReg_GUM_REG_R15,

  RIP = gum_sys::_GumCpuReg_GUM_REG_RIP,

  /* Meta */
  XAX = gum_sys::_GumCpuReg_GUM_REG_XAX,
  XCX = gum_sys::_GumCpuReg_GUM_REG_XCX,
  XDX = gum_sys::_GumCpuReg_GUM_REG_XDX,
  XBX = gum_sys::_GumCpuReg_GUM_REG_XBX,
  XSP = gum_sys::_GumCpuReg_GUM_REG_XSP,
  XBP = gum_sys::_GumCpuReg_GUM_REG_XBP,
  XSI = gum_sys::_GumCpuReg_GUM_REG_XSI,
  XDI = gum_sys::_GumCpuReg_GUM_REG_XDI,

  XIP = gum_sys::_GumCpuReg_GUM_REG_XIP,

  None = gum_sys::_GumCpuReg_GUM_REG_NONE,
}

#[cfg(target_arch = "aarch64")]
#[derive(FromPrimitive)]
#[repr(u32)]
pub enum Register {
  FFR = gum_sys::arm64_reg_ARM64_REG_FFR,
  FP = gum_sys::arm64_reg_ARM64_REG_FP,
  LR = gum_sys::arm64_reg_ARM64_REG_LR,
  NZCV = gum_sys::arm64_reg_ARM64_REG_NZCV,
  SP = gum_sys::arm64_reg_ARM64_REG_SP,
  WSP = gum_sys::arm64_reg_ARM64_REG_WSP,
  WZR = gum_sys::arm64_reg_ARM64_REG_WZR,
  XZR = gum_sys::arm64_reg_ARM64_REG_XZR,

  X0 = gum_sys::arm64_reg_ARM64_REG_X0,
  X1 = gum_sys::arm64_reg_ARM64_REG_X1,
  X2 = gum_sys::arm64_reg_ARM64_REG_X2,
  X3 = gum_sys::arm64_reg_ARM64_REG_X3,
  X4 = gum_sys::arm64_reg_ARM64_REG_X4,
  X5 = gum_sys::arm64_reg_ARM64_REG_X5,
  X6 = gum_sys::arm64_reg_ARM64_REG_X6,
  X7 = gum_sys::arm64_reg_ARM64_REG_X7,
  X8 = gum_sys::arm64_reg_ARM64_REG_X8,
  X9 = gum_sys::arm64_reg_ARM64_REG_X9,
  X10 = gum_sys::arm64_reg_ARM64_REG_X10,
  X11 = gum_sys::arm64_reg_ARM64_REG_X11,
  X12 = gum_sys::arm64_reg_ARM64_REG_X12,
  X13 = gum_sys::arm64_reg_ARM64_REG_X13,
  X14 = gum_sys::arm64_reg_ARM64_REG_X14,
  X15 = gum_sys::arm64_reg_ARM64_REG_X15,
  X16 = gum_sys::arm64_reg_ARM64_REG_X16,
  X17 = gum_sys::arm64_reg_ARM64_REG_X17,
  X18 = gum_sys::arm64_reg_ARM64_REG_X18,
  X19 = gum_sys::arm64_reg_ARM64_REG_X19,
  X20 = gum_sys::arm64_reg_ARM64_REG_X20,
  X21 = gum_sys::arm64_reg_ARM64_REG_X21,
  X22 = gum_sys::arm64_reg_ARM64_REG_X22,
  X23 = gum_sys::arm64_reg_ARM64_REG_X23,
  X24 = gum_sys::arm64_reg_ARM64_REG_X24,
  X25 = gum_sys::arm64_reg_ARM64_REG_X25,
  X26 = gum_sys::arm64_reg_ARM64_REG_X26,
  X27 = gum_sys::arm64_reg_ARM64_REG_X27,
  X28 = gum_sys::arm64_reg_ARM64_REG_X28,

  W0 = gum_sys::arm64_reg_ARM64_REG_W0,
  W1 = gum_sys::arm64_reg_ARM64_REG_W1,
  W2 = gum_sys::arm64_reg_ARM64_REG_W2,
  W3 = gum_sys::arm64_reg_ARM64_REG_W3,
  W4 = gum_sys::arm64_reg_ARM64_REG_W4,
  W5 = gum_sys::arm64_reg_ARM64_REG_W5,
  W6 = gum_sys::arm64_reg_ARM64_REG_W6,
  W7 = gum_sys::arm64_reg_ARM64_REG_W7,
  W8 = gum_sys::arm64_reg_ARM64_REG_W8,
  W9 = gum_sys::arm64_reg_ARM64_REG_W9,
  W10 = gum_sys::arm64_reg_ARM64_REG_W10,
  W11 = gum_sys::arm64_reg_ARM64_REG_W11,
  W12 = gum_sys::arm64_reg_ARM64_REG_W12,
  W13 = gum_sys::arm64_reg_ARM64_REG_W13,
  W14 = gum_sys::arm64_reg_ARM64_REG_W14,
  W15 = gum_sys::arm64_reg_ARM64_REG_W15,
  W16 = gum_sys::arm64_reg_ARM64_REG_W16,
  W17 = gum_sys::arm64_reg_ARM64_REG_W17,
  W18 = gum_sys::arm64_reg_ARM64_REG_W18,
  W19 = gum_sys::arm64_reg_ARM64_REG_W19,
  W20 = gum_sys::arm64_reg_ARM64_REG_W20,
  W21 = gum_sys::arm64_reg_ARM64_REG_W21,
  W22 = gum_sys::arm64_reg_ARM64_REG_W22,
  W23 = gum_sys::arm64_reg_ARM64_REG_W23,
  W24 = gum_sys::arm64_reg_ARM64_REG_W24,
  W25 = gum_sys::arm64_reg_ARM64_REG_W25,
  W26 = gum_sys::arm64_reg_ARM64_REG_W26,
  W27 = gum_sys::arm64_reg_ARM64_REG_W27,
  W28 = gum_sys::arm64_reg_ARM64_REG_W28,
  W29 = gum_sys::arm64_reg_ARM64_REG_W29,
  W30 = gum_sys::arm64_reg_ARM64_REG_W30,

  S0 = gum_sys::arm64_reg_ARM64_REG_S0,
  S1 = gum_sys::arm64_reg_ARM64_REG_S1,
  S2 = gum_sys::arm64_reg_ARM64_REG_S2,
  S3 = gum_sys::arm64_reg_ARM64_REG_S3,
  S4 = gum_sys::arm64_reg_ARM64_REG_S4,
  S5 = gum_sys::arm64_reg_ARM64_REG_S5,
  S6 = gum_sys::arm64_reg_ARM64_REG_S6,
  S7 = gum_sys::arm64_reg_ARM64_REG_S7,
  S8 = gum_sys::arm64_reg_ARM64_REG_S8,
  S9 = gum_sys::arm64_reg_ARM64_REG_S9,
  S10 = gum_sys::arm64_reg_ARM64_REG_S10,
  S11 = gum_sys::arm64_reg_ARM64_REG_S11,
  S12 = gum_sys::arm64_reg_ARM64_REG_S12,
  S13 = gum_sys::arm64_reg_ARM64_REG_S13,
  S14 = gum_sys::arm64_reg_ARM64_REG_S14,
  S15 = gum_sys::arm64_reg_ARM64_REG_S15,
  S16 = gum_sys::arm64_reg_ARM64_REG_S16,
  S17 = gum_sys::arm64_reg_ARM64_REG_S17,
  S18 = gum_sys::arm64_reg_ARM64_REG_S18,
  S19 = gum_sys::arm64_reg_ARM64_REG_S19,
  S20 = gum_sys::arm64_reg_ARM64_REG_S20,
  S21 = gum_sys::arm64_reg_ARM64_REG_S21,
  S22 = gum_sys::arm64_reg_ARM64_REG_S22,
  S23 = gum_sys::arm64_reg_ARM64_REG_S23,
  S24 = gum_sys::arm64_reg_ARM64_REG_S24,
  S25 = gum_sys::arm64_reg_ARM64_REG_S25,
  S26 = gum_sys::arm64_reg_ARM64_REG_S26,
  S27 = gum_sys::arm64_reg_ARM64_REG_S27,
  S28 = gum_sys::arm64_reg_ARM64_REG_S28,
  S29 = gum_sys::arm64_reg_ARM64_REG_S29,
  S30 = gum_sys::arm64_reg_ARM64_REG_S30,
  S31 = gum_sys::arm64_reg_ARM64_REG_S31,

  H0 = gum_sys::arm64_reg_ARM64_REG_H0,
  H1 = gum_sys::arm64_reg_ARM64_REG_H1,
  H2 = gum_sys::arm64_reg_ARM64_REG_H2,
  H3 = gum_sys::arm64_reg_ARM64_REG_H3,
  H4 = gum_sys::arm64_reg_ARM64_REG_H4,
  H5 = gum_sys::arm64_reg_ARM64_REG_H5,
  H6 = gum_sys::arm64_reg_ARM64_REG_H6,
  H7 = gum_sys::arm64_reg_ARM64_REG_H7,
  H8 = gum_sys::arm64_reg_ARM64_REG_H8,
  H9 = gum_sys::arm64_reg_ARM64_REG_H9,
  H10 = gum_sys::arm64_reg_ARM64_REG_H10,
  H11 = gum_sys::arm64_reg_ARM64_REG_H11,
  H12 = gum_sys::arm64_reg_ARM64_REG_H12,
  H13 = gum_sys::arm64_reg_ARM64_REG_H13,
  H14 = gum_sys::arm64_reg_ARM64_REG_H14,
  H15 = gum_sys::arm64_reg_ARM64_REG_H15,
  H16 = gum_sys::arm64_reg_ARM64_REG_H16,
  H17 = gum_sys::arm64_reg_ARM64_REG_H17,
  H18 = gum_sys::arm64_reg_ARM64_REG_H18,
  H19 = gum_sys::arm64_reg_ARM64_REG_H19,
  H20 = gum_sys::arm64_reg_ARM64_REG_H20,
  H21 = gum_sys::arm64_reg_ARM64_REG_H21,
  H22 = gum_sys::arm64_reg_ARM64_REG_H22,
  H23 = gum_sys::arm64_reg_ARM64_REG_H23,
  H24 = gum_sys::arm64_reg_ARM64_REG_H24,
  H25 = gum_sys::arm64_reg_ARM64_REG_H25,
  H26 = gum_sys::arm64_reg_ARM64_REG_H26,
  H27 = gum_sys::arm64_reg_ARM64_REG_H27,
  H28 = gum_sys::arm64_reg_ARM64_REG_H28,
  H29 = gum_sys::arm64_reg_ARM64_REG_H29,
  H30 = gum_sys::arm64_reg_ARM64_REG_H30,
  H31 = gum_sys::arm64_reg_ARM64_REG_H31,

  B0 = gum_sys::arm64_reg_ARM64_REG_B0,
  B1 = gum_sys::arm64_reg_ARM64_REG_B1,
  B2 = gum_sys::arm64_reg_ARM64_REG_B2,
  B3 = gum_sys::arm64_reg_ARM64_REG_B3,
  B4 = gum_sys::arm64_reg_ARM64_REG_B4,
  B5 = gum_sys::arm64_reg_ARM64_REG_B5,
  B6 = gum_sys::arm64_reg_ARM64_REG_B6,
  B7 = gum_sys::arm64_reg_ARM64_REG_B7,
  B8 = gum_sys::arm64_reg_ARM64_REG_B8,
  B9 = gum_sys::arm64_reg_ARM64_REG_B9,
  B10 = gum_sys::arm64_reg_ARM64_REG_B10,
  B11 = gum_sys::arm64_reg_ARM64_REG_B11,
  B12 = gum_sys::arm64_reg_ARM64_REG_B12,
  B13 = gum_sys::arm64_reg_ARM64_REG_B13,
  B14 = gum_sys::arm64_reg_ARM64_REG_B14,
  B15 = gum_sys::arm64_reg_ARM64_REG_B15,
  B16 = gum_sys::arm64_reg_ARM64_REG_B16,
  B17 = gum_sys::arm64_reg_ARM64_REG_B17,
  B18 = gum_sys::arm64_reg_ARM64_REG_B18,
  B19 = gum_sys::arm64_reg_ARM64_REG_B19,
  B20 = gum_sys::arm64_reg_ARM64_REG_B20,
  B21 = gum_sys::arm64_reg_ARM64_REG_B21,
  B22 = gum_sys::arm64_reg_ARM64_REG_B22,
  B23 = gum_sys::arm64_reg_ARM64_REG_B23,
  B24 = gum_sys::arm64_reg_ARM64_REG_B24,
  B25 = gum_sys::arm64_reg_ARM64_REG_B25,
  B26 = gum_sys::arm64_reg_ARM64_REG_B26,
  B27 = gum_sys::arm64_reg_ARM64_REG_B27,
  B28 = gum_sys::arm64_reg_ARM64_REG_B28,
  B29 = gum_sys::arm64_reg_ARM64_REG_B29,
  B30 = gum_sys::arm64_reg_ARM64_REG_B30,
  B31 = gum_sys::arm64_reg_ARM64_REG_B31,

  D0 = gum_sys::arm64_reg_ARM64_REG_D0,
  D1 = gum_sys::arm64_reg_ARM64_REG_D1,
  D2 = gum_sys::arm64_reg_ARM64_REG_D2,
  D3 = gum_sys::arm64_reg_ARM64_REG_D3,
  D4 = gum_sys::arm64_reg_ARM64_REG_D4,
  D5 = gum_sys::arm64_reg_ARM64_REG_D5,
  D6 = gum_sys::arm64_reg_ARM64_REG_D6,
  D7 = gum_sys::arm64_reg_ARM64_REG_D7,
  D8 = gum_sys::arm64_reg_ARM64_REG_D8,
  D9 = gum_sys::arm64_reg_ARM64_REG_D9,
  D10 = gum_sys::arm64_reg_ARM64_REG_D10,
  D11 = gum_sys::arm64_reg_ARM64_REG_D11,
  D12 = gum_sys::arm64_reg_ARM64_REG_D12,
  D13 = gum_sys::arm64_reg_ARM64_REG_D13,
  D14 = gum_sys::arm64_reg_ARM64_REG_D14,
  D15 = gum_sys::arm64_reg_ARM64_REG_D15,
  D16 = gum_sys::arm64_reg_ARM64_REG_D16,
  D17 = gum_sys::arm64_reg_ARM64_REG_D17,
  D18 = gum_sys::arm64_reg_ARM64_REG_D18,
  D19 = gum_sys::arm64_reg_ARM64_REG_D19,
  D20 = gum_sys::arm64_reg_ARM64_REG_D20,
  D21 = gum_sys::arm64_reg_ARM64_REG_D21,
  D22 = gum_sys::arm64_reg_ARM64_REG_D22,
  D23 = gum_sys::arm64_reg_ARM64_REG_D23,
  D24 = gum_sys::arm64_reg_ARM64_REG_D24,
  D25 = gum_sys::arm64_reg_ARM64_REG_D25,
  D26 = gum_sys::arm64_reg_ARM64_REG_D26,
  D27 = gum_sys::arm64_reg_ARM64_REG_D27,
  D28 = gum_sys::arm64_reg_ARM64_REG_D28,
  D29 = gum_sys::arm64_reg_ARM64_REG_D29,
  D30 = gum_sys::arm64_reg_ARM64_REG_D30,
  D31 = gum_sys::arm64_reg_ARM64_REG_D31,

  Q0 = gum_sys::arm64_reg_ARM64_REG_Q0,
  Q1 = gum_sys::arm64_reg_ARM64_REG_Q1,
  Q2 = gum_sys::arm64_reg_ARM64_REG_Q2,
  Q3 = gum_sys::arm64_reg_ARM64_REG_Q3,
  Q4 = gum_sys::arm64_reg_ARM64_REG_Q4,
  Q5 = gum_sys::arm64_reg_ARM64_REG_Q5,
  Q6 = gum_sys::arm64_reg_ARM64_REG_Q6,
  Q7 = gum_sys::arm64_reg_ARM64_REG_Q7,
  Q8 = gum_sys::arm64_reg_ARM64_REG_Q8,
  Q9 = gum_sys::arm64_reg_ARM64_REG_Q9,
  Q10 = gum_sys::arm64_reg_ARM64_REG_Q10,
  Q11 = gum_sys::arm64_reg_ARM64_REG_Q11,
  Q12 = gum_sys::arm64_reg_ARM64_REG_Q12,
  Q13 = gum_sys::arm64_reg_ARM64_REG_Q13,
  Q14 = gum_sys::arm64_reg_ARM64_REG_Q14,
  Q15 = gum_sys::arm64_reg_ARM64_REG_Q15,
  Q16 = gum_sys::arm64_reg_ARM64_REG_Q16,
  Q17 = gum_sys::arm64_reg_ARM64_REG_Q17,
  Q18 = gum_sys::arm64_reg_ARM64_REG_Q18,
  Q19 = gum_sys::arm64_reg_ARM64_REG_Q19,
  Q20 = gum_sys::arm64_reg_ARM64_REG_Q20,
  Q21 = gum_sys::arm64_reg_ARM64_REG_Q21,
  Q22 = gum_sys::arm64_reg_ARM64_REG_Q22,
  Q23 = gum_sys::arm64_reg_ARM64_REG_Q23,
  Q24 = gum_sys::arm64_reg_ARM64_REG_Q24,
  Q25 = gum_sys::arm64_reg_ARM64_REG_Q25,
  Q26 = gum_sys::arm64_reg_ARM64_REG_Q26,
  Q27 = gum_sys::arm64_reg_ARM64_REG_Q27,
  Q28 = gum_sys::arm64_reg_ARM64_REG_Q28,
  Q29 = gum_sys::arm64_reg_ARM64_REG_Q29,
  Q30 = gum_sys::arm64_reg_ARM64_REG_Q30,
  Q31 = gum_sys::arm64_reg_ARM64_REG_Q31,


  Z0 = gum_sys::arm64_reg_ARM64_REG_Z0,
  Z1 = gum_sys::arm64_reg_ARM64_REG_Z1,
  Z2 = gum_sys::arm64_reg_ARM64_REG_Z2,
  Z3 = gum_sys::arm64_reg_ARM64_REG_Z3,
  Z4 = gum_sys::arm64_reg_ARM64_REG_Z4,
  Z5 = gum_sys::arm64_reg_ARM64_REG_Z5,
  Z6 = gum_sys::arm64_reg_ARM64_REG_Z6,
  Z7 = gum_sys::arm64_reg_ARM64_REG_Z7,
  Z8 = gum_sys::arm64_reg_ARM64_REG_Z8,
  Z9 = gum_sys::arm64_reg_ARM64_REG_Z9,
  Z10 = gum_sys::arm64_reg_ARM64_REG_Z10,
  Z11 = gum_sys::arm64_reg_ARM64_REG_Z11,
  Z12 = gum_sys::arm64_reg_ARM64_REG_Z12,
  Z13 = gum_sys::arm64_reg_ARM64_REG_Z13,
  Z14 = gum_sys::arm64_reg_ARM64_REG_Z14,
  Z15 = gum_sys::arm64_reg_ARM64_REG_Z15,
  Z16 = gum_sys::arm64_reg_ARM64_REG_Z16,
  Z17 = gum_sys::arm64_reg_ARM64_REG_Z17,
  Z18 = gum_sys::arm64_reg_ARM64_REG_Z18,
  Z19 = gum_sys::arm64_reg_ARM64_REG_Z19,
  Z20 = gum_sys::arm64_reg_ARM64_REG_Z20,
  Z21 = gum_sys::arm64_reg_ARM64_REG_Z21,
  Z22 = gum_sys::arm64_reg_ARM64_REG_Z22,
  Z23 = gum_sys::arm64_reg_ARM64_REG_Z23,
  Z24 = gum_sys::arm64_reg_ARM64_REG_Z24,
  Z25 = gum_sys::arm64_reg_ARM64_REG_Z25,
  Z26 = gum_sys::arm64_reg_ARM64_REG_Z26,
  Z27 = gum_sys::arm64_reg_ARM64_REG_Z27,
  Z28 = gum_sys::arm64_reg_ARM64_REG_Z28,
  Z29 = gum_sys::arm64_reg_ARM64_REG_Z29,
  Z30 = gum_sys::arm64_reg_ARM64_REG_Z30,
  Z31 = gum_sys::arm64_reg_ARM64_REG_Z31,


  V0 = gum_sys::arm64_reg_ARM64_REG_V0,
  V1 = gum_sys::arm64_reg_ARM64_REG_V1,
  V2 = gum_sys::arm64_reg_ARM64_REG_V2,
  V3 = gum_sys::arm64_reg_ARM64_REG_V3,
  V4 = gum_sys::arm64_reg_ARM64_REG_V4,
  V5 = gum_sys::arm64_reg_ARM64_REG_V5,
  V6 = gum_sys::arm64_reg_ARM64_REG_V6,
  V7 = gum_sys::arm64_reg_ARM64_REG_V7,
  V8 = gum_sys::arm64_reg_ARM64_REG_V8,
  V9 = gum_sys::arm64_reg_ARM64_REG_V9,
  V10 = gum_sys::arm64_reg_ARM64_REG_V10,
  V11 = gum_sys::arm64_reg_ARM64_REG_V11,
  V12 = gum_sys::arm64_reg_ARM64_REG_V12,
  V13 = gum_sys::arm64_reg_ARM64_REG_V13,
  V14 = gum_sys::arm64_reg_ARM64_REG_V14,
  V15 = gum_sys::arm64_reg_ARM64_REG_V15,
  V16 = gum_sys::arm64_reg_ARM64_REG_V16,
  V17 = gum_sys::arm64_reg_ARM64_REG_V17,
  V18 = gum_sys::arm64_reg_ARM64_REG_V18,
  V19 = gum_sys::arm64_reg_ARM64_REG_V19,
  V20 = gum_sys::arm64_reg_ARM64_REG_V20,
  V21 = gum_sys::arm64_reg_ARM64_REG_V21,
  V22 = gum_sys::arm64_reg_ARM64_REG_V22,
  V23 = gum_sys::arm64_reg_ARM64_REG_V23,
  V24 = gum_sys::arm64_reg_ARM64_REG_V24,
  V25 = gum_sys::arm64_reg_ARM64_REG_V25,
  V26 = gum_sys::arm64_reg_ARM64_REG_V26,
  V27 = gum_sys::arm64_reg_ARM64_REG_V27,
  V28 = gum_sys::arm64_reg_ARM64_REG_V28,
  V29 = gum_sys::arm64_reg_ARM64_REG_V29,
  V30 = gum_sys::arm64_reg_ARM64_REG_V30,
  V31 = gum_sys::arm64_reg_ARM64_REG_V31,
}

#[cfg(target_arch = "aarch64")]
#[derive(FromPrimitive)]
#[repr(u32)]
pub enum IndexMode {
  PostAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_POST_ADJUST,
  SignedOffset = gum_sys::_GumArm64IndexMode_GUM_INDEX_SIGNED_OFFSET,
  PreAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_PRE_ADJUST,
}

/// A trait all InstructionWriters share, to make it easier to return them and to consolidate
/// common functions.
pub trait InstructionWriter {
    /// Retrieve the writer's current program counter
    fn pc(&self) -> u64;

    /// Retrieve the writer's current code offset
    fn code_offset(&self) -> u64;

    /// Check if we can branch directly between the given source and target addresses
    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool;

    /// Check if we can branch directly to the target address from the current pc
    fn can_branch_directly_to(&self, target: u64) -> bool{
        self.can_branch_directly_between(self.pc(), target)
    }

    /// Add the bytes specified to the instruction stream
    fn put_bytes(&self, bytes: &[u8]);

    /// Add a label at the curent point in the instruction stream
    fn put_label(&self, id: u64);
}

/// The x86/x86_64 instruction writer
#[cfg(target_arch = "x86_64")]
pub struct X86InstructionWriter {
    writer: *mut gum_sys::_GumX86Writer,
}

/// InstructionWriter implementation for the x86/x86_64 instruction writer
#[cfg(target_arch = "x86_64")]
impl InstructionWriter for X86InstructionWriter {
    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        if unsafe { gum_sys::gum_x86_writer_can_branch_directly_between(source, target) } != 0 {
            true
        } else {
            false
        }
    }

    fn put_bytes(&self, bytes: &[u8]) {
        println!("put_bytes: {:?}", bytes);
        unsafe { gum_sys::gum_x86_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32) }
    }

    fn put_label(&self, id: u64) {
        unsafe { gum_sys::gum_x86_writer_put_label(self.writer, id as *const c_void) };
    }
}

#[cfg(target_arch = "x86_64")]
impl X86InstructionWriter {
    /// Create a new X86InstructionWriter from the raw pointer
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumX86Writer) -> Self {
        Self {
            writer,
        }
    }

    /// Insert a jmp near to a label. The label is specified by id
    pub fn put_jmp_near_label(&self, id: u64) {
        unsafe { gum_sys::gum_x86_writer_put_jmp_near_label(self.writer, id as *const c_void) };
    }

    /// Insert a lea d, [s + o] instruction
    pub fn put_lea_reg_reg_offset(&self, dst_reg: Register, src_reg: Register, src_offset: i32) {
        unsafe { gum_sys::gum_x86_writer_put_lea_reg_reg_offset(self.writer, dst_reg as u32, src_reg as u32, src_offset as i64) };
    }

    /// Insert a push reg instruction
    pub fn put_push_reg(&self, reg: Register) {
        unsafe { gum_sys::gum_x86_writer_put_push_reg(self.writer, reg as u32) };
    }

    /// Insert a pop reg instruction
    pub fn put_pop_reg(&self, reg: Register) {
        unsafe { gum_sys::gum_x86_writer_put_pop_reg(self.writer, reg as u32) };
    }

    /// Insert a mov reg, [address] instruction
    pub fn put_mov_reg_address(&self, reg: Register, address: u64) {
      //println!("put_mov_reg_address: reg: {}, addresss: {:x}", reg as u32, address);
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_address(self.writer, reg as u32, address) };
    }
    /// Insert a call address instruction
    pub fn put_call_address(&self, address: u64) {
        unsafe { gum_sys::gum_x86_writer_put_call_address(self.writer, address) };
    }
}

/// The aarch64 instruction writer
pub struct Aarch64InstructionWriter {
#[cfg(target_arch = "aarch64")]
    writer: *mut gum_sys::_GumArm64Writer,
}
///
/// InstructionWriter implementation for the aarch_64 instruction writer
#[cfg(target_arch = "aarch64")]
impl InstructionWriter for Aarch64InstructionWriter {
    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        if unsafe { gum_sys::gum_arm64_writer_can_branch_directly_between(self.writer, source, target) } != 0 {
            true
        } else {
            false
        }
    }

    fn put_bytes(&self, bytes: &[u8]) {
        unsafe { gum_sys::gum_arm64_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32) };
    }

    fn put_label(&self, id: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_label(self.writer, id as *const c_void) };
    }
}

#[cfg(target_arch = "aarch64")]
impl Aarch64InstructionWriter {
    /// Create a new Aarch64InstructionWriter from the raw pointer
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumArm64Writer) -> Self {
        Self {
            writer,
        }
    }

    /// Insert a b to a label. The label is specified by id
    pub fn put_b_label(&self, id: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_b_label(self.writer, id as *const c_void) };
    }

    /// Insert a sub d, l, r instruction
    pub fn pub_sub_reg_reg_imm(&self, dst_reg: Register, left_reg: Register, right_value: u64) {
      unsafe { gum_sys::gum_arm64_writer_put_sub_reg_reg_imm(self.writer, dst_reg as u32, left_reg as u32, right_value) };
    }

    /// Insert a add d, l, r instruction
    pub fn pub_add_reg_reg_imm(&self, dst_reg: Register, left_reg: Register, right_value: u64) {
      unsafe { gum_sys::gum_arm64_writer_put_add_reg_reg_imm(self.writer, dst_reg as u32, left_reg as u32, right_value) };
    }

    /// Insert a stp reg, reg, [reg + o] instruction
    pub fn put_stp_reg_reg_reg_offset(&self, reg_a: Register, reg_b: Register, reg_dst: Register, offset: i64, mode: IndexMode) {
        unsafe { gum_sys::gum_arm64_writer_put_stp_reg_reg_reg_offset(self.writer, reg_a as u32, reg_b as u32, reg_dst as u32, offset, mode as u32) };
    }

    /// Insert a ldp reg, reg, [reg + o] instruction
    pub fn put_ldp_reg_reg_reg_offset(&self, reg_a: Register, reg_b: Register, reg_src: Register, offset: i64, mode: IndexMode) {
        unsafe { gum_sys::gum_arm64_writer_put_ldp_reg_reg_reg_offset(self.writer, reg_a as u32, reg_b as u32, reg_src as u32, offset, mode as u32) };
    }

    /// Insert a mov reg, u64 instruction
    pub fn put_ldr_reg_u64(&self, reg: Register, address: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_ldr_reg_u64(self.writer, reg as u32, address) };
    }

    /// Insert a bl imm instruction
    pub fn put_bl_imm(&self, address: u64) {
        unsafe { gum_sys::gum_arm64_writer_put_bl_imm(self.writer, address) };
    }



}
