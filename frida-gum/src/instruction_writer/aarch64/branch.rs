use frida_gum_sys as gum_sys;

#[repr(u32)]
pub enum Aarch64BranchCondition {
    Eq = gum_sys::arm64_cc_ARM64_CC_EQ,
    Ne = gum_sys::arm64_cc_ARM64_CC_NE,
    Hs = gum_sys::arm64_cc_ARM64_CC_HS,
    Lo = gum_sys::arm64_cc_ARM64_CC_LO,
    Mi = gum_sys::arm64_cc_ARM64_CC_MI,
    Pl = gum_sys::arm64_cc_ARM64_CC_PL,
    Vs = gum_sys::arm64_cc_ARM64_CC_VS,
    Vc = gum_sys::arm64_cc_ARM64_CC_VC,
    Hi = gum_sys::arm64_cc_ARM64_CC_HI,
    Ls = gum_sys::arm64_cc_ARM64_CC_LS,
    Ge = gum_sys::arm64_cc_ARM64_CC_GE,
    Lt = gum_sys::arm64_cc_ARM64_CC_LT,
    Gt = gum_sys::arm64_cc_ARM64_CC_GT,
    Le = gum_sys::arm64_cc_ARM64_CC_LE,
    Al = gum_sys::arm64_cc_ARM64_CC_AL,
    Nv = gum_sys::arm64_cc_ARM64_CC_NV,
}
