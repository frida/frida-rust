use frida_gum_sys as gum_sys;

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum IndexMode {
    PostAdjust = gum_sys::_GumArm64IndexMode::GUM_INDEX_POST_ADJUST as u32,
    SignedOffset = gum_sys::_GumArm64IndexMode::GUM_INDEX_SIGNED_OFFSET as u32,
    PreAdjust = gum_sys::_GumArm64IndexMode::GUM_INDEX_PRE_ADJUST as u32,
}
