use frida_gum_sys as gum_sys;

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum IndexMode {
    PostAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_POST_ADJUST,
    SignedOffset = gum_sys::_GumArm64IndexMode_GUM_INDEX_SIGNED_OFFSET,
    PreAdjust = gum_sys::_GumArm64IndexMode_GUM_INDEX_PRE_ADJUST,
}
