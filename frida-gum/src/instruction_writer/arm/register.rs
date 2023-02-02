use frida_gum_sys as gum_sys;

#[derive(FromPrimitive, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u32)]
pub enum ArmRegister {
    R0 = gum_sys::arm_reg_ARM_REG_R0 as u32,
    R1 = gum_sys::arm_reg_ARM_REG_R1 as u32,
    R2 = gum_sys::arm_reg_ARM_REG_R2 as u32,
    R3 = gum_sys::arm_reg_ARM_REG_R3 as u32,
    R4 = gum_sys::arm_reg_ARM_REG_R4 as u32,
    R5 = gum_sys::arm_reg_ARM_REG_R5 as u32,
    R6 = gum_sys::arm_reg_ARM_REG_R6 as u32,
    R7 = gum_sys::arm_reg_ARM_REG_R7 as u32,
    R8 = gum_sys::arm_reg_ARM_REG_R8 as u32,
    R9 = gum_sys::arm_reg_ARM_REG_R9 as u32,
    R10 = gum_sys::arm_reg_ARM_REG_R10 as u32,
    R11 = gum_sys::arm_reg_ARM_REG_R11 as u32,
    R12 = gum_sys::arm_reg_ARM_REG_R12 as u32,
    R13 = gum_sys::arm_reg_ARM_REG_R13 as u32,
    R14 = gum_sys::arm_reg_ARM_REG_R14 as u32,
    R15 = gum_sys::arm_reg_ARM_REG_R15 as u32,
}
