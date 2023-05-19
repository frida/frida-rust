mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

pub use frida_gum_sys::arm_reg as ArmRegister;

pub type TargetInstructionWriter = ArmInstructionWriter;
pub type TargetRelocator = ArmRelocator;
pub type TargetRegister = ArmRegister;
