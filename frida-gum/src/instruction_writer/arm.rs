mod register;
pub use register::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

pub type TargetInstructionWriter = ArmInstructionWriter;
pub type TargetRelocator = ArmRelocator;
pub type TargetRegister = ArmRegister;
