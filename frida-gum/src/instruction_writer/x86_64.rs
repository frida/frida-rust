mod branch;
pub use branch::*;

mod register;
pub use register::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

pub type TargetInstructionWriter = X86InstructionWriter;
pub type TargetRelocator = X86Relocator;
pub type TargetRegister = X86Register;
pub type TargetBranchCondition = X86BranchCondition;
