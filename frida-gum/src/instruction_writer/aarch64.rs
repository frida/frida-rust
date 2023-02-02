mod branch;
pub use branch::*;

mod index;
pub use index::*;

mod register;
pub use register::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

pub type TargetInstructionWriter = Aarch64InstructionWriter;
pub type TargetRelocator = Aarch64Relocator;
pub type TargetRegister = Aarch64Register;
pub type TargetBranchCondition = Aarch64BranchCondition;
