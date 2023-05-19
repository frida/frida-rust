mod index;
pub use index::*;

mod relocator;
pub use relocator::*;

mod writer;
pub use writer::*;

pub use frida_gum_sys::arm64_cc as Aarch64BranchCondition;
pub use frida_gum_sys::arm64_reg as Aarch64Register;

pub type TargetInstructionWriter = Aarch64InstructionWriter;
pub type TargetRelocator = Aarch64Relocator;
pub type TargetRegister = Aarch64Register;
pub type TargetBranchCondition = Aarch64BranchCondition;
