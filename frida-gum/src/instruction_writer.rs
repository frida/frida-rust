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
pub struct X86InstructionWriter {
    writer: *mut gum_sys::_GumX86Writer,
}

/// InstructionWriter implementation for the x86/x86_64 instruction writer
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
