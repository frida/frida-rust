/*
 * Copyright © 2021 Keegan Saunders
 * Copyright © 2021 S Rubenstein
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
#[cfg(target_arch = "arm")]
mod arm;
#[cfg(target_arch = "arm")]
pub use arm::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

use frida_gum_sys::Insn;

pub enum Argument {
    Register(TargetRegister),
    Address(u64),
}

/// A trait all [`InstructionWriter`]s share.
pub trait InstructionWriter {
    /// Create a new [`InstructionWriter`] to write code to the given address
    fn new(code_address: u64) -> Self;

    /// Retrieve the writer's current program counter.
    fn pc(&self) -> u64;

    /// Retrieve the writer's current code offset.
    fn code_offset(&self) -> u64;

    /// Check if we can branch directly between the given source and target addresses.
    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool;

    /// Check if we can branch directly to the target address from the current
    /// program counter.
    fn can_branch_directly_to(&self, target: u64) -> bool {
        self.can_branch_directly_between(self.pc(), target)
    }

    /// Add the bytes specified to the instruction stream.
    fn put_bytes(&self, bytes: &[u8]) -> bool;

    /// Add a label at the curent point in the instruction stream.
    fn put_label(&self, id: u64) -> bool;

    /// Reset the writer to the given code address
    fn reset(&self, code_address: u64);

    /// Add a branch to an immediate address
    fn put_branch_address(&self, address: u64) -> bool;

    /// Add a nop instruction
    fn put_nop(&self);

    /// Flush the writer, outputing any pending ldr-immediates
    fn flush(&self) -> bool;
}

pub trait Relocator {
    /// Create a new [`Relocator`] for the input code address, outputting to the specified
    /// [`InstructionWriter`]
    fn new(input_code: u64, output: &mut TargetInstructionWriter) -> Self;

    /// Read one instruction from the input stream
    fn read_one(&mut self) -> (u32, Insn);

    /// Check if the relocator has reached the end of input
    fn eoi(&mut self) -> bool;

    /// Relocate and write all instructions to the output [`InstructionWriter`]
    fn write_all(&mut self);

    /// Relocate and write one instruction to the output [`InstructionWriter`]
    fn write_one(&mut self) -> bool;

    /// Skip one instruction
    fn skip_one(&mut self) -> bool;
}
