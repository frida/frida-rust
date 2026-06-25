use {
    crate::{
        NativePointer,
        instruction_writer::{Argument, InstructionWriter, X86BranchCondition, X86Register},
    },
    core::ffi::c_void,
    frida_gum_sys as gum_sys,
    gum_sys::{GumArgument, GumBranchHint, gssize},
};

#[cfg(not(any(
    feature = "module-names",
    feature = "backtrace",
    feature = "memory-access-monitor"
)))]
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The x86/x86_64 instruction writer.
pub struct X86InstructionWriter {
    pub(crate) writer: *mut gum_sys::_GumX86Writer,
    is_from_new: bool,
}

impl InstructionWriter for X86InstructionWriter {
    fn new(code_address: u64) -> Self {
        Self {
            writer: unsafe { gum_sys::gum_x86_writer_new(code_address as *mut c_void) },
            is_from_new: true,
        }
    }

    fn code_offset(&self) -> u64 {
        unsafe { (*self.writer).code as u64 }
    }

    fn pc(&self) -> u64 {
        unsafe { (*self.writer).pc }
    }

    fn can_branch_directly_between(&self, source: u64, target: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_can_branch_directly_between(source, target) != 0 }
    }

    fn put_bytes(&self, bytes: &[u8]) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_bytes(self.writer, bytes.as_ptr(), bytes.len() as u32);
            true
        }
    }

    fn put_label(&self, id: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_label(self.writer, id as *const c_void) != 0 }
    }

    fn reset(&self, code_address: u64) {
        unsafe { gum_sys::gum_x86_writer_reset(self.writer, code_address as *mut c_void) }
    }

    fn put_branch_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    fn put_nop(&self) {
        unsafe { gum_sys::gum_x86_writer_put_nop(self.writer) }
    }

    fn flush(&self) -> bool {
        unsafe { gum_sys::gum_x86_writer_flush(self.writer) != 0 }
    }
}

impl X86InstructionWriter {
    pub(crate) fn from_raw(writer: *mut gum_sys::_GumX86Writer) -> Self {
        Self {
            writer,
            is_from_new: false,
        }
    }

    /// Get the underlying frida gum writer object
    pub fn raw_writer(&self) -> *mut gum_sys::_GumX86Writer {
        self.writer
    }

    /// Clear (free) the writer's internal state without deallocating the
    /// writer struct itself.
    pub fn clear(&self) {
        unsafe { gum_sys::gum_x86_writer_clear(self.writer) };
    }

    /// Get a pointer to the writer's current write cursor.
    pub fn cur(&self) -> NativePointer {
        NativePointer(unsafe { gum_sys::gum_x86_writer_cur(self.writer) })
    }

    /// Get the writer's byte offset from the original code address.
    pub fn offset(&self) -> u32 {
        unsafe { gum_sys::gum_x86_writer_offset(self.writer) }
    }

    /// Set the target CPU type (IA32, AMD64, etc).
    pub fn set_target_cpu(&self, cpu_type: gum_sys::GumCpuType) {
        unsafe { gum_sys::gum_x86_writer_set_target_cpu(self.writer, cpu_type) };
    }

    /// Set the target ABI (Unix or Windows). This affects how
    /// `put_call_*_with_arguments` lays out arguments.
    pub fn set_target_abi(&self, abi_type: gum_sys::GumAbiType) {
        unsafe { gum_sys::gum_x86_writer_set_target_abi(self.writer, abi_type) };
    }

    /// Get the register that holds the n-th argument of a function call
    /// under the writer's current ABI / CPU configuration.
    ///
    /// Returns `None` if Frida reports a register that is unknown to this
    /// binding (typically an indication that the writer has not been
    /// configured with a target ABI).
    pub fn get_cpu_register_for_nth_argument(&self, n: u32) -> Option<X86Register> {
        let raw =
            unsafe { gum_sys::gum_x86_writer_get_cpu_register_for_nth_argument(self.writer, n) };
        num::FromPrimitive::from_u32(raw as u32)
    }

    pub fn put_leave(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_leave(self.writer);
        }
    }

    pub fn put_ret(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_ret(self.writer);
        }
    }

    pub fn put_ret_imm(&self, imm: u16) {
        unsafe {
            gum_sys::gum_x86_writer_put_ret_imm(self.writer, imm);
        }
    }

    pub fn put_jmp_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_address(self.writer, address) != 0 }
    }

    pub fn put_jmp_short_label(&self, id: u64) {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_short_label(self.writer, id as *const c_void);
        }
    }

    /// Insert a `jmp` near to a label. The label is specified by `id`.
    pub fn put_jmp_near_label(&self, id: u64) {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_near_label(self.writer, id as *const c_void);
        }
    }

    pub fn put_jmp_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_ptr(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_reg_ptr(self.writer, reg as u32) != 0 }
    }

    pub fn put_jmp_reg_offset_ptr(&self, reg: X86Register, offset: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jmp_reg_offset_ptr(
                self.writer,
                reg as u32,
                offset as gssize,
            ) != 0
        }
    }

    pub fn put_jmp_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_jmp_near_ptr(self.writer, address) != 0 }
    }

    pub fn put_jcc_short_label(
        &self,
        condition: X86BranchCondition,
        label_id: u64,
        hint: GumBranchHint,
    ) {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_short_label(
                self.writer,
                #[allow(clippy::useless_conversion)]
                (condition as u32).try_into().unwrap(),
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_jcc_near_label(
        &self,
        condition: X86BranchCondition,
        label_id: u64,
        hint: GumBranchHint,
    ) {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_near_label(
                self.writer,
                #[allow(clippy::useless_conversion)]
                (condition as u32).try_into().unwrap(),
                label_id as *const c_void,
                hint,
            )
        }
    }

    pub fn put_mov_reg_gs_u32_ptr(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_gs_u32_ptr(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_add_reg_imm(&self, reg: X86Register, imm: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_add_reg_imm(self.writer, reg as u32, imm as gssize) != 0
        }
    }

    pub fn put_add_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_add_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_add_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_add_reg_near_ptr(self.writer, dst_reg as u32, address) != 0
        }
    }

    pub fn put_sub_reg_imm(&self, dst_reg: X86Register, imm: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_sub_reg_imm(self.writer, dst_reg as u32, imm as gssize) != 0
        }
    }

    pub fn put_sub_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_sub_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_sub_reg_near_ptr(&self, dst_reg: X86Register, address: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_sub_reg_near_ptr(self.writer, dst_reg as u32, address) != 0
        }
    }

    pub fn put_inc_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_inc_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_dec_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_dec_reg(self.writer, reg as u32) != 0 }
    }

    pub fn put_and_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_and_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_and_reg_u32(&self, reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_and_reg_u32(self.writer, reg as u32, imm) != 0 }
    }

    pub fn put_shl_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shl_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_shr_reg_u8(&self, dst_reg: X86Register, imm: u8) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_shr_reg_u8(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_xor_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_xor_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_mov_reg_reg(&self, dst_reg: X86Register, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg(self.writer, dst_reg as u32, src_reg as u32)
                != 0
        }
    }

    pub fn put_mov_reg_u32(&self, dst_reg: X86Register, imm: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u32(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_u64(&self, dst_reg: X86Register, imm: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_mov_reg_u64(self.writer, dst_reg as u32, imm) != 0 }
    }

    pub fn put_mov_reg_address(&self, dst_reg: X86Register, address: u64) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_address(self.writer, dst_reg as u32, address);
        }
    }

    pub fn put_mov_reg_ptr_u32(&self, dst_reg: X86Register, imm: u32) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_u32(self.writer, dst_reg as u32, imm);
        }
    }

    pub fn put_mov_reg_offset_ptr_u32(
        &self,
        dst_reg: X86Register,
        offset: isize,
        imm: u32,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_u32(
                self.writer,
                dst_reg as u32,
                offset as gssize,
                imm,
            ) != 0
        }
    }

    pub fn put_mov_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    pub fn put_mov_reg_offset_ptr_reg(
        &self,
        dst_reg: X86Register,
        offset: isize,
        src_reg: X86Register,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_offset_ptr_reg(
                self.writer,
                dst_reg as u32,
                offset as gssize,
                src_reg as u32,
            ) != 0
        }
    }

    pub fn put_mov_reg_reg_ptr(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg_ptr(self.writer, dst_reg as u32, src_reg as u32)
        }
    }

    pub fn put_mov_reg_reg_offset_ptr(
        &self,
        dst_reg: X86Register,
        src_reg: X86Register,
        offset: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_reg_offset_ptr(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                offset as gssize,
            ) != 0
        }
    }

    pub fn put_mov_reg_base_index_scale_offset_ptr(
        &self,
        dst_reg: X86Register,
        base_reg: X86Register,
        index_reg: X86Register,
        scale: u8,
        offset: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr(
                self.writer,
                dst_reg as u32,
                base_reg as u32,
                index_reg as u32,
                scale,
                offset as gssize,
            ) != 0
        }
    }

    /// Insert a `lea d, [s + o]` instruction.
    pub fn put_lea_reg_reg_offset(
        &self,
        dst_reg: X86Register,
        src_reg: X86Register,
        src_offset: isize,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_lea_reg_reg_offset(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
                src_offset as gssize,
            ) != 0
        }
    }

    pub fn put_push_u32(&self, imm: u32) {
        unsafe {
            gum_sys::gum_x86_writer_put_push_u32(self.writer, imm);
        }
    }

    pub fn put_push_near_ptr(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_near_ptr(self.writer, address) != 0 }
    }

    /// Insert a `push R` instruction.
    pub fn put_push_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_push_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a `pop R` instruction.
    pub fn put_pop_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_pop_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a call address instruction.
    pub fn put_call_address(&self, address: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_call_address(self.writer, address) != 0 }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_arguments(&self, address: u64, arguments: &[Argument]) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 {
                            reg: *register as i32,
                        },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_x86_writer_put_call_address_with_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    #[allow(clippy::useless_conversion)]
    pub fn put_call_address_with_aligned_arguments(
        &self,
        address: u64,
        arguments: &[Argument],
    ) -> bool {
        unsafe {
            let arguments: Vec<GumArgument> = arguments
                .iter()
                .map(|argument| match argument {
                    Argument::Register(register) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 {
                            reg: *register as i32,
                        },
                    },
                    Argument::Address(address) => GumArgument {
                        type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.try_into().unwrap(),
                        value: gum_sys::_GumArgument__bindgen_ty_1 { address: *address },
                    },
                })
                .collect();

            gum_sys::gum_x86_writer_put_call_address_with_aligned_arguments_array(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                address,
                arguments.len() as u32,
                arguments.as_ptr(),
            ) != 0
        }
    }

    pub fn put_test_reg_reg(&self, reg_a: X86Register, reg_b: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_test_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }
    pub fn put_nop(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_nop(self.writer);
        }
    }

    pub fn put_pushfx(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_pushfx(self.writer);
        }
    }

    pub fn put_popfx(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_popfx(self.writer);
        }
    }

    pub fn put_pushax(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_pushax(self.writer);
        }
    }

    pub fn put_popax(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_popax(self.writer);
        }
    }

    /// Insert a breakpoint instruction (int3).
    pub fn put_breakpoint(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_breakpoint(self.writer);
        }
    }

    /// Insert padding bytes (NOP instructions).
    pub fn put_padding(&self, n: u32) {
        unsafe {
            gum_sys::gum_x86_writer_put_padding(self.writer, n);
        }
    }

    /// Insert NOP instructions with specific encoding for padding.
    pub fn put_nop_padding(&self, n: u32) {
        unsafe {
            gum_sys::gum_x86_writer_put_nop_padding(self.writer, n);
        }
    }

    /// Insert a single unsigned 8-bit value.
    pub fn put_u8(&self, value: u8) {
        unsafe {
            gum_sys::gum_x86_writer_put_u8(self.writer, value);
        }
    }

    /// Insert a single signed 8-bit value.
    pub fn put_s8(&self, value: i8) {
        unsafe {
            gum_sys::gum_x86_writer_put_s8(self.writer, value);
        }
    }

    /// Insert a `call` indirect through an address.
    pub fn put_call_indirect(&self, addr: u64) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_call_indirect(self.writer, addr) != 0 }
    }

    /// Insert a `call` indirect through a label.
    pub fn put_call_indirect_label(&self, label_id: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_indirect_label(self.writer, label_id as *const c_void)
                != 0
        }
    }

    /// Insert a `call` near to a label.
    pub fn put_call_near_label(&self, label_id: u64) {
        unsafe {
            gum_sys::gum_x86_writer_put_call_near_label(self.writer, label_id as *const c_void);
        }
    }

    /// Insert a `call` to a register.
    pub fn put_call_reg(&self, reg: X86Register) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_call_reg(self.writer, reg as u32) != 0 }
    }

    /// Insert a `call` to a register with offset.
    pub fn put_call_reg_offset_ptr(&self, reg: X86Register, offset: isize) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_offset_ptr(
                self.writer,
                reg as u32,
                offset as gssize,
            ) != 0
        }
    }

    /// Insert a `call` to an address with arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_address_with_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        func: u64,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_address_with_arguments_array(
                self.writer,
                conv,
                func,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to an address with aligned arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_address_with_aligned_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        func: u64,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_address_with_aligned_arguments_array(
                self.writer,
                conv,
                func,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to a register with arguments.
    pub fn put_call_reg_with_arguments(&self, reg: X86Register, arguments: &[Argument]) -> bool {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_with_arguments(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                reg as u32,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            ) != 0
        }
    }

    /// Insert a `call` to a register with arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_reg_with_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        reg: u32,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_with_arguments_array(
                self.writer,
                conv,
                reg,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to a register with aligned arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_reg_with_aligned_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        reg: u32,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_with_aligned_arguments_array(
                self.writer,
                conv,
                reg,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to a register offset pointer with arguments.
    pub fn put_call_reg_offset_ptr_with_arguments(
        &self,
        reg: X86Register,
        offset: isize,
        arguments: &[Argument],
    ) -> bool {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_offset_ptr_with_arguments(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                reg as u32,
                offset as gssize,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            ) != 0
        }
    }

    /// Insert a `call` to a register offset pointer with arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_reg_offset_ptr_with_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        reg: u32,
        offset: isize,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_offset_ptr_with_arguments_array(
                self.writer,
                conv,
                reg,
                offset as gssize,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to a register offset pointer with aligned arguments.
    pub fn put_call_reg_offset_ptr_with_aligned_arguments(
        &self,
        reg: X86Register,
        offset: isize,
        arguments: &[Argument],
    ) -> bool {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                reg as u32,
                offset as gssize,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            ) != 0
        }
    }

    /// Insert a `call` to a register offset pointer with aligned arguments array.
    ///
    /// # Safety
    ///
    /// The `args` pointer must be valid for `n_args` elements.
    pub unsafe fn put_call_reg_offset_ptr_with_aligned_arguments_array(
        &self,
        conv: gum_sys::GumCallingConvention,
        reg: u32,
        offset: isize,
        n_args: u32,
        args: *const GumArgument,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_offset_ptr_with_aligned_arguments_array(
                self.writer,
                conv,
                reg,
                offset as gssize,
                n_args,
                args,
            ) != 0
        }
    }

    /// Insert a `call` to a register with aligned arguments.
    pub fn put_call_reg_with_aligned_arguments(
        &self,
        reg: X86Register,
        arguments: &[Argument],
    ) -> bool {
        let gum_arguments = Self::convert_arguments(arguments);
        unsafe {
            gum_sys::gum_x86_writer_put_call_reg_with_aligned_arguments(
                self.writer,
                gum_sys::_GumCallingConvention_GUM_CALL_CAPI
                    .try_into()
                    .unwrap(),
                reg as u32,
                gum_arguments.len() as u32,
                gum_arguments.as_ptr(),
            ) != 0
        }
    }

    /// Insert a CLC (clear carry flag) instruction.
    pub fn put_clc(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_clc(self.writer);
        }
    }

    /// Insert a STC (set carry flag) instruction.
    pub fn put_stc(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_stc(self.writer);
        }
    }

    /// Insert a CLD (clear direction flag) instruction.
    pub fn put_cld(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_cld(self.writer);
        }
    }

    /// Insert a STD (set direction flag) instruction.
    pub fn put_std(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_std(self.writer);
        }
    }

    /// Insert a CPUID instruction.
    pub fn put_cpuid(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_cpuid(self.writer);
        }
    }

    /// Insert a LFENCE (load fence) instruction.
    pub fn put_lfence(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_lfence(self.writer);
        }
    }

    /// Insert an RDTSC (read time-stamp counter) instruction.
    pub fn put_rdtsc(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_rdtsc(self.writer);
        }
    }

    /// Insert a PAUSE instruction.
    pub fn put_pause(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_pause(self.writer);
        }
    }

    /// Insert a LAHF (load flags into AH) instruction.
    pub fn put_lahf(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_lahf(self.writer);
        }
    }

    /// Insert a SAHF (store AH into flags) instruction.
    pub fn put_sahf(&self) {
        unsafe {
            gum_sys::gum_x86_writer_put_sahf(self.writer);
        }
    }

    /// Insert a `cmp` immediate pointer with immediate u32.
    pub fn put_cmp_imm_ptr_imm_u32(&self, imm_ptr: u64, imm_value: u32) {
        unsafe {
            gum_sys::gum_x86_writer_put_cmp_imm_ptr_imm_u32(
                self.writer,
                imm_ptr as *const c_void,
                imm_value,
            );
        }
    }

    /// Insert a `cmp` register with immediate i32.
    pub fn put_cmp_reg_i32(&self, reg: X86Register, imm_value: i32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_cmp_reg_i32(self.writer, reg as u32, imm_value) != 0 }
    }

    /// Insert a `cmp` register offset pointer with register.
    pub fn put_cmp_reg_offset_ptr_reg(
        &self,
        reg_a: X86Register,
        offset: isize,
        reg_b: X86Register,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_cmp_reg_offset_ptr_reg(
                self.writer,
                reg_a as u32,
                offset as gssize,
                reg_b as u32,
            ) != 0
        }
    }

    /// Insert a `cmp` register with register.
    pub fn put_cmp_reg_reg(&self, reg_a: X86Register, reg_b: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_cmp_reg_reg(self.writer, reg_a as u32, reg_b as u32) != 0
        }
    }

    /// Insert a `test` register with immediate u32.
    pub fn put_test_reg_u32(&self, reg: X86Register, imm_value: u32) -> bool {
        unsafe { gum_sys::gum_x86_writer_put_test_reg_u32(self.writer, reg as u32, imm_value) != 0 }
    }

    /// Insert a conditional jump short to the given condition.
    pub fn put_jcc_short(
        &self,
        condition: X86BranchCondition,
        target: u64,
        hint: GumBranchHint,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_short(
                self.writer,
                condition as _,
                target as *const c_void,
                hint,
            ) != 0
        }
    }

    /// Insert a conditional jump near to the given condition.
    pub fn put_jcc_near(
        &self,
        condition: X86BranchCondition,
        target: u64,
        hint: GumBranchHint,
    ) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_jcc_near(
                self.writer,
                condition as _,
                target as *const c_void,
                hint,
            ) != 0
        }
    }

    /// Insert a `inc` to a register pointer.
    ///
    /// # Arguments
    ///
    /// * `target` - Pointer size: BYTE (0), DWORD (1), or QWORD (2)
    /// * `reg` - Register to increment
    pub fn put_inc_reg_ptr(&self, target: u32, reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_inc_reg_ptr(self.writer, target, reg as u32);
        }
    }

    /// Insert a `dec` to a register pointer.
    ///
    /// # Arguments
    ///
    /// * `target` - Pointer size: BYTE (0), DWORD (1), or QWORD (2)
    /// * `reg` - Register to decrement
    pub fn put_dec_reg_ptr(&self, target: u32, reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_dec_reg_ptr(self.writer, target, reg as u32);
        }
    }

    /// Insert a `lock inc` to an immediate 32-bit pointer.
    pub fn put_lock_inc_imm32_ptr(&self, target: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_lock_inc_imm32_ptr(self.writer, target as *mut c_void) != 0
        }
    }

    /// Insert a `lock dec` to an immediate 32-bit pointer.
    pub fn put_lock_dec_imm32_ptr(&self, target: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_lock_dec_imm32_ptr(self.writer, target as *mut c_void) != 0
        }
    }

    /// Insert a `lock cmpxchg` register pointer with register.
    pub fn put_lock_cmpxchg_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `lock xadd` register pointer with register.
    pub fn put_lock_xadd_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_lock_xadd_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `xchg` register with register pointer.
    pub fn put_xchg_reg_reg_ptr(&self, left_reg: X86Register, right_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_xchg_reg_reg_ptr(
                self.writer,
                left_reg as u32,
                right_reg as u32,
            );
        }
    }

    /// Insert a `push` immediate pointer.
    pub fn put_push_imm_ptr(&self, imm_ptr: u64) {
        unsafe {
            gum_sys::gum_x86_writer_put_push_imm_ptr(self.writer, imm_ptr as *const c_void);
        }
    }

    /// Insert a `mov` from near pointer to register.
    pub fn put_mov_reg_near_ptr(&self, dst_reg: X86Register, src: u64) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_near_ptr(self.writer, dst_reg as u32, src) != 0
        }
    }

    /// Insert a `mov` from register to near pointer.
    pub fn put_mov_near_ptr_reg(&self, dst: u64, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_near_ptr_reg(self.writer, dst, src_reg as u32) != 0
        }
    }

    /// Insert a `mov` from FS segment register pointer to register.
    pub fn put_mov_reg_fs_reg_ptr(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_fs_reg_ptr(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `mov` from FS segment u32 pointer to register.
    pub fn put_mov_reg_fs_u32_ptr(&self, dst_reg: X86Register, fs_offset: u32) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_fs_u32_ptr(self.writer, dst_reg as u32, fs_offset)
                != 0
        }
    }

    /// Insert a `mov` from register to FS segment register pointer.
    pub fn put_mov_fs_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_fs_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `mov` from register to FS segment u32 pointer.
    pub fn put_mov_fs_u32_ptr_reg(&self, fs_offset: u32, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_fs_u32_ptr_reg(self.writer, fs_offset, src_reg as u32)
                != 0
        }
    }

    /// Insert a `mov` from GS segment register pointer to register.
    pub fn put_mov_reg_gs_reg_ptr(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_reg_gs_reg_ptr(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `mov` from register to GS segment register pointer.
    pub fn put_mov_gs_reg_ptr_reg(&self, dst_reg: X86Register, src_reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_gs_reg_ptr_reg(
                self.writer,
                dst_reg as u32,
                src_reg as u32,
            );
        }
    }

    /// Insert a `mov` from register to GS segment u32 pointer.
    pub fn put_mov_gs_u32_ptr_reg(&self, gs_offset: u32, src_reg: X86Register) -> bool {
        unsafe {
            gum_sys::gum_x86_writer_put_mov_gs_u32_ptr_reg(self.writer, gs_offset, src_reg as u32)
                != 0
        }
    }

    /// Insert a `movdqu` from XMM0 to EAX offset pointer.
    pub fn put_movdqu_eax_offset_ptr_xmm0(&self, offset: i8) {
        unsafe {
            gum_sys::gum_x86_writer_put_movdqu_eax_offset_ptr_xmm0(self.writer, offset);
        }
    }

    /// Insert a `movdqu` from ESP offset pointer to XMM0.
    pub fn put_movdqu_xmm0_esp_offset_ptr(&self, offset: i8) {
        unsafe {
            gum_sys::gum_x86_writer_put_movdqu_xmm0_esp_offset_ptr(self.writer, offset);
        }
    }

    /// Insert a `movq` from XMM0 to EAX offset pointer.
    pub fn put_movq_eax_offset_ptr_xmm0(&self, offset: i8) {
        unsafe {
            gum_sys::gum_x86_writer_put_movq_eax_offset_ptr_xmm0(self.writer, offset);
        }
    }

    /// Insert a `movq` from ESP offset pointer to XMM0.
    pub fn put_movq_xmm0_esp_offset_ptr(&self, offset: i8) {
        unsafe {
            gum_sys::gum_x86_writer_put_movq_xmm0_esp_offset_ptr(self.writer, offset);
        }
    }

    /// Insert an `fxsave` to a register pointer.
    pub fn put_fxsave_reg_ptr(&self, reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_fxsave_reg_ptr(self.writer, reg as u32);
        }
    }

    /// Insert an `fxrstor` from a register pointer.
    pub fn put_fxrstor_reg_ptr(&self, reg: X86Register) {
        unsafe {
            gum_sys::gum_x86_writer_put_fxrstor_reg_ptr(self.writer, reg as u32);
        }
    }

    /// Helper to convert Argument slice to GumArgument Vec.
    fn convert_arguments(arguments: &[Argument]) -> Vec<GumArgument> {
        arguments
            .iter()
            .map(|arg| match arg {
                Argument::Register(reg) => GumArgument {
                    type_: gum_sys::_GumArgType_GUM_ARG_REGISTER.try_into().unwrap(),
                    value: gum_sys::_GumArgument__bindgen_ty_1 { reg: *reg as i32 },
                },
                Argument::Address(addr) => GumArgument {
                    type_: gum_sys::_GumArgType_GUM_ARG_ADDRESS.try_into().unwrap(),
                    value: gum_sys::_GumArgument__bindgen_ty_1 { address: *addr },
                },
            })
            .collect()
    }
}

impl Drop for X86InstructionWriter {
    fn drop(&mut self) {
        if self.is_from_new {
            unsafe { gum_sys::gum_x86_writer_unref(self.writer) }
        }
    }
}
