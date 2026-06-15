/*
 * Copyright © 2026 Kirby Kuehl
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Native control-flow graph construction and dominator analysis.
//!
//! A [`ControlFlowGraph`] models the basic blocks of a function and the edges
//! between them, computed directly from machine code. It can be built for a
//! function whose entry point is known ([`ControlFlowGraph::for_function`]),
//! and then queried for block bounds, successors/predecessors, and dominance
//! relationships (using the Cooper-Harvey-Kennedy dominator algorithm).
//!
//! This is particularly useful for deciding *where* it is safe to install a
//! redirect: [`ControlFlowGraph::enumerate_dominating_sites`] reports the
//! instruction-aligned addresses that dominate a target along with how many
//! contiguous bytes may be overwritten there without another control-flow edge
//! landing inside the redirect.

use {crate::NativePointer, core::ffi::c_void, frida_gum_sys as gum_sys};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A site that dominates a target address, reported by
/// [`ControlFlowGraph::enumerate_dominating_sites`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DominatingSite {
    /// Instruction-aligned address that dominates the target.
    pub site: NativePointer,
    /// Number of contiguous bytes at `site` that may be overwritten by a
    /// redirect without another control-flow edge landing inside them.
    pub capacity: usize,
}

/// The start and end (exclusive) addresses of a basic block.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BlockBounds {
    /// First address of the block.
    pub start: u64,
    /// One past the last address of the block.
    pub end: u64,
}

/// A control-flow graph computed from machine code.
pub struct ControlFlowGraph {
    inner: *mut gum_sys::GumControlFlowGraph,
}

impl ControlFlowGraph {
    /// Build a control-flow graph starting at `entry`, decoding instructions
    /// with the given capstone architecture and mode.
    ///
    /// `find_range` is called to resolve the contiguous code range covering an
    /// address — for the entry, and for every direct branch target that falls
    /// outside the ranges discovered so far. It receives the address to locate
    /// and must return `Some(MemoryRange)` for the covering range, or `None`
    /// if the address is not part of any known code range.
    ///
    /// Prefer [`ControlFlowGraph::for_function`] unless you need to supply a
    /// custom range resolver (e.g. for code that is not described by the
    /// platform's unwind information).
    ///
    /// # Safety
    ///
    /// `entry` must point to a valid instruction decodable with `arch`/`mode`,
    /// and `find_range` must return ranges that accurately describe readable,
    /// executable memory.
    pub unsafe fn new<F>(
        entry: NativePointer,
        arch: gum_sys::cs_arch,
        mode: gum_sys::cs_mode,
        mut find_range: F,
    ) -> Self
    where
        F: FnMut(NativePointer) -> Option<crate::MemoryRange>,
    {
        unsafe extern "C" fn trampoline<F>(
            address: gum_sys::gconstpointer,
            range: *mut gum_sys::GumMemoryRange,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(NativePointer) -> Option<crate::MemoryRange>,
        {
            let find_range = unsafe { &mut *(user_data as *mut F) };
            match find_range(NativePointer(address as *mut c_void)) {
                Some(found) => {
                    unsafe { *range = found.memory_range };
                    i32::from(true)
                }
                None => i32::from(false),
            }
        }

        Self {
            inner: unsafe {
                gum_sys::gum_control_flow_graph_new(
                    entry.0,
                    arch,
                    mode,
                    Some(trampoline::<F>),
                    &mut find_range as *mut _ as *mut c_void,
                )
            },
        }
    }

    /// Build a control-flow graph for the function starting at `entry_point`.
    ///
    /// Ranges are resolved via the platform's unwind information, so this works
    /// even on stripped binaries with no symbol table.
    ///
    /// # Safety
    ///
    /// `entry_point` must point to the first instruction of a function in a
    /// readable, executable memory region.
    pub unsafe fn for_function(entry_point: NativePointer) -> Self {
        Self {
            inner: unsafe { gum_sys::gum_control_flow_graph_new_for_function(entry_point.0) },
        }
    }

    /// Whether block dominance holds between two addresses: returns `true` if
    /// every path from the entry to `b` passes through `a`.
    pub fn dominates(&self, a: NativePointer, b: NativePointer) -> bool {
        unsafe { gum_sys::gum_control_flow_graph_dominates(self.inner, a.0, b.0) != 0 }
    }

    /// Enumerate the instruction-aligned sites that dominate `target`.
    ///
    /// The closure is invoked once per [`DominatingSite`]; return `true` to
    /// continue enumeration or `false` to stop early.
    pub fn enumerate_dominating_sites<F>(&self, target: NativePointer, mut callback: F)
    where
        F: FnMut(DominatingSite) -> bool,
    {
        unsafe extern "C" fn trampoline<F>(
            site: gum_sys::gconstpointer,
            capacity: gum_sys::gsize,
            user_data: gum_sys::gpointer,
        ) -> gum_sys::gboolean
        where
            F: FnMut(DominatingSite) -> bool,
        {
            let callback = unsafe { &mut *(user_data as *mut F) };
            let cont = callback(DominatingSite {
                site: NativePointer(site as *mut c_void),
                capacity: capacity as usize,
            });
            i32::from(cont)
        }

        unsafe {
            gum_sys::gum_control_flow_graph_enumerate_dominating_sites(
                self.inner,
                target.0,
                Some(trampoline::<F>),
                &mut callback as *mut _ as *mut c_void,
            );
        }
    }

    /// The number of basic blocks in the graph.
    pub fn num_blocks(&self) -> u32 {
        unsafe { gum_sys::gum_control_flow_graph_get_num_blocks(self.inner) }
    }

    /// The index of the entry block.
    pub fn entry_block(&self) -> u32 {
        unsafe { gum_sys::gum_control_flow_graph_get_entry_block(self.inner) }
    }

    /// Find the index of the block containing `address`.
    pub fn find_block_containing(&self, address: NativePointer) -> u32 {
        unsafe { gum_sys::gum_control_flow_graph_find_block_containing(self.inner, address.0) }
    }

    /// Get the start/end bounds of the block at `index`.
    pub fn block_bounds(&self, index: u32) -> BlockBounds {
        let mut start: gum_sys::GumAddress = 0;
        let mut end: gum_sys::GumAddress = 0;
        unsafe {
            gum_sys::gum_control_flow_graph_get_block_bounds(
                self.inner, index, &mut start, &mut end,
            );
        }
        BlockBounds { start, end }
    }

    /// Get the index of the immediate dominator of the block at `index`.
    pub fn block_immediate_dominator(&self, index: u32) -> u32 {
        unsafe { gum_sys::gum_control_flow_graph_get_block_immediate_dominator(self.inner, index) }
    }

    /// Get the successor block indices of the block at `index`.
    pub fn block_successors(&self, index: u32) -> Vec<u32> {
        let mut ptr: *const gum_sys::guint = core::ptr::null();
        let len = unsafe {
            gum_sys::gum_control_flow_graph_get_block_successors(self.inner, index, &mut ptr)
        };
        unsafe { slice_to_vec(ptr, len) }
    }

    /// Get the predecessor block indices of the block at `index`.
    pub fn block_predecessors(&self, index: u32) -> Vec<u32> {
        let mut ptr: *const gum_sys::guint = core::ptr::null();
        let len = unsafe {
            gum_sys::gum_control_flow_graph_get_block_predecessors(self.inner, index, &mut ptr)
        };
        unsafe { slice_to_vec(ptr, len) }
    }

    /// Find the capstone instruction containing `address`, if any.
    ///
    /// The returned pointer is owned by the graph and is valid only for as long
    /// as this [`ControlFlowGraph`] is alive.
    pub fn find_instruction_containing(
        &self,
        address: NativePointer,
    ) -> Option<*const gum_sys::cs_insn> {
        let insn = unsafe {
            gum_sys::gum_control_flow_graph_find_instruction_containing(self.inner, address.0)
        };
        if insn.is_null() { None } else { Some(insn) }
    }
}

/// Copy a C array of `guint` (owned by the graph) into an owned `Vec<u32>`.
unsafe fn slice_to_vec(ptr: *const gum_sys::guint, len: gum_sys::guint) -> Vec<u32> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { core::slice::from_raw_parts(ptr, len as usize).to_vec() }
}

impl Drop for ControlFlowGraph {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_control_flow_graph_free(self.inner) };
    }
}
