use core::ffi::CStr;
use core::fmt::{self, Debug};

use bitflags::bitflags;
use frida_gum_sys::{
    self as gum_sys, GumCpuContext, GumThreadFlags, GumThreadFlags_GUM_THREAD_FLAGS_ALL,
    GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT,
    GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER,
    GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE, GumThreadFlags_GUM_THREAD_FLAGS_NAME,
    GumThreadFlags_GUM_THREAD_FLAGS_NONE, GumThreadFlags_GUM_THREAD_FLAGS_STATE, GumThreadId,
    GumThreadState_GUM_THREAD_HALTED, GumThreadState_GUM_THREAD_STOPPED,
    GumThreadState_GUM_THREAD_UNINTERRUPTIBLE, GumThreadState_GUM_THREAD_WAITING,
};
use frida_gum_sys::{GumThreadDetails, GumThreadState_GUM_THREAD_RUNNING};
use num::FromPrimitive;

#[cfg(feature = "backtrace")]
use crate::Backtracer;
use crate::{CpuContext, NativePointer};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ThreadFlags: GumThreadFlags {
        const NAME                 = GumThreadFlags_GUM_THREAD_FLAGS_NAME;
        const STATE                = GumThreadFlags_GUM_THREAD_FLAGS_STATE;
        const CPU_CONTEXT          = GumThreadFlags_GUM_THREAD_FLAGS_CPU_CONTEXT;
        const ENTRYPOINT_ROUTINE   = GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_ROUTINE;
        const ENTRYPOINT_PARAMETER = GumThreadFlags_GUM_THREAD_FLAGS_ENTRYPOINT_PARAMETER;

        const NONE = GumThreadFlags_GUM_THREAD_FLAGS_NONE;
        const ALL = GumThreadFlags_GUM_THREAD_FLAGS_ALL;
    }
}

#[derive(Debug, FromPrimitive)]
#[repr(u32)] // Repr GumThreadState (c_uint) not available
pub enum ThreadState {
    Running = GumThreadState_GUM_THREAD_RUNNING as _,
    Stopped = GumThreadState_GUM_THREAD_STOPPED as _,
    Waiting = GumThreadState_GUM_THREAD_WAITING as _,
    Uninterruptible = GumThreadState_GUM_THREAD_UNINTERRUPTIBLE as _,
    Halted = GumThreadState_GUM_THREAD_HALTED as _,
}

#[derive(Debug)]
pub struct Entrypoint {
    pub routine: NativePointer,
    pub parameter: NativePointer,
}

pub struct Thread {
    thread: *mut GumThreadDetails,
}

impl Thread {
    pub(crate) fn from_raw(thread: *const GumThreadDetails) -> Self {
        // I'm not sure if copying the threads details is needed, but it looks like that threads are not refcounted, so
        // there is no guarantee that they won't be freed
        let thread = unsafe { gum_sys::gum_thread_details_copy(thread) };

        Self { thread }
    }

    pub fn flags(&self) -> ThreadFlags {
        ThreadFlags::from_bits_truncate((unsafe { &*self.thread }).flags)
    }

    pub fn id(&self) -> GumThreadId {
        unsafe { &*self.thread }.id
    }

    pub fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(({ *self.thread }).name) }
    }

    pub fn state(&self) -> ThreadState {
        ThreadState::from_u32(unsafe { ({ *self.thread }).state } as _).unwrap()
    }

    fn gum_cpu_context(&self) -> &GumCpuContext {
        unsafe { &(*self.thread).cpu_context }
    }

    // todo: return an immutable reference instead of an owned object; without this multiple threads can obtain a Process instance,
    // get the same CpuContexts and cause a data race
    /// Modifying CpuContexts from multiple threads is unsound, as they may share the same pointer
    pub fn cpu_context(&self) -> CpuContext<'_> {
        CpuContext::from_raw(self.gum_cpu_context() as *const _ as *mut GumCpuContext)
    }

    pub fn entrypoint(&self) -> Entrypoint {
        let entrypoint = unsafe { &(*self.thread).entrypoint };
        Entrypoint {
            routine: NativePointer(entrypoint.routine as *mut _),
            parameter: NativePointer(entrypoint.parameter as *mut _),
        }
    }

    #[cfg(feature = "backtrace")]
    pub fn backtrace_accurate(&self) -> Vec<usize> {
        Backtracer::accurate_with_context(self.gum_cpu_context())
    }

    #[cfg(feature = "backtrace")]
    pub fn backtrace_fuzzy(&self) -> Vec<usize> {
        Backtracer::fuzzy_with_context(self.gum_cpu_context())
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        unsafe { gum_sys::gum_thread_details_free(self.thread) };
    }
}

impl Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thread")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}
