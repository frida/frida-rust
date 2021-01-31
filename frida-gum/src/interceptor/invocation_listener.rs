use frida_gum_sys as gum_sys;
use std::marker::PhantomData;
use std::os::raw::c_void;

/// Represents a pair of listeners attached to a function.
pub trait InvocationListener {
    /// Called when the attached function is entered.
    fn on_enter(&mut self, context: InvocationContext);
    /// Called before the attached function is exited.
    fn on_leave(&mut self, context: InvocationContext);
}

unsafe extern "C" fn call_on_enter<I: InvocationListener>(
    user_data: *mut c_void,
    context: *mut gum_sys::GumInvocationContext,
) {
    let listener: &mut I = &mut *(user_data as *mut I);
    listener.on_enter(InvocationContext {
        context,
        phantom: PhantomData,
    });
}

unsafe extern "C" fn call_on_leave<I: InvocationListener>(
    user_data: *mut c_void,
    context: *mut gum_sys::GumInvocationContext,
) {
    let listener: &mut I = &mut *(user_data as *mut I);
    listener.on_leave(InvocationContext {
        context,
        phantom: PhantomData,
    });
}

pub(crate) fn invocation_listener_transform<I: InvocationListener>(
    mut invocation_listener: &I,
) -> *mut frida_gum_sys::GumInvocationListener {
    let rust = frida_gum_sys::RustInvocationListenerVTable {
        user_data: &mut invocation_listener as *mut _ as *mut c_void,
        on_enter: Some(call_on_enter::<I>),
        on_leave: Some(call_on_leave::<I>),
    };

    unsafe { frida_gum_sys::gum_rust_invocation_listener_new(rust) }
}

/// Represents the processor state when an [`InvocationListener`] is entered.
pub struct InvocationContext<'a> {
    context: *mut gum_sys::GumInvocationContext,
    phantom: PhantomData<&'a gum_sys::GumInvocationContext>,
}

/// Represents the points at which an [`InvocationContext`] can exist.
pub enum PointCut {
    Enter,
    Leave,
}

impl From<gum_sys::GumPointCut> for PointCut {
    fn from(point_cut: gum_sys::GumPointCut) -> PointCut {
        match point_cut {
            gum_sys::_GumPointCut_GUM_POINT_ENTER => PointCut::Enter,
            gum_sys::_GumPointCut_GUM_POINT_LEAVE => PointCut::Leave,
            _ => unreachable!(),
        }
    }
}

impl<'a> InvocationContext<'a> {
    /// Point at which the [`InvocationContext`] exists.
    pub fn point_cut(&self) -> PointCut {
        unsafe { gum_sys::gum_invocation_context_get_point_cut(self.context) }.into()
    }

    /// Get a numbered argument from the processor context, determined by the platform calling convention.
    pub fn arg(&self, n: u32) -> usize {
        unsafe { gum_sys::gum_invocation_context_get_nth_argument(self.context, n) as usize }
    }

    /// Set a numbered argument in the processor context, determined by the platform calling convention.
    pub unsafe fn set_arg(&self, n: u32, value: usize) {
        gum_sys::gum_invocation_context_replace_nth_argument(self.context, n, value as *mut c_void)
    }

    /// Get the value of the register used for the platform calling convention's return value.
    pub fn return_value(&self) -> usize {
        unsafe { gum_sys::gum_invocation_context_get_return_value(self.context) as usize }
    }

    /// Set the value of the register used for the platform calling convention's return value.
    pub unsafe fn set_return_value(&self, value: usize) {
        gum_sys::gum_invocation_context_replace_return_value(self.context, value as *mut c_void)
    }

    /// Get the destination address after the function returns.
    pub fn return_addr(&self) -> usize {
        unsafe { gum_sys::gum_invocation_context_get_return_address(self.context) as usize }
    }

    /// Get the thread ID of the currently executing function.
    pub fn thread_id(&self) -> u32 {
        unsafe { gum_sys::gum_invocation_context_get_thread_id(self.context) as u32 }
    }

    /// Get the number of recursive interceptor invocations.
    pub fn depth(&self) -> u32 {
        unsafe { gum_sys::gum_invocation_context_get_depth(self.context) as u32 }
    }
}
