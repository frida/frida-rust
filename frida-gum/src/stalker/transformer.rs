use crate::{CpuContext, Gum};
use std::marker::PhantomData;
use std::collections::HashMap;
use std::ffi::c_void;

//use std::rc::Rc;
use std::cell::RefCell;

//use lazy_static::lazy_static;

struct ClosureMap {
    cache: HashMap<*const c_void, *mut c_void>,
}

impl ClosureMap {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    pub fn contains_key(&self, key: *const c_void) -> bool {
        //println!("contains_key: {:?}", key);
        self.cache.contains_key(&key)
    }

    pub fn insert(&mut self, key: *const c_void, value: *mut c_void) -> Option<*mut c_void> {
        self.cache.insert(key, value)
    }

    pub fn get(&self, key: *const c_void) -> *mut c_void {
        *self.cache.get(&key).unwrap() as *mut c_void
    }

}

//unsafe impl Sync for ClosureMap {}
//unsafe impl Send for ClosureMap {}



//lazy_static!{
    //static ref CLOSURE_MAP: ClosureMap<HashMap<*const c_void, *mut c_void>> = ClosureMap { cache: HashMap::new() };
//}
static mut CLOSURE_MAP: Option<RefCell<ClosureMap>> = None;

pub struct StalkerIterator<'a> {
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerIterator>,
}

extern "C" fn put_callout_callback(
    cpu_context: *mut frida_gum_sys::GumCpuContext,
    user_data: *mut c_void,
) {
    //let mut f = unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(CpuContext)>) };
    unsafe {
        (*(user_data as *mut Box<dyn FnMut(CpuContext)>))(CpuContext::from_raw(cpu_context));
    }
    // Leak the box again, we want to destruct it in the data_destroy callback.
    //
    //Box::leak(f);
}

//unsafe extern "C" fn put_callout_destroy(_user_data: *mut c_void) {
    ////let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(CpuContext)>);
//}

impl<'a> StalkerIterator<'a> {
    fn from_raw(iterator: *mut frida_gum_sys::GumStalkerIterator) -> StalkerIterator<'a> {
        StalkerIterator {
            iterator,
            phantom: PhantomData,
        }
    }

    pub fn keep_instr(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.iterator) };
    }

    pub fn put_callout(&self, callout: impl FnMut(CpuContext)) {
        unsafe {
            let callout_ptr = &callout as *const _ as *const c_void;
            let cm = &mut CLOSURE_MAP.as_mut().unwrap();
            let mut closure_map = cm.borrow_mut();
            let user_data = if !closure_map.contains_key(callout_ptr) {
                let new_user_data = Box::into_raw(Box::new(Box::new(callout) as Box<dyn FnMut(CpuContext)>))
                    as *mut _ as *mut c_void;
                closure_map.insert(callout_ptr, new_user_data);
                new_user_data
            } else {
                closure_map.get(callout_ptr)
            };

            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.iterator,
                Some(put_callout_callback),
                user_data,
                None,
                //Some(put_callout_destroy),
            )
        };
    }
}

use frida_gum_sys::cs_insn;

pub struct Instruction<'a> {
    parent: *mut frida_gum_sys::GumStalkerIterator,
    _instr: *const cs_insn,
    phantom: PhantomData<&'a *const cs_insn>,
}

impl<'a> Instruction<'a> {
    fn from_raw(
        parent: *mut frida_gum_sys::GumStalkerIterator,
        instr: *const cs_insn,
    ) -> Instruction<'a> {
        Instruction {
            parent,
            _instr: instr,
            phantom: PhantomData,
        }
    }

    pub fn keep(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.parent) };
    }

    pub fn put_callout(&self, callout: impl FnMut(CpuContext)) {
        unsafe {
            let callout_ptr = &callout as *const _ as *const c_void;
            let cm = &mut CLOSURE_MAP.as_mut().unwrap();
            let mut closure_map = cm.borrow_mut();
            let user_data = if !closure_map.contains_key(callout_ptr) {
                let new_user_data = Box::into_raw(Box::new(Box::new(callout) as Box<dyn FnMut(CpuContext)>))
                    as *mut _ as *mut c_void;
                closure_map.insert(callout_ptr, new_user_data);
                new_user_data
            } else {
                closure_map.get(callout_ptr)
            };

            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.parent,
                Some(put_callout_callback),
                user_data,
                None,
                //Some(put_callout_destroy),
            )
        };
    }

    pub fn get_instruction(&self) -> *const cs_insn {
        self._instr
    }
}

impl<'a> Iterator for StalkerIterator<'a> {
    type Item = Instruction<'a>;

    fn next(&mut self) -> Option<Instruction<'a>> {
        let mut instr: *const cs_insn = std::ptr::null();
        if unsafe { frida_gum_sys::gum_stalker_iterator_next(self.iterator, &mut instr as *mut _) }
            != 0
        {
            Some(Instruction::from_raw(self.iterator, instr))
        } else {
            None
        }
    }
}

pub struct StalkerOutput<'a> {
    pub output: *mut frida_gum_sys::GumStalkerOutput,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerOutput>,
}

impl<'a> StalkerOutput<'a> {
    fn from_raw(output: *mut frida_gum_sys::GumStalkerOutput) -> StalkerOutput<'a> {
        StalkerOutput {
            output,
            phantom: PhantomData,
        }
    }
}

extern "C" fn transformer_callback(
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    output: *mut frida_gum_sys::GumStalkerOutput,
    user_data: *mut c_void,
) {
    let mut f =
        unsafe { Box::from_raw(user_data as *mut Box<dyn FnMut(StalkerIterator, StalkerOutput)>) };
    f(
        StalkerIterator::from_raw(iterator),
        StalkerOutput::from_raw(output),
    );
    // Leak the box again, we want to destruct it in the data_destroy callback.
    //
    Box::leak(f);
}

unsafe extern "C" fn transformer_destroy(user_data: *mut c_void) {
    let _ = Box::from_raw(user_data as *mut Box<dyn FnMut(StalkerIterator, StalkerOutput)>);
}

pub struct Transformer<'a> {
    pub(crate) transformer: *mut frida_gum_sys::GumStalkerTransformer,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerTransformer>,
}

impl<'a> Transformer<'a> {
    pub fn from_callback<'b>(
        _gum: &'b Gum,
        callback: impl FnMut(StalkerIterator, StalkerOutput),
    ) -> Transformer<'a>
    where
        'b: 'a,
    {

        unsafe {
            CLOSURE_MAP = Some(RefCell::new(ClosureMap::new()));
        }


        let user_data = Box::leak(Box::new(
            Box::new(callback) as Box<dyn FnMut(StalkerIterator, StalkerOutput)>
        )) as *mut _ as *mut c_void;

        Transformer {
            transformer: unsafe {
                frida_gum_sys::gum_stalker_transformer_make_from_callback(
                    Some(transformer_callback),
                    user_data,
                    Some(transformer_destroy),
                )
            },
            phantom: PhantomData,
        }
    }
}

impl<'a> Drop for Transformer<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::g_object_unref(self.transformer as *mut c_void) }
    }
}
