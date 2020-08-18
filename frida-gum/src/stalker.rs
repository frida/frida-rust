use std::marker::PhantomData;
use std::os::raw::c_void;

use frida_gum_sys;
use frida_gum_sys::_GumEvent as GumEvent;

use crate::{Gum, NativePointer};

#[derive(FromPrimitive)]
#[repr(u32)]
pub enum EventMask {
    None = 0,
    Call = 1 << 0,
    Ret = 1 << 1,
    Exec = 1 << 2,
    Block = 1 << 3,
    Compile = 1 << 4,
}

pub enum Event {
    Call {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Ret {
        location: NativePointer,
        target: NativePointer,
        depth: i32,
    },
    Exec {
        location: NativePointer,
    },
    Block {
        begin: NativePointer,
        end: NativePointer,
    },
    Compile {
        begin: NativePointer,
        end: NativePointer,
    },
}

impl From<GumEvent> for Event {
    fn from(event: GumEvent) -> Event {
        match num::FromPrimitive::from_u32(unsafe { event.type_ }).unwrap() {
            EventMask::None => unreachable!(),
            EventMask::Call => {
                let call = unsafe { event.call };
                Event::Call {
                    location: NativePointer(call.location),
                    target: NativePointer(call.target),
                    depth: call.depth,
                }
            }
            EventMask::Ret => {
                let ret = unsafe { event.ret };
                Event::Ret {
                    location: NativePointer(ret.location),
                    target: NativePointer(ret.target),
                    depth: ret.depth,
                }
            }
            EventMask::Exec => {
                let exec = unsafe { event.exec };
                Event::Exec {
                    location: NativePointer(exec.location),
                }
            }
            EventMask::Block => {
                let block = unsafe { event.block };
                Event::Block {
                    begin: NativePointer(block.begin),
                    end: NativePointer(block.end),
                }
            }
            EventMask::Compile => {
                let compile = unsafe { event.compile };
                Event::Compile {
                    begin: NativePointer(compile.begin),
                    end: NativePointer(compile.end),
                }
            }
        }
    }
}

pub trait EventSink {
    fn query_mask(&mut self) -> EventMask;
    fn start(&mut self);
    fn process(&mut self, event: &Event);
    fn flush(&mut self);
    fn stop(&mut self);
}

unsafe extern "C" fn call_start<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = std::mem::transmute(user_data);
    event_sink.start();
}

unsafe extern "C" fn call_process<S: EventSink>(
    user_data: *mut c_void,
    event: *const frida_gum_sys::GumEvent,
) {
    let event_sink: &mut S = std::mem::transmute(user_data);
    event_sink.process(&(*event).into());
}

unsafe extern "C" fn call_flush<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = std::mem::transmute(user_data);
    event_sink.flush();
}

unsafe extern "C" fn call_stop<S: EventSink>(user_data: *mut c_void) {
    let event_sink: &mut S = std::mem::transmute(user_data);
    event_sink.stop();
}

unsafe extern "C" fn call_query_mask<S: EventSink>(
    user_data: *mut c_void,
) -> frida_gum_sys::GumEventType {
    let event_sink: &mut S = std::mem::transmute(user_data);
    event_sink.query_mask() as u32
}

fn event_sink_transform<S: EventSink>(mut event_sink: &S) -> *mut frida_gum_sys::GumEventSink {
    let rust = frida_gum_sys::RustVTable {
        user_data: &mut event_sink as *mut _ as *mut c_void,
        query_mask: Some(call_query_mask::<S>),
        start: Some(call_start::<S>),
        process: Some(call_process::<S>),
        flush: Some(call_flush::<S>),
        stop: Some(call_stop::<S>),
    };

    unsafe { frida_gum_sys::gum_rust_event_sink_new(rust) }
}

pub struct CpuContext<'a> {
    cpu_context: *mut frida_gum_sys::GumCpuContext,
    phantom: PhantomData<&'a frida_gum_sys::GumCpuContext>,
}

impl<'a> CpuContext<'a> {
    fn from_raw(cpu_context: *mut frida_gum_sys::GumCpuContext) -> CpuContext<'a> {
        CpuContext {
            cpu_context,
            phantom: PhantomData,
        }
    }
}

pub struct StalkerIterator<'a> {
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerIterator>,
}

unsafe extern "C" fn spring1<F>(
    cpu_context: *mut frida_gum_sys::GumCpuContext,
    user_data: *mut c_void,
) where
    F: FnMut(CpuContext),
{
    let user_data = &mut *(user_data as *mut F);
    user_data(CpuContext::from_raw(cpu_context));
}

pub fn get_trampoline1<F>(_closure: &F) -> frida_gum_sys::GumStalkerCallout
where
    F: FnMut(CpuContext),
{
    Some(spring1::<F>)
}

// IntoIterator is what you want to implement !!!
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

    pub fn put_callout(&self, mut callout: impl FnMut(CpuContext)) {
        unsafe {
            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.iterator,
                get_trampoline1(&callout),
                &mut callout as *mut _ as *mut c_void,
                None,
            )
        };
    }
}

use frida_gum_sys::cs_insn;

pub struct Instruction<'a> {
    parent: *mut frida_gum_sys::GumStalkerIterator,
    instr: *const cs_insn,
    phantom: PhantomData<&'a *const cs_insn>,
}

impl<'a> Instruction<'a> {
    fn from_raw(
        parent: *mut frida_gum_sys::GumStalkerIterator,
        instr: *const cs_insn,
    ) -> Instruction<'a> {
        Instruction {
            parent,
            instr,
            phantom: PhantomData,
        }
    }

    pub fn keep(&self) {
        unsafe { frida_gum_sys::gum_stalker_iterator_keep(self.parent) };
    }

    pub fn put_callout(&self, mut callout: impl FnMut(CpuContext)) {
        unsafe {
            frida_gum_sys::gum_stalker_iterator_put_callout(
                self.parent,
                get_trampoline1(&callout),
                &mut callout as *mut _ as *mut c_void,
                None,
            )
        };
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

// impl<'a> Iterator for StalkerIterator<'a> {
//     type Item = *const cs_insn;
//
//     fn next(&mut self) -> Option<*const cs_insn> {
//         let mut instr: *const cs_insn = std::ptr::null();
//         if unsafe { frida_gum_sys::gum_stalker_iterator_next(self.iterator, &mut instr as *mut _) }
//             != 0
//         {
//             Some(instr)
//         } else {
//             None
//         }
//     }
// }

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

unsafe extern "C" fn spring<F>(
    iterator: *mut frida_gum_sys::GumStalkerIterator,
    output: *mut frida_gum_sys::GumStalkerOutput,
    user_data: *mut c_void,
) where
    F: FnMut(StalkerIterator, StalkerOutput),
{
    let user_data = &mut *(user_data as *mut F);
    user_data(
        StalkerIterator::from_raw(iterator),
        StalkerOutput::from_raw(output),
    );
}

pub fn get_trampoline<F>(_closure: &F) -> frida_gum_sys::GumStalkerTransformerCallback
where
    F: FnMut(StalkerIterator, StalkerOutput),
{
    Some(spring::<F>)
}

pub struct Transformer<'a> {
    transformer: *mut frida_gum_sys::GumStalkerTransformer,
    phantom: PhantomData<&'a frida_gum_sys::GumStalkerTransformer>,
}

// FIXME(keegan) the FnMut should be Send + Sync and have a lifetime of the
// Transformer
impl<'a> Transformer<'a> {
    pub fn from_callback<'b>(
        _gum: &'b Gum,
        mut callback: impl FnMut(StalkerIterator, StalkerOutput),
    ) -> Transformer<'a>
    where
        'b: 'a,
    {
        Transformer {
            transformer: unsafe {
                frida_gum_sys::gum_stalker_transformer_make_from_callback(
                    get_trampoline(&callback),
                    &mut callback as *mut _ as *mut c_void,
                    None,
                )
            },
            phantom: PhantomData,
        }
    }
}

impl<'a> Drop for Transformer<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::_frida_g_object_unref(self.transformer as *mut c_void) }
    }
}

pub struct Stalker<'a> {
    stalker: *mut frida_gum_sys::GumStalker,
    phantom: PhantomData<&'a frida_gum_sys::GumStalker>,
}

impl<'a> Stalker<'a> {
    pub fn is_supported(_gum: &Gum) -> bool {
        unsafe { frida_gum_sys::gum_stalker_is_supported() != 0 }
    }

    pub fn new<'b>(_gum: &'b Gum) -> Stalker
    where
        'b: 'a,
    {
        Stalker {
            stalker: unsafe { frida_gum_sys::gum_stalker_new() },
            phantom: PhantomData,
        }
    }

    // GUM_API void gum_stalker_exclude (GumStalker * self,
    //     const GumMemoryRange * range);

    pub fn set_trust_threshold(&mut self, threshold: i32) {
        unsafe { frida_gum_sys::gum_stalker_set_trust_threshold(self.stalker, threshold) };
    }

    pub fn get_trust_threshold(&self) -> i32 {
        unsafe { frida_gum_sys::gum_stalker_get_trust_threshold(self.stalker) }
    }

    pub fn flush(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_flush(self.stalker) }
    }

    pub fn stop(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_stop(self.stalker) }
    }

    pub fn garbage_collect(&mut self) -> bool {
        unsafe { frida_gum_sys::gum_stalker_garbage_collect(self.stalker) != 0 }
    }

    pub fn follow_me<S: EventSink>(&mut self, transformer: Transformer, event_sink: &mut S) {
        unsafe {
            frida_gum_sys::gum_stalker_follow_me(
                self.stalker,
                transformer.transformer,
                event_sink_transform(event_sink),
            );
        }
    }

    pub fn unfollow_me(&mut self) {
        unsafe { frida_gum_sys::gum_stalker_unfollow_me(self.stalker) };
    }

    // GUM_API void gum_stalker_follow_me (GumStalker * self,
    //     GumStalkerTransformer * transformer, GumEventSink * sink);
    // GUM_API void gum_stalker_unfollow_me (GumStalker * self);
    // GUM_API gboolean gum_stalker_is_following_me (GumStalker * self);
}

impl<'a> Drop for Stalker<'a> {
    fn drop(&mut self) {
        unsafe { frida_gum_sys::_frida_g_object_unref(self.stalker as *mut c_void) };
    }
}
