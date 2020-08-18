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

pub(crate) fn event_sink_transform<S: EventSink>(
    mut event_sink: &S,
) -> *mut frida_gum_sys::GumEventSink {
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
