#![feature(c_variadic)]
use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use frida_gum_sys;
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: gum::Gum = gum::Gum::obtain();
}

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::None
    }

    fn start(&mut self) {
        println!("start");
    }

    fn process(&mut self, _event: &Event) {
        println!("process");
    }

    fn flush(&mut self) {
        println!("flush");
    }

    fn stop(&mut self) {
        println!("stop");
    }
}

fn main() {
    let mut stalker = Stalker::new(&GUM);

    let transformer = Transformer::from_callback(&GUM, |iterator, output| unsafe {
        use frida_gum_sys::*;
        let mut instr: *const cs_insn = std::ptr::null_mut();
        while gum_stalker_iterator_next(iterator.iterator, &mut instr as *mut _) != 0 {
            gum_stalker_iterator_keep(iterator.iterator);
        }

        println!("Transformed...");
    });

    let mut event_sink = SampleEventSink;
    stalker.follow_me(transformer, &mut event_sink);
    stalker.unfollow_me();
}
