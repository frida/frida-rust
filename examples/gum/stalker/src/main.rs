/* This example is in the public domain */

use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, Transformer};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
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

    let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
        for instr in basic_block {
            instr.put_callout(|_cpu_context| {});
            instr.keep();
        }
    });

    let mut event_sink = SampleEventSink;
    stalker.follow_me(&transformer, Some(&mut event_sink));
    stalker.unfollow_me();
}
