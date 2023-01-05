/* This example is in the public domain */

use frida_gum as gum;
use frida_gum::stalker::{Event, EventMask, EventSink, Stalker, StalkerObserver, Transformer};
use frida_gum_sys as gum_sys;
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: gum::Gum = unsafe { gum::Gum::obtain() };
}

struct SampleEventSink;

impl EventSink for SampleEventSink {
    fn query_mask(&mut self) -> EventMask {
        EventMask::Exec
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

struct SampleStalkerObserver;

impl StalkerObserver for SampleStalkerObserver {
    fn switch_callback(
        &mut self,
        from_address: gum_sys::gpointer,
        start_address: gum_sys::gpointer,
        from_insn: gum_sys::gpointer,
        target: &mut gum_sys::gpointer,
    ) {
        println!(
            "from_address: {:p}, start_address: {:p}, from_insn: {:p}, target: {:p}",
            from_address, start_address, from_insn, *target
        );
    }

    fn notify_backpatch(
        &mut self,
        _backpatch: *const gum_sys::GumBackpatch,
        _size: gum_sys::gsize,
    ) {
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
    stalker.set_observer(&SampleStalkerObserver);
    stalker.unfollow_me();
}
