use {
    crate::{
        error::GumResult,
        script::{context::Context, data::ScriptData, scheduler::Scheduler},
    },
    core::pin::Pin,
};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String};

mod backend;
mod context;
mod data;
mod scheduler;

pub use backend::*;

pub struct Script<F>
where
    F: Fn(&str, &[u8]),
{
    context: Context,
    name: String,
    payload: String,
    data: Pin<Box<ScriptData<F>>>,
}

impl<F> Script<F>
where
    F: Fn(&str, &[u8]),
{
    pub fn load<N: Into<String>, P: Into<String>>(
        backend: &Backend,
        name: N,
        payload: P,
        callback: Option<F>,
    ) -> GumResult<Script<F>> {
        let scheduler = Scheduler::obtain(backend);
        scheduler.disable_background_thread();

        let context = scheduler.get_context();
        context.create_main_loop(true);
        context.set_as_thread_default();

        let mut script = Script {
            context,
            name: name.into(),
            payload: payload.into(),
            data: Box::pin(ScriptData::new(callback)),
        };

        backend.load_script(&mut script)?;
        script.run_event_loop();
        script.data.loaded()?;
        Ok(script)
    }

    pub fn run_event_loop(&self) {
        self.context.run(false);
    }
}
