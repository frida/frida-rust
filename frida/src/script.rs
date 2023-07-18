/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{FridaScriptOptions, _FridaScript};
use serde::Deserialize;
use serde_json::Value;
use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{
    ffi::{c_char, c_void, CStr, CString},
    ptr::null_mut,
};

use crate::{Error, Result};

const FRIDA_RPC: &str = "frida:rpc";

/// Represents a Frida message.
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Message {
    /// Represents a message with type send
    #[serde(alias = "send")]
    Send(SendMessage),
    /// Represents a message with type log
    #[serde(alias = "log")]
    Log(LogMessage),
    /// Represents a message with type error
    #[serde(alias = "error")]
    Error(ErrorMessage),
    /// Represents a message with other types
    #[serde(untagged)]
    Other(Value),
}

/// Represents a log message.
#[derive(Deserialize, Debug)]
pub struct LogMessage {
    _level: String,
    _payload: String,
}

/// Represents an error message.
#[derive(Deserialize, Debug)]
pub struct ErrorMessage {
    _column_number: usize,
    _description: String,
}

/// Represents a message with type send
#[derive(Deserialize, Debug)]
pub struct SendMessage {
    payload: Payload,
}

/// Represents a message payload.
#[derive(Deserialize, Debug, Clone)]
pub struct Payload {
    /// Message type.
    pub r#type: String,
    /// Message id.
    pub id: usize,
    /// Message result.
    pub result: String,
    /// Message returns.
    pub returns: Value,
}

struct CallbackHandler {
    script_handler: Option<Box<dyn ScriptHandler>>,
    chan: (Sender<Value>, Receiver<Value>),
}

impl CallbackHandler {
    fn new() -> Self {
        Self {
            chan: channel(),
            script_handler: None,
        }
    }

    fn add_handler<H: ScriptHandler + 'static>(&mut self, handler: H) {
        self.script_handler = Some(Box::from(handler));
    }
}

unsafe extern "C" fn call_on_message(
    _script_ptr: *mut _FridaScript,
    message: *const i8,
    _data: &frida_sys::_GBytes,
    user_data: *mut c_void,
) {
    let msg = CStr::from_ptr(message as *const c_char)
        .to_str()
        .unwrap_or_default();

    let parsed_msg: Message = serde_json::from_str(msg).unwrap();
    let callback_handler: *mut CallbackHandler = user_data as _;

    on_message(callback_handler.as_mut().unwrap(), &parsed_msg);
}

fn on_message(cb_h: &mut CallbackHandler, message: &Message) {
    match message {
        Message::Send(SendMessage { payload }) if payload.r#type == FRIDA_RPC => {
            let (tx, _) = &cb_h.chan;
            let _ = tx.send(payload.returns.clone());
        }
        msg => {
            cb_h.script_handler.as_mut().map(|sh| sh.on_message(msg));
        }
    }
}
/// Represents a script signal handler.
pub trait ScriptHandler {
    /// Handler called when a message is shared from JavaScript to Rust.
    fn on_message(&mut self, message: &Message);
}

/// Reprents a Frida script.
pub struct Script<'a> {
    script_ptr: *mut _FridaScript,
    phantom: PhantomData<&'a _FridaScript>,
    callback_handler: CallbackHandler,
    call_id_counter: Cell<usize>,
}

impl<'a> Script<'a> {
    pub(crate) fn from_raw(script_ptr: *mut _FridaScript) -> Script<'a> {
        Script {
            script_ptr,
            callback_handler: CallbackHandler::new(),
            call_id_counter: Cell::new(0),
            phantom: PhantomData,
        }
    }

    /// Loads the script into the process.
    pub fn load(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_load_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::LoadingFailed)
        }
    }

    /// Unloads the script from the process.
    pub fn unload(&self) -> Result<()> {
        let mut error: *mut frida_sys::GError = std::ptr::null_mut();
        unsafe { frida_sys::frida_script_unload_sync(self.script_ptr, null_mut(), &mut error) };

        if error.is_null() {
            Ok(())
        } else {
            Err(Error::UnloadingFailed)
        }
    }

    /// Handles the `message` signal for the script and wraps into [`ScriptHandler`].
    ///
    /// # Example
    ///
    /// ```
    /// use frida::ScriptHandler;
    ///
    /// struct Handler;
    ///
    /// impl ScriptHandler for Handler {
    ///     fn on_message(&mut self, message: &Message) {
    ///         println!("{message}");
    ///     }
    /// }
    /// ```
    pub fn handle_message<H: ScriptHandler + 'static>(&mut self, handler: H) -> Result<()> {
        let message = CString::new("message").map_err(|_| Error::CStringFailed)?;
        self.callback_handler.add_handler(handler);
        let _callbaack_handler = unsafe {
            let callback = Some(std::mem::transmute(call_on_message as *mut c_void));

            frida_sys::g_signal_connect_data(
                self.script_ptr as _,
                message.as_ptr(),
                callback,
                (&self.callback_handler as *const _ as *mut CallbackHandler) as *mut c_void,
                None,
                0,
            )
        };

        Ok(())
    }

    /// Posts a message to the script.
    pub fn post(&self, message: &str) -> Result<()> {
        let message = CString::new(message).map_err(|_| Error::CStringFailed)?;

        unsafe { frida_sys::frida_script_post(self.script_ptr, message.as_ptr() as _, null_mut()) };
        Ok(())
    }

    fn count_id(&self) -> usize {
        let cur = self.call_id_counter.get();
        self.call_id_counter.replace(cur + 1);
        cur
    }

    /// Makes a call to the `exports` object in the script.
    pub fn make_exports_call(&self, _fn_name: &str, _args: Vec<Value>) -> Result<Value> {
        let rpc_json = {
            let name = FRIDA_RPC.into();
            let id = self.count_id().into();
            let rpc_type = "call".into();
            let rpc_function = _fn_name.into();
            let args = _args.into();

            let rpc_query: [Value; 5] = [name, id, rpc_type, rpc_function, args];

            serde_json::to_string(&rpc_query).unwrap()
        };

        self.post(&rpc_json).unwrap();
        let (_, rx) = &self.callback_handler.chan;
        rx.recv().or(Err(Error::RpcError))
    }
    /// List all exports of the script.
    pub fn list_exports(&self) -> Result<Value> {
        let rpc_json = {
            let name = FRIDA_RPC.into();
            let id = self.count_id().into();
            let rpc_type = "list".into();
            let rpc_function = Value::Null;
            let args = Value::Null;

            let rpc_query: [Value; 5] = [name, id, rpc_type, rpc_function, args];

            serde_json::to_string(&rpc_query).unwrap()
        };

        self.post(&rpc_json).unwrap();
        let (_, rx) = &self.callback_handler.chan;
        rx.recv().or(Err(Error::RpcError))
    }
}

impl<'a> Drop for Script<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.script_ptr as _) }
    }
}

/// The JavaScript runtime of Frida.
pub enum ScriptRuntime {
    /// Default Frida runtime.
    Default,
    /// QuickJS runtime.
    QJS,
    /// Google V8 runtime.
    V8,
}

impl From<ScriptRuntime> for frida_sys::FridaScriptRuntime {
    fn from(runtime: ScriptRuntime) -> Self {
        match runtime {
            ScriptRuntime::Default => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_DEFAULT,
            ScriptRuntime::QJS => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_QJS,
            ScriptRuntime::V8 => frida_sys::FridaScriptRuntime_FRIDA_SCRIPT_RUNTIME_V8,
        }
    }
}

/// Represents options passed to the Frida script registrar.
pub struct ScriptOption {
    ptr: *mut FridaScriptOptions,
}

impl ScriptOption {
    /// Create a new set of script options.
    pub fn new() -> Self {
        let ptr = unsafe { frida_sys::frida_script_options_new() };
        Self { ptr }
    }

    /// Get the name of the script.
    pub fn get_name(&self) -> &'static str {
        let name = unsafe { CStr::from_ptr(frida_sys::frida_script_options_get_name(self.ptr)) };
        name.to_str().unwrap_or_default()
    }

    /// Set the name of the script.
    pub fn set_name(self, name: &str) -> Self {
        unsafe { frida_sys::frida_script_options_set_name(self.ptr, name.as_ptr() as _) };
        self
    }

    /// Set the runtime of the script.
    pub fn set_runtime(self, runtime: ScriptRuntime) -> Self {
        unsafe { frida_sys::frida_script_options_set_runtime(self.ptr, runtime.into()) };
        self
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut FridaScriptOptions {
        self.ptr
    }
}

impl Default for ScriptOption {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ScriptOption {
    fn drop(&mut self) {
        unsafe {
            frida_sys::g_clear_object(
                &mut self.ptr as *mut *mut frida_sys::_FridaScriptOptions as _,
            )
        }
    }
}
