/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{
    FridaScriptOptions, _FridaScript, _GBytes, g_bytes_get_data, g_bytes_new, g_bytes_unref, gsize,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::{cell::RefCell, marker::PhantomData, rc::Rc};
use std::{
    ffi::{c_char, c_void, CStr, CString},
    ptr::null_mut,
};

use crate::{Error, Result};

/// Represents a Frida message
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum Message {
    /// Message of type "send"
    Send(MessageSend),
    /// Message of type "log"
    Log(MessageLog),
    /// Message of type "error"
    Error(MessageError),
    /// Any other type of message.
    Other(Value),
}

/// Send Message.
#[derive(Deserialize, Debug)]
pub struct MessageSend {
    /// Payload of a Send Message.
    pub payload: SendPayload,
}

/// Log Message.
#[derive(Deserialize, Debug)]
pub struct MessageLog {
    /// Log Level.
    pub level: MessageLogLevel,
    /// Payload of a Message Log.
    pub payload: String,
}

/// Error message.
/// This message is sent when a JavaScript runtime error occurs, such as a misspelled word.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MessageError {
    /// Error description.
    pub description: String,
    /// Stack trace string.
    pub stack: String,
    /// Script file name that failed.
    pub file_name: String,
    /// Line number with the error.
    pub line_number: usize,
    /// Column number with the error.
    pub column_number: usize,
}

/// Represents a Message Log Level Types.
/// Used by `MessageLog._level`
#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MessageLogLevel {
    /// Indicates an informal message.
    Info,
    /// Represents a debugging message.
    Debug,
    /// Signifies a warning message.
    Warning,
    /// Represents an error message.
    Error,
}

/// Represents a MessageSend's payload.
#[derive(Deserialize, Debug)]
pub struct SendPayload {
    /// Send message type
    pub r#type: String,
    /// Send message ID
    pub id: usize,
    /// Send message result.
    pub result: String,
    /// Send message returns.
    pub returns: Value,
}

unsafe extern "C" fn call_on_message<I: ScriptHandler>(
    _script_ptr: *mut _FridaScript,
    message: *const i8,
    data: *const frida_sys::_GBytes,
    user_data: *mut c_void,
) {
    let c_msg = CStr::from_ptr(message as *const c_char)
        .to_str()
        .unwrap_or_default();

    let formatted_msg: Message = serde_json::from_str(c_msg).unwrap_or_else(|err| {
        Message::Other(serde_json::json!({
            "error": err.to_string(),
            "data": c_msg
        }))
    });

    match formatted_msg {
        Message::Send(msg) => {
            if msg.payload.r#type == "frida:rpc" {
                let callback_handler: *mut CallbackHandler = user_data as _;
                on_message(callback_handler.as_mut().unwrap(), Message::Send(msg));
            }
        }
        _ => {
            let handler: &mut I = &mut *(user_data as *mut I);

            // Retrieve extra message data, if any.
            if data.is_null() {
                handler.on_message(&formatted_msg, None);
                return;
            }

            let mut raw_data_size: gsize = 0;
            let raw_data: *const u8 = g_bytes_get_data(
                // Cast to mut should be safe, as this function doesn't modify the data.
                data as *mut _GBytes,
                std::ptr::from_mut(&mut raw_data_size),
            ) as *const u8;
            let data_vec = if raw_data_size == 0 || raw_data.is_null() {
                None
            } else {
                // Copy to a vector to avoid potential lifetime issues.
                Some(
                    std::slice::from_raw_parts(raw_data, raw_data_size.try_into().unwrap())
                        .to_vec(),
                )
            };
            handler.on_message(&formatted_msg, data_vec);
        }
    }
}

fn on_message(cb_handler: &mut CallbackHandler, message: Message) {
    let (tx, _) = &cb_handler.channel;
    let _ = tx.send((message, None));
}

/// Represents a script signal handler.
pub trait ScriptHandler {
    /// Handler called when a message is shared from JavaScript to Rust.
    fn on_message(&mut self, message: &Message, data: Option<Vec<u8>>);
}

/// Represents a Frida script.
pub struct Script<'a> {
    script_ptr: *mut _FridaScript,
    rpc_id_counter: Rc<RefCell<usize>>,
    callback_handler: Rc<RefCell<CallbackHandler>>,
    ///Exports of the script.
    pub exports: Exports<'a>,
    phantom: PhantomData<&'a _FridaScript>,
}

/// This represents the exports of the script.
pub struct Exports<'a> {
    script_ptr: *mut _FridaScript,
    rpc_id_counter: Rc<RefCell<usize>>,
    callback_handler: Rc<RefCell<CallbackHandler>>,
    phantom: PhantomData<&'a _FridaScript>,
}

impl Exports<'_> {
    fn inc_id(&mut self) -> usize {
        let mut counter_borrow = self.rpc_id_counter.borrow_mut();
        *counter_borrow += 1;
        *counter_borrow
    }
}

impl<'a> Script<'a> {
    pub(crate) fn from_raw(script_ptr: *mut _FridaScript) -> Script<'a> {
        let rpc_counter = Rc::new(RefCell::new(0));
        let handler = Rc::new(RefCell::new(CallbackHandler::new()));
        Script {
            script_ptr,
            phantom: PhantomData,
            rpc_id_counter: rpc_counter.clone(),
            callback_handler: handler.clone(),
            exports: Exports {
                script_ptr,
                phantom: PhantomData,
                rpc_id_counter: rpc_counter,
                callback_handler: handler,
            },
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
    ///     fn on_message(&mut self, message: &frida::Message, data: Option<Vec<u8>>) {
    ///         println!("Message: {:?}", message);
    ///         println!("Data: {:?}", data);
    ///     }
    /// }
    /// ```
    pub fn handle_message<I: ScriptHandler + 'static>(&mut self, handler: I) -> Result<()> {
        let message = CString::new("message").map_err(|_| Error::CStringFailed)?;
        let mut borrowed_callback_handler = self.callback_handler.borrow_mut();
        (*borrowed_callback_handler).add_handler(handler);
        let user_data =
            (&(*borrowed_callback_handler) as *const _ as *mut CallbackHandler) as *mut c_void;
        unsafe {
            let callback = Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                unsafe extern "C" fn(),
            >(call_on_message::<I> as *mut c_void));

            frida_sys::g_signal_connect_data(
                self.script_ptr as _,
                message.as_ptr(),
                callback,
                user_data,
                None,
                0,
            )
        };

        Ok(())
    }

    /// Post a JSON-encoded message to the script with optional binary data
    ///
    /// NOTE: `message` must be valid JSON otherwise the script will throw a SyntaxError
    pub fn post<S: AsRef<str>>(&self, message: S, data: Option<&[u8]>) -> Result<()> {
        let message = CString::new(message.as_ref()).map_err(|_| Error::CStringFailed)?;

        unsafe {
            let g_data = if let Some(data) = data {
                g_bytes_new(data.as_ptr() as _, data.len() as _)
            } else {
                std::ptr::null_mut()
            };
            frida_sys::frida_script_post(self.script_ptr as _, message.as_ptr() as _, g_data);
            g_bytes_unref(g_data);
        }

        Ok(())
    }

    fn inc_id(&mut self) -> usize {
        let mut counter_borrow = self.rpc_id_counter.borrow_mut();
        *counter_borrow += 1;
        *counter_borrow
    }

    /// List all the exported attributes from the script's rpc
    pub fn list_exports(&mut self) -> Result<Vec<String>> {
        let json_req = {
            let name = "frida:rpc".into();
            let id = self.inc_id().into();
            let rpc_type = "list".into();
            let rpc_function = Value::Null;
            let args = Value::Null;

            let rpc_query: [Value; 5] = [name, id, rpc_type, rpc_function, args];

            serde_json::to_string(&rpc_query).unwrap()
        };

        self.post(&json_req, None).unwrap();
        let borrowed_callback_handler = self.callback_handler.borrow();
        let (_, rx) = &borrowed_callback_handler.channel;
        let (rpc_result, _) = rx.recv().unwrap();

        let func_list: Vec<String> = match rpc_result {
            Message::Send(r) => {
                let tmp_list: Vec<String> = r
                    .payload
                    .returns
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|i| i.as_str().unwrap_or("").to_string())
                    .collect();

                tmp_list
            }
            _ => Vec::new(),
        };

        Ok(func_list)
    }
}

impl Exports<'_> {
    /// Run exported functions from a Frida script.
    pub fn call(&mut self, function_name: &str, args: Option<Value>) -> Result<Option<Value>> {
        let json_req: String = {
            let name = "frida:rpc";
            let id = self.inc_id();
            let rpc_type = "call";

            let args: String = match args {
                Some(a) => serde_json::to_string(&a).unwrap(),
                None => "[]".into(),
            };

            format!(
                "[\"{}\", {}, \"{}\", \"{}\", {}]",
                name, id, rpc_type, function_name, args
            )
        };

        let message = CString::new(json_req.as_str()).map_err(|_| Error::CStringFailed)?;

        unsafe {
            let g_data = std::ptr::null_mut();
            frida_sys::frida_script_post(self.script_ptr as _, message.as_ptr() as _, g_data);
            g_bytes_unref(g_data);
        }

        let borrowed_callback_handler = self.callback_handler.borrow();
        let (_, rx) = &borrowed_callback_handler.channel;
        let (rpc_result, _) = rx.recv().unwrap();

        match rpc_result {
            Message::Send(r) => {
                if r.payload.result == "ok" {
                    let returns = r.payload.returns;

                    match returns {
                        Value::Null => Ok(None),
                        _ => Ok(Some(returns)),
                    }
                } else {
                    let err_msg = r.payload.returns.to_string();
                    Err(Error::RpcJsError { message: err_msg })
                }
            }
            _ => Err(Error::RpcUnexpectedMessage),
        }
    }
}

impl Drop for Script<'_> {
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

type MsgSender = Sender<(Message, Option<Vec<u8>>)>;
type MsgReceiver = Receiver<(Message, Option<Vec<u8>>)>;
struct CallbackHandler {
    channel: (MsgSender, MsgReceiver),
    script_handler: Option<Box<dyn ScriptHandler>>,
}

impl CallbackHandler {
    fn new() -> Self {
        Self {
            channel: channel(),
            script_handler: None,
        }
    }

    fn add_handler<I: ScriptHandler + 'static>(&mut self, handler: I) {
        self.script_handler = Some(Box::from(handler));
    }
}
