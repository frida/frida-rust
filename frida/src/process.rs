/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use frida_sys::{FridaSpawnOptions, _FridaProcess};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;

/// Process management in Frida.
pub struct Process<'a> {
    process_ptr: *mut _FridaProcess,
    phantom: PhantomData<&'a _FridaProcess>,
}

impl<'a> Process<'a> {
    pub(crate) fn from_raw(process_ptr: *mut _FridaProcess) -> Process<'a> {
        Process {
            process_ptr,
            phantom: PhantomData,
        }
    }

    /// Returns the name of the process.
    pub fn get_name(&self) -> &str {
        let process_name =
            unsafe { CStr::from_ptr(frida_sys::frida_process_get_name(self.process_ptr) as _) };

        process_name.to_str().unwrap_or_default()
    }

    /// Returns the process ID of the process.
    pub fn get_pid(&self) -> u32 {
        unsafe { frida_sys::frida_process_get_pid(self.process_ptr) }
    }
}

impl<'a> Drop for Process<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.process_ptr as _) }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
/// Standard I/O routing for a spawn
pub enum SpawnStdio {
    /// Inherit parent's Standard I/O
    Inherit = 0,

    /// Use pipes for Standard I/O
    Pipe = 1,
}

/// Process Spawn Options
pub struct SpawnOptions<'a> {
    pub(crate) options_ptr: *mut FridaSpawnOptions,
    phantom: PhantomData<&'a FridaSpawnOptions>,
}

impl<'a> SpawnOptions<'a> {
    pub(crate) fn from_raw(options_ptr: *mut FridaSpawnOptions) -> Self {
        Self {
            options_ptr,
            phantom: PhantomData,
        }
    }

    /// Create an empty SpawnOptions instance
    pub fn new() -> Self {
        Self::from_raw(unsafe { frida_sys::frida_spawn_options_new() })
    }

    /// Set the argv vector
    pub fn argv<S, L>(self, args: L) -> Self
    where
        S: AsRef<str>,
        L: IntoIterator<Item = S>,
    {
        let args: Vec<CString> = args
            .into_iter()
            .map(|s| CString::new(s.as_ref()).unwrap())
            .collect();
        let mut arg_ptrs: Vec<*mut _> = args.iter().map(|s| s.as_ptr() as *mut _).collect();
        unsafe {
            frida_sys::frida_spawn_options_set_argv(
                self.options_ptr,
                arg_ptrs.as_mut_ptr(),
                arg_ptrs.len().try_into().unwrap(),
            );
        }
        self
    }

    /// Set the working directory
    pub fn cwd<S: AsRef<CStr>>(self, cwd: S) -> Self {
        unsafe {
            frida_sys::frida_spawn_options_set_cwd(
                self.options_ptr,
                cwd.as_ref().as_ptr() as *mut _,
            );
        }
        self
    }

    /// Set the env vector
    pub fn env<K, V, M>(self, env: M) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
        M: IntoIterator<Item = (K, V)>,
    {
        let env: Vec<CString> = env
            .into_iter()
            .map(|(key, value)| {
                CString::new(format!("{}={}", key.as_ref(), value.as_ref())).unwrap()
            })
            .collect();
        let mut env_ptrs: Vec<*mut _> = env.iter().map(|s| s.as_ptr() as *mut _).collect();
        unsafe {
            frida_sys::frida_spawn_options_set_env(
                self.options_ptr,
                env_ptrs.as_mut_ptr(),
                env_ptrs.len().try_into().unwrap(),
            );
        }
        self
    }

    /// Set the envp vector
    pub fn envp<K, V, M>(self, envp: M) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
        M: IntoIterator<Item = (K, V)>,
    {
        let envp: Vec<CString> = envp
            .into_iter()
            .map(|(key, value)| {
                CString::new(format!("{}={}", key.as_ref(), value.as_ref())).unwrap()
            })
            .collect();
        let mut envp_ptrs: Vec<*mut _> = envp.iter().map(|s| s.as_ptr() as *mut _).collect();
        unsafe {
            frida_sys::frida_spawn_options_set_envp(
                self.options_ptr,
                envp_ptrs.as_mut_ptr(),
                envp_ptrs.len().try_into().unwrap(),
            );
        }
        self
    }

    /// Set the Standard I/O handling
    pub fn stdio(self, stdio: SpawnStdio) -> Self {
        unsafe { frida_sys::frida_spawn_options_set_stdio(self.options_ptr, stdio as _) }
        self
    }
}

impl<'a> Default for SpawnOptions<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Drop for SpawnOptions<'a> {
    fn drop(&mut self) {
        unsafe { frida_sys::frida_unref(self.options_ptr as _) }
    }
}
