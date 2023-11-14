/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use thiserror::Error;

/// Custom `Error` for Frida
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to attach to a device.
    #[error("Failed to attach")]
    DeviceAttachError,

    /// Failled to lookup a device.
    #[error("Failed to lookup device")]
    DeviceLookupFailed,

    /// Failed to detach a session.
    #[error("Failed to detach the current session")]
    SessionDetachError,

    /// Failed to create a script in a session.
    #[error("Failed to create the script")]
    ScriptCreationError,

    /// Failled to load a script in a session.
    #[error("Failed to load the script")]
    LoadingFailed,

    /// Failed to unload a script in a session.
    #[error("Failed to unload the script")]
    UnloadingFailed,

    /// CString conversion failed.
    #[error("Failed to convert the string into CString")]
    CStringFailed,

    /// Failed to inject library
    #[error("Failed to inject library ({code}) {message}")]
    InjectFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to query device parameters
    #[error("Failed to query device system parameters ({code}) {message}")]
    DeviceQuerySystemParametersFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to spawn program
    #[error("Failed to spawn program ({code}) {message}")]
    SpawnFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to resume
    #[error("Failed to resume ({code}) {message}")]
    ResumeFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },

    /// Failed to kill
    #[error("Failed to kill PID ({code}) {message}")]
    KillFailed {
        /// Error code
        code: i32,
        /// Error message
        message: String,
    },
}
