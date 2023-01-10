/*
 * Copyright © 2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use thiserror::Error;

/// Custom `Error` for Frida
#[derive(Error, Debug)]
pub enum Error {
    /// Bad signature during Interceptor operation
    #[error("Bad signature")]
    InterceptorBadSignature,

    /// Function is already replaced during Interceptor operation
    #[error("Function already replaced")]
    InterceptorAlreadyReplaced,

    /// Policy violation
    #[error("Policy violation")]
    PolicyViolation,

    /// Other Interceptor error
    #[error("Interceptor error")]
    InterceptorError,

    /// Memory access error
    #[error("Memory access error")]
    MemoryAccessError,

    #[error("Wrong type")]
    WrongType,
}
