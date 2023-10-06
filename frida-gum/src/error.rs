/*
 * Copyright © 2021 Keegan Saunders
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */
use core::fmt;

/// Custom `Error` for Frida
pub enum Error {
    /// Bad signature during Interceptor operation
    InterceptorBadSignature,

    /// Function is already replaced during Interceptor operation
    InterceptorAlreadyReplaced,

    /// Policy violation
    PolicyViolation,

    /// Other Interceptor error
    InterceptorError,

    /// Memory access error
    MemoryAccessError,

    WrongType,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InterceptorBadSignature => write!(fmt, "Bad signature"),
            Error::InterceptorAlreadyReplaced => write!(fmt, "Function already replaced"),
            Error::PolicyViolation => write!(fmt, "Policy violation"),
            Error::InterceptorError => write!(fmt, "Interceptor error"),
            Error::MemoryAccessError => write!(fmt, "Memory access error"),
            Error::WrongType => write!(fmt, "Wrong type"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{self:}")
    }
}

#[allow(unused)]
pub type GumResult<T> = Result<T, Error>;
