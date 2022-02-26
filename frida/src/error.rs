/*
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FridaCoreError {
    #[error("Failed to attach")]
    DeviceAttachError,
    #[error("Failed to detach the current session")]
    SessionDetachError,
    #[error("Failed to create the script")]
    ScriptCreationError,
    #[error("Failed to load the script")]
    LoadingFailed,
    #[error("Failed to unload the script")]
    UnloadingFailed,
    #[error("Failed to convert the string into CString")]
    CStringFailed,
}
