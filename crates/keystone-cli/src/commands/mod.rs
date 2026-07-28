//! One module per command.
//!
//! Each exposes a single `run` taking the [`Context`](crate::context::Context)
//! and its own parsed arguments, so `main` is only a dispatch table and the
//! commands share no mutable state.

pub mod bootstrap;
pub mod credential_process;
pub mod doctor;
pub mod enroll;
pub mod infra;
pub mod init;
pub mod inspect;
pub mod profiles;
pub mod revoke;
pub mod rotate;
pub mod test;
