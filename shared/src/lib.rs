#![cfg_attr(feature = "kernel", no_std)]

// only under kernel: bring in alloc
#[cfg(feature = "kernel")]
extern crate alloc;

#[cfg(feature = "user")]
pub mod errors;

#[cfg(feature = "user")]
pub mod traits;

pub mod constants;
pub mod events;
