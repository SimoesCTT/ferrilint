//! # rpm-parse-rs
//! Zero-copy RPM header, lead, and payload parser in pure Rust.

pub mod lead;
pub mod header;
pub mod payload;

pub use lead::RpmLead;
pub use header::{RpmHeader, HeaderIndex};
pub use payload::{CpioArchive, CpioEntry};
