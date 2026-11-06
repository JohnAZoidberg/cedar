//! Library internals for the `cedar` CY4500 capture tool. Exposed so that
//! integration tests and examples can exercise the decoder and file writers
//! without a physical device.
//!
//! With the default `cli` feature disabled, only the device-independent parts
//! (decoding, file formats, reports) are built; that is what the WebAssembly
//! front end in `web/` uses.

#[cfg(feature = "cli")]
pub mod capture;
pub mod dump;
pub mod java_serial;
pub mod km003c;
pub mod pd_decode;
pub mod pd_session;
pub mod protocol;
pub mod reader;
pub mod report;
pub mod writer;
