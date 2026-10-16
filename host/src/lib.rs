//! airlock core: disposable microVMs, the strict host side of the guest
//! protocol, reports. Shared by the CLI and the desktop app.

pub mod analysis;
pub mod live;
pub mod pdf;
pub mod report;
pub mod session;
pub mod vm;

pub use airlock_proto as proto;
