//! Network Intelligence core: platform-independent models and logic.
//!
//! Nothing in this crate talks to the operating system. Data sources
//! (`ni-windows`), active probes (`ni-probe`), storage and the UI depend on
//! these types, so the correlation and diagnostics logic can be tested on any
//! platform with recorded inputs.
//!
//! Every persisted or exported structure carries a schema version
//! ([`EVENT_SCHEMA_VERSION`], [`finding::FINDING_SCHEMA_VERSION`]).

pub mod addr;
pub mod correlate;
pub mod endpoint;
pub mod event;
pub mod finding;
pub mod probe;
pub mod process;
pub mod session;
pub mod source;
pub mod time;

/// Version of the [`event::Event`] / [`endpoint::EndpointRecord`] JSON shape.
pub const EVENT_SCHEMA_VERSION: u32 = 1;
