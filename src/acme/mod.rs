//! Low-level ACME client implementation.
//!
//! This module provides the basic semantics of the RFC 8555 specification (and some of its extensions) as asynchronous
//! Rust functions. However, this module intentionally contains no higher-level logic related to
//! ACME specifics such as authorization, key management, order management, or issuance flows. Rather, this module is
//! meant as a set of low-level routines that can be used to build a higher-level ACME client on top of.

pub mod client;
pub mod error;
pub mod http;
pub mod object;
