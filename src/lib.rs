#![deny(warnings)]
#![deny(missing_docs)]
//! Parsing library for hosts file common on Linux/UNIX systems. Represents different parts of the
//! file as faithfully as possible as `Cow<str>`, allowing reconstruction of the original and in-
//! place modifications.
//!
//! Intended to be compatible to any hosts file outlined in `man 5 hosts`. Uses the nom parser
//! combinator library.

mod parse;

pub use parse::try_parse_hosts;
pub use parse::HostsPart;
pub use parse::HostsPartFamily;
