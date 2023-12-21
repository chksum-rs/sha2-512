//! This module is optional and can be enabled using the `reader` Cargo feature.
//!
//! The [`Reader`] allows on-the-fly calculation of the digest while reading the data.
//!
//! # Enabling
//!
//! Add the following entry to your `Cargo.toml` file to enable the `reader` feature:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-512 = { version = "0.0.0", features = ["reader"] }
//! ```
//!
//! Alternatively, use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2-512 --features reader
//! ```
//!
//! # Example
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//! use std::io::Read; // required by reader
//!
//! # use chksum_sha2_512::Result;
//! use chksum_sha2_512 as sha2_512;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let mut reader = sha2_512::reader::new(file);
//!
//! let mut buffer = Vec::new();
//! reader.read_to_end(&mut buffer)?;
//! assert_eq!(buffer, b"example data");
//!
//! let digest = reader.digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! # Ok(())
//! # }
//! ```

use std::io::Read;

use chksum_reader as reader;

use crate::SHA2_512;

/// A specialized [`Reader`](reader::Reader) type with the [`SHA2_512`] hash algorithm.
pub type Reader<R> = reader::Reader<R, SHA2_512>;

/// Creates new [`Reader`].
pub fn new<R>(inner: R) -> Reader<R>
where
    R: Read,
{
    reader::new(inner)
}

/// Creates new [`Reader`] with provided hash.
pub fn with_hash<R>(inner: R, hash: SHA2_512) -> Reader<R>
where
    R: Read,
{
    reader::with_hash(inner, hash)
}
