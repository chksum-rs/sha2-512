//! This module is optional and can be enabled using the `writer` Cargo feature.
//!
//! The [`Writer`] allows on-the-fly calculation of the digest while writing the data.
//!
//! # Enabling
//!
//! Add the following entry to your `Cargo.toml` file to enable the `writer` feature:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-512 = { version = "0.0.0", features = ["writer"] }
//! ```
//!
//! Alternatively, use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2-512 --features writer
//! ```
//!
//! # Example
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//! use std::io::Write; // required by writer
//!
//! # use chksum_sha2_512::Result;
//! use chksum_sha2_512 as sha2_512;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let mut writer = sha2_512::writer::new(file);
//!
//! writer.write_all(b"example data")?;
//!
//! let digest = writer.digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! # Ok(())
//! # }
//! ```

use std::io::Write;

use chksum_writer as writer;

use crate::SHA2_512;

/// A specialized [`Writer`](writer::Writer) type with the [`SHA2_512`] hash algorithm.
pub type Writer<W> = writer::Writer<W, SHA2_512>;

/// Creates new [`Writer`].
pub fn new(inner: impl Write) -> Writer<impl Write> {
    writer::new(inner)
}

/// Creates new [`Writer`] with provided hash.
pub fn with_hash(inner: impl Write, hash: SHA2_512) -> Writer<impl Write> {
    writer::with_hash(inner, hash)
}
