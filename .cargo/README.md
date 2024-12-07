# chksum-sha2-512

[![GitHub](https://img.shields.io/badge/github-chksum--rs%2Fsha2--512-24292e?style=flat-square&logo=github "GitHub")](https://github.com/chksum-rs/sha2-512)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/sha2-512/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/sha2-512/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-sha2-512?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-sha2-512/)
[![MSRV](https://img.shields.io/badge/MSRV-1.74.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/sha2-512/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-sha2-512/0.1.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-sha2-512/0.1.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/sha2-512?style=flat-square "LICENSE")](https://github.com/chksum-rs/sha2-512/blob/master/LICENSE)

An implementation of the SHA-2 512 hash function with a straightforward interface for computing digests of bytes, files, directories, and more.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-sha2-512 = "0.1.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-sha2-512
```

## Usage

Use the `chksum` function to calculate digest of file, directory and so on.

```rust
use chksum_sha2_512 as sha2_512;

let file = File::open(path)?;
let digest = sha2_512::chksum(file)?;
assert_eq!(
    digest.to_hex_lowercase(),
    "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-sha2-512/).

## License

This crate is licensed under the MIT License.
