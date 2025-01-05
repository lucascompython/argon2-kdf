#![deny(missing_docs)]

//! A library for hashing passwords and deriving encryption keys using
//! [Argon2](https://en.wikipedia.org/wiki/Argon2). Argon2 is a memory-hard
//! [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) and was
//! the winner of the [Password Hashing Competition](https://www.password-hashing.net). It can
//! generate exceptionally strong hashes.
//!
//! This crate is an alternative to the
//! [argon2 crate](https://docs.rs/rust-argon2/latest/argon2/). The argon2 crate is a pure Rust
//! implementation, whereas this crate uses
//! [the original C Argon2 library](https://github.com/P-H-C/phc-winner-argon2). The original C
//! implementation usually benchmarks faster than the argon2 crate's implementation (though you
//! really should test it on your own machine--performance benchmarks are rarely universally
//! applicable).
//!
//! This crate was designed with simplicity and ease-of-use in mind. Just take a look at the
//! examples!
//!
//! # Usage
//!
//! To use argon2-kdf, add the following to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! argon2-kdf = "1.5.3"
//! ```
//! To pass build flags to the C compiler used to build the Argon2 library, you may add a
//! semicolon-delimited list of flags to the `ARGON2_KDF_C_COMPILER_FLAGS` environment variable.
//! For example, if you wish to disable the AVX optimizations that are on by default, you can
//! build using the following command:
//! `ARGON2_KDF_C_COMPILER_FLAGS="-mno-avx512f;-mno-avx2" cargo build`.
//!
//! # Examples
//!
//! Hash a password, then verify the hash:
//!
//! ```rust
//! use argon2_kdf::{Hasher, Hash};
//!
//! let password = b"password";
//! let hash: Hash<16, 32> = Hasher::default().hash(password).unwrap();
//! assert!(hash.verify(password));
//! ```
//!
//! Convert a hash to a string and back:
//!
//! ```rust
//! use argon2_kdf::{Hasher, Hash};
//! use std::str::FromStr;
//!
//! let password = b"password";
//! let hash: Hash<16, 32> = Hasher::default().hash(password).unwrap();
//! let hash_string = hash.to_string();
//! let hash: Hash<16, 32> = Hash::from_str(&hash_string).unwrap();
//! assert!(hash.verify(password));
//! ```
//!
//! Hash a password with a secret, then verify the hash:
//!
//! ```rust
//! use argon2_kdf::{Hasher, Hash, Secret};
//!
//! let password = b"password";
//! let secret = b"secret";
//! let hash: Hash<16, 32> = Hasher::default()
//!     .secret(secret.into())
//!     .hash(password)
//!     .unwrap();
//! assert!(hash.verify_with_secret(password, secret.into()));
//! ```
//!
//! Hash a password with a custom salt, then verify the hash:
//!
//! ```rust
//! use argon2_kdf::{Hasher, Hash};
//!
//! let password = b"password";
//! let salt = b"customsalt";
//! let hash: Hash<10, 32> = Hasher::default()
//!     .custom_salt(salt)
//!     .hash(password)
//!     .unwrap();
//! assert!(hash.verify(password));
//! ```

mod bindings;
mod error;
mod hasher;
mod lexer;

pub use error::Argon2Error;
pub use hasher::{Algorithm, Hash, Hasher, Secret};
