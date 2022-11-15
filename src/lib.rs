//! Manage encrypted secrets for your applications.
//!
//! street-cred provides the means to encrypt/decrypt files and data through both a cli
//! tool and as a library.
//!
//! # Quickstart (CLI)
//!
//! Navigate to a directory where you'd like to have encrypted secrets stored and
//! use the following command to generate an encrypted secrets file.
//!
//! ``` sh
//! street-cred init
//! ```
//!
//! This will create two files for you. The first is `credentials.yml.enc`, which stores your
//! secrets encrypted. You can safely rename this file as needed. The second file generated is
//! your `master.key`. This is your encryption key, protect it like a password!
//!
//! To edit your encrypted secrets, use the following command.
//!
//! ```sh
//! street-cred edit credentials.yml.enc
//! ```
//!
//! This should open your secrets file unecrypted in your EDITOR. If you don't have an editor
//! set, it will default to vim for editing your secrets. Upon saving and closing your editor,
//! the contents of your file will be re-encrypted using your encryption key and written out
//! to disk.
//!
//! # Quickstart (Library)
//!
//! In order to use street-cred as a library in your own code, you'll need to add street-cred to
//! your dependencies in Cargo.toml. You can quickly accomplish this by running the following command.
//!
//! ```sh
//! cargo add street-cred
//! ```
//!
//! Once you've added the crate to your project, you can import various parts of it to start encrypting
//! your data.
//!
//! Encrypting/Decrypting files can be accomplished with [FileEncryption].
//!
//! Encrypting/Decrypting data directly can be accomplished using [MessageEncryption]. While using
//! MessageEncryption, you'll need to provide some random data for the encryption process like the
//! encryption key and initialization vector. street-cred provides a few utility functions for this
//! data via [CipherGeneration].
//!

mod encryption;
mod serialization;

pub use crate::encryption::{CipherGeneration, FileEncryption, MessageEncryption};
pub use crate::serialization::RubyMarshal;
