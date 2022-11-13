# Street Cred

![Build Status](https://github.com/endoze/street-cred/actions/workflows/ci.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/endoze/street-cred/badge.svg?branch=master)](https://coveralls.io/github/endoze/street-cred?branch=master)
[![Crate](https://img.shields.io/crates/v/street-cred.svg)](https://crates.io/crates/street-cred)
[![Docs](https://docs.rs/street-cred/badge.svg)](https://docs.rs/street-cred)

Manage encrypted secrets for your applications.

## Installation

As a command line tool:

```sh
cargo install street-cred
```

As a dependency of a Rust project:

```sh
cargo add street-cred
```

## CLI Usage

Street Cred expects your encryption key to be in an environment variable named `MASTER_KEY` or in a file in the current directory named `master.key`.

```sh
# Edit existing file
street-cred edit secrets.txt.enc
```

## Library Usage

You can also use Street Cred as a library for simple encryption/decryption in your own code.

```rust
use street_cred::FileEncryption;

let file_path = String::from("secrets.txt.enc");
let encryption_key = String::from("425D76994EE6101105DDDA2EE2604AA0");
let file_encryption = FileEncryption::new(file_path, encryption_key);

if let Some((decrypted_contents, initialization_vector, additional_authenticated_data)) = file_encryption.decrypt() {
  // do something with decrypted_contents, initialization_vector, additional_authenticated_data
};
```

## Inpsiration

Seeing how Ruby on Rails allowed storing encrypted secrets along side existing application code, I wanted this same capability without the
Ruby/Rails requirement. This cli app and library allow developers to use the same pattern of storing encrypted secrets in repositories.

## Security Notes

You should ensure that you never commit or track your encryption key in your repository if you choose to use this code to store encrypted secrets
in a code repository. You can set up git to ignore both the encryption key and unencrypted file to ensure they are never committed.

Here's a sample gitignore setup that assumes a key stored in `master.key` and encrypted secrets in `secrets.txt.enc`:

```
# .gitignore
master.key
secrets.txt
```
