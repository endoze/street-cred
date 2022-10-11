# Street Cred

Manage encrypted secrets for your applications.

## Installation
```sh
cargo install street-cred
```

## Usage

Street Cred expects your encryption key to be in an environment variable named `MASTER_KEY` or in a file in the current directory named `master.key`.

```sh
# Edit existing file
street-cred edit secrets.txt
```