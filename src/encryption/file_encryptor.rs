#![allow(unused)]

use crate::MessageEncryption;
use crate::RubyMarshal;
use anyhow::anyhow;
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process;
use std::{fs, io};
use thurgood::rc::{from_reader, to_writer, Error, RbAny, RbRef};

/// Represents an encryped file that we can edit the contents of while
/// preserving the encryption.
///
/// # Examples
///
/// You can create a `FileEncryption` using the following code:
///
/// ```
/// use street_cred::FileEncryption;
///
/// let file_name = String::from("encrypted.txt");
/// let key = String::from("16 byte key line");
/// let file_encryption = FileEncryption::new(file_name, key);
///
/// // File is decrypted, opened in your EDITOR for modification
/// // and once closed, re-encrypts the file if it's contents have changed.
/// // let result = file_encryption.edit();
///
/// // match result {
/// //   Ok(_) -> {},
/// //   Err(why) => println!("{}", why),
/// // }
/// ```
pub struct FileEncryption {
  file_path: String,
  key: String,
}

impl FileEncryption {
  /// Create a new instance of FileEncryption.
  ///
  /// # Arguments
  /// * `file_path` - Path to the encrypted file.
  /// * `key` - Key to use for encryption/decryption.
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::FileEncryption;
  ///
  /// let file_path = String::from("some_file.txt");
  /// let key = String::from("425D76994EE6101105DDDA2EE2604AA0");
  /// let file_encryption = FileEncryption::new(file_path, key);
  /// ```
  pub fn new(file_path: String, key: String) -> Self {
    FileEncryption {
      file_path: shellexpand::tilde(&file_path).to_string(),
      key,
    }
  }

  /// Edit the contents of an encrypted file via your preferred EDITOR.
  /// If no EDITOR environment variable is set, will default to vim.
  pub fn edit(&self) -> anyhow::Result<()> {
    match self.decrypt() {
      Ok((contents, iv, aad)) => {
        let temp_file_path = self.temp_file_location()?;

        self.write_file(temp_file_path.clone(), contents.clone())?;

        Self::launch_editor_for_path(&temp_file_path);

        let old_file_contents = contents;
        let temp_file_contents = fs::read_to_string(temp_file_path.clone())?;

        if old_file_contents != temp_file_contents {
          let encrypted_contents = self.encrypt(temp_file_contents.as_bytes(), &iv, "")?;

          self.write_file(temp_file_path, encrypted_contents)?;
          self.replace_file_atomically()?;
        } else {
          fs::remove_file(temp_file_path);
        }
      }

      Err(why) => {
        panic!("Decryption failed: {}", why);
      }
    }

    Ok(())
  }

  /// Decrypts the contents of the `FileEncryption` and returns them as a tuple
  /// with three Strings.
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::FileEncryption;
  ///
  /// let file_path = String::from("some_file.txt");
  /// let key = String::from("425D76994EE6101105DDDA2EE2604AA0");
  /// let file_encryption = FileEncryption::new(file_path, key);
  /// // let (contents, iv, aad) = file_encryption.decrypt()?;
  /// ```
  pub fn decrypt(&self) -> anyhow::Result<(String, String, String)> {
    let contents = self.read_file()?;
    let split_contents = MessageEncryption::split_encrypted_contents(&contents)?;
    let message = split_contents[0];
    let iv = split_contents[1];
    let encrypted_aad = split_contents[2];

    let decryptor = MessageEncryption::new(message.as_bytes().to_vec(), &self.key, "");

    match decryptor.decrypt(iv, encrypted_aad) {
      Ok(decrypted_contents) => Ok((decrypted_contents, iv.into(), encrypted_aad.into())),
      Err(why) => Err(anyhow!("Invalid encrypted contents in decrypt: {}", why)),
    }
  }

  /// Encrypts the contents of the `FileEncryption` and returns them as a `String`
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::FileEncryption;
  ///
  /// let file_path = String::from("some_file.txt");
  /// let key = String::from("425D76994EE6101105DDDA2EE2604AA0");
  /// let file_encryption = FileEncryption::new(file_path, key);
  /// let contents = "a secret message";
  /// let iv = "fWoW3cyLE2/JfiiF";
  /// let aad = "";
  ///
  /// // let encrypted_contents = file_encryption.encrypt()?;
  /// ```
  pub fn encrypt(&self, contents: &[u8], iv: &str, aad: &str) -> anyhow::Result<String> {
    let encryptor = MessageEncryption::new(contents.to_vec(), &self.key, aad);

    match encryptor.encrypt() {
      Ok(encrypted_contents) => Ok(encrypted_contents),
      Err(why) => Err(anyhow!("{}", why)),
    }
  }

  fn launch_editor_for_path(path: &Path) -> anyhow::Result<()> {
    let editor = match std::env::var("EDITOR") {
      Ok(editor) => editor,
      Err(_) => String::from("vim"),
    };
    let editor_command = format!("{} {}", editor, path.canonicalize()?.to_string_lossy());

    std::process::Command::new("/usr/bin/env")
      .arg("sh")
      .arg("-c")
      .arg(editor_command)
      .spawn()
      .expect("Error: Failed to run editor")
      .wait()
      .expect("Error: Editor returned a non-zero status");

    Ok(())
  }

  fn read_file(&self) -> anyhow::Result<String> {
    let path = Path::new(&self.file_path);

    let contents = fs::read_to_string(path)?;

    Ok(contents)
  }

  fn write_file<T, U>(&self, path: T, contents: U) -> io::Result<()>
  where
    T: AsRef<Path>,
    U: AsRef<[u8]>,
  {
    fs::write(path, contents)?;

    Ok(())
  }

  fn replace_file_atomically(&self) -> anyhow::Result<()> {
    let path = PathBuf::from(&self.file_path);
    let mut temp_file_path = self.temp_file_location()?;

    fs::rename(temp_file_path, path)?;

    Ok(())
  }

  fn temp_file_location(&self) -> anyhow::Result<PathBuf> {
    let mut temp_directory_path = env::temp_dir();
    let original_filename = PathBuf::from(&self.file_path)
      .file_name()
      .ok_or_else(|| anyhow!("Could not generate absolute path for encrypted file"))?
      .to_owned();

    let final_path = format!(
      "{}.{}",
      process::id(),
      original_filename
        .to_str()
        .ok_or_else(|| anyhow!("Could not generate absolute path for temporary file"))?
    );
    let mut final_path = PathBuf::from(final_path);

    if let Some(extension) = final_path.extension() {
      if OsStr::new("enc") == extension {
        final_path.set_extension("");
      }
    }

    temp_directory_path.push(final_path);

    Ok(temp_directory_path)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use assert_fs::prelude::*;
  use lazy_static::lazy_static;
  use std::env::VarError;
  use std::panic::{RefUnwindSafe, UnwindSafe};
  use std::sync::Mutex;
  use std::{env, panic};

  lazy_static! {
    static ref SERIAL_TEST: Mutex<()> = Default::default();
  }

  /// Sets environment variables to the given value for the duration of the closure.
  /// Restores the previous values when the closure completes or panics, before unwinding the panic.
  pub fn with_env_vars<F>(kvs: Vec<(&str, Option<&str>)>, closure: F)
  where
    F: Fn() + UnwindSafe + RefUnwindSafe,
  {
    let guard = SERIAL_TEST.lock().unwrap();
    let mut old_kvs: Vec<(&str, Result<String, VarError>)> = Vec::new();

    for (k, v) in kvs {
      let old_v = env::var(k);
      old_kvs.push((k, old_v));
      match v {
        None => env::remove_var(k),
        Some(v) => env::set_var(k, v),
      }
    }

    match panic::catch_unwind(|| {
      closure();
    }) {
      Ok(_) => {
        for (k, v) in old_kvs {
          reset_env(k, v);
        }
      }
      Err(err) => {
        for (k, v) in old_kvs {
          reset_env(k, v);
        }
        drop(guard);
        panic::resume_unwind(err);
      }
    };
  }

  fn reset_env(k: &str, old: Result<String, VarError>) {
    if let Ok(v) = old {
      env::set_var(k, v);
    } else {
      env::remove_var(k);
    }
  }

  #[test]
  fn test_edit() {
    with_env_vars(vec![("EDITOR", Some("echo"))], || {
      let temp = assert_fs::TempDir::new().unwrap();
      let input_file = temp.child("encoded.txt.enc");
      temp
        .copy_from("./tests/fixtures/", &["*.txt", "*.enc"])
        .unwrap();

      let file_encryption = FileEncryption::new(
        input_file.to_string_lossy().to_string(),
        String::from("200a0e90e538d17390c8c4bc3bc71e44"),
      );

      assert!(file_encryption.edit().is_ok());
    });
  }

  #[test]
  #[should_panic]
  fn test_broken_encryption_edit() {
    with_env_vars(vec![("EDITOR", Some("echo"))], || {
      let temp = assert_fs::TempDir::new().unwrap();
      let input_file = temp.child("no_encryption.txt");
      temp.copy_from("./tests/fixtures/", &["*.txt"]).unwrap();

      let file_encryption = FileEncryption::new(
        input_file.to_string_lossy().to_string(),
        String::from("200a0e90e538d17390c8c4bc3bc71e44"),
      );

      file_encryption.edit();
    });
  }

  #[test]
  fn test_broken_decryption_decrypt() {
    with_env_vars(vec![("EDITOR", Some("echo"))], || {
      let temp = assert_fs::TempDir::new().unwrap();
      let input_file = temp.child("encoded.txt");
      temp.copy_from("./tests/fixtures/", &["*.txt"]).unwrap();

      let file_encryption = FileEncryption::new(
        input_file.to_string_lossy().to_string(),
        String::from("200a0e80e538d17390c8c4bc3bc71e44"),
      );

      let result = file_encryption.decrypt();

      assert!(result.is_err());
    });
  }

  #[test]
  fn test_broken_encryption_encrypt() {
    with_env_vars(vec![("EDITOR", Some("echo"))], || {
      let temp = assert_fs::TempDir::new().unwrap();
      let input_file = temp.child("encoded.txt");
      temp.copy_from("./tests/fixtures/", &["*.txt"]).unwrap();

      let file_encryption = FileEncryption::new(
        input_file.to_string_lossy().to_string(),
        String::from("200a0e80e538d17390c8c4bc3bc71e44"),
      );

      let message = String::from("super secret contents");
      let iv = "66ag";
      let invalid_aad = "66ag=========";

      let result = file_encryption.encrypt(message.as_bytes(), iv, invalid_aad);

      assert!(result.is_err());
    });
  }

  #[test]
  fn test_edit_with_file_changes() {
    with_env_vars(vec![("EDITOR", Some("echo 'another' >> "))], || {
      let temp = assert_fs::TempDir::new().unwrap();
      let input_file = temp.child("encoded.txt");
      temp.copy_from("./tests/fixtures/", &["*.txt"]).unwrap();

      let file_encryption = FileEncryption::new(
        input_file.to_string_lossy().to_string(),
        String::from("200a0e90e538d17390c8c4bc3bc71e44"),
      );

      assert!(file_encryption.edit().is_ok());
    });
  }
}
