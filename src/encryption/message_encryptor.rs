#![allow(unused)]

use crate::serialization::RubyMarshal;
use crate::CipherGeneration;
use anyhow::anyhow;
use core::iter::repeat;
use core::str;
use crypto::aead::{AeadDecryptor, AeadEncryptor};
use crypto::aes_gcm::AesGcm;
use std::fmt::Display;

/// A storage container that represents a message you want to encrypt/decrypt.
/// In order for both operations to work, you also need to store the encryption key
/// and additional authenticated data (plaintext).
///
/// # Examples
///
/// You can create a `MessageEncryption` using the following code:
///
/// ```
/// use street_cred::MessageEncryption;
///
/// let message = b"secret message".to_vec();
/// let key = "425D76994EE6101105DDDA2EE2604AA0";
/// let aad = "additional authenticated data";
/// let encryptor = MessageEncryption::new(message, key, aad);
/// ```
pub struct MessageEncryption {
  message: Vec<u8>,
  key: String,
  aad: String,
}

impl MessageEncryption {
  /// Create a new instance of MessageEncryption
  ///
  /// # Arguments
  /// * `message` - Message to be encrypted
  /// * `key` - Key to use for encryption/decryption
  /// * `aad` - Additional authenticated data
  ///
  /// # Examples
  /// ```
  /// use street_cred::MessageEncryption;
  ///
  /// let message = b"secret message".to_vec();
  /// let key = "425D76994EE6101105DDDA2EE2604AA0";
  /// let aad = "additional authenticated data";
  /// let encryptor = MessageEncryption::new(message, key, aad);
  /// ```
  pub fn new(message: Vec<u8>, key: &str, aad: &str) -> Self {
    MessageEncryption {
      message,
      key: key.to_string(),
      aad: aad.to_string(),
    }
  }

  /// Decrypts the contents of the `MessageEncryption` and returns them as a `String`
  ///
  /// # Arguments
  ///
  /// * `iv` - Initialization vector used when initially encrypting the message
  /// * `encrypted_aad` - Additional Authenticated data resulting from encrypting the message
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::MessageEncryption;
  ///
  /// let encrypted_message = b"".to_vec();
  /// let key = "425D76994EE6101105DDDA2EE2604AA0";
  /// let plaintext_aad = "";
  /// let iv = "fWoW3cyLE2/JfiiF";
  /// let encrypted_aad = "DyMEJPXzmksJGb+QumM2Rd6X";
  ///
  /// let decryptor = MessageEncryption::new(encrypted_message, key, plaintext_aad);
  /// let decrypted_contents = decryptor.decrypt(iv, encrypted_aad);
  ///
  /// match decrypted_contents {
  ///   Ok(contents) => println!("Decrypted Contents: {}", contents),
  ///   Err(why) => println!("Error: {}", why),
  /// }
  /// ```
  pub fn decrypt(&self, iv: &str, encrypted_aad: &str) -> anyhow::Result<String> {
    if let (Ok(key), Ok(iv), Ok(message), Ok(aad), Ok(encrypted_aad)) = (
      hex_to_bytes(&self.key),
      base64::decode(iv),
      base64::decode(&self.message),
      base64::decode(&self.aad),
      base64::decode(encrypted_aad),
    ) {
      let key_size = crypto::aes::KeySize::KeySize128;
      let mut decipher = AesGcm::new(key_size, &key, &iv, &aad);

      // create output buffer the same size as the encrypted message
      // this is where we will store the decrypted message results
      let mut decrypted_output_buffer: Vec<u8> = repeat(0).take(message.len()).collect();

      let result = decipher.decrypt(
        &message,
        &mut decrypted_output_buffer[..],
        &encrypted_aad[..],
      );

      let content = RubyMarshal::deserialize(&decrypted_output_buffer)?;

      if result {
        return Ok(String::from_utf8(content)?);
      }
    }

    Err(anyhow!("Decryption not successful"))
  }

  /// Encrypts the contents of the `MessageEncryption` and returns them as a `String`
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::MessageEncryption;
  ///
  /// let plaintext_message = b"super secret message".to_vec();
  /// let key = "16 byte key line";
  /// let plaintext_aad = "";
  /// let encryptor = MessageEncryption::new(plaintext_message, key, plaintext_aad);
  /// let encrypted_contents = encryptor.encrypt();
  ///
  /// match encrypted_contents {
  ///   Ok(contents) => println!("Encrypted Contents: {}", contents),
  ///   Err(why) => println!("Error: {}", why),
  /// }
  /// ```
  pub fn encrypt(&self) -> anyhow::Result<String> {
    if let (Ok(key), Ok(decoded_aad)) = (hex_to_bytes(&self.key), base64::decode(&self.aad)) {
      let key_size = crypto::aes::KeySize::KeySize128;
      let random_iv = CipherGeneration::random_iv();
      let mut cipher = AesGcm::new(key_size, &key, &random_iv, &decoded_aad);

      let serialized_message = RubyMarshal::serialize(std::str::from_utf8(&self.message)?)?;

      // create output buffer the same size as the message to be encrypted
      // this is where we will store the encrypted message results
      let mut encrypted_output: Vec<u8> = repeat(0).take(serialized_message.len()).collect();

      // create output buffer the same size as the auth tag
      // this is where we will store the encrypted auth tag results
      let mut encrypted_aad_output: Vec<u8> = repeat(0).take(16).collect();

      cipher.encrypt(
        &serialized_message,
        &mut encrypted_output[..],
        &mut encrypted_aad_output[..],
      );

      let encryption_result = format!(
        "{}--{}--{}",
        base64::encode(encrypted_output),
        base64::encode(random_iv),
        base64::encode(encrypted_aad_output)
      );

      return Ok(encryption_result);
    }

    Err(anyhow!("Encryption not successful"))
  }

  /// Split contents of an encrypted file into a Vec with a length of 3.
  /// The first index is the encrypted contents, the second index is the
  /// initialization vector, and the third index is the additional authenticated
  /// data.
  ///
  /// # Arguments
  ///
  /// * `contents` - The entire encrypted file as one long string. Encrypted
  /// contents should be formatted like this: "message--iv--aad"
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::MessageEncryption;
  ///
  /// let encrypted_contents = "HPxd1UcM3cH+Rt0HaIOFzdHqIPWIc3yR--/EoLW7ichWLzLh3V--7L1L8uPH7LoQYLkEfIckgA==";
  /// let split_parts = MessageEncryption::split_encrypted_contents(encrypted_contents);
  /// ```
  pub fn split_encrypted_contents(contents: &str) -> anyhow::Result<Vec<&str>> {
    let contents = contents.split("--").fold(Vec::new(), |mut acc, content| {
      acc.push(content);

      acc
    });

    if contents.len() == 3 {
      Ok(contents)
    } else {
      Err(anyhow!("Invalid encrypted contents"))
    }
  }
}

fn hex_to_bytes(raw_hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
  hex::decode(raw_hex)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::FileEncryption;
  use std::io;

  #[test]
  fn test_encrypt_decrypt_cycle() {
    let key = "8872ebc11db3ea2ed08cc629d199b164";
    let aad = "";
    let plaintext_message = b"banana: true
apple: false
orange: false";

    let encryptor = MessageEncryption::new(plaintext_message.to_vec(), key, aad);

    let encrypted_result = match encryptor.encrypt() {
      Ok(encrypted_contents) => encrypted_contents,
      Err(..) => panic!("first encryption failed"),
    };

    let split_data = MessageEncryption::split_encrypted_contents(&encrypted_result).unwrap();

    let new_message = split_data[0];
    let new_iv = split_data[1];
    let new_aad = split_data[2];

    let decryptor = MessageEncryption::new(new_message.as_bytes().to_vec(), key, aad);

    let decrypted_result = decryptor.decrypt(new_iv, new_aad);

    let encryptor = match decrypted_result {
      Ok(decrypted_contents) => {
        MessageEncryption::new(decrypted_contents.as_bytes().to_vec(), key, aad)
      }
      Err(why) => panic!("first decryption failed {}", why),
    };

    let encrypted_result = match encryptor.encrypt() {
      Ok(encrypted_contents) => encrypted_contents,
      Err(why) => panic!("second encryption failed {}", why),
    };

    let split_data = MessageEncryption::split_encrypted_contents(&encrypted_result).unwrap();
    let new_message = split_data[0];
    let new_iv = split_data[1];
    let new_aad = split_data[2];

    let decryptor = MessageEncryption::new(new_message.as_bytes().to_vec(), key, aad);

    let decrypted_result = decryptor.decrypt(new_iv, new_aad);

    match decrypted_result {
      Ok(decrypted_contents) => {
        assert_eq!(decrypted_contents.as_bytes(), plaintext_message);
      }
      Err(why) => panic!("second decryption failed"),
    };
  }

  #[test]
  fn test_decryption_fails() {
    let key = "8872ebc11db3ea2ed08cc629d199b164";
    let aad = "";
    let plaintext_message = b"banana: true
apple: false
orange: false";

    let decryptor = MessageEncryption::new(plaintext_message.to_vec(), key, aad);

    let result = decryptor.decrypt("", "banana");

    assert!(result.is_err());
  }

  #[test]
  fn test_encryption_fails() {
    let key = "8872ebc11db3ea2";
    let aad = "";
    let plaintext_message = b"banana: true
apple: false
orange: false";

    let encryptor = MessageEncryption::new(plaintext_message.to_vec(), key, aad);

    let result = encryptor.encrypt();

    assert!(result.is_err());
  }

  #[test]
  fn test_invalid_aad_for_decrypt() {
    let invalid_aad = "66ag";
    let aad = "";
    let key = "8872ebc11db3ea2";
    let plaintext_message = b"banana: true
apple: false
orange: false";

    let decryptor = MessageEncryption::new(plaintext_message.to_vec(), key, aad);

    let result = decryptor.decrypt("", invalid_aad);

    assert!(result.is_err());
  }

  #[test]
  fn test_invalid_aad_for_encrypt() {
    let invalid_aad = "66ag";
    let key = "8872ebc11db3ea2";
    let plaintext_message = b"banana: true
apple: false
orange: false";

    let encryptor = MessageEncryption::new(plaintext_message.to_vec(), key, invalid_aad);

    let result = encryptor.encrypt();

    assert!(result.is_err());
  }
}
