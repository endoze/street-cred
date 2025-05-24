use crate::CipherGeneration;
use crate::serialization::RubyMarshal;
use aes_gcm::{
  Aes128Gcm,
  aead::{Aead, KeyInit, generic_array::GenericArray},
};
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};

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
  /// * `tag` - Additional Authenticated data resulting from encrypting the message
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
  /// let tag = "DyMEJPXzmksJGb+QumM2Rd6X";
  ///
  /// let decryptor = MessageEncryption::new(encrypted_message, key, plaintext_aad);
  /// let decrypted_contents = decryptor.decrypt(iv, tag);
  ///
  /// match decrypted_contents {
  ///   Ok(contents) => println!("Decrypted Contents: {}", contents),
  ///   Err(why) => println!("Error: {}", why),
  /// }
  /// ```
  pub fn decrypt(&self, iv: &str, tag: &str) -> anyhow::Result<String> {
    if let (Ok(key), Ok(iv), Ok(message), Ok(tag)) = (
      hex_to_bytes(&self.key),
      general_purpose::STANDARD.decode(iv),
      general_purpose::STANDARD.decode(&self.message),
      general_purpose::STANDARD.decode(tag),
    ) {
      let key = GenericArray::from_slice(&key);
      let iv = GenericArray::from_slice(&iv);
      let decipher = Aes128Gcm::new(key);

      let mut ciphertext = message;
      ciphertext.extend_from_slice(&tag);

      let payload = aes_gcm::aead::Payload {
        msg: &ciphertext,
        aad: self.aad.as_bytes(),
      };

      let plaintext = decipher.decrypt(iv, payload);

      if let Ok(plaintext) = plaintext {
        let content = RubyMarshal::deserialize(plaintext)?;

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
    if let Ok(key) = hex_to_bytes(&self.key) {
      let key = GenericArray::from_slice(&key);
      let random_iv = CipherGeneration::random_iv();
      let random_iv = GenericArray::from_slice(&random_iv);
      let cipher = Aes128Gcm::new(key);

      let serialized_message = RubyMarshal::serialize(std::str::from_utf8(&self.message)?)?;

      let payload = aes_gcm::aead::Payload {
        msg: &serialized_message,
        aad: self.aad.as_bytes(),
      };

      let encrypted = cipher.encrypt(random_iv, payload);

      if let Ok(encrypted) = encrypted {
        let (ct, tag) = encrypted.split_at(encrypted.len() - 16);

        let encryption_result = format!(
          "{}--{}--{}",
          general_purpose::STANDARD.encode(ct),
          general_purpose::STANDARD.encode(random_iv),
          general_purpose::STANDARD.encode(tag)
        );

        return Ok(encryption_result);
      }
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
  ///   contents should be formatted like this: "message--iv--aad"
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
      Err(_) => panic!("second decryption failed"),
    };
  }

  #[test]
  fn test_encryption_decryption_with_aad() {
    let key = "8872ebc11db3ea2ed08cc629d199b164";
    let aad = "some value";
    let plaintext_message = "banana: true
  apple: false
  orange: false";

    let encryptor = MessageEncryption::new(plaintext_message.as_bytes().to_vec(), key, aad);

    let encrypted_result = match encryptor.encrypt() {
      Ok(encrypted_contents) => encrypted_contents,
      Err(..) => panic!("first encryption failed"),
    };

    let split_data = MessageEncryption::split_encrypted_contents(&encrypted_result).unwrap();

    let new_message = split_data[0];
    let new_iv = split_data[1];
    let new_aad = split_data[2];

    let decryptor = MessageEncryption::new(new_message.as_bytes().to_vec(), key, aad);

    let result = decryptor.decrypt(new_iv, new_aad);

    assert_eq!(plaintext_message, result.unwrap());
  }

  #[test]
  fn test_decryption_fails_with_incorrect_iv() {
    let key = "94b6b40cabf62ee59c9aa13a86f0e7d7";
    let aad = "";
    let encrypted_message = b"1alR88JGbSy1wz44cgVgZC3mH2Fg9HjRFtl6NwRoOfpqNzJ61Ub48O1YhJUqaszJgJ8=";
    let decryptor = MessageEncryption::new(encrypted_message.to_vec(), key, aad);

    let result = decryptor.decrypt("123456789012345", "pksKcg/so9Pq3UMHjfnVsg==");

    assert!(result.is_err());
  }

  #[test]
  fn test_encryption_fails_with_non_hex_key() {
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
}
