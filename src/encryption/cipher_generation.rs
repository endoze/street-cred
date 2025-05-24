use aes_gcm::{
  Aes128Gcm,
  aead::{KeyInit, OsRng, rand_core::RngCore},
};

/// Collection of functions that generate random data for encryption/decryption.
pub struct CipherGeneration {}

impl CipherGeneration {
  /// Generates a random 12 byte initialization vector and returns it as a
  /// `Vec<u8>`
  ///
  /// # Example
  ///
  /// ```
  /// use street_cred::CipherGeneration;
  ///
  /// let random_iv = CipherGeneration::random_iv();
  /// ```
  pub fn random_iv() -> Vec<u8> {
    Self::random_bytes(12)
  }

  /// Generates a random 16 byte encryption key and returns it as a
  /// `Vec<u8>`
  ///
  /// # Example
  ///
  /// ```
  /// use street_cred::CipherGeneration;
  ///
  /// let key = CipherGeneration::random_key();
  /// ```
  pub fn random_key() -> String {
    let key = Aes128Gcm::generate_key(&mut OsRng);
    hex::encode(key)
  }

  /// Generates a Vec of a specified length filled with random bytes and returns it as a
  /// `Vec<u8>`
  ///
  /// # Arguments
  /// * `length` - Size of the vector to generate
  ///
  fn random_bytes(length: usize) -> Vec<u8> {
    let mut data = vec![0; length];
    OsRng.fill_bytes(&mut data);

    data
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_random_iv() {
    let first_random_iv = CipherGeneration::random_iv();
    let second_random_iv = CipherGeneration::random_iv();

    assert_ne!(first_random_iv, second_random_iv);
  }

  #[test]
  fn test_random_key() {
    let first_random_key = CipherGeneration::random_key();
    let second_random_key = CipherGeneration::random_key();

    assert_ne!(first_random_key, second_random_key);
  }

  #[test]
  fn test_random_bytes() {
    let first_random_bytes = CipherGeneration::random_bytes(10);
    let second_random_bytes = CipherGeneration::random_bytes(10);

    assert_ne!(first_random_bytes, second_random_bytes);
  }
}
