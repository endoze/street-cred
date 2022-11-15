#![allow(unused)]
use anyhow::anyhow;
use anyhow::Context;
use thurgood::rc::{from_reader, to_writer, Error, RbAny, RbFields, RbRef};

/// Collection of functions used for serialize/deserialize in the RubyMarshal format.
pub struct RubyMarshal {}

impl RubyMarshal {
  /// Serialize a string into the Ruby Marshal format.
  ///
  /// # Arguments
  /// * `contents` - String to serialize
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::RubyMarshal;
  ///
  /// let string = "Peanut Butter Jelly Time";
  ///
  /// let serialized = RubyMarshal::serialize(string);
  ///
  /// assert_eq!(b"\x04\x08I\"\x1dPeanut Butter Jelly Time\x06:\x06ET", serialized.unwrap().as_slice());
  /// ```
  pub fn serialize(contents: &str) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let bytes_written = to_writer(&mut buffer, &RbAny::from(RbRef::Str(contents.to_string())));

    Ok(buffer)
  }

  /// Deserialize data from the Ruby Marshal format.
  ///
  /// # Arguments
  /// * `contents` - Data to deserialize
  ///
  /// # Examples
  ///
  /// ```
  /// use street_cred::RubyMarshal;
  ///
  /// let data = b"\x04\x08I\"\x1dPeanut Butter Jelly Time\x06:\x06ET";
  ///
  /// let string = RubyMarshal::deserialize(data);
  ///
  /// assert_eq!(b"Peanut Butter Jelly Time", string.unwrap().as_slice());
  /// ```
  pub fn deserialize<T>(contents: T) -> anyhow::Result<Vec<u8>>
  where
    T: AsRef<[u8]>,
  {
    let cursor = std::io::Cursor::new(contents);
    let ruby_contents = from_reader(cursor)?;
    let content = ruby_contents
      .as_string()
      .context("deserialization failed")?;

    Ok(content.as_bytes().into())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn serialization_of_valid_data() -> anyhow::Result<()> {
    let test_string = "Peanut Butter Jelly Time";

    let serialized_string = RubyMarshal::serialize(test_string)?;

    let expected_serialization = b"\x04\x08I\"\x1dPeanut Butter Jelly Time\x06:\x06ET";

    assert_eq!(expected_serialization, serialized_string.as_slice());

    Ok(())
  }

  #[test]
  fn deserialization_of_valid_data() -> anyhow::Result<()> {
    let test_string = "\x04\x08I\"\x1dPeanut Butter Jelly Time\x06:\x06ET";
    let deserialized_string = RubyMarshal::deserialize(test_string)?;

    let expected_deserialization = b"Peanut Butter Jelly Time";

    assert_eq!(expected_deserialization, deserialized_string.as_slice());

    Ok(())
  }

  #[test]
  fn deserialization_of_invalid_data() {
    let test_string = "\x04\x08I\"\x1dPeanut Butter Jelly TimeET";
    let deserialized_string = RubyMarshal::deserialize(test_string);

    assert!(deserialized_string.is_err());
  }
}
