#![cfg(not(tarpaulin_include))]
use anyhow::anyhow;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use street_cred::FileEncryption;

#[derive(Serialize, Deserialize, Debug)]
struct App {
  master_key: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Read contents of a file
  Edit(Edit),
  /// Initialize new secrets file
  Init(Init),
}

#[derive(Args)]
struct Edit {
  file_name: String,
}

#[derive(Args)]
struct Init {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let cli = Cli::parse();

  match cli.command {
    Commands::Edit(file) => match retrieve_encryption_key() {
      Ok(key) => {
        let fc = FileEncryption::new(file.file_name, key);
        let result = fc.edit();

        match result {
          Ok(_) => {}
          Err(why) => println!("{}", why),
        }
      }

      Err(why) => println!("{}", why),
    },
    Commands::Init(..) => match FileEncryption::create("./") {
      Ok(_) => {}
      Err(why) => println!("{}", why),
    },
  }

  Ok(())
}

fn retrieve_encryption_key() -> anyhow::Result<String> {
  if let Ok(key) = std::env::var("MASTER_KEY") {
    return Ok(key);
  }

  let key_file_path = std::path::Path::new("master.key");

  if key_file_path.exists() {
    let key = std::fs::read_to_string(key_file_path)?;

    return Ok(key);
  }

  Err(anyhow!("Could not find master key in environment or file."))
}
