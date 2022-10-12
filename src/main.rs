#![cfg(not(tarpaulin_include))]
use aws_secrets::{config_from_env, SecretsExt};
use clap::{Args, Parser, Subcommand};
use street_cred::FileEncryption;
use serde::{Deserialize, Serialize};
use serde_json::{to_string, Value};
use anyhow::anyhow;

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
  /// Retrieve a key from aws secrets
  Get(Get),
  /// Read contents of a file
  Edit(Edit),
  /// Initialize new secrets file
  Init(Init),
}

#[derive(Args)]
struct Get {
  /// Name of secret in aws secrets
  bag_name: String,
  /// Name of key in bag to retrieve
  key_name: Option<String>,
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
    Commands::Get(get) => {
      let secret_string = retrieve_aws_secret(&get.bag_name).await?;

      println!("{}", secret_string.master_key);
    }
    Commands::Edit(file) => {
      match retrieve_encryption_key() {
        Ok(key) => {
          let fc = FileEncryption::new(file.file_name, key);
          let result = fc.edit();

          match result {
            Ok(_) => {}
            Err(why) => println!("{}", why),
          }
        }

        Err(why) => println!("{}", why),
      }
    }
    Commands::Init(..) => {
      match FileEncryption::create("./") {
        Ok(_) => {},
        Err(why) => println!("{}", why),
      }
    }
  }

  Ok(())
}

#[allow(unused)]
async fn retrieve_aws_secret(bag_name: &str) -> Result<App, Box<dyn std::error::Error>> {
  let shared_config = config_from_env().await;
  let value: Value = bag_name.get_secret(&shared_config).await?;

  let app: App = serde_json::from_str(&to_string(&value)?)?;

  Ok(app)
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
