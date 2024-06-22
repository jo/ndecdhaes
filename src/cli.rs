use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(name = "NDECDHAES")]
#[clap(about = "NDECDHAES - Newline delimited ECDH-P256 AES-GCM BASE64", long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate private key
    GenerateKey {},

    /// Export public key from private key
    PublicKey {},

    /// Encrypt stdin to public key
    Encrypt {
        /// Filename of file containing public key
        #[clap(index = 1, value_name = "FILENAME")]
        public_key_filename: PathBuf,
    },

    /// Decrypt newline delimited ecdh aes stream
    Decrypt {
        /// Filename of file containing secret key
        #[clap(index = 1, value_name = "FILENAME")]
        secret_key_filename: PathBuf,
    }
}
