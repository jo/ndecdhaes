use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
};
use base64::Engine;
use std::io::BufRead;
use p256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    EncodedPoint, PublicKey, SecretKey,
};
use rand_core::OsRng;
use std::{
    io, io::{Error, Read, Write},
    str, str::FromStr,
    fs,
};

use crate::cli::{Args, Commands};

fn read_stdin() -> Vec<u8> {
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).unwrap();
    data
}

pub struct Ndecdhaes {
    args: Args,
}

impl Ndecdhaes {
    pub fn new(args: Args) -> Self {
        Self { args }
    }

    pub fn run(&self) -> Result<(), Error> {
        match &self.args.command {
            Commands::GenerateKey {} => {
                let secret = SecretKey::random(&mut OsRng);
                let pem = secret.to_pkcs8_pem(Default::default()).unwrap();
                let pem_string: &str = pem.as_ref();
                io::stdout()
                    .write_all(pem_string.as_bytes())
                    .expect("Unable to write to stdout");
            }

            Commands::PublicKey {} => {
                let pem = read_stdin();

                let pem_string = str::from_utf8(&pem).unwrap();
                let secret = SecretKey::from_pkcs8_pem(pem_string).expect("should be parsable");
                let pk_bytes = EncodedPoint::from(secret.public_key());
                let public = PublicKey::from_sec1_bytes(pk_bytes.as_ref()).unwrap();
                let public_pem = public.to_public_key_pem(Default::default()).unwrap();
                let public_pem_string: &str = public_pem.as_ref();
                io::stdout()
                    .write_all(public_pem_string.as_bytes())
                    .expect("Unable to write to stdout");
            }

            Commands::Encrypt {
                public_key_filename,
            } => {
                let public_key_pem = fs::read(&public_key_filename).unwrap();
                let public_pem_string = str::from_utf8(&public_key_pem).unwrap();
                let public = PublicKey::from_str(public_pem_string).unwrap();

                let secret = EphemeralSecret::random(&mut OsRng);
                let encoded_point = EncodedPoint::from(secret.public_key());
                let public_bytes = encoded_point.as_bytes();

                // TODO: validate
                let data = read_stdin();

                let shared = secret.diffie_hellman(&public);

                let key = shared.raw_secret_bytes();

                let cipher = Aes256Gcm::new(key);
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
                let ciphertext = cipher.encrypt(&nonce, data.as_ref()).unwrap();

                let mut result = vec![];
                result.extend(public_bytes); // 65 Bytes
                result.extend(nonce);        // 12 Bytes
                result.extend(ciphertext);   // rest

                let data = base64::prelude::BASE64_STANDARD
                    .encode(result);

                println!("{}", data);
            }

            Commands::Decrypt {
                secret_key_filename,
            } => {
                let secret_key_pem = fs::read(&secret_key_filename).unwrap();
                let secret_pem_string = str::from_utf8(&secret_key_pem).unwrap();
                let secret = SecretKey::from_pkcs8_pem(secret_pem_string).unwrap();

                for line in io::stdin().lock().lines() {
                    match line {
                        Ok(line) => {
                            let data = base64::prelude::BASE64_STANDARD
                                .decode(line.as_bytes())
                                .expect("Failed to decode base64 data.");

                            let public_key_bytes = &data[0..65];
                            let public = PublicKey::from_sec1_bytes(public_key_bytes).unwrap();

                            let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                            let key = shared.raw_secret_bytes();

                            let nonce = &data[65..(65 + 12)];

                            let ciphertext = &data[(65 + 12)..];

                            let cipher = Aes256Gcm::new(key);
                            let text = cipher.decrypt(nonce.into(), ciphertext.as_ref()).unwrap();

                            io::stdout()
                                .write_all(&text)
                                .expect("Unable to write to stdout");
                        },
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }
}
