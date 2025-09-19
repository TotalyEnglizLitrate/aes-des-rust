mod aes;
mod block_cipher;
mod des;
mod helper;

use std::fs;

use clap::Parser;

use self::{
    aes::Aes128,
    block_cipher::BlockCipher,
    des::{Des, TripleDes},
};

#[derive(Parser)]
#[command(
    version = "v1.0.1",
    about = "A CLI tool for AES, DES, and 3DES encryption/decryption"
)]
struct CliOptions {
    #[arg(
        short, long, value_parser = ["aes", "des", "3des"],
        help = "Specifies the encryption algorithm to use.",
    )]
    algorithm: String,

    #[arg(
        short, long,
        value_parser = ["encrypt", "decrypt"], default_value = "encrypt",
        help = "Specifies the operation mode.",
    )]
    mode: String,

    #[arg(
        short,
        long,
        required_if_eq("mode", "decrypt"),
        help = "Specifies the encryption/decryption key (required for decryption)."
    )]
    key: Option<String>,

    #[arg(short, long, help = "The string to process.", group = "input")]
    string: Option<String>,

    #[arg(short, long, help = "The file to process.", group = "input")]
    file: Option<String>,

    #[arg(long, help = "Specifies that the input string is hex-encoded.")]
    hex: bool,

    #[arg(
        short,
        long,
        help = "Specifies the file to write the output (ciphertext or decrypted text). Ciphertext will be written in hex format."
    )]
    output: Option<String>,
}

fn main() {
    let matches = CliOptions::parse();
    let algorithm = matches.algorithm;
    let mode = matches.mode;
    let key = matches
        .key
        .map(|s| {
            hex_string_to_bytes(&s).unwrap_or_else(|err| {
                eprintln!("Invalid hex key: {}", err);
                std::process::exit(1);
            })
        })
        .or(None);

    // Handle input data properly based on mode and hex flag
    let input_bytes = if let Some(string) = matches.string {
        if matches.hex {
            // For hex input, convert directly to bytes without UTF-8 conversion
            match hex_string_to_bytes(&string) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("Invalid hex string: {}", err);
                    return;
                }
            }
        } else {
            // For regular string input, convert to bytes
            string.as_bytes().to_vec()
        }
    } else if let Some(file) = matches.file {
        match fs::read_to_string(file) {
            Ok(content) => {
                if matches.hex {
                    // If file content is hex, convert to bytes
                    match hex_string_to_bytes(content.trim()) {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            eprintln!("Invalid hex content in file: {}", err);
                            return;
                        }
                    }
                } else {
                    content.as_bytes().to_vec()
                }
            }
            Err(err) => {
                eprintln!("Error reading file: {}", err);
                return;
            }
        }
    } else {
        eprintln!("No input provided");
        return;
    };

    let (result, used_key) = match algorithm.as_str() {
        "aes" => {
            let encryption_key = key.unwrap_or_else(|| Aes128::gen_key().to_vec());
            let result = if mode == "encrypt" {
                Aes128::encrypt(&input_bytes, &encryption_key, true)
            } else {
                Aes128::decrypt(&input_bytes, &encryption_key, true)
            };
            (result, encryption_key)
        }
        "des" => {
            let encryption_key = key.unwrap_or_else(|| Des::gen_key().to_vec());
            let result = if mode == "encrypt" {
                Des::encrypt(&input_bytes, &encryption_key, true)
            } else {
                Des::decrypt(&input_bytes, &encryption_key, true)
            };
            (result, encryption_key)
        }
        "3des" => {
            let encryption_key = key.unwrap_or_else(|| TripleDes::gen_key().to_vec());
            let result = if mode == "encrypt" {
                TripleDes::encrypt(&input_bytes, &encryption_key, true)
            } else {
                TripleDes::decrypt(&input_bytes, &encryption_key, true)
            };
            (result, encryption_key)
        }
        _ => {
            eprintln!("Unsupported algorithm: {}", algorithm);
            return;
        }
    };

    match result {
        Ok(output) => {
            println!("Using key: {}", bytes_to_hex_string(&used_key));
            if mode == "encrypt" {
                println!("Encrypted output: {}", bytes_to_utf8_string(&output));
                println!("Encrypted output (hex): {}", bytes_to_hex_string(&output));
            } else {
                println!("Decrypted output: {}", bytes_to_utf8_string(&output));
            }

            if let Some(output_file) = &matches.output {
                let write_result = if mode == "encrypt" {
                    fs::write(output_file, bytes_to_hex_string(&output))
                } else {
                    fs::write(output_file, bytes_to_utf8_string(&output))
                };
                if let Err(err) = write_result {
                    eprintln!("Error writing to file: {}", err);
                } else {
                    println!("Output written to {}", output_file);
                }
            }
        }
        Err(err) => eprintln!("Error during {}: {}", mode, err),
    }
}

fn hex_char_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_string_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_char_value(bytes[i])
            .ok_or_else(|| format!("Invalid hex character at position {}", i))?;
        let lo = hex_char_value(bytes[i + 1])
            .ok_or_else(|| format!("Invalid hex character at position {}", i + 1))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, &b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8(out).unwrap()
}

fn bytes_to_utf8_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
        // Warning has ANSI escape code for yellow text<F2>
        eprintln!("\x1b[1;33mWarning\x1b[0m: Non-UTF8 bytes encountered, using lossy conversion.");
        String::from_utf8_lossy(bytes).to_string()
    })
}
