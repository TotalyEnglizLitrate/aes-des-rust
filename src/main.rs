mod aes;
mod block_cipher;
mod constants;
mod des;

use aes::Aes128;
use block_cipher::BlockCipher;
use clap::{Arg, ArgAction, ArgGroup, Command};
use des::{Des, TripleDes};
use std::fs;

fn main() {
    let matches = Command::new("AES/DES CLI")
        .version("1.0")
        .author("Narendra Sampath Kumar <narendra24110064@snuchennai.edu.in>")
        .about("Encrypt or decrypt strings or files using AES, DES, or 3DES algorithms")
        .arg(
            Arg::new("algorithm")
                .short('a')
                .long("algorithm")
                .value_name("ALGORITHM")
                .help("Specifies the encryption algorithm")
                .value_parser(["aes", "des", "3des"])
                .required(true),
        )
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .value_name("MODE")
                .help("Specifies the operation mode")
                .required(true)
                .value_parser(["encrypt", "decrypt"]),
        )
        .arg(
            Arg::new("key")
                .short('k')
                .long("key")
                .value_name("KEY")
                .help("Specifies the encryption/decryption key (required for decryption)"),
        )
        .arg(
            Arg::new("string")
                .short('s')
                .long("string")
                .value_name("STRING")
                .help("The string to process"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("FILE")
                .help("The file to process"),
        )
        .arg(
            Arg::new("hex")
                .long("hex")
                .action(ArgAction::SetTrue)
                .help("Specifies that the input string is hex-encoded"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT")
                .help("Specifies the file to write the output (ciphertext or decrypted text)"),
        )
        .group(
            ArgGroup::new("input")
                .args(&["string", "file"])
                .required(true),
        )
        .get_matches();

    let algorithm = matches
        .get_one::<String>("algorithm")
        .unwrap()
        .to_ascii_lowercase();
    let mode = matches.get_one::<String>("mode").unwrap();
    let key = matches
        .get_one::<String>("key")
        .map(|s| {
            hex_string_to_bytes(s).unwrap_or_else(|err| {
                eprintln!("Invalid hex key: {}", err);
                std::process::exit(1);
            })
        })
        .or(None);

    if mode == "decrypt" && key.is_none() {
        eprintln!("Error: A key must be provided for decryption.");
        return;
    }

    // Handle input data properly based on mode and hex flag
    let input_bytes = if let Some(string) = matches.get_one::<String>("string") {
        if matches.get_flag("hex") {
            // For hex input, convert directly to bytes without UTF-8 conversion
            match hex_string_to_bytes(string) {
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
    } else if let Some(file) = matches.get_one::<String>("file") {
        match fs::read_to_string(file) {
            Ok(content) => {
                if matches.get_flag("hex") {
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

            if let Some(output_file) = matches.get_one::<String>("output") {
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
    // SAFETY: bytes are valid ASCII hex
    unsafe { String::from_utf8_unchecked(out) }
}

fn bytes_to_utf8_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
        eprintln!("Warning: Non-UTF8 bytes encountered, using lossy conversion.");
        String::from_utf8_lossy(bytes).to_string()
    })
}
