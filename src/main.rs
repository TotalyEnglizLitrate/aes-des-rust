use std::fs;

use clap::Parser;

use aes_des_rust::{
    aes::Aes128,
    block_cipher::BlockCipher,
    des::{Des, TripleDes},
    helper::{bytes_to_hex_string, bytes_to_utf8_string, hex_string_to_bytes}
};

#[derive(Parser)]
#[command(
    version = "v1.0.3",
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
            println!("{}ed output: {}", mode, bytes_to_utf8_string(&output));
            println!("{}ed output (hex): {}", mode, bytes_to_hex_string(&output));
            println!("\nUsing key: {}", bytes_to_hex_string(&used_key));

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
