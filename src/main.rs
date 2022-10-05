use std::io;
use std::io::Write;

// £ isn't ascii so can't be here - it's unicode so messes with string lengths.
const ALPHABET: &str = r#"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"$%^&*()/<>,.?:;'@#~|-=_+ "#;

enum Mode {
    Encrypt,
    Decrypt
}

fn main() {
    println!("Welcome to the vernam cipher!");

    let mut mode = Mode::Encrypt;
    loop {
        let mut okay = false;
        while !okay {
            let response = ask("Encrypt (e) or decrypt (d)?");

            okay = true;
            if response == "e".to_string() {
                mode = Mode::Encrypt;
            } else if response == "d".to_string() {
                mode = Mode::Decrypt;
            } else {
                okay = false;
            }
        }

        match mode {
            Mode::Encrypt => {
                encrypt();
            }
            Mode::Decrypt => {
                decrypt();
            }
        }
    }
}

fn encrypt() {
    let plaintext = ask("Enter the plaintext");
    let key = get_key(plaintext.len());

    let output = vernam_encrypt(plaintext, key);

    println!("Encrypted text: {}", output);
}

fn vernam_encrypt(plaintext: String, key: String) -> String {
    let mut output = String::new();

    for i in 0..(plaintext.len()) {
        let plain_digit: u8 = get_char_index(plaintext.chars().nth(i).unwrap());
        let key_digit: u8 = get_char_index(key.chars().nth(i).unwrap());

        let cipher_digit = plain_digit ^ key_digit;

        output.push_str(&cipher_digit.to_string());
        output.push(' ');
    }

    // Remove last space from line
    let output = output.trim_end().to_string();

    output
}

fn decrypt() {
    let mut encrypted_values = vec!();
    '_get_encrypted_text: loop {
        let encrypted_text = ask("Enter the encrypted text");
        let split_encrypted_text = encrypted_text.split_whitespace();

        for segment in split_encrypted_text {
            match segment.parse::<u8>() {
                Ok(u) => {
                    encrypted_values.push(u);
                }
                Err(_) => {
                    println!("Invalid encrypted text. Please try again");
                    continue '_get_encrypted_text;
                }
            }
        }

        break;
    }

    let key = get_key(encrypted_values.len());

    let output = vernam_decrypt(encrypted_values, key);

    println!("The plaintext is: {}", output);
}

fn vernam_decrypt(encrypted_values: Vec<u8>, key: String) -> String {
    let mut output = String::default();

    for i in 0..(encrypted_values.len()) {
        let encrypted_u8 = encrypted_values[i];

        let key_char = key.chars().nth(i).unwrap();
        let key_u8 = get_char_index(key_char);

        let plain_u8 = encrypted_u8 ^ key_u8;
        let plain_char = get_index_char(plain_u8).unwrap();

        output.push(plain_char);
    }

    output
}

fn get_char_index(c: char) -> u8 {
    ALPHABET.find(c).unwrap() as u8
}

fn get_index_char(d: u8) -> Option<char> {
    ALPHABET.chars().nth(d as usize)
}

fn ask(q: &str) -> String {
    println!("{}", q);
    print!(" >> ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut output = String::default();
    io::stdin().read_line(&mut output).expect("Failed to read in line");
    output = output.replace('\n', "");

    output
}

fn get_key(min_len: usize) -> String {
    let mut got_key = false;
    let mut key = String::default();
    while !got_key {
        key = ask("Enter the key");
        if key.len() >= min_len {
            got_key = true;
        } else {
            println!("Key must be longer or equal length to the plaintext");
        }
    }

    key
}

#[cfg(test)]
mod tests {
    use crate::{vernam_decrypt, vernam_encrypt};

    #[test]
    fn encrypt() {
        assert_eq!(vernam_encrypt("abc".to_string(), "bob".to_string()), "1 51 7")
    }

    #[test]
    fn decrypt() {
        assert_eq!(vernam_decrypt(vec!(1, 51, 7), "bob".to_string()), "abc".to_string())
    }
}
