use core::str;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    str::FromStr,
};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, Salt, SaltString},
    Argon2, PasswordHash,
};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use zeroize::Zeroize;

pub const SALT_SIZE: usize = 22;
pub const NONCE_SIZE: usize = 12;

fn decrypt_database(
    password: &SecretString,
    decrypted_db_file_path: &str,
    encrypted_db_file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read the entire database file into memory
    let mut encrypted_db_file = fs::File::open(encrypted_db_file_path)?;
    let mut encrypted_data = Vec::new();
    encrypted_db_file.read_to_end(&mut encrypted_data)?;

    let keyderived = password.expose_secret();
    let nonce = Nonce::from_slice(&encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE]);
    println!("Nonce: {:?}", nonce);
    println!("Nonce len: {:?}", nonce.len());

    let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];

    // 3. Encrypt the Database
    println!("Key Derived: {:?}", keyderived);
    let parsed_hash = PasswordHash::new(keyderived).map_err(|_| "Error in password check")?;

    let key = parsed_hash.hash.unwrap();
    let key_bytes = key.as_bytes();
    if key_bytes.len() != 32 {
        panic!("Key length is not 32 bytes");
    }
    println!("Key Bytes: {:?}", key_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Error encrypting database")?;

    // 4. Write the Salt and Ciphertext to the Encrypted File
    let mut decrypted_file = fs::File::create(decrypted_db_file_path)?;
    decrypted_file.write_all(&plaintext)?;

    Ok(())
}

fn encrypt_database(
    password: &SecretString,
    salt: &SaltString,
    db_file_path: &str,
    encrypted_db_file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read the entire database file into memory
    let mut db_file = fs::File::open(db_file_path)?;
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)?;

    // 3. Encrypt the Database
    let parsed_hash =
        PasswordHash::new(password.expose_secret()).map_err(|_| "Error in password check")?;

    let key = parsed_hash.hash.unwrap();
    let key_bytes = key.as_bytes();
    if key_bytes.len() != 32 {
        panic!("Key length is not 32 bytes");
    }

    println!("Key Byte: {:?}", key_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    println!("Nonce: {:?}", nonce);
    println!("Nonce len: {:?}", nonce.len());
    let ciphertext = cipher
        .encrypt(&nonce, db_data.as_slice())
        .map_err(|_| "Error encrypting database")?;

    // 4. Write the Salt and Ciphertext to the Encrypted File
    let mut encrypted_file = fs::File::create(encrypted_db_file_path)?;
    encrypted_file.write_all(salt.as_str().as_bytes())?; // Store the salt string
    encrypted_file.write_all(&nonce)?;
    encrypted_file.write_all(&ciphertext)?;

    Ok(())
}

async fn create_database(db_file_path: &str) -> Result<(), sqlx::Error> {
    let db_options = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_file_path))?
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(db_options).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            age INTEGER
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query("INSERT INTO users (name, age) VALUES (?1, ?2)")
        .bind("Alice")
        .bind(30)
        .execute(&pool)
        .await?;

    pool.close().await;
    Ok(())
}

// Helper function to derive the key and nonce from the password and salt
fn derive_key(
    password: &SecretString,
    salt: Option<SaltString>,
) -> Result<(String, SaltString), Box<dyn std::error::Error>> {
    //Create argon2 instance
    let argon2 = Argon2::default();
    //Create salt if not provided
    let salt = if let Some(salt) = salt {
        salt
    } else {
        SaltString::generate(&mut OsRng)
    };
    println!("Salt: {:?}", salt);
    println!("Salt len: {:?}", salt.len());

    let buf = &mut [0u8; Salt::RECOMMENDED_LENGTH];

    let salt_decoded = salt.decode_b64(buf).unwrap();
    println!("Salt decoded: {:?}", salt_decoded);
    println!("Salt decoded lenght: {:?}", salt_decoded.len());

    println!("Password: {:?}", password.expose_secret().as_bytes());

    // Use expose_secret() to access the underlying string data
    let password_hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map_err(|_| "Error hashing password")?
        .to_string();

    println!("Password hash: {:?}", password_hash);
    Ok((password_hash, salt))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Password input from user
    let mut password = String::from("my_super_secret_password");
    let db_file_path = "mostro.db";
    let encrypted_db_file_path = "mostro-encrypted.db";
    let decrypted_db_file_path = "mostro-decrypted.db";

    // Create the database if encrypted file does not exist
    let (argon2_password, argon_salt) = if !Path::new(encrypted_db_file_path).exists() {
        create_database(db_file_path).await?;
        derive_key(&SecretString::from(password.clone()), None).map_err(|_| "Error deriving key")?
    }
    // If encrypted file exists, derive the key from the password and salt saved in the file
    else {
        println!("Database already exists");
        let mut encrypted_db_file = fs::File::open(encrypted_db_file_path)?;
        let mut encrypted_data = Vec::new();
        encrypted_db_file.read_to_end(&mut encrypted_data)?;

        // 2. Parse the Salt and Ciphertext from the Encrypted File
        let salt = match str::from_utf8(&encrypted_data[0..SALT_SIZE]) {
            Ok(salt) => salt,
            Err(e) => {
                return Err(e.into());
            }
        };
        derive_key(
            &SecretString::from(password.clone()),
            Some(SaltString::from_b64(salt).unwrap()),
        )
        .map_err(|_| "Error deriving key")?
    };

    // Derive a secret key from the password
    println!("Generated key: {:?}", argon2_password);
    // Immediately zeroize the password from the RAM
    password.zeroize();

    // Encrypt the database
    let _ = encrypt_database(
        &SecretString::from(argon2_password.clone()),
        &argon_salt,
        db_file_path,
        encrypted_db_file_path,
    );

    // Decrypt the database
    let _ = decrypt_database(
        &SecretString::from(argon2_password),
        decrypted_db_file_path,
        encrypted_db_file_path,
    );

    Ok(())
}
