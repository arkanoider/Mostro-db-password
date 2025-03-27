use std::{fs, io::{Read, Write}, str::FromStr};

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};  
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};

fn derive_key(password: &str, salt: &SaltString) -> Result<String, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let key = argon2.hash_password(password.as_bytes(), salt)?.to_string();
    Ok(key)
}

fn encrypt_database(password: &SecretString, db_file_path: &str, encrypted_db_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read the entire database file into memory
    let mut db_file = fs::File::open(db_file_path)?;
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)?;

    // 2. Generate Salt, Key, and Nonce
    let salt = SaltString::generate(&mut OsRng);

    // 3. Encrypt the Database
    let key = ChaCha20Poly1305::generate_key(password.expose_secret().as_bytes().into());
    let cipher = ChaCha20Poly1305::new(password.expose_secret().as_bytes().into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, db_data.as_slice()).map_err(|_| "Error encrypting database")?;

    // 4. Write the Salt and Ciphertext to the Encrypted File
    let mut encrypted_file = fs::File::create(encrypted_db_file_path)?;
    encrypted_file.write_all(salt.as_str().as_bytes())?; // Store the salt string
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
        )"
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
fn derive_key_and_nonce(password: &SecretString, salt: &SaltString) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {

    let argon2 = Argon2::default();

    // Use expose_secret() to access the underlying string data
    let password_hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)?;

    let hash_bytes = password_hash.hash.ok_or("Missing hash")?.to_vec();

    let key = hash_bytes[..KEY_LEN].to_vec();
    let nonce = hash_bytes[KEY_LEN..].to_vec();

    Ok((key, nonce))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1️⃣ password input from user
    let mut password = String::from("my_super_secret_password");
    let db_file_path = "mostro.db";
    let encrypted_db_file_path = "mostro-encrypted.db";
    // 2️⃣ Create the database
    create_database(db_file_path).await?;

    let salt = SaltString::generate(&mut OsRng);

    // 3️⃣ Derive a secret key from the password
    let argon2_password = derive_key_and_nonce(&SecretString::from(password), &salt).map_err(|_| "Error deriving key")?;

    println!("Generated key: {:?}", argon2_password);

    // 4️⃣ Encrypt the database
  //  let _= encrypt_database(&SecretString::from(argon2_password), db_file_path, encrypted_db_file_path);

    // 4️⃣ Immediately zeroize the password from the RAM
    password.zeroize();
    
    Ok(())
}