use std::{fs, io::{Read, Write}, str::FromStr};

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHasher, Salt, SaltString
    },
    Argon2, PasswordHash, PasswordVerifier
};
use chacha20poly1305::{aead::AeadMut, ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};  
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};


// fn decrypt_database(password: &SecretString, salt: &SaltString, decrypted_db_file_path: &str, encrypted_db_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
//     // 1. Read the entire database file into memory
//     let mut encrypted_db_file = fs::File::open(encrypted_db_file_path)?;
//     let mut encrypted_data = Vec::new();
//     encrypted_db_file.read_to_end(&mut encrypted_data)?;


//     // 2. Parse the Salt and Ciphertext from the Encrypted File
//     let salt = &encrypted_data[0..SALT_SIZE];
//     let nonce = Nonce::from_slice(&encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE]);
//     let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];


//     let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
//     let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
//     let ciphertext = cipher.decrypt(&nonce, db_data.as_slice()).map_err(|_| "Error encrypting database")?;

//     // 4. Write the Salt and Ciphertext to the Encrypted File
//     let mut encrypted_file = fs::File::create(decrypted_db_file_path)?;
//     encrypted_file.write_all(salt.as_str().as_bytes())?; // Store the salt string
//     encrypted_file.write_all(&ciphertext)?;

//     Ok(())
// }

fn encrypt_database(password: &SecretString, salt: &SaltString, db_file_path: &str, encrypted_db_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read the entire database file into memory
    let mut db_file = fs::File::open(db_file_path)?;
    let mut db_data = Vec::new();
    db_file.read_to_end(&mut db_data)?;


    // 3. Encrypt the Database
    let parsed_hash = PasswordHash::new(&password.expose_secret()).map_err(|_| "Error in password check")?;
    
    let key = parsed_hash.hash.unwrap();
    if key.len() != 32 {
        panic!("Key length is not 32 bytes");
    }

    let key_bytes = key.as_bytes();
    if key_bytes.len() != 32 {
        panic!("Key length is not 32 bytes");
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    println!("Nonce len: {:?}", nonce.len());
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
fn derive_key(password: &SecretString) -> Result<(String,SaltString), Box<dyn std::error::Error>> {

    let argon2 = Argon2::default();

    println!("Argon2 Config: {:?}", argon2);
    //Create salt
    let salt = SaltString::generate(&mut OsRng);
    println!("Salt: {:?}", salt);
    println!("Salt len: {:?}", salt.len());

    let buf = &mut [0u8; Salt::RECOMMENDED_LENGTH];

    let salt_decoded = salt.decode_b64(buf).unwrap();
    println!("Salt decoded: {:?}", salt_decoded);
    println!("Salt decoded lenght: {:?}", salt_decoded.len());


    // Use expose_secret() to access the underlying string data
    let password_hash = argon2.hash_password(password.expose_secret().as_bytes(), &salt).map_err(|_| "Error hashing password")?.to_string();

    Ok((password_hash, salt))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1️⃣ password input from user
    let mut password = String::from("my_super_secret_password");
    let db_file_path = "mostro.db";
    let encrypted_db_file_path = "mostro-encrypted.db";
    let decrypted_db_file_path = "mostro-decrypted.db";
    // 2️⃣ Create the database
    create_database(db_file_path).await?;

    // 3️⃣ Derive a secret key from the password
    let (argon2_password, argon_salt ) = derive_key(&SecretString::from(password)).map_err(|_| "Error deriving key")?;

    println!("Generated key: {:?}", argon2_password);

    // 4️⃣ Encrypt the database
    let _ = encrypt_database(&SecretString::from(argon2_password), &argon_salt, db_file_path, encrypted_db_file_path);

    // let _ = decrypt_database(&SecretString::from(argon2_password), &argon_salt, decrypted_db_file_path, encrypted_db_file_path)

    // 4️⃣ Immediately zeroize the password from the RAM
    // password.zeroize();
    
    Ok(())
}