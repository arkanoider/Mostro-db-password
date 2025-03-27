use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use zeroize::Zeroize;

fn derive_key(password: &str, salt: &SaltString) -> Result<Vec<u8>, argon2::password_hash::Error> {
    let argon2 = Argon2::default();
    let key = argon2.hash_password(password.as_bytes(), salt)?.to_string();
    Ok(key.as_bytes().to_vec())
}

fn main() -> Result<(), argon2::password_hash::Error> {
    // 1️⃣ L'utente inserisce la password
    let mut password = String::from("my_super_secret_password");

    // 2️⃣ Generiamo un sale casuale
    let salt = SaltString::generate(&mut OsRng);

    // 3️⃣ Deriviamo una chiave segreta dalla password
    let mut key = derive_key(&password, &salt)?;

    // 4️⃣ Cancelliamo subito la password dalla RAM
    password.zeroize();

    println!("Generated key: {:?}", key);

    // 5️⃣ Dopo l'uso, cancelliamo anche la chiave dalla RAM
    key.zeroize();

    Ok(())
}