## Basic idea for database encryption of mostro daemon

Basically the flow i have in mind is :

- Get input password from user input
- Use argon2 to derive a robust key
- Use the key derive to encrypt with chacha20poly the mostrodb
- When operations on db are needed we will use key in RAM to decrypt,update db and save new file encrypted again.

Pros:
- Few time database is not encrypted at rest
- Password in ram is a good trade off for safety ( next step could be using a TPM chip or some external key manager) - i added the use of [secrecy](https://crates.io/crates/secrecy) crate to avoid leak during dump or log of ram variable.
  
