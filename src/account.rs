use std::fs;
use std::path::Path;

use k256::{PublicKey, SecretKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::{Digest, Shake256, Sha3_256, digest::{Update, ExtendableOutput, XofReader}};
use rand_core::{OsRng, RngCore}; // requires 'getrandom' feature
use serde::{ Serialize, Deserialize};
use argon2::{self, PasswordHasher};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use argon2::password_hash::SaltString;
// 256-bit key for AES

const ENC_KEY_LEN: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct P256k1PublicKey {
    curve: String,
    x: Vec<u8>,
    y: Vec<u8>,
}

fn new_p256k1_public_key(pub_key: &PublicKey) -> P256k1PublicKey {
    P256k1PublicKey {
        curve: "P-256k1".to_string(),
        x: pub_key.to_encoded_point(false).x().unwrap().to_vec(),
        y: pub_key.to_encoded_point(false).y().unwrap().to_vec(),
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct P256k1PrivateKey {
    pub_key: P256k1PublicKey,
    d: Vec<u8>,
}

fn new_p256k1_private_key(prv_key: &SecretKey) -> P256k1PrivateKey {
    P256k1PrivateKey {
        pub_key: new_p256k1_public_key(&prv_key.public_key()),
        d: prv_key.to_bytes().to_vec(),
    }
}

#[derive(Debug, Clone)]
struct Address(String);

impl Address {
    fn new(pub_key: &PublicKey) -> Self {
        let _pk = new_p256k1_public_key(&pub_key);
        let jpub = serde_json::to_vec(&_pk).unwrap();
        let mut hasher = Shake256::default();
        hasher.update(&jpub);
        let boxed = hasher.finalize_boxed(32);
        Address(hex::encode(&boxed.to_vec()))
    }
}

#[derive(Debug)]
struct Account {
    prv: SecretKey,
    addr: Address,
}

impl Account {
    fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        let addr = Address::new(&public_key);
        Account {
            prv: secret_key,
            addr,
        }
    }

    fn address(&self) -> &Address {
        &self.addr
    }

    fn write(&self, dir: &str, pass: &[u8]) -> std::io::Result<()> {
        let jprv = self.encode_private_key()?;
        let cprv = encrypt_with_password(&jprv, pass);
        fs::create_dir_all(dir)?;
        let path = Path::new(dir).join(&self.addr.0);
        fs::write(path, cprv.unwrap())?;
        Ok(())
    }

    fn read_account(path: &str, pass: &[u8]) -> std::io::Result<Self> {
        let cprv = fs::read(path)?;
        let jprv = decrypt_with_password(&cprv.to_vec(), pass);
        Self::decode_private_key(&jprv.unwrap())
    }

    fn encode_private_key(&self) -> std::io::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&new_p256k1_private_key(&self.prv))?)
    }

    fn decode_private_key(jprv: &[u8]) -> std::io::Result<Self> {
        let pk: P256k1PrivateKey = serde_json::from_slice(jprv)?;
        let prv = SecretKey::from_slice(&pk.d).unwrap();
        let addr = Address::new(&prv.public_key());
        Ok(Account { prv, addr })
    }
}

fn encrypt_with_password(msg: &[u8], pass: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut salt = vec![0u8; ENC_KEY_LEN];
    OsRng.fill_bytes(&mut salt);

    let salt_string = SaltString::encode_b64(&salt).unwrap();

    let argon2 = argon2::Argon2::default();
    let binding = argon2.hash_password(pass, &salt_string).unwrap().hash.unwrap();
    let password_hash = binding.as_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&password_hash);

    let cipher = Aes256Gcm::new(&key);

    let mut nonce = [0u8; 12]; // GCM nonce size
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(&Nonce::from_slice(&nonce), msg);
    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext.unwrap());
    Ok(output)
}

fn decrypt_with_password(ciph: &[u8], pass: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (salt, rest) = ciph.split_at(ENC_KEY_LEN);
    let salt_string = SaltString::encode_b64(&salt).unwrap();

    let argon2 = argon2::Argon2::default();
    let binding = argon2.hash_password(pass, &salt_string).unwrap().hash.unwrap();
    let password_hash = binding.as_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&password_hash);

    let cipher = Aes256Gcm::new(&key);

    let (nonce, ciphertext) = rest.split_at(12); // GCM nonce size
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext);
    Ok(plaintext.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account() {
        let account = Account::new();
        println!("Account: {:?}", account);
        assert_eq!(account.address().0.len(), 64);
    }


    #[test]
    fn test_write_read() {
        let account = Account::new();
        let pass = b"password";
        let dir = "test_dir";
        account.write(dir, pass).unwrap();
        let read_account = Account::read_account(&format!("{}/{}", dir, account.address().0), pass).unwrap();
        assert_eq!(account.address().0, read_account.address().0);
        assert_eq!(account.prv.public_key().to_encoded_point(false).x().unwrap(), read_account.prv.public_key().to_encoded_point(false).x().unwrap());
        assert_eq!(account.prv.public_key().to_encoded_point(false).y().unwrap(), read_account.prv.public_key().to_encoded_point(false).y().unwrap());
        assert_eq!(account.prv.to_bytes(), read_account.prv.to_bytes());
        fs::remove_dir_all(dir).unwrap();
    }

}