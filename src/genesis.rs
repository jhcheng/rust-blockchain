use crate::account::{new_address, Address};
use crate::common::{new_hash, Hash};
use crate::tx::now;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::sha2::Digest;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::{fs, io};

const GENESIS_FILE: &'static str = "genesis.json";

#[derive(Serialize, Deserialize, Clone)]
pub struct Genesis {
    chain: String,
    pub authority: Address,
    pub balances: HashMap<Address, u64>,
    time: u64,
}

impl Genesis {
    pub fn new(name: String, authority: &Address, acc: &Address, balance: u64) -> Result<Self, String> {
        let mut map = HashMap::<Address, u64>::new();
        map.insert(acc.clone(), balance);
        Ok(Genesis{chain: name, authority: authority.clone(), balances: map, time: now().timestamp() as u64})
    }

    pub fn hash(&self) -> Hash {
        new_hash(&self)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SigGenesis {
    pub genesis: Genesis,
    sig: Vec<u8>,
    rec_id: u8,
}

impl SigGenesis {
    pub fn new(genesis: Genesis, sig: &[u8], rec_id: u8) -> Result<Self, String> {
        Ok(SigGenesis{genesis: genesis , sig: sig.to_vec(), rec_id})
    }

    pub fn hash(&self) -> Hash {
        new_hash(&self)
    }

    pub fn write(&self, dir: &str) -> io::Result<()> {
        let jgen = serde_json::to_vec(self)?;
        fs::create_dir_all(dir)?;
        let path = PathBuf::from(dir).join(GENESIS_FILE);
        let mut file = File::create(path)?;
        file.write_all(&jgen)?;
        Ok(())
    }

}


pub fn read_genesis(dir: &str) -> io::Result<SigGenesis> {
    let path = PathBuf::from(dir).join(GENESIS_FILE);
    let mut file = File::open(path)?;
    let mut jgen = Vec::new();
    file.read_to_end(&mut jgen)?;
    let gen: SigGenesis = serde_json::from_slice(&jgen)?;
    Ok(gen)
}

pub fn read_genesis_bytes(dir: &str) -> io::Result<Vec<u8>> {
    let path = PathBuf::from(dir).join(GENESIS_FILE);
    let mut file = File::open(path)?;
    let mut jgen = Vec::new();
    file.read_to_end(&mut jgen)?;
    Ok(jgen)
}

pub fn verify_gen(gen: &SigGenesis) -> Result<bool, Box<dyn std::error::Error>> {
    let hash = gen.genesis.hash(); // Implement the hash method as needed
    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(hash),
        &Signature::try_from(gen.sig.as_slice()).unwrap(),
        RecoveryId::try_from(gen.rec_id).unwrap(),
    );
    let public_key = PublicKey::from(recovered_key.unwrap());
    let acc = new_address(&public_key); // Implement `new_address` to create an address from the public key
    Ok(acc == gen.genesis.authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::tests::{create_account, BLOCK_STORE_DIR, CHAIN_NAME, KEY_STORE_DIR, OWNER_BALANCE};

    #[test]
    fn test_genesis() {
        let _ = fs::remove_dir_all(KEY_STORE_DIR);
        let _ = fs::remove_dir_all(BLOCK_STORE_DIR);

        let auth = create_account();
        let acc = create_account();
        let gen = Genesis::new(CHAIN_NAME.to_string(), auth.address(), acc.address(), OWNER_BALANCE).unwrap();
        let sign_gen = auth.sign_gen(gen);
        sign_gen.write(BLOCK_STORE_DIR).unwrap();
        let sign_gen_read = read_genesis(BLOCK_STORE_DIR).unwrap();
        let valid = verify_gen(&sign_gen_read).unwrap();
        assert!(valid);
    }

}