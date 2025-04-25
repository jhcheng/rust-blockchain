use k256::sha2::Digest;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::fmt::Display;
use std::ops::Add;

pub const HASH_LEN: usize = 32;
pub const ENC_KEY_LEN: usize = 32;

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Default, Copy)]
#[derive(Hash)]
pub struct Hash([u8; HASH_LEN]);

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Hash {
    pub fn to_string(&self) -> String {
        hex::encode(self.0)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.0.into_iter().all(|b| b == 0)
    }

}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for Hash {
    type Output = String;

    fn add(self, rhs: Self) -> Self::Output {
        [self.to_string(), rhs.to_string()].concat()
    }
}

pub fn new_hash(val : & impl Serialize) -> Hash {
    let data = serde_json::to_vec(&val).unwrap();
    let mut hasher = Keccak256::default();
    hasher.update(&data);
    let output = hasher.finalize();
    let slice = output.as_slice();
    let array = match slice.try_into() {
        Ok(array) => array,
        Err(_) => panic!("Expected a hash of length {} but it was {}", HASH_LEN, slice.len()),
    };
    Hash(array)
}

#[cfg(test)]
pub mod tests {
    use crate::account::{Account, Address};
    use crate::genesis::{Genesis, SigGenesis};

    pub const KEY_STORE_DIR: &'static str = ".key_store";
    pub const BLOCK_STORE_DIR: &'static str = ".block_store";

    pub const OWNER_BALANCE: u64 = 1000;
    pub const KEY_PASS: &'static str = "key_pass";
    pub const CHAIN_NAME: &'static str = "test-chain";

    pub fn create_account() -> Account {
        let acc = Account::new();
        acc.write(KEY_STORE_DIR, KEY_PASS.as_bytes()).unwrap();
        acc
    }

    pub fn create_genesis() -> SigGenesis {
        let auth = create_account();
        let acc = create_account();
        let gen = Genesis::new(CHAIN_NAME.to_string(), auth.address(), acc.address(), OWNER_BALANCE).unwrap();
        auth.sign_gen(gen)
    }

    pub fn genesis_account(sig_genesis: SigGenesis) -> (Address, u64) {
        sig_genesis.genesis.balances.into_iter().next().unwrap()
    }
}