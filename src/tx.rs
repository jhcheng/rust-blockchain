use crate::account::{new_address, Address};
use chrono::{DateTime, FixedOffset, Utc};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[cfg(not(test))]
pub fn now() -> DateTime<FixedOffset> {
    Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tx {
    pub from: Address,
    pub to: Address,
    pub value: u64,
    pub nonce: u64,
    pub(crate) time: u64,
}

impl Tx {
    pub fn new(from: &Address, to: &Address, value: u64, nonce: u64) -> Self {
        Tx {
            from: from.clone(),
            to: to.clone(),
            value,
            nonce,
            time: now().timestamp() as u64,
        }
    }

    pub fn hash(&self) -> Hash {
        new_hash(self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SigTx {
    pub tx: Tx,
    sig: Vec<u8>,
    rec_id: u8,
}

impl SigTx {
    pub fn new(tx: &Tx, sig: &Vec<u8>, rec_id: u8) -> Self {
        SigTx { tx: tx.clone(), sig: sig.to_vec(), rec_id }
    }
    
    pub fn hash(&self) -> Hash {
        new_hash(self)
    }

}

pub fn verify_tx(sig_tx: SigTx) -> bool {
    let hash = sig_tx.tx.hash();
    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(hash),
        &Signature::try_from(sig_tx.sig.as_slice()).unwrap(),
        RecoveryId::try_from(sig_tx.rec_id).unwrap(),
    );
    let public_key = PublicKey::from(recovered_key.unwrap());
    let addr = new_address(&public_key);
    addr == sig_tx.tx.from
}

pub fn tx_hash(tx: &SigTx) -> Hash {
    new_hash(tx)
}

pub fn tx_pair_hash(l : Hash, r : Hash) -> Hash {
    if r.is_empty() {
        l
    } else {
        new_hash(&(l + r))
    }
}

struct SearchTx {

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::common::HASH_LEN;

    #[test]
    fn test_new_hash() {
        let addr = Address::from(String::from("test"));
        let hash = new_hash(&addr);  // it will be serialized to "test" with double quotes
        assert_eq!(hash.len(), HASH_LEN);
        assert_eq!(hex::encode(&hash), "57315cf71be5ffcaf957b9cc196b322e1c4d5a1832396abcee71d05d8caf41a6");
    }
    
    #[test]
    fn test_hash() {
        mock_time::set_mock_time(
            DateTime::from_timestamp(12345678, 0).unwrap().fixed_offset(),
        );

        let tx = Tx::new(&Address::from(String::from("from")), &Address::from(String::from("to")), 1, 1);
        let json = serde_json::to_string(&tx).unwrap();
        let hash = tx.hash();
        assert_eq!(hash.len(), HASH_LEN);
        assert_eq!(hash.to_string(), "f9820c261f18dbcb0d05b2f83e0c31dec6496f3798cb0cc1d889ddd46665d6da");
    }

    #[test]
    fn test_verify_tx() {
        let from = Account::new();
        let to = Account::new();
        let tx = Tx::new(&from.address(), &to.address(), 1, 1);
        let tx_sig = from.sign_tx(&tx);
        assert_eq!(verify_tx(tx_sig), true);
    }

}

#[cfg(test)]
pub mod mock_time {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static MOCK_TIME: RefCell<Option<DateTime<FixedOffset>>> = RefCell::new(None);
    }

    pub fn now() -> DateTime<FixedOffset> {
        MOCK_TIME.with(|cell| {
            cell.borrow()
                .as_ref()
                .cloned()
                .unwrap_or_else(|| Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap()))
        })
    }

    pub fn set_mock_time(time: DateTime<FixedOffset>) {
        MOCK_TIME.with(|cell| *cell.borrow_mut() = Some(time));
    }

    pub fn clear_mock_time() {
        MOCK_TIME.with(|cell| *cell.borrow_mut() = None);
    }
}

use crate::common::{new_hash, Hash};
#[cfg(test)]
pub use mock_time::now;
