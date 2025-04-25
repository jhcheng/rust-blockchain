use crate::account::{new_address, Address};
use crate::common::{new_hash, Hash};
use crate::merkle::merkle_hash;
use crate::tx::{now, tx_hash, tx_pair_hash, SigTx};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::sha2::Digest;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::{fs, io};

const BLOCKS_FILE: &str = "block.store";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Block {
    pub(crate) number: u64,
    pub(crate) parent: Hash,
    pub(crate) txs: Vec<SigTx>,
    merkle_tree: Vec<Hash>,
    pub(crate) merkle_root: Hash,
    time: u64,
}

impl Block {
    pub(crate) fn new(number: u64, parent: Hash, txs: &[SigTx]) -> Result<Self, String> {
        let merkle_tree = merkle_hash(&txs, tx_hash, tx_pair_hash)?;
        let merkle_root = merkle_tree.to_vec()[0];
        let blk = Block {
            number,
            parent,
            txs: txs.to_vec(),
            merkle_tree,
            merkle_root,
            time: now().timestamp() as u64,
        };
        Ok(blk)
    }

    pub(crate) fn hash(&self) -> Hash {
        new_hash(&self)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SigBlock {
    pub(crate) block: Block,
    pub(crate) sig: Vec<u8>,
    rec_id: u8,
}

impl SigBlock {
    pub fn new(block: Block, sig: &[u8], rec_id: u8) -> Result<Self, String> {
        Ok(SigBlock { block, sig: sig.to_vec(), rec_id })
    }
    pub(crate) fn hash(&self) -> Hash {
        new_hash(&self)
    }

    pub fn write(&self, dir: &str) -> io::Result<()> {
        fs::create_dir_all(PathBuf::from(dir))?;
        let path = PathBuf::from(dir).join(BLOCKS_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path)?;

        serde_json::to_writer(&file, self)?;
        Ok(())
    }
}

pub fn init_block_store(dir: &str) -> io::Result<()> {
    let path = PathBuf::from(dir).join(BLOCKS_FILE);
    let file = OpenOptions::new()
        .create(true) // Create the file if it does not exist
        .read(true)   // Open the file for reading
        .open(&path)?; // Open the file and handle potential errors

    // The file is opened successfully; you can perform additional operations here if needed.
    drop(file); // Explicitly drop the file handle
    Ok(())
}

pub fn read_block(dir: &str) -> io::Result<Vec<SigBlock>> {
    let path = PathBuf::from(dir).join(BLOCKS_FILE);
    let file = OpenOptions::new().read(true).open(&path)?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();
    for line in reader.lines() {
        let blk = serde_json::from_str(&line?)?;
        blocks.push(blk);
    }
    Ok(blocks)
}

/*
pub fn read_blocks<F>(dir: &str, yield_fn: F) -> io::Result<(Box<dyn Fn()>, Box<dyn Fn()>)>
where
    F: Fn(io::Result<SigBlock>) -> bool + 'static,
{
    let path = PathBuf::from(dir).join(BLOCKS_FILE);
    let file = OpenOptions::new().read(true).open(&path)?;
    let reader = BufReader::new(file);
    let blocks = Arc::new(reader);
    let close = Box::new(move || {
        // Closing logic if needed
    });

    let blocks_fn = Box::new(move || {
        for line in blocks.lines() {
            match line {
                Ok(line_content) => {
                    let blk: SigBlock = serde_json::from_str(&line_content).unwrap();
                    if !yield_fn(Ok(blk)) {
                        break;
                    }
                }
                Err(e) => {
                    yield_fn(Err(e));
                    break;
                }
            }
        }
    });

    Ok((blocks_fn, close))
}

pub fn read_blocks_bytes<F>(dir: &str, yield_fn: F) -> io::Result<(Box<dyn Fn()>, Box<dyn Fn()>)>
where
    F: Fn(io::Result<&[u8]>) -> bool + 'static,
{
    let path = PathBuf::from(dir).join(BLOCKS_FILE);
    let file = OpenOptions::new().read(true).open(&path)?;
    let reader = BufReader::new(file);

    let close = Box::new(move || {
        // Closing logic if needed
    });
    
    let blocks_fn = Box::new(move || {
        for line in reader.lines() {
                match line {
                    Ok(line_content) => {
                        if !yield_fn(Ok(line_content.as_bytes())) {
                            break;
                        }
                    }
                    Err(e) => {
                        yield_fn(Err(e));
                        break;
                    }
                }
            }        
    });

    Ok((blocks_fn, close))
}
 */

pub fn verify_block(sig_block: SigBlock, authority: Address) -> Result<bool, String> {
    let hash = sig_block.block.hash(); // Replace with actual hash computation
    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(hash),
        &Signature::try_from(sig_block.sig.as_slice()).unwrap(),
        RecoveryId::try_from(sig_block.rec_id).unwrap(),
    );
    let public_key = PublicKey::from(recovered_key.unwrap());
    let acc = new_address(&public_key); // Implement `new_address` to create an address from the public key
    Ok(acc == authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::common::tests::{create_genesis, genesis_account, BLOCK_STORE_DIR, KEY_PASS, KEY_STORE_DIR};
    use crate::tx::Tx;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_block() {
        let _ = fs::remove_dir_all(KEY_STORE_DIR);
        let _ = fs::remove_dir_all(BLOCK_STORE_DIR);
        
        let sig_genesis = create_genesis();
        let auth = Account::read_account(Path::new(KEY_STORE_DIR).join(&sig_genesis.genesis.authority).to_str().unwrap(), KEY_PASS.as_bytes()).unwrap();
        let (owner_acc, _) = genesis_account(sig_genesis.clone());
        let acc = Account::read_account(Path::new(KEY_STORE_DIR).join(&owner_acc).to_str().unwrap(), KEY_PASS.as_bytes()).unwrap();
        let tx = Tx::new(&Address::from(String::from("from")), &Address::from(String::from("to")), 12, 1);
        let sig_tx = acc.sign_tx(&tx);
        let blk = Block::new(1, sig_genesis.hash(), &[sig_tx]).unwrap();
        let sig_blk = auth.sign_block(blk);
        sig_blk.write(BLOCK_STORE_DIR).unwrap();
        let blocks = read_block(BLOCK_STORE_DIR).unwrap();
        for sb in blocks {
            let valid = verify_block(sb, auth.address().clone()).unwrap();
            assert!(valid);
        }
    }
}