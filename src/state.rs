use crate::account::{Account, Address};
use crate::block::{verify_block, Block, SigBlock};
use crate::common::Hash;
use crate::genesis::SigGenesis;
use crate::merkle::merkle_hash;
use crate::tx::{tx_hash, tx_pair_hash, verify_tx, SigTx};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::rc::Rc;
use std::sync::RwLock;

#[derive(Debug)]
struct State {
    mtx: RwLock<()>, // Mutex for synchronization
    authority: Address,
    balances: HashMap<Address, u64>,
    nonces: HashMap<Address, u64>,
    last_block: SigBlock,
    genesis_hash: Hash,
    txs: HashMap<Hash, SigTx>,
    pending: Option<Rc<RefCell<State>>>,
}

impl State {
    fn new(gen: SigGenesis) -> State {
        let balances = gen.genesis.balances.clone();
        let authority = gen.genesis.authority.clone();
        let genesis_hash = gen.hash();

        State {
            mtx: RwLock::new(()),
            authority: authority.clone(),
            balances: balances.clone(),
            nonces: HashMap::new(),
            last_block: SigBlock::default(), // Assuming default implementation
            genesis_hash,
            txs: HashMap::new(),
            pending: Some(Rc::new(RefCell::new(State {
                mtx: RwLock::new(()),
                authority,
                balances,
                nonces: HashMap::new(),
                last_block: SigBlock::default(),
                genesis_hash,
                txs: HashMap::new(),
                pending: None,
            }))),
        }
    }

    fn apply(&mut self, clone: &State) {
        let _lock = self.mtx.write().unwrap();
        self.balances = clone.balances.clone();
        self.nonces = clone.nonces.clone();
        self.last_block = clone.last_block.clone();
        let mut pending = self.pending.take().unwrap();
        pending.borrow_mut().balances = self.balances.clone();
        pending.borrow_mut().nonces = self.nonces.clone();
        for tx in clone.last_block.block.txs.iter() {
            pending.borrow_mut().txs.remove(&tx.hash());
        }
    }

    fn authority(&self) -> &Address {
        &self.authority
    }

    fn balance(&self, acc: &Address) -> (u64, bool) {
        let _lock = self.mtx.read().unwrap();
        match self.balances.get(acc) {
            Some(&balance) => (balance, true),
            None => (0, false),
        }
    }

    fn nonce(&self, acc: &Address) -> u64 {
        let _lock = self.mtx.read().unwrap();
        *self.nonces.get(acc).unwrap_or(&0)
    }

    fn last_block(&self) -> &SigBlock {
        let _lock = self.mtx.read().unwrap();
        &self.last_block
    }

    fn apply_tx(&mut self, sig_tx: SigTx) -> Result<(), String> {
        let _lock = self.mtx.write().unwrap();
        let valid = verify_tx(sig_tx.to_owned());
        if !valid {
            Err(String::from("tx error: invalid transaction signature\n"))?
        }
        let tx = sig_tx.clone().tx;
        if tx.nonce != self.nonces.get(&tx.from).unwrap_or(&0) + 1 {
            Err(String::from("tx error: invalid transaction nonce\n"))?
        }
        if self.balances.get(&tx.from).unwrap_or(&0) < &tx.value {
            Err(String::from("tx error: insufficient account funds\n"))?
        }
        *self.balances.get_mut(&tx.from).unwrap() -= tx.value;
        *self.balances.get_mut(&tx.to).unwrap_or(&mut 0) += tx.value;
        *self.nonces.get_mut(&tx.from).unwrap_or(&mut 0) += 1;
        self.txs.insert(sig_tx.hash(), sig_tx);
        Ok(())
    }

    fn create_block(&mut self, authority: Account) -> Result<SigBlock, String> {
        // Sort transactions by time
        let mut sorted_txs = Vec::<SigTx>::new();
        for tx in self.pending.as_ref().unwrap().borrow_mut().txs.values() {
            sorted_txs.push(tx.clone());
        }
        sorted_txs.sort_by(|a, b| a.tx.time.cmp(&b.tx.time));

        let mut valid_txs = Vec::new();
        for tx in sorted_txs {
            if let Err(err) = self.apply_tx(tx.clone()) {
                println!("tx error: rejected: {}", err);
                continue;
            }
            valid_txs.push(tx);
        }

        if valid_txs.is_empty() {
            Err("empty list of valid pending transactions".to_string())?
        }

        let parent = if self.last_block.block.number == 0 {
            self.genesis_hash.clone()
        } else {
            self.last_block.hash()
        };

        let blk = Block::new(self.last_block.block.number + 1, parent, valid_txs.as_slice())?;
        Ok(authority.sign_block(blk))
    }

    fn apply_block(&mut self, sig_blk: SigBlock) -> Result<(), String> {
        let valid = verify_block(sig_blk.to_owned(), self.authority.clone())?;
        if !valid {
            Err(String::from("blk error: invalid block signature\n"))?
        }
        if sig_blk.block.number != self.last_block.block.number + 1 {
            Err(String::from("blk error: invalid block number\n"))?
        }
        let parent = if sig_blk.block.number == 1 {
            self.genesis_hash.clone()
        } else {
            self.last_block.hash()
        };
        if sig_blk.block.parent != parent {
            Err(String::from("blk error: invalid parent hash\n"))?
        }
        let merkle_tree = merkle_hash(sig_blk.block.txs.as_slice(), tx_hash, tx_pair_hash)?;
        let merkle_root = merkle_tree.as_slice()[0];
        if merkle_root != sig_blk.block.merkle_root {
            Err(String::from("blk error: invalid merkle root\n"))?
        }
        for sig_tx in sig_blk.clone().block.txs {
            self.apply_tx(sig_tx)?;
        }
        self.last_block = sig_blk;
        Ok(())
    }

    fn apply_block_to_state(&mut self, sig_blk: SigBlock) -> Result<(), String> {
        let mut state = self.clone();
        state.apply_block(sig_blk)?;
        self.apply(&state);
        Ok(())
    }

}

impl Clone for State {
    fn clone(&self) -> State {
        let _lock = self.mtx.read().unwrap();
        let pending = self.pending.as_ref().unwrap();
        assert!(!pending.borrow().txs.is_empty());
        let s = State {
            mtx: RwLock::new(()),
            authority: self.authority.clone(),
            balances: self.balances.clone(),
            nonces: self.nonces.clone(),
            last_block: self.last_block.clone(),
            genesis_hash: self.genesis_hash.clone(),
            txs: self.txs.clone(),
            pending: Some(Rc::new(RefCell::new(State {
                mtx: RwLock::new(()),
                authority: self.authority.clone(),
                balances: pending.borrow().balances.clone(),
                nonces: pending.borrow().nonces.clone(),
                last_block: pending.borrow().last_block.clone(),
                genesis_hash: self.genesis_hash.clone(),
                txs: pending.borrow().txs.clone(),
                pending: None,
            }))),
        };
        s
    }
}

// Implementing fmt::Display for pretty printing
impl Display for State {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        let _lock = self.mtx.read().unwrap();
        let mut output = String::from("* Balances and nonces\n");
        //let format = String::from("acc %-7.7s:                    %8d %8d\n");

        for (acc, &bal) in &self.balances {
            let nonce = self.nonces.get(acc).unwrap_or(&0);
            output.push_str(&format!("acc {}: {} {} \n", acc, bal, nonce));
        }

        output.push_str("* Last block\n");
        output.push_str(&format!("{:?}", self.last_block));

        if let Some(ref pending) = self.pending {
            if !pending.borrow().txs.is_empty() {
                output.push_str("* Pending txs\n");
                for tx in pending.borrow().txs.values() {
                    output.push_str(&format!("{:?}\n", tx));
                }
            }
            if !pending.borrow().balances.is_empty() {
                output.push_str("* Pending balances and nonces\n");
                for (acc, &bal) in &pending.borrow().balances {
                    output.push_str(&format!("acc {}: {} {} \n", acc, bal, pending.borrow().nonce(acc)));
                }
            }
        }

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::common::tests::{create_account, create_genesis, genesis_account, KEY_PASS, KEY_STORE_DIR};
    use crate::tx::Tx;
    use std::io::{Error, ErrorKind};

    struct TestCase {
        name: String,
        value: u64,
        nonce_inc: u64,
        error: Option<Error>
    }

    #[test]
    fn test_apply_tx() {
        let sig_gen = create_genesis();
        let state = State::new(sig_gen.clone());
        let pending = state.pending.as_ref().unwrap();
        let (owner_acc, owner_bal) = genesis_account(sig_gen);
        let acc = Account::read_account(&format!("{}/{}", KEY_STORE_DIR, owner_acc), KEY_PASS.as_bytes()).unwrap();
        let cases = vec![
            TestCase {name: String::from("valid tx 1"), value: 12, nonce_inc: 1, error: None},
            TestCase {name: String::from("invalid nonce error"), value: 99, nonce_inc: 0, error: Some(Error::new(ErrorKind::InvalidData, "invalid nonce"))},
            TestCase {name: String::from("valid tx 2"), value: 34, nonce_inc: 1, error: None},
        ];
        for case in cases {
            let tx = Tx::new(&acc.address(), &Address::from(String::from("to")), case.value, pending.borrow().nonce(acc.address()) + case.nonce_inc);
            let sig_tx = acc.sign_tx(&tx);
            let is_error = pending.borrow_mut().apply_tx(sig_tx).is_err();
            assert!((is_error && case.error.is_some()) || (!is_error && case.error.is_none()));
        }

        let (got, exist) = pending.borrow().balance(&acc.address());
        assert!(exist);
        let exp = owner_bal - 12 - 34;
        assert_eq!(got, exp);
        // insufficient funds error
        {
            let tx = Tx::new(&acc.address(), &Address::from(String::from("from")), 1000, pending.borrow().nonce(acc.address()) + 1);
            let sig_tx = acc.sign_tx(&tx);
            let err = pending.borrow_mut().apply_tx(sig_tx).err().unwrap();
            assert_eq!(err, "tx error: insufficient account funds\n");
        }
        // invalid signature error
        {
            let acc2 = create_account();
            let tx = Tx::new(&acc.address(), &Address::from(String::from("from")), 12, pending.borrow().nonce(acc.address()) + 1);
            let sig_tx = acc2.sign_tx(&tx);
            let err = pending.borrow_mut().apply_tx(sig_tx).err().unwrap();
            assert_eq!(err, "tx error: invalid transaction signature\n");
        }
    }

    #[test]
    fn test_apply_block() {
        let sig_gen = create_genesis();
        let mut state = State::new(sig_gen.clone());
        let (owner_acc, owner_bal) = genesis_account(sig_gen.clone());
        let acc = Account::read_account(&format!("{}/{}", KEY_STORE_DIR, owner_acc), KEY_PASS.as_bytes()).unwrap();
        let auth = Account::read_account(&format!("{}/{}", KEY_STORE_DIR, sig_gen.genesis.authority), KEY_PASS.as_bytes()).unwrap();
        // Create and apply several valid and invalid transactions to the pending state
        for value in [12, 1000, 34] {
            let tx = Tx::new(&acc.address(), &Address::from(String::from("to")), value, state.pending.as_ref().unwrap().borrow().nonce(acc.address()) + 1);
            let sig_tx = acc.sign_tx(&tx);
            // Apply the transaction to the pending state
            let err = state.pending.as_ref().unwrap().borrow_mut().apply_tx(sig_tx).err();
            if err.is_some() {
                print!("{}", err.unwrap());
            }
        }
        assert!(!state.pending.as_ref().unwrap().borrow().txs.is_empty());
        // Create a new block on the cloned state
        let mut clone = state.clone();
        assert_eq!(clone.pending.as_ref().unwrap().borrow().txs.len(), 2);
        let sig_blk = clone.create_block(auth).unwrap();
        // Apply the new block to the cloned state
        clone = state.clone();
        let err = clone.apply_block(sig_blk).is_err();
        assert!(!err);
        // Apply the cloned state with the new block updates to the confirmed state
        state.apply(&clone);
        let (got, exist) = state.balance(&acc.address());
        let exp = owner_bal - 12 - 34;
        assert!(exist);
        assert_eq!(got, exp);
    }
}