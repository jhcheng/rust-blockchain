
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