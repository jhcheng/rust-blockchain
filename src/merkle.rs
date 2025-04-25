use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Debug, Display};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Proof<H: Eq + PartialEq + Clone + Default + Display> {
    hash: H,
    direction: Direction,
}

fn new_proof<H: Eq + PartialEq + Clone + Default + Display>(
    hash: H,
    direction: Direction,
) -> Proof<H> {
    Proof { hash, direction }
}

pub fn merkle_hash<T, H: Eq + PartialEq + Clone + Default>(
    txs: &[T],
    type_hash: impl Fn(&T) -> H,
    pair_hash: impl Fn(H, H) -> H,
) -> Result<Vec<H>, String> {
    if txs.is_empty() {
        return Err("merkle hash: empty transaction list".to_string());
    }

    let htxs: Vec<H> = txs.iter().map(|tx| type_hash(tx)).collect();
    let l = 2_usize.pow((htxs.len() as f64).log(2.0).ceil() as u32 + 1) - 1;
    let mut merkle_tree = vec![Default::default(); l];
    let mut chd = l / 2;

    for (i, j) in (0..htxs.len()).zip(chd..l) {
        merkle_tree[j] = htxs[i].clone();
    }

    let mut l = chd * 2;
    let mut par = chd / 2;

    while chd > 0 {
        for (i, j) in (chd..l).step_by(2).zip(par..) {
            merkle_tree[j] = pair_hash(merkle_tree[i].clone(), merkle_tree[i + 1].clone());
        }
        chd /= 2;
        l = chd * 2;
        par = chd / 2;
    }

    Ok(merkle_tree)
}

pub fn merkle_prove<H: Eq + PartialEq + Clone + Default + Debug + Display>(
    txh: H,
    merkle_tree: &[H],
) -> Result<Vec<Proof<H>>, Box<dyn Error>> {
    if merkle_tree.is_empty() {
        return Err("merkle prove: empty merkle tree".into());
    }

    let start = merkle_tree.len() / 2;
    let mut i = merkle_tree[start..]
        .iter()
        .position(|h| *h == txh)
        .ok_or_else(|| format!("merkle prove: transaction {:?} not found", txh))?
        + start;

    if merkle_tree.len() == 1 {
        return Ok(vec![new_proof(merkle_tree[0].clone(), Direction::Left)]);
    }
    if merkle_tree.len() == 3 {
        return Ok(vec![
            new_proof(merkle_tree[1].clone(), Direction::Left),
            new_proof(merkle_tree[2].clone(), Direction::Right),
        ]);
    }

    let mut merkle_proof = Vec::new();
    let nil_hash: H = Default::default(); // Assuming H implements Default

    if i % 2 == 0 {
        merkle_proof.push(new_proof(merkle_tree[i - 1].clone(), Direction::Left));
        merkle_proof.push(new_proof(merkle_tree[i].clone(), Direction::Right));
        i -= 1;
    } else {
        merkle_proof.push(new_proof(merkle_tree[i].clone(), Direction::Left));
        let hash = &merkle_tree[i + 1];
        if *hash != nil_hash {
            merkle_proof.push(new_proof(hash.clone(), Direction::Right));
        }
        i += 1;
    }

    loop {
        if i % 2 == 0 {
            i = (i - 2) / 2;
        } else {
            i = (i - 1) / 2;
        }
        if i % 2 == 0 {
            i -= 1;
        } else {
            i += 1;
        }
        let hash = &merkle_tree[i];
        if *hash != nil_hash {
            if i % 2 == 0 {
                merkle_proof.push(new_proof(hash.clone(), Direction::Right));
            } else {
                merkle_proof.push(new_proof(hash.clone(), Direction::Left));
            }
        }
        if i == 2 || i == 1 {
            break;
        }
    }
    Ok(merkle_proof)
}

fn merkle_verify<H: PartialEq + Eq + Clone + Default + Debug + Display>(
    txh: H,
    merkle_proof: &[Proof<H>],
    merkle_root: H,
    pair_hash: fn(H, H) -> H,
) -> bool {
    let i = merkle_proof.iter().position(|proof| proof.hash == txh);

    if i.is_none() {
        return false;
    }

    let mut hash = merkle_proof[0].hash.clone();
    for proof in &merkle_proof[1..] {
        match proof.direction {
            Direction::Left => {
                hash = pair_hash(proof.hash.clone(), hash);
            }
            Direction::Right => {
                hash = pair_hash(hash, proof.hash.clone());
            }
        }
    }

    hash == merkle_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::new_hash;
    use crate::tx::tx_pair_hash;

    fn str_range(end: usize) -> Vec<String> {
        let mut slc = Vec::with_capacity(end);
        for i in 0..end {
            slc.push((i + 1).to_string());
        }
        slc
    }

    fn format_merkle_tree(merkle_tree: &[String]) -> String {
        let mt: Vec<String> = merkle_tree
            .iter()
            .map(|hash| hash.chars().take(4).collect())
            .collect();
        format!("{:?}", mt)
    }

    fn format_merkle_proof<H: Eq + PartialEq + Clone + Default + Display + Copy>(
        merkle_proof: &[Proof<H>],
    ) -> String {
        let mp: Vec<String> = merkle_proof
            .iter()
            .map(|proof| {
                let dir = match proof.direction {
                    Direction::Left => "L",
                    Direction::Right => "R",
                };
                format!("{}-{}", proof.hash.to_string().chars().take(4).collect::<String>(), dir)
            })
            .collect();
        format!("{:?}", mp)
    }

    #[test]
    fn test_merkle_hash_prove_verify() {
        for i in 0..9 {
            // Generate lists of transactions starting from ["1"] to ["1".."9"] inclusive
            let txs = str_range(i + 1);
            // Construct the Merkle tree for the generated list of transactions
            let merkle_tree = merkle_hash(&txs, new_hash, tx_pair_hash).unwrap();
            // Print the array representation of the constructed Merkle tree
            println!(
                "Tree ({}) {:?}",
                txs.len(),
                format_merkle_tree(
                    &merkle_tree
                        .clone()
                        .iter()
                        .map(|&h| h.to_string())
                        .collect::<Vec<String>>()
                        .as_ref()
                )
            );
            let merkle_root = merkle_tree[0];

            // Start iterating over the transactions from the generated transaction list
            for tx in &txs {
                let txh = new_hash(tx);
                // Derive the Merkle proof for the transaction hash from the constructed Merkle tree
                let merkle_proof = merkle_prove(txh, &merkle_tree).unwrap();
                // Print the derived Merkle proof
                println!(
                    "Proof {} {:.4} {:?}",
                    tx,
                    txh.to_string().chars().take(4).collect::<String>(),
                    format_merkle_proof(&merkle_proof)
                );
                // Verify the derived Merkle proof for the transaction hash and the constructed Merkle root
                let valid = merkle_verify(txh, &merkle_proof, merkle_root, tx_pair_hash);
                // Verify that the derived Merkle proof is correct
                if valid {
                    println!("valid");
                } else {
                    println!("INVALID");
                }
                if !valid {
                    panic!(
                        "invalid Merkle proof: {} {:.4} {:?}",
                        tx,
                        txh,
                        format_merkle_proof(&merkle_proof)
                    );
                }
            }
        }
    }

    fn format_merkle_tree_str(merkle_tree: &[String]) -> String {
        let mut mt: Vec<String> = merkle_tree.to_vec(); // Clone the input vector
        for i in 0..mt.len() {
            if mt[i].is_empty() {
                mt[i] = "_".to_string(); // Replace empty strings with "_"
            }
        }
        format!("{:?}", mt) // Format the vector as a string
    }

}
