//! Two-choice legacy FindAndDelete fixture for pinned Bitcoin Core.
//!
//! This deliberately uses raw consensus bytecode: the exact embedded signature
//! pushes are the object of the test and must not be optimized or rewritten.
//! Test keys are public. This is not the Binohash grinding protocol.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_SINGLE: u8 = 0x03;
const SIGHASH_SINGLE_ANYONECANPAY: u8 = 0x83;

fn p2sh(script: &[u8]) -> ScriptBuf {
    let digest = hash160::Hash::hash(script);
    ScriptBuf::from_bytes(
        [
            vec![0xa9, 0x14],
            digest.to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    )
}

fn input(txid: Txid, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn spend_script_sig(puzzle_signature: &[u8], choose_first: bool, redeem: &[u8]) -> ScriptBuf {
    // P2SH scriptSig: CHECKMULTISIG dummy, puzzle signature, selected branch,
    // redeemScript. The branch is a push-only OP_1 or OP_0.
    ScriptBuf::from_bytes(
        [
            vec![0x00],
            push_data(puzzle_signature),
            vec![if choose_first { 0x51 } else { 0x00 }],
            push_data(redeem),
        ]
        .concat(),
    )
}

fn transaction_record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "vsize": tx.vsize(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "input_script_sig_bytes": tx.input.iter().map(|input| input.script_sig.len()).collect::<Vec<_>>(),
    })
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let pool_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let puzzle_key = SecretKey::from_slice(&[2; 32]).unwrap();
    let pool_pubkey = PublicKey::from_secret_key(&secp, &pool_key).serialize();
    let puzzle_pubkey = PublicKey::from_secret_key(&secp, &puzzle_key).serialize();

    // Input index 1 with one output triggers legacy SIGHASH_SINGLE's fixed
    // digest. Two defined sighash flag bytes give distinct embedded pushes
    // while the same ECDSA signature and pool key remain valid.
    let mut bug_digest = [0_u8; 32];
    bug_digest[0] = 1;
    let pool_der = secp
        .sign_ecdsa(&Message::from_digest(bug_digest), &pool_key)
        .serialize_der();
    let mut pool_a = pool_der.to_vec();
    pool_a.push(SIGHASH_SINGLE);
    let mut pool_b = pool_der.to_vec();
    pool_b.push(SIGHASH_SINGLE_ANYONECANPAY);

    // OP_IF <pool_a> OP_ELSE <pool_b> OP_ENDIF OP_2 <puzzle_key>
    // <pool_key> OP_2 OP_CHECKMULTISIG. Both embedded pushes remain in
    // scriptCode; FindAndDelete removes only the chosen pool signature.
    let redeem = ScriptBuf::from_bytes(
        [
            vec![0x63],
            push_data(&pool_a),
            vec![0x67],
            push_data(&pool_b),
            vec![0x68, 0x52],
            push_data(&puzzle_pubkey),
            push_data(&pool_pubkey),
            vec![0x52, 0xae],
        ]
        .concat(),
    );
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let candidates = [
        ("first", true, 0_u32, 1_u32, 0_usize),
        ("second", false, 2_u32, 3_u32, 1_usize),
    ];
    let rows: Vec<Value> = candidates
        .iter()
        .map(|(name, choose_first, easy_vout, bino_vout, selected_index)| {
            let mut tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![
                    input(funding_txid, *easy_vout),
                    input(funding_txid, *bino_vout),
                ],
                output: vec![TxOut {
                    value: Amount::from_sat(2 * INPUT_VALUE - FEE),
                    script_pubkey: destination.clone(),
                }],
            };
            tx.input[0].script_sig = ScriptBuf::from_bytes(push_data(easy_redeem.as_bytes()));
            let digest = binohash_digest(
                &tx,
                1,
                &redeem,
                &[pool_a.clone(), pool_b.clone()],
                &[*selected_index],
                u32::from(SIGHASH_ALL),
            )
            .unwrap();
            let pool_hash_type = if *choose_first {
                SIGHASH_SINGLE
            } else {
                SIGHASH_SINGLE_ANYONECANPAY
            };
            let pool_digest = binohash_digest(
                &tx,
                1,
                &redeem,
                &[pool_a.clone(), pool_b.clone()],
                &[*selected_index],
                u32::from(pool_hash_type),
            )
            .unwrap();
            assert_eq!(pool_digest, bug_digest);
            let mut puzzle_signature = secp
                .sign_ecdsa(&Message::from_digest(digest), &puzzle_key)
                .serialize_der()
                .to_vec();
            puzzle_signature.push(SIGHASH_ALL);
            tx.input[1].script_sig =
                spend_script_sig(&puzzle_signature, *choose_first, redeem.as_bytes());
            let valid = transaction_record(&tx);

            let mut wrong_selection = tx.clone();
            wrong_selection.input[1].script_sig =
                spend_script_sig(&puzzle_signature, !choose_first, redeem.as_bytes());
            json!({
                "name": name,
                "selected_index": selected_index,
                "selected_pool_signature_hex": if *choose_first { &pool_a } else { &pool_b }.to_lower_hex_string(),
                "local_digest_hex": digest.to_lower_hex_string(),
                "puzzle_signature_hex": puzzle_signature.to_lower_hex_string(),
                "valid": valid,
                "wrong_selection": transaction_record(&wrong_selection),
            })
        })
        .collect();
    assert_ne!(rows[0]["local_digest_hex"], rows[1]["local_digest_hex"]);
    assert!(redeem.len() <= 520);
    json!({
        "experiment": "binohash-legacy-two-choice-core",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "binohash_script_pubkey_hex": p2sh(redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "easy_script_pubkey_hex": p2sh(easy_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "pool_signature_a_hex": pool_a.to_lower_hex_string(),
        "pool_signature_b_hex": pool_b.to_lower_hex_string(),
        "results": rows,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_core_fixtures FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_pool_signatures_change_the_signed_legacy_digest() {
        let txid = Txid::from_str(&"00".repeat(32)).unwrap();
        let fixture = generate(txid, ScriptBuf::from_bytes(vec![0x51]));
        assert_eq!(fixture["results"].as_array().unwrap().len(), 2);
        assert_ne!(
            fixture["results"][0]["local_digest_hex"],
            fixture["results"][1]["local_digest_hex"]
        );
        assert!(fixture["redeem_script_bytes"].as_u64().unwrap() <= 520);
    }
}
