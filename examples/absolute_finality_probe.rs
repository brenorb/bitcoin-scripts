//! JSON-stdin adapter for the host-side absolute-finality preflight.
//!
//! The result is only an `nLockTime` check. It does not validate the whole
//! transaction. Missing required candidate-chain context is `unsupported`.

use bitcoin::{consensus::encode::deserialize_hex, Transaction};
use bitcoin_lab::support::absolute_finality::{
    evaluate_absolute_finality, AbsoluteFinalityVerdict, CandidateBlockContext,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

#[derive(Deserialize)]
struct Request {
    tx_hex: Option<String>,
    candidate_height: Option<u32>,
    candidate_parent_mtp: Option<i64>,
}

fn unsupported(reason: &str) -> Value {
    json!({"verdict": "unsupported", "reason": reason})
}

fn evaluate(request: Request) -> Value {
    let Some(hex) = request.tx_hex else {
        return unsupported("missing_tx_hex");
    };
    let tx: Transaction = match deserialize_hex(&hex) {
        Ok(tx) => tx,
        Err(_) => return unsupported("invalid_tx_hex"),
    };
    let mut output = json!({
        "txid": tx.compute_txid().to_string(),
        "lock_time": tx.lock_time.to_consensus_u32(),
        "input_sequences": tx.input.iter().map(|input| input.sequence.0).collect::<Vec<_>>(),
    });
    let context = CandidateBlockContext {
        height: request.candidate_height,
        parent_mtp: request.candidate_parent_mtp,
    };
    match evaluate_absolute_finality(&tx, &context) {
        AbsoluteFinalityVerdict::Final => output["verdict"] = json!("final"),
        AbsoluteFinalityVerdict::NonFinal { .. } => output["verdict"] = json!("nonfinal"),
        AbsoluteFinalityVerdict::Unsupported(reason) => {
            output["verdict"] = json!("unsupported");
            output["reason"] = json!(format!("{reason:?}"));
        }
    }
    output
}

fn main() {
    let mut input = String::new();
    let result = match io::stdin().read_to_string(&mut input) {
        Ok(_) => match serde_json::from_str::<Request>(&input) {
            Ok(request) => evaluate(request),
            Err(_) => unsupported("invalid_request_json"),
        },
        Err(_) => unsupported("stdin_read_failed"),
    };
    println!("{result}");
}
