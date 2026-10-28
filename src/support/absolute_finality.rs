//! Host-side absolute transaction-finality preflight for a candidate block.
//!
//! Mirrors Bitcoin Core v30.3 `IsFinalTx` with BIP113's parent-block median
//! time past as the time argument. This checks only `nLockTime` and final input
//! sequences. It does not establish UTXO existence, BIP68 maturity, script
//! validity, or relay-policy acceptance. Chain facts must come from the same
//! candidate chain; missing facts yield `Unsupported`, not a rejection.

use bitcoin::Transaction;

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const FINAL_SEQUENCE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateBlockContext {
    pub height: Option<u32>,
    /// Median time past of the candidate block's parent (BIP113).
    pub parent_mtp: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteFinalityUnsupportedReason {
    NoInputs,
    MissingCandidateHeight,
    InvalidCandidateHeight,
    MissingCandidateParentMtp,
    InvalidCandidateParentMtp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsoluteFinalityVerdict {
    Final,
    NonFinal { lock_time: u32 },
    Unsupported(AbsoluteFinalityUnsupportedReason),
}

/// Evaluate absolute `nLockTime` at the candidate block boundary.
///
/// Core considers a transaction final when its lock time is zero, strictly
/// below the relevant candidate height/MTP, or every input sequence is final.
/// The all-final-sequence escape requires no chain facts. The verdict is only
/// an absolute-finality preflight, never a complete transaction verdict.
pub fn evaluate_absolute_finality(
    tx: &Transaction,
    candidate: &CandidateBlockContext,
) -> AbsoluteFinalityVerdict {
    use AbsoluteFinalityUnsupportedReason as Unsupported;

    if tx.input.is_empty() {
        return AbsoluteFinalityVerdict::Unsupported(Unsupported::NoInputs);
    }
    let lock_time = tx.lock_time.to_consensus_u32();
    if lock_time == 0
        || tx
            .input
            .iter()
            .all(|input| input.sequence.0 == FINAL_SEQUENCE)
    {
        return AbsoluteFinalityVerdict::Final;
    }

    let comparison = if lock_time < LOCKTIME_THRESHOLD {
        let Some(height) = candidate.height else {
            return AbsoluteFinalityVerdict::Unsupported(Unsupported::MissingCandidateHeight);
        };
        if height == 0 {
            return AbsoluteFinalityVerdict::Unsupported(Unsupported::InvalidCandidateHeight);
        }
        height as i64
    } else {
        let Some(parent_mtp) = candidate.parent_mtp else {
            return AbsoluteFinalityVerdict::Unsupported(Unsupported::MissingCandidateParentMtp);
        };
        if !(0..=u32::MAX as i64).contains(&parent_mtp) {
            return AbsoluteFinalityVerdict::Unsupported(Unsupported::InvalidCandidateParentMtp);
        }
        parent_mtp
    };

    if (lock_time as i64) < comparison {
        AbsoluteFinalityVerdict::Final
    } else {
        AbsoluteFinalityVerdict::NonFinal { lock_time }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction, OutPoint, ScriptBuf, Sequence, TxIn, Witness};

    fn transaction_with(lock_time: u32, sequences: &[u32]) -> Transaction {
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::from_consensus(lock_time),
            input: sequences
                .iter()
                .map(|sequence| TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(*sequence),
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![],
        }
    }

    fn context(height: Option<u32>, parent_mtp: Option<i64>) -> CandidateBlockContext {
        CandidateBlockContext { height, parent_mtp }
    }

    #[test]
    fn height_lock_is_strict_and_ignores_time() {
        let tx = transaction_with(104, &[0]);
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(Some(104), None)),
            AbsoluteFinalityVerdict::NonFinal { lock_time: 104 }
        );
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(Some(105), None)),
            AbsoluteFinalityVerdict::Final
        );
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(None, Some(2_000_000_000))),
            AbsoluteFinalityVerdict::Unsupported(
                AbsoluteFinalityUnsupportedReason::MissingCandidateHeight
            )
        );
    }

    #[test]
    fn time_lock_uses_parent_mtp_and_threshold() {
        let just_below_threshold = transaction_with(499_999_999, &[0]);
        assert_eq!(
            evaluate_absolute_finality(&just_below_threshold, &context(Some(500_000_000), None)),
            AbsoluteFinalityVerdict::Final
        );
        let tx = transaction_with(500_000_000, &[0]);
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(Some(1_000_000), Some(500_000_000))),
            AbsoluteFinalityVerdict::NonFinal {
                lock_time: 500_000_000
            }
        );
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(None, Some(500_000_001))),
            AbsoluteFinalityVerdict::Final
        );
        assert_eq!(
            evaluate_absolute_finality(&tx, &context(Some(1_000_000), None)),
            AbsoluteFinalityVerdict::Unsupported(
                AbsoluteFinalityUnsupportedReason::MissingCandidateParentMtp
            )
        );
    }

    #[test]
    fn zero_and_all_final_sequences_bypass_lock_time() {
        assert_eq!(
            evaluate_absolute_finality(&transaction_with(0, &[0]), &context(None, None)),
            AbsoluteFinalityVerdict::Final
        );
        assert_eq!(
            evaluate_absolute_finality(
                &transaction_with(u32::MAX, &[u32::MAX, u32::MAX]),
                &context(None, None)
            ),
            AbsoluteFinalityVerdict::Final
        );
        assert_eq!(
            evaluate_absolute_finality(
                &transaction_with(u32::MAX, &[u32::MAX, u32::MAX - 1]),
                &context(None, None)
            ),
            AbsoluteFinalityVerdict::Unsupported(
                AbsoluteFinalityUnsupportedReason::MissingCandidateParentMtp
            )
        );
    }

    #[test]
    fn invalid_or_missing_context_is_not_a_nonfinal_verdict() {
        let height_tx = transaction_with(1, &[0]);
        assert_eq!(
            evaluate_absolute_finality(&height_tx, &context(Some(0), None)),
            AbsoluteFinalityVerdict::Unsupported(
                AbsoluteFinalityUnsupportedReason::InvalidCandidateHeight
            )
        );
        let time_tx = transaction_with(500_000_000, &[0]);
        for mtp in [-1, u32::MAX as i64 + 1] {
            assert_eq!(
                evaluate_absolute_finality(&time_tx, &context(None, Some(mtp))),
                AbsoluteFinalityVerdict::Unsupported(
                    AbsoluteFinalityUnsupportedReason::InvalidCandidateParentMtp
                )
            );
        }
        assert_eq!(
            evaluate_absolute_finality(&transaction_with(0, &[]), &context(None, None)),
            AbsoluteFinalityVerdict::Unsupported(AbsoluteFinalityUnsupportedReason::NoInputs)
        );
    }
}
