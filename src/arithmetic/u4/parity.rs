//! Batched parity projection for u4 limbs.
//!
//! [`u4_nibbles_to_parity`] is the numeric-range API: it checks only that each
//! input is numerically in `0..=15` and does not bind a byte-unique ScriptNum
//! encoding. [`u4_nibbles_to_parity_canonical`] is the canonical API: it also
//! rejects non-minimal aliases and negative zero, at one extra stack item per
//! query and a one-item-smaller maximum batch.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

/// Persistent items used by the nibble-parity lookup table.
pub const U4_PARITY_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
/// Two temporary stack items are needed by each range check.
pub const U4_PARITY_MAX_BATCH: u32 = 1_000 - U4_PARITY_TABLE_ITEMS - 2;

/// Largest canonical batch that fits the 1,000-item stack limit without
/// unrelated state. The canonical-encoding check needs three temporary items,
/// one more than the numeric range check.
pub const U4_PARITY_CANONICAL_MAX_BATCH: u32 = 1_000 - U4_PARITY_TABLE_ITEMS - 3;

fn parity(value: u32) -> u32 {
    (value.count_ones() & 1) as u32
}

fn push_parity_table() -> Script {
    script! {
        for value in (0..U4_PARITY_TABLE_ITEMS).rev() {
            { parity(value) }
        }
    }
}

/// Consume `nibble_count` range-checked nibbles and replace each with its parity.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with `nibble[n-1]`
/// on top. After: `preserved | parity[0] | ... | parity[n-1]`, with the last
/// output on top. Every input is checked to be in `0..=15` before it indexes
/// the table. The check is numeric only: under consensus numeric semantics a
/// non-minimal ScriptNum alias of an in-range value is accepted (only the
/// MINIMALDATA policy flag rejects it, in the interpreter). Use
/// [`u4_nibbles_to_parity_canonical`] when a byte-unique witness encoding is
/// required.
pub fn u4_nibbles_to_parity(nibble_count: u32) -> Script {
    u4_nibbles_to_parity_impl(nibble_count, false)
}

/// Consume `nibble_count` canonically encoded nibbles and replace each with
/// its parity.
///
/// Same stack contract as [`u4_nibbles_to_parity`], but each input must also be
/// the minimal ScriptNum encoding of a value in `0..=15`; non-minimal aliases
/// and negative zero are rejected. The standalone peak is `n + 19`, so the
/// generator accepts `1..=981` (compositions need
/// `n + 19 + unrelated_live_items <= 1000` across both stacks).
pub fn u4_nibbles_to_parity_canonical(nibble_count: u32) -> Script {
    u4_nibbles_to_parity_impl(nibble_count, true)
}

fn u4_nibbles_to_parity_impl(nibble_count: u32, canonical: bool) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    let max_batch = if canonical {
        U4_PARITY_CANONICAL_MAX_BATCH
    } else {
        U4_PARITY_MAX_BATCH
    };
    assert!(
        nibble_count <= max_batch,
        "nibble-parity batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_parity_table() }
        for _ in 0..nibble_count {
            { U4_PARITY_TABLE_ITEMS } OP_ROLL
            if canonical {
                { verify_canonical_nibble() }
            } else {
                OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            }
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_PARITY_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{
            execution::{execute_script, execute_script_with_inputs_strict, ExecuteInfo},
            script::{script, ScriptCompilation},
            tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
        },
    };
    use bitcoin_scriptexec::ExecError;

    #[test]
    fn projects_all_nibble_parities_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_parity(16) }
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "parity projection failed: {result}");
    }

    #[test]
    fn distinguishes_asymmetric_output_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("017") }
            { u4_nibbles_to_parity(3) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "parity ordering failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for position in 0..3 {
            let mut input = vec![1; 3];
            input[position] = if position % 2 == 0 { -1 } else { 16 };
            let result = execute_script(script! {
                for nibble in input { { nibble } }
                { u4_nibbles_to_parity(3) }
                OP_2DROP OP_DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble at {position}");
        }

        for position in 0..3 {
            let mut witness = vec![vec![1]; 3];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_nibbles_to_parity(3) }
                    OP_2DROP OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized nibble at {position}");
        }
    }

    #[test]
    fn rejects_zero_and_overlarge_batches() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_parity(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_parity(U4_PARITY_MAX_BATCH + 1) }).is_err()
        );
    }

    #[test]
    fn respects_combined_stack_frontier() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_parity(U4_PARITY_MAX_BATCH) }
                { u4_drop(U4_PARITY_MAX_BATCH) }
                OP_TRUE
            },
            vec![Vec::new(); U4_PARITY_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum parity batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let mut preserved_witness = vec![vec![7]];
        preserved_witness.extend(vec![Vec::new(); 980]);
        let preserved = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_parity(980) }
                { u4_drop(980) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved_witness,
        );
        assert!(preserved.success, "preserved state failed: {preserved}");

        let mut over_budget_witness = vec![vec![7]];
        over_budget_witness.extend(vec![Vec::new(); 981]);
        let over_budget = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_parity(981) }
            },
            over_budget_witness,
        );
        assert_eq!(over_budget.error, Some(ExecError::StackSize));
    }

    #[test]
    fn canonical_batch_boundary_is_one_item_smaller() {
        let witness = vec![vec![15]; U4_PARITY_CANONICAL_MAX_BATCH as usize];
        let result = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_parity_canonical(U4_PARITY_CANONICAL_MAX_BATCH) }
                for _ in 0..U4_PARITY_CANONICAL_MAX_BATCH { OP_DROP }
                OP_TRUE
            },
            witness,
        );
        assert!(result.success, "canonical max batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_parity_canonical(U4_PARITY_CANONICAL_MAX_BATCH + 1)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| { u4_nibbles_to_parity_canonical(0) }).is_err());

        let _ = u4_nibbles_to_parity(U4_PARITY_MAX_BATCH);
    }

    #[test]
    fn canonical_projection_matches_reference_values() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_parity_canonical(16) }
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(
            result.success,
            "canonical parity projection failed: {result}"
        );
    }

    /// Execute under the local consensus profile, which does not apply
    /// MINIMALDATA to numeric operands. Rejections of non-minimal aliases here
    /// therefore come from the fragment, not from the interpreter.
    fn execute_consensus(script: Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
        let result = execute_tapscript(
            script.compile_with_policy(),
            witness,
            TapscriptProfile::Consensus,
        );
        let TapscriptOutcome::Executed(execution) = result.outcome else {
            panic!("unexpected tapscript outcome: {result:?}");
        };
        execution
    }

    #[test]
    fn canonical_projection_rejects_malformed_nibbles() {
        let script = script! {
            { u4_nibbles_to_parity_canonical(4) }
            for _ in 0..4 { OP_DROP }
            OP_TRUE
        };
        let control = execute_consensus(script.clone(), vec![vec![1]; 4]);
        assert!(control.success, "canonical control failed: {control}");

        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed nibble at {position}: {result}"
                );
            }

            // Non-minimal aliases of in-range values (`0x0100` = 1,
            // `0x00` = 0, `0x0f00` = 15, `0x80` = negative zero) pass a
            // numeric range check under consensus numeric semantics; only the
            // canonical-encoding check rejects them.
            for replacement in [
                vec![1, 0],
                vec![0],
                vec![15, 0],
                vec![0x80],
                vec![0, 1],
                vec![0x81],
            ] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement.clone();
                let result = execute_consensus(script.clone(), witness);
                assert!(
                    !result.success,
                    "consensus profile accepted malformed nibble {replacement:02x?} at {position}: {result}"
                );
                assert_ne!(
                    result.error,
                    Some(ExecError::MinimalData),
                    "rejection must come from the fragment, not MINIMALDATA"
                );
            }
        }
    }

    #[test]
    fn canonical_projection_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_nibbles_to_parity_canonical(2) }
                OP_DROP OP_DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2]],
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn canonical_respects_combined_stack_frontier() {
        let mut preserved_witness = vec![vec![7]];
        preserved_witness.extend(vec![vec![15]; 979]);
        let preserved = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_parity_canonical(979) }
                { u4_drop(979) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved_witness,
        );
        assert!(
            preserved.success,
            "canonical preserved state failed: {preserved}"
        );
        assert_eq!(preserved.stats.max_nb_stack_items, 1000);

        let mut over_budget_witness = vec![vec![7]];
        over_budget_witness.extend(vec![vec![15]; 980]);
        let over_budget = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_parity_canonical(980) }
            },
            over_budget_witness,
        );
        assert_eq!(over_budget.error, Some(ExecError::StackSize));
    }

    #[test]
    fn range_api_accepts_numeric_alias_that_canonical_api_rejects() {
        // `[0x01, 0x00]` is a non-minimal ScriptNum encoding of 1.
        let alias_witness = vec![Vec::new(), vec![1, 0], vec![7]];
        let check_outputs = script! {
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        };
        let range_script = script! {
            { u4_nibbles_to_parity(3) }
            { check_outputs.clone() }
        };
        let canonical_script = script! {
            { u4_nibbles_to_parity_canonical(3) }
            { check_outputs }
        };

        // Consensus numeric semantics: the numeric-range API accepts the
        // alias and projects it like the minimal value; the canonical API
        // rejects it in its byte-equality check.
        let range_only = execute_consensus(range_script.clone(), alias_witness.clone());
        assert!(
            range_only.success,
            "numeric-range API is documented to accept aliases: {range_only}"
        );
        let canonical = execute_consensus(canonical_script.clone(), alias_witness.clone());
        assert!(!canonical.success, "canonical API accepted an alias");
        assert_eq!(canonical.error, Some(ExecError::EqualVerify));

        // The default research helper applies MINIMALDATA to numeric operands,
        // so there the interpreter, not the numeric-range fragment, rejects it.
        let range_minimal = execute_script_with_inputs_strict(range_script, alias_witness);
        assert_eq!(range_minimal.error, Some(ExecError::MinimalData));

        let minimal_witness = vec![Vec::new(), vec![1], vec![7]];
        let canonical_control = execute_consensus(canonical_script, minimal_witness);
        assert!(
            canonical_control.success,
            "canonical control failed: {canonical_control}"
        );
    }
}
