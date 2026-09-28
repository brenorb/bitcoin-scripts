//! Batched least-significant-bit projection for range-checked u4 limbs.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

/// Persistent items used by the nibble-LSB lookup table.
pub const U4_LSB_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_LSB_MAX_BATCH: u32 = 1_000 - U4_LSB_TABLE_ITEMS - 2;

/// Largest canonical batch that fits after each input's raw-encoding check.
pub const U4_LSB_CANONICAL_MAX_BATCH: u32 = 1_000 - U4_LSB_TABLE_ITEMS - 3;

fn push_lsb_table() -> Script {
    script! {
        for value in (0..U4_LSB_TABLE_ITEMS).rev() {
            { value & 1 }
        }
    }
}

/// Consume range-checked nibbles and replace each with its least-significant bit.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | lsb[0] | ... | lsb[n-1]`, with the last output
/// on top. Every input is range-checked before it indexes the table.
pub fn u4_nibbles_to_lsb(nibble_count: u32) -> Script {
    u4_nibbles_to_lsb_impl(nibble_count, false)
}

/// Consume minimally encoded nibbles and replace each with its least-significant bit.
///
/// Same stack contract as [`u4_nibbles_to_lsb`], but each input must also be
/// the canonical (minimal) ScriptNum encoding of a value in `0..=15`; redundant
/// sign bytes and negative zero are rejected. The canonicality check costs one
/// extra combined-stack item per query, so the batch is limited to
/// `1..=U4_LSB_CANONICAL_MAX_BATCH` (981).
pub fn u4_nibbles_to_lsb_canonical(nibble_count: u32) -> Script {
    u4_nibbles_to_lsb_impl(nibble_count, true)
}

fn u4_nibbles_to_lsb_impl(nibble_count: u32, canonical: bool) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    let max_batch = if canonical {
        U4_LSB_CANONICAL_MAX_BATCH
    } else {
        U4_LSB_MAX_BATCH
    };
    assert!(
        nibble_count <= max_batch,
        "nibble-LSB batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_lsb_table() }
        for _ in 0..nibble_count {
            { U4_LSB_TABLE_ITEMS } OP_ROLL
            if canonical {
                { verify_canonical_nibble() }
            } else {
                OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            }
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_LSB_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::{u4_drop, u4_hex_to_nibbles},
        support::{
            execution::{
                execute_script, execute_script_with_inputs, execute_script_with_inputs_strict,
                ExecuteInfo,
            },
            script::{script, ScriptCompilation},
            tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
        },
    };
    use bitcoin_scriptexec::ExecError;

    fn assert_validation_error(actual: Option<ExecError>, expected: ExecError, case: &str) {
        assert_eq!(actual, Some(expected), "{case}");
    }

    #[test]
    fn projects_all_nibble_least_significant_bits_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lsb(16) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "LSB projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_each_position() {
        let valid_cleanup_control = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb(3) }
                OP_2DROP OP_DROP OP_TRUE
            },
            vec![vec![1]; 3],
        );
        assert!(
            valid_cleanup_control.success,
            "valid witness failed the shared cleanup harness: {valid_cleanup_control}"
        );

        for position in 0..3 {
            for (encoded, expected) in [
                (vec![0x81], ExecError::Verify),
                (vec![0x10], ExecError::Verify),
                (vec![0, 0, 0, 0, 1], ExecError::ScriptIntNumericOverflow),
            ] {
                let mut witness = vec![vec![1]; 3];
                witness[position] = encoded;
                let result = execute_script_with_inputs_strict(
                    script! {
                        { u4_nibbles_to_lsb(3) }
                        OP_2DROP OP_DROP OP_TRUE
                    },
                    witness,
                );
                assert_validation_error(
                    result.error,
                    expected,
                    &format!("unexpected error for malformed nibble at position {position}"),
                );
            }
        }

        // The same exact-error assertion must reject a test-only fragment with
        // the production range checks removed. OP_PICK(16) then reads the
        // preserved sentinel below the table and the terminal predicate fails
        // with EqualVerify instead of the expected Verify.
        let lookup_bypass = execute_script_with_inputs_strict(
            script! {
                { push_lsb_table() }
                16 OP_ROLL
                OP_PICK OP_TOALTSTACK
                { u4_drop(U4_LSB_TABLE_ITEMS) }
                OP_FROMALTSTACK
                0 OP_EQUALVERIFY
                7 OP_EQUAL
            },
            vec![vec![7], vec![16]],
        );
        assert_eq!(lookup_bypass.error, Some(ExecError::EqualVerify));
        let bypass_assertion = std::panic::catch_unwind(|| {
            assert_validation_error(
                lookup_bypass.error,
                ExecError::Verify,
                "test-only LSB range-check bypass was not detected",
            )
        });
        assert!(
            bypass_assertion.is_err(),
            "test assertion accepted a bypass"
        );

        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lsb(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lsb(U4_LSB_MAX_BATCH + 1)).is_err());
    }

    #[test]
    fn respects_stack_frontier_and_preserves_state() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb(U4_LSB_MAX_BATCH) }
                { u4_drop(U4_LSB_MAX_BATCH) }
                OP_TRUE
            },
            vec![Vec::new(); U4_LSB_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum LSB batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let mut preserved = vec![vec![7]];
        preserved.extend(vec![Vec::new(); 980]);
        let with_state = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_lsb(980) }
                { u4_drop(980) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved,
        );
        assert!(with_state.success, "preserved state failed: {with_state}");

        let mut over_budget = vec![vec![7]];
        over_budget.extend(vec![Vec::new(); U4_LSB_MAX_BATCH as usize]);
        let rejected = execute_script_with_inputs_strict(
            script! { OP_9 OP_TOALTSTACK { u4_nibbles_to_lsb(U4_LSB_MAX_BATCH) } },
            over_budget,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    fn canonical_batch_boundary_is_one_item_smaller() {
        let canonical_witness = vec![vec![15]; U4_LSB_CANONICAL_MAX_BATCH as usize];
        let canonical = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb_canonical(U4_LSB_CANONICAL_MAX_BATCH) }
                for _ in 0..U4_LSB_CANONICAL_MAX_BATCH { OP_DROP }
                OP_TRUE
            },
            canonical_witness,
        );
        assert!(canonical.success, "canonical max batch failed: {canonical}");
        assert_eq!(canonical.stats.max_nb_stack_items, 1_000);

        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_lsb_canonical(U4_LSB_CANONICAL_MAX_BATCH + 1)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| { u4_nibbles_to_lsb_canonical(0) }).is_err());

        // The ordinary wrapper retains the one-item-larger generation bound;
        // its existing metric fixture covers the normal 32-item execution.
        let _ = u4_nibbles_to_lsb(U4_LSB_MAX_BATCH);
    }

    #[test]
    fn canonical_projection_matches_reference_values() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lsb_canonical(16) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "canonical LSB projection failed: {result}");
    }

    #[test]
    fn canonical_projection_rejects_malformed_nibbles() {
        // The consensus tapscript profile decodes non-minimal ScriptNums, so raw
        // aliases reach the canonicality check. The default helper enforces
        // minimal numbers and would reject them with MinimalData before it.
        fn run_consensus(fragment: Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
            let script = script! {
                { fragment }
                for _ in 0..4 { OP_DROP }
                OP_TRUE
            }
            .compile_with_policy();
            match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
                TapscriptOutcome::Executed(result) => result,
                outcome => panic!("expected local consensus-profile execution: {outcome:?}"),
            }
        }

        let control = run_consensus(u4_nibbles_to_lsb_canonical(4), vec![vec![1]; 4]);
        assert!(control.success, "canonical valid control failed: {control}");

        for position in 0..4 {
            for (replacement, range_only_accepts, expected) in [
                // Redundant zero byte aliasing 1.
                (vec![1, 0], true, ExecError::EqualVerify),
                // Negative zero aliasing 0.
                (vec![0x80], true, ExecError::EqualVerify),
                // Minimal 256 is out of range for both APIs.
                (vec![0, 1], false, ExecError::Verify),
            ] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement.clone();

                let range_only = run_consensus(u4_nibbles_to_lsb(4), witness.clone());
                assert_eq!(
                    range_only.success, range_only_accepts,
                    "range-only control for {replacement:?} at {position}: {range_only}"
                );

                let canonical = run_consensus(u4_nibbles_to_lsb_canonical(4), witness.clone());
                assert_validation_error(
                    canonical.error,
                    expected,
                    &format!("canonical API mishandled {replacement:?} at {position}"),
                );

                let minimal_helper = execute_script_with_inputs(
                    script! {
                        { u4_nibbles_to_lsb_canonical(4) }
                        for _ in 0..4 { OP_DROP }
                        OP_TRUE
                    },
                    witness,
                );
                assert!(
                    !minimal_helper.success,
                    "accepted malformed nibble at {position}: {minimal_helper}"
                );
            }
        }
    }

    #[test]
    fn canonical_projection_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_nibbles_to_lsb_canonical(2) }
                OP_DROP OP_DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2]],
        );
        assert!(result.success, "{result}");
    }
}
