//! Embedded-threshold masks for checked u4 limbs.

use crate::support::script::*;

/// Largest standalone batch; callers must satisfy `batch + 2 + preserved <= 1000`.
pub const U4_LT_MASK_MAX_BATCH: u32 = 1_000 - 2;

/// Replace each checked u4 nibble with whether it is below an embedded threshold.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | mask[0] | ... | mask[n-1]`, with the last mask
/// on top. The threshold is public generation-time data and must be a u4.
pub fn u4_nibbles_to_lt_mask(threshold: u8, nibble_count: u32) -> Script {
    assert!(threshold < 16, "threshold must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_LT_MASK_MAX_BATCH,
        "nibble threshold-mask batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            { threshold } OP_LESSTHAN OP_TOALTSTACK
        }
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
            execution::{
                execute_raw_script_with_inputs_strict, execute_script,
                execute_script_with_inputs_strict,
            },
            script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
        },
    };
    use bitcoin_scriptexec::ExecError;

    fn compile_boundary(body: Script) -> Vec<u8> {
        script! {
            { body }
            for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
        }
        .compile_with_policy()
        .to_bytes()
    }

    #[test]
    fn projects_all_threshold_boundaries_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lt_mask(5, 16) }
            for _ in 0..11 { 0 OP_EQUALVERIFY }
            for _ in 0..5 { 1 OP_EQUALVERIFY }
            OP_TRUE
        });
        assert!(result.success, "threshold mask failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lt_mask(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lt_mask(5, 0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_lt_mask(5, U4_LT_MASK_MAX_BATCH + 1)
        })
        .is_err());

        let checked_script = script! {
            { u4_nibbles_to_lt_mask(5, 3) }
            for _ in 0..3 { OP_DROP }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for invalid in [vec![0x81], vec![0x10]] {
            for invalid_index in 0..3 {
                let mut witness = vec![vec![1u8]; 3];
                witness[invalid_index] = invalid.clone();
                let result = execute_raw_script_with_inputs_strict(checked_script.clone(), witness);
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "accepted invalid nibble at position {invalid_index}: {result}"
                );
            }
        }

        let result = execute_raw_script_with_inputs_strict(
            compile_boundary(u4_nibbles_to_lt_mask(5, U4_LT_MASK_MAX_BATCH)),
            vec![Vec::new(); U4_LT_MASK_MAX_BATCH as usize],
        );
        assert!(
            result.error.is_none(),
            "998-item threshold mask failed: {result}"
        );
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    fn handles_threshold_endpoints() {
        for (threshold, input, expected) in [(0, 0, 0), (15, 14, 1), (15, 15, 0)] {
            let result = execute_script(script! {
                { input }
                { u4_nibbles_to_lt_mask(threshold, 1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "threshold endpoint failed: threshold={threshold}, input={input}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4 5 15
            { u4_nibbles_to_lt_mask(5, 3) }
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "threshold mask changed surrounding state: {result}"
        );
    }

    #[test]
    fn composes_with_preserved_state_at_the_stack_boundary() {
        let main_script = compile_boundary(u4_nibbles_to_lt_mask(5, 997));
        let main_result = execute_raw_script_with_inputs_strict(
            main_script,
            std::iter::once(vec![99u8])
                .chain(std::iter::repeat_n(Vec::new(), 997))
                .collect(),
        );
        assert!(
            main_result.error.is_none(),
            "997-item main state failed: {main_result}"
        );
        assert_eq!(main_result.final_stack.get(0), vec![99]);

        let alt_script = compile_boundary(script! {
            77 OP_TOALTSTACK
            { u4_nibbles_to_lt_mask(5, 997) }
            OP_FROMALTSTACK
        });
        let alt_result = execute_raw_script_with_inputs_strict(
            alt_script,
            std::iter::repeat_n(Vec::new(), 997).collect(),
        );
        assert!(
            alt_result.error.is_none(),
            "997-item alt state failed: {alt_result}"
        );
        assert_eq!(alt_result.final_stack.get(997), vec![77]);

        let failure_script = compile_boundary(u4_nibbles_to_lt_mask(5, U4_LT_MASK_MAX_BATCH));
        let failure = execute_raw_script_with_inputs_strict(
            failure_script,
            std::iter::once(vec![99u8])
                .chain(std::iter::repeat_n(
                    Vec::new(),
                    U4_LT_MASK_MAX_BATCH as usize,
                ))
                .collect(),
        );
        assert_eq!(failure.error, Some(ExecError::StackSize));
    }

    fn scriptnum_nibble(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    #[test]
    fn asymmetric_boundary_vectors_keep_positions_for_every_threshold() {
        for threshold in 0u8..16 {
            // Bottom-to-top inputs: threshold-1, threshold, threshold+1, 0, 15.
            let mut inputs = Vec::new();
            if threshold > 0 {
                inputs.push(threshold - 1);
            }
            inputs.push(threshold);
            if threshold < 15 {
                inputs.push(threshold + 1);
            }
            inputs.extend([0, 15]);
            let masks: Vec<Vec<u8>> = inputs
                .iter()
                .map(|&value| scriptnum_nibble(u8::from(value < threshold)))
                .collect();
            if threshold > 0 {
                let reversed: Vec<Vec<u8>> = masks.iter().rev().cloned().collect();
                assert_ne!(masks, reversed, "threshold {threshold} vector is symmetric");
            }

            let nibble_count = inputs.len() as u32;
            let result = execute_script_with_inputs_strict(
                script! {
                    77 OP_TOALTSTACK
                    { u4_nibbles_to_lt_mask(threshold, nibble_count) }
                    OP_FROMALTSTACK
                },
                std::iter::once(vec![99u8])
                    .chain(inputs.iter().map(|&value| scriptnum_nibble(value)))
                    .collect(),
            );
            assert!(result.error.is_none(), "threshold {threshold}: {result}");

            let expected: Vec<Vec<u8>> = std::iter::once(vec![99u8])
                .chain(masks)
                .chain(std::iter::once(vec![77u8]))
                .collect();
            let actual: Vec<Vec<u8>> = (0..result.final_stack.len())
                .map(|index| result.final_stack.get(index))
                .collect();
            assert_eq!(
                actual, expected,
                "threshold {threshold}, inputs {inputs:?}: bottom-to-top stack mismatch"
            );
        }
    }

    #[test]
    fn exact_stack_frontier_admits_max_preserved_and_rejects_one_more() {
        for nibble_count in [1, 16, 500, U4_LT_MASK_MAX_BATCH] {
            let max_preserved = (U4_LT_MASK_MAX_BATCH - nibble_count) as usize;
            for alt_items in [0usize, 1] {
                let script = compile_boundary(script! {
                    for _ in 0..alt_items { 77 OP_TOALTSTACK }
                    { u4_nibbles_to_lt_mask(5, nibble_count) }
                    for _ in 0..alt_items { OP_FROMALTSTACK }
                });
                for (preserved, fits) in [(max_preserved, true), (max_preserved + 1, false)] {
                    let Some(main_items) = preserved.checked_sub(alt_items) else {
                        continue;
                    };
                    let witness = std::iter::repeat_n(vec![99u8], main_items)
                        .chain(std::iter::repeat_n(vec![4u8], nibble_count as usize))
                        .collect();
                    let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
                    let case = format!(
                        "batch {nibble_count}, main {main_items}, alt {alt_items}, preserved {preserved}"
                    );
                    if fits {
                        assert!(result.error.is_none(), "{case} failed: {result}");
                        assert_eq!(result.stats.max_nb_stack_items, 1_000, "{case}");
                        assert_eq!(
                            result.final_stack.len(),
                            preserved + nibble_count as usize,
                            "{case}"
                        );
                    } else {
                        assert_eq!(result.error, Some(ExecError::StackSize), "{case}");
                    }
                }
            }
        }
    }
}
