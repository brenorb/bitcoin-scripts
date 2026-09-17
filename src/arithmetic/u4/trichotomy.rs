//! Embedded-threshold three-way classifiers for checked u4 limbs.

use crate::support::script::*;

/// Largest standalone batch; callers must satisfy `batch + 2 + preserved <= 1000`.
pub const U4_TRICHOTOMY_MAX_BATCH: u32 = 1_000 - 2;

/// Classify each checked u4 nibble relative to an embedded threshold.
///
/// The result encoding is `0` for less-than, `1` for equal, and `2` for
/// greater-than. Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the
/// last nibble on top. After: `preserved | class[0] | ... | class[n-1]`, with
/// the last class on top.
pub fn u4_nibbles_to_trichotomy(threshold: u8, nibble_count: u32) -> Script {
    assert!(threshold < 16, "threshold must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_TRICHOTOMY_MAX_BATCH,
        "nibble trichotomy batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DUP { threshold } OP_LESSTHAN
            OP_IF
                OP_DROP 0
            OP_ELSE
                { threshold } OP_GREATERTHAN
                OP_IF
                    2
                OP_ELSE
                    1
                OP_ENDIF
            OP_ENDIF
            OP_TOALTSTACK
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
                execute_script_buf_with_options,
            },
            script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
        },
    };
    use bitcoin_scriptexec::{ExecError, Options};

    fn compile_boundary(body: Script) -> Vec<u8> {
        script! {
            { body }
            for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
        }
        .compile_with_policy()
        .to_bytes()
    }

    #[test]
    fn classifies_all_three_relations_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_trichotomy(5, 16) }
            for _ in 0..10 { 2 OP_EQUALVERIFY }
            1 OP_EQUALVERIFY
            for _ in 0..5 { 0 OP_EQUALVERIFY }
            OP_TRUE
        });
        assert!(result.success, "trichotomy classification failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_trichotomy(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_trichotomy(5, 0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_trichotomy(5, U4_TRICHOTOMY_MAX_BATCH + 1)
        })
        .is_err());

        let checked_script = script! {
            { u4_nibbles_to_trichotomy(5, 3) }
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
            compile_boundary(u4_nibbles_to_trichotomy(5, U4_TRICHOTOMY_MAX_BATCH)),
            vec![Vec::new(); U4_TRICHOTOMY_MAX_BATCH as usize],
        );
        assert!(
            result.error.is_none(),
            "998-item trichotomy failed: {result}"
        );
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    fn handles_threshold_endpoints() {
        for (threshold, input, expected) in [(0, 0, 1), (0, 1, 2), (15, 14, 0), (15, 15, 1)] {
            let result = execute_script(script! {
                { input }
                { u4_nibbles_to_trichotomy(threshold, 1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "trichotomy endpoint failed: threshold={threshold}, input={input}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4 5 5
            { u4_nibbles_to_trichotomy(5, 3) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "trichotomy changed surrounding state: {result}"
        );
    }

    #[test]
    fn compares_nonminimal_numeric_encodings_and_preserves_boundary_state() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        for alias_index in 0..3 {
            let result_script = script! {
                { u4_nibbles_to_trichotomy(1, 3) }
                for output_index in (0..3).rev() {
                    if output_index == alias_index { 1 } else { 0 }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![0u8]; 3];
            witness[alias_index] = vec![1, 0];
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(result_script),
                witness,
                options.clone(),
            )
            .expect("nonminimal one alias execution");
            assert!(
                result.success,
                "nonminimal one alias failed at {alias_index}: {result}"
            );
        }
        for alias in [vec![0x80], vec![0, 0]] {
            for alias_index in 0..3 {
                let result_script = script! {
                    { u4_nibbles_to_trichotomy(1, 3) }
                    for output_index in (0..3).rev() {
                        if output_index == alias_index { 0 } else { 1 }
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![1u8]; 3];
                witness[alias_index] = alias.clone();
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(result_script),
                    witness,
                    options.clone(),
                )
                .expect("nonminimal numeric alias execution");
                assert!(
                    result.success,
                    "nonminimal alias failed at {alias_index}: {result}"
                );
            }
        }

        let main_result = execute_raw_script_with_inputs_strict(
            compile_boundary(u4_nibbles_to_trichotomy(5, 997)),
            std::iter::once(vec![99u8])
                .chain(std::iter::repeat_n(Vec::new(), 997))
                .collect(),
        );
        assert!(
            main_result.error.is_none(),
            "997-item main state failed: {main_result}"
        );
        assert_eq!(main_result.final_stack.get(0), vec![99]);

        let alt_result = execute_raw_script_with_inputs_strict(
            compile_boundary(script! {
                77 OP_TOALTSTACK
                { u4_nibbles_to_trichotomy(5, 997) }
                OP_FROMALTSTACK
            }),
            std::iter::repeat_n(Vec::new(), 997).collect(),
        );
        assert!(
            alt_result.error.is_none(),
            "997-item alt state failed: {alt_result}"
        );
        assert_eq!(alt_result.final_stack.get(997), vec![77]);
    }
}
