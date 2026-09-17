//! Embedded-symbol equality masks for checked u4 limbs.

use crate::support::script::*;

/// Largest standalone batch; callers must satisfy `batch + 2 + preserved <= 1000`.
pub const U4_EQ_MASK_MAX_BATCH: u32 = 1_000 - 2;

/// Replace each checked u4 nibble with whether it equals an embedded symbol.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | mask[0] | ... | mask[n-1]`, with the last mask
/// on top. The symbol is public generation-time data and must be a u4.
pub fn u4_nibbles_to_eq_mask(value: u8, nibble_count: u32) -> Script {
    assert!(value < 16, "equality target must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_EQ_MASK_MAX_BATCH,
        "nibble equality-mask batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            { value } OP_NUMEQUAL OP_TOALTSTACK
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
    fn projects_one_hot_equality_mask_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_eq_mask(5, 16) }
            for _ in 0..10 { 0 OP_EQUALVERIFY }
            1 OP_EQUALVERIFY
            for _ in 0..5 { 0 OP_EQUALVERIFY }
            OP_TRUE
        });
        assert!(result.success, "equality mask failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_eq_mask(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_eq_mask(5, 0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_eq_mask(5, U4_EQ_MASK_MAX_BATCH + 1)
        })
        .is_err());

        let checked_script = script! {
            { u4_nibbles_to_eq_mask(5, 3) }
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
            compile_boundary(u4_nibbles_to_eq_mask(5, U4_EQ_MASK_MAX_BATCH)),
            vec![Vec::new(); U4_EQ_MASK_MAX_BATCH as usize],
        );
        assert!(
            result.error.is_none(),
            "998-item equality mask failed: {result}"
        );
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    fn handles_target_endpoints() {
        for (value, input, expected) in [(0, 0, 1), (0, 15, 0), (15, 14, 0), (15, 15, 1)] {
            let result = execute_script(script! {
                { input }
                { u4_nibbles_to_eq_mask(value, 1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "equality endpoint failed: value={value}, input={input}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4 5 5
            { u4_nibbles_to_eq_mask(5, 3) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "equality mask changed surrounding state: {result}"
        );
    }

    #[test]
    fn compares_nonminimal_numeric_encodings_and_preserves_boundary_state() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let only_one_script = script! {
            { u4_nibbles_to_eq_mask(1, 3) }
            for _ in 0..3 { 1 OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for alias_index in 0..3 {
            let mut witness = vec![vec![1u8]; 3];
            witness[alias_index] = vec![1, 0];
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(only_one_script.clone()),
                witness,
                options.clone(),
            )
            .expect("nonminimal one alias execution");
            assert!(result.success, "nonminimal one alias failed: {result}");
        }

        for alias in [vec![0x80], vec![0, 0]] {
            for alias_index in 0..3 {
                let zero_and_one_script = script! {
                    { u4_nibbles_to_eq_mask(0, 3) }
                    for output_index in (0..3).rev() {
                        if output_index == alias_index { 1 } else { 0 }
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![1u8]; 3];
                witness[alias_index] = alias.clone();
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(zero_and_one_script.clone()),
                    witness,
                    options.clone(),
                )
                .expect("zero alias execution");
                assert!(
                    result.success,
                    "zero alias failed at {alias_index}: {result}"
                );
            }
        }

        let main_script = compile_boundary(u4_nibbles_to_eq_mask(5, 997));
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
            { u4_nibbles_to_eq_mask(5, 997) }
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
    }
}
