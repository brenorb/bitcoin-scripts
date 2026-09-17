//! Embedded-cap saturation for checked u4 limbs.

use crate::support::script::*;

/// Largest standalone batch; callers must satisfy `batch + 2 + preserved <= 1000`.
pub const U4_CLAMP_MAX_BATCH: u32 = 1_000 - 2;

/// Replace each checked u4 nibble with `min(nibble, maximum)`.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | clamped[0] | ... | clamped[n-1]`, with the last
/// result on top. The cap is public generation-time data and must be a u4.
pub fn u4_nibbles_to_clamp(maximum: u8, nibble_count: u32) -> Script {
    assert!(maximum < 16, "clamp maximum must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_CLAMP_MAX_BATCH,
        "nibble-clamp batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DUP { maximum } OP_GREATERTHAN
            OP_IF
                OP_DROP { maximum }
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
    fn clamps_all_nibbles_to_an_embedded_cap_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_clamp(4, 16) }
            for _ in 0..12 { 4 OP_EQUALVERIFY }
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "nibble clamp failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_clamp(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_clamp(4, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_clamp(4, U4_CLAMP_MAX_BATCH + 1) })
                .is_err()
        );

        let checked_script = script! {
            { u4_nibbles_to_clamp(4, 3) }
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
            compile_boundary(u4_nibbles_to_clamp(4, U4_CLAMP_MAX_BATCH)),
            vec![Vec::new(); U4_CLAMP_MAX_BATCH as usize],
        );
        assert!(result.error.is_none(), "998-item clamp failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    fn handles_cap_endpoints() {
        for (maximum, input, expected) in [(0, 0, 0), (0, 15, 0), (15, 14, 14), (15, 15, 15)] {
            let result = execute_script(script! {
                { input }
                { u4_nibbles_to_clamp(maximum, 1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "clamp endpoint failed: maximum={maximum}, input={input}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            3 5 15
            { u4_nibbles_to_clamp(5, 3) }
            5 OP_EQUALVERIFY
            5 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "nibble clamp changed surrounding state: {result}"
        );
    }

    #[test]
    fn compares_nonminimal_numeric_encodings_and_preserves_boundary_state() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let clamp_script = u4_nibbles_to_clamp(1, 3).compile_with_policy().to_bytes();
        for alias_index in 0..3 {
            let mut witness = vec![vec![0u8]; 3];
            witness[alias_index] = vec![1, 0];
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(clamp_script.clone()),
                witness,
                options.clone(),
            )
            .expect("nonminimal one alias execution");
            for output_index in 0..3 {
                let expected = if output_index == alias_index {
                    vec![1, 0]
                } else {
                    vec![0]
                };
                assert_eq!(result.final_stack.get(output_index), expected);
            }
        }
        for alias in [vec![0x80], vec![0, 0]] {
            for alias_index in 0..3 {
                let mut witness = vec![vec![1u8]; 3];
                witness[alias_index] = alias.clone();
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(clamp_script.clone()),
                    witness,
                    options.clone(),
                )
                .expect("zero alias execution");
                for output_index in 0..3 {
                    let expected = if output_index == alias_index {
                        alias.clone()
                    } else {
                        vec![1]
                    };
                    assert_eq!(result.final_stack.get(output_index), expected);
                }
            }
        }
        for (maximum, input, expected) in [
            (2, vec![1, 0], vec![1, 0]),
            (2, vec![0, 0], vec![0, 0]),
            (1, vec![2, 0], vec![1]),
        ] {
            let result_script = u4_nibbles_to_clamp(maximum, 1)
                .compile_with_policy()
                .to_bytes();
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(result_script),
                vec![input],
                options.clone(),
            )
            .expect("numeric alias preservation execution");
            assert_eq!(result.final_stack.get(0), expected);
        }

        let main_result = execute_raw_script_with_inputs_strict(
            compile_boundary(u4_nibbles_to_clamp(5, 997)),
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
                { u4_nibbles_to_clamp(5, 997) }
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
