//! Checked cyclic lag-equality masks for contiguous u4 vectors.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps the source and result schedules below
/// the 1,000-item combined stack limit.
pub const U4_CYCLIC_EQUAL_MAX_BATCH: u32 = 499;

/// Compare each nibble with the nibble `offset` positions ahead, wrapping around.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | equal[0] ... equal[n-1]`.
pub fn u4_nibbles_to_cyclic_equality(nibble_count: u32, offset: u32) -> Script {
    assert!(nibble_count > 0, "cyclic equality needs a nonempty vector");
    assert!(
        nibble_count <= U4_CYCLIC_EQUAL_MAX_BATCH,
        "cyclic equality batch exceeds Bitcoin Script's stack limit"
    );

    let offset = offset % nibble_count;
    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for output_index in (0..nibble_count).rev() {
            { nibble_count - 1 - output_index } OP_PICK
            { nibble_count - ((output_index + offset) % nibble_count) } OP_PICK
            OP_NUMEQUAL OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
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
            execution::{execute_script, execute_script_buf_with_options},
            script::{script, ScriptCompilation},
        },
    };
    use bitcoin_scriptexec::Options;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    #[test]
    fn compares_a_wrapped_periodic_vector_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("12341234") }
            { u4_nibbles_to_cyclic_equality(8, 4) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "cyclic equality failed: {result}");

        let nonperiodic = execute_script(script! {
            { u4_hex_to_nibbles("1123") }
            { u4_nibbles_to_cyclic_equality(4, 1) }
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(
            nonperiodic.success,
            "nonperiodic cyclic equality failed: {nonperiodic}"
        );
    }

    #[test]
    fn supports_zero_offset_and_preserves_surrounding_stack_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("12") }
            { u4_nibbles_to_cyclic_equality(2, 0) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let validation_script = script! {
            { u4_nibbles_to_cyclic_equality(2, 1) }
            OP_2DROP
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for invalid in [-1, 16] {
            for index in 0..2 {
                let mut witness = vec![scriptnum(1), scriptnum(1)];
                witness[index] = scriptnum(invalid);
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(validation_script.clone()),
                    witness,
                    options.clone(),
                )
                .expect("invalid nibble execution");
                assert!(
                    result.error.is_some(),
                    "accepted invalid nibble {invalid} at {index}: {result}"
                );
            }
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_cyclic_equality(0, 1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_cyclic_equality(U4_CYCLIC_EQUAL_MAX_BATCH + 1, 1)
        })
        .is_err());
    }

    #[test]
    fn compares_numeric_aliases() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let equality_script = |nibble_count, offset| {
            script! {
                { u4_nibbles_to_cyclic_equality(nibble_count, offset) }
                1 OP_EQUALVERIFY
                1 OP_EQUAL
                OP_TRUE
            }
            .compile_with_policy()
            .to_bytes()
        };

        for witness in [
            vec![scriptnum(1), vec![1, 0]],
            vec![vec![1, 0], scriptnum(1)],
            vec![scriptnum(0), vec![0x80]],
        ] {
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(equality_script(2, 1)),
                witness,
                options.clone(),
            )
            .expect("numeric alias execution");
            assert!(result.error.is_none(), "rejected numeric aliases: {result}");
        }
    }
}
