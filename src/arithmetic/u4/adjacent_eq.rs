use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps the input and result schedules below
/// the 1,000-item stack limit.
pub const U4_ADJACENT_EQUAL_MAX_BATCH: u32 = 499;

/// Consume checked nibbles and return one equality bit for each adjacent pair.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | equal[0] ... equal[n-2]`, with `equal[n-2]` on top.
pub fn u4_adjacent_equal_mask(nibble_count: u32) -> Script {
    assert!(
        nibble_count >= 2,
        "adjacent equality needs at least two nibbles"
    );
    assert!(
        nibble_count <= U4_ADJACENT_EQUAL_MAX_BATCH,
        "adjacent equality batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for index in (0..nibble_count - 1).rev() {
            { nibble_count - 1 - index } OP_PICK
            { nibble_count - 1 - index } OP_PICK
            OP_NUMEQUAL OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count - 1 {
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
    fn emits_adjacent_equality_bits_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("112234") }
            { u4_adjacent_equal_mask(6) }
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "adjacent equality failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let equality_script = script! {
            { u4_adjacent_equal_mask(2) }
            OP_DROP
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for invalid in [-1, 16] {
            for index in 0..2 {
                let mut witness = vec![scriptnum(1), scriptnum(1)];
                witness[index] = scriptnum(invalid);
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(equality_script.clone()),
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
        assert!(std::panic::catch_unwind(|| u4_adjacent_equal_mask(1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_adjacent_equal_mask(U4_ADJACENT_EQUAL_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn compares_numeric_aliases_and_preserves_both_stacks() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let equality_script = script! {
            { u4_adjacent_equal_mask(2) }
            OP_VERIFY
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for witness in [
            vec![scriptnum(1), vec![1, 0]],
            vec![vec![1, 0], scriptnum(1)],
            vec![scriptnum(0), vec![0]],
            vec![vec![0x80], scriptnum(0)],
        ] {
            let result = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(equality_script.clone()),
                witness,
                options.clone(),
            )
            .expect("numeric alias execution");
            assert!(result.error.is_none(), "rejected numeric aliases: {result}");
        }

        let mixed = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(
                script! {
                    { u4_adjacent_equal_mask(4) }
                    1 OP_EQUALVERIFY
                    0 OP_EQUALVERIFY
                    1 OP_EQUALVERIFY
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes(),
            ),
            vec![scriptnum(1), vec![1, 0], scriptnum(2), vec![2, 0]],
            options.clone(),
        )
        .expect("mixed equality execution");
        assert!(mixed.error.is_none(), "mixed equality failed: {mixed}");

        let preserved = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(
                script! {
                    55 OP_TOALTSTACK
                    77
                    1
                    1
                    { u4_adjacent_equal_mask(2) }
                    OP_VERIFY
                    77 OP_EQUALVERIFY
                    OP_FROMALTSTACK 55 OP_EQUALVERIFY
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes(),
            ),
            vec![],
            options,
        )
        .expect("preserved stack execution");
        assert!(
            preserved.error.is_none(),
            "numeric equality changed surrounding state: {preserved}"
        );
    }

    #[test]
    fn preserves_surrounding_stack_items() {
        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_adjacent_equal_mask(4) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
