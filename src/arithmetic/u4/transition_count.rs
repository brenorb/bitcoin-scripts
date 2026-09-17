use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch before accounting for unrelated live stack state.
pub const U4_TRANSITION_COUNT_MAX_BATCH: u32 = 997;

/// Count unequal adjacent pairs in a checked u4 vector.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | transition_count`, where the count is in
/// `0..=n-1`.
pub fn u4_nibbles_transition_count(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "transition count needs a nonempty vector");
    assert!(
        nibble_count <= U4_TRANSITION_COUNT_MAX_BATCH,
        "transition-count batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        0 OP_TOALTSTACK
        for index in (0..nibble_count - 1).rev() {
            { nibble_count - 1 - index } OP_PICK
            { nibble_count - 1 - index } OP_PICK
            OP_NUMEQUAL OP_NOT
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        OP_FROMALTSTACK
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
    fn counts_transitions_and_preserves_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("112234") }
            { u4_nibbles_transition_count(6) }
            3 OP_EQUAL
        });
        assert!(result.success, "transition count failed: {result}");

        let constant = execute_script(script! {
            { u4_hex_to_nibbles("ffff") }
            { u4_nibbles_transition_count(4) }
            0 OP_EQUAL
        });
        assert!(
            constant.success,
            "constant vector counted a transition: {constant}"
        );
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let count_script = script! {
            { u4_nibbles_transition_count(2) }
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
                    bitcoin::ScriptBuf::from_bytes(count_script.clone()),
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
        assert!(std::panic::catch_unwind(|| u4_nibbles_transition_count(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_transition_count(U4_TRANSITION_COUNT_MAX_BATCH + 1)
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
        let count_script = script! {
            { u4_nibbles_transition_count(2) }
            0 OP_EQUALVERIFY
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
                bitcoin::ScriptBuf::from_bytes(count_script.clone()),
                witness,
                options.clone(),
            )
            .expect("numeric alias execution");
            assert!(result.error.is_none(), "rejected numeric aliases: {result}");
        }

        let mixed = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(
                script! {
                    { u4_nibbles_transition_count(5) }
                    2 OP_EQUALVERIFY
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes(),
            ),
            vec![
                scriptnum(1),
                vec![1, 0],
                scriptnum(2),
                vec![2, 0],
                scriptnum(1),
            ],
            options.clone(),
        )
        .expect("mixed transition execution");
        assert!(
            mixed.error.is_none(),
            "mixed transition count failed: {mixed}"
        );

        let preserved = execute_script(script! {
            55 OP_TOALTSTACK
            77
            1
            1
            { u4_nibbles_transition_count(2) }
            0 OP_EQUALVERIFY
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 55 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            preserved.success,
            "numeric equality changed surrounding state: {preserved}"
        );
    }

    #[test]
    fn preserves_surrounding_stack_items_and_singletons() {
        let singleton = execute_script(script! {
            7
            { u4_hex_to_nibbles("a") }
            { u4_nibbles_transition_count(1) }
            0 OP_EQUALVERIFY
            7 OP_EQUAL
        });
        assert!(singleton.success, "singleton failed: {singleton}");

        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_nibbles_transition_count(4) }
            1 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
