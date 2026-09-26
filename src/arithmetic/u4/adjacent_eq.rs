use super::stack::u4_drop;
use crate::support::script::*;

/// Conservative supported batch limit for the input and result schedules.
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
            execution::{execute_script, ExecuteInfo},
            script::{script, ScriptCompilation},
            tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
        },
    };
    use bitcoin::{
        opcodes::all::{OP_EQUAL, OP_NUMEQUAL},
        script::Instruction,
        ScriptBuf,
    };

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    fn run_consensus(witness: Vec<Vec<u8>>, script: ScriptBuf) -> ExecuteInfo {
        match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected local consensus-profile execution: {outcome:?}"),
        }
    }

    fn assert_clean_truthy(result: &ExecuteInfo) {
        assert!(result.stack_limit_enforced, "stack limit was not enforced");
        assert!(
            result.error.is_none(),
            "unexpected execution error: {result}"
        );
        assert!(result.success, "complete script failed: {result}");
        assert_eq!(
            result.final_stack.len(),
            1,
            "script did not leave a clean stack: {result}"
        );
        assert_eq!(
            result.final_stack.get(0),
            vec![1],
            "script result is not OP_TRUE: {result}"
        );
    }

    fn output_checked_leaf(nibble_count: u32, expected: &[i64]) -> ScriptBuf {
        assert_eq!(expected.len(), nibble_count as usize - 1);
        script! {
            { u4_adjacent_equal_mask(nibble_count) }
            for value in expected.iter().rev() {
                { *value } OP_NUMEQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn historical_byte_equality_leaf(nibble_count: u32, expected: &[i64]) -> ScriptBuf {
        // The before-fix source at a5f2b72 used OP_EQUAL here. Rebuild the
        // policy-produced instructions and change only that comparator opcode,
        // matching the historical implementation without parsing raw bytes.
        let current = output_checked_leaf(nibble_count, expected);
        let mut builder = ScriptBuf::new();
        let mut changed = 0;
        for instruction in current.instructions() {
            match instruction.expect("valid compiled test script") {
                Instruction::Op(OP_NUMEQUAL) => {
                    builder.push_opcode(OP_EQUAL);
                    changed += 1;
                }
                instruction => builder.push_instruction(instruction),
            }
        }
        assert_eq!(changed, nibble_count as usize - 1);
        builder
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
        let equality_script = script! {
            { u4_adjacent_equal_mask(2) }
            OP_DROP
            OP_TRUE
        }
        .compile_with_policy();
        // This valid control uses the same leaf, witness shape, and explicit
        // consensus profile as the malformed cases below.
        let valid = run_consensus(vec![scriptnum(1), scriptnum(1)], equality_script.clone());
        assert_clean_truthy(&valid);

        let cases = [
            (scriptnum(-1), bitcoin_scriptexec::ExecError::Verify),
            (scriptnum(16), bitcoin_scriptexec::ExecError::Verify),
            (
                vec![0, 0, 0, 0x80, 0],
                bitcoin_scriptexec::ExecError::ScriptIntNumericOverflow,
            ),
        ];
        for (invalid, expected_error) in cases {
            for index in 0..2 {
                let mut witness = vec![scriptnum(1), scriptnum(1)];
                witness[index] = invalid.clone();
                let result = run_consensus(witness, equality_script.clone());
                assert!(
                    result.stack_limit_enforced,
                    "stack limit was not enforced for invalid nibble at {index}: {result}"
                );
                assert_eq!(
                    result.error,
                    Some(expected_error.clone()),
                    "wrong error for invalid nibble at {index}: {result}"
                );
                assert!(
                    !result.success,
                    "accepted invalid nibble at {index}: {result}"
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
        for witness in [
            vec![scriptnum(1), vec![1, 0]],
            vec![vec![1, 0], scriptnum(1)],
            vec![scriptnum(0), vec![0]],
            vec![vec![0x80], scriptnum(0)],
        ] {
            let result = run_consensus(witness, output_checked_leaf(2, &[1]));
            assert_clean_truthy(&result);
        }

        // Pair equality is intentionally asymmetric. Check every output in
        // its contract order so reversing the result vector cannot pass.
        let asymmetric = run_consensus(
            vec![
                scriptnum(1),
                vec![1, 0],
                scriptnum(2),
                vec![2, 0],
                scriptnum(3),
                scriptnum(4),
            ],
            output_checked_leaf(6, &[1, 0, 1, 0, 0]),
        );
        assert_clean_truthy(&asymmetric);

        let preserved = run_consensus(
            vec![],
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
            .compile_with_policy(),
        );
        assert_clean_truthy(&preserved);
    }

    #[test]
    fn historical_byte_equality_mutant_fails_the_alias_contract() {
        let witness = vec![scriptnum(1), vec![1, 0]];
        let fixed = run_consensus(witness.clone(), output_checked_leaf(2, &[1]));
        assert_clean_truthy(&fixed);

        let historical = run_consensus(witness, historical_byte_equality_leaf(2, &[1]));
        assert_eq!(
            historical.error,
            Some(bitcoin_scriptexec::ExecError::Verify),
            "historical OP_EQUAL mutant must fail at the output contract: {historical}"
        );
        assert!(
            !historical.success,
            "historical comparator unexpectedly succeeded: {historical}"
        );
        let historical_assertion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_clean_truthy(&historical)
        }));
        assert!(
            historical_assertion.is_err(),
            "historical OP_EQUAL comparator unexpectedly passed the numeric alias contract"
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
