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
            execution::execute_script,
            script::{script, ScriptCompilation},
            tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
        },
    };
    use bitcoin::{
        opcodes::all::{OP_EQUAL, OP_NUMEQUAL},
        script::{Builder, Instruction},
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    fn complete_mask_script(nibble_count: u32, offset: u32, expected: &[bool]) -> Script {
        assert_eq!(expected.len(), nibble_count as usize);
        script! {
            { u4_nibbles_to_cyclic_equality(nibble_count, offset) }
            for output_index in (0..nibble_count).rev() {
                { i64::from(expected[output_index as usize]) } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    fn assert_complete_mask(
        script: bitcoin::ScriptBuf,
        witness: Vec<Vec<u8>>,
        expected_acceptance: bool,
    ) -> Option<ExecError> {
        let result = execute_tapscript(script, witness, TapscriptProfile::Consensus);
        let mut error = None;
        let accepted = match result.outcome {
            TapscriptOutcome::Executed(execution) => {
                if !execution.success {
                    error = execution.error.clone();
                }
                execution.success
                    && execution.final_stack.len() == 1
                    && execution.final_stack.get(0) == scriptnum(1)
            }
            other => panic!("unexpected tapscript profile outcome: {other:?}"),
        };
        assert_eq!(
            accepted, expected_acceptance,
            "complete-mask acceptance mismatch; interpreter error: {error:?}"
        );
        error
    }

    fn byte_equality_mutant(script: &Script) -> ScriptBuf {
        let mut builder = Builder::new();
        let mut replaced = 0;
        for instruction in script.clone().compile_with_policy().instructions() {
            builder = match instruction.expect("valid compiled instruction") {
                Instruction::Op(OP_NUMEQUAL) => {
                    replaced += 1;
                    builder.push_opcode(OP_EQUAL)
                }
                Instruction::Op(opcode) => builder.push_opcode(opcode),
                Instruction::PushBytes(bytes) => builder.push_slice(bytes),
            };
        }
        assert!(replaced > 0, "mutant target OP_NUMEQUAL was not present");
        builder.into_script()
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
        let validation_script = complete_mask_script(2, 1, &[true, true]).compile_with_policy();
        assert_complete_mask(
            validation_script.clone(),
            vec![scriptnum(1), scriptnum(1)],
            true,
        );
        for (invalid, expected_error) in [
            (scriptnum(-1), ExecError::Verify),
            (scriptnum(16), ExecError::Verify),
            (vec![1, 0, 0, 0, 0], ExecError::ScriptIntNumericOverflow),
        ] {
            for index in 0..2 {
                let mut witness = vec![scriptnum(1), scriptnum(1)];
                witness[index] = invalid.clone();
                let error = assert_complete_mask(validation_script.clone(), witness, false);
                assert_eq!(
                    error,
                    Some(expected_error.clone()),
                    "input {index}: {invalid:?}"
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
    fn numeric_aliases_pass_numeric_contract_and_fail_byte_equality_mutant() {
        let script = complete_mask_script(2, 1, &[true, true]).compile_with_policy();
        for witness in [
            vec![scriptnum(1), vec![1, 0]],
            vec![vec![1, 0], scriptnum(1)],
            vec![scriptnum(0), vec![0x80]],
        ] {
            assert_complete_mask(script.clone(), witness, true);
        }

        let byte_equality_mutant = byte_equality_mutant(&script! {
            { u4_nibbles_to_cyclic_equality(2, 1) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            OP_TRUE
        });
        let error = assert_complete_mask(
            byte_equality_mutant.clone(),
            vec![scriptnum(1), vec![1, 0]],
            false,
        );
        assert_eq!(error, Some(ExecError::EqualVerify));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_complete_mask(byte_equality_mutant, vec![scriptnum(1), vec![1, 0]], true);
        }))
        .is_err());
    }

    #[test]
    fn preserves_asymmetric_order_and_reduces_large_offsets_modulo_length() {
        let witness = vec![scriptnum(1), scriptnum(1), scriptnum(2)];
        assert_complete_mask(
            complete_mask_script(3, 1, &[true, false, false]).compile_with_policy(),
            witness.clone(),
            true,
        );
        assert_complete_mask(
            complete_mask_script(3, 5, &[false, true, false]).compile_with_policy(),
            witness,
            true,
        );
    }

    #[test]
    fn executes_the_standalone_stack_frontier_under_consensus_profile() {
        let n = U4_CYCLIC_EQUAL_MAX_BATCH;
        let script = script! {
            { u4_nibbles_to_cyclic_equality(n, 7) }
            for _ in 0..n { OP_DROP }
            OP_TRUE
        }
        .compile_with_policy();
        let witness: Vec<Vec<u8>> = std::iter::repeat_with(|| scriptnum(15))
            .take(n as usize)
            .collect();
        let result = execute_tapscript(script, witness.clone(), TapscriptProfile::Consensus);
        let TapscriptOutcome::Executed(execution) = result.outcome else {
            panic!("unexpected frontier outcome: {result:?}");
        };
        assert!(execution.success, "frontier execution failed: {execution}");
        assert_eq!(execution.stats.max_nb_stack_items, 999);

        let one_preserved = script! {
            { u4_nibbles_to_cyclic_equality(n, 7) }
            for _ in 0..n { OP_DROP }
            99 OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy();
        let witness_one = std::iter::once(scriptnum(99))
            .chain(witness.clone())
            .collect();
        let result = execute_tapscript(one_preserved, witness_one, TapscriptProfile::Consensus);
        let TapscriptOutcome::Executed(one) = result.outcome else {
            panic!("unexpected one-preserved outcome: {result:?}");
        };
        assert!(one.success, "one-preserved frontier failed: {one}");
        assert_eq!(one.stats.max_nb_stack_items, 1_000);

        let two_preserved = script! {
            { u4_nibbles_to_cyclic_equality(n, 7) }
            for _ in 0..n { OP_DROP }
            OP_2DROP
            OP_TRUE
        }
        .compile_with_policy();
        let witness_two = [scriptnum(99), scriptnum(98)]
            .into_iter()
            .chain(witness)
            .collect();
        let result = execute_tapscript(two_preserved, witness_two, TapscriptProfile::Consensus);
        let TapscriptOutcome::Executed(two) = result.outcome else {
            panic!("unexpected two-preserved outcome: {result:?}");
        };
        assert!(
            !two.success,
            "two-preserved overflow unexpectedly passed: {two}"
        );
        assert_eq!(two.error, Some(ExecError::StackSize));
        assert_eq!(two.stats.max_nb_stack_items, 1_001);
    }
}
