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
            execution::execute_script,
            script::{script, Script, ScriptCompilation},
            tapscript::{execute_tapscript, TapscriptProfile},
        },
    };
    use bitcoin::{
        opcodes::all::{OP_EQUAL, OP_NOT, OP_NUMNOTEQUAL},
        script::Instruction,
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    fn assert_contract(
        script: Script,
        witness: Vec<Vec<u8>>,
        expected_success: bool,
        expected_error: Option<ExecError>,
    ) -> crate::support::tapscript::TapscriptResult {
        assert_compiled_contract(
            script.compile_with_policy(),
            witness,
            expected_success,
            expected_error,
        )
    }

    fn assert_compiled_contract(
        compiled: ScriptBuf,
        witness: Vec<Vec<u8>>,
        expected_success: bool,
        expected_error: Option<ExecError>,
    ) -> crate::support::tapscript::TapscriptResult {
        let result = execute_tapscript(compiled, witness, TapscriptProfile::Consensus);
        assert_eq!(result.profile, TapscriptProfile::Consensus);
        assert_eq!(result.accepted(), Some(expected_success), "{result:?}");
        let execution = result.execution().expect("ordinary interpreter execution");
        assert!(execution.stack_limit_enforced, "{execution}");
        assert_eq!(execution.success, expected_success, "{execution}");
        assert_eq!(execution.error, expected_error, "{execution}");
        if expected_success {
            assert_eq!(execution.final_stack.len(), 1, "{execution}");
            assert_eq!(execution.final_stack.get(0), vec![1], "{execution}");
        }
        result
    }

    fn checked_count(expected: i64) -> Script {
        script! {
            { u4_nibbles_transition_count(2) }
            { expected } OP_NUMEQUALVERIFY
            OP_TRUE
        }
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
        for (invalid, error) in [
            (-1, ExecError::Verify),
            (16, ExecError::Verify),
            (2_147_483_648, ExecError::ScriptIntNumericOverflow),
        ] {
            for index in 0..2 {
                let mut witness = vec![scriptnum(1), scriptnum(1)];
                witness[index] = scriptnum(invalid);
                assert_contract(checked_count(0), witness, false, Some(error.clone()));
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
        for witness in [
            vec![scriptnum(1), vec![1, 0]],
            vec![vec![1, 0], scriptnum(1)],
            vec![scriptnum(0), vec![0]],
            vec![vec![0x80], vec![0]],
        ] {
            assert_contract(checked_count(0), witness, true, None);
        }

        assert_contract(
            script! {
                { u4_nibbles_transition_count(5) }
                2 OP_NUMEQUALVERIFY
                OP_TRUE
            },
            vec![
                scriptnum(1),
                vec![1, 0],
                scriptnum(2),
                vec![2, 0],
                scriptnum(1),
            ],
            true,
            None,
        );

        // Mutate the compiled fragment with the raw-byte comparator from the
        // original implementation. The same complete-terminal assertion must
        // reject this bypass on numeric aliases.
        let complete = checked_count(0).compile_with_policy();
        let mut builder = bitcoin::script::Builder::new();
        let mut replaced = 0;
        for instruction in complete.instructions() {
            match instruction.expect("compiled instruction parses") {
                Instruction::Op(opcode) if opcode == OP_NUMNOTEQUAL => {
                    if replaced == 0 {
                        builder = builder.push_opcode(OP_EQUAL);
                        builder = builder.push_opcode(OP_NOT);
                        replaced = 1;
                    } else {
                        builder = builder.push_opcode(opcode);
                    }
                }
                Instruction::Op(opcode) => builder = builder.push_opcode(opcode),
                Instruction::PushBytes(bytes) => builder = builder.push_slice(bytes),
            }
        }
        assert_eq!(replaced, 1, "mutant must replace the transition comparator");
        let mutant = builder.into_script();
        let alias_witness = vec![scriptnum(1), vec![1, 0]];
        assert_compiled_contract(
            mutant.clone(),
            alias_witness.clone(),
            false,
            Some(ExecError::NumEqualVerify),
        );
        let mutant_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_compiled_contract(mutant, alias_witness, true, None)
        }));
        assert!(
            mutant_result.is_err(),
            "bytewise mutant escaped the contract"
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
        assert_contract(
            script! {
                { u4_nibbles_transition_count(1) }
                0 OP_NUMEQUAL
            },
            vec![scriptnum(10)],
            true,
            None,
        );

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

    #[test]
    fn measures_standalone_and_composed_stack_frontiers() {
        let standalone_nibbles = (0..U4_TRANSITION_COUNT_MAX_BATCH)
            .map(|index| scriptnum(if index % 2 == 0 { 1 } else { 2 }))
            .collect::<Vec<_>>();
        assert_eq!(standalone_nibbles.len(), 997);
        assert_eq!(
            bitcoin::consensus::serialize(&bitcoin::Witness::from_slice(&standalone_nibbles)).len(),
            1_997
        );
        let standalone_script = script! {
            { u4_nibbles_transition_count(U4_TRANSITION_COUNT_MAX_BATCH) }
            { U4_TRANSITION_COUNT_MAX_BATCH - 1 } OP_NUMEQUAL
        };
        let standalone_script_bytes = standalone_script.clone().compile_with_policy().len();
        eprintln!("frontier standalone locking-script bytes={standalone_script_bytes}");
        let standalone = assert_contract(standalone_script, standalone_nibbles.clone(), true, None);
        assert_eq!(
            standalone.execution().unwrap().stats.max_nb_stack_items,
            1_000
        );

        // One preserved main-stack item, 995 data nibbles, and one
        // script-created alt-stack item coexist before the fragment runs.
        let mut composed_witness = vec![scriptnum(77)];
        composed_witness
            .extend((0..995).map(|index| scriptnum(if index % 2 == 0 { 1 } else { 2 })));
        assert_eq!(composed_witness.len(), 996);
        assert_eq!(
            bitcoin::consensus::serialize(&bitcoin::Witness::from_slice(&composed_witness)).len(),
            1_995
        );
        let composed_script = script! {
            OP_1 OP_TOALTSTACK
            { u4_nibbles_transition_count(995) }
            994 OP_NUMEQUALVERIFY
            OP_DROP
            OP_FROMALTSTACK 1 OP_NUMEQUAL
        };
        let composed_script_bytes = composed_script.clone().compile_with_policy().len();
        eprintln!("frontier main+alt locking-script bytes={composed_script_bytes}");
        let composed = assert_contract(composed_script, composed_witness, true, None);
        assert_eq!(
            composed.execution().unwrap().stats.max_nb_stack_items,
            1_000
        );

        // One additional data nibble makes the combined main/alt-stack
        // frontier 1,001 items, so the same profile rejects at StackSize.
        let mut over_limit_witness = vec![scriptnum(77)];
        over_limit_witness
            .extend((0..996).map(|index| scriptnum(if index % 2 == 0 { 1 } else { 2 })));
        assert_eq!(over_limit_witness.len(), 997);
        assert_eq!(
            bitcoin::consensus::serialize(&bitcoin::Witness::from_slice(&over_limit_witness)).len(),
            1_997
        );
        let over_limit_script = script! {
            OP_1 OP_TOALTSTACK
            { u4_nibbles_transition_count(996) }
            OP_DROP OP_TRUE
        };
        let over_limit_script_bytes = over_limit_script.clone().compile_with_policy().len();
        eprintln!("frontier over-limit locking-script bytes={over_limit_script_bytes}");
        let over_limit = assert_contract(
            over_limit_script,
            over_limit_witness,
            false,
            Some(ExecError::StackSize),
        );
        assert_eq!(
            over_limit.execution().unwrap().stats.max_nb_stack_items,
            1_001
        );
    }
}
