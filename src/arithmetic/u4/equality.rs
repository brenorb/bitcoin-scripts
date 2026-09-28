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
            execution::{execute_raw_script_with_inputs_strict, execute_script, ExecuteInfo},
            script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
            tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
        },
    };
    use bitcoin::{
        opcodes::all::{OP_EQUAL, OP_NUMEQUAL},
        script::Instruction,
        ScriptBuf,
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

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    /// Raw-witness alias contract: the local `TapscriptProfile::Consensus`
    /// profile disables global numeric minimality (`require_minimal: false`)
    /// and enforces the combined 1,000-item stack limit. This is a local
    /// fragment execution, not Bitcoin Core or complete-spend validation.
    fn run_profile(
        witness: Vec<Vec<u8>>,
        script: ScriptBuf,
        profile: TapscriptProfile,
    ) -> ExecuteInfo {
        match execute_tapscript(script, witness, profile).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected local {profile:?}-profile execution: {outcome:?}"),
        }
    }

    fn run_consensus(witness: Vec<Vec<u8>>, script: ScriptBuf) -> ExecuteInfo {
        run_profile(witness, script, TapscriptProfile::Consensus)
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

    /// Complete leaf that checks every mask item in input order: `expected[0]`
    /// is the bottom output and `expected[n - 1]` the top output.
    fn output_checked_leaf(fragment: Script, expected: &[i64]) -> ScriptBuf {
        script! {
            { fragment }
            for value in expected.iter().rev() {
                { *value } OP_NUMEQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    /// The schedule reviewed at `16fdc6d`: roll the bottom input first, then
    /// restore the staged results, which reverses the mask. The comparator is
    /// kept numeric so this mutant isolates the output-order defect.
    fn historical_reversed_schedule(value: u8, nibble_count: u32) -> Script {
        script! {
            for index in (0..nibble_count).rev() {
                { index } OP_ROLL
                OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
                { value } OP_NUMEQUAL OP_TOALTSTACK
            }
            for _ in 0..nibble_count {
                OP_FROMALTSTACK
            }
        }
    }

    /// The byte comparator reviewed at `16fdc6d`: rebuild the policy-produced
    /// leaf and replace only the fragment's `OP_NUMEQUAL` with `OP_EQUAL`.
    fn historical_byte_equality(leaf: &ScriptBuf, nibble_count: u32) -> ScriptBuf {
        let mut builder = ScriptBuf::new();
        let mut changed = 0;
        for instruction in leaf.instructions() {
            match instruction.expect("valid compiled test script") {
                Instruction::Op(OP_NUMEQUAL) => {
                    builder.push_opcode(OP_EQUAL);
                    changed += 1;
                }
                instruction => builder.push_instruction(instruction),
            }
        }
        assert_eq!(changed, nibble_count as usize);
        builder
    }

    // Target 1 over mixed canonical and non-minimal numeric encodings. The
    // mask [1, 0, 1, 0, 1, 0] is not a palindrome, so a reversed output
    // schedule is detected; byte equality would yield [0, 0, 1, 0, 0, 0].
    fn asymmetric_alias_witness() -> Vec<Vec<u8>> {
        vec![
            vec![1, 0],
            vec![0x80],
            scriptnum(1),
            vec![2, 0],
            vec![1, 0, 0, 0],
            scriptnum(15),
        ]
    }
    const ASYMMETRIC_ALIAS_MASK: [i64; 6] = [1, 0, 1, 0, 1, 0];

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
        let only_one_script = script! {
            { u4_nibbles_to_eq_mask(1, 3) }
            for _ in 0..3 { 1 OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy();
        for alias_index in 0..3 {
            let mut witness = vec![vec![1u8]; 3];
            witness[alias_index] = vec![1, 0];
            let result = run_consensus(witness, only_one_script.clone());
            assert_clean_truthy(&result);
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
                .compile_with_policy();
                let mut witness = vec![vec![1u8]; 3];
                witness[alias_index] = alias.clone();
                let result = run_consensus(witness, zero_and_one_script);
                assert_clean_truthy(&result);
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

    #[test]
    fn numeric_aliases_follow_an_asymmetric_mask_in_input_order() {
        let leaf = output_checked_leaf(u4_nibbles_to_eq_mask(1, 6), &ASYMMETRIC_ALIAS_MASK);
        assert_clean_truthy(&run_consensus(asymmetric_alias_witness(), leaf.clone()));

        // Canonical control with the same leaf and the same numeric values.
        let canonical = [1, 0, 1, 2, 1, 15].map(scriptnum).to_vec();
        assert_clean_truthy(&run_consensus(canonical, leaf.clone()));

        // The alias result is a Consensus-profile contract. The local Policy
        // profile enforces numeric minimality and rejects the first alias.
        let policy = run_profile(asymmetric_alias_witness(), leaf, TapscriptProfile::Policy);
        assert_eq!(
            policy.error,
            Some(ExecError::MinimalData),
            "Policy profile did not reject the non-minimal nibble: {policy}"
        );
        assert!(!policy.success);
    }

    #[test]
    fn historical_byte_equality_and_reversed_schedule_mutants_fail() {
        let fixed = output_checked_leaf(u4_nibbles_to_eq_mask(1, 6), &ASYMMETRIC_ALIAS_MASK);
        assert_clean_truthy(&run_consensus(asymmetric_alias_witness(), fixed.clone()));

        let mutants = [
            (
                "OP_EQUAL comparator",
                historical_byte_equality(&fixed, 6),
                ExecError::Verify,
            ),
            (
                "reversed output schedule",
                output_checked_leaf(historical_reversed_schedule(1, 6), &ASYMMETRIC_ALIAS_MASK),
                ExecError::NumEqualVerify,
            ),
        ];
        for (name, mutant, expected_error) in mutants {
            // Build and execute outside the panic-catching assertion so that a
            // setup failure cannot be counted as a detected mutant.
            let result = run_consensus(asymmetric_alias_witness(), mutant);
            assert!(result.stack_limit_enforced);
            assert_eq!(
                result.error,
                Some(expected_error),
                "{name} mutant must fail at the output contract: {result}"
            );
            assert!(!result.success, "{name} mutant unexpectedly succeeded");
            let contract = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_clean_truthy(&result)
            }));
            assert!(
                contract.is_err(),
                "{name} mutant passed the asymmetric numeric-alias contract"
            );
        }
    }
}
