//! Membership-mask projection for checked u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_PRESENCE_MAX_BATCH: u32 = 1_000 - 16 - 2;

/// Consume checked u4 nibbles and return one presence bit for each nibble.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | present[0] ... present[15]`, where `present[n]`
/// is one iff nibble `n` appeared in the input. Every input is range-checked.
pub fn u4_nibbles_to_presence_bits(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_PRESENCE_MAX_BATCH,
        "nibble-presence batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { index } OP_PICK
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DROP
        }

        for nibble in (0..16).rev() {
            0
            for index in 0..nibble_count {
                { nibble }
                { index + 2 } OP_PICK
                OP_NUMEQUAL
                OP_BOOLOR
            }
            OP_TOALTSTACK
        }

        { u4_drop(nibble_count) }
        for _ in 0..16 {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::{
            test_helpers::{assert_clean_true, run_tapscript, scriptnum},
            u4::stack::u4_hex_to_nibbles,
        },
        support::{
            execution::{execute_script, ExecuteInfo},
            script::{script, ScriptCompilation},
            tapscript::TapscriptProfile,
        },
    };
    use bitcoin::{
        opcodes::all::{OP_EQUAL, OP_NUMEQUAL},
        script::Instruction,
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    fn run_consensus(witness: Vec<Vec<u8>>, script: ScriptBuf) -> ExecuteInfo {
        run_tapscript(script, witness, TapscriptProfile::Consensus)
    }

    /// Complete leaf that checks all 16 presence bits in value order:
    /// `expected[0]` is `present[0]` (bottom output) and `expected[15]` is
    /// `present[15]` (top output). Numeric checks keep the leaf independent of
    /// the Boolean output encoding.
    fn output_checked_leaf(fragment: Script, expected: &[i64; 16]) -> ScriptBuf {
        script! {
            { fragment }
            for bit in expected.iter().rev() {
                { *bit } OP_NUMEQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    /// Test-only mutant of the defect reviewed at `aa7d824`: rebuild the
    /// policy-produced leaf and replace only the fragment's `OP_NUMEQUAL`
    /// membership comparisons with bytewise `OP_EQUAL`.
    fn byte_equality_mutant(leaf: &ScriptBuf) -> (ScriptBuf, usize) {
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
        (builder, changed)
    }

    /// Test-only mutant that reverses the 16 presence outputs, so `present[0]`
    /// is on top instead of `present[15]`.
    fn reversed_output_order_mutant(nibble_count: u32) -> Script {
        script! {
            { u4_nibbles_to_presence_bits(nibble_count) }
            for depth in 1..16 {
                { depth } OP_ROLL
            }
        }
    }

    // Raw witness items with numeric values 1, 0, 2, 5, 15. Items 0, 1, 2 and
    // 4 are non-minimal aliases (negative zero is `[0x80]`); item 3 is
    // canonical. The expected presence vector is not a palindrome, so a
    // reversed output order is detected, and bytewise equality against the
    // canonical constants would lose at least values 1, 2 and 15.
    fn asymmetric_alias_witness() -> Vec<Vec<u8>> {
        vec![
            vec![0x01, 0x00],
            vec![0x80],
            vec![0x02, 0x00],
            scriptnum(5),
            vec![0x0f, 0x00, 0x00, 0x00],
        ]
    }
    const ASYMMETRIC_ALIAS_VALUES: [i64; 5] = [1, 0, 2, 5, 15];
    const ASYMMETRIC_PRESENCE: [i64; 16] = [1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[test]
    fn projects_presence_bits() {
        for (input, expected) in [
            ("0123456789abcdef", [1; 16]),
            ("001122", [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ("f0f0", [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(input) }
                { u4_nibbles_to_presence_bits(input.len() as u32) }
                for bit in expected.into_iter().rev() {
                    { bit } OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "presence bits failed for {input}: {result}");
        }
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_presence_bits(1) }
                for _ in 0..16 { OP_DROP }
                OP_TRUE
            });
            assert_eq!(
                result.error,
                Some(ExecError::Verify),
                "accepted invalid nibble {invalid}: {result}"
            );
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_presence_bits(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_presence_bits(U4_PRESENCE_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn compares_nonminimal_numeric_encodings_by_value() {
        let expected = |present: &[u8]| {
            let mut bits = [0i64; 16];
            for &nibble in present {
                bits[nibble as usize] = 1;
            }
            bits
        };
        let only_one_leaf = output_checked_leaf(u4_nibbles_to_presence_bits(3), &expected(&[1]));
        for alias_index in 0..3 {
            let mut witness = vec![vec![1u8]; 3];
            witness[alias_index] = vec![0x01, 0x00];
            assert_clean_true(&run_consensus(witness, only_one_leaf.clone()));
        }

        let zero_and_one_leaf =
            output_checked_leaf(u4_nibbles_to_presence_bits(3), &expected(&[0, 1]));
        for alias in [vec![0x80], vec![0x00, 0x00]] {
            for alias_index in 0..3 {
                let mut witness = vec![vec![1u8]; 3];
                witness[alias_index] = alias.clone();
                assert_clean_true(&run_consensus(witness, zero_and_one_leaf.clone()));
            }
        }
    }

    #[test]
    fn numeric_aliases_follow_ordered_presence_bits() {
        let leaf = output_checked_leaf(
            u4_nibbles_to_presence_bits(ASYMMETRIC_ALIAS_VALUES.len() as u32),
            &ASYMMETRIC_PRESENCE,
        );
        assert_clean_true(&run_consensus(asymmetric_alias_witness(), leaf.clone()));

        // Canonical control: same leaf, same numeric values.
        let canonical = ASYMMETRIC_ALIAS_VALUES.map(scriptnum).to_vec();
        assert_clean_true(&run_consensus(canonical.clone(), leaf.clone()));
        assert_clean_true(&run_tapscript(
            leaf.clone(),
            canonical,
            TapscriptProfile::Policy,
        ));

        // The alias result is a Consensus-profile contract. The local Policy
        // profile enforces numeric minimality and rejects the first alias.
        let policy = run_tapscript(leaf, asymmetric_alias_witness(), TapscriptProfile::Policy);
        assert_eq!(
            policy.error,
            Some(ExecError::MinimalData),
            "Policy profile did not reject the non-minimal nibble: {policy}"
        );
        assert!(!policy.success);
    }

    #[test]
    fn byte_equality_and_reversed_output_mutants_fail() {
        let nibble_count = ASYMMETRIC_ALIAS_VALUES.len() as u32;
        let fixed = output_checked_leaf(
            u4_nibbles_to_presence_bits(nibble_count),
            &ASYMMETRIC_PRESENCE,
        );
        assert_clean_true(&run_consensus(asymmetric_alias_witness(), fixed.clone()));

        let (byte_equality, changed) = byte_equality_mutant(&fixed);
        assert!(changed > 0, "no OP_NUMEQUAL comparison to mutate");
        let reversed = output_checked_leaf(
            reversed_output_order_mutant(nibble_count),
            &ASYMMETRIC_PRESENCE,
        );
        for (name, mutant) in [
            ("OP_EQUAL comparator", byte_equality),
            ("reversed output order", reversed),
        ] {
            // Execute outside the panic-catching assertion so that a setup
            // failure cannot be counted as a detected mutant.
            let result = run_consensus(asymmetric_alias_witness(), mutant);
            assert!(result.stack_limit_enforced);
            assert_eq!(
                result.error,
                Some(ExecError::NumEqualVerify),
                "{name} mutant must fail at the output contract: {result}"
            );
            assert!(!result.success, "{name} mutant unexpectedly succeeded");
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            0 1 2
            { u4_nibbles_to_presence_bits(3) }
            for nibble in (0..16).rev() {
                if nibble <= 2 { 1 } else { 0 }
                OP_EQUALVERIFY
            }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "presence bits changed surrounding state: {result}"
        );
    }
}
