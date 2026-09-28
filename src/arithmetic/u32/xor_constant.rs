//! Checked XOR of a byte-oriented u32 word with a generation-time constant.

use super::{
    stack::{u32_drop, u32_fromaltstack, u32_push, u32_toaltstack, verify_canonical_byte},
    xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};
use crate::support::script::{script, Script};

/// XOR the top canonical u32 word with an embedded constant.
///
/// The word uses the normal most-significant-byte-first layout, with the
/// least-significant byte on top. The constant is embedded in the script, so
/// only the four input limbs are supplied by the witness.
pub fn u32_xor_constant(value: u32) -> Script {
    script! {
        { u32_toaltstack() }
        { u8_push_xor_table() }
        { u32_fromaltstack() }
        { u32_push(value) }
        { u32_toaltstack() }
        for _ in 0..4 {
            3 OP_ROLL
            { verify_canonical_byte() }
        }
        { u32_fromaltstack() }
        { u32_xor(0, 1, 3) }
        { u32_toaltstack() }
        { u32_drop() }
        { u8_drop_xor_table() }
        { u32_fromaltstack() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::arithmetic::u32::stack::{u32_equal, u32_equalverify};
    use crate::support::execution::execute_script;
    use crate::support::script::ScriptCompilation;
    use crate::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    // The complete-leaf and alias-predicate helpers below mirror the
    // embedded-constant OR/AND/XNOR tests. They stay local because those
    // helpers are private to each sibling test module and no shared u32
    // constant-Boolean test module exists on main.

    const MASK: u32 = 0x89ab_cdef;
    /// Out-of-byte-range sentinels, so no adapter limb or table item can alias them.
    const MAIN_SENTINELS: [i64; 2] = [-1, 1000];
    const ALT_SENTINELS: [i64; 2] = [1001, -2];

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    fn byte_word(value: u32) -> Vec<Vec<u8>> {
        value
            .to_be_bytes()
            .into_iter()
            .map(|byte| scriptnum(i64::from(byte)))
            .collect()
    }

    fn complete_leaf(fragment: Script) -> ScriptBuf {
        script! {
            { fragment }
            { u32_drop() }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn complete_result_leaf(word: u32, mask: u32) -> ScriptBuf {
        script! {
            { u32_xor_constant(mask) }
            { u32_push(word ^ mask) }
            { u32_equal() }
            OP_VERIFY
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn executed_success(script: &ScriptBuf, witness: Vec<Vec<u8>>) -> bool {
        matches!(
            execute_tapscript(script.clone(), witness, TapscriptProfile::Consensus).outcome,
            TapscriptOutcome::Executed(info) if info.success
        )
    }

    fn all_nonminimal_aliases_rejected(script: &ScriptBuf) -> bool {
        let canonical = vec![vec![1]; 4];
        let control = execute_tapscript(
            script.clone(),
            canonical.clone(),
            TapscriptProfile::Consensus,
        );
        let TapscriptOutcome::Executed(info) = &control.outcome else {
            panic!("control leaf had no execution verdict: {control:?}");
        };
        assert!(info.success, "control leaf failed: {control:?}");
        assert!(info.stack_limit_enforced);
        assert_eq!(info.final_stack.len(), 1);
        assert_eq!(info.final_stack.get(0), vec![1]);
        assert!(info.stats.max_nb_stack_items <= 1000);

        (0..4).all(|index| {
            let mut witness = canonical.clone();
            witness[index] = vec![1, 0];
            matches!(
                execute_tapscript(script.clone(), witness, TapscriptProfile::Consensus).outcome,
                TapscriptOutcome::Executed(ref info)
                    if !info.success && info.error == Some(ExecError::EqualVerify)
            )
        })
    }

    /// Historical defect: all four checks inspect the same top limb.
    fn top_limb_only_mutant(value: u32) -> Script {
        script! {
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_push(value) }
            { u32_toaltstack() }
            for _ in 0..4 {
                { verify_canonical_byte() }
            }
            { u32_fromaltstack() }
            { u32_xor(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() }
            { u8_drop_xor_table() }
            { u32_fromaltstack() }
        }
    }

    /// Cleanup defect: drops only 255 of the 256 table items.
    fn undropped_table_item_mutant(value: u32) -> Script {
        script! {
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_push(value) }
            { u32_toaltstack() }
            for _ in 0..4 {
                3 OP_ROLL
                { verify_canonical_byte() }
            }
            { u32_fromaltstack() }
            { u32_xor(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() }
            for _ in 0..127 {
                OP_2DROP
            }
            OP_DROP
            { u32_fromaltstack() }
        }
    }

    /// A complete leaf with two main-stack sentinels below the word and two
    /// alt-stack sentinels. After every call, `OP_DEPTH` must be exactly two
    /// sentinels plus one result word, so no table item can survive.
    fn state_leaf(fragment: fn(u32) -> Script, masks: &[u32], word: u32) -> ScriptBuf {
        let expected = masks.iter().fold(word, |acc, mask| acc ^ mask);
        script! {
            { ALT_SENTINELS[0] } OP_TOALTSTACK
            { ALT_SENTINELS[1] } OP_TOALTSTACK
            for mask in masks.iter().copied() {
                { fragment(mask) }
                OP_DEPTH 6 OP_EQUALVERIFY
            }
            { u32_push(expected) }
            { u32_equalverify() }
            { MAIN_SENTINELS[1] } OP_EQUALVERIFY
            { MAIN_SENTINELS[0] } OP_EQUALVERIFY
            OP_DEPTH 0 OP_EQUALVERIFY
            OP_FROMALTSTACK { ALT_SENTINELS[1] } OP_EQUALVERIFY
            OP_FROMALTSTACK { ALT_SENTINELS[0] } OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn state_witness(word: u32) -> Vec<Vec<u8>> {
        MAIN_SENTINELS
            .into_iter()
            .map(scriptnum)
            .chain(byte_word(word))
            .collect()
    }

    #[test]
    fn projects_boundary_and_pattern_words() {
        let mut cases = vec![
            (0, 0),
            (0, u32::MAX),
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (1, 0xff00_00ff),
            (0x0123_4567, 0x89ab_cdef),
            (u32::MAX, 0x8000_0000),
            (0x8000_0000, 0x7fff_ffff),
        ];
        let mut rng = StdRng::seed_from_u64(0x7533_325f_786f_7263);
        for _ in 0..100 {
            cases.push((rng.gen(), rng.gen()));
        }
        for (word, constant) in cases {
            let leaf = complete_result_leaf(word, constant);
            run_with_witness(&leaf.to_bytes(), word_witness(word));
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        let leaf = complete_leaf(u32_xor_constant(MASK));
        let canonical = vec![vec![1]; 4];
        assert!(executed_success(&leaf, canonical.clone()));
        for (raw, expected_error) in [
            (vec![0x81], ExecError::Verify),
            (vec![0xff], ExecError::Verify),
            (vec![0, 1], ExecError::Verify),
            (vec![0x80], ExecError::EqualVerify),
            (vec![1, 0], ExecError::EqualVerify),
            (vec![0, 0, 0, 0, 1], ExecError::ScriptIntNumericOverflow),
        ] {
            for index in 0..4 {
                let mut witness = canonical.clone();
                witness[index] = raw.clone();
                let result = execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                assert!(
                    matches!(
                        result.outcome,
                        TapscriptOutcome::Executed(ref info)
                            if !info.success && info.error == Some(expected_error.clone())
                    ),
                    "limb {index} with {raw:02x?} produced unexpected outcome: {result:?}"
                );
            }
        }

        for input_count in 0..4 {
            let result = execute_tapscript(
                leaf.clone(),
                vec![vec![1]; input_count],
                TapscriptProfile::Consensus,
            );
            assert!(
                matches!(
                    result.outcome,
                    TapscriptOutcome::Executed(ref info)
                        if !info.success && info.error == Some(ExecError::InvalidStackOperation)
                ),
                "accepted only {input_count} input limbs: {result:?}"
            );
        }

        assert!(all_nonminimal_aliases_rejected(&leaf));

        // The historical top-limb-only validator must fail the same predicate:
        // it accepts the non-minimal alias at positions 0-2.
        let historical_mutant = complete_leaf(top_limb_only_mutant(MASK));
        assert!(!all_nonminimal_aliases_rejected(&historical_mutant));
        assert!(executed_success(&historical_mutant, canonical.clone()));
        for index in 0..4 {
            let mut witness = canonical.clone();
            witness[index] = vec![1, 0];
            let result = execute_tapscript(
                historical_mutant.clone(),
                witness,
                TapscriptProfile::Consensus,
            );
            if index < 3 {
                assert!(
                    matches!(result.outcome, TapscriptOutcome::Executed(ref info) if info.success),
                    "historical mutant did not accept limb {index}: {result:?}"
                );
            } else {
                assert!(
                    matches!(
                        result.outcome,
                        TapscriptOutcome::Executed(ref info)
                            if !info.success && info.error == Some(ExecError::EqualVerify)
                    ),
                    "historical mutant changed top-limb behavior: {result:?}"
                );
            }
        }

        // Canonical high bytes need a 0x00 sign byte and must still succeed,
        // with the correct XOR result, at every position.
        let base = 0x1234_5678u32;
        for value in [128u32, 255] {
            for index in 0..4 {
                let shift = 8 * (3 - index);
                let word = (base & !(0xff << shift)) | (value << shift);
                let mut witness = byte_word(base);
                witness[index] = scriptnum(i64::from(value));
                assert_eq!(witness, byte_word(word));
                let result = execute_tapscript(
                    complete_result_leaf(word, MASK),
                    witness,
                    TapscriptProfile::Consensus,
                );
                assert!(
                    matches!(result.outcome, TapscriptOutcome::Executed(ref info) if info.success),
                    "rejected canonical limb {value} at {index}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn drops_whole_table_and_restores_stack_state() {
        let word = 0x1020_3040;
        let run = |fragment: fn(u32) -> Script, masks: &[u32]| {
            execute_tapscript(
                state_leaf(fragment, masks, word),
                state_witness(word),
                TapscriptProfile::Consensus,
            )
        };

        let mut peaks = Vec::new();
        for masks in [&[MASK][..], &[MASK, 0x5566_7788, u32::MAX][..]] {
            let result = run(u32_xor_constant, masks);
            let TapscriptOutcome::Executed(info) = &result.outcome else {
                panic!("state leaf had no execution verdict: {result:?}");
            };
            assert!(
                info.success,
                "{} call(s) broke stack state: {result:?}",
                masks.len()
            );
            assert!(info.stack_limit_enforced);
            assert_eq!(info.final_stack.len(), 1);
            assert_eq!(info.final_stack.get(0), vec![1]);
            peaks.push(info.stats.max_nb_stack_items);
        }
        // Four sentinels plus the isolated 272-item fragment peak. Sequential
        // calls do not accumulate table items.
        assert_eq!(peaks, vec![276, 276]);

        // Leaving one table item behind still yields the correct result word,
        // but the depth check after the call must reject it.
        let result = run(undropped_table_item_mutant, &[MASK]);
        assert!(
            matches!(
                result.outcome,
                TapscriptOutcome::Executed(ref info)
                    if !info.success && info.error == Some(ExecError::EqualVerify)
            ),
            "undropped table item was not detected: {result:?}"
        );
        let mutant_output = script! {
            { undropped_table_item_mutant(MASK) }
            { u32_push(word ^ MASK) }
            { u32_equalverify() }
            OP_DEPTH 1 OP_EQUALVERIFY
            OP_DROP
            OP_TRUE
        }
        .compile_with_policy();
        assert!(executed_success(&mutant_output, byte_word(word)));
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let word = 0x1020_3040;
        let constant = 0x5566_7788;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u32_push(word) }
            { u32_xor_constant(constant) }
            { u32_push(word ^ constant) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "stack-preserving constant XOR failed: {result}"
        );
    }
}
