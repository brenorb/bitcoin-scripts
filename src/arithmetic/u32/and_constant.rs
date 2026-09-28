//! Checked bitwise AND of a byte-oriented u32 word and an embedded mask.

use super::{
    and::u32_and,
    stack::{u32_drop, u32_fromaltstack, u32_push, u32_toaltstack, verify_canonical_byte},
    xor::{u8_drop_xor_table, u8_push_xor_table},
};
use crate::support::script::{script, Script};

/// ANDs the top canonical u32 word with an embedded public mask.
///
/// The input is four most-significant-byte-first numeric limbs. Each limb is
/// checked for both the byte range and minimal ScriptNum encoding. The shared
/// Boolean table is generated and removed within the fragment.
pub fn u32_and_constant(value: u32) -> Script {
    script! {
        for _ in 0..4 {
            3 OP_ROLL
            { verify_canonical_byte() }
        }
        { u32_toaltstack() }
        { u8_push_xor_table() }
        { u32_fromaltstack() }
        { u32_push(value) }
        { u32_and(0, 1, 3) }
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
    use crate::arithmetic::u32::stack::{u32_equal, u32_equalverify, u32_push};
    use crate::support::execution::execute_script;
    use crate::support::script::ScriptCompilation;
    use crate::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    // The complete-leaf and alias-predicate helpers below mirror the
    // embedded-constant OR tests. They stay local because no shared u32
    // constant-Boolean test module exists on main.

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    fn byte_word(value: u32) -> [Vec<u8>; 4] {
        [
            scriptnum(value >> 24),
            scriptnum((value >> 16) & 0xff),
            scriptnum((value >> 8) & 0xff),
            scriptnum(value & 0xff),
        ]
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
            { u32_and_constant(mask) }
            { u32_push(word & mask) }
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

    #[test]
    fn masks_boundaries_and_patterns() {
        let mut cases = vec![
            (0, 0),
            (0, u32::MAX),
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (0x0123_4567, 0x89ab_cdef),
            (0x8000_0000, 0x7fff_ffff),
        ];
        let mut rng = StdRng::seed_from_u64(0x7533_325f_616e_6463);
        for _ in 0..100 {
            cases.push((rng.gen(), rng.gen()));
        }
        for (word, mask) in cases {
            let leaf = complete_result_leaf(word, mask);
            run_with_witness(&leaf.to_bytes(), word_witness(word));
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        let leaf = complete_leaf(u32_and_constant(0x89ab_cdef));
        let canonical = vec![vec![1]; 4];
        assert!(executed_success(&leaf, canonical.clone()));
        for (raw, expected_error) in [
            (vec![0x81], ExecError::Verify),
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

        assert!(all_nonminimal_aliases_rejected(&leaf));

        // Historical implementation: all four checks inspect the same top
        // limb, so the regression predicate above must fail for positions 0–2.
        let historical_mutant = script! {
            for _ in 0..4 {
                { verify_canonical_byte() }
            }
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_push(0x89ab_cdef) }
            { u32_and(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() }
            { u8_drop_xor_table() }
            { u32_fromaltstack() }
        };
        let historical_mutant = complete_leaf(historical_mutant);
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
        for value in [128, 255] {
            for index in 0..4 {
                let mut witness = byte_word(0x1234_5678).to_vec();
                witness[index] = scriptnum(value);
                let result = execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                assert!(
                    matches!(result.outcome, TapscriptOutcome::Executed(ref info) if info.success),
                    "rejected canonical limb {value} at {index}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let word = 0x1020_3040;
        let mask = 0x5566_7788;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u32_push(word) }
            { u32_and_constant(mask) }
            { u32_push(word & mask) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "constant AND did not preserve stack state: {result}"
        );
    }
}
