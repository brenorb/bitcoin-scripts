//! Checked subtraction of a byte-oriented u32 word and an embedded constant.

use super::{
    stack::{u32_push, verify_canonical_byte},
    sub::u32_sub_drop,
};
use crate::support::script::{script, Script};

/// Subtracts an embedded constant from the top canonical u32 word modulo
/// `2^32`.
///
/// The input is four most-significant-byte-first numeric limbs. Each limb is
/// checked for both the byte range and minimal ScriptNum encoding. The
/// constant is public script data, so it contributes no witness items.
pub fn u32_sub_constant(value: u32) -> Script {
    script! {
        for _ in 0..4 {
            3 OP_ROLL
            { verify_canonical_byte() }
        }
        { u32_push(value) }
        { u32_sub_drop(1, 0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::arithmetic::u32::stack::{u32_drop, u32_equal, u32_equalverify};
    use crate::support::execution::execute_script;
    use crate::support::script::ScriptCompilation;
    use crate::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    const CONSTANT: u32 = 0x89ab_cdef;

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

    /// Complete leaf: consume all four outputs, then leave exactly `OP_TRUE`.
    fn complete_leaf(fragment: Script) -> ScriptBuf {
        script! {
            { fragment }
            { u32_drop() }
            OP_TRUE
        }
        .compile_with_policy()
    }

    /// Complete leaf that also checks the four output limbs against the
    /// independently computed `expected` word.
    fn complete_result_leaf(constant: u32, expected: u32) -> ScriptBuf {
        script! {
            { u32_sub_constant(constant) }
            { u32_push(expected) }
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
    fn subtracts_boundaries_and_wraps() {
        // (word, constant, expected): explicit wrap and borrow vectors.
        let mut cases = vec![
            // One borrow across exactly one limb boundary (low, middle, high);
            // listed first so a dropped borrow reports its own boundary.
            (0x0000_0100, 0x0000_0001, 0x0000_00ff),
            (0x0001_0000, 0x0000_0100, 0x0000_ff00),
            (0x0100_0000, 0x0001_0000, 0x00ff_0000),
            // Identities and the 0xffffffff boundary.
            (0, 0, 0),
            (u32::MAX, 0, u32::MAX),
            (u32::MAX, u32::MAX, 0),
            (u32::MAX, 1, 0xffff_fffe),
            (0xffff_fffe, u32::MAX, u32::MAX),
            (0x0101_0101, 0x0101_0101, 0),
            // 0 - c wraps modulo 2^32.
            (0, 1, u32::MAX),
            (0, 0x80, 0xffff_ff80),
            (0, 0x100, 0xffff_ff00),
            (0, 0x1_0000, 0xffff_0000),
            (0, 0x100_0000, 0xff00_0000),
            (0, 0x8000_0000, 0x8000_0000),
            (0, u32::MAX, 1),
            (1, u32::MAX, 2),
            // Borrow propagating through two and three boundaries.
            (0x0001_0000, 0x0000_0001, 0x0000_ffff),
            (0x0100_0000, 0x0000_0001, 0x00ff_ffff),
            (0x0100_0000, 0x0000_0100, 0x00ff_ff00),
            // Borrow out of the top limb (wrap) without and with lower borrows.
            (0x0000_0000, 0x0100_0000, 0xff00_0000),
            (0x00ff_ffff, 0x0100_0000, 0xffff_ffff),
            (0x0000_00ff, 0x0000_0100, 0xffff_ffff),
            // Previously covered sign/midpoint and mixed patterns.
            (0x7fff_ffff, 1, 0x7fff_fffe),
            (0x8000_0000, 1, 0x7fff_ffff),
            (0x8000_0000, 0x8000_0000, 0),
            (0x0123_4567, 0x89ab_cdef, 0x7777_7778),
        ];
        for &(word, constant, expected) in &cases {
            assert_eq!(word.wrapping_sub(constant), expected, "bad vector");
        }
        let mut rng = StdRng::seed_from_u64(0x7533_325f_7375_6263);
        for _ in 0..100 {
            let (word, constant): (u32, u32) = (rng.gen(), rng.gen());
            cases.push((word, constant, word.wrapping_sub(constant)));
        }
        for (word, constant, expected) in cases {
            let leaf = complete_result_leaf(constant, expected);
            run_with_witness(&leaf.to_bytes(), word_witness(word));
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        let leaf = complete_leaf(u32_sub_constant(CONSTANT));
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

        // Historical implementation shape: all four checks inspect the same
        // top limb, so the regression predicate above must fail for positions
        // 0-2 while the canonical control still succeeds.
        let historical_mutant = complete_leaf(script! {
            for _ in 0..4 {
                { verify_canonical_byte() }
            }
            { u32_push(CONSTANT) }
            { u32_sub_drop(1, 0) }
        });
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

        // Canonical controls at every position, including one-byte and
        // two-byte ScriptNum boundaries, must succeed.
        for value in [0, 127, 128, 255] {
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
        for (word, constant) in [(0x1020_3040, 0x5566_7788), (0, 1), (0, u32::MAX)] {
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                { u32_push(word) }
                { u32_sub_constant(constant) }
                { u32_push(word.wrapping_sub(constant)) }
                { u32_equalverify() }
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(
                result.success,
                "constant sub did not preserve stack state for {word:08x}-{constant:08x}: {result}"
            );
        }
    }
}
