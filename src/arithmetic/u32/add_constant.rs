//! Checked addition of a byte-oriented u32 word and an embedded constant.

use super::{
    add::u32_add_drop,
    stack::{u32_push, verify_canonical_byte},
};
use crate::support::script::{script, Script};

/// Adds an embedded constant to the top canonical u32 word modulo `2^32`.
///
/// The input is four most-significant-byte-first numeric limbs. Each limb is
/// checked for both the byte range and minimal ScriptNum encoding. The
/// constant is public script data, so it contributes no witness items.
pub fn u32_add_constant(value: u32) -> Script {
    script! {
        for _ in 0..4 {
            3 OP_ROLL
            { verify_canonical_byte() }
        }
        { u32_push(value) }
        { u32_add_drop(0, 1) }
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

    /// Consumes the four output limbs and leaves `OP_TRUE`, so a success is a
    /// complete local leaf verdict rather than a truthy leftover limb.
    fn complete_leaf(fragment: Script) -> ScriptBuf {
        script! {
            { fragment }
            { u32_drop() }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn complete_result_leaf(word: u32, constant: u32) -> ScriptBuf {
        leaf_expecting(constant, word.wrapping_add(constant))
    }

    fn leaf_expecting(constant: u32, expected: u32) -> ScriptBuf {
        script! {
            { u32_add_constant(constant) }
            { u32_push(expected) }
            { u32_equal() }
            OP_VERIFY
            OP_TRUE
        }
        .compile_with_policy()
    }

    /// Limb-wise addition modulo 256 with every inter-limb carry discarded.
    fn carry_free_sum(word: u32, constant: u32) -> u32 {
        u32::from_be_bytes(std::array::from_fn(|i| {
            word.to_be_bytes()[i].wrapping_add(constant.to_be_bytes()[i])
        }))
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
    fn adds_boundaries_wraps_and_carries() {
        let mut cases = vec![
            // No carry at any boundary.
            (0, 0),
            (0, u32::MAX),
            (0x7f7f_7f7f, 0x8080_8080),
            (0x0123_4567, 0x89ab_cdef),
            // Wraps modulo 2^32.
            (u32::MAX, 1),
            (u32::MAX, 0x80),
            (u32::MAX, u32::MAX),
            (1, u32::MAX),
            (0x8000_0000, 0x8000_0000),
            (0xff00_0000, 0x0100_0000),
            (0x7fff_ffff, 1),
        ];
        for boundary in 1..4 {
            let low_shift = 8 * (boundary - 1);
            let low_mask = (1u32 << (8 * boundary)) - 1;
            // Carry crosses only this limb boundary.
            cases.push((0xff << low_shift, 1 << low_shift));
            // Carry ripples through every lower limb into this boundary.
            cases.push((low_mask, 1));
            // Carry-in alone overflows limb `boundary`: 0xff + 0 + carry.
            cases.push((
                0xff << (8 * boundary) | 0x80 << low_shift,
                0x80 << low_shift,
            ));
            // Complementary limbs sum to 0xff and a carry-in overflows them.
            cases.push((
                0x5a << (8 * boundary) | 0xff << low_shift,
                0xa5 << (8 * boundary) | 1 << low_shift,
            ));
        }
        let mut rng = StdRng::seed_from_u64(0x7533_325f_6164_6463);
        for _ in 0..100 {
            cases.push((rng.gen(), rng.gen()));
        }
        for (word, constant) in cases {
            let leaf = complete_result_leaf(word, constant);
            run_with_witness(&leaf.to_bytes(), word_witness(word));
        }
    }

    #[test]
    fn carry_vectors_match_reference() {
        // Expected outputs are pinned literally, one vector per carry path.
        // Each leaf must reject the carry-free limb-wise sum, so the vectors
        // distinguish a correct carry chain from one that drops carries.
        for (word, constant, expected) in [
            (u32::MAX, 1, 0),
            (0x0000_00ff, 1, 0x0000_0100),
            (0x0000_ff00, 0x0000_0100, 0x0001_0000),
            (0x00ff_0000, 0x0001_0000, 0x0100_0000),
            (0x0000_ffff, 1, 0x0001_0000),
            (0x00ff_ffff, 1, 0x0100_0000),
            (0x0000_ff80, 0x80, 0x0001_0000),
            (0x00ff_8000, 0x8000, 0x0100_0000),
            (0xff80_0000, 0x0080_0000, 0),
            (0xffff_ffff, 0xffff_ffff, 0xffff_fffe),
        ] {
            assert_eq!(word.wrapping_add(constant), expected);
            let carry_free = carry_free_sum(word, constant);
            assert_ne!(carry_free, expected);
            let leaf = leaf_expecting(constant, expected);
            run_with_witness(&leaf.to_bytes(), word_witness(word));
            let result = execute_tapscript(
                leaf_expecting(constant, carry_free),
                byte_word(word).to_vec(),
                TapscriptProfile::Consensus,
            );
            assert!(
                matches!(
                    result.outcome,
                    TapscriptOutcome::Executed(ref info)
                        if !info.success && info.error == Some(ExecError::Verify)
                ),
                "{word:08x}+{constant:08x} matched carry-free sum {carry_free:08x}: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        let leaf = complete_leaf(u32_add_constant(0x89ab_cdef));
        let canonical = vec![vec![1]; 4];
        assert!(executed_success(&leaf, canonical.clone()));
        for (raw, expected_error) in [
            (vec![0x81], ExecError::Verify),
            (vec![0, 1], ExecError::Verify),
            (vec![0x80], ExecError::EqualVerify),
            (vec![0, 0x80], ExecError::EqualVerify),
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

        // Historical implementation at 3c1cf46: all four checks inspect the
        // same top limb, so the regression predicate above must fail for
        // positions 0-2.
        let historical_mutant = complete_leaf(script! {
            for _ in 0..4 {
                { verify_canonical_byte() }
            }
            { u32_push(0x89ab_cdef) }
            { u32_add_drop(0, 1) }
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

        for value in [0, 1, 127, 128, 255] {
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
        let constant = 0x5566_7788;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u32_push(word) }
            { u32_add_constant(constant) }
            { u32_push(word.wrapping_add(constant)) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "constant add did not preserve stack state: {result}"
        );
    }
}
