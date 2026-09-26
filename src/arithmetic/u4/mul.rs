use super::stack::u4_drop;
use crate::support::script::*;

/// Pushes the 16x16 table for multiplication modulo 16.
pub fn u4_push_full_product_table() -> Script {
    script! {
        for a in (0..16).rev() {
            for b in (0..16).rev() {
                { (a * b) % 16 }
            }
        }
    }
}

/// Drops a full modulo-16 product table.
pub fn u4_drop_full_product_table() -> Script {
    u4_drop(256)
}

/// Multiplies two canonical u4 values modulo 16.
///
/// The product table must be below the two inputs. The table remains below the
/// result so callers can reuse it or remove it with `u4_drop_full_product_table`.
pub fn u4_mul_mod16() -> Script {
    script! {
        // Both witness values must be valid table coordinates.
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        1 OP_PICK 0 16 OP_WITHIN OP_VERIFY

        // Form 16*a+b, with a below b on entry.
        OP_SWAP
        for _ in 0..4 {
            OP_DUP OP_ADD
        }
        OP_ADD
        OP_PICK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::run_with_witness;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn multiplication_script() -> Vec<u8> {
        multiplication_script_with(u4_mul_mod16())
    }

    fn multiplication_script_with(multiply: Script) -> Vec<u8> {
        script! {
            OP_TOALTSTACK
            OP_TOALTSTACK
            { u4_push_full_product_table() }
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            { multiply }
            OP_TOALTSTACK
            { u4_drop_full_product_table() }
            OP_FROMALTSTACK
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes()
    }

    #[test]
    fn multiplies_every_nibble_pair() {
        let script = multiplication_script();
        for a in 0..16 {
            for b in 0..16 {
                run_with_witness(&script, [(a * b) % 16, a, b]);
            }
        }
    }

    #[test]
    fn preserves_every_product_table_entry_across_all_pairs_and_cleanup() {
        let result = execute_script(script! {
            { u4_push_full_product_table() }

            for a in 0..16 {
                for b in 0..16 {
                    { a }
                    { b }
                    { u4_mul_mod16() }
                    OP_TOALTSTACK
                }
            }

            // Verify each actual resident entry after all lookups, before
            // cleanup drops the table. The table remains on the main stack.
            for table_index in 0..256 {
                { table_index }
                OP_PICK
                { ((table_index / 16) * (table_index % 16)) % 16 }
                OP_EQUALVERIFY
            }

            { u4_drop_full_product_table() }

            for a in (0..16).rev() {
                for b in (0..16).rev() {
                    OP_FROMALTSTACK
                    { (a * b) % 16 }
                    OP_EQUALVERIFY
                }
            }

            OP_TRUE
        });
        assert!(
            result.success,
            "product table values, order, reuse, or cleanup changed: {result}"
        );
        assert!(result.stack_limit_enforced);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    #[test]
    fn preserves_product_table_across_all_pairs() {
        let result = execute_script(script! {
            { u4_push_full_product_table() }
            for a in 0..16 {
                for b in 0..16 {
                    { a }
                    { b }
                    { u4_mul_mod16() }
                    OP_TOALTSTACK
                }
            }
            { u4_drop_full_product_table() }
            for a in (0..16).rev() {
                for b in (0..16).rev() {
                    OP_FROMALTSTACK
                    { (a * b) % 16 }
                    OP_EQUALVERIFY
                }
            }
            OP_TRUE
        });
        assert!(
            result.success,
            "product table was not reusable across all pairs: {result}"
        );
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        let script = multiplication_script();
        for &(a, b, ref expected_error) in &[
            (-1, 0, ExecError::Verify),
            (16, 0, ExecError::Verify),
            (0, -1, ExecError::Verify),
            (0, 16, ExecError::Verify),
            (
                i64::from(i32::MAX) + 1,
                0,
                ExecError::ScriptIntNumericOverflow,
            ),
            (
                0,
                i64::from(i32::MAX) + 1,
                ExecError::ScriptIntNumericOverflow,
            ),
        ] {
            let witness = [0, a, b]
                .into_iter()
                .map(|value| {
                    let mut bytes = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
                    bytes[..len].to_vec()
                })
                .collect();
            let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
            assert!(
                !result.success,
                "accepted invalid pair ({a}, {b}): {result}"
            );
            assert!(result.stack_limit_enforced);
            assert_eq!(
                result.error,
                Some(expected_error.clone()),
                "pair ({a}, {b}): {result}"
            );
        }
    }

    #[test]
    fn faithful_historical_add_chain_is_caught_by_the_positive_product_assertion() {
        let valid_script = multiplication_script();
        // The exact pre-fix sequence from 1a9c4c9: four bare ADDs and the
        // trailing SWAP/ADD route the table entry instead of forming 16*a+b.
        let historical_mul = script! {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            1 OP_PICK 0 16 OP_WITHIN OP_VERIFY
            OP_SWAP
            OP_DUP
            OP_ADD
            OP_ADD
            OP_ADD
            OP_ADD
            OP_SWAP
            OP_ADD
            OP_PICK
        };
        let historical_script = multiplication_script_with(historical_mul);

        // The control and faithful mutant use the same complete leaf builder,
        // strict tapscript helper, and run_with_witness success contract.
        run_with_witness(&valid_script, [0, 0, 0]);
        let historical = execute_raw_script_with_inputs_strict(
            historical_script.clone(),
            [0, 0, 0]
                .map(|value| {
                    let mut bytes = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut bytes, value);
                    bytes[..len].to_vec()
                })
                .to_vec(),
        );
        assert!(historical.stack_limit_enforced);
        assert_eq!(historical.error, Some(ExecError::InvalidStackOperation));
        assert_eq!(
            historical.last_opcode,
            Some(bitcoin::opcodes::all::OP_2DROP)
        );

        let caught = std::panic::catch_unwind(|| {
            run_with_witness(&historical_script, [0, 0, 0]);
        });
        assert!(
            caught.is_err(),
            "positive product assertion accepted historical mutant"
        );
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_9 OP_TOALTSTACK
            7
            15
            3
            5
            OP_TOALTSTACK
            OP_TOALTSTACK
            { u4_push_full_product_table() }
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            { u4_mul_mod16() }
            OP_TOALTSTACK
            { u4_drop_full_product_table() }
            OP_FROMALTSTACK
            OP_EQUALVERIFY
            7 OP_EQUALVERIFY
            OP_FROMALTSTACK 9 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "u4 multiplication changed surrounding state: {result}"
        );
    }
}
