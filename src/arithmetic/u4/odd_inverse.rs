//! Checked inversion of odd u4 values modulo 16.

use super::stack::u4_drop;
use crate::support::script::*;

/// Number of entries kept by the odd-unit inverse table.
pub const U4_ODD_INVERSE_TABLE_ITEMS: u32 = 16;

fn inverse(value: u32) -> u32 {
    match value {
        1 => 1,
        3 => 11,
        5 => 13,
        7 => 7,
        9 => 9,
        11 => 3,
        13 => 5,
        15 => 15,
        _ => 0,
    }
}

/// Push the lookup table for odd `value^-1 mod 16`, indexed by `value`.
pub fn u4_push_odd_inverse_table() -> Script {
    script! {
        for value in (0..U4_ODD_INVERSE_TABLE_ITEMS).rev() {
            { inverse(value) }
        }
    }
}

/// Remove a table pushed by [`u4_push_odd_inverse_table`].
pub fn u4_drop_odd_inverse_table() -> Script {
    u4_drop(U4_ODD_INVERSE_TABLE_ITEMS)
}

/// Check an odd u4 value and replace it with its multiplicative inverse modulo 16.
///
/// Before: `preserved | table[16] | value`\
/// After: `preserved | table[16] | value^-1 mod 16`
pub fn u4_odd_inverse_mod16() -> Script {
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        OP_PICK
        OP_DUP OP_0NOTEQUAL OP_VERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_script, execute_script_buf_with_options, ExecuteInfo};
    use crate::support::script::ScriptCompilation;
    use bitcoin_scriptexec::{ExecError, Options};

    fn scriptnum(value: i32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
        bytes[..length].to_vec()
    }

    fn assert_complete_contract(result: &ExecuteInfo) {
        assert!(result.success, "complete inverse contract failed: {result}");
        assert_eq!(
            result.error, None,
            "successful contract has an error: {result}"
        );
        assert!(
            result.stack_limit_enforced,
            "contract did not enforce the tapscript stack limit: {result}"
        );
        assert_eq!(
            result.final_stack.len(),
            1,
            "contract must leave a clean stack: {result}"
        );
        assert_eq!(
            result.final_stack.get(0),
            vec![1],
            "contract must leave OP_TRUE: {result}"
        );
    }

    fn assert_table_values() -> Script {
        script! {
            for (index, expected) in [0, 1, 0, 11, 0, 13, 0, 7, 0, 9, 0, 3, 0, 5, 0, 15].iter().enumerate() {
                { index as u32 } OP_PICK
                { *expected }
                OP_EQUALVERIFY
            }
        }
    }

    fn strict_options() -> Options {
        Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        }
    }

    fn complete_input_cleanup_script() -> bitcoin::ScriptBuf {
        script! {
            99 OP_TOALTSTACK
            OP_TOALTSTACK
            { u4_push_odd_inverse_table() }
            OP_FROMALTSTACK
            { u4_odd_inverse_mod16() }
            OP_TOALTSTACK
            { assert_table_values() }
            { u4_drop_odd_inverse_table() }
            OP_FROMALTSTACK OP_DROP
            OP_FROMALTSTACK 99 OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn run_input_and_cleanup(value: i32, options: Options) -> ExecuteInfo {
        run_witness_and_cleanup(scriptnum(value), options)
    }

    fn run_witness_and_cleanup(witness_item: Vec<u8>, options: Options) -> ExecuteInfo {
        execute_script_buf_with_options(
            complete_input_cleanup_script(),
            vec![witness_item],
            options,
        )
        .expect("complete inverse execution initialization")
    }

    #[test]
    fn inverts_every_odd_nibble_and_preserves_surrounding_state() {
        for (value, expected) in [
            (1, 1),
            (3, 11),
            (5, 13),
            (7, 7),
            (9, 9),
            (11, 3),
            (13, 5),
            (15, 15),
        ] {
            // Construct an independent expected comparison in the same leaf
            // so the final success predicate checks the actual lookup result.
            let result = crate::support::execution::execute_script_with_inputs_strict(
                script! {
                    99 OP_TOALTSTACK
                    OP_TOALTSTACK
                    { u4_push_odd_inverse_table() }
                    OP_FROMALTSTACK
                    { u4_odd_inverse_mod16() }
                    OP_TOALTSTACK
                    { assert_table_values() }
                    { u4_drop_odd_inverse_table() }
                    OP_FROMALTSTACK
                    { expected }
                    OP_EQUALVERIFY
                    OP_FROMALTSTACK
                    99 OP_EQUALVERIFY
                    OP_TRUE
                },
                vec![scriptnum(value as i32)],
            );
            assert_complete_contract(&result);
        }
    }

    #[test]
    fn preserves_product_table_across_all_odd_queries() {
        let query = u4_odd_inverse_mod16();
        let result = run_table_contract(query);
        assert_complete_contract(&result);
    }

    fn run_table_contract(query: Script) -> ExecuteInfo {
        execute_script(script! {
            42
            99 OP_TOALTSTACK
            { u4_push_odd_inverse_table() }
            for (value, _) in [(1, 1), (3, 11), (5, 13), (7, 7), (9, 9), (11, 3), (13, 5), (15, 15)] {
                { value }
                { query.clone() }
                OP_TOALTSTACK
            }
            { assert_table_values() }
            { u4_drop_odd_inverse_table() }
            for expected in [15, 5, 3, 9, 7, 13, 11, 1] {
                OP_FROMALTSTACK
                { expected }
                OP_EQUALVERIFY
            }
            42 OP_EQUALVERIFY
            OP_FROMALTSTACK 99 OP_EQUALVERIFY
            OP_TRUE
        })
    }

    #[test]
    fn historical_table_consumption_mutant_fails_the_same_contract_assertion() {
        let mutant_query = script! {
            { u4_odd_inverse_mod16() }
            // Faithful mutation from pre-fix source 963e9aefb5a214eb323e750e45301e8412856945.
            OP_SWAP OP_DROP
        };
        let result = run_table_contract(mutant_query);
        assert_eq!(result.error, Some(ExecError::Verify));
        let assertion = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_complete_contract(&result)
        }));
        assert!(
            assertion.is_err(),
            "mutant passed the complete contract assertion"
        );
    }

    #[test]
    fn rejects_even_and_out_of_range_values() {
        let options = strict_options();
        let valid_control = run_input_and_cleanup(1, options.clone());
        assert_complete_contract(&valid_control);
        for value in [0, 2, 4, 6, 8, 10, 12, 14, 16, -1] {
            let result = run_input_and_cleanup(value, options.clone());
            assert_eq!(
                result.error,
                Some(ExecError::Verify),
                "unexpected rejection for {value}: {result}"
            );
        }
        let oversized_num = run_witness_and_cleanup(vec![0, 0, 0, 0, 1], options.clone());
        assert_eq!(
            oversized_num.error,
            Some(ExecError::ScriptIntNumericOverflow)
        );
        let oversized_item = run_witness_and_cleanup(vec![0; 521], options);
        assert_eq!(oversized_item.error, Some(ExecError::PushSize));
    }
}
