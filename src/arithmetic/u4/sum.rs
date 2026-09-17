//! Checked modulo-16 reduction for a batch of u4 limbs.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

/// Persistent entries in the table for sums from 0 through 30.
pub const U4_SUM_TABLE_ITEMS: u32 = 31;

/// Conservative largest batch under the combined stack-item limit.
pub const U4_SUM_MAX_BATCH: u32 = 1_000 - U4_SUM_TABLE_ITEMS - 4;

fn push_sum_table() -> Script {
    script! {
        for value in (0..U4_SUM_TABLE_ITEMS).rev() {
            { value & 0xf }
        }
    }
}

/// Consume canonical nibbles and return their sum modulo 16.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | (sum(nibble) mod 16)`. The table remains live
/// while each input is checked and reduced, then is removed.
pub fn u4_nibbles_to_sum_mod16(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_SUM_MAX_BATCH,
        "nibble-sum batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        0 OP_TOALTSTACK
        { push_sum_table() }
        for _ in 0..nibble_count {
            { U4_SUM_TABLE_ITEMS } OP_ROLL
            { verify_canonical_nibble() }
            OP_FROMALTSTACK
            OP_ADD
            OP_PICK
            OP_TOALTSTACK
        }
        { u4_drop(U4_SUM_TABLE_ITEMS) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs_strict;
    use crate::support::script::script;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut encoded = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut encoded, value);
        encoded[..length].to_vec()
    }

    fn check(values: &[u8]) {
        let expected = values.iter().map(|value| u32::from(*value)).sum::<u32>() % 16;
        let result = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_sum_mod16(values.len() as u32) }
                { expected }
                OP_EQUAL
            },
            values
                .iter()
                .map(|value| scriptnum(i64::from(*value)))
                .collect(),
        );
        assert!(result.success, "sum failed for {values:?}: {result}");
    }

    #[test]
    fn reduces_boundary_and_mixed_batches() {
        check(&[0]);
        check(&[15]);
        check(&[15, 15, 15, 15]);
        check(&(0..16).collect::<Vec<_>>());
        check(&[1, 7, 8, 15, 2, 14, 3, 13]);
    }

    #[test]
    fn preserves_unrelated_main_and_altstack_items() {
        let result = crate::support::execution::execute_script(script! {
            11 OP_TOALTSTACK
            22
            1 2 3 4
            { u4_nibbles_to_sum_mod16(4) }
            10 OP_EQUALVERIFY
            22 OP_EQUALVERIFY
            OP_FROMALTSTACK
            11 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_invalid_numeric_nibbles_in_every_position() {
        for position in 0..4 {
            let mut values = [0i64; 4];
            values[position] = if position % 2 == 0 { -1 } else { 16 };
            let result = crate::support::execution::execute_script(script! {
                { values[0] }
                { values[1] }
                { values[2] }
                { values[3] }
                { u4_nibbles_to_sum_mod16(4) }
                OP_DROP OP_TRUE
            });
            assert!(
                !result.success,
                "accepted invalid nibble at position {position}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_zero_in_every_position() {
        for position in 0..4 {
            let mut witness = vec![scriptnum(0); 4];
            witness[position] = vec![0, 0];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_nibbles_to_sum_mod16(4) }
                    OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(
                !result.success,
                "accepted noncanonical nibble at position {position}"
            );
        }
    }

    #[test]
    fn rejects_invalid_batch_sizes() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_sum_mod16(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| u4_nibbles_to_sum_mod16(U4_SUM_MAX_BATCH + 1)).is_err()
        );
    }
}
