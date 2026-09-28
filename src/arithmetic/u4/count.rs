//! Fixed-symbol occurrence counts for checked u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch; callers must satisfy `batch + 3 + preserved <= 1000`.
pub const U4_COUNT_MAX_BATCH: u32 = 1_000 - 3;

/// Count occurrences of one generation-time nibble in a checked u4 batch.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | count`, where `count` is in `0..=n`.
pub fn u4_nibbles_count(value: u8, nibble_count: u32) -> Script {
    assert!(value < 16, "count target must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_COUNT_MAX_BATCH,
        "nibble-count batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { index } OP_PICK
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DROP
        }

        0
        for index in 0..nibble_count {
            { value }
            { index + 2 } OP_PICK
            OP_NUMEQUAL
            OP_ADD
        }

        OP_TOALTSTACK
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
            execution::{
                execute_raw_script_with_inputs_strict, execute_script,
                execute_script_buf_with_options,
            },
            script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
        },
    };
    use bitcoin_scriptexec::{ExecError, Options};

    fn compile_boundary(body: Script) -> Vec<u8> {
        script! {
            { body }
            for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
        }
        .compile_with_policy()
        .to_bytes()
    }

    /// Runs `alt_items` alt-stack items and `main_items` lower main-stack items
    /// around a batch of zero nibbles under the strict 1,000-item limit, then
    /// checks the count and every preserved value.
    fn run_preserved_frontier(
        main_items: u32,
        alt_items: u32,
        nibble_count: u32,
    ) -> crate::support::execution::ExecuteInfo {
        let body = script! {
            for index in 0..alt_items {
                { 70 + index as i64 } OP_TOALTSTACK
            }
            { u4_nibbles_count(0, nibble_count) }
            { nibble_count as i64 } OP_EQUALVERIFY
            for index in (0..main_items).rev() {
                { 90 + index as i64 } OP_EQUALVERIFY
            }
            for index in (0..alt_items).rev() {
                OP_FROMALTSTACK { 70 + index as i64 } OP_EQUALVERIFY
            }
            OP_TRUE
        };
        execute_raw_script_with_inputs_strict(
            compile_boundary(body),
            (0..main_items)
                .map(|index| vec![90 + index as u8])
                .chain(std::iter::repeat_n(Vec::new(), nibble_count as usize))
                .collect(),
        )
    }

    #[test]
    fn exact_stack_frontier_admits_max_preserved_and_rejects_one_more() {
        for nibble_count in [1, 16, 500, U4_COUNT_MAX_BATCH] {
            let max_preserved = (U4_COUNT_MAX_BATCH - nibble_count) as usize;
            for alt_items in [0usize, 1] {
                let script = compile_boundary(script! {
                    for _ in 0..alt_items { 77 OP_TOALTSTACK }
                    { u4_nibbles_count(4, nibble_count) }
                    for _ in 0..alt_items { OP_FROMALTSTACK }
                });
                for (preserved, fits) in [(max_preserved, true), (max_preserved + 1, false)] {
                    let Some(main_items) = preserved.checked_sub(alt_items) else {
                        continue;
                    };
                    let witness = std::iter::repeat_n(vec![99u8], main_items)
                        .chain(std::iter::repeat_n(vec![4u8], nibble_count as usize))
                        .collect();
                    let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
                    let case = format!(
                        "batch {nibble_count}, main {main_items}, alt {alt_items}, preserved {preserved}"
                    );
                    if fits {
                        assert!(result.error.is_none(), "{case} failed: {result}");
                        assert_eq!(result.stats.max_nb_stack_items, 1_000, "{case}");
                        assert_eq!(result.final_stack.len(), preserved + 1, "{case}");
                    } else {
                        assert_eq!(result.error, Some(ExecError::StackSize), "{case}");
                    }
                }
            }
        }
    }

    #[test]
    fn preserved_state_stack_frontier_is_exact() {
        for (main_items, alt_items) in [(1, 0), (0, 1), (1, 1), (3, 2)] {
            let preserved = main_items + alt_items;
            let maximum = U4_COUNT_MAX_BATCH - preserved;
            let accepted = run_preserved_frontier(main_items, alt_items, maximum);
            assert!(
                accepted.success,
                "preserved frontier main={main_items} alt={alt_items} n={maximum} failed: {accepted}"
            );
            assert_eq!(accepted.stats.max_nb_stack_items, 1_000);

            let rejected = run_preserved_frontier(main_items, alt_items, maximum + 1);
            assert_eq!(
                rejected.error,
                Some(ExecError::StackSize),
                "preserved frontier main={main_items} alt={alt_items} n={} was not rejected: {rejected}",
                maximum + 1
            );
        }
    }

    #[test]
    fn counts_boundary_and_repeated_symbols() {
        for (input, target, expected) in [
            ("0123456789abcdef", 0, 1),
            ("001122", 1, 2),
            ("ffff", 15, 4),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(input) }
                { u4_nibbles_count(target, input.len() as u32) }
                { expected } OP_EQUAL
            });
            assert!(result.success, "symbol count failed for {input}: {result}");
        }
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_count(0, 1) }
                OP_DROP
                OP_TRUE
            });
            assert_eq!(
                result.error,
                Some(ExecError::Verify),
                "accepted invalid nibble {invalid}: {result}"
            );
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_count(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_count(0, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_count(0, U4_COUNT_MAX_BATCH + 1) }).is_err()
        );

        let result = execute_raw_script_with_inputs_strict(
            script! {
                { u4_nibbles_count(0, U4_COUNT_MAX_BATCH) }
                { U4_COUNT_MAX_BATCH as i64 } OP_EQUALVERIFY
                OP_TRUE
            }
            .compile_with_policy()
            .to_bytes(),
            vec![Vec::new(); U4_COUNT_MAX_BATCH as usize],
        );
        assert!(result.success, "997-item count failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        for count in [U4_COUNT_MAX_BATCH + 1] {
            assert!(std::panic::catch_unwind(|| u4_nibbles_count(0, count)).is_err());
        }
    }

    #[test]
    fn counts_nonminimal_numeric_encodings_and_preserves_boundary_state() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let checked_script = script! {
            { u4_nibbles_count(1, 3) }
            2 OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let result = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(checked_script),
            vec![vec![1, 0], vec![1], vec![0x80]],
            options.clone(),
        )
        .expect("nonminimal count execution");
        assert!(result.success, "nonminimal numeric count failed: {result}");

        for (preserved, on_altstack) in [(996, false), (996, true)] {
            let script = if on_altstack {
                script! {
                    77 OP_TOALTSTACK
                    for _ in 0..preserved { 0 }
                    { u4_nibbles_count(0, preserved) }
                    { preserved as i64 } OP_EQUALVERIFY
                    OP_FROMALTSTACK 77 OP_EQUALVERIFY
                    OP_TRUE
                }
            } else {
                script! {
                    77
                    for _ in 0..preserved { 0 }
                    { u4_nibbles_count(0, preserved) }
                    { preserved as i64 } OP_EQUALVERIFY
                    77 OP_EQUALVERIFY
                    OP_TRUE
                }
            };
            let result = execute_script(script);
            assert!(
                result.success,
                "996-item count changed preserved state (alt={on_altstack}): {result}"
            );
        }

        let result = execute_script(script! {
            77
            for _ in 0..U4_COUNT_MAX_BATCH { 0 }
            { u4_nibbles_count(0, U4_COUNT_MAX_BATCH) }
            { U4_COUNT_MAX_BATCH as i64 } OP_EQUALVERIFY
            OP_TRUE
        });
        assert_eq!(result.error, Some(ExecError::StackSize));
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            0 1 0
            { u4_nibbles_count(0, 3) }
            2 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "symbol count changed surrounding state: {result}"
        );
    }
}
