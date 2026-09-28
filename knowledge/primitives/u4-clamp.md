# Checked u4 embedded-cap clamp

`arithmetic::u4::clamp::u4_nibbles_to_clamp` consumes a contiguous batch of
canonical u4 nibbles and replaces each item with `min(nibble, maximum)`. The
cap is embedded public locking-script data, so it adds no repeated witness
items.

## Boundary and comparison

Every hostile nibble is range-checked before the cap comparison. Generation
rejects a non-u4 cap, an empty batch, and a batch over the standalone
strict-stack ceiling of 998 items. With preserved live state, callers must
satisfy `nibble_count + 2 + preserved_items <= 1000`. The fragment preserves
unrelated lower main-stack and alt-stack state and returns values in the
original order.

It processes the top input first and stages each result on the alt stack, so
restoration returns the documented bottom-to-top order. Tests check this with
distinct runtime witness nibbles and distinct preserved main and alt items;
the earlier bottom-first `OP_ROLL` schedule returns the exact reversed vector
and fails that test. The frontier test covers batches 1, 16, 997, and 998. At
equality, with preserved items on the main stack, the alt stack, or both, it
reaches a combined 1,000-item peak and leaves preserved state intact. One more
preserved item fails with `StackSize`. The fragment adds zero hint items, so
only the batch, its two temporary items, and the caller's preserved items count
against the 1,000-item limit.

The numeric range check does not enforce byte-unique ScriptNum encoding. A
permissive execution profile accepts aliases such as `[1, 0]` and `[0x80]`;
values at or below the cap preserve those original bytes, while values above
the cap are replaced by the embedded cap. A caller that needs canonical
witness bytes must compose the existing `verify_canonical_nibble()` boundary
before this clamp.

The representative configuration uses cap `4` over 16 canonical one-byte
witness nibbles. It includes range checks, cap comparisons, replacement, and
output restoration; it excludes input pushes, the terminal predicate,
unrelated live state, and transaction context. No hints are required.

Unlike the threshold masks and trichotomy classifier, this construction
returns normalized bounded digits. It is useful before a fixed-domain lookup
when out-of-range values should collapse to one public endpoint, but it does
not by itself prove that such collapsing is protocol-safe.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::clamp::tests --lib
cargo test --locked --test primitive_metrics u4_clamp_metrics_are_current -- --exact
python3 tools/kb.py validate
```
