# Checked u4 embedded-equality mask

`arithmetic::u4::equality::u4_nibbles_to_eq_mask` consumes a contiguous batch
of canonical u4 nibbles and replaces each item with the numeric Boolean for
`nibble == value`. The target symbol is embedded public locking-script data,
so repeated uses do not add target witness items.

## Boundary and comparison

Every hostile nibble is range-checked before numeric equality. Generation rejects
a non-u4 target, an empty batch, and a batch over the standalone strict-stack
ceiling of 998 items. With preserved live state, callers must satisfy
`nibble_count + 2 + preserved_items <= 1000`. The fragment preserves unrelated
lower main-stack and alt-stack state and returns one mask item per input in the
original order.

The numeric range check does not enforce byte-unique ScriptNum encoding, and the
comparison uses numeric equality. Under the local `TapscriptProfile::Consensus`
profile (`require_minimal: false`, stack limit enforced), raw witness aliases
such as `[1, 0]` or `[1, 0, 0, 0]` for one and `[0x80]` or `[0, 0]` for zero
therefore produce the same mask bit as their canonical encodings. Tests check
this at every position and on the non-palindromic mask `[1, 0, 1, 0, 1, 0]`, so
both a byte-equality comparator and a reversed output schedule are rejected by
test-only mutants of the historical implementation. The local `Policy` profile
rejects the same aliases with `MinimalData`. A caller that needs canonical
witness bytes must compose the existing `verify_canonical_nibble()` boundary
before this mask.

The representative configuration uses target `5` over 16 canonical one-byte
witness nibbles. It includes range checks, numeric equality tests, and output
restoration; it excludes input pushes, the terminal predicate, unrelated live
state, and transaction context. No hints are required. The 33-byte witness is
the measured canonical fixture, not a maximum: permitted numeric aliases can be
longer, so the catalog records no maximum witness size.

The mask exposes positions, unlike the fixed-symbol occurrence counter, which
only returns one aggregate count. It also avoids the 16-item lookup table used
by parity/LSB projections, at the cost of one direct equality per input.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::equality::tests --lib
cargo test --locked --test primitive_metrics u4_eq_mask_metrics_are_current -- --exact
python3 tools/kb.py validate
```
