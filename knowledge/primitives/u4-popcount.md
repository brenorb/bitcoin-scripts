# Checked u4 population-count projection

`arithmetic::u4::popcount::u4_nibbles_to_popcount` consumes a contiguous batch
of numeric nibbles, proves each value is in `0..=15`, and replaces it with its
Hamming weight (`0..=4`). It is a compact bridge for consumers that need a
per-nibble set-bit count without expanding all four bits.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | weight[0] | ... | weight[n-1]`, with the last
  weight on top.
- **Evidence:** `locally-reproduced` by exhaustive 16-value tests,
  malformed-input and batch-boundary tests, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not a dynamic opcode
  or deployment claim.
- **Execution class:** `unclassified`; no Bitcoin Core consensus or relay-policy
  transaction has validated this fragment.

The generated 16-item table is kept on the main stack while each input is
range-checked and looked up, then removed before outputs are restored. The
standalone batch ceiling is 982 input items before unrelated stack state is
accounted for. Numeric range checks do not establish byte-unique ScriptNum
encoding, and the fragment does not provide a terminal predicate or clean-stack
guarantee.

## Research question and boundary

Can a checked per-nibble Hamming-weight projection add information beyond the
existing parity/LSB projections without increasing the fixed lookup, witness,
or stack cost? The hypothesis is that a generated 16-item table can return
`0..=4` with the same 440-byte, 50-item, zero-hint profile. The comparison
objective is the closest u4 parity projection and the existing byte-table
`u32_popcount` construction, under the same fragment-only boundary.

The threat model treats every input ScriptNum as hostile: values outside
`0..=15` must fail before `OP_PICK`, while non-minimal encodings remain outside
this fragment's claims. Hard constraints are the 1,000-item combined
main/alt-stack limit, deterministic table generation, no witness hints, and no
consensus or relay-policy assumption. Execution is therefore `unclassified`.

Compared with `u4_nibbles_to_parity`, population count preserves more
information while keeping the same table, witness, and stack profile. Compared
with `u32_popcount`, it is a per-nibble projection and avoids the 256-entry
byte table when the surrounding representation is already u4.

Run:

```sh
cargo test --locked arithmetic::u4::popcount
cargo test --locked --test primitive_metrics u4_popcount_metrics_are_current
python3 tools/kb.py validate
```
