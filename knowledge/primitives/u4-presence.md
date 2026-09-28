# Checked u4 presence-bit projection

`arithmetic::u4::presence::u4_nibbles_to_presence_bits` consumes a contiguous
batch of numeric u4 nibbles and returns 16 Boolean items. Output item `n` is
one iff nibble `n` occurred in the input. The construction uses only numeric
equality and `OP_BOOLOR`; it does not rely on disabled bitwise opcodes.

## Boundary and comparison

Every hostile input nibble is range-checked before the 16 membership scans.
Membership uses `OP_NUMEQUAL`, so a raw witness alias yields the presence bit
of its numeric value. The regression runs complete leaves under the local
`TapscriptProfile::Consensus` profile (global numeric minimality disabled,
stack limit enforced) that check all 16 outputs in value order and end with a
single `OP_TRUE`. Its witness mixes `[0x01, 0x00]`, negative zero `[0x80]`,
`[0x02, 0x00]`, canonical 5 and `[0x0f, 0x00, 0x00, 0x00]`; the expected
vector (0, 1, 2, 5 and 15 present) is not a palindrome. A canonical control
succeeds under both local profiles, and the local `Policy` profile rejects the
alias witness with `MinimalData`. Test-only mutants that restore bytewise
`OP_EQUAL` or reverse the output order fail that leaf with `NumEqualVerify`.
The representative witness metric below uses canonical one-byte encodings only.
The input nibbles are consumed, and unrelated lower main-stack and alt-stack
state is preserved. The output is a Boolean vector rather than a packed mask,
which keeps the operation compatible with tapscript's enabled opcode set.

The representative 16-nibble all-`0x0f` boundary uses one-byte canonical
witness items and zero hints. The metric includes all 16 range checks, 256
equality checks, Boolean folds, and output restoration; it excludes input
pushes, terminal predicates, unrelated live state, and transaction context.

Evidence is `locally-reproduced`; execution is `unclassified`. The local
strict executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

This is a membership projection, not a packed bitmask or a duplicate detector
by itself: callers can compare or combine the returned bits according to their
protocol's boundary.

## Reproduction

```sh
cargo test --locked arithmetic::u4::presence::tests --lib
cargo test --locked --test primitive_metrics u4_presence_bits_metrics_are_current -- --exact
python3 tools/kb.py validate
```
