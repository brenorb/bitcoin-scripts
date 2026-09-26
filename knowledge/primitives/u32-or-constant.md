# Embedded-constant u32 OR

## Research question

Can a public u32 mask be embedded in the locking script so a checked,
byte-oriented bitwise OR uses four witness items instead of a second
witness-supplied word?

## Construction and threat model

`u32_or_constant(value)` consumes the top four canonical byte limbs, validates
each original hostile limb with `verify_canonical_byte()` before table setup,
and loads the existing 256-entry
byte Boolean table, ORs every byte with the public compile-time `value`, and
removes the table before returning. The mask is script data, not a secret.

The input witness is hostile. The checks reject negative values, values above
255, and non-minimal ScriptNum aliases before any table query. The table is
the repository's existing XOR/AND/OR table and is generated afresh for this
fragment; it is not a witness hint.

## Comparison objective and boundary

The objective is witness width and entry-item count when the mask is public,
compared with the generic table-backed `u32_or` composition. The
`fragment-with-memory` boundary includes four canonical byte checks, table
setup and cleanup, all four byte queries, and output routing. It excludes
witness pushes, terminal predicates, unrelated live state, and transaction
framing.

| Construction | Locking script | Representative witness | Maximum witness | Data items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Embedded mask `0x89abcdef` | 776 | 13 bytes | 13 bytes | 4 | 0 | 272 | 548 |
| Generic `u32_or` with runtime mask | not measured at this boundary | 25-byte maximum | 25 bytes | 8 | 0 | table-dependent | not measured here |

The embedded form removes four witness data items and saves the second word's
serialized witness bytes, while retaining the 256-item table. It is useful
when the mask is public, fixed at script-generation time, and witness width or
item count is important. Table sharing can make the generic composition
preferable for multiple operations.

## Evidence and execution class

The implementation and metric boundary are `locally-reproduced`; deployment
is `unclassified`. The metric fixture uses mask `0x89abcdef` and four
canonical `0xff` data limbs. Runtime result cases cover zero, all-zero/all-one
masks, boundary masks, and 100 seeded word/mask pairs. Malformed-input and
stack-preservation cases are described below.

Result cases use complete leaves that compare the OR output with the expected
word and the shared `run_with_witness` strict helper. The malformed-input
regression uses a leaf that consumes all four outputs and ends in `OP_TRUE`,
executed with the explicit tapscript consensus profile (`require_minimal =
false`, combined main-plus-alt-stack limit enabled). It checks that negative,
out-of-range, negative-zero, non-minimal, and five-byte overflow limbs fail
with the expected interpreter errors at every original limb. A faithful
mutant of the historical no-rotation validator passes the same successful
control and accepts non-minimal aliases in positions 0–2 while rejecting
position 3.

The reproduction uses `rust-bitcoin-script`
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and `bitcoin-scriptexec`
[`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).
The earlier review's reproduction request is recorded in
[Robin's comment](https://github.com/solving-bitcoin/bitcoin-scripts/pull/146#issuecomment-5725176079),
and the follow-up asks to keep checks on all four original limbs in
[the latest comment](https://github.com/solving-bitcoin/bitcoin-scripts/pull/146#issuecomment-5835974652).
The historical validator source at PR commit
[`c00ce1a`](https://github.com/solving-bitcoin/bitcoin-scripts/commit/c00ce1a)
and reviewed commit
[`2ee1cfc7f7211054b8b970d0e109f4fe6cbd36c6`](https://github.com/solving-bitcoin/bitcoin-scripts/commit/2ee1cfc7f7211054b8b970d0e109f4fe6cbd36c6)
use the historical lockfile pin to interpreter
[`702544c9a045ac4fc14846da6da6559e2b7cd9d1`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/702544c9a045ac4fc14846da6da6559e2b7cd9d1).
The historical source and lockfile were inspected; the original commit was
not re-executed under that historical interpreter. Its faithful no-rotation
mutant was exercised as a regression control under the current local profile.
These are local interpreter results, not Bitcoin Core differential,
complete-transaction, relay-policy, or cryptographic claims. The 548 figure is
a static non-push opcode count, not a dynamic execution or validation-weight
claim.

## Parameters and witness

- `value` is any public `u32`; there is no default.
- The witness supplies four canonical numeric byte limbs in
  most-significant-byte-first order, with the least-significant limb on top.
- The complete measured input has four data items and zero hint items. No
  hints coexist at entry; the generated Boolean table contributes 256 script
  items to the live stack during the operation.
- The 13-byte fixture uses four canonical `0xff` limbs. Callers must account
  for the table and all unrelated live state under the 1,000-item combined
  main-plus-alt-stack limit.

## Script compatibility and standardness

The fragment uses opcodes available in legacy Script, P2SH, P2WSH, and
tapscript, but its table-backed static opcode count exceeds the historical
201-opcode P2SH/P2WSH limit as a standalone fragment. That does not classify
the construction as deployable or non-deployable in a larger protocol; the
complete script and execution context must be checked separately. Relay and
mining policy are also separate questions. See
[`script-types.md`](../../docs/script-types.md) and
[`standardness.md`](../../docs/standardness.md).

## Stack contract

Before: `... | a3 | a2 | a1 | a0`, with four canonical byte-valued items at
the top of the main stack.

After: `... | (a | value)3 | (a | value)2 | (a | value)1 | (a | value)0`.
The four input items are consumed. The fragment temporarily uses both stacks
for table queries, carries, and output routing, then removes the table and
restores caller-owned alt-stack state. It does not provide a terminal
predicate or clean-stack wrapper.

## Reproduction

```sh
cargo test --locked arithmetic::u32::or_constant::tests --lib
cargo test --locked --test primitive_metrics u32_or_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
