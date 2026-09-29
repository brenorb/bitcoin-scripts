# Checked u4 parity projection

`arithmetic::u4::parity` replaces each nibble of a contiguous batch with one
numeric parity bit using a 16-item generated lookup table, so it is useful when
a protocol needs parity but not the four expanded bits. It exposes two
distinct APIs with the same stack contract:

| API | Input check | Batch range | Standalone peak |
| --- | --- | --- | --- |
| `u4_nibbles_to_parity(n)` | numeric range `0..=15` only | `1..=982` | `n + 18` |
| `u4_nibbles_to_parity_canonical(n)` | numeric range plus minimal ScriptNum encoding | `1..=981` | `n + 19` |

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | parity[0] | ... | parity[n-1]`, with the last bit
  on top.
- **Evidence:** `locally-reproduced` by exhaustive nibble tests, malformed-input
  tests, strict stack-frontier tests, and strict metric fixtures for both APIs.
- **Execution class:** `unclassified`. The local strict executor runs the
  fragments in tapscript context with the combined stack limit; no Bitcoin Core
  consensus or relay-policy transaction has been tested.

## Numeric-range API

`u4_nibbles_to_parity` consumes numeric nibbles and proves each value is in
`0..=15` before it indexes the table. At 32 nibbles it costs 440
locking-script bytes, 65 serialized witness bytes for 32 one-byte data items,
50 combined stack items, and no hints. The fragment contains 328 static
non-push opcodes; that is not an executed-opcode or deployment claim.

The range check protects the lookup index but does not establish a byte-unique
ScriptNum encoding. Under the local consensus profile, which does not apply
MINIMALDATA to numeric operands, a non-minimal alias of an in-range value
(for example `0x0100` for 1) is accepted and projected like the minimal value;
the policy profile and the default research helpers reject it only because the
interpreter enforces MINIMALDATA. The
standalone combined stack peak is `n + 18`, so the generator accepts
`1..=982`; unrelated main/alt-stack state reduces that frontier. Focused tests
cover asymmetric ordering, negative, above-range, and oversized numeric inputs
at each position, the 1,000-item frontier, and preserved main/alt-stack state.

## Canonical-encoding API

The canonical variant answers whether the same 16-item parity table can bind
minimal ScriptNum encodings without changing the output contract. It replaces
only the per-item numeric check with `verify_canonical_nibble()`. At 32
hostile witness nibbles it costs 504 bytes, 65 serialized witness bytes, 51
combined stack items, zero hints, and 360 static non-push opcodes, versus 440
bytes and 50 items for the numeric-range form. The canonical standalone batch
range is `1..=981`, while the numeric-range form reaches `1..=982`; the extra
validator item changes the peak from `n + 18` to `n + 19`. Compositions must
leave `n + 19 + unrelated_live_items <= 1000`, counting both stacks.

The threat model treats every nibble as hostile raw ScriptNum data. The
canonical variant rejects redundant sign bytes and negative zero as well as
negative and out-of-range values. Focused tests execute the exact 981-item
strict frontier at a 1,000-item peak, a 979-item batch with one main-stack and
one alt-stack item preserved at the 1,000-item peak, the 980-item batch with
the same state rejected for stack size, malformed raw encodings at every
position under the local consensus profile (so rejection comes from the
fragment, not MINIMALDATA), and an alias that the numeric-range API accepts
but the canonical API rejects under that profile. The fragment-only boundary includes table setup, canonical
checks, queries, cleanup, and output restoration; it excludes witness pushes,
terminal predicates, unrelated live state, and transaction context.

## Composition

Both variants are projection fragments, not complete locking scripts: callers
still need a terminal predicate and any required clean-stack behavior. Use the
canonical API whenever the protocol needs a byte-unique witness encoding; the
numeric-range API alone does not provide one.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-parity`.
