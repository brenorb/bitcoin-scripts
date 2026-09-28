# Embedded-constant u32 XNOR

## Research question

Can a public u32 mask be embedded in the locking script so a checked,
byte-oriented bitwise XNOR uses four witness items instead of a second
witness-supplied word?

## Construction and threat model

`u32_xnor_constant(value)` consumes four most-significant-byte-first limbs.
Before any table lookup or arithmetic can normalize them, it checks every
original limb for numeric range `0..=255` and canonical ScriptNum encoding. It
then XORs the input word with the public compile-time mask through the shared
256-item Boolean table, removes the table, complements each output byte, and
restores the output order. The mask is public; no cryptographic security claim
is made.

The regression test feeds nonminimal `0x0100` encodings at each original limb
under `TapscriptProfile::Consensus`, which sets `require_minimal: false` while
enforcing the local combined 1,000-item stack limit. Each alias fails at the
primitive's own canonicality check with `EqualVerify`. Negative values and
values above 255 fail with `Verify`; numeric operands wider than four bytes
fail with `ScriptIntNumericOverflow`. The canonical control uses the same
complete leaf, consumes all four XNOR outputs, and ends in `OP_TRUE`, so a
rejection cannot come from leftover outputs or clean-stack behavior.

## Comparison objective and boundary

The objective is witness width and entry-item count when the mask is public,
compared with a generic two-word XNOR composition. The `fragment-with-memory`
metric boundary includes four canonical byte checks, table setup and cleanup,
four XOR queries, four byte complements, and output routing. It excludes
witness serialization, terminal predicates/output comparison, unrelated live
state, and transaction context.

| Construction | Locking script | Representative witness | Maximum witness | Data items | Hint items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Embedded mask `0x89abcdef` | 686 bytes | 13 bytes | 13 bytes | 4 | 0 | 272 | 502 |
| Generic XNOR with runtime mask | unmeasured | 25 bytes | 25 bytes | 8 | 0 | table-dependent | not measured here |

For the measured embedded-mask configuration, all four data items coexist on
the initial stack and no witness hints are required. The representative 13
serialized bytes include the witness item-count prefix and four canonical
`0xff` ScriptNums; the maximum is also 13 bytes for four canonical byte limbs.
The generated table contributes 256 live items during execution, and the
measured peak includes those items together with the four data items and
intermediates. Any surrounding stack state must fit within the remaining
1,000-item combined main/alt-stack budget.

The generic row compares only the complete numeric-word data witnesses: 25
serialized bytes and eight data items. Its script bytes and complete-fragment
costs are not measured here. The embedded form saves 12 witness bytes and four
entry items at the stated configuration. This is a witness-width comparison;
there is no locking-script cost claim for the generic composition.

## Evidence and execution class

Correctness and metrics are `locally-reproduced`; deployment remains
`unclassified`. The local tests use [`bitcoin-scriptexec` revision
`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed)
and [`rust-bitcoin-script` revision
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180).
Generated scripts are compiled
through `compile_with_policy()`; 686 bytes is the final policy-produced size,
and the unoptimized serialization was not measured separately. Canonical
positive cases use the shared strict local witness helper. Raw nonminimal aliases use the explicit consensus-oriented local
Tapscript profile, not the policy profile.

Historical review reproduced the original defect on commit
`47c1a7141ad91e54ec6b8494b10e2e1b6f8f6d2d`: its validator repeated the check
on one original limb without advancing through the word. With a valid
four-item control, nonminimal `0x0100` encodings at positions 0, 1, and 2
succeeded, while position 3 failed with `EqualVerify`. The historical probe
used [`bitcoin-scriptexec` revision
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/702544c9a045ac4fc14846da6da6559e2b7cd9d1)
and compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. The current code advances the
original limb before each subsequent check, and a test-only historical mutant
confirms that the same all-position regression catches the old behavior.

These local fragment runs do not validate a Taproot commitment, full
transaction, or Bitcoin Core consensus execution. No relay-policy, complete-
transaction, dynamic-opcode, or validation-weight claim is made. The 502
figure is a static non-push opcode count. It exceeds the 201-opcode limit used
by legacy and P2WSH scripts; tapscript removes that limit, but this local result
alone does not establish deployability.

## Parameters and stack contract

- `value` is any public `u32`; there is no default.
- The witness supplies four canonical numeric byte limbs in
  most-significant-byte-first order.
- Each invocation uses exactly 0 incremental hint items. The four data items
  coexist at script entry; the representative complete data witness has four
  items and 13 serialized bytes.
- The primitive returns `~(input ^ value)` as four byte limbs in the original
  most-significant-byte-first order. It consumes the input and removes its
  temporary table while preserving unrelated caller state.
- The primitive is a fragment and does not provide a terminal predicate or
  clean-stack wrapper.

## Reproduction

```sh
cargo test --locked --lib arithmetic::u32::xnor_constant::tests
cargo test --locked --test primitive_metrics u32_xnor_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The broad repository suite and field-arithmetic tests are outside this focused
contribution run.
