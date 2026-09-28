# Checked u4 adjacent-equality mask

## Question

Can a checked u4 fragment expose equality between neighboring nibbles without
expanding the inputs into bits or installing a lookup table?

## Construction

`u4_adjacent_equal_mask(n)` consumes `n` numeric nibbles in input order and
returns `n-1` ScriptNum booleans. Output `i` is true exactly when
`nibble[i] == nibble[i+1]`. Inputs are range-checked as `0..=15`; non-minimal
raw ScriptNum encodings remain a caller-level canonicality concern, but equal
numeric aliases compare equal.

The fragment keeps the original inputs on the main stack while it computes
pairs from the end toward the beginning and stores only the boolean results on
the altstack. It therefore has no hint items or table memory and leaves
unrelated surrounding stack state intact.

## Evidence

- evidence: `locally-reproduced`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, 31 output bits
- comparison: direct pair equality versus bit expansion or table lookup

The raw-witness alias and output-order regressions use the repository's
explicit local `TapscriptProfile::Consensus`: `require_minimal=false` permits
numeric aliases and the 1,000-item combined main/alt-stack limit is enforced.
These cases append checks for every output in contract order and a single
`OP_TRUE`. Alias tests cover both input orders, zero aliases, and a six-input
asymmetric output vector whose five bits are checked individually. The
invalid-input tests instead consume the hypothetical output and end in
`OP_TRUE`; a canonical valid witness control uses that same harness. Invalid
values `-1`, `16`, and a five-byte ScriptNum overflow are checked at every
input position against exact local interpreter errors.

The before-fix generator source was inspected at PR commit
[`a5f2b7224390c0c8e24eec4e0ee6cb0c17aea764`](https://github.com/solving-bitcoin/bitcoin-scripts/commit/a5f2b7224390c0c8e24eec4e0ee6cb0c17aea764),
file `src/arithmetic/u4/adjacent_eq.rs` (SHA-256
`fe8e288f28c6734471ac7b415402d819d585ac75c742bbe21d699df6e6296040`). It
compares raw encodings with `OP_EQUAL`. The regression also applies a test-only
parsed-instruction mutation that changes only the current `OP_NUMEQUAL`
opcodes back to `OP_EQUAL`; with witnesses `[0x01]` and `[0x01, 0x00]`, the
terminal assertion fails with `ExecError::Verify`. This is an exact-opcode
mutation of the inspected before-fix implementation, not a run of the
historical repository checkout. The explicit profile is a local tapscript
interpreter result, not a Bitcoin Core transaction validation.

The representative metric is the final 558-byte `ScriptBuf` produced by
`ScriptCompilation::compile_with_policy()` for 32 checked inputs and 31 output
bits, with 361 static non-push opcodes. Its 65-byte witness fixture is 32
canonical one-byte data items; the zero incremental hint count is separate from
those data items. All 32 items coexist at script entry. The 64-item peak is the
combined main and alt stack measured by the strict local helper with output
cleanup and a terminal truthy result. The witness byte figure covers only the
32 data items, not a complete Taproot witness containing a script, control
block, or annex. The named metric test uses the strict helper's tapscript mode,
enforces the combined stack limit, and uses its default minimal-number flag;
the explicit alias regressions use the separate consensus profile above.

Both local paths use the pinned `bitcoin-scriptexec` revision
`a09e87af444034698697f0a2267e755cf72f9aed`; compilation uses the pinned
`bitcoin-script` revision `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and the
centralized compilation policy. No independent Bitcoin Core or relay-policy
validation has been performed. The fragment is not a complete locking script
and does not provide its own terminal predicate.

## Limitations

The output is a run-boundary mask rather than a packed bitstring. The API
supports batches up to 499 inputs. This is a conservative supported limit, not
a claim that it is the largest valid standalone batch; callers must lower it
when composing with unrelated live stack state.
