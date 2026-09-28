# Checked u4 least-significant-bit projection

`arithmetic::u4::lsb::u4_nibbles_to_lsb` consumes a contiguous batch of
range-checked four-bit limbs, proves each value is in `0..=15`, and replaces it
with its least-significant bit. It avoids materializing the other three bits
when a bit-oriented encoding needs only the low bit.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | lsb[0] | ... | lsb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by all-nibble ordering tests, malformed
  input tests at every position, preserved-state and batch-size boundary tests,
  and a strict metric fixture. A separately scoped complete Taproot spend is
  differentially validated by Bitcoin Core v30.3.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes across 32 data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `unclassified` for the reusable fragment. The separate
  complete-leaf fixture below is `policy-validated`.

The fixture `u4-lsb-0123456789abcdef` supplies nibbles `0..=15` in canonical
ScriptNum encodings, appends equality checks for the reversed output order, and is
accepted by both Bitcoin Core v30.3 consensus and its default relay policy.
The complete leaf uses 16 data items, zero incremental hints, and 18 total
witness items at entry (the sixteen data items, leaf script, and control block).
It has a 264-byte policy-compiled locking script, 184 static non-push opcodes,
32 serialized data-witness bytes, 333 serialized Taproot witness bytes, and a
34-item combined main/alt-stack peak under the strict local helper. The local
measurement uses `execute_raw_script_with_inputs_strict` in tapscript context;
it enforces the stack limit but does not perform full transaction validation.
Core v30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227` validates the
complete regtest spend under consensus and default relay policy. Reproduce it with:

```sh
python3 tools/core_regtest.py --download-core \
  --output target/ci-reports/core-validation-u4-lsb.json
```

This validates one 16-nibble complete transaction and terminal equality
predicate, not the 32-nibble metric configuration or arbitrary compositions.
The fragment measurement above retains its local evidence and deployment scope.

## Canonical witness adapter

`arithmetic::u4::lsb::u4_nibbles_to_lsb_canonical` is a separate API; the
range-checked `u4_nibbles_to_lsb` above is unchanged. The research question is
whether the existing 16-item LSB table can bind byte-unique ScriptNum encodings
without changing the projection contract. The canonical variant reuses the same
table and replaces only the per-item numeric check with
`verify_canonical_nibble()`. For 32 hostile witness nibbles it costs 504
bytes, 65 serialized witness bytes, 51 combined stack items, zero hint items,
and 360 static non-push opcodes. The range-checked form remains 440 bytes and
50 items, but it is appropriate only when a caller already owns canonical
limbs. The canonical standalone batch range is `1..=981`, while the
range-checked form reaches `1..=982`; the extra canonical check adds one stack
item to the per-input peak. The 981-input canonical batch executes under the
strict local helper (`execute_script_with_inputs_strict`, tapscript context,
combined stack limit enforced) with a 1,000-item combined peak, and generation
rejects 982 inputs. Compositions must leave
`n + 19 + unrelated_live_items <= 1000`, counting both stacks.

The threat model treats every nibble as hostile raw ScriptNum data. The
canonical variant rejects redundant sign bytes and negative zero in addition
to negative and out-of-range values. Its fragment-only boundary includes the
16-item table, canonical checks, queries, cleanup, and output restoration; it
excludes witness pushes, terminal predicates, unrelated live state, and
transaction context. Deterministic tests cover all nibble values, malformed
encodings at every position, the executed 981-input frontier, and surrounding
main/alt-stack preservation. The malformed-encoding test runs under the local
`TapscriptProfile::Consensus` profile, which decodes non-minimal ScriptNums: there
the range-checked API accepts the alias byte strings `[0x01, 0x00]` (one with a
redundant zero byte) and `[0x80]` (negative zero), while the canonical API
rejects them with `EqualVerify`. The default local helper enforces minimal
numbers and would reject those aliases before the canonicality check runs. Evidence is `locally-reproduced`; deployment
remains `unclassified`. The Core v30.3 complete-leaf fixture above exercises
only the range-checked API and does not validate the canonical variant.

This is a projection fragment, not a complete locking script. Numeric range
checking does not establish canonical or byte-unique ScriptNum encoding.
Callers still need any terminal predicate and clean-stack rule required by
their protocol. Use `u4_nibbles_to_lsb_canonical` when the fragment itself
must reject non-minimal nibble encodings.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-lsb`.
