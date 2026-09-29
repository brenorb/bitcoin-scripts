# Ternary hash-path commitments

Authenticate base-3 trits using three fixed two-hash codewords: `0 -> SS`,
`1 -> SR`, `2 -> RS`, with SHA-256 `S` and RIPEMD-160 `R`, followed by a final
R. `RR` is deliberately unused. The integer adapter reconstructs a 1–31-bit
non-negative Script integer and rejects values outside the requested width.

## Parameters

- `bit_width`: required (no default), `1..=31` for the integer adapter. It uses
  the smallest fixed number of trits covering the full width (`20` trits at 31
  bits). Values `>= 2^bit_width` are rejected by the host helpers and by Script.
- `trit_count`: required and non-zero for the generic path; trits are `0..=2`.
- `preimage`: caller-chosen byte string, at most 520 bytes on-chain.
- `commitment`: 20 bytes.

## Script metrics

Metrics are fragment-only: input pushes and the caller's output predicate are
excluded; witness bytes include CompactSize item counts and lengths. Sizes use
`compile_with_policy()` with optimization enabled. Stack peaks combine main
and alt stacks. Metric execution uses the strict local tapscript-context
executor with the 1,000-item stack limit enabled; deployment is
`unclassified`, not Core consensus or relay-policy validation.

| Configuration | Locking script | Unlocking witness | Hint items | Maximum stack items |
| --- | ---: | ---: | ---: | ---: |
| `verify_ternary_hash_path_to_integer(31, commitment)` | <!-- metric:ternary_hash_path_integer_31 -->947<!-- /metric:ternary_hash_path_integer_31 --> bytes | <!-- metric:ternary_hash_path_integer_witness_31 -->63<!-- /metric:ternary_hash_path_integer_witness_31 --> bytes (32-byte nonce, 20 trits, 21 data items) | 0 (none) | <!-- metric:ternary_hash_path_integer_stack_31 -->24<!-- /metric:ternary_hash_path_integer_stack_31 --> |

The benchmark example executes the same representative witness and reports
919 static instructions, 794 of them static non-push opcodes (inactive branches
included). At interpreter pin `a09e87af444034698697f0a2267e755cf72f9aed`, the
tapscript `opcode_count` statistic also reports 919 because it counts every
instruction position, executed or not; it is not an executed-opcode total, and
none is claimed for this fragment.

## Security

Generic collision resistance is at most 80 bits; preimage resistance at most
160 bits. Binding assumes the unconventional mixed-hash schedule, which has no
dedicated cryptanalysis. Hiding needs unpredictable opening entropy. No
one-time key is required. The ternary path uses three of the four fixed-length
four-way codewords; its explicit canonical trit checks prevent alternate byte
encodings from selecting the same trit.

## Script compatibility and standardness

The fragment performs its own exact trit checks and does not rely on tapscript
`MINIMALIF`. Every emitted opcode exists in bare script, P2SH, P2WSH and
tapscript, but the measured configuration was executed only in the local
tapscript-context executor; consensus and policy have not been validated. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Integer witness order is `most_significant_trit, ..., least_significant_trit,
preimage`; the verifier's first `OP_SWAP` activates the least-significant trit.
Zero is the empty vector and `1`/`2` are exactly `[01]`/`[02]`; padded,
negative-zero and other encodings are rejected. There are **0 hint items**
per invocation, and 21 data items for 31 bits, all present at entry. Peak 24
leaves room for 976 unrelated live items under the combined 1,000-item limit.

## Stack contract

- `verify_ternary_hash_path_to_integer`: `... tritN-1 ... trit0 preimage ->
  ... value`. Trits are saved on the altstack while hashing and drained during
  reconstruction; surrounding main- and alt-stack state is preserved.
- `verify_ternary_hash_path`: `... tritN-1 ... trit0 preimage -> ... true`.
- `ternary_hash_path_script`: returns the digest instead of verifying it.

Append a terminal predicate for clean truthy success.

## Operational notes

Before the final `3*acc + trit` step, the integer adapter checks
`acc <= floor((2^width-1)/3)` and, when equal, `trit <= (2^width-1) mod 3`, so
out-of-range values are rejected before any value wider than the declared
integer is produced. Tests cover every codeword, integer boundaries, the
`2^width-1` acceptance and `2^width` rejection at every width `1..=31` (widths
1 and 31 additionally require the width check's `OP_VERIFY`, not a later
ScriptNum overflow, to reject), surrounding-stack preservation, ScriptNum
overflow, wrong openings, padded trits and out-of-range generic trits. Both
branches of the width check are exercised at every width with an `OP_VERIFY`
rejection: 58 values whose final-step accumulator exceeds the quotient
(`(q+1)*3` and `3^t-1`; unreachable at widths 1 and 3) and 46 values whose
accumulator equals it with a final trit above the remainder. The construction
is dominated by the four-way path for ordinary 31-bit integers (NR-072).

## Knowledge-base integration

See [the knowledge page](../../../knowledge/primitives/ternary-hash-path-integer.md),
[comparison](../../../knowledge/comparisons/commitments.md), catalog record
`commitment/ternary-hash-path-integer`, NR-072, and OP-030.
