# Checked u4 transition count

## Question

Can a u4 vector expose its number of unequal neighboring pairs without
materializing an intermediate equality mask?

## Construction

`u4_nibbles_transition_count(n)` consumes `n` numeric nibbles in input order
and returns the number of indices `i` for which `nibble[i] != nibble[i+1]`.
It range-checks every hostile input, compares pairs with numeric ScriptNum
equality, and folds the inequality bits into one altstack accumulator. The
result is in `0..=n-1` even when permissive ScriptNum aliases are supplied.

## Evidence

- evidence: `locally-reproduced`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, one compact count
- comparison: direct fold versus adjacent-mask materialization

The implementation includes repeated, alternating, singleton, malformed,
boundary, permissive-encoding, and surrounding-stack cases. Its alias checks
run under `TapscriptProfile::Consensus` with non-minimal numbers permitted, a
stack limit enforced, and a final `OP_NUMEQUALVERIFY OP_TRUE` predicate. A
test-only mutant replaces the compiled numeric inequality with bytewise
inequality (`OP_EQUAL OP_NOT`);
the same terminal assertion rejects the mixed-encoding witness with
`NumEqualVerify`.

The exact frontier regression uses alternating minimal `[01]` and `[02]`
nibbles and checks the returned count before requiring a single true result:

| Fragment boundary | Data-stack items and serialized bytes | Other live state | Compiled locking-script bytes | Combined peak | Result |
| --- | --- | --- | ---: | ---: | --- |
| Standalone `n=997` | 997 data, 0 hints; 1,997 bytes | None | 22,982 | 1,000 | Accepted, count 996 |
| Composed `n=995` | 995 nibbles plus 1 preserved main item, 0 hints; 1,995 bytes | 1 alt-stack item created before the fragment | 22,941 | 1,000 | Accepted, count 994; main item consumed, alt sentinel checked |
| First over-limit `n=996` | 996 nibbles plus 1 preserved main item, 0 hints; 1,997 bytes | 1 alt-stack item created before the fragment | 22,958 | 1,001 | Rejected with `StackSize` |

All listed witness items coexist at script entry. Each locking-script size is
the final `ScriptCompilation::compile_with_policy()` serialization, including
its terminal checks; each is under the 32 KiB optimizer cutoff and uses
`CompileOptions::ALL`. The composed leaves also include altstack setup and
cleanup. These sizes exclude witness serialization, control blocks, annexes,
and other Taproot witness data, so they are not complete witness sizes. The
alt-stack item is made by the locking script prelude and remains live across
the fragment; the preserved main item is a witness item below the nibbles. The
local helper enforces the combined main/alt-stack limit in a tapscript
interpreter, but does not validate a transaction or run Bitcoin Core.
Deployment remains `unclassified`.

## Limitations

The output discards the locations of individual transitions. The standalone
batch ceiling is 997 inputs before accounting for unrelated live stack state.
The measured bound is `n + 3 + preserved_main + preserved_alt <= 1000`, where
the three temporary items are the pair operands and altstack accumulator at
the fragment boundary. Reduce the batch when caller state remains live.
