# Absolute transaction finality against pinned Bitcoin Core

Question: can a host-side check distinguish a locally successful Taproot leaf
from a transaction whose absolute `nLockTime` is still non-final? The comparison
objective is the exact height and median-time-past (MTP) equality boundary and
the first eligible block under both consensus and default relay policy. This
experiment checks correctness, not an optimization.

[BIP113 at commit `24e96e8`](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0113.mediawiki)
sets the time endpoint to the candidate block's **parent** MTP. [Core v30.3
`IsFinalTx` at commit `49faec4`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/consensus/tx_verify.cpp)
requires the nonzero lock time to be **strictly less** than candidate height
when below 500,000,000, or strictly less than parent MTP otherwise. If every
input sequence is `0xffffffff`, the lock time is ignored. The new
[`support::absolute_finality` preflight](../src/support/absolute_finality.rs)
mirrors only this rule. A missing relevant candidate height/MTP yields
`Unsupported`, not a rejection. It does not validate inputs, BIP68 maturity,
scripts, commitments, signatures, or complete transactions.

The [pinned Core runner](../tools/tapscript_finality_regtest.py) reuses three
distinct public CSV fixture commitments from the 19-output funding manifest.
Their leaves succeed locally at both stages. After confirmation at height 102,
candidate height **103** equals the first transaction's lock time and parent
MTP **1800049664** equals the second's. The local preflight says `NonFinal` for
both. Core rejects each separately with `bad-txns-nonfinal` under block
validation and `non-final` under `testmempoolaccept`. A third transaction has a
future time lock but an all-final input sequence; the preflight says `Final`,
and Core accepts it under policy and mines it at height 103. The resulting
candidate height **104** and parent MTP **1800050176** are the first eligible
stage for the other two: the preflight says `Final`, policy accepts both, and
Core mines both in one block. Missing chain facts give `Unsupported` for the
active-locktime transactions. These are five stage-by-case comparisons, each
against Core consensus and policy; all ten outcomes match. The two equality
spends are `consensus-incompatible`; the three accepted spends are
`policy-validated` for these funded transactions. Evidence is
`differentially-validated` for these exact cases.

The source fixture's local leaf run used `nLockTime=0`. This runner requires the
same exact `OP_CSV OP_DROP OP_TRUE` serialization and unchanged input sequence
for each modified transaction; that leaf reads the sequence but not `nLockTime`.
The local absolute-finality probe parses each modified transaction's exact hex
and verifies its txid. Core independently executes each funded transaction.

Each final policy-produced leaf is a three-byte `OP_CSV OP_DROP OP_TRUE` script;
it has one data item and **zero auxiliary hint items per invocation**. The one
item is on the entry stack, with a strict combined main-plus-alt peak of one.
Complete witnesses have three items (operand, leaf, 33-byte control block),
serialized to 40 bytes for the height case and 45 bytes for the time and
all-final controls. Transaction weights are 418, 423 and 423 WU respectively.
Initial and remaining signature budgets are 90 or 95 units because no
signature opcode executes. Static non-push opcode count is two; dynamic
executed-opcode count is unavailable. No batching or repetition is measured.
The leaves are below the 32-KiB optimizer cutoff and use the final
`CompileOptions::ALL` serialization for commitments and byte metrics.

Reproduce with:

```sh
cargo test --locked --lib absolute_finality::tests
python3 -m unittest discover -s tools -p 'test_tapscript_finality_regtest.py'
python3 tools/tapscript_finality_regtest.py --download-core
```

The [stored report](../tests/data/tapscript-finality-v30.3.json) records the
funded transactions, exact Core diagnostics, candidate block identities,
local verdicts, witness metrics, verified Core archive and resolved interpreter.
Two fresh isolated Core runs produced byte-identical reports; SHA256
`17ffe9b1cd6b434cf7437c108f33db93e92247d54752c11653349151b4d4f5f2`.
The offline guards reject changed source identity, boundary, transaction
identity and rejection category. Local leaf success and absolute-finality
success remain separate diagnostics; neither establishes complete transaction
validity outside the recorded Core cases. Broader finality and transaction
context remains in [OP-001](open-problems.md#op-001--strict-execution-matrix).
