# Transaction introspection with Binohash

Binohash is an external reported construction whose primary source uses legacy
signature behavior and proof-of-work grinding to expose a collision-resistant
transaction digest to Script without a consensus change.

```text
Transaction mutations and legacy sighash
├── FindAndDelete / OP_CHECKMULTISIG behavior
├── subset and nonce grinding
├── two-round digest extraction
├── Script-readable digest
└── Lamport authentication into a later verification protocol
```

The repository has a [legacy core reproduction](../primitives/binohash-legacy-core.md)
for opcode-boundary deletion, subset-dependent legacy sighashes, and the
`SIGHASH_SINGLE` bug constant. A reduced two-choice fixture now validates two
complete funded P2SH spends against pinned Bitcoin Core v30.3. Both selected
spends satisfy consensus but fail default relay policy; flipping selection
without re-signing fails consensus. This is not the two-round grinding
protocol, ECDSA nonce search, or Script-readable digest. Do not model Binohash
with the default tapscript executor: its legacy signature context and
transaction template are essential semantics. Full reproduction still needs
grinding parameters, mutation constraints, Script extraction, and full costs.
See `introspection/binohash` and `OP-011`.
