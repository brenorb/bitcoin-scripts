# Damm finite-state checksum: initial experiment

Question: does keeping the fixed 100-entry Damm transition table resident across
runtime decimal digits beat a table-free balanced dispatch while preserving both
caller stacks and an exact bounded witness contract? The new private seed's
repeated-state and decimal motifs suggested a finite-state checksum. Catalog,
negative-result and source searches found no recorded Damm/decimal transducer;
this is a coverage gap, not novelty of the established Damm algorithm.

Hypothesis: a single table amortizes setup/cleanup after a small number of digits,
with a substantial entry-stack cost. Compare left-to-right resident lookup,
table-free balanced mapping and a first-row-specialized resident schedule using
the same numeric digit validation, stable input order and output check. Known
initial state is zero. No cryptographic security or deployment claim is made.

Inputs bottom-to-top: `digit0 ... digit[n-1]`. Every item is hostile and must be
an at-most-four-byte ScriptNum numerically in 0..=9. Numeric aliases are permitted
when the profile allows nonminimal numbers; this is distinct from native exact
binary selectors. Output is a canonical checksum digit. Both caller stacks
must be preserved. There are n ordinary data items and exactly zero hints per
invocation, all present at entry. Repeated preloaded groups share the entry
limit; no discarded or future inputs are free.

Source: CheckDigits.Net commit 734afa2d3596862ef4c3bb3ec404b512b96b8965:
https://github.com/KnowledgeForwardSolutions/CheckDigits.Net/tree/734afa2d3596862ef4c3bb3ec404b512b96b8965.
Exact upstream table, fold implementation and MIT license are preserved in
`reference/`. File SHA256:

- DammQuasigroupTable.cs: b5be157bdbc16daf91a1caf75911cc648ac108488a878909a8b1e22cd75ceaf2
- DammAlgorithm.cs: 626e5584a381c3a79d2d03f40e363d3769b830ecba0f6f7b02335b0cdb323135
- LICENSE.txt: 004a28c5066c23ebee0263565d9e66c1e40d0409d5042a9194334b41d7da132f

Its numeric fold starts at zero and performs table[state,digit] left to right.
The reference API rejects empty text and its validation wrapper requires at
least two characters; our research numeric empty-fold boundary returns zero,
so those API wrappers must not be conflated. The original 2004 dissertation
(DOI 10.17192/z2004.0516) could not be fetched because the current repository
returns an access-denied page; no exact thesis table or proof inspection is
claimed. The upstream repository is primary evidence for this implementation;
its statement of origin/error guarantees is reported until reproduced locally.

Hard constraints: central compilation policy, both-stack limit 1,000, 520-byte
entry elements, exact numeric range and observable output/caller state. Use the
explicit local Consensus tapscript profile (numeric minimality off, MINIMALIF
on, stack enforcement on, OP_CAT off, synthetic empty transaction, data-only
budget, no signatures). Local results remain locally-reproduced/unclassified;
no Core/policy class is inherited from other experiments. Static non-push counts
are separate; executed counts and complete transaction budget are unavailable.

Estimated resident peak is n+104 for positive n; dispatch should save the table
space. These are estimates pending policy-produced measurements. Probe script
bytes include table setup/cleanup, selection, input validation and output state;
exclude witness pushes and terminal checks. Leaf checks exact final digit then
returns TRUE. Witness serialization includes all n data items and prefixes,
excludes script/control block/annex/transaction. Promote only after shared typed
malformed-position/alias/mutation/order/caller-state/frontier contracts, immutable
artifact bindings, KB updates and the full required non-field test run.
Base bf9ee0bb34987a9130ad9dc13a06e18fef137296; reserve NR-079 / OP-037.

## Initial locally reproduced observations

At 32 digits with deterministic `(7*i+3)%10` numeric inputs:

| Schedule | Fragment / checked leaf bytes | Combined peak |
| --- | ---: | ---: |
| Resident 100-entry table | 766 / 769 | 136 |
| First-row dispatch warmup then resident table | 829 / 832 | 135 |
| First-row table then runtime ten-entry row tables | 5,652 / 5,655 | 42 |
| Table-free balanced dispatch | 27,809 / 27,812 | 35 |

All use ALL, the same 32 ordinary entry data items, exactly zero hints and
61 witness bytes (zero digits use empty ScriptNums). Resident setup amortizes
by two digits: 191 bytes/106 peak versus row-table 206/12. At one digit it
loses: 172/105 versus row-table 27/11 and table-free 81/4. These are measured
tradeoffs, not a universal best representation.

Resident reaches exactly 1,000 at 896 digits; warmup at 897; row-table at 990;
table-free at 997. The next digit rejects typed StackSize at first peak 1,001
in each schedule. Large row/table-free scripts use NONE above the cutoff:
990-digit row-table is 180,873 bytes unoptimized, versus 18,046 ALL for the
896-digit resident table. Do not compare unlike digit counts as a byte saving.
At the matched 128-digit boundary, resident is 2,686 bytes/232 peak versus
row-table 23,124/138 ALL and dispatch 113,731/131 explicitly unoptimized NONE.

The prototype passes 4,444 numeric vectors (all vectors through three digits
across four schedules), longer asymmetric vectors, malformed values at every
position with typed Verify/numeric-overflow/PushSize errors, allowed numeric
aliases and compiled guard-bypass mutations. Every bypass preserves valid
controls and makes the same typed Verify assertion fail, with unchanged cleanup
and a preserved zero caller item available to expose out-of-table picks. These
expected caught assertion panics appear in the standalone probe's stderr; its
process exits successfully when every mutation is detected.

The table's row/column permutations, zero diagonal and all 1,000 adjacent-pair
state relations are checked locally. An independent Python check reads the
exact preserved upstream table, verifies the Rust transcription, these
properties, each measured output and witness byte count. Original C# execution
has not been performed, and this does not claim Bitcoin Core validation.
Empty numeric folds remain distinct from the upstream string API.

Initial tested source: `INITIAL_SOURCE_REVISION_PENDING`. Source/dependency
pins and final artifact hashes are in `initial-probe.json`. Reproduce:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example damm_finite_state_probe -- INITIAL_SOURCE_REVISION_PENDING > /tmp/damm-probe.json
cmp research/damm-finite-state/initial-probe.json /tmp/damm-probe.json
python3 research/damm-finite-state/verify_reference.py
```

A shared target directory may be used to reuse already built dependencies.
The public API, full caller main/alt frontier suite, policy probes, immutable
integrated artifact contracts, catalog/README markers and required full tests
remain to be completed before any public promotion or PR.
