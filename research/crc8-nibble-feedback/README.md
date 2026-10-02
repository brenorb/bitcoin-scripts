# CRC-8 nibble feedback: initial experiment

Question: can a sixteen-entry feedback table plus the existing triangular
nibble XOR table beat a serial bit-register schedule for CRC-8 polynomial
`x^8+x^2+x+1` while retaining hostile-input checks, zero hints, and bounded
combined stack usage? Recurrent fixed-distance patterns in a fresh private
seed motivated a feedback experiment. Atlas/source/negative-result searches
found no recorded CRC-8 primitive; that is a coverage gap, not a novelty claim.

Use initial CRC zero, MSB-first nibbles (high nibble before low nibble of each
byte), no final reflection or xor. The first logical nibble is at the top of
the witness. Every numeric input is checked in 0..=15, at most four bytes;
numeric aliases are allowed by the local Consensus profile. Output is one
canonical numeric byte, not an eight-bit raw byte string. All N ordinary
message items coexist at entry; **zero hint items and zero hint bytes**.
CRC-8 provides no cryptographic authentication or collision resistance claim.
The caller binds message provenance, byte pairing and the expected checksum.

Hypothesis: four-bit feedback reduces code growth but its 184 resident table
items restrict all-entry message length compared with eight live CRC bits.
State `(H,L)` updates through `T(H xor d)`, where `T(i)` is the remainder of
`i*x^8` modulo the polynomial. New high nibble is `L xor high(T)` and low is
`low(T)`. Tables include sixteen paired high/low entries, the existing
136-item triangular XOR table and sixteen existing lookup offsets. The serial
baseline keeps eight bits and feeds each input bit through a linear register.
Both include numeric guards, all setup/cleanup and canonical byte packing;
leaf variants additionally compare the exact checksum and return TRUE.
Witness bytes serialize the complete item vector and prefixes, excluding
leaf/control block/annex/transaction framing. Actual compilation uses the
repository ALL<=32KiB / NONE-above policy, including each final checked leaf.

Primary polynomial/order reference: SMBus Specification v3.1, 2018-03-19,
section 6.4.1.3 (p.37),
<https://smbus.org/specs/SMBus_3_1_20180319.pdf>, PDF SHA256
`ae22a791184fdd649c3101f70c3ce238c35b08c7f5b736458e740b903d1bf386`.
Algorithm context: Linux v6.18 commit
`7d0a66e4bb9081d75c82ec4957c50034cb0ea449`,
<https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/lib/crc/crc8.c>.
The generic Linux routine permits a caller-selected initial state; its header
default/complement conventions are not substituted for this experiment's
explicit zero initialization/no-xor profile. No Linux source is copied or
executed. The host oracle computes exact polynomial remainders independently.

Threat model: hostile nibble values/encodings, every live input position,
wrong order, short inputs, caller stack corruption, transient combined depth
and terminal-check bypass. The initial private probe exhausts 4,096 state/
nibble transitions and 65,536 two-byte messages for each family, numeric
aliases, typed malformed/short inputs, deliberately bypassed compiled guards
with valid controls caught by the same typed assertion, and both caller-stack
frontiers. Qualification must later extend the shared contracts to strict
canonical siblings, output/ordering mutations, policy controls and composition.

Execution is locally-reproduced/unclassified only after the actual probe
passes. The local Consensus tapscript profile has numeric minimality off,
MINIMALIF and combined stack checks on, OP_CAT off, CLTV/CSV checks on,
synthetic empty transaction, data-only budget and no signatures. Static
non-push counts are separate from unavailable executed counts and complete
transaction-budget evidence. Production source remains unchanged during this
initial experiment; no catalog or deployment promotion is made yet.

## Initial locally reproduced observations

Both schedules pass every one of the 4,096 CRC-state/nibble transitions and
65,536 two-byte messages: 139,264 executions before the additional fixtures,
hostile inputs and caller frontiers. An independent Python bitwise recurrence
checks both output-stream digests against the Rust polynomial-division oracle,
all 32 scalar rows, witness/output serialization and locked Cargo identities.
The explicitly zero-initialized ASCII `123456789` fixture produces 244 (`f4`).
No Linux execution or Bitcoin Core comparison is claimed.

| Input | Feedback fragment / exact-CRC leaf | Serial fragment / leaf | Feedback / serial peak | Serialized fixture witness |
| --- | ---: | ---: | ---: | ---: |
| 1 nibble, experimental half-byte | 361 / 364 | 157 / 160 | 189 / 14 | 3 |
| 1 byte | 414 / 419 | 285 / 290 | 190 / 15 | 5 |
| 2 bytes | 520 / 524 | 541 / 545 | 192 / 17 | 9 |
| 9 bytes, ASCII fixture | 1,262 / 1,267 | 2,333 / 2,338 | 206 / 31 | 37 |
| 16 bytes | 2,004 / 2,009 | 4,125 / 4,130 | 220 / 45 | 63 |
| 64 bytes | 7,092 / 7,097 | 16,413 / 16,418 | 316 / 141 | 249 |
| 128 bytes | 13,876 / 13,881 | 33,565 / 33,570 | 444 / 269 | 499 |

All rows use ALL except the 128-byte serial fragment/leaf, explicitly
unoptimized NONE. Every byte uses two ordinary numeric nibble items, zero hints,
all at entry. The standalone empty case consumes no data, produces numeric zero
in one fragment byte and has a one-byte exact-check TRUE leaf after ALL; it does
not provide a true bare checksum predicate. Tables, validation, state and cleanup
are included equally in fragment costs, while leaf costs add the exact result
predicate. Small messages retain the table's startup loss.

At nonempty all-entry boundaries, the measured combined peaks are N+188 for
feedback and N+13 for serial, including future inputs and any existing caller
main/alt items. Feedback accepts 812 nibbles at peak 1,000 and rejects 813 at
1,001; serial accepts 987 at 1,000 and rejects 988 at 1,001. The odd 987-nibble
case is an experimental half-byte stream, not a complete SMBus message. Complete
byte-paired maxima are therefore 406 bytes for feedback and 493 for serial, the
latter with one remaining caller item. Feedback's accepted checked leaf is
43,349 bytes and serial's is 129,330, both explicitly unoptimized NONE. Fixture
witnesses are 1,576/1,916 bytes; maximum numeric-alias witnesses are 4,063/4,938.
Every hint count is zero. The 32-nibble caller tests observe every preserved
opaque byte at exactly 1,000 with zero or three alt items, and an extra item fails
with StackSize. These local fragment outcomes do not establish deployability.

The same typed Verify assertions detect deliberate compiled range-guard bypasses
at all four input positions after clean valid controls and clean mutant controls.
The hostile value 16 aliases a valid table query when validation is removed; the
serial decomposition clips it to 15. Aliases/negative zero pass the documented
numeric profile. Every position rejects negative/above-range inputs as Verify,
5..520-byte values as ScriptIntNumericOverflow, and 521-byte items as PushSize;
all short prefixes fail InvalidStackOperation.

A construction-time error in the private serial reference left an extra copy of
the feedback bit at each step. The retained original-step mutation reproduces
five zero output items for one zero nibble, while the corrected reference leaves
one canonical zero. The **same exact-output assertion** catches the original
step after the corrected control passes. This is a private reference regression,
not a defect or fix in existing production source. Its artifact records the
actual compiled hash, error, output digest and resource statistics. Expected
caught assertion panics appear in probe stderr; the complete probe exits zero.

Initial tested source: `0db90b9450d96a0bdf292d633fff14036bac2745`. Reproduce after source pin:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example crc8_probe -- 0db90b9450d96a0bdf292d633fff14036bac2745 > /tmp/crc8-probe.json
cmp research/crc8-nibble-feedback/initial-probe.json /tmp/crc8-probe.json
python3 research/crc8-nibble-feedback/verify_probe.py
```

Debug assertions and overflow checks stay enabled. Public API design, canonical
sibling contracts, asymmetric ordering and terminal mutations, partial Policy
controls, composition, named metrics, full non-field checks and KB promotion
remain before any primitive PR. The original reproduction will be preserved.
