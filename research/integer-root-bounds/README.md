# Integer floor-root bounds: initial experiment

Question: can a residual-difference schedule compute floor square roots in the
nonnegative four-byte ScriptNum domain without witness hints, a lookup table,
variable multiplication or division opcodes? The fresh private seed's small
digit peaks and separated runs motivated a boundary/threshold experiment.
Catalog, comparisons, negative results and arithmetic source searches found
no recorded integer floor-root construction; field roots and modulo-16
squaring have different semantics. Absence is a coverage gap, not nonexistence.

Hypothesis: fixed high-to-low root-bit trials beat a balanced constant square
threshold tree in bytes as width increases. State is `(residual=x-r*r, r)`.
A trial bit b costs delta `2*r*b+b*b`; accept only if residual>=delta, subtract
delta and add b to r. The identity follows directly from expanding `(r+b)^2`.
The Script uses the existing `mul_by_constant(2*b)`, not a new multiplier.
Only numeric inputs 0..=2^bits-1, bits 1..=31, are admitted. Every input is
hostile and range checked; at-most-four-byte numeric aliases are allowed when
the profile permits them. Output is a canonical root and caller main/alt state
survives. No cryptographic or authorization property is claimed.

Compare identical numeric checks, input domain, canonical output, cleanup and
exact-root terminal predicates. One ordinary input item, **zero hint items and
zero hint bytes**, all present at entry. Fragment excludes witness pushes and
terminal predicates; leaf binds the exact root then TRUE. Witness serialization
includes item/count prefixes, excludes leaf/control block/annex/transaction.
Repeated all-entry invocations must count every future input and saved output,
even though each invocation has zero hints. No composed capacity claim yet.

Local Consensus tapscript profile: numeric minimality off, MINIMALIF on, stack
limit on, OP_CAT off, CLTV/CSV checks on; synthetic empty transaction, data-only
budget, no signatures. Results remain locally-reproduced/unclassified. Static
non-push counts are separate; executed counts and complete transaction budget
are unavailable. All compilations use the repository's ALL<=32KiB/NONE policy.
Large threshold trees must be explicitly labeled unoptimized.

Estimates before execution: restoring needs five live items including its input;
threshold dispatch needs three. High-to-low differences avoid forming the
possibly overflowing entire candidate square in 31-bit arithmetic. Intermediate
numeric bounds still need mathematical review and executable square-edge tests.
Do not promote these estimates, or isolated success, to consensus validity.

Primary algorithm context: Linux v6.18 commit
`7d0a66e4bb9081d75c82ec4957c50034cb0ea449`,
[int_sqrt](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/lib/math/int_sqrt.c),
documents an established shift/subtract integer square root. Its code is not
ported. This prototype derives the square-difference identity independently;
it is not a claim of a new root algorithm. The independent Python oracle uses
[math.isqrt](https://docs.python.org/3.14/library/math.html#math.isqrt), with
CPython v3.14.7 source commit `823f0323ee6ec1402088b73bce1a38473cac36dc` and
the actual runtime version printed. The Rust host oracle is a separate exact
u64 binary search; no floating-point roots are used.

The private example will exhaust both 16-bit input domains, every distinct
31-bit square endpoint for restoring, numeric aliases, typed malformed and
short inputs, compiled range/terminal bypasses with same-assertion valid
controls, and observable full caller main/alt frontiers. It precedes any
production source changes. Reserve NR-080 / OP-038 only if later qualification
justifies a new primitive or negative result.

## Initial locally reproduced observations

The two algorithms each pass all 65,536 16-bit inputs. Restoring also passes
all 92,681 distinct endpoints `q*q-1`, `q*q`, and `(q+1)^2-1` clipped to the
31-bit range. An independent exact Python math.isqrt oracle checks the output
stream digests, every measured output, witness serialization and source/Cargo
bindings. These are 223,753 scalar executions before additional malformed,
alias, width-domain and frontier controls; this is not Core execution.

| Input width | Restoring fragment / exact-root leaf | Threshold fragment / leaf | Options restoring / threshold |
| --- | ---: | ---: | --- |
| 8 | 99 / 102 | 147 / 150 | ALL / ALL |
| 16 | 232 / 237 | 2,989 / 2,994 | ALL / ALL |
| 24 | 405 / 410 | 54,109 / 54,114 | ALL / NONE (unoptimized) |
| 31 | 614 / 620 | 659,112 / 659,118 | ALL / NONE (unoptimized) |

Each max-input fixture uses one ordinary data item, zero hints, and respectively
4/5/6/6 serialized witness bytes. Fragment peak is 5 for restoring and 3 for
thresholds; every preserved main/alt byte is observed at combined peak 1,000
with either zero or three alt items, and one extra caller item fails StackSize.
The complete admissible numeric witness maximum is 6 bytes, including allowed
four-byte aliases; selected canonical witnesses are smaller at some widths.
A zero root is valid arithmetic output although a bare zero fragment is false;
its exact-root leaf returns one TRUE. Result correctness and clean leaf success
are recorded separately.

The compiled numeric guards and exact-root predicates have deliberate bypasses.
The same typed Verify/EqualVerify assertion catches each bypass after unchanged
valid controls and cleanup pass. Expected caught assertion panics appear in the
probe stderr; all checks complete with exit status zero. Numeric aliases and
negative zero are accepted when the Consensus profile allows them; malformed
5..520-byte numbers fail ScriptIntNumericOverflow, 521-byte elements PushSize,
short input InvalidStackOperation, and numerically out-of-domain inputs Verify.

Arithmetic bound (local proof from the invariant, not a deployment claim): root
bits k<=16. Before trial b, accepted root r is a multiple of 2b with
`0<=r<=2^k-2b`. For k=16, the first delta is 2^30; the maximum later delta is
`5*2^28=1,342,177,280` at b=2^14. All smaller power-of-two trials have a smaller
bound. `2*r*b` is no larger than delta, so double-and-add intermediates also fit
four-byte numeric arithmetic. Conditional subtraction keeps residual nonnegative,
and r+b stays <=65,535. Thus the schedule avoids forming an overflowing full
candidate square while maintaining `residual=x-r*r` and greedily accepting only
root bits whose candidate square fits x. Exhaustive square-edge tests support
this arithmetic argument; broader composition/contract qualification remains.

Initial tested source: `4d5b08e0f6c19e1a52bbc0805da4f307bd422fd5`. The report records
all final hashes, exact profile and dependency pins. Reproduce:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example integer_root_probe -- 4d5b08e0f6c19e1a52bbc0805da4f307bd422fd5 > /tmp/integer-root-probe.json
cmp research/integer-root-bounds/initial-probe.json /tmp/integer-root-probe.json
python3 research/integer-root-bounds/verify_probe.py
```

The prototype is private research code; production source has not changed.
Public parameter/API design, small-width crossover measurements, shared policy
and adversarial contracts, all-entry repeated composition, named metrics, catalog
integration and the full required non-field test run remain before promotion.
