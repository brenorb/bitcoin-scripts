# SHA-256

SHA-256 compression exposed through u32 and u4 stack representations. The
`sha2_*` prefix names the SHA-2 family implementation while this directory fixes
the concrete algorithm to SHA-256.

## Parameters

- Message length is supplied at script-generation time.
- `sha2_u32`: one byte per stack item internally; optimized paths exist for 32
  and 80 bytes. The documented default is 32 bytes.
- `sha2_u32::sha256_prefix`: retains the first 1..=32 digest bytes after the
  complete compression schedule.
- `sha2_u4`: two nibbles per input byte and optional addition-table use chosen
  from the block count. The documented default is 32 bytes.
- `sha2_u4_stack`: the tracked-stack generator additionally selects addition
  tables and full/half XOR tables; defaults in its size tests are enabled.

## Script metrics

Sizes are hashing fragments only. They exclude message pushes/witness bytes and
output comparison.

| Implementation | 32-byte input script |
| --- | ---: |
| `sha2_u32` | <!-- metric:sha2_u32_32 -->512428<!-- /metric:sha2_u32_32 --> bytes |
| `sha2_u32`, first 8 digest bytes | <!-- metric:sha2_u32_prefix_32_8 -->512456<!-- /metric:sha2_u32_prefix_32_8 --> bytes |
| `sha2_u4` | <!-- metric:sha2_u4_32 -->332942<!-- /metric:sha2_u4_32 --> bytes |

The `sha2_u4` multi-chunk path reuses its 16-entry row-offset lookup table
while replacing the 136-entry XOR/AND table between chunks. For an 80-byte
two-chunk message this saves 11 bytes over reloading the unchanged lookup
table:

| Profile | Script bytes | Witness bytes | Hints | Strict peak | Fragment opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `sha2_u4(80)` with shared lookup | <!-- metric:sha2_u4_80_shared_lookup -->736595<!-- /metric:sha2_u4_80_shared_lookup --> | <!-- metric:sha2_u4_80_shared_lookup_witness -->161<!-- /metric:sha2_u4_80_shared_lookup_witness --> | <!-- metric:sha2_u4_80_shared_lookup_hints -->0<!-- /metric:sha2_u4_80_shared_lookup_hints --> | <!-- metric:sha2_u4_80_shared_lookup_stack -->905<!-- /metric:sha2_u4_80_shared_lookup_stack --> | <!-- metric:sha2_u4_80_shared_lookup_opcodes -->594466<!-- /metric:sha2_u4_80_shared_lookup_opcodes --> |

The profile uses 160 complete data items for the 80 message nibbles and no
auxiliary hints; padding, output cleanup, and the terminal predicate are
outside the fragment byte count. The strict run is local `bitcoin-scriptexec`
evidence only and does not establish consensus or relay-policy deployment.

Both fragments exceed the repository optimizer's 32 KiB input cutoff and are
reported unoptimized.

Maximum stack depth depends on input length and implementation. The
`sha2_u4_stack` generator records it with `StackTracker`; executable hash tests
cover the u32 and u4 layouts.

## Security

SHA-256 provides a 256-bit output, with generic 128-bit collision resistance
and 256-bit preimage/second-preimage resistance. These claims assume canonical
SHA-256 use; they do not authenticate witness data by themselves.

## Script compatibility and standardness

The opcode vocabulary is shared by legacy script and tapscript, but the
generated scripts are large and operation-heavy. Practical use is tapscript or
research execution; many configurations exceed P2SH/P2WSH/bare policy or
legacy limits. The caller must append output verification and cleanstack logic.

The `sha256_prefix(num_bytes, output_bytes)` adapter keeps the first
`1..=32` digest bytes and drops the rest. It does not reduce the compression
cost; use it only when the surrounding protocol deliberately chooses a
truncated digest binding.

## Witness and hints

No hints are required. `sha2_u32` consumes one stack item per byte;
`sha2_u4` consumes two canonical nibbles per byte in the order documented by
the push helpers.
