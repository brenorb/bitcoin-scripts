# AES-128

Bitcoin Script implementation of AES-128 encryption for one 128-bit block with
a generation-time key.

## Parameters

- Block size: fixed at 128 bits, represented by 32 nibbles.
- Key size: fixed at 128 bits. `aes128_encrypt` takes a required `[u8; 16]`
  key and embeds its expanded round keys in the generated fragment; there is no
  default key. Metrics use the all-zero key.
- Encryption only. No public decryption or block-cipher mode is exposed.
- `aes128_expand_key`, `aes128_encrypt_ref`, and `bytes_to_nibbles` are provided
  for key expansion, native reference checks, and stack encoding.
- `aes128_mix_columns` applies the checked AES linear MixColumns layer to one
  128-bit block without a key or the other AES round layers.

## Script metrics

The locking-fragment metric excludes plaintext pushes and output comparison.
Its exact size is mildly key-dependent because zero XOR constants are omitted
and Script-number push widths vary.

| Fragment | Size/depth |
| --- | ---: |
| `aes128_encrypt([0; 16])` | <!-- metric:aes128_encrypt -->25388<!-- /metric:aes128_encrypt --> bytes |
| Plaintext witness, all-zero block | <!-- metric:aes128_witness_min -->33<!-- /metric:aes128_witness_min --> bytes |
| Plaintext witness, no zero nibbles | <!-- metric:aes128_witness_max -->65<!-- /metric:aes128_witness_max --> bytes |
| Maximum combined main/alt-stack depth | <!-- metric:aes128_stack -->908<!-- /metric:aes128_stack --> items |
| `aes128_mix_columns` | <!-- metric:aes128_mix_columns -->3738<!-- /metric:aes128_mix_columns --> bytes |
| MixColumns witness, canonical 7 nibbles | <!-- metric:aes128_mix_columns_witness -->65<!-- /metric:aes128_mix_columns_witness --> bytes |
| MixColumns witness, canonical 15 nibbles | <!-- metric:aes128_mix_columns_witness_max -->65<!-- /metric:aes128_mix_columns_witness_max --> bytes |
| MixColumns maximum combined main/alt-stack depth | <!-- metric:aes128_mix_columns_stack -->908<!-- /metric:aes128_mix_columns_stack --> items |
| MixColumns static non-push opcodes | <!-- metric:aes128_mix_columns_opcodes -->1959<!-- /metric:aes128_mix_columns_opcodes --> |
| MixColumns shared lookup items | <!-- metric:aes128_mix_columns_table_items -->832<!-- /metric:aes128_mix_columns_table_items --> |

The generator uses one 832-item shared lookup memory. It fuses the initial
AddRoundKey into the first SubBytes pass, SubBytes with ShiftRows, and
MixColumns with each following AddRoundKey. Each column's `xtime` values are
computed once and reused by adjacent output rows. The most frequently accessed
tables occupy the shallowest stack positions.

The standalone `aes128_mix_columns` fragment reuses the same 832-item memory,
checks every witness nibble for canonical `0..=15` encoding, and removes the
temporary table before returning. It returns the 32 transformed nibbles in
state order and requires no hints.

Tests execute the FIPS-197 known-answer vector and the all-zero vector, compare
the native reference against three published vectors, and pin the zero-key
size and maximum stack depth. MixColumns tests cover boundary/random vectors,
non-canonical and out-of-range nibbles, and preservation of surrounding stack
state.

## Security

AES-128 has a 128-bit key and a 128-bit block. Its nominal exhaustive-key-search
security is 128 bits, while generic block collisions appear after roughly
`2^64` blocks. The full encryption fragment provides neither authentication
nor a mode of operation; callers must supply those properties. The standalone
MixColumns layer is public linear algebra and makes no independent
cryptographic-security claim. The embedded key is public and this
implementation makes no side-channel claim.

## Script compatibility and standardness

The fragment uses arithmetic and stack opcodes available in both legacy Script
and Tapscript, but its size and opcode count exceed the legacy limits. It is
therefore usable as Tapscript, not as bare script, P2SH, or P2WSH. Tapscript
removes the 10,000-byte script-size and 201-non-push-opcode limits while retaining
the 1,000-item combined-stack limit, which this implementation satisfies.

The fragment alone does not satisfy Tapscript's cleanstack rule because it
intentionally returns 32 transformed nibbles. A caller must compare or consume
all outputs and leave exactly one truthy stack item. `aes128_mix_columns` checks
canonical integer encoding and the `0..=15` range for each input nibble;
`aes128_encrypt` retains its caller-validated input contract.

## Witness and hints

No hints are required. Both fragments consume 32 witness nibbles, with nibble 0
(byte 0's high nibble) on top and nibble 31 (byte 15's low nibble) deepest.
`aes128_encrypt` returns ciphertext in the same order and embeds its key in the
script; `aes128_mix_columns` returns the transformed state and has no key.
