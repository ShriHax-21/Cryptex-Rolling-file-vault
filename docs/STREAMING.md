Streaming encryption metadata

Format (JSON) fields:

- `format_version`: integer. Current format version = 1.
- `wrapped_file_key`: object with KEK wrapping details:
  - `kek_salt`: hex of salt used to derive KEK with KeyManager.derive_key(salt).
  - `ciphertext`: hex of wrapped file key ciphertext.
  - `nonce`: hex nonce used for the KEK AES-GCM wrap.
  - `tag`: hex authentication tag for the wrapped key.
- `file_base_nonce`: hex 8-byte base nonce used to derive per-chunk 12-byte nonces (base||counter).
- `chunk_size`: integer chunk size in bytes used when encrypting.
- `chunks`: list of objects for each chunk in order:
  - `offset`: plaintext offset for this chunk.
  - `length`: ciphertext length in bytes stored in the ciphertext file.
  - `nonce`: hex nonce used for this chunk (12 bytes).
  - `tag`: hex AEAD tag for this chunk.
- `total_plain_size`: integer, original plaintext size.
- `state`: `incomplete` or `completed` — used to indicate resumable state.

Resume behaviour:

- During encryption, a temporary ciphertext file (`<dest>.part`) is written and metadata is updated atomically after each chunk.
- If a crash occurs, re-running the encrypt function will load the metadata and resume from the last recorded chunk.
- The decrypt operation reads the metadata and proceeds chunk-by-chunk, verifying per-chunk AEAD tags.

Backwards compatibility:

- If a ciphertext file lacks a `.meta.json` file, the code falls back to the previous whole-file behaviour (no streaming metadata).
- Small files (<= 1 MiB by default) are written with a single-chunk metadata entry to maintain compatibility.

Notes:

- The KEK is derived with `KeyManager.derive_key(salt)` using a random `kek_salt`; the derived KEK encrypts the per-file random `file_key` via AES-GCM.
- Per-chunk nonces are deterministically derived as `file_base_nonce (8 bytes) || chunk_counter (4 bytes, big-endian)`.
- Metadata updates are atomic via writing `<meta>.tmp` then `os.replace()`.
