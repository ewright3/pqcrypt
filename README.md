# pqcrypt

A self-contained CLI for **post-quantum file encryption**. Single static binary,
no runtime, no external services.

## Cryptography

| Layer | Algorithm |
|-------|-----------|
| Key encapsulation | **Hybrid**: X25519 ECDH  +  **ML-KEM-768** (Kyber, NIST FIPS 203) |
| Key derivation | HKDF-SHA-256 over `x25519_shared \|\| mlkem_shared` |
| Bulk encryption | AES-256-GCM, 64 KiB chunks (constant memory, any file size) |
| Private-key protection | Argon2id (64 MiB, t=3) → AES-256-GCM |

The KEM is **hybrid** on purpose: an attacker must break *both* X25519 and
ML-KEM-768 to recover a file, so you are no worse off than classical crypto today
and protected against a future quantum adversary ("harvest now, decrypt later").

Each chunk authenticates its index and an end-of-stream flag, so truncation,
reordering, or extension of a ciphertext is detected on decrypt.

`encrypt`/`decrypt` handle one file. `archive`/`extract` bundle a filtered file
tree into a single container with the same AEAD stream — see [Archives](#archives-bulk--filtering).

## Install

### Download a prebuilt binary

Grab one from the [latest release](https://github.com/ewright3/pqcrypt/releases/latest).
Every binary is fully static (CGO disabled) — no runtime, nothing to install.

| File | Platform |
|------|----------|
| `pqcrypt-windows-amd64.exe` | Windows, Intel/AMD |
| `pqcrypt-windows-arm64.exe` | Windows on ARM |
| `pqcrypt-macos-arm64` | macOS, Apple Silicon (M1+) |
| `pqcrypt-macos-amd64` | macOS, Intel |
| `pqcrypt-linux-amd64` | Linux, Intel/AMD |
| `pqcrypt-linux-arm64` | Linux, ARM |

```sh
# example: Linux x86-64
VER=v0.1.1
curl -LO https://github.com/ewright3/pqcrypt/releases/download/$VER/pqcrypt-linux-amd64
curl -LO https://github.com/ewright3/pqcrypt/releases/download/$VER/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
chmod +x pqcrypt-linux-amd64
```

On macOS the binary is unsigned, so also run
`xattr -d com.apple.quarantine pqcrypt-macos-*` (or right-click → Open once).

### Build from source

Single platform:

```
go build -o pqcrypt.exe .
```

All platforms at once (Windows / macOS / Linux, amd64 + arm64):

```
./build.sh        # outputs to dist/ with SHA256SUMS.txt
```

## Use

```
# 1. Generate an identity (prompts for a passphrase to wrap the private key)
pqcrypt keygen -out alice
#   -> alice.pub  (share freely)
#   -> alice.key  (secret, passphrase-encrypted)

# 2. Anyone with alice.pub encrypts a file to Alice
pqcrypt encrypt -pub alice.pub -in report.pdf
#   -> report.pdf.pqc

# 3. Alice decrypts with her private key
pqcrypt decrypt -key alice.key -in report.pdf.pqc
#   -> report.pdf   (original name is stored, encrypted, in the container)
```

The original filename is encrypted into the container, so decrypt restores it
even if the `.pqc` file was renamed. It is written next to the input file;
pass `-out PATH` to choose the location yourself. Embedded names are reduced to
a bare basename on extraction (no directory or drive components).

### Archives (bulk + filtering)

Bundle a tree into **one** encrypted, integrity-protected container:

```
# whole directory (zstd-compressed by default)
pqcrypt archive -pub alice.pub -out proj.pqc proj/

# filter: only Go sources, skip vendored deps
pqcrypt archive -pub alice.pub -out src.pqc --match '*.go' --ignore '*/node_modules/*' proj/

# no compression, feed an explicit file list (from find/grep/PowerShell)
find . -name '*.csv' -newer .last | \
  pqcrypt archive -pub alice.pub -out data.pqc --compress none @-

# extract (writes to a temp dir, promoted only after the whole stream verifies)
pqcrypt extract -key alice.key -in proj.pqc            # -> ./proj/
pqcrypt extract -key alice.key -in proj.pqc -o dest --overwrite
pqcrypt extract -key alice.key -in data.pqc --verify-first
```

| Flag | Meaning |
|------|---------|
| `--match GLOB` / `--ignore GLOB` | include / exclude, repeatable; matched against the basename and (if the pattern has a `/`) the full path |
| `--compress none\|fast\|best` | zstd level; default `fast` |
| `-L` | follow symlinks (store target contents); otherwise symlinks and special files are skipped with a notice |
| `@listfile` / `@-` | read newline-separated paths from a file or stdin |
| `--verify-first` | authenticate the entire archive before writing any file (two passes; needs a seekable input) |
| `--overwrite` | merge into an existing output directory |

A directory argument is stored relative to its parent (`proj/…`), so an absolute
path doesn't bury the tree. Member paths are sanitized on extraction — absolute
paths, drive letters, and `..` escapes are rejected.

The whole archive is one AEAD stream: any bit flip, truncation, or added/removed
member fails extraction. **Caveat**: extraction is streaming, so with a tampered
archive some earlier files may already be written to the temp dir before the
failure is detected — the temp dir is then removed, but use `--verify-first` if
you need a hard guarantee that nothing is written unless the whole archive is
intact.

### Passphrase sources (`-pass`)

| Value | Meaning |
|-------|---------|
| *(omitted)* | prompt on the terminal |
| `env:VAR` | read from environment variable `VAR` |
| `file:PATH` | first line of `PATH` |
| `-` | read from stdin |

Existing output files are never overwritten.

## Notes / limitations

- No signatures yet — a file proves it was encrypted to your key, not *who*
  sent it. Add ML-DSA (Dilithium) if you need sender authentication.
- The container format is versioned (`PQCRYPTF3`; a 1-byte content-type marks
  file vs. tar vs. tar+zstd). Future changes bump the magic.
- `--compress` uses zstd; compress-then-encrypt leaks plaintext compressibility
  via ciphertext length. Use `--compress none` if that matters for your data.
- No archive index: `extract` streams the whole container; there is no "list"
  or single-member extract, and no in-place update.
- Uses `github.com/cloudflare/circl` (ML-KEM), `golang.org/x/crypto`
  (X25519 / HKDF / Argon2id), and `github.com/klauspost/compress` (zstd).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
