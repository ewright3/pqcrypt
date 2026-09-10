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

## Build

Single platform:

```
go build -o pqcrypt.exe .
```

All platforms at once (Windows / macOS / Linux, amd64 + arm64):

```
./build.sh        # outputs to dist/ with SHA256SUMS.txt
```

CGO is disabled, so every binary is fully static with no runtime dependency.
Pick the one for your OS/CPU:

| File | Platform |
|------|----------|
| `pqcrypt-windows-amd64.exe` | Windows, Intel/AMD |
| `pqcrypt-windows-arm64.exe` | Windows on ARM |
| `pqcrypt-macos-arm64` | macOS, Apple Silicon (M1+) |
| `pqcrypt-macos-amd64` | macOS, Intel |
| `pqcrypt-linux-amd64` | Linux, Intel/AMD |
| `pqcrypt-linux-arm64` | Linux, ARM |

On macOS/Linux: `chmod +x pqcrypt-*` before first run. macOS may require
`xattr -d com.apple.quarantine pqcrypt-macos-*` since the binary is unsigned.

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
pqcrypt decrypt -key alice.key -in report.pdf.pqc -out report.pdf
```

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
- The container format is versioned (`PQCRYPTF1`); future changes bump the magic.
- Uses `github.com/cloudflare/circl` for ML-KEM and `golang.org/x/crypto` for
  X25519 / HKDF / Argon2id.
