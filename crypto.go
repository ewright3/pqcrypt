package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// On-disk container format:
//
//   magic      "PQCRYPTF3"            9 bytes
//   ctype      content-type byte      1 byte   (see CT* constants)
//   xEphPub    X25519 ephemeral pub   32 bytes
//   kemCT      ML-KEM-768 ciphertext  mlkem768.CiphertextSize
//   salt       HKDF salt              16 bytes
//   npfx       AES-GCM nonce prefix   4 bytes
//   nameLen    uint16 big-endian      2 bytes
//   nameBlob   AES-256-GCM(name), nonce = npfx||2^64-1, AAD = filenameAAD
//   chunks...  repeated until EOF:
//                len   uint32 big-endian  (length of the following blob)
//                blob  AES-256-GCM(plaintext) incl. 16-byte tag
//
// Per-chunk nonce = npfx (4) || counter uint64 BE (8).
// Per-chunk AAD   = counter uint64 BE (8) || finalFlag byte (1).
// The final chunk carries finalFlag=1, so truncation or extension is detected.

const (
	fileMagic    = "PQCRYPTF3"
	chunkPlain   = 64 * 1024
	saltLen      = 16
	noncePfxLen  = 4
	hkdfInfo     = "pqcrypt v1 aes-256-gcm hybrid x25519+mlkem768"
	filenameAAD  = "pqcrypt v2 filename"
	maxNameLen   = 512
	x25519KeyLen = 32
)

// Content types stored in the header's ctype byte.
const (
	CTFile    byte = 0 // body is a single file's bytes
	CTTar     byte = 1 // body is an uncompressed tar stream
	CTTarZstd byte = 2 // body is a zstd-compressed tar stream
)

// filenameNonce is a fixed reserved counter value that data chunks
// (counting up from 0) will never reach, so it can never collide.
func filenameNonce(pfx []byte) []byte { return chunkNonce(pfx, ^uint64(0)) }

func deriveAESKey(xShared, kemShared, salt []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(xShared)+len(kemShared))
	ikm = append(ikm, xShared...)
	ikm = append(ikm, kemShared...)
	r := hkdf.New(sha256.New, ikm, salt, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func chunkNonce(pfx []byte, counter uint64) []byte {
	n := make([]byte, 12)
	copy(n, pfx)
	binary.BigEndian.PutUint64(n[noncePfxLen:], counter)
	return n
}

func chunkAAD(counter uint64, final bool) []byte {
	a := make([]byte, 9)
	binary.BigEndian.PutUint64(a[:8], counter)
	if final {
		a[8] = 1
	}
	return a
}

// SealStream encrypts everything read from r to pub, writing the container to w.
// ctype records what the plaintext body is; name is an advisory label (a
// filename, or a suggested output directory for archives) stored encrypted.
func SealStream(w io.Writer, r io.Reader, pub *PublicKey, ctype byte, name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("name too long (%d > %d)", len(name), maxNameLen)
	}

	xEphPriv := make([]byte, x25519KeyLen)
	if _, err := rand.Read(xEphPriv); err != nil {
		return err
	}
	xEphPub, err := curve25519.X25519(xEphPriv, curve25519.Basepoint)
	if err != nil {
		return err
	}
	xShared, err := curve25519.X25519(xEphPriv, pub.X25519)
	if err != nil {
		return err
	}
	if isAllZero(xShared) {
		return errors.New("x25519: degenerate shared secret")
	}

	scheme := mlkem768.Scheme()
	kemPub, err := scheme.UnmarshalBinaryPublicKey(pub.MLKEM)
	if err != nil {
		return fmt.Errorf("bad ml-kem public key: %w", err)
	}
	kemCT, kemShared, err := scheme.Encapsulate(kemPub)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	npfx := make([]byte, noncePfxLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(npfx); err != nil {
		return err
	}

	key, err := deriveAESKey(xShared, kemShared, salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	if _, err := w.Write([]byte(fileMagic)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{ctype}); err != nil {
		return err
	}
	for _, part := range [][]byte{xEphPub, kemCT, salt, npfx} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}

	sealedName := gcm.Seal(nil, filenameNonce(npfx), []byte(name), []byte(filenameAAD))
	var nlb [2]byte
	binary.BigEndian.PutUint16(nlb[:], uint16(len(sealedName)))
	if _, err := w.Write(nlb[:]); err != nil {
		return err
	}
	if _, err := w.Write(sealedName); err != nil {
		return err
	}

	buf := make([]byte, chunkPlain)
	var counter uint64
	for {
		n, readErr := io.ReadFull(r, buf)
		final := false
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			final = true
		} else if readErr != nil {
			return readErr
		}
		sealed := gcm.Seal(nil, chunkNonce(npfx, counter), buf[:n], chunkAAD(counter, final))
		var lenb [4]byte
		binary.BigEndian.PutUint32(lenb[:], uint32(len(sealed)))
		if _, err := w.Write(lenb[:]); err != nil {
			return err
		}
		if _, err := w.Write(sealed); err != nil {
			return err
		}
		counter++
		if final {
			return nil
		}
	}
}

// OpenStream authenticates and parses a container header from r, then returns a
// reader that decrypts the body on demand. The body reader authenticates each
// chunk before yielding its bytes and returns an error at EOF if the stream was
// truncated (missing final chunk) or extended (trailing data).
func OpenStream(r io.Reader, priv *PrivateKey) (ctype byte, name string, body io.Reader, err error) {
	magic := make([]byte, len(fileMagic))
	if _, err = io.ReadFull(r, magic); err != nil {
		return 0, "", nil, errors.New("not a pqcrypt container (truncated header)")
	}
	if string(magic) != fileMagic {
		return 0, "", nil, errors.New("not a pqcrypt container (bad magic)")
	}
	var cb [1]byte
	if _, err = io.ReadFull(r, cb[:]); err != nil {
		return 0, "", nil, errors.New("truncated header")
	}
	ctype = cb[0]

	xEphPub := make([]byte, x25519KeyLen)
	kemCT := make([]byte, mlkem768.CiphertextSize)
	salt := make([]byte, saltLen)
	npfx := make([]byte, noncePfxLen)
	for _, part := range [][]byte{xEphPub, kemCT, salt, npfx} {
		if _, err = io.ReadFull(r, part); err != nil {
			return 0, "", nil, errors.New("truncated header")
		}
	}

	xShared, err := curve25519.X25519(priv.X25519, xEphPub)
	if err != nil {
		return 0, "", nil, err
	}
	if isAllZero(xShared) {
		return 0, "", nil, errors.New("x25519: degenerate shared secret")
	}

	scheme := mlkem768.Scheme()
	kemPriv, err := scheme.UnmarshalBinaryPrivateKey(priv.MLKEM)
	if err != nil {
		return 0, "", nil, fmt.Errorf("bad ml-kem private key: %w", err)
	}
	kemShared, err := scheme.Decapsulate(kemPriv, kemCT)
	if err != nil {
		return 0, "", nil, err
	}

	key, err := deriveAESKey(xShared, kemShared, salt)
	if err != nil {
		return 0, "", nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, "", nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, "", nil, err
	}

	var nlb [2]byte
	if _, err = io.ReadFull(r, nlb[:]); err != nil {
		return 0, "", nil, errors.New("truncated header (name length)")
	}
	nameBlob := make([]byte, binary.BigEndian.Uint16(nlb[:]))
	if _, err = io.ReadFull(r, nameBlob); err != nil {
		return 0, "", nil, errors.New("truncated header (name)")
	}
	nameBytes, err := gcm.Open(nil, filenameNonce(npfx), nameBlob, []byte(filenameAAD))
	if err != nil {
		return 0, "", nil, errors.New("header failed authentication (wrong key or corrupt container)")
	}

	return ctype, string(nameBytes), &bodyReader{r: r, gcm: gcm, npfx: npfx}, nil
}

// bodyReader decrypts the chunked body produced by SealStream.
type bodyReader struct {
	r       io.Reader
	gcm     cipher.AEAD
	npfx    []byte
	counter uint64
	pending []byte
	sawFin  bool
	done    bool
	err     error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	for {
		if len(b.pending) > 0 {
			n := copy(p, b.pending)
			b.pending = b.pending[n:]
			return n, nil
		}
		if b.err != nil {
			return 0, b.err
		}
		if b.done {
			return 0, io.EOF
		}

		var lenb [4]byte
		_, e := io.ReadFull(b.r, lenb[:])
		if e == io.EOF {
			if !b.sawFin {
				b.err = errors.New("container ends without a final chunk (truncated?)")
				return 0, b.err
			}
			b.done = true
			return 0, io.EOF
		}
		if e != nil {
			b.err = errors.New("truncated chunk length")
			return 0, b.err
		}
		if b.sawFin {
			b.err = errors.New("trailing data after final chunk (tampered?)")
			return 0, b.err
		}
		clen := binary.BigEndian.Uint32(lenb[:])
		if clen < 16 || clen > chunkPlain+16 {
			b.err = fmt.Errorf("implausible chunk length %d", clen)
			return 0, b.err
		}
		blob := make([]byte, clen)
		if _, e := io.ReadFull(b.r, blob); e != nil {
			b.err = errors.New("truncated chunk body")
			return 0, b.err
		}

		pt, e := b.gcm.Open(nil, chunkNonce(b.npfx, b.counter), blob, chunkAAD(b.counter, false))
		if e != nil {
			pt, e = b.gcm.Open(nil, chunkNonce(b.npfx, b.counter), blob, chunkAAD(b.counter, true))
			if e != nil {
				b.err = fmt.Errorf("chunk %d failed authentication (wrong key or corrupt)", b.counter)
				return 0, b.err
			}
			b.sawFin = true
		}
		b.counter++
		b.pending = pt
	}
}

// Encrypt is the single-file convenience wrapper over SealStream.
func Encrypt(w io.Writer, r io.Reader, pub *PublicKey, name string) error {
	return SealStream(w, r, pub, CTFile, name)
}

func isAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
