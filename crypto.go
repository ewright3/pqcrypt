package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

// On-disk container format:
//
//   magic      "PQCRYPTF1"            9 bytes
//   xEphPub    X25519 ephemeral pub   32 bytes
//   kemCT      ML-KEM-768 ciphertext  mlkem768.CiphertextSize
//   salt       HKDF salt              16 bytes
//   npfx       AES-GCM nonce prefix   4 bytes
//   nameLen    uint16 big-endian      2 bytes
//   nameBlob   AES-256-GCM(original filename), nonce = npfx||2^64-1
//   chunks...  repeated until EOF:
//                len   uint32 big-endian  (length of the following blob)
//                blob  AES-256-GCM(plaintext) incl. 16-byte tag
//
// Per-chunk nonce = npfx (4) || counter uint64 BE (8).
// Per-chunk AAD   = counter uint64 BE (8) || finalFlag byte (1).
// The final chunk carries finalFlag=1, so truncation or extension is detected.

const (
	fileMagic    = "PQCRYPTF2"
	chunkPlain   = 64 * 1024
	saltLen      = 16
	noncePfxLen  = 4
	hkdfInfo     = "pqcrypt v1 aes-256-gcm hybrid x25519+mlkem768"
	filenameAAD  = "pqcrypt v2 filename"
	maxNameLen   = 512
	x25519KeyLen = 32
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

// Encrypt streams plaintext from r into ciphertext on w, sealed to pub.
// origName is the plaintext's original filename; it is encrypted into the
// container so decrypt can restore it. Pass "" to omit it.
func Encrypt(w io.Writer, r io.Reader, pub *PublicKey, origName string) error {
	if len(origName) > maxNameLen {
		return fmt.Errorf("original filename too long (%d > %d)", len(origName), maxNameLen)
	}
	// Ephemeral X25519.
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

	// ML-KEM-768 encapsulation.
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

	// Header.
	if _, err := w.Write([]byte(fileMagic)); err != nil {
		return err
	}
	for _, part := range [][]byte{xEphPub, kemCT, salt, npfx} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}

	// Encrypted original filename.
	sealedName := gcm.Seal(nil, filenameNonce(npfx), []byte(origName), []byte(filenameAAD))
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

// Decrypt reads a container from r, using priv. Once the (authenticated)
// original filename is recovered it calls openOut(origName) to obtain the
// writer for the plaintext, then streams the body into it. openOut may
// ignore the name (e.g. when the caller passed an explicit -out path).
func Decrypt(r io.Reader, priv *PrivateKey, openOut func(origName string) (io.Writer, error)) error {
	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return errors.New("not a pqcrypt file (truncated header)")
	}
	if string(magic) != fileMagic {
		return errors.New("not a pqcrypt file (bad magic)")
	}

	xEphPub := make([]byte, x25519KeyLen)
	kemCT := make([]byte, mlkem768.CiphertextSize)
	salt := make([]byte, saltLen)
	npfx := make([]byte, noncePfxLen)
	for _, part := range [][]byte{xEphPub, kemCT, salt, npfx} {
		if _, err := io.ReadFull(r, part); err != nil {
			return errors.New("truncated header")
		}
	}

	xShared, err := curve25519.X25519(priv.X25519, xEphPub)
	if err != nil {
		return err
	}
	if isAllZero(xShared) {
		return errors.New("x25519: degenerate shared secret")
	}

	scheme := mlkem768.Scheme()
	kemPriv, err := scheme.UnmarshalBinaryPrivateKey(priv.MLKEM)
	if err != nil {
		return fmt.Errorf("bad ml-kem private key: %w", err)
	}
	kemShared, err := scheme.Decapsulate(kemPriv, kemCT)
	if err != nil {
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

	// Encrypted original filename.
	var nlb [2]byte
	if _, err := io.ReadFull(r, nlb[:]); err != nil {
		return errors.New("truncated header (filename length)")
	}
	nameBlob := make([]byte, binary.BigEndian.Uint16(nlb[:]))
	if _, err := io.ReadFull(r, nameBlob); err != nil {
		return errors.New("truncated header (filename)")
	}
	nameBytes, err := gcm.Open(nil, filenameNonce(npfx), nameBlob, []byte(filenameAAD))
	if err != nil {
		return errors.New("header failed authentication (wrong key or corrupt file)")
	}

	w, err := openOut(string(nameBytes))
	if err != nil {
		return err
	}

	var counter uint64
	sawFinal := false
	for {
		var lenb [4]byte
		_, err := io.ReadFull(r, lenb[:])
		if err == io.EOF {
			if !sawFinal {
				return errors.New("ciphertext ends without a final chunk (truncated?)")
			}
			return nil
		}
		if err != nil {
			return errors.New("truncated chunk length")
		}
		if sawFinal {
			return errors.New("trailing data after final chunk (tampered?)")
		}
		clen := binary.BigEndian.Uint32(lenb[:])
		if clen < 16 || clen > chunkPlain+16 {
			return fmt.Errorf("implausible chunk length %d", clen)
		}
		blob := make([]byte, clen)
		if _, err := io.ReadFull(r, blob); err != nil {
			return errors.New("truncated chunk body")
		}

		// Try final=false first, then final=true; only one AAD can authenticate.
		pt, err := gcm.Open(nil, chunkNonce(npfx, counter), blob, chunkAAD(counter, false))
		if err != nil {
			pt, err = gcm.Open(nil, chunkNonce(npfx, counter), blob, chunkAAD(counter, true))
			if err != nil {
				return fmt.Errorf("chunk %d failed authentication (wrong key or corrupt)", counter)
			}
			sawFinal = true
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		counter++
	}
}

func isAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
