package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

// A PQ-hybrid identity: an X25519 keypair plus an ML-KEM-768 (Kyber) keypair.
// Encryption targets the two public keys together; either algorithm staying
// unbroken keeps the file secret.

const (
	pubMagic  = "PQCRYPT PUBLIC KEY"
	privMagic = "PQCRYPT PRIVATE KEY"

	x25519PubLen  = 32
	x25519PrivLen = 32
)

type PublicKey struct {
	X25519 []byte // 32 bytes
	MLKEM  []byte // mlkem768.PublicKeySize
}

type PrivateKey struct {
	X25519 []byte // 32 bytes
	MLKEM  []byte // mlkem768.PrivateKeySize
	Pub    PublicKey
}

// GenerateKeypair creates a fresh hybrid identity.
func GenerateKeypair() (*PrivateKey, error) {
	xPriv := make([]byte, x25519PrivLen)
	if _, err := rand.Read(xPriv); err != nil {
		return nil, err
	}
	xPub, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	kemPub, kemPriv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}
	kemPubB, _ := kemPub.MarshalBinary()
	kemPrivB, _ := kemPriv.MarshalBinary()

	return &PrivateKey{
		X25519: xPriv,
		MLKEM:  kemPrivB,
		Pub: PublicKey{
			X25519: xPub,
			MLKEM:  kemPubB,
		},
	}, nil
}

// ---- public key file (not secret, plain armor) ----

type pubFile struct {
	Version int    `json:"v"`
	X25519  string `json:"x25519"`
	MLKEM   string `json:"mlkem768"`
}

func (p PublicKey) Armor() string {
	body, _ := json.Marshal(pubFile{
		Version: 1,
		X25519:  base64.StdEncoding.EncodeToString(p.X25519),
		MLKEM:   base64.StdEncoding.EncodeToString(p.MLKEM),
	})
	b64 := base64.StdEncoding.EncodeToString(body)
	return armorWrap(pubMagic, b64)
}

func ParsePublicKey(s string) (*PublicKey, error) {
	body, err := armorUnwrap(pubMagic, s)
	if err != nil {
		return nil, err
	}
	var pf pubFile
	if err := json.Unmarshal(body, &pf); err != nil {
		return nil, err
	}
	x, err := base64.StdEncoding.DecodeString(pf.X25519)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(pf.MLKEM)
	if err != nil {
		return nil, err
	}
	if len(x) != x25519PubLen || len(k) != mlkem768.PublicKeySize {
		return nil, errors.New("public key: wrong component size")
	}
	return &PublicKey{X25519: x, MLKEM: k}, nil
}

// ---- private key file (passphrase-encrypted) ----

type privFile struct {
	Version   int    `json:"v"`
	KDF       string `json:"kdf"` // "argon2id"
	Salt      string `json:"salt"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Nonce     string `json:"nonce"`
	Sealed    string `json:"sealed"` // AES-256-GCM(secret JSON)
	Pub       string `json:"pub"`    // armored public key, for convenience
}

type privSecret struct {
	X25519 string `json:"x25519"`
	MLKEM  string `json:"mlkem768"`
}

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
)

func (k *PrivateKey) Armor(passphrase []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, 32)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	secret, _ := json.Marshal(privSecret{
		X25519: base64.StdEncoding.EncodeToString(k.X25519),
		MLKEM:  base64.StdEncoding.EncodeToString(k.MLKEM),
	})
	sealed := gcm.Seal(nil, nonce, secret, []byte(privMagic))

	body, _ := json.Marshal(privFile{
		Version:   1,
		KDF:       "argon2id",
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Time:      argonTime,
		MemoryKiB: argonMemory,
		Threads:   argonThreads,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Sealed:    base64.StdEncoding.EncodeToString(sealed),
		Pub:       k.Pub.Armor(),
	})
	return armorWrap(privMagic, base64.StdEncoding.EncodeToString(body)), nil
}

func ParsePrivateKey(s string, passphrase []byte) (*PrivateKey, error) {
	body, err := armorUnwrap(privMagic, s)
	if err != nil {
		return nil, err
	}
	var pf privFile
	if err := json.Unmarshal(body, &pf); err != nil {
		return nil, err
	}
	if pf.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported kdf %q", pf.KDF)
	}
	salt, _ := base64.StdEncoding.DecodeString(pf.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(pf.Nonce)
	sealed, _ := base64.StdEncoding.DecodeString(pf.Sealed)

	dk := argon2.IDKey(passphrase, salt, pf.Time, pf.MemoryKiB, pf.Threads, 32)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	secretJSON, err := gcm.Open(nil, nonce, sealed, []byte(privMagic))
	if err != nil {
		return nil, errors.New("cannot decrypt private key: wrong passphrase or corrupt file")
	}
	var ps privSecret
	if err := json.Unmarshal(secretJSON, &ps); err != nil {
		return nil, err
	}
	xPriv, _ := base64.StdEncoding.DecodeString(ps.X25519)
	kemPriv, _ := base64.StdEncoding.DecodeString(ps.MLKEM)
	if len(xPriv) != x25519PrivLen || len(kemPriv) != mlkem768.PrivateKeySize {
		return nil, errors.New("private key: wrong component size")
	}
	pk, err := ParsePublicKey(pf.Pub)
	if err != nil {
		return nil, fmt.Errorf("private key file missing embedded public key: %w", err)
	}
	return &PrivateKey{X25519: xPriv, MLKEM: kemPriv, Pub: *pk}, nil
}

// ---- armor helpers ----

func armorWrap(magic, b64 string) string {
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + magic + "-----\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end] + "\n")
	}
	sb.WriteString("-----END " + magic + "-----\n")
	return sb.String()
}

func armorUnwrap(magic, s string) ([]byte, error) {
	begin := "-----BEGIN " + magic + "-----"
	end := "-----END " + magic + "-----"
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j < i {
		return nil, fmt.Errorf("not a %s block", magic)
	}
	inner := s[i+len(begin) : j]
	inner = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, inner)
	raw, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func readFileTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
