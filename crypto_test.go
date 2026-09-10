package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func newIdentity(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func roundTrip(t *testing.T, size int) {
	t.Helper()
	id := newIdentity(t)
	plain := make([]byte, size)
	rand.Read(plain)

	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(plain), &id.Pub, "orig.bin"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var out bytes.Buffer
	gotName := ""
	err := Decrypt(bytes.NewReader(ct.Bytes()), id, func(name string) (io.Writer, error) {
		gotName = name
		return &out, nil
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if gotName != "orig.bin" {
		t.Fatalf("filename not restored: %q", gotName)
	}
	if !bytes.Equal(plain, out.Bytes()) {
		t.Fatalf("round trip mismatch at size %d", size)
	}
}

func discard(name string) (io.Writer, error) { return io.Discard, nil }

func TestRoundTripSizes(t *testing.T) {
	for _, s := range []int{0, 1, 100, chunkPlain - 1, chunkPlain, chunkPlain + 1, 3*chunkPlain + 7} {
		roundTrip(t, s)
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader([]byte("hello")), &a.Pub, "x"); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(bytes.NewReader(ct.Bytes()), b, discard); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestTruncationDetected(t *testing.T) {
	id := newIdentity(t)
	plain := make([]byte, 3*chunkPlain)
	rand.Read(plain)
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(plain), &id.Pub, "x"); err != nil {
		t.Fatal(err)
	}
	cut := ct.Bytes()[:ct.Len()-200] // drop part of the final chunk
	if err := Decrypt(bytes.NewReader(cut), id, discard); err == nil {
		t.Fatal("truncated ciphertext should fail")
	}
}

func TestKeyArmorRoundTrip(t *testing.T) {
	id := newIdentity(t)
	pass := []byte("correct horse battery staple")
	armored, err := id.Armor(pass)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKey(armored, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.X25519, id.X25519) || !bytes.Equal(back.MLKEM, id.MLKEM) {
		t.Fatal("key components changed through armor")
	}
	if _, err := ParsePrivateKey(armored, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase should not parse")
	}
}
