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
	ctype, name, body, err := OpenStream(bytes.NewReader(ct.Bytes()), id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if ctype != CTFile {
		t.Fatalf("ctype = %d, want CTFile", ctype)
	}
	if name != "orig.bin" {
		t.Fatalf("filename not restored: %q", name)
	}
	out, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(plain, out) {
		t.Fatalf("round trip mismatch at size %d", size)
	}
}

func drain(id *PrivateKey, ct []byte) error {
	_, _, body, err := OpenStream(bytes.NewReader(ct), id)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, body)
	return err
}

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
	if err := drain(b, ct.Bytes()); err == nil {
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
	if err := drain(id, cut); err == nil {
		t.Fatal("truncated ciphertext should fail")
	}
}

func TestTamperDetected(t *testing.T) {
	id := newIdentity(t)
	plain := make([]byte, 5000)
	rand.Read(plain)
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(plain), &id.Pub, "x"); err != nil {
		t.Fatal(err)
	}
	b := ct.Bytes()
	b[len(b)-50] ^= 0x01 // flip a bit in the final chunk
	if err := drain(id, b); err == nil {
		t.Fatal("tampered ciphertext should fail")
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
