package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSanitizeExtractPath(t *testing.T) {
	dest := filepath.Join(os.TempDir(), "pqx-dest")
	bad := []string{
		"/etc/passwd",
		"../escape",
		"a/../../escape",
		"",
	}
	if runtime.GOOS == "windows" {
		bad = append(bad, `C:\Windows\System32\x`, `\\server\share\x`)
	}
	for _, b := range bad {
		if _, err := sanitizeExtractPath(dest, b); err == nil {
			t.Errorf("expected rejection for %q", b)
		}
	}
	good := []string{"a/b/c.txt", "file.txt", "deep/nested/ok"}
	for _, g := range good {
		p, err := sanitizeExtractPath(dest, g)
		if err != nil {
			t.Errorf("unexpected rejection for %q: %v", g, err)
		}
		if rel, _ := filepath.Rel(dest, p); rel == ".." {
			t.Errorf("%q escaped dest", g)
		}
	}
}

func TestArchiveRoundTripAndOverwrite(t *testing.T) {
	id := newIdentity(t)
	root := t.TempDir()
	srcDir := filepath.Join(root, "tree")
	mustWrite(t, filepath.Join(srcDir, "a.txt"), "alpha")
	mustWrite(t, filepath.Join(srcDir, "sub", "b.txt"), "bravo")
	mustWrite(t, filepath.Join(srcDir, "sub", "c.log"), "charlie")

	for _, compress := range []string{"none", "fast", "best"} {
		// A directory root is stored relative to its parent, so members
		// land under "tree/..." regardless of srcDir being absolute.
		members, _, err := collectMembers([]string{srcDir}, "", nil, []string{"*.log"}, false)
		if err != nil {
			t.Fatal(err)
		}
		var ct bytes.Buffer
		if err := ArchiveSeal(&ct, members, compress, "tree", &id.Pub); err != nil {
			t.Fatalf("seal (%s): %v", compress, err)
		}
		dest := filepath.Join(root, "out-"+compress)
		if err := ArchiveExtract(bytes.NewReader(ct.Bytes()), id, dest, false); err != nil {
			t.Fatalf("extract (%s): %v", compress, err)
		}
		if got := readFile(t, filepath.Join(dest, "tree", "a.txt")); got != "alpha" {
			t.Errorf("%s: a.txt = %q", compress, got)
		}
		if got := readFile(t, filepath.Join(dest, "tree", "sub", "b.txt")); got != "bravo" {
			t.Errorf("%s: b.txt = %q", compress, got)
		}
		if _, err := os.Stat(filepath.Join(dest, "tree", "sub", "c.log")); err == nil {
			t.Errorf("%s: c.log should have been excluded", compress)
		}
		// Second extract into the same dir must fail without overwrite, succeed with it.
		if err := ArchiveExtract(bytes.NewReader(ct.Bytes()), id, dest, false); err == nil {
			t.Errorf("%s: expected overwrite refusal", compress)
		}
		if err := ArchiveExtract(bytes.NewReader(ct.Bytes()), id, dest, true); err != nil {
			t.Errorf("%s: overwrite extract failed: %v", compress, err)
		}
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
