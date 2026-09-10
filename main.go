// pqcrypt is a self-contained CLI for post-quantum file encryption.
//
// It uses a hybrid KEM: X25519 (classical ECDH) combined with ML-KEM-768
// (Kyber, NIST FIPS 203). A content key is derived from both shared secrets
// via HKDF-SHA-256 and the body is sealed with AES-256-GCM, streamed in
// 64 KiB chunks so any size uses constant memory.
//
// Commands:
//
//	pqcrypt keygen  -out NAME [-pass SOURCE]
//	pqcrypt encrypt -pub NAME.pub -in FILE [-out FILE.pqc]
//	pqcrypt decrypt -key NAME.key -in FILE.pqc [-out FILE] [-pass SOURCE]
//	pqcrypt archive -pub NAME.pub -out ARC.pqc [--match GLOB] [--ignore GLOB]
//	                [--compress none|fast|best] [-L] PATH... | @listfile
//	pqcrypt extract -key NAME.key -in ARC.pqc [-o DIR] [--verify-first]
//	                [--overwrite] [-pass SOURCE]
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "encrypt", "enc":
		err = cmdEncrypt(os.Args[2:])
	case "decrypt", "dec":
		err = cmdDecrypt(os.Args[2:])
	case "archive", "ar":
		err = cmdArchive(os.Args[2:])
	case "extract", "x":
		err = cmdExtract(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pqcrypt: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `pqcrypt - post-quantum (hybrid X25519 + ML-KEM-768) file encryption

  pqcrypt keygen  -out NAME [-pass SOURCE]
      Write NAME.pub (share this) and NAME.key (keep secret, passphrase-wrapped).

  pqcrypt encrypt -pub NAME.pub -in FILE [-out FILE.pqc]
      Encrypt one FILE to the holder of NAME.key.

  pqcrypt decrypt -key NAME.key -in FILE.pqc [-out FILE] [-pass SOURCE]
      Decrypt one FILE.pqc.

  pqcrypt archive -pub NAME.pub -out ARC.pqc [options] PATH... | @listfile
      Bundle files/directories into one encrypted, integrity-protected archive.
        --match GLOB      include only entries matching GLOB (repeatable)
        --ignore GLOB     exclude entries matching GLOB (repeatable)
        --compress X      none | fast (default) | best
        -L               follow symlinks (store their target's contents)
        @listfile         read newline-separated paths from a file ("@-" = stdin)

  pqcrypt extract -key NAME.key -in ARC.pqc [-o DIR] [-pass SOURCE]
      Extract an archive. Writes to a temp dir, promoted only after the whole
      stream authenticates.
        -o DIR           output directory (default: name stored in the archive)
        --verify-first   authenticate the entire archive before writing anything
        --overwrite      merge into DIR if it already exists

SOURCE for -pass:
  (omitted)   prompt on the terminal
  env:VAR     read passphrase from environment variable VAR
  file:PATH   read passphrase from the first line of PATH
  -           read passphrase from stdin
`)
}

// ---- flag parsing ----

// parseFlags is the simple "one value per flag" parser used by keygen/
// encrypt/decrypt. Every flag takes a value; a bare trailing flag is "".
func parseFlags(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		a = strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			m[a[:eq]] = a[eq+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			m[a] = args[i+1]
			i++
		} else {
			m[a] = ""
		}
	}
	return m
}

// multiArgs is the richer parser for archive/extract: repeatable flags,
// boolean flags, fused -i!GLOB / -x!GLOB, and positionals.
type multiArgs struct {
	str  map[string]string
	list map[string][]string
	flag map[string]bool
	pos  []string
}

func parseMulti(args []string, boolNames ...string) multiArgs {
	isBool := map[string]bool{}
	for _, b := range boolNames {
		isBool[b] = true
	}
	m := multiArgs{str: map[string]string{}, list: map[string][]string{}, flag: map[string]bool{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			m.pos = append(m.pos, a)
			continue
		}
		a = strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			k, v := a[:eq], a[eq+1:]
			m.str[k] = v
			m.list[k] = append(m.list[k], v)
			continue
		}
		if isBool[a] {
			m.flag[a] = true
			continue
		}
		val := ""
		if i+1 < len(args) && (!strings.HasPrefix(args[i+1], "-") || args[i+1] == "-") {
			val = args[i+1]
			i++
		}
		m.str[a] = val
		m.list[a] = append(m.list[a], val)
	}
	return m
}

func getPassphrase(source string, confirm bool) ([]byte, error) {
	switch {
	case source == "" || source == "prompt":
		fmt.Fprint(os.Stderr, "Passphrase: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if confirm {
			fmt.Fprint(os.Stderr, "Confirm passphrase: ")
			p2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, err
			}
			if string(p) != string(p2) {
				return nil, errors.New("passphrases do not match")
			}
		}
		if len(p) == 0 {
			return nil, errors.New("empty passphrase")
		}
		return p, nil
	case source == "-":
		var line string
		fmt.Fscanln(os.Stdin, &line)
		return []byte(line), nil
	case strings.HasPrefix(source, "env:"):
		v, ok := os.LookupEnv(source[4:])
		if !ok {
			return nil, fmt.Errorf("environment variable %s not set", source[4:])
		}
		return []byte(v), nil
	case strings.HasPrefix(source, "file:"):
		b, err := os.ReadFile(source[5:])
		if err != nil {
			return nil, err
		}
		s := strings.SplitN(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n", 2)[0]
		return []byte(s), nil
	default:
		return nil, fmt.Errorf("unrecognized -pass source %q", source)
	}
}

func loadPublicKey(path string) (*PublicKey, error) {
	s, err := readFileTrim(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(s)
}

func loadPrivateKey(path, passSource string) (*PrivateKey, error) {
	s, err := readFileTrim(path)
	if err != nil {
		return nil, err
	}
	pass, err := getPassphrase(passSource, false)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(s, pass)
}

func cmdKeygen(args []string) error {
	f := parseFlags(args)
	name := f["out"]
	if name == "" {
		return errors.New("keygen: -out NAME is required")
	}
	pubPath := name + ".pub"
	keyPath := name + ".key"
	for _, p := range []string{pubPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("refusing to overwrite existing %s", p)
		}
	}

	pass, err := getPassphrase(f["pass"], true)
	if err != nil {
		return err
	}

	priv, err := GenerateKeypair()
	if err != nil {
		return err
	}
	armoredPriv, err := priv.Armor(pass)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, []byte(priv.Pub.Armor()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, []byte(armoredPriv), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s (public, shareable)\n", pubPath)
	fmt.Printf("wrote %s (private, keep secret)\n", keyPath)
	return nil
}

func cmdEncrypt(args []string) error {
	f := parseFlags(args)
	pubPath, inPath := f["pub"], f["in"]
	if pubPath == "" || inPath == "" {
		return errors.New("encrypt: -pub and -in are required")
	}
	outPath := f["out"]
	if outPath == "" {
		outPath = inPath + ".pqc"
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", outPath)
	}

	pub, err := loadPublicKey(pubPath)
	if err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	if err := Encrypt(out, in, pub, filepath.Base(inPath)); err != nil {
		out.Close()
		os.Remove(outPath)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Printf("encrypted %s -> %s\n", inPath, outPath)
	return nil
}

func cmdDecrypt(args []string) error {
	f := parseFlags(args)
	keyPath, inPath := f["key"], f["in"]
	if keyPath == "" || inPath == "" {
		return errors.New("decrypt: -key and -in are required")
	}
	forcedOut := f["out"] // may be ""

	priv, err := loadPrivateKey(keyPath, f["pass"])
	if err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	ctype, name, body, err := OpenStream(in, priv)
	if err != nil {
		return err
	}
	if ctype != CTFile {
		return errors.New("this container is an archive — use `extract`")
	}

	var outPath string
	if forcedOut != "" {
		outPath = forcedOut
	} else {
		n := sanitizeName(name)
		if n == "" {
			n = strings.TrimSuffix(filepath.Base(inPath), ".pqc")
			if n == filepath.Base(inPath) {
				n += ".dec"
			}
		}
		outPath = filepath.Join(filepath.Dir(inPath), n)
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", outPath)
	}
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(outFile, body); err != nil {
		outFile.Close()
		os.Remove(outPath)
		return err
	}
	if err := outFile.Close(); err != nil {
		return err
	}
	fmt.Printf("decrypted %s -> %s\n", inPath, outPath)
	return nil
}

func cmdArchive(args []string) error {
	a := parseMulti(args, "L", "dereference")
	pubPath := a.str["pub"]
	outPath := a.str["out"]
	if pubPath == "" || outPath == "" {
		return errors.New("archive: -pub and -out are required")
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", outPath)
	}

	var listFile string
	var roots []string
	for _, p := range a.pos {
		if strings.HasPrefix(p, "@") {
			listFile = p[1:]
		} else {
			roots = append(roots, p)
		}
	}
	deref := a.flag["L"] || a.flag["dereference"]

	members, skipped, err := collectMembers(roots, listFile, a.list["match"], a.list["ignore"], deref)
	if err != nil {
		return err
	}
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped %s\n", s)
	}
	if len(members) == 0 {
		return errors.New("nothing selected to archive")
	}

	pub, err := loadPublicKey(pubPath)
	if err != nil {
		return err
	}

	suggested := strings.TrimSuffix(filepath.Base(outPath), ".pqc")
	if len(roots) == 1 {
		if fi, e := os.Stat(roots[0]); e == nil && fi.IsDir() {
			suggested = filepath.Base(roots[0])
		}
	}

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := ArchiveSeal(out, members, a.str["compress"], suggested, pub); err != nil {
		out.Close()
		os.Remove(outPath)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Printf("archived %d entry(ies) -> %s\n", len(members), outPath)
	return nil
}

func cmdExtract(args []string) error {
	a := parseMulti(args, "verify-first", "overwrite")
	keyPath := a.str["key"]
	inPath := a.str["in"]
	if keyPath == "" || inPath == "" {
		return errors.New("extract: -key and -in are required")
	}
	destDir := a.str["o"]
	if destDir == "" {
		destDir = a.str["out"]
	}
	verifyFirst := a.flag["verify-first"]
	overwrite := a.flag["overwrite"]

	priv, err := loadPrivateKey(keyPath, a.str["pass"])
	if err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	ctype, name, body, err := OpenStream(in, priv)
	if err != nil {
		return err
	}
	if ctype != CTTar && ctype != CTTarZstd {
		return errors.New("this container is a single file — use `decrypt`")
	}

	if destDir == "" {
		n := sanitizeName(name)
		if n == "" {
			n = strings.TrimSuffix(filepath.Base(inPath), ".pqc")
			if n == filepath.Base(inPath) {
				n += ".extracted"
			}
		}
		destDir = filepath.Join(filepath.Dir(inPath), n)
	}

	if verifyFirst {
		if _, err := io.Copy(io.Discard, body); err != nil {
			return fmt.Errorf("verification failed, nothing written: %w", err)
		}
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return ArchiveExtract(in, priv, destDir, overwrite)
	}
	return extractTar(ctype, body, destDir, overwrite)
}

// sanitizeName reduces an embedded name to a bare, safe basename:
// no directory components, no drive letters, no "." / ".." .
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.TrimSpace(name)
	if name == "." || name == ".." {
		return ""
	}
	return name
}
