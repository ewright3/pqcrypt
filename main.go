// pqcrypt is a self-contained CLI for post-quantum file encryption.
//
// It uses a hybrid KEM: X25519 (classical ECDH) combined with ML-KEM-768
// (Kyber, NIST FIPS 203). A random content key is derived from both shared
// secrets via HKDF-SHA-256 and the file body is sealed with AES-256-GCM,
// streamed in 64 KiB chunks so arbitrarily large files use constant memory.
//
// Usage:
//
//	pqcrypt keygen  -out NAME [-pass ENV|-]        generate NAME.pub / NAME.key
//	pqcrypt encrypt -pub NAME.pub -in F [-out F.pqc]
//	pqcrypt decrypt -key NAME.key -in F.pqc [-out F] [-pass ENV|-]
package main

import (
	"errors"
	"fmt"
	"os"
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
      Encrypt FILE to the holder of NAME.key.

  pqcrypt decrypt -key NAME.key -in FILE.pqc [-out FILE] [-pass SOURCE]
      Decrypt FILE.pqc.

SOURCE for -pass:
  (omitted)   prompt on the terminal
  env:VAR     read passphrase from environment variable VAR
  file:PATH   read passphrase from first line of PATH
  -           read passphrase from stdin
`)
}

// ---- flag parsing (tiny, dependency-free) ----

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
			m[a] = "true"
		}
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

	pubArmor, err := readFileTrim(pubPath)
	if err != nil {
		return err
	}
	pub, err := ParsePublicKey(pubArmor)
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

	if err := Encrypt(out, in, pub); err != nil {
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
	outPath := f["out"]
	if outPath == "" {
		outPath = strings.TrimSuffix(inPath, ".pqc")
		if outPath == inPath {
			outPath = inPath + ".dec"
		}
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s", outPath)
	}

	keyArmor, err := readFileTrim(keyPath)
	if err != nil {
		return err
	}
	pass, err := getPassphrase(f["pass"], false)
	if err != nil {
		return err
	}
	priv, err := ParsePrivateKey(keyArmor, pass)
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

	if err := Decrypt(out, in, priv); err != nil {
		out.Close()
		os.Remove(outPath)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	fmt.Printf("decrypted %s -> %s\n", inPath, outPath)
	return nil
}
