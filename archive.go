package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// archiveMember is one file or directory selected for archiving.
type archiveMember struct {
	abs  string      // absolute path on disk
	name string      // slash-separated path stored in the archive
	info os.FileInfo // stat (post-deref for symlinks when -L)
}

// toArchiveName reduces an input path to a safe, slash-separated relative
// name: no leading slash, no drive letter, no leading "../".
func toArchiveName(p string) string {
	p = filepath.Clean(p)
	if vol := filepath.VolumeName(p); vol != "" {
		p = p[len(vol):]
	}
	p = filepath.ToSlash(p)
	p = strings.TrimLeft(p, "/")
	for strings.HasPrefix(p, "../") {
		p = p[len("../"):]
	}
	if p == ".." {
		p = ""
	}
	return p
}

// matchFilters reports whether an archive name passes the include/exclude sets.
// Patterns are matched (path.Match) against both the basename and, if the
// pattern contains a slash, the full slash-path.
func matchFilters(name string, includes, excludes []string) bool {
	base := path.Base(name)
	hit := func(pat string) bool {
		if ok, _ := path.Match(pat, base); ok {
			return true
		}
		if strings.Contains(pat, "/") {
			if ok, _ := path.Match(pat, name); ok {
				return true
			}
		}
		return false
	}
	for _, pat := range excludes {
		if hit(pat) {
			return false
		}
	}
	if len(includes) == 0 {
		return true
	}
	for _, pat := range includes {
		if hit(pat) {
			return true
		}
	}
	return false
}

// collectMembers walks the given roots (or the paths listed in listFile) and
// returns the selected members plus a list of skipped special files.
func collectMembers(roots []string, listFile string, includes, excludes []string, deref bool) (members []archiveMember, skipped []string, err error) {
	if listFile != "" {
		var data []byte
		if listFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(listFile)
		}
		if err != nil {
			return nil, nil, err
		}
		roots = nil
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				roots = append(roots, line)
			}
		}
	}
	if len(roots) == 0 {
		return nil, nil, errors.New("no input paths")
	}

	seen := map[string]bool{}
	add := func(diskPath, arcName string, fi os.FileInfo) {
		arcName = toArchiveName(arcName)
		if arcName == "" || seen[arcName] {
			return
		}
		seen[arcName] = true
		members = append(members, archiveMember{abs: diskPath, name: arcName, info: fi})
	}

	for _, root := range roots {
		lst, lerr := os.Lstat(root)
		if lerr != nil {
			return nil, nil, lerr
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			if !deref {
				skipped = append(skipped, root+" (symlink)")
				continue
			}
			if lst, lerr = os.Stat(root); lerr != nil {
				return nil, nil, lerr
			}
		}

		if !lst.IsDir() {
			if lst.Mode().IsRegular() {
				if matchFilters(toArchiveName(root), includes, excludes) {
					add(root, root, lst)
				}
			} else {
				skipped = append(skipped, root+" (not a regular file)")
			}
			continue
		}

		// A directory is stored relative to its own parent, so
		// `archive out.pqc /home/me/proj` yields "proj/..." rather than
		// burying everything under "home/me/proj/...".
		dirPrefix := path.Base(filepath.ToSlash(filepath.Clean(root)))
		if dirPrefix == "." || dirPrefix == "/" || dirPrefix == "" {
			if abs, e := filepath.Abs(root); e == nil {
				dirPrefix = path.Base(filepath.ToSlash(abs))
			}
		}
		dirPrefix = toArchiveName(dirPrefix)

		walkErr := filepath.WalkDir(root, func(p string, d os.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			rel, _ := filepath.Rel(root, p)
			arcName := path.Join(dirPrefix, filepath.ToSlash(rel))
			fi, ferr := d.Info()
			if ferr != nil {
				return ferr
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				if !deref {
					skipped = append(skipped, p+" (symlink)")
					return nil
				}
				if fi, ferr = os.Stat(p); ferr != nil {
					return ferr
				}
			}
			switch {
			case fi.IsDir():
				add(p, arcName, fi) // keep dir entries so empty dirs survive
			case fi.Mode().IsRegular():
				if matchFilters(arcName, includes, excludes) {
					add(p, arcName, fi)
				}
			default:
				skipped = append(skipped, p+" (not a regular file)")
			}
			return nil
		})
		if walkErr != nil {
			return nil, nil, walkErr
		}
	}

	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
	return members, skipped, nil
}

// writeTar streams a deterministic tar of members into w.
func writeTar(w io.Writer, members []archiveMember) error {
	tw := tar.NewWriter(w)
	for _, m := range members {
		hdr, err := tar.FileInfoHeader(m.info, "")
		if err != nil {
			return err
		}
		hdr.Name = m.name
		if m.info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		// Drop ownership for portable, reproducible archives.
		hdr.Uid, hdr.Gid = 0, 0
		hdr.Uname, hdr.Gname = "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !m.info.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(m.abs)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return err
		}
	}
	return tw.Close()
}

func zstdLevel(name string) (zstd.EncoderLevel, bool) {
	switch name {
	case "", "fast":
		return zstd.SpeedFastest, true
	case "default":
		return zstd.SpeedDefault, true
	case "best":
		return zstd.SpeedBestCompression, true
	case "none":
		return 0, false
	}
	return zstd.SpeedFastest, true
}

// ArchiveSeal builds a tar (optionally zstd-compressed) of members and encrypts
// it to pub, writing the container to out. suggestedName is stored (encrypted)
// as the default extraction directory.
func ArchiveSeal(out io.Writer, members []archiveMember, compress, suggestedName string, pub *PublicKey) error {
	level, useZstd := zstdLevel(compress)
	ctype := CTTar
	if useZstd {
		ctype = CTTarZstd
	}

	pr, pw := io.Pipe()
	go func() {
		var dst io.Writer = pw
		var zw *zstd.Encoder
		if useZstd {
			var zerr error
			if zw, zerr = zstd.NewWriter(pw, zstd.WithEncoderLevel(level)); zerr != nil {
				pw.CloseWithError(zerr)
				return
			}
			dst = zw
		}
		err := writeTar(dst, members)
		if zw != nil {
			if cerr := zw.Close(); err == nil {
				err = cerr
			}
		}
		pw.CloseWithError(err)
	}()

	return SealStream(out, pr, pub, ctype, suggestedName)
}

// sanitizeExtractPath resolves an archive member name to a path inside dest,
// rejecting absolute paths, drive letters, and any ".." escape.
func sanitizeExtractPath(dest, name string) (string, error) {
	name = filepath.ToSlash(name)
	if name == "" || strings.HasPrefix(name, "/") || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	full := filepath.Join(dest, clean)
	rel, err := filepath.Rel(dest, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return full, nil
}

// ArchiveExtract decrypts an archive container from in and writes its contents
// under destDir.
func ArchiveExtract(in io.Reader, priv *PrivateKey, destDir string, overwrite bool) error {
	ctype, _, body, err := OpenStream(in, priv)
	if err != nil {
		return err
	}
	return extractTar(ctype, body, destDir, overwrite)
}

// extractTar unpacks an already-opened archive body. Extraction goes to a
// sibling temp directory first and is promoted to destDir only after the whole
// stream authenticates.
func extractTar(ctype byte, body io.Reader, destDir string, overwrite bool) (err error) {
	if ctype != CTTar && ctype != CTTarZstd {
		return errors.New("this container is a single file, not an archive — use `decrypt`")
	}

	var src io.Reader = body
	if ctype == CTTarZstd {
		zr, zerr := zstd.NewReader(body)
		if zerr != nil {
			return zerr
		}
		defer zr.Close()
		src = zr
	}

	parent := filepath.Dir(destDir)
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(destDir)+".pqc-tmp-")
	if err != nil {
		return err
	}
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			os.RemoveAll(tmp)
		}
	}()

	tr := tar.NewReader(src)
	var nfiles int
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e // includes bodyReader's truncation/tamper errors
		}
		target, e := sanitizeExtractPath(tmp, hdr.Name)
		if e != nil {
			return e
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if e := os.MkdirAll(target, 0o755); e != nil {
				return e
			}
		case tar.TypeReg:
			if e := os.MkdirAll(filepath.Dir(target), 0o755); e != nil {
				return e
			}
			f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, hdr.FileInfo().Mode().Perm())
			if e != nil {
				return e
			}
			_, e = io.Copy(f, tr)
			f.Close()
			if e != nil {
				return e
			}
			nfiles++
		default:
			fmt.Fprintf(os.Stderr, "  skipping %s (unsupported entry type)\n", hdr.Name)
		}
	}

	if err := promoteDir(tmp, destDir, overwrite); err != nil {
		return err
	}
	cleanupTmp = false
	fmt.Printf("extracted %d file(s) -> %s\n", nfiles, destDir)
	return nil
}

// promoteDir moves the freshly extracted tmp tree into place at dest.
func promoteDir(tmp, dest string, overwrite bool) error {
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		return os.Rename(tmp, dest)
	}
	if !overwrite {
		return fmt.Errorf("%s already exists (pass --overwrite to merge into it)", dest)
	}
	return filepath.WalkDir(tmp, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(tmp, p)
		if rel == "." {
			return nil
		}
		dst := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		os.Remove(dst)
		return os.Rename(p, dst)
	})
}
