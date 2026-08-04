package nginx

import (
	"os"
	"path/filepath"
	"strings"
)

// WriteAtomic writes content to path via a temp file in the same directory
// followed by an atomic rename, so readers (including `nginx -t`/reload)
// never observe a partially-written file.
func WriteAtomic(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-apply-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// CopyConfTree copies every *.conf file from srcDir into dstDir, skipping
// excludeName. Used to build the "staging" overlay directory that gets
// nginx -t'd before the real conf.d is touched. Missing srcDir is treated as
// empty (first-ever apply on a fresh host).
func CopyConfTree(srcDir, dstDir, excludeName string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") || strings.HasPrefix(name, ".") {
			continue
		}
		if name == excludeName {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
