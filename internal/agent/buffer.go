//go:build agent

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"
)

var pushSeq atomic.Uint64

// DiskBuffer persists reports that failed to POST so they can be retried
// once the central is reachable again — "buffer em disco + retry" per plan
// B2. Bounded by MaxFiles to avoid unbounded disk growth if the central is
// down for a long time (oldest files are dropped first).
type DiskBuffer struct {
	Dir      string
	MaxFiles int
}

func NewDiskBuffer(dir string, maxFiles int) *DiskBuffer {
	if maxFiles <= 0 {
		maxFiles = 500
	}
	return &DiskBuffer{Dir: dir, MaxFiles: maxFiles}
}

// Push writes body to a new file named by timestamp (nanosecond-resolution,
// monotonic-ish via time.Now().UnixNano(), sufficient for a single-process
// writer) and trims the oldest files beyond MaxFiles.
func (b *DiskBuffer) Push(body []byte) error {
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return err
	}
	// The sequence suffix guarantees uniqueness/ordering even if two pushes
	// land in the same nanosecond (observed on some filesystems/clocks).
	seq := pushSeq.Add(1)
	name := filepath.Join(b.Dir, fmt.Sprintf("%s-%08d.json", time.Now().UTC().Format("20060102T150405.000000000Z"), seq))
	if err := os.WriteFile(name, body, 0o600); err != nil {
		return err
	}
	return b.trim()
}

// Pending returns buffered file paths, oldest first (lexicographic sort is
// correct because the filename is a fixed-width RFC3339-like timestamp).
func (b *DiskBuffer) Pending() ([]string, error) {
	entries, err := os.ReadDir(b.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, filepath.Join(b.Dir, e.Name()))
	}
	sort.Strings(names)
	return names, nil
}

func (b *DiskBuffer) Remove(path string) error {
	return os.Remove(path)
}

func (b *DiskBuffer) trim() error {
	pending, err := b.Pending()
	if err != nil {
		return err
	}
	excess := len(pending) - b.MaxFiles
	for i := 0; i < excess; i++ {
		_ = os.Remove(pending[i])
	}
	return nil
}
