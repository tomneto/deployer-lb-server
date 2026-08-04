package nginx

import (
	"regexp"
	"strings"
)

var (
	fileMarkerRe = regexp.MustCompile(`^# configuration file (.+):$`)
	serverNameRe = regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)
	managedByRe  = regexp.MustCompile(`^#\s*managed-by:\s*deployer-lb-server\s+app=(\S+)`)
)

// FileBlock is one file's worth of parsed `nginx -T` output.
type FileBlock struct {
	File        string
	Managed     bool
	App         string
	ServerNames []string
}

// ParseDump splits `nginx -T` output into per-file blocks, tagging each as
// "managed" (first line is our `# managed-by:` header) or not, and
// collecting every server_name it declares.
//
// This is intentionally tolerant of nginx -T's exact formatting quirks
// (indentation, trailing comments) — it only needs to answer one question
// reliably: "does this hostname already live in a file we didn't write?"
func ParseDump(dump string) []FileBlock {
	lines := strings.Split(dump, "\n")
	var blocks []FileBlock
	var current *FileBlock
	atFileStart := false

	flush := func() {
		if current != nil {
			blocks = append(blocks, *current)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if m := fileMarkerRe.FindStringSubmatch(trimmed); m != nil {
			flush()
			current = &FileBlock{File: m[1]}
			atFileStart = true
			continue
		}
		if current == nil {
			continue
		}
		if atFileStart {
			if trimmed != "" {
				if mm := managedByRe.FindStringSubmatch(trimmed); mm != nil {
					current.Managed = true
					current.App = mm[1]
				}
				atFileStart = false
			}
		}
		if mm := serverNameRe.FindStringSubmatch(line); mm != nil {
			current.ServerNames = append(current.ServerNames, strings.Fields(mm[1])...)
		}
	}
	flush()
	return blocks
}

// FindDomainOwner returns the FileBlock that declares domain as a
// server_name, if any.
func FindDomainOwner(dump, domain string) (FileBlock, bool) {
	for _, b := range ParseDump(dump) {
		for _, sn := range b.ServerNames {
			if strings.EqualFold(sn, domain) {
				return b, true
			}
		}
	}
	return FileBlock{}, false
}
