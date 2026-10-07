package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReadConfTree assembles a `nginx -T`-shaped dump by reading the config files
// itself, following `include` directives from the main file.
//
// It exists because `nginx -T` cannot run under this unit's sandbox. The
// directive that breaks it is not ours to override: the main config already
// declares `pid /run/nginx.pid`, `ProtectSystem=strict` makes /run read-only,
// and passing `-g "pid ..."` fails with "directive is duplicate". Reading is
// never blocked by the sandbox — only writing is — so the file tree is
// reachable even when running nginx is not.
//
// Lower fidelity than the real thing, and deliberately so: it does not expand
// variables, does not resolve `include` paths the way nginx's own prefix logic
// would, and makes no attempt to be a config parser. It produces the same
// `# configuration file <path>:` markers the dump uses, so everything
// downstream treats both sources identically.
func ReadConfTree(mainPath string) (string, error) {
	if mainPath == "" {
		mainPath = "/etc/nginx/nginx.conf"
	}
	seen := map[string]bool{}
	var out strings.Builder
	if err := appendConf(&out, mainPath, filepath.Dir(mainPath), seen, 0); err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// maxIncludeDepth stops a cycle from eating the process. nginx itself refuses
// deep nesting, and a config that needs more than this is beyond what this
// fallback claims to handle.
const maxIncludeDepth = 10

func appendConf(out *strings.Builder, path, prefix string, seen map[string]bool, depth int) error {
	if depth > maxIncludeDepth {
		return nil
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(prefix, abs)
	}
	// An include glob can legitimately name the same file twice; emitting it
	// twice would make the panel show duplicate vhosts that do not exist.
	if seen[abs] {
		return nil
	}
	seen[abs] = true

	body, err := os.ReadFile(abs) // #nosec G304 -- paths come from the config tree
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}

	fmt.Fprintf(out, "# configuration file %s:\n", abs)
	out.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		out.WriteString("\n")
	}

	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "include") {
			continue
		}
		target := strings.TrimSpace(strings.TrimPrefix(trimmed, "include"))
		target = strings.TrimSuffix(strings.TrimSpace(target), ";")
		target = strings.Trim(target, `"'`)
		if target == "" || strings.Contains(target, "$") {
			// A variable in an include path is nginx resolving something at
			// runtime; guessing it would invent config that may not exist.
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(prefix, target)
		}
		matches, err := filepath.Glob(target)
		if err != nil || len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			// A failed include is not fatal: nginx itself tolerates a glob
			// that matches nothing, and one unreadable file must not cost the
			// whole tree.
			_ = appendConf(out, m, prefix, seen, depth+1)
		}
	}
	return nil
}
