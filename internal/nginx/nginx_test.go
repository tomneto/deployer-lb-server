package nginx

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleDump = `# configuration file /etc/nginx/nginx.conf:
user www-data;
http {
    include /etc/nginx/conf.d/*.conf;
}

# configuration file /etc/nginx/conf.d/legacy-manual.conf:
server {
    listen 80;
    server_name legacy.workspacefy.com www.legacy.workspacefy.com;
    location / { proxy_pass http://127.0.0.1:9000; }
}

# configuration file /etc/nginx/conf.d/app-a.conf:
# managed-by: deployer-lb-server app=app-a revision=3
upstream app_a_pool {
    server 10.10.0.2:10200;
}
server {
    listen 80;
    server_name app-a.workspacefy.com;
    location / { proxy_pass http://app_a_pool; }
}
`

func TestParseDumpDetectsManagedVsLegacy(t *testing.T) {
	blocks := ParseDump(sampleDump)

	var legacy, managed *FileBlock
	for i := range blocks {
		switch blocks[i].File {
		case "/etc/nginx/conf.d/legacy-manual.conf":
			legacy = &blocks[i]
		case "/etc/nginx/conf.d/app-a.conf":
			managed = &blocks[i]
		}
	}
	if legacy == nil {
		t.Fatal("expected to find legacy-manual.conf block")
	}
	if legacy.Managed {
		t.Fatal("legacy-manual.conf must not be classified as managed")
	}
	if len(legacy.ServerNames) != 2 {
		t.Fatalf("expected 2 server_names in legacy block, got %v", legacy.ServerNames)
	}

	if managed == nil {
		t.Fatal("expected to find app-a.conf block")
	}
	if !managed.Managed || managed.App != "app-a" {
		t.Fatalf("expected app-a.conf to be managed by app-a, got %+v", managed)
	}
}

func TestFindDomainOwnerLegacyCollision(t *testing.T) {
	block, found := FindDomainOwner(sampleDump, "legacy.workspacefy.com")
	if !found {
		t.Fatal("expected to find legacy.workspacefy.com")
	}
	if block.Managed {
		t.Fatal("expected legacy.workspacefy.com owner to be unmanaged")
	}
}

func TestFindDomainOwnerManaged(t *testing.T) {
	block, found := FindDomainOwner(sampleDump, "app-a.workspacefy.com")
	if !found {
		t.Fatal("expected to find app-a.workspacefy.com")
	}
	if !block.Managed || block.App != "app-a" {
		t.Fatalf("expected managed by app-a, got %+v", block)
	}
}

func TestFindDomainOwnerNotFound(t *testing.T) {
	_, found := FindDomainOwner(sampleDump, "nowhere.example.com")
	if found {
		t.Fatal("expected not found for an unclaimed domain")
	}
}

func TestWriteAtomicCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app-a.conf")
	if err := WriteAtomic(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteAtomic error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	// no leftover temp files
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 file in dir, got %d", len(entries))
	}
}

func TestCopyConfTreeExcludesAndFilters(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	os.WriteFile(filepath.Join(src, "keep.conf"), []byte("keep"), 0o644)
	os.WriteFile(filepath.Join(src, "app-a.conf"), []byte("exclude-me"), 0o644)
	os.WriteFile(filepath.Join(src, "notes.txt"), []byte("ignore"), 0o644)

	if err := CopyConfTree(src, dst, "app-a.conf"); err != nil {
		t.Fatalf("CopyConfTree error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dst, "keep.conf")); err != nil {
		t.Fatal("expected keep.conf to be copied")
	}
	if _, err := os.Stat(filepath.Join(dst, "app-a.conf")); err == nil {
		t.Fatal("expected app-a.conf to be excluded")
	}
	if _, err := os.Stat(filepath.Join(dst, "notes.txt")); err == nil {
		t.Fatal("expected non-.conf files to be ignored")
	}
}

func TestCopyConfTreeMissingSrcIsNotError(t *testing.T) {
	dst := t.TempDir()
	if err := CopyConfTree(filepath.Join(dst, "does-not-exist"), dst, ""); err != nil {
		t.Fatalf("expected missing srcDir to be tolerated, got %v", err)
	}
}

func TestFakeRunnerDefaults(t *testing.T) {
	f := NewFakeRunner()
	ok, _, err := f.Test("whatever")
	if !ok || err != nil {
		t.Fatal("expected default FakeRunner.Test to succeed")
	}
	if _, err := f.Reload(); err != nil {
		t.Fatal("expected default FakeRunner.Reload to succeed")
	}
	if f.TestCalls != 1 || f.ReloadCalls != 1 {
		t.Fatalf("expected call counters to increment, got Test=%d Reload=%d", f.TestCalls, f.ReloadCalls)
	}
}
