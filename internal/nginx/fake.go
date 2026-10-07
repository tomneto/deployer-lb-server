package nginx

import (
	"fmt"
	"sync"
)

// FakeRunner is an in-memory, injectable stand-in for Runner used by tests
// (and by anything else that wants to exercise the listener without a real
// nginx/systemd on the host). All behaviors default to "succeeds" and can be
// overridden per test via the *Func fields.
type FakeRunner struct {
	mu sync.Mutex

	TestFunc     func(confDir string) (bool, string, error)
	// Nil de propósito por padrão: o host de produção NÃO consegue rodar
	// `nginx -t` contra a config real (ProtectSystem=strict + `pid` em /run),
	// e o default do fake precisa ser o mundo real, não o confortável.
	TestLiveFunc func() (bool, string, error)
	ReloadFunc   func() (string, error)
	DumpFunc     func() (string, error)
	IsActiveFunc func() (bool, error)

	TestCalls     int
	TestLiveCalls int
	ReloadCalls   int
	DumpCalls     int
	IsActiveCalls int
}

// NewFakeRunner returns a FakeRunner whose commands all succeed trivially.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		TestFunc:     func(string) (bool, string, error) { return true, "syntax is ok", nil },
		ReloadFunc:   func() (string, error) { return "reloaded", nil },
		DumpFunc:     func() (string, error) { return "", nil },
		IsActiveFunc: func() (bool, error) { return true, nil },
	}
}

func (f *FakeRunner) TestLive() (bool, string, error) {
	f.mu.Lock()
	fn := f.TestLiveFunc
	f.TestLiveCalls++
	f.mu.Unlock()
	if fn == nil {
		return false, "nginx: [emerg] open() \"/run/nginx.pid\" failed (13: Permission denied)",
			errAssert("sandbox")
	}
	return fn()
}

func (f *FakeRunner) Test(confDir string) (bool, string, error) {
	f.mu.Lock()
	f.TestCalls++
	fn := f.TestFunc
	f.mu.Unlock()
	return fn(confDir)
}

func (f *FakeRunner) Reload() (string, error) {
	f.mu.Lock()
	f.ReloadCalls++
	fn := f.ReloadFunc
	f.mu.Unlock()
	return fn()
}

func (f *FakeRunner) DumpConfig() (string, error) {
	f.mu.Lock()
	f.DumpCalls++
	fn := f.DumpFunc
	f.mu.Unlock()
	return fn()
}

func (f *FakeRunner) IsActive() (bool, error) {
	f.mu.Lock()
	f.IsActiveCalls++
	fn := f.IsActiveFunc
	f.mu.Unlock()
	return fn()
}

// errAssert is a tiny stand-in for "the command failed", so the fake can report
// a non-nil error without importing a heavier package.
func errAssert(msg string) error { return fmt.Errorf("%s", msg) }
