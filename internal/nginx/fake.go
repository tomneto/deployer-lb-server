package nginx

import "sync"

// FakeRunner is an in-memory, injectable stand-in for Runner used by tests
// (and by anything else that wants to exercise the listener without a real
// nginx/systemd on the host). All behaviors default to "succeeds" and can be
// overridden per test via the *Func fields.
type FakeRunner struct {
	mu sync.Mutex

	TestFunc     func(confDir string) (bool, string, error)
	ReloadFunc   func() (string, error)
	DumpFunc     func() (string, error)
	IsActiveFunc func() (bool, error)

	TestCalls     int
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
