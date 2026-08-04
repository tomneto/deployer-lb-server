//go:build agent

package agent

import (
	"errors"
	"reflect"
	"testing"
)

const fixtureInspectJSON = `[
  {
    "Id": "abc123",
    "Name": "/app-a",
    "Config": {"Image": "ghcr.io/tomneto/app-a:latest"},
    "State": {"Status": "running", "Health": {"Status": "healthy"}},
    "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "10200"}]}}
  },
  {
    "Id": "def456",
    "Name": "/redis",
    "Config": {"Image": "redis:7"},
    "State": {"Status": "restarting"},
    "NetworkSettings": {"Ports": {}}
  }
]`

func TestParseDockerInspect(t *testing.T) {
	got, err := ParseDockerInspect([]byte(fixtureInspectJSON))
	if err != nil {
		t.Fatalf("ParseDockerInspect() error = %v", err)
	}

	want := []Container{
		{
			ID:     "abc123",
			Name:   "app-a",
			Image:  "ghcr.io/tomneto/app-a:latest",
			State:  "running",
			Health: "healthy",
			Ports:  []string{"0.0.0.0:10200->8080/tcp"},
		},
		{
			ID:    "def456",
			Name:  "redis",
			Image: "redis:7",
			State: "restarting",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseDockerInspect() = %#v, want %#v", got, want)
	}
}

func TestParseDockerInspect_InvalidJSON(t *testing.T) {
	if _, err := ParseDockerInspect([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestCollectContainers_NoContainers(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name != "docker" || args[0] != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("\n"), nil
	}

	info := CollectContainers(run)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if len(info.Containers) != 0 {
		t.Fatalf("expected no containers, got %v", info.Containers)
	}
}

func TestCollectContainers_HappyPath(t *testing.T) {
	calls := 0
	run := func(name string, args ...string) ([]byte, error) {
		calls++
		if name != "docker" {
			t.Fatalf("unexpected binary: %s", name)
		}
		switch args[0] {
		case "ps":
			return []byte("abc123\ndef456\n"), nil
		case "inspect":
			if !reflect.DeepEqual(args[1:], []string{"abc123", "def456"}) {
				t.Fatalf("unexpected inspect args: %v", args[1:])
			}
			return []byte(fixtureInspectJSON), nil
		default:
			t.Fatalf("unexpected docker subcommand: %s", args[0])
			return nil, nil
		}
	}

	info := CollectContainers(run)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if len(info.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(info.Containers))
	}
	if calls != 2 {
		t.Fatalf("expected 2 docker invocations (ps + inspect), got %d", calls)
	}
}

func TestCollectContainers_PsFails(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("docker: command not found")
	}
	info := CollectContainers(run)
	if info.OK {
		t.Fatal("expected OK=false when docker ps fails")
	}
	if info.Containers == nil {
		t.Fatal("expected non-nil empty Containers slice on failure")
	}
}
