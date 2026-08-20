//go:build agent

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Runner executes an external command and returns combined stdout. It is the
// seam that lets tests substitute canned `docker ps`/`docker inspect` output
// without a real Docker daemon.
type Runner func(name string, args ...string) ([]byte, error)

// ExecRunner is the production Runner: it shells out to the real binary.
func ExecRunner(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

// TimeoutRunner is ExecRunner with a hard deadline, for the one docker call
// whose duration is not bounded by anything the agent controls
// (`docker stats --no-stream` samples every container's cgroup twice). Past the
// deadline the child is killed and the caller gets an error — which every
// collector folds into an ok:false section — so a slow docker daemon costs a
// missing section, never a late or skipped report.
func TimeoutRunner(d time.Duration) Runner {
	return func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).Output()
	}
}

// dockerInspectEntry mirrors only the fields of `docker inspect` output that
// the report needs — the full schema is huge and versioned by Docker itself.
type dockerInspectEntry struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
	// ImageID is the top-level `Image` of the inspect entry: the image's
	// config digest ("sha256:…"). Config.Image below is a different thing —
	// the tag the container was started with — and only the digest is a safe
	// join key against the image inventory (C6/WS-6).
	ImageID string `json:"Image"`
	Config  struct {
		Image string `json:"Image"`
		// ExposedPorts is the image's declared container-side ports, keyed
		// "8080/tcp" with an empty-object value. Distinct from
		// NetworkSettings.Ports below, which only describes what was actually
		// PUBLISHED to the host — a container can expose a port nobody mapped.
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
		// Pid/StartedAt feed the C3 cross-referencing: container ↔ host
		// process (ports/processes sections) ↔ start time.
		Pid       int32  `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		// Networks is keyed by network name; a host-network container has a
		// single "host" entry whose IPAddress is empty (it owns no interface).
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
}

// CollectContainers lists containers via `docker ps -q` then resolves detail
// via `docker inspect` on the returned IDs, mirroring build_infra()'s
// container inventory (pipe-improves.md §2.3/§2.7.2). Never returns an error
// to the caller — failures fold into DockerInfo{OK:false} so a missing/broken
// docker CLI never crashes the agent loop.
func CollectContainers(run Runner) DockerInfo {
	if run == nil {
		run = ExecRunner
	}

	psOut, err := run("docker", "ps", "-q")
	if err != nil {
		return DockerInfo{OK: false, Error: "docker ps: " + err.Error(), Containers: []Container{}}
	}

	ids := parseContainerIDs(psOut)
	if len(ids) == 0 {
		return DockerInfo{OK: true, Containers: []Container{}}
	}

	args := append([]string{"inspect"}, ids...)
	inspectOut, err := run("docker", args...)
	if err != nil {
		return DockerInfo{OK: false, Error: "docker inspect: " + err.Error(), Containers: []Container{}}
	}

	containers, err := ParseDockerInspect(inspectOut)
	if err != nil {
		return DockerInfo{OK: false, Error: "parse inspect: " + err.Error(), Containers: []Container{}}
	}

	return DockerInfo{OK: true, Containers: containers}
}

func parseContainerIDs(out []byte) []string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	ids := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			ids = append(ids, l)
		}
	}
	return ids
}

// ParseDockerInspect decodes a `docker inspect` JSON array into the report's
// Container shape. Exported so tests can feed fixtures directly.
func ParseDockerInspect(raw []byte) ([]Container, error) {
	var entries []dockerInspectEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("unmarshal docker inspect output: %w", err)
	}

	out := make([]Container, 0, len(entries))
	for _, e := range entries {
		c := Container{
			ID:        e.ID,
			Name:      strings.TrimPrefix(e.Name, "/"),
			Image:     e.Config.Image,
			ImageID:   e.ImageID,
			State:     e.State.Status,
			Pid:       e.State.Pid,
			StartedAt: e.State.StartedAt,
		}
		if e.State.Health != nil {
			c.Health = e.State.Health.Status
		}
		c.ExposedPorts = parseExposedPorts(e.Config.ExposedPorts)
		c.NetworkMode = e.HostConfig.NetworkMode
		c.Networks, c.IPAddress = parseNetworks(e.NetworkSettings.Networks)

		containerPorts := make([]string, 0, len(e.NetworkSettings.Ports))
		for containerPort := range e.NetworkSettings.Ports {
			containerPorts = append(containerPorts, containerPort)
		}
		sort.Strings(containerPorts)

		for _, containerPort := range containerPorts {
			bindings := e.NetworkSettings.Ports[containerPort]
			if len(bindings) == 0 {
				c.Ports = append(c.Ports, containerPort)
				continue
			}
			for _, b := range bindings {
				c.Ports = append(c.Ports, fmt.Sprintf("%s:%s->%s", b.HostIP, b.HostPort, containerPort))
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// parseNetworks turns docker's `NetworkSettings.Networks` map into the sorted
// network names plus the IP on the first of them.
//
// The IP is deliberately "the first network's" rather than a map: it exists to
// answer "can something else address this container directly", and a container
// on several networks is answered by joining on the NAMES instead. A
// host-network container yields the name "host" and an empty IP — the empty IP
// is information, not a gap.
//
// Returns nil (not an empty slice) when there is nothing, so the field stays
// out of the JSON entirely.
func parseNetworks(raw map[string]struct {
	IPAddress string `json:"IPAddress"`
}) ([]string, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, raw[names[0]].IPAddress
}

// parseExposedPorts turns docker's `Config.ExposedPorts` keys ("8080/tcp",
// "53/udp") into bare port numbers, sorted ascending for a stable report. The
// protocol is dropped on purpose: the consumer joins these against the
// listeners/services view, which is keyed by port. Returns nil (not an empty
// slice) when nothing is exposed, so the field stays out of the JSON entirely.
func parseExposedPorts(raw map[string]struct{}) []int {
	if len(raw) == 0 {
		return nil
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(raw))
	for spec := range raw {
		portStr, _, _ := strings.Cut(spec, "/")
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port <= 0 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Ints(out)
	return out
}

// ContainerPIDs returns the unique host PIDs of the running containers, used
// by CollectProcesses' cardinality filter (container processes are always
// kept).
func (d DockerInfo) ContainerPIDs() []int32 {
	seen := map[int32]bool{}
	out := make([]int32, 0, len(d.Containers))
	for _, c := range d.Containers {
		if c.Pid > 0 && !seen[c.Pid] {
			seen[c.Pid] = true
			out = append(out, c.Pid)
		}
	}
	return out
}
