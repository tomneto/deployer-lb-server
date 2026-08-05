//go:build agent

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
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

// dockerInspectEntry mirrors only the fields of `docker inspect` output that
// the report needs — the full schema is huge and versioned by Docker itself.
type dockerInspectEntry struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
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
	} `json:"NetworkSettings"`
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
			State:     e.State.Status,
			Pid:       e.State.Pid,
			StartedAt: e.State.StartedAt,
		}
		if e.State.Health != nil {
			c.Health = e.State.Health.Status
		}

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
