# deployer-lb-server

Go binaries + `setup.sh` provisioner for the load-balancer (`deployer-lb-server`,
build tag `lb`) and the per-host telemetry agent (`deployer-lb-agent`, build
tag `agent`) that report into the backoffice's infra views. `setup.sh`
installs either mode on a target host (Ubuntu/Debian or RHEL-family):
dependencies, WireGuard, the binary itself, config, and the systemd unit.

## Layout

- `cmd/apply-server`, `cmd/agent` — the two binaries' entrypoints.
- `internal/agent` — telemetry collection (connections, disk I/O, containers,
  processes, systemd units, WireGuard peers) and the signed HTTP transport
  that POSTs reports to the backoffice intake.
- `internal/lbserver`, `internal/nginx`, `internal/render` — LB-mode config
  rendering/reload.
- `internal/provision`, `internal/version`, `internal/auth` — shared
  provisioning/versioning/auth helpers.
- `setup.sh` — the idempotent installer driven over SSH by selfApi's
  `provisioning.py` in production.
- `.github/workflows/release.yml` — on `v*` tags: builds both binaries
  (amd64/arm64) and publishes a GitHub release with them as assets.

## Building

```
go build -tags lb    -o deployer-lb-server ./cmd/apply-server
go build -tags agent -o deployer-lb-agent   ./cmd/agent
```

Both binaries print their build version with `-v`/`--version`, stamped via
ldflags from `git describe --tags --always --dirty` — see
`internal/version/version.go`. `setup.sh` (and `release.yml`) build with the
same ldflags.

## Tests

Three tiers, by cost and where each one runs.

### 1. Unit tests — fast, run everywhere

```
go test -tags agent ./internal/...
```

Covers `internal/agent`'s collectors (connections, disk I/O, docker/images/
stats, ports, processes, systemd, WireGuard) and the signed transport
(`transport_test.go`, HMAC scheme in `hmac_test.go`) via injectable seams
(`Runner`, `PingFunc`, `httptest`) — no real host state, no network, no
Docker. Also runs `internal/auth`, `internal/lbserver`, `internal/nginx`,
`internal/render`.

**Not currently run in CI** — `release.yml` only builds; there is no `go
test` step wired in yet. Run it yourself before pushing changes to
`internal/agent`.

There's also a standalone shell-level unit test for the
`setup.sh`/`download_or_build_binary()` fix (rejecting a stale prebuilt
binary that doesn't match the current checkout's version):

```
bash scripts/test-download-or-build-binary.sh
```

No Docker, no network — extracts the real function out of `setup.sh` and
exercises it against a throwaway local git repo + fake binaries.

### 2. `setup.sh` provisioning smoke test — manual only, real systemd containers

```
bash scripts/test-provision.sh              # both distros, mode lb
bash scripts/test-provision.sh --mode agent  # both distros, mode agent
```

Drives the real `setup.sh` via `docker exec` (not SSH) against throwaway
Ubuntu 24.04 / Oracle Linux 9 containers with real systemd
(`docker-compose.provision-test.yaml`, `privileged: true` + mounted cgroup).
**Never run automatically** — hosted CI runners don't reliably grant
`--privileged`/cgroup access to nested containers; see that script's own
header.

### 3. Agent-over-real-SSH integration test — manual only, local before release

```
bash scripts/test-agent-ssh.sh              # local docker fixture
bash scripts/test-agent-ssh.sh --keep       # ...and leave the container up for inspection
```

Brings up `docker-compose.ssh-test.yaml` (systemd + sshd on Ubuntu 24.04 —
heavier than tier 2's fixture because it also needs a real sshd), then runs
`go test -tags integration ./tests/integration/...`, which:

1. SSHes in as root (real SSH, not `docker exec` — mirrors how selfApi's
   `provisioning.py` actually reaches a target in production).
2. Runs the real `setup.sh agent ...` (no bypass — proves provisioning
   itself works, not just the resulting binary).
3. Confirms `deployer-lb-agent.service` comes up active.
4. Confirms the agent's next few reports actually reach a fake intake with
   valid HMAC signatures and `connections`/`disk_io`/`agent_version`
   present — the exact fields whose absence causes the backoffice frontend
   to show "não reporta conexões de rede" / "Aguardando amostras…".
5. Re-runs `scripts/test-download-or-build-binary.sh` over the same SSH
   connection, proving the stale-prebuilt-binary fix holds up remotely too.

**Also confirmed not to run reliably in CI**: `release.yml` briefly gated
releases on this (tag `v0.2.2`) and the job failed in ~2 minutes on a
GitHub-hosted runner — well short of any of the test's own timeouts, so
it's an environment limitation (nested `privileged`/cgroup systemd), not a
flaky hang worth retrying around. Same reasoning as tier 2. Run this
locally before cutting a release instead.

If your local Docker environment also can't create a real WireGuard
interface (e.g. Docker Desktop's WSL2 VM — another nested-virtualization
limitation), point the same test at any other reachable SSH host instead of
the local fixture:

```
SKIP_FIXTURE=1 \
SSH_TEST_HOST=<host> SSH_TEST_USER=root SSH_TEST_PASSWORD=<password> \
INTAKE_ADVERTISE_HOST=<address that host can reach this machine on> \
bash scripts/test-agent-ssh.sh
```

No need to pre-clone anything there — the test tars up the exact local
checkout (uncommitted changes included) and extracts it into a fresh remote
temp dir itself, cleaned up when the test ends. Use `SSH_TEST_KEY=<path>`
instead of `SSH_TEST_PASSWORD` for key-based auth, and `REPO_REMOTE_PATH` to
pin a specific already-populated path instead of the auto-copy. See
`tests/integration/agent_ssh_test.go`'s `envOr()` calls for the full list of
variables and their defaults.

### What actually runs in CI today

Only `.github/workflows/release.yml`'s `build`/`release` jobs, triggered on
`v*` tags: cross-compile both binaries (amd64/arm64) and publish a GitHub
release. No test tier above is wired into CI — all three are run by hand,
tiers 2 and 3 specifically *because* hosted runners can't reliably provide
the privileged/systemd environment they need. Run tiers 1–3 locally before
tagging a release.
