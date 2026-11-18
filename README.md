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
- `conf/nginx-app.conf.tmpl` — the managed vhost template, **compiled into
  the binary** via `conf/embed.go`. It carries `client_max_body_size 100m;` on
  purpose: nginx defaults to 1m, which is below the 3MB slices the backend's
  chunked upload sends, so uploads got a bare 413 from the proxy. 100m matches
  Cloudflare's Free/Pro cap and leaves the real ceiling to the application. Do
  not drop it.

  `setup.sh` still installs the file under `/etc/nginx/lb-templates/`, but that
  copy is now documentation, not the source: `NGINX_TEMPLATE_PATH` is an
  explicit override and defaults to empty. The reason is skew. Template and
  binary used to ship as two independent artifacts, and `text/template` has no
  tolerance for a field it does not know — a template referencing a method a
  older binary lacks fails at Execute, which `runApplyLocked` turns into a 400,
  which `lb_sync_worker` marks FAILED with no retry. One stale file would have
  silently broken *every* apply on that host. The listener now renders a probe
  payload at boot and refuses to start if it fails, so a bad override halts the
  fleet's canary instead of poisoning applies one pipeline at a time.

  Até v0.6.4 essa frase era só metade verdadeira: `write_lb_env` escrevia
  `NGINX_TEMPLATE_PATH=/etc/nginx/lb-templates/nginx-app.conf.tmpl` no
  `lb.env`, ou seja, deixava o override LIGADO em todo host provisionado — e o
  template vinha do checkout enquanto o binário vinha de `releases/latest`.
  Foi assim que `{{if $.Streaming.Enabled}}`, novo no template, encontrou um
  binário v0.6.4 sem o campo: `VerifyTemplate()` é `log.Fatal` e roda ANTES do
  bind, então o listener morria no boot e a central via `dial tcp
  10.10.0.1:8443: connect: connection refused` — sem 404, sem apply falho, sem
  pista. O `lb.env` agora nasce com a variável vazia.

- Managed vhosts can declare several `location` blocks (`locations` in the
  apply payload, schema_version 2): `=`, `^~`, `~`, `~*` and prefix matchers,
  plus `proxy_pass` to an external destination. Validation is a strict
  allowlist in `internal/render/locations.go` — everything there becomes nginx
  config verbatim, so a `;` or `}` slipping through would be arbitrary config
  injection. Named locations (`@name`) and disk serving (`root`) are
  deliberately NOT supported; the reasons are in that file.

- `GET /v1/fidelity` answers "could the managed template reproduce the vhosts
  this nginx actually serves, and what would be lost trying". Read-only by
  contract: it never emits a ready-to-apply payload, because the classifier
  sits on top of a tolerant parser and must not become a writer of production
  config. An unrecognised directive counts AGAINST a vhost, never in favour.
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

## Releases — toda alteração precisa de uma tag

**Mudou o que o alvo instala (os binários ou o `setup.sh`), corte uma tag
anotada.** Sem ela a alteração existe no GitHub e não chega a host nenhum.

O motivo está no `download_or_build_binary` do `setup.sh`, que resolve o
binário em três degraus:

1. `bin/<nome>` dentro do checkout, quando a central pré-compilou — e **só**
   quando o carimbo de `<binário> -v` bate com o `git describe` do checkout,
   para um binário deixado ali antes de um `git pull` não ser reinstalado
   como se fosse novo;
2. o asset `<nome>-linux-<goarch>` de `releases/latest/download`;
3. `go build` no próprio alvo, que exige Go num host que frequentemente não
   tem.

O degrau 2 é o normal, e ele diz `latest`: sem tag nova, todo alvo que não
recebeu um pré-compilado instala a release anterior. Nada falha, nada avisa
— o painel mostra "deployer atualizado" e o host segue com o binário velho.
Foi exatamente assim que a rota `/v1/include` passou a existir no `main` e o
LB de produção continuou respondendo 404 nela.

Cortar a release:

```
git tag -a v0.6.4 -m "o que mudou, em prosa, para quem vai decidir se rola"
git push origin v0.6.4
```

A tag tem de ser **anotada** (`-a`): o `release.yml` usa a anotação como
corpo das notas da release (`git tag -l --format='%(contents)'`), e uma tag
leve não tem anotação — a release sai com a lista de commits gerada e nada
mais, que não diz a um operador se o agente novo pode ir para produção.

O resto é automático: o workflow compila os quatro binários para amd64 e
arm64, confere que todo asset está no disco antes de publicar (uma release
vazia degradaria em silêncio para "todo alvo compila Go ao provisionar") e
publica com os nomes que o `setup.sh` busca.

Depois da release, "Atualizar deployer" no backoffice entrega o binário
novo. Antes dela, não entrega.

## Tests

Three tiers, by cost and where each one runs.

### 1. Unit tests — fast, run everywhere

```
go test -tags agent ./internal/...
```

Covers `internal/agent`'s collectors (connections, disk I/O, docker/images/
stats, ports, processes, security, systemd, WireGuard) and the signed transport
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

And one for the nftables IP guard (`scripts/lib/ip-lib.sh`), which drives the
reconcile diff, the `/32` normalization and the protected-range refusal
against a mock `nft` that keeps set contents in files:

```
bash scripts/test-ipctl.sh
```

No root, no nftables, no container. What it deliberately does not cover is
whether the kernel accepts the ruleset — that is tier 2.

E um terceiro, para os guardas que separam "o `setup.sh lb` terminou" de "a
porta de controle responde" — `NGINX_TEMPLATE_PATH` vazio no `lb.env`, o
`--port` que não pode ser público, e o health check do step 6 que agora reprova
quando a unit não está nem subindo:

```
bash scripts/test-lb-listener-guards.sh
```

Também sem docker e sem systemd: extrai as funções reais do `setup.sh` e as
exercita contra stubs de `systemctl`/`curl`/`journalctl`.

E dois que cobrem o que os três acima, por construção, não enxergavam — eles
extraem corpos de função com `sed` e os chamam isolados, de modo que o código
de TOPO do `setup.sh` (o parse de flags e a validação de argumentos) nunca era
executado por teste nenhum:

```
bash scripts/test-setup-function-order.sh
bash scripts/test-setup-arg-validation.sh
```

O primeiro é estático: nenhuma linha de topo pode chamar função definida mais
abaixo. Bash só conhece uma função depois de ter LIDO a definição, então uma
chamada antes dela vira `command not found` — exit **127**, antes do primeiro
passo, e sem linha `ERROR:` no log porque `die()` nunca roda. É o primo shell
do `check:tdz` do frontend.

O segundo invoca o `setup.sh` de verdade, com `id` e `sudo` stubados para que
`elevate_to_root` pare na porta do primeiro passo: confere que o parse termina
nos dois modos e que cada argumento recusado traz a própria mensagem. Os dois
aceitam um caminho como argumento, para se conferir que REPROVAM uma versão
quebrada (`git show v0.7.0:setup.sh > /tmp/x.sh`) e não só aprovam a atual.

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

**Rode-o antes de cortar release, mesmo que os testes do tier 1 estejam
verdes.** Ele é o único lugar onde o `setup.sh` encontra um host de verdade, e
a v0.7.0 mostrou o preço de pular: três paredes que nenhum teste de unidade vê
— uma função chamada antes de ser definida (exit 127 em qualquer distro), o
binário `hostname` que o Oracle Linux 9 não traz (exit 127 na primeira linha,
pelo `set -e` numa substituição de comando), e o `default_server` que o pacote
do nginx já instala no Debian/Ubuntu, que faz o `nginx -t` do passo 4 recusar
a config com "a duplicate default server for 0.0.0.0:80".

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
