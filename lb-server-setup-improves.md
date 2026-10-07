# setup.sh robustness audit — pending fixes

## Contexto

Depois de corrigir o OOM-kill do docker-ce (`ensure_swap`/`install_docker`,
mesclado e liberado como v0.2.8), foi feita uma auditoria mais ampla do
`setup.sh`: "temos mais coisas que podem ser ou causar falhas?". Três
exploradores cobriram em paralelo (1) deps/distro/docker, (2)
WireGuard/binário/config, (3) systemd/validação/elevação + integração com
`selfApi/api/services/backoffice/deploy/provisioning.py`. Decisão: corrigir
tudo, inclusive baixa severidade.

Um achado ("injeção de comando via heredoc não citado" em
`write_lb_env`/`write_agent_env`) foi **verificado empiricamente e é falso
positivo** — bash não re-avalia o resultado de uma expansão de parâmetro
(`${VAR}` num heredoc não citado expande o valor literal de `VAR` uma única
vez; `$(...)` *dentro do valor* não é tratado como novo comando — testado com
`touch` embutido numa variável, o arquivo não foi criado). Rebaixado para
achado de baixa severidade (corrupção de dado na escrita do arquivo, não
RCE).

Durante a investigação surgiu uma regra de arquitetura que não estava sendo
respeitada: **a porta de controle do LB nunca pode ser exposta em IP
público — sempre WireGuard**. `targets.py:24-36` (`resolve_app_host`)
documenta precedência "wireguard-first, public-IP-fallback, hostname-last",
e `lb_origin()` (`targets.py:51-62`) usa exatamente essa função — logo
`_lb_listen_addr()` (`provisioning.py:204-210`) pode gerar `setup.sh lb
--port <public_ip>:8443`, fazendo o binário Go bindar o listener de controle
(que recebe `/v1/apply` do central) numa interface pública.

**Importante (confirmado pelo usuário):** o fallback para IP público em
`resolve_app_host`/`resolve_ssh_host` é **intencional e não deve ser
removido** — ele existe só para o primeiro SSH de bootstrap, antes de o
WireGuard estar configurado no host (chicken-and-egg: sem SSH não dá pra
rodar `setup.sh` e configurar o WG). WireGuard é o "caminho feliz" tanto para
o tráfego LB↔central quanto, depois do bootstrap, para SSH também. **Não
mexer no firewall de IP público** (não abrir, não fechar) — o fix aqui é
específico do `lb_origin()`/porta de controle do LB, não do mecanismo de
fallback em si.

## Arquivos

- `deployer-lb-server/setup.sh` (maioria dos itens)
- `selfApi/api/services/backoffice/deploy/targets.py` (`lb_origin`) — item do
  IP público, único ponto tocado fora deste repo

## Alta severidade

**A1. `lb_origin()` nunca deve cair para IP público (`selfApi/targets.py`)**
Trocar `lb_origin()` para usar `target.get("wireguard_ip")` diretamente em
vez de `resolve_app_host()`, retornando `None` se ausente. Chamadores já
tratam `None` (`check_listener` retorna `STATUS_UNKNOWN`; `_lb_listen_addr`
cai para `127.0.0.1:8443`, que é seguro — loopback, não público). Não mexer
em `resolve_app_host`/`resolve_ssh_host` genéricos — o fallback deles para
`public_ip` continua existindo e é o caminho certo para o primeiro SSH.

**A2. `setup.sh`: validar que `--port` nunca bind em endereço público**
Em `step4_config_lb` (antes de `write_lb_env`), extrair o host de `$LB_PORT`
e `die()` se não for `127.0.0.1`/`localhost` nem estiver no mesmo /24 de
`$WG_IP`. Defense-in-depth: barra a causa raiz (A1) mesmo se regredir, e
barra um operador rodando o comando manualmente com endereço errado. Não
envolve tocar em firewall algum — é só validação de argumento antes de
escrever a config.

**A3. `rm -f "$tmp"` apaga o binário pré-compilado versionado
(`step3_binary_lb`/`step3_binary_agent`)**
`download_or_build_binary` pode retornar `$REPO_ROOT/bin/$name` diretamente
(quando a versão bate) em vez de uma cópia em `/tmp`. O `rm -f "$tmp"` que
segue apaga esse arquivo do checkout, quebrando o caminho "prefer prebuilt"
já na segunda execução. Fix: só `rm -f` quando `$tmp` estiver sob `/tmp`
(`[[ "$tmp" == /tmp/* ]] && rm -f "$tmp"`).

**A4. `systemctl enable --now`/`restart` nunca checados
(`step5_systemd_lb`/`step5_systemd_agent`)**
Combinado com A5, o script pode terminar com exit 0 e o serviço morto/
crash-loop. Fix: checar exit code de `enable --now` e do `restart`; em caso
de falha, `die()` com `systemctl status --no-pager <unit>` e `journalctl -u
<unit> -n 20 --no-pager` anexados à mensagem.

**A5. `step6_validate_lb`/`step6_validate_agent` nunca falham de verdade**
`GET /v1/health` e `validate_agent_intake` só logam warning. Fix: se o
binário acabou de ser (re)instalado nesta execução e o healthcheck falha,
tratar como fatal — mesmo anexo de `systemctl status`/`journalctl` de A4.
Manter warning apenas quando não há indício de crash (unidade
`active`/`activating`, só ainda não respondeu).

**A6. `wg_installed_version()` sem `|| true` — pode matar o script sem
diagnóstico**
Sob `set -e`, se `wg --version | grep ...` não casar, a atribuição em
`ensure_wireguard_tools_version` aborta o script antes do fallback de log
rodar. Fix: `... | head -n1 || true` — mesmo padrão já usado no parse de
versão do nginx.

**A7. WireGuard nunca reconfigurado em re-run**
Se a interface já existe, o script só valida e nunca reescreve `wg0.conf` —
mesmo que `--wg-peers`/`--wg-hub` tenham mudado; um re-run pra adicionar
peer "funciona" (exit 0) e não muda nada. Fix: sempre regravar `wg0.conf`
(idempotente por natureza) e usar `wg syncconf` (recarrega peers sem
derrubar a interface) quando ela já existe; só cair para `systemctl enable
--now wg-quick@` quando ainda não existir. Log explícito de peers
adicionados/removidos comparando o dump antes/depois.

## Média severidade

**M1. Install de nginx sem contexto de erro** — envolver os 3 branches
(apt/dnf/yum) com captura de exit code e `die()` citando
`OS_ID`/`OS_VERSION_ID`, mesmo padrão de `install_docker`.

**M2. `ensure_rhel_epel` branch "ol" não garante `dnf-plugins-core` antes do
`config-manager`** — replicar o guard já usado em `install_docker`.

**M3. `get.docker.com | sh` sem fallback em distros não-RHEL** — sem mudança
de comportamento (não há repo genérico pra Debian/Ubuntu), só melhorar a
mensagem final de `die()` citando `OS_ID`/`OS_VERSION_ID`.

**M4. Lock de pacote (dnf/apt/yum) pode travar em silêncio até o timeout de
1800s do SSH, sem log** — adicionar timeout explícito nas chamadas de install
mais pesadas, com `die()` citando "package manager lock held" quando estoura.

**M5. Exit code do `iptables-bootstrap.sh` ignorado** — `bash "$bootstrap" ||
die "iptables-bootstrap.sh failed — DNAT chain not fully applied"`.

**M6. Binário baixado só verificado por "não vazio"** — rodar `"$dest" -v`
(ou checar ELF) antes de instalar, `die()` se falhar.

**M7. `parse_peer_list`/`write_wg_peer_blocks` sem proteção contra newline
embutida** — sanitizar/rejeitar newline em cada `pair` antes de interpolar em
`wg0.conf`.

**M8. `write_lb_env`/`write_agent_env`: heredoc não citado pode corromper
valores com `$`/crase** (achado rebaixado, ver Contexto) — trocar para
heredoc citado + `printf '%s=%s\n' KEY "$VALUE"` por linha, tratando o valor
sempre como string literal.

## Baixa severidade

**L1. Flags numéricas não validadas** (`--interval`, `--wg-port`) — validar
`^[0-9]+$` no parsing, `die()` citando o valor recebido se inválido.

**L2. `sudo -n true` falso-negativo com `Defaults requiretty`** — mencionar
esse caso alternativo na mensagem de `die()` de `elevate_to_root`.

**L3. `wg genkey` pode travar por falta de entropia sem log intermediário**
— log antes da chamada avisando que pode ficar esperando entropia.

**L4. `systemctl enable --now` + `restart` incondicional no primeiro
install** — decisão: manter como está (double-start inofensivo), só
documentar a decisão no código.

**L5. Captura de pubkey no log_tail compartilhado entre modos lb+agent no
mesmo host** (`provisioning.py`, fora do setup.sh) — mesmo host = mesma
chave pública, inofensivo; não mexer, só documentar.

## Verificação

- `bash -n setup.sh` a cada bloco de mudança.
- Harness de teste isolado (variáveis + stubs de `swapon`/`dnf`/`systemctl`/
  etc., como já feito pro fix do OOM) para: validação de host de `--port`
  (A2), checagem de exit code de `systemctl` (A4), guard de newline em
  `parse_peer_list` (M7).
- Rodar `wg_iface_configured` + `write_wg_peer_blocks` duas vezes seguidas
  (container real ou mock de `wg`/`ip link`) confirmando que o re-run
  atualiza os peers (A7) sem derrubar a interface.
- Testes Python existentes que já fixam `lb_origin() == wireguard_ip`
  continuam passando: `pytest tests/api/test_backoffice_deploy_engine.py
  tests/api/test_backoffice_deploy_local_target.py
  tests/api/test_backoffice_provisioning.py
  tests/api/test_backoffice_connectivity.py
  tests/api/test_backoffice_lb_sync_worker.py`; adicionar teste novo cobrindo
  `wireguard_ip` ausente → `lb_origin() is None` (hoje cairia em
  `public_ip`).
- Commit + push no `deployer-lb-server` (branch `main`) e tag de release
  nova (`v0.2.9`) seguindo o processo já usado pro fix do OOM.
- Commit no `selfApi` para o fix de `lb_origin`, com os testes acima
  passando.
