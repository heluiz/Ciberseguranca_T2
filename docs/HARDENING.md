# Endurecimento (hardening) do servidor e dos containers

Card S5_15. O servidor `10.0.99.150` é do docente, compartilhado com a turma,
e o aluno entra como usuário comum (sem `sudo`). Por isso o checklist separa o
que **o projeto aplica** (containers, imagem, aplicação) do que **cabe ao
administrador do servidor** (SSH, firewall, atualizações), deixado como
recomendação com os comandos.

## 1. Containers (aplicado, `compose.servidor.yaml` e `compose.yaml`)

| Opção | Em quais serviços | Efeito |
| --- | --- | --- |
| `read_only: true` (e `tmpfs: [/tmp]` onde o programa precisa de temporário) | aplicação, preparação, monitor, terminal | Sistema de arquivos só leitura: um invasor não grava binário nem altera o código |
| `cap_drop: [ALL]` | aplicação, preparação, monitor, terminal | Nenhuma capacidade do kernel (nem trocar dono de arquivo, nem abrir porta baixa) |
| `security_opt: no-new-privileges` | todos | Nenhum processo ganha privilégio por setuid |
| Usuário sem privilégio (`USER` no Dockerfile, uid 10001) | aplicação e terminal | Nada roda como root dentro do container |
| `mem_limit` (512m banco/app, 256m terminal, 128m monitor) e `pids_limit` | todos | Um vazamento de memória ou uma "fork bomb" não derruba o servidor dos colegas |
| Banco sem porta publicada | `db` | O PostgreSQL só é alcançável pela rede interna do Compose |
| Só a aplicação publica porta (2200) | `app` | O terminal não tem porta (S5_20) |
| Papel do banco sem DDL na execução | `app` usa `sentinel_app`; só a preparação usa o proprietário | Uma injeção não criaria nem apagaria tabelas |
| Rotação de log (10 MB × 3) | todos | O disco não enche |
| `restart: unless-stopped` + healthcheck | banco, app, monitor, terminal | Volta sozinho depois de falha ou reinício do servidor |

Verificar depois de subir (a aplicação continua funcionando com tudo isso):

```bash
cd ~/trab02_2026_2_12621cbs200
sh ops/servidor/verificar.sh
docker inspect -f '{{.Name}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} user={{.Config.User}}' \
  $(docker ps -q --filter name=trab02_2026_2_12621cbs200)
curl -fsS http://127.0.0.1:2200/health/
```

O teste `tests_web/test_nomenclatura.py` confere no CI que nenhum serviço
perde essas opções.

## 2. Aplicação (aplicado)

`DEBUG=0`; `manage.py check --deploy` sem aviso; CSP `'self'`; cookies
`HttpOnly`/`SameSite`; bloqueio de força bruta; segundo fator disponível;
senhas Argon2id; segredos gerados por `subir.sh` no `.env` criado com `umask 077` (só o dono lê),
fora do Git e da imagem. Detalhes em [OWASP-TOP10.md](OWASP-TOP10.md) e
[SENHAS-E-ACESSO.md](SENHAS-E-ACESSO.md).

## 3. Imagem (aplicado no CI)

- Base `slim` (Debian sem compilador nem ferramentas de rede).
- `.dockerignore` deixa de fora `.git`, `.env`, testes e documentação.
- Trivy no job `container` do GitHub Actions: falha com vulnerabilidade
  CRÍTICA que já tenha correção. O relatório completo (alta e crítica):

  ```bash
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
    image --severity HIGH,CRITICAL --ignore-unfixed trab02_2026_2_12621cbs200:1.0
  ```

- Corrigir = reconstruir com a base atualizada (`docker compose -f
  compose.servidor.yaml build --pull`) e subir; repetir a varredura e guardar
  as duas saídas (antes e depois) como evidência.

Registre o que a varredura achar no próprio SENTINEL (ativo
"trab02_2026_2_12621cbs200", tipo Sistema interno; uma vulnerabilidade por CVE,
com a nota CVSS que o Trivy mostra) e abra a **Análise de risco**: o risco do
ativo e de quem depende dele é recalculado na hora.

## 4. Servidor (recomendação ao administrador)

Não aplicado pelo aluno: exige `sudo` num servidor compartilhado. Fica como
checklist com os comandos (Ubuntu/Debian).

| Item | Comando ou configuração | Por quê |
| --- | --- | --- |
| SSH só com chave | `/etc/ssh/sshd_config.d/10-hardening.conf`: `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | Senha não pode ser adivinhada se não é aceita |
| Sem login de root | `PermitRootLogin no` | Cada pessoa entra com a própria conta (rastreável) |
| Menos tentativas | `MaxAuthTries 3`, `LoginGraceTime 30` | Força bruta mais lenta |
| Só quem precisa | `AllowGroups alunos professores` | |
| Testar antes de sair | `sudo sshd -t && sudo systemctl reload ssh`, e abrir **outra** sessão antes de fechar a atual | Um erro na configuração não tranca ninguém fora |
| Atualizações de segurança automáticas | `sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades` | Correções do sistema sem esperar alguém lembrar |
| Firewall | `sudo ufw default deny incoming && sudo ufw allow OpenSSH && sudo ufw allow 2000:2999/tcp && sudo ufw enable` | Só SSH e as portas da turma |
| Bloqueio de força bruta | `sudo apt install fail2ban` (jail `sshd`) | |
| Docker | usuários no grupo `docker` equivalem a root no servidor: preferir Docker rootless ou um socket por aluno | Isolamento entre alunos |

## 5. O que o projeto faz para não interferir nos colegas (S5_20)

- Todo nome tem o prefixo `trab02_2026_2_12621cbs200`: projeto Compose,
  containers, imagens, volumes e rede. `docker compose down` só alcança o que
  é do projeto.
- Uma porta só, a 2200; o banco e o terminal não publicam porta.
- Limites de memória e processos em todos os containers.
- `subir.sh` nunca apaga volume e para se encontrar um banco sem o `.env`.
