# Inventário de Equipamentos e Vulnerabilidades

Programa de linha de comando em Python para cadastro, consulta, atualização e
remoção (CRUD) de equipamentos de TI e das vulnerabilidades que os afetam, com
**cálculo do risco de cada equipamento por álgebra linear**, um **plano de
correção** que diz o que mais reduz o risco da rede, uma **base das CVEs
exploradas em ataques**, explicadas em português e que funciona sem internet,
e execução em **container Docker**.

2ª atividade avaliativa (sprints 3, 4 e 5) do Bacharelado em Cibersegurança —
FEELT/UFU, 2026/2. Continuação do Trabalho 1: os requisitos dele continuam
valendo, e o programa foi reescrito em orientação a objetos.

## Início rápido

Com o Docker ligado (veja [O que instalar](#o-que-instalar)), na pasta do
projeto:

```
docker compose up -d --build
docker cp dados_exemplo/inventario_exemplo.json inventario:/app/dados/inventario.json
docker restart inventario
docker attach inventario
```

O primeiro comando constrói a imagem e liga o container, com as opções de
segurança do `compose.yaml`; os dois seguintes põem a base de exemplo no volume
dos dados e religam o programa, que lê a base ao abrir. No `docker attach`,
tecle Enter para ver o menu; Ctrl+P e depois Ctrl+Q saem dele sem parar o
programa. Se já existir um container `inventario`, criado antes com o
`docker run`, apague-o primeiro com `docker rm -f inventario` (os dados ficam
no volume). Sem Docker, com o Python, veja
[Direto no computador](#direto-no-computador). O que mostrar na apresentação
está no [Roteiro de demonstração](#roteiro-de-demonstração). Para clonar (ou
atualizar), construir, pôr a base de exemplo e abrir o programa num comando só,
de qualquer pasta, veja [Em um comando só](#em-um-comando-só).

## Sumário

- [Como executar](#como-executar)
- [Como usar](#como-usar)
- [Requisitos do Trabalho 2](#requisitos-do-trabalho-2)
- [Estrutura](#estrutura)
- [Orientação a objetos](#orientação-a-objetos)
- [O modelo de risco](#o-modelo-de-risco)
- [Formato do arquivo de dados](#formato-do-arquivo-de-dados)
- [Base de CVEs exploradas](#base-de-cves-exploradas)
- [Decisões de projeto](#decisões-de-projeto)
- [Segurança e LGPD](#segurança-e-lgpd)
- [Normas seguidas](#normas-seguidas)
- [Limitações conhecidas](#limitações-conhecidas)
- [Testes](#testes)
- [Fluxo de trabalho no Git](#fluxo-de-trabalho-no-git)
- [Dados de exemplo](#dados-de-exemplo)

## Como executar

Há três jeitos de rodar o programa: direto no computador, com o Python; num
container Docker no seu computador, como na apresentação; e num container no
servidor do docente, onde ele precisa ficar 24 horas no ar (requisito 3). Lá,
ele roda desde 27/10/2026, e as provas estão em
[Provas das 24 horas](#provas-das-24-horas).

### Em um comando só

O jeito mais curto, para quem só quer **abrir o programa**: um único comando
que confere o que falta, clona o repositório (ou o atualiza com `git pull`, se
já existir), constrói a imagem, põe a base de exemplo no volume na primeira vez
e abre o menu. Ele roda de qualquer pasta — não é preciso clonar nem entrar na
pasta do projeto antes. As seções seguintes explicam cada passo em separado,
para quando você quiser entender ou controlar o processo.

Diferente do [Início rápido](#início-rápido), ele abre o programa com
`docker run -it --rm` em vez de `docker attach`: o menu aparece na hora, sem
teclar Enter. Ao sair (opção 0 ou `sair`), o container é descartado, mas os
dados ficam no volume `inventario-dados` e voltam no próximo. Rodar o comando
de novo atualiza o código e reabre, com os mesmos dados.

O Docker precisa estar instalado e ligado — no Windows, o Docker Desktop
aberto (veja [O que instalar](#o-que-instalar)). No Linux, o próprio comando
instala o Git e o Docker se faltarem, e usa `sudo` no Docker enquanto o seu
usuário não estiver no grupo `docker`.

**Windows (PowerShell):**

```
cd $HOME; if (-not (Get-Command git -ErrorAction SilentlyContinue)) { winget install -e --id Git.Git }; if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Host 'Instale o Docker Desktop: winget install -e --id Docker.DockerDesktop'; return }; docker info *> $null; if ($LASTEXITCODE -ne 0) { Write-Host 'Abra o Docker Desktop, espere "Engine running" e rode de novo.'; return }; if (Test-Path "$HOME\Ciberseguranca_T2\.git") { git -C "$HOME\Ciberseguranca_T2" pull } else { git clone https://github.com/heluiz/Ciberseguranca_T2.git "$HOME\Ciberseguranca_T2" }; cd "$HOME\Ciberseguranca_T2"; docker build -t inventario:1.0 .; docker run --rm --user root --entrypoint sh -v inventario-dados:/app/dados inventario:1.0 -c "[ -f /app/dados/inventario.json ] || { cp /app/dados_exemplo/inventario_exemplo.json /app/dados/inventario.json && chown 10001:10001 /app/dados/inventario.json; }"; docker run -it --rm --read-only --security-opt no-new-privileges -v inventario-dados:/app/dados inventario:1.0
```

**Linux (Debian e Ubuntu):**

```
if ! command -v git >/dev/null; then sudo apt update && sudo apt install -y git; fi; if ! command -v docker >/dev/null; then sudo apt install -y docker.io && sudo systemctl enable --now docker; fi; D=docker; docker info >/dev/null 2>&1 || D="sudo docker"; if [ -d ~/Ciberseguranca_T2/.git ]; then git -C ~/Ciberseguranca_T2 pull; else git clone https://github.com/heluiz/Ciberseguranca_T2.git ~/Ciberseguranca_T2; fi; cd ~/Ciberseguranca_T2 && $D build -t inventario:1.0 . && $D run --rm --user root --entrypoint sh -v inventario-dados:/app/dados inventario:1.0 -c '[ -f /app/dados/inventario.json ] || { cp /app/dados_exemplo/inventario_exemplo.json /app/dados/inventario.json && chown 10001:10001 /app/dados/inventario.json; }' && $D run -it --rm --read-only --security-opt no-new-privileges -v inventario-dados:/app/dados inventario:1.0
```

**Arch Linux:**

```
if ! command -v git >/dev/null; then sudo pacman -S --needed --noconfirm git; fi; if ! command -v docker >/dev/null; then sudo pacman -S --needed --noconfirm docker && sudo systemctl enable --now docker; fi; D=docker; docker info >/dev/null 2>&1 || D="sudo docker"; if [ -d ~/Ciberseguranca_T2/.git ]; then git -C ~/Ciberseguranca_T2 pull; else git clone https://github.com/heluiz/Ciberseguranca_T2.git ~/Ciberseguranca_T2; fi; cd ~/Ciberseguranca_T2 && $D build -t inventario:1.0 . && $D run --rm --user root --entrypoint sh -v inventario-dados:/app/dados inventario:1.0 -c '[ -f /app/dados/inventario.json ] || { cp /app/dados_exemplo/inventario_exemplo.json /app/dados/inventario.json && chown 10001:10001 /app/dados/inventario.json; }' && $D run -it --rm --read-only --security-opt no-new-privileges -v inventario-dados:/app/dados inventario:1.0
```

A base de exemplo só entra quando ainda não há dados: se você já cadastrou
alguma coisa, o comando não a sobrescreve. Para recomeçar com ela, apague o
volume antes (`docker volume rm inventario-dados`) e rode de novo. Para abrir
**vazio**, sem a base de exemplo, use o [Início rápido](#início-rápido) sem os
passos do `docker cp`. Mais detalhes da base estão em
[Dados de exemplo](#dados-de-exemplo).

**Sem Docker, com o Python.** Clona ou atualiza, cria o ambiente virtual
(`.venv`), instala as bibliotecas, põe a base de exemplo em
`dados/inventario.json` (se ainda não existir) e abre o programa. Requer o
Python 3.11 ou mais novo (veja [O que instalar](#o-que-instalar)); no Windows,
o comando chama o Python do `.venv` direto, sem ativar, para não esbarrar na
política de execução do PowerShell.

**Windows (PowerShell):**

```
cd $HOME; if (-not (Get-Command git -ErrorAction SilentlyContinue)) { winget install -e --id Git.Git }; if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Write-Host 'Instale o Python 3.11+ (py install 3.14) e abra um terminal novo.'; return }; if (Test-Path "$HOME\Ciberseguranca_T2\.git") { git -C "$HOME\Ciberseguranca_T2" pull } else { git clone https://github.com/heluiz/Ciberseguranca_T2.git "$HOME\Ciberseguranca_T2" }; cd "$HOME\Ciberseguranca_T2"; python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -q -r requirements.txt; if (-not (Test-Path dados\inventario.json)) { New-Item -ItemType Directory -Force dados > $null; Copy-Item dados_exemplo\inventario_exemplo.json dados\inventario.json }; .\.venv\Scripts\python.exe main.py
```

**Linux (Debian e Ubuntu):**

```
if ! command -v git >/dev/null; then sudo apt update && sudo apt install -y git; fi; if ! command -v python3 >/dev/null || ! dpkg -s python3-venv >/dev/null 2>&1; then sudo apt update && sudo apt install -y python3 python3-venv; fi; if [ -d ~/Ciberseguranca_T2/.git ]; then git -C ~/Ciberseguranca_T2 pull; else git clone https://github.com/heluiz/Ciberseguranca_T2.git ~/Ciberseguranca_T2; fi; cd ~/Ciberseguranca_T2 && python3 -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt && mkdir -p dados && { [ -f dados/inventario.json ] || cp dados_exemplo/inventario_exemplo.json dados/inventario.json; } && python main.py
```

**Arch Linux:**

```
if ! command -v git >/dev/null; then sudo pacman -S --needed --noconfirm git; fi; if ! command -v python >/dev/null; then sudo pacman -S --needed --noconfirm python; fi; if [ -d ~/Ciberseguranca_T2/.git ]; then git -C ~/Ciberseguranca_T2 pull; else git clone https://github.com/heluiz/Ciberseguranca_T2.git ~/Ciberseguranca_T2; fi; cd ~/Ciberseguranca_T2 && python -m venv .venv && . .venv/bin/activate && pip install -q -r requirements.txt && mkdir -p dados && { [ -f dados/inventario.json ] || cp dados_exemplo/inventario_exemplo.json dados/inventario.json; } && python main.py
```

### O que instalar

| Ferramenta | Direto no computador | Docker no computador | Servidor do docente | Para conferir |
| --- | --- | --- | --- | --- |
| Git | Sim (ou o ZIP do GitHub) | Sim (ou o ZIP do GitHub) | Sim, no servidor | `git --version` |
| Python 3.11 ou mais novo | Sim | Não: vem na imagem | Não: vem na imagem | `python --version` |
| WSL 2 (só no Windows) | Não | Sim | Não | `wsl --version` |
| Docker | Não | Sim: Docker Desktop | Sim, no servidor | `docker version` |
| Cliente SSH | Não | Não | Sim, no seu computador | `ssh -V` |

**Git.** No Windows, baixe o instalador em
[git-scm.com](https://git-scm.com/downloads/win) e aceite as opções padrão, ou
rode no PowerShell `winget install --id Git.Git -e --source winget`. No Debian
e no Ubuntu: `sudo apt install git`. Sem o Git, o botão **Code → Download
ZIP** do GitHub baixa o código, mas aí não dá para atualizá-lo com `git pull`.

**Python**, só para rodar direto no computador. Use o 3.14, o mesmo da imagem
Docker; os testes passaram do 3.11 ao 3.15. No Windows, o python.org recomenda
hoje o *Python install manager*, da Microsoft Store ou de
[python.org/downloads](https://www.python.org/downloads/): depois de
instalá-lo, `py install 3.14` instala o Python 3.14. O instalador tradicional
ainda existe para o 3.14 (deixa de existir no 3.16); nele, marque **Add
python.exe to PATH**. Abra um terminal novo e confira com `python --version`.
No Debian e no Ubuntu: `sudo apt install python3 python3-venv`; lá o comando
é `python3`.

**WSL 2 e Docker Desktop**, no Windows, para o Docker no computador:

1. A virtualização do processador precisa estar ligada: no Gerenciador de
   Tarefas, em Desempenho → CPU, tem de aparecer "Virtualização: Habilitado".
   Se estiver desabilitada, ligue-a na BIOS (UEFI) do computador.
2. No PowerShell aberto **como administrador**, rode `wsl --install` (ou
   `wsl --update`, se o WSL já estiver instalado) e reinicie o computador. O
   `wsl --version` tem de mostrar a versão 2.1.5 ou mais nova.
3. Instale o
   [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/)
   com a opção **Use WSL 2 instead of Hyper-V** marcada. Ele pede o Windows 10
   22H2 ou o 11 23H2 (ou mais novos) e 8 GB de memória, e é gratuito para uso
   pessoal e educacional.
4. **Abra o Docker Desktop**, que não abre sozinho depois de instalado, e
   espere aparecer "Engine running". Em Settings → General, a opção *Start
   Docker Desktop when you sign in to your computer* faz ele abrir junto com
   o Windows.
5. Confira: `docker version` mostra as partes *Client* e *Server*, e
   `docker run --rm hello-world` baixa e roda uma imagem de teste.

No Linux, instale o [Docker Engine](https://docs.docker.com/engine/install/).
Quem não está no grupo `docker` precisa de `sudo` antes de cada comando
`docker`; `sudo usermod -aG docker $USER` inclui o seu usuário no grupo, a
partir do próximo login. No macOS, use o Docker Desktop.

**Cliente SSH**, para entrar no servidor do docente. Já vem no Windows 10 e no
11, no Linux e no macOS. Se o `ssh -V` não funcionar no Windows, adicione o
recurso opcional *Cliente OpenSSH* nas Configurações.

### Baixar o código

```
git clone https://github.com/heluiz/Ciberseguranca_T2.git
cd Ciberseguranca_T2
```

Os comandos das próximas seções rodam dentro dessa pasta. Para receber as
atualizações do repositório depois, `git pull`.

### Direto no computador

Requer Python 3.11 ou superior e duas bibliotecas: o NumPy, usado no modelo de
risco, e a `cvss`, que calcula a nota CVSS a partir do vetor. O Python 3.10
parou de receber correções de segurança em 1º de outubro de 2026, por isso não
é mais indicado. Os testes passaram do Python 3.11 ao 3.15, com o NumPy 1.26,
o 2.4 e o 2.5; a imagem Docker usa o Python 3.14.

As bibliotecas ficam num ambiente virtual (*venv*): a pasta `.venv`, dentro do
projeto, com uma cópia própria delas, sem mexer no Python do sistema. No Linux
ele é obrigatório, porque lá o Python do sistema recusa o `pip install` com o
erro `externally-managed-environment`. A pasta `.venv` fica fora do Git e da
imagem Docker.

No Windows, no PowerShell:

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

No Linux e no macOS:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Com o ambiente ativado (a segunda linha), o `(.venv)` aparece no começo da
linha de comando, e `python` e `pip` passam a ser os do ambiente. Num terminal
novo, basta ativar de novo e rodar `python main.py`: a instalação não se
repete. Se o PowerShell disser que a execução de scripts foi desabilitada,
rode uma vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` e ative de
novo.

O programa começa com a base vazia (`dados/inventario.json`, criado ao gravar
a primeira alteração). Para testá-lo com dados fictícios, veja
[Dados de exemplo](#dados-de-exemplo). Para sair, use a opção 0 ou digite
`sair`. Os testes estão em [Testes](#testes).

### Em container Docker

Requer o Docker ligado (veja [O que instalar](#o-que-instalar)): no Windows,
abra o Docker Desktop antes. Os comandos rodam na pasta do projeto, e a
primeira construção precisa de internet, para baixar a imagem do Python e as
bibliotecas.

```
docker build -t inventario:1.0 .
docker volume create inventario-dados

docker run -dit --name inventario --restart unless-stopped \
  --read-only --security-opt no-new-privileges \
  -v inventario-dados:/app/dados inventario:1.0

docker attach inventario
```

(No PowerShell, a barra invertida no fim da linha não continua o comando:
escreva o `docker run` numa linha só, sem as barras.) Para começar com a base
de exemplo, copie-a para o volume antes do primeiro `docker run`, como em
[Dados de exemplo](#dados-de-exemplo).

No `docker attach` a tela costuma aparecer vazia, porque o Docker não repete
o que já foi impresso: **tecle Enter e a tela de abertura (logotipo e menu) é
desenhada de novo** (se o programa estiver esperando a opção do menu; numa
pergunta, o Enter vale como resposta). Para sair sem parar o programa, tecle
**Ctrl+P e depois Ctrl+Q.** O container continua rodando e dá para voltar com
outro `docker attach`. No terminal do VS Code, o Ctrl+P abre a busca de
arquivos do editor e não chega ao Docker: faça o `docker attach` no PowerShell
ou no Windows Terminal.

O `compose.yaml` é uma alternativa que faz a construção, o volume e a execução
de uma vez, com as mesmas opções: `docker compose up -d --build`, seguido de
`docker attach inventario`. Use um jeito ou o outro: os dois dão ao container
o nome `inventario`, e o segundo daria conflito. Para trocar, apague antes o
container com `docker rm -f inventario`; os dados continuam no volume.

| Opção | Por quê |
| --- | --- |
| `-d` | O container roda em segundo plano (*detached*). |
| `-i` e `-t` | Mantêm a entrada aberta e alocam um terminal. O processo principal é um menu que espera o teclado com `input()`; sem terminal, `input()` recebe fim de entrada e o programa terminaria na hora. Por isso é `-dit` e não só `-d`. Sem terminal, o programa explica isso e para. |
| `--restart unless-stopped` | O Docker religa o programa se ele cair ou se o servidor reiniciar, a não ser que alguém tenha parado o container de propósito (`docker stop`). |
| `--read-only` | O sistema de arquivos do container fica só para leitura; o programa grava apenas no volume dos dados. Quem conseguisse rodar algo lá dentro não poderia alterar o código nem instalar nada. |
| `--security-opt no-new-privileges` | Nenhum processo do container consegue ganhar mais privilégios do que já tem (por exemplo, por um programa com *setuid*). |
| `-v inventario-dados:/app/dados` | Os dados ficam num *volume*: sobrevivem a `docker rm` e à troca da imagem por uma versão nova. A base de CVEs atualizada (opção 16) fica no mesmo volume. |

Dentro do container o programa se comporta de forma diferente em cinco pontos,
ligados pela variável de ambiente `INVENTARIO_EM_CONTAINER` (definida no
`Dockerfile`):

- **Ctrl+C é ignorado.** No `docker attach` ele chegaria ao programa e o
  derrubaria; o menu lembra que Ctrl+P, Ctrl+Q é o caminho para sair.
- **Sair pede confirmação**, seja pela opção 0, seja digitando `sair` em
  qualquer pergunta, porque encerrar o programa para o container (o Docker o
  religa, mas o tempo de atividade recomeça).
- **Ctrl+D é ignorado** (com um aviso), pelo mesmo motivo.
- **Enter no menu traz a tela de abertura**: limpa a tela e mostra o logotipo
  e o menu, porque depois do `docker attach` a tela fica vazia. O Docker só
  avisa o programa da conexão quando o tamanho da janela muda, então não dá
  para desenhar a tela sozinho em todo `attach`.
- **`docker stop` encerra na hora.** O programa trata o sinal SIGTERM; sem
  isso, o processo número 1 do container o ignoraria e o Docker esperaria 10
  segundos antes de matá-lo.

Para acompanhar o container:

```
docker ps                                   # STATUS mostra "Up ... " e (healthy)
docker inspect -f '{{.State.StartedAt}}' inventario
docker logs inventario                      # saída do programa
docker stop inventario                      # para (não religa sozinho)
docker start inventario                     # liga de novo, com os mesmos dados
```

O `HEALTHCHECK` do `Dockerfile` confere a cada minuto que o arquivo de dados
continua legível e válido; `docker ps` mostra `(healthy)` enquanto estiver.

Se o arquivo de dados ficar inválido (editado à mão com erro, por exemplo), o
programa recusa a base e termina com código 1, sem sobrescrever nada; com
`--restart unless-stopped`, o Docker tenta religá-lo de novo e de novo, com um
intervalo que dobra a cada tentativa (até 1 minuto). Para consertar:
`docker stop inventario`, depois corrija o arquivo dentro do volume (por
exemplo, `docker run --rm -it -v inventario-dados:/d alpine vi /d/inventario.json`)
ou mova-o para outro nome, e `docker start inventario`.

Para atualizar o programa, mantendo os dados: o `git pull` traz o código novo,
e o `docker run` é o mesmo de antes.

```
git pull
docker build -t inventario:1.0 .
docker rm -f inventario
docker run -dit --name inventario --restart unless-stopped \
  --read-only --security-opt no-new-privileges \
  -v inventario-dados:/app/dados inventario:1.0
```

Se o volume foi criado por uma versão anterior da imagem, em que o usuário do
programa tinha o UID 1000 (hoje é 10001), rode uma vez, entre o `docker rm` e o
`docker run`, o comando abaixo, que passa os arquivos do volume para o usuário
novo. Sem ele, o programa lê a base, mas não consegue gravar:

```
docker run --rm --user root -v inventario-dados:/app/dados inventario:1.0 chown -R 10001:10001 /app/dados
```

### No servidor do docente

O requisito 3 pede o container funcionando por no mínimo 24 horas num servidor
disponibilizado pelo docente. O servidor é um Linux compartilhado pela turma:
cada aluno tem um usuário próprio, com `sudo`, e entra por SSH para rodar lá os
mesmos comandos do Docker. O docente informa o endereço, o usuário e a senha
inicial. O endereço é da rede interna da universidade: só dá para entrar de
dentro dela, no campus, ou por uma VPN que chegue até ela.

Os comandos abaixo usam `usuario` e `endereco-do-servidor` no lugar dos dados
reais, que ficam fora deste repositório público, e o sufixo `heluiz` nos nomes
da imagem, do container e do volume. Quem repetir os passos troca o sufixo pelo
próprio nome: num servidor compartilhado, nomes iguais aos de um colega dão
conflito ou misturam os dados dos dois.

#### Como ficou a implantação

O container foi ligado no servidor do docente em 27/10/2026, com os passos de
[Implantar, passo a passo](#implantar-passo-a-passo), e o requisito está
cumprido: na leitura de 29/10, às 20:19, ele estava no ar havia 46 horas, sem
interrupção, como mostram as [Provas das 24 horas](#provas-das-24-horas).

| O quê | No servidor do docente |
| --- | --- |
| Versão | Commit `abae5ec`, a `main` depois do Pull Request #12 |
| Imagem | `inventario-heluiz:1.0`, construída no próprio servidor (277 MB) |
| Volume | `inventario-heluiz-dados`, com a base de exemplo, que é fictícia |
| Container | `inventario-heluiz`, ligado com `--restart unless-stopped`, `--read-only` e `--security-opt no-new-privileges`; roda com o usuário `inventario` e não publica nenhuma porta |
| Acesso | Por SSH, com chave e o atalho `ufu`; a senha inicial foi trocada |
| Registro | Uma linha por hora em `uptime_inventario.log`, gravada pelo `cron` do servidor |

#### Acessar o servidor

O servidor só responde de dentro da rede da universidade; fora dela, o `ssh`
termina em `Connection timed out`. De qualquer computador, quem entra é o mesmo
usuário: muda só o jeito de provar quem é, com a chave ou com a senha.

**Do computador com a chave**, aquele em que foi feito o passo 2: ele tem a
chave SSH e o atalho `ufu` e entra sem pedir senha. No PowerShell (no Linux e
no macOS, no terminal):

```
ssh ufu                                            # entra no servidor; exit sai
ssh ufu docker ps --filter name=inventario-heluiz  # o container está no ar?
ssh ufu "date; docker inspect -f '{{.State.StartedAt}}' inventario-heluiz"
ssh ufu tail -n 5 uptime_inventario.log            # as últimas horas do registro
scp ufu:uptime_inventario.log .                    # traz uma cópia do registro
ssh -t ufu docker attach inventario-heluiz         # abre o menu do programa
```

O terceiro comando mostra a hora do servidor e o momento em que o container
ligou, em UTC (três horas à frente de Brasília): a diferença entre os dois é o
tempo exato no ar, que o `docker ps` arredonda. No último, o `-t` pede um
terminal ao SSH; sem ele, o `docker attach` recusa com
`the input device is not a TTY`. No menu, tecle Enter para ver a tela e saia
com Ctrl+P e depois Ctrl+Q, que desligam o terminal sem parar o programa. A
opção 0 e o `sair`, depois de confirmados, encerram o programa: o Docker religa
o container, mas o tempo no ar recomeça (veja o passo 8). No terminal do VS
Code, o Ctrl+P não chega ao Docker: use o PowerShell ou o Windows Terminal.

**De outro computador seu**, crie nele uma chave e copie a parte pública para o
servidor, como no passo 2 (a senha é pedida uma última vez), e crie o mesmo
atalho `ufu`: daí em diante, os comandos acima funcionam iguais. Cada
computador tem a sua chave; a privada (o arquivo `id_ed25519`, sem o `.pub`)
nunca sai do computador em que foi criada. Um comentário com o nome do
computador no `ssh-keygen` (`-C "notebook"`, por exemplo) identifica cada chave
no servidor: `ssh ufu cat .ssh/authorized_keys` lista as chaves, uma por linha,
e apagar a linha de um computador (com `nano ~/.ssh/authorized_keys`, no
servidor) tira o acesso dele.

**De um computador que não é seu**, como o de um laboratório, entre com o
usuário e a senha, sem criar chave nem atalho nele:

```
ssh usuario@endereco-do-servidor
ssh usuario@endereco-do-servidor docker ps --filter name=inventario-heluiz
ssh -t usuario@endereco-do-servidor docker attach inventario-heluiz
```

A senha é pedida a cada comando, não aparece enquanto é digitada e nunca vai na
linha de comando, que fica no histórico do terminal. Na primeira conexão de
cada computador, o SSH mostra a impressão digital (*fingerprint*) da chave do
servidor e pergunta se deve confiar nela. Na conexão de 29/10/2026, a chave do
servidor do docente apareceu como ED25519, com a impressão digital
`SHA256:fBlR6gdx1SG+BOMn96iQnH3lTCASIODy4Wo1lEs5JsU`; no computador com a
chave, `ssh-keygen -lF endereco-do-servidor` mostra a que ficou guardada na
primeira conexão dele. Iguais, responda `yes`; diferentes, não continue (veja
`REMOTE HOST IDENTIFICATION HAS CHANGED`, em
[Problemas comuns](#problemas-comuns)).

Ao terminar, apague o que ficou nesse computador: as cópias de provas que tiver
gravado e o registro do servidor, que o SSH guardou na primeira conexão. No
PowerShell:

```
ssh-keygen -R endereco-do-servidor
Remove-Item $HOME\.ssh\known_hosts.old
Remove-Item $HOME\evidencias_24h.txt       # se gravou aqui a prova do passo 9
```

O `ssh-keygen -R` tira o servidor do arquivo `known_hosts` e guarda uma cópia
de como ele era em `known_hosts.old`, que o segundo comando apaga. Antes de
apagar uma prova, leve uma cópia dela.

Se a conexão cair no meio de um comando (a rede caiu, o computador foi
desligado), o container continua rodando: o que roda no servidor não depende da
conexão de ninguém.

#### Provas das 24 horas

São duas provas independentes: três leituras feitas por SSH, com o comando do
passo 9, e o registro de hora em hora que o próprio servidor gravou, pelo
`cron`, sem ninguém conectado.

| Leitura | Quando (Brasília) | `docker ps` | Ligado em (UTC) | Religamentos | Saúde |
| --- | --- | --- | --- | --- | --- |
| 1ª | 27/10, 19:33:18 | `Up 3 minutes (healthy)` | 2026-10-27T22:29:37Z | 0 | healthy |
| 2ª | 28/10, 19:34:27 | `Up 21 hours (healthy)` | 2026-10-28T01:17:52Z | 0 | healthy |
| 3ª | 29/10, 20:19:02 | `Up 46 hours (healthy)` | 2026-10-28T01:17:52Z | 0 | healthy |

Da 1ª para a 2ª leitura, o horário de ligação mudou de 19:29:37 para 22:17:52
de 27/10, no horário de Brasília (o `docker inspect` mostra em UTC, três horas
à frente). Ninguém mexeu no container: o servidor reiniciou, e o `uptime -s`
mostrou que ele voltou a ligar às 22:17:08; todos os containers que rodavam lá
mostravam o mesmo tempo no ar. O `--restart unless-stopped` funcionou como
devia: o Docker religou o `inventario-heluiz` sozinho, 44 segundos depois do
boot. A contagem das 24 horas recomeçou ali e se completou em 28/10, às
22:17:52. O religamento continuou em 0 porque esse contador só registra os
religamentos feitos depois de o programa terminar, e volta a 0 quando o Docker
liga o container junto com o servidor.

**O critério.** O `docker ps` arredonda o tempo: mostra `Up 24 hours` a partir
de 23 horas e meia. Por isso, a prova é a diferença entre o horário de ligação
e a hora da leitura. Na 3ª leitura, de 22:17:52 de 27/10 a 20:19:02 de 29/10,
são 46 horas e 1 minuto, com o mesmo horário de ligação da 2ª leitura e nenhum
religamento.

**O registro de hora em hora** tem 49 linhas, de 20:00 de 27/10 a 20:00 de
29/10, todas `(healthy)`, e cada uma bate com o horário de ligação das
leituras. A única queda é a do reinício do servidor, entre as linhas das 22:00
e das 23:00 de 27/10. A linha das 22:00 de 28/10 já mostra `Up 24 hours`, mas
eram 23 horas e 42 minutos; a primeira com mais de 24 horas é a das 23:00, e
daí em diante o tempo no ar cresce sem parar. Seis das 49 linhas:

```
2026-10-27T20:00:01-03:00 Up 30 minutes (healthy)
2026-10-27T22:00:01-03:00 Up 3 hours (healthy)
2026-10-27T23:00:01-03:00 Up 42 minutes (healthy)
2026-10-28T22:00:01-03:00 Up 24 hours (healthy)
2026-10-28T23:00:01-03:00 Up 25 hours (healthy)
2026-10-29T20:00:01-03:00 Up 46 hours (healthy)
```

#### Acesso administrativo

O docente pediu a cada aluno que provasse ter acesso de administrador criando,
na pasta do `root`, um arquivo com o próprio nome. A pasta `/root` é do
administrador e fica fechada para os outros usuários: sem `sudo`, o `touch`
daria `Permission denied`. Foi feito em 27/10, às 20:30, numa sessão aberta com
`ssh ufu`:

```
sudo -l                        # (ALL : ALL) ALL: com sudo, pode tudo
sudo touch /root/Heluiz.txt    # cria o arquivo, vazio, como root
sudo ls -l /root/Heluiz.txt
-rw-r--r-- 1 root root 0 Oct 27 20:30 /root/Heluiz.txt
```

O dono `root`, na saída do `ls -l`, é a prova: o arquivo só teria esse dono se
o comando tivesse rodado como root. Para mostrá-lo de novo, do computador com a
chave: `ssh -t ufu sudo ls -l /root/Heluiz.txt` (o `-t` dá ao `sudo` um
terminal para pedir a senha). Já o `sudo echo texto > /root/arquivo` não
funcionaria: quem faz o `>` é o shell do usuário comum, sem privilégio; o jeito
certo é `echo texto | sudo tee /root/arquivo`.

#### Implantar, passo a passo

Os passos que puseram o container no ar em 27/10. Servem para refazer a
implantação, com uma versão nova ou em outro servidor.

**Antes de começar.**

- Leve para o servidor a versão final, já na `main` do GitHub e com a
  verificação automática verde: mudar o código depois obriga a recriar o
  container, e a contagem das 24 horas recomeça.
- Ligue o container com folga antes do prazo de entrega, para dar tempo de
  recomeçar se algo zerar a contagem.
- Como só dá para entrar no servidor de dentro da rede da universidade, um
  jeito prático é ligar o container num dia de aula e juntar as provas no dia
  seguinte, mais de 24 horas depois. O registro de hora em hora do passo 9 é
  feito pelo próprio servidor, sem ninguém conectado.

**1. Primeiro acesso e troca da senha.** No PowerShell (no Linux e no macOS, no
terminal):

```
ssh usuario@endereco-do-servidor
```

Na primeira conexão, o SSH mostra a impressão digital (*fingerprint*) da chave
do servidor e pergunta se deve confiar nela; se o docente tiver divulgado a
impressão digital, compare as duas antes de responder `yes`. A senha não
aparece enquanto é digitada. Já no servidor, troque a senha inicial e saia:

```
passwd
exit
```

A senha nova vale para entrar e para o `sudo`. Num servidor em que os usuários
têm `sudo`, quem descobre a senha de alguém administra a máquina em nome dele.

**2. Chave SSH e atalho, no seu computador.** Com a chave, o SSH entra sem
pedir senha, e o `docker context` (no fim desta seção) passa a funcionar,
porque ele não aceita senha. No PowerShell, veja primeiro se você já tem uma
chave:

```
Test-Path $env:USERPROFILE\.ssh\id_ed25519.pub
```

Se a resposta for `True`, use a chave que já existe e pule o `ssh-keygen`:
gerar outra por cima apaga a atual, e o que dependia dela (o acesso ao GitHub
por SSH, por exemplo) para de funcionar. Se for `False`, crie a chave; o Enter
aceita o lugar padrão, e a frase-senha é opcional (com ela, o SSH a pede a cada
conexão):

```
ssh-keygen -t ed25519 -C "seu-email"
```

Copie a parte pública da chave para o servidor. É a última vez que a senha é
pedida:

```
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh usuario@endereco-do-servidor "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

Por fim, crie o atalho `ufu` no arquivo de configuração do SSH. Troque o
endereço e o usuário e cole o bloco inteiro no PowerShell:

```
@'
Host ufu
    HostName endereco-do-servidor
    User usuario
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ServerAliveInterval 60
'@ | Add-Content $env:USERPROFILE\.ssh\config
```

O arquivo se chama só `config`, sem extensão; pelo Bloco de Notas, é fácil ele
virar `config.txt`, que o SSH não lê. `IdentitiesOnly yes` faz o SSH oferecer
só essa chave (o servidor recusa a conexão depois de algumas chaves erradas), e
`ServerAliveInterval 60` mantém a conexão viva quando ela fica parada, como no
`docker attach`. Confira: `ssh ufu` tem de entrar sem pedir senha. Daqui em
diante, os comandos usam o atalho.

No Linux e no macOS, os passos são os mesmos, com o `ssh-copy-id` no lugar do
`type ... | ssh ...` (`ssh-copy-id usuario@endereco-do-servidor`) e o bloco
`Host ufu` no arquivo `~/.ssh/config`.

**3. Conhecer o servidor.** Entre com `ssh ufu` e confira o que ele tem:

```
whoami; hostname; uname -m        # usuário, nome e processador
sudo -l                           # "(ALL : ALL) ALL": você tem sudo
git --version
docker version                    # tem de mostrar Client e Server
systemctl is-enabled docker       # "enabled": o Docker liga com o servidor
groups                            # o grupo docker tem de aparecer
df -h ~ /var/lib/docker           # espaço livre; a imagem ocupa uns 280 MB
docker ps -a                      # containers que já existem no servidor
git ls-remote https://github.com/heluiz/Ciberseguranca_T2.git HEAD
```

- Se o `docker version` responder `permission denied`, falta o grupo `docker`.
  Com o `sudo`, inclua o seu usuário nele e entre de novo:
  `sudo usermod -aG docker $USER`, depois `exit` e `ssh ufu`. O grupo `docker`
  dá, na prática, poder de administrador; aqui, quem já tem `sudo` não ganha
  nada além do que já tinha.
- Se faltar o `docker` ou o `git`, combine com o docente antes de instalar: o
  servidor é de todos.
- O `git ls-remote` tem de mostrar um código e a palavra `HEAD` (o commit mais
  recente da `main`). Se ele terminar em erro, o servidor não sai para a
  internet: veja *Servidor sem acesso à internet*, no fim desta seção.

**4. Baixar o código e construir a imagem.**

```
git clone https://github.com/heluiz/Ciberseguranca_T2.git
cd Ciberseguranca_T2
git log -1 --oneline
docker build -t inventario-heluiz:1.0 .
docker volume create inventario-heluiz-dados
```

O `git log` mostra o commit que vai rodar; anote-o, porque ele identifica a
versão avaliada. Se a pasta já existir, de uma tentativa anterior, entre nela e
use `git pull` no lugar do `git clone`. Se o repositório estiver privado, o
`git clone` pede login: no lugar da senha, use um token de acesso pessoal do
GitHub, sem gravá-lo no servidor.

Se o Docker do servidor não tiver o componente `buildx`, como o do servidor do
docente, o `docker build` começa com o aviso
`DEPRECATED: The legacy builder is deprecated` e usa o construtor antigo, que
mostra as 12 etapas do Dockerfile (de `Step 1/12` a `Step 12/12`) e termina em
`Successfully tagged inventario-heluiz:1.0`. O aviso não muda a imagem.

**5. Pôr a base de exemplo, antes de ligar o container.** No servidor, use só a
base de exemplo, que é fictícia: lá, os outros usuários com `sudo` também
alcançam o container e os dados (veja [Segurança e LGPD](#segurança-e-lgpd)).

```
docker create --name semente-heluiz -v inventario-heluiz-dados:/app/dados inventario-heluiz:1.0
docker cp dados_exemplo/inventario_exemplo.json semente-heluiz:/app/dados/inventario.json
docker rm semente-heluiz
```

**6. Ligar o container.**

```
docker run -dit --name inventario-heluiz --restart unless-stopped \
  --read-only --security-opt no-new-privileges \
  -v inventario-heluiz-dados:/app/dados inventario-heluiz:1.0
```

As opções são as de [Em container Docker](#em-container-docker). O programa
não abre nenhuma porta de rede, por isso não há nada a liberar no firewall.

**7. Conferir e sair.**

```
docker ps --filter name=inventario-heluiz
```

O `STATUS` mostra `Up` e, depois de um minuto, `(healthy)`. Para ver o menu,
`docker attach inventario-heluiz` e Enter (do seu computador, direto:
`ssh -t ufu docker attach inventario-heluiz`); para sair dele sem parar o
programa, Ctrl+P e depois Ctrl+Q, no PowerShell ou no Windows Terminal (no
terminal do VS Code, o Ctrl+P não chega ao Docker). Por fim, `exit` fecha a
conexão, e o container continua rodando. O `docker attach` não é preciso para
provar as 24 horas: o `docker ps` e o `docker inspect` bastam.

**8. Durante as 24 horas, não mexer no container.** A contagem recomeça com
`docker restart`, `docker stop` e `docker start`; com um `sair` confirmado no
menu, ou a opção 0; com a recriação do container (`docker rm` e outro
`docker run`, que é o jeito de trocar a imagem); e com um reinício do servidor,
embora o Docker religue o container sozinho (foi o que aconteceu em 27/10: veja
[Provas das 24 horas](#provas-das-24-horas)). Construir a imagem de novo não
afeta o container que está rodando, que continua com a imagem com que foi
criado. Na apresentação, se for mostrar o container do servidor, entre com
`docker attach` e saia com Ctrl+P e Ctrl+Q, nunca pela opção 0.

**9. Guardar as provas.** Do seu computador, sem entrar no servidor, este
comando mostra o estado do container e o acrescenta a um arquivo:

```
ssh ufu "date; docker ps --filter name=inventario-heluiz; docker inspect -f 'Ligado em {{.State.StartedAt}} (UTC) | religado {{.RestartCount}} vez(es) | {{.State.Health.Status}}' inventario-heluiz" | Tee-Object -Append -FilePath $HOME\evidencias_24h.txt
```

No Linux e no macOS, troque o fim por `| tee -a ~/evidencias_24h.txt`. De um
computador sem a chave, troque `ufu` por `usuario@endereco-do-servidor`: a
senha é pedida, e o arquivo fica naquele computador. Rode o comando logo depois
de ligar o container e de novo depois de 24 horas. Na segunda vez, o
`docker ps` tem de mostrar `Up 24 hours` ou mais, o horário de ligação tem de
ser o mesmo da primeira e o religamento tem de continuar em 0. O horário do
`docker inspect` está em UTC, três horas à frente do de Brasília. Um print da
tela com o `docker ps` também serve de prova.

Para ter ainda um registro de hora em hora, feito pelo próprio servidor, sem
ninguém conectado, agende a conferência no `cron` do seu usuário, colando o
bloco inteiro no servidor:

```
(crontab -l 2>/dev/null; cat <<'EOF'
0 * * * * echo "$(date -Is) $(docker ps -a --filter name=inventario-heluiz --format '{{.Status}}' 2>&1)" >> $HOME/uptime_inventario.log
EOF
) | crontab -
crontab -l
```

A cada hora cheia, o arquivo `uptime_inventario.log` ganha uma linha como
`2026-11-20T15:00:01-03:00 Up 5 hours (healthy)`. Do seu computador,
`ssh ufu cat uptime_inventario.log` mostra o registro, e
`scp ufu:uptime_inventario.log .` traz uma cópia.

**10. Cuidados num servidor compartilhado.**

- **Não reinicie o servidor**, nem para testar o religamento: isso derruba o
  container de todos e zera a contagem deles. Para ver o
  `--restart unless-stopped` funcionando, reinicie o Docker Desktop no seu
  computador e confira com `docker ps` que o container voltou sozinho.
- **Não mexa no firewall (`ufw`), nos serviços (`systemctl`) nem na
  configuração do SSH ou do Docker**: um erro ali pode deixar a turma inteira,
  você inclusive, sem acesso.
- **Nunca rode `docker system prune`, `docker image prune` ou
  `docker volume prune`.** Eles agem sobre o Docker do servidor inteiro e
  apagam o que estiver parado ou sem uso, seja de quem for. Apague só o que é
  seu, pelo nome.
- **Não use o `compose.yaml` no servidor**: ele usa nomes fixos (`inventario` e
  `inventario-dados`), que podem ser os de um colega.
- **Não deixe senhas nem tokens em arquivos do servidor**, nem pelo
  `git config credential.helper store`: quem tem `sudo` lê qualquer arquivo.
- **Não instale nem atualize pacotes do sistema** sem combinar com o docente.

**11. Atualizar o programa**, só depois das 24 horas ou se a contagem já tiver
sido perdida. Uma etiqueta nova a cada versão evita imagens sem nome ocupando
espaço:

```
cd ~/Ciberseguranca_T2
git pull
docker build -t inventario-heluiz:1.1 .
docker rm -f inventario-heluiz
docker run -dit --name inventario-heluiz --restart unless-stopped \
  --read-only --security-opt no-new-privileges \
  -v inventario-heluiz-dados:/app/dados inventario-heluiz:1.1
docker rmi inventario-heluiz:1.0
```

Os dados continuam no volume, e a contagem das 24 horas recomeça.

**12. Depois da avaliação**, quando o docente não precisar mais do container,
guarde uma cópia dos dados e libere o espaço do servidor:

```
docker cp inventario-heluiz:/app/dados/inventario.json ~/inventario_servidor.json
docker rm -f inventario-heluiz
docker rmi inventario-heluiz:1.0
docker volume rm inventario-heluiz-dados
crontab -r
```

O `docker rmi` vai com a etiqueta em uso (`docker image ls inventario-heluiz`
mostra qual é), e o `crontab -r` apaga o agendamento do passo 9. Do seu
computador, `scp ufu:inventario_servidor.json ufu:uptime_inventario.log .`
traz as cópias; depois, no servidor, `rm -rf ~/Ciberseguranca_T2` apaga o
código.

Dois outros caminhos:

**Servidor sem acesso à internet.** Construa a imagem no seu computador e
leve-a pronta, num arquivo, junto com a base de exemplo:

```
docker build -t inventario-heluiz:1.0 .
docker save -o inventario-heluiz.tar inventario-heluiz:1.0
scp inventario-heluiz.tar dados_exemplo/inventario_exemplo.json ufu:
```

No servidor, `docker load -i inventario-heluiz.tar` carrega a imagem, e
`docker volume create inventario-heluiz-dados` cria o volume; depois, siga os
passos 5 e 6, com `inventario_exemplo.json` no lugar de
`dados_exemplo/inventario_exemplo.json`. O processador do servidor precisa ser
do mesmo tipo do seu: nos PCs comuns, o `uname -m` do passo 3 mostra `x86_64`.

**Comandar o servidor do seu computador.** O Docker do seu computador pode
mandar os comandos para o Docker do servidor, por SSH, com um *contexto* que
usa o atalho e a chave do passo 2:

```
docker context create ufu --docker "host=ssh://ufu"
docker --context ufu ps
docker --context ufu build -t inventario-heluiz:1.0 .
```

O `build` envia a pasta do projeto do seu computador, inclusive mudanças que
ainda não estão no GitHub. Os outros comandos desta seção (`volume`, `create`,
`cp`, `run`, `attach`) funcionam do mesmo jeito, com `--context ufu`; no
PowerShell, o `docker run` vai numa linha só, sem as barras invertidas. O
contexto exige a chave SSH e o seu usuário no grupo `docker` do servidor: o
Docker não aceita senha nem usa o `sudo`.

### Problemas comuns

| O que aparece | Por quê | O que fazer |
| --- | --- | --- |
| `python` responde que o Python não foi encontrado, ou abre a Microsoft Store | O Python não está instalado, ou não está no PATH | Instale-o (veja [O que instalar](#o-que-instalar)) e abra um terminal novo; no instalador tradicional, marque **Add python.exe to PATH** |
| `error: externally-managed-environment`, no `pip install` | No Linux, o Python do sistema não aceita bibliotecas instaladas pelo `pip` | Use o ambiente virtual, como em [Direto no computador](#direto-no-computador) |
| O PowerShell diz que a execução de scripts foi desabilitada, ao ativar o `.venv` | A política de execução do PowerShell bloqueia scripts | Rode uma vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ModuleNotFoundError: No module named 'numpy'` | O ambiente virtual não está ativado, ou as bibliotecas não foram instaladas nele | Ative o `.venv` (aparece `(.venv)` na linha de comando) e rode `pip install -r requirements.txt` |
| `failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine` | O Docker Desktop está fechado | Abra o Docker Desktop e espere aparecer "Engine running" |
| `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock` | No Linux, o seu usuário não tem permissão para usar o Docker | Use `sudo` antes do comando ou entre no grupo `docker` |
| `Conflict. The container name "/inventario" is already in use` | Já existe um container com esse nome | `docker start inventario` liga o que já existe; `docker rm -f inventario` o apaga, para criar de novo (os dados ficam no volume) |
| `Este programa é interativo e precisa de um terminal`, no `docker logs inventario` | O `docker run` foi feito sem `-it` | `docker rm -f inventario` e o `docker run` de novo, com `-dit` |
| Ctrl+P, Ctrl+Q não sai do `docker attach` | No terminal do VS Code, o Ctrl+P abre a busca de arquivos | Faça o `docker attach` no PowerShell ou no Windows Terminal |
| `A base não foi atualizada (raw.githubusercontent.com: ...; www.cisa.gov: ...)`, na opção 16 | Sem internet, ou a rede bloqueia esses sites (um proxy ou firewall) | Nada muda: o programa continua com a base que tinha. Tente de novo mais tarde ou em outra rede; num servidor sem internet, a base que vem com o programa continua valendo |
| `ssh: connect to host ... port 22: Connection timed out` | O computador está fora da rede interna da universidade, onde fica o servidor do docente | Conecte-se à rede do campus (ou a uma VPN que chegue até ela) e tente de novo |
| `Permission denied (publickey,password)`, no `ssh` | Usuário ou senha errados; com o atalho `ufu`, também pode ser a chave, que ainda não está no servidor | Confira o usuário (maiúsculas e minúsculas contam) e a senha; refaça a cópia da chave, no passo 2 de [No servidor do docente](#no-servidor-do-docente) |
| `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` | A chave do servidor não é mais a da primeira conexão: ou o servidor foi reinstalado, ou alguém se pôs no meio da conexão (ataque *man-in-the-middle*) | Não continue: pergunte ao docente se o servidor mudou. Só depois, `ssh-keygen -R endereco-do-servidor` apaga a chave antiga, e a próxima conexão pergunta de novo |
| `no space left on device`, no `docker build` do servidor | O disco do servidor acabou | Avise o docente. Não rode nenhum `prune`: ele apagaria também o que é dos colegas |
| `ssh: Could not resolve hostname ufu` | O atalho `ufu` só existe no computador em que foi criado, no passo 2 de [Implantar, passo a passo](#implantar-passo-a-passo) | Use `ssh usuario@endereco-do-servidor`, ou crie o atalho neste computador (veja [Acessar o servidor](#acessar-o-servidor)) |
| `the input device is not a TTY`, no `ssh ufu docker attach ...` | Sem o `-t`, o SSH não dá terminal ao comando, e o `docker attach` precisa de um | `ssh -t ufu docker attach inventario-heluiz` |
| O `sudo` diz que precisa de um terminal para ler a senha, no `ssh ufu sudo ...` | Pelo mesmo motivo: sem o `-t`, não há onde digitar a senha | `ssh -t ufu sudo ...` |
| `command not found` num comando colado no servidor, com `^[[200~` ou `[200~` grudado no texto | O terminal marca o começo e o fim do texto colado (*bracketed paste*), e a marca entrou no comando | Cole uma linha de cada vez; se continuar, rode uma vez no servidor `bind 'set enable-bracketed-paste off'` |
| `DEPRECATED: The legacy builder is deprecated`, no `docker build` do servidor | O Docker do servidor não tem o componente `buildx` e constrói com o construtor antigo | Nada: a imagem sai igual |
| `ter├ºa` no lugar de `terça`, na data da prova do passo 9 | O PowerShell lê o texto do servidor, que está em UTF-8, com outra codificação | Nada: a data está certa. Para ver os acentos, rode antes, na mesma janela, `[Console]::OutputEncoding = [Text.Encoding]::UTF8` |

## Como usar

O menu numerado dá acesso a todas as operações:

```
==============================================================
 Equipamentos
   1 - Cadastrar equipamento
   2 - Listar todos os equipamentos
   3 - Buscar equipamento (por ID, hostname, responsável...)
   4 - Atualizar equipamento
   5 - Excluir equipamento (e o que depende dele)
 Vulnerabilidades
   6 - Cadastrar vulnerabilidade em um equipamento
   7 - Ver vulnerabilidades de um equipamento
   8 - Atualizar vulnerabilidade
   9 - Excluir vulnerabilidade de um equipamento
  10 - Vulnerabilidades pendentes (todas, da mais grave)
 Dependências e risco
  11 - Cadastrar dependência entre equipamentos
  12 - Árvore de dependências de um equipamento (e remoção)
  13 - Risco de todos os equipamentos (próprio e efetivo)
  14 - Risco de um equipamento (passo a passo)
  15 - Matrizes do modelo (M, v, F, A) e verificação de I - A
 Base de CVEs exploradas
  16 - Buscar falhas exploradas, sugestões e atualização
 Correções
  17 - Plano de correção (o que mais reduz o risco)
   0 - Sair
==============================================================
  Em qualquer pergunta: voltar · sair · limpar · ajuda
```

| Opção | Faz |
| --- | --- |
| 1 | Cadastra um equipamento, com a ficha técnica se quiser (e, em seguida, suas vulnerabilidades iniciais) |
| 2 | Lista todos os equipamentos |
| 3 | Busca por ID, hostname, responsável, lotação, tipo, ficha técnica, CVE ou CWE |
| 4 | Atualiza um equipamento e a ficha técnica dele (Enter mantém o valor atual); inclui mudar o tipo |
| 5 | Exclui um equipamento, com os vínculos dele com as vulnerabilidades e as dependências que apontavam para ele |
| 6 | Registra uma vulnerabilidade num equipamento: uma nova (com CVE e CWE, se houver) ou uma já existente no catálogo |
| 7 | Mostra um equipamento e suas vulnerabilidades, da mais grave |
| 8 | Atualiza uma vulnerabilidade (descrição, CVE, CWE, categoria, nota ou vetor CVSS) ou o status dela naquele equipamento |
| 9 | Tira uma vulnerabilidade de um equipamento (cadastro errado ou duplicado) |
| 10 | Lista as vulnerabilidades pendentes de todos os equipamentos, da mais grave |
| 11 | Cadastra uma dependência entre dois equipamentos |
| 12 | Mostra a árvore de dependências de um equipamento nos dois sentidos (quem depende dele e do que ele depende, direta e indiretamente) e permite remover uma dependência direta |
| 13 | Mostra o risco próprio e o efetivo de **todos** os equipamentos |
| 14 | Mostra, passo a passo, como o risco de **um** equipamento foi calculado |
| 15 | Mostra M, v, M v, F, b e A (para poucos equipamentos), o posto de M e a dimensão do seu núcleo, e a verificação de I − A, com o determinante, o número de condição e o posto |
| 16 | Busca na base de CVEs exploradas (por palavras, por fabricante e produto, ou pela ficha técnica de um equipamento), explica a CVE escolhida em português, com o que a CISA manda fazer, registra a CVE num equipamento e atualiza a base pela internet |
| 17 | Lista as correções, da que mais reduz o risco total da rede para a que menos reduz, e mostra a conta e o que fazer em cada uma |

Depois de cada operação, o resultado fica na tela até o Enter. Além dos
números, estas palavras valem em qualquer pergunta do programa:

| Comando | Efeito |
| --- | --- |
| `voltar` | Abandona a tela atual e volta ao menu, sem gravar o que estava pela metade |
| `sair` | Fecha o programa |
| `limpar` | Limpa a tela; no menu, desenha o menu de novo |
| `ajuda` ou `?` | Mostra a lista de comandos |
| `lista` | Nas perguntas de ID de equipamento (e na escolha de uma vulnerabilidade do catálogo, na opção 6), mostra os registros e repete a pergunta |
| `-` | Na atualização de um campo opcional (CVE, CWE e ficha técnica, nas opções 4 e 8), apaga o campo; Enter mantém o valor atual |

Números decimais aceitam vírgula ou ponto (`7,5` ou `7.5`).

**A CVE e o CWE** de uma vulnerabilidade nova são opcionais. A primeira
pergunta é a CVE, como `CVE-2019-0708` (o prefixo pode faltar: `2019-0708`
também vale). Uma CVE aparece uma vez só no catálogo: se ela já está lá, o
programa mostra qual é a vulnerabilidade e oferece registrar a mesma neste
equipamento. Depois da categoria vem o CWE, o tipo de fraqueza, como
`CWE-416`. O formato dos dois é conferido. Se a CVE está na
[base de CVEs exploradas](#base-de-cves-exploradas), o programa mostra o que
a base sabe dela e oferece usar a descrição, o CWE e a nota de lá (Enter
aceita): aí, dos dados da vulnerabilidade, só a categoria é perguntada, e o
Enter escolhe "falta de atualização".

**A ficha técnica** do equipamento, no cadastro (opção 1) ou na atualização
(opção 4), também é opcional: fabricante, modelo, número de série, número de
patrimônio, sistema (operacional ou firmware) e versão. O patrimônio identifica
o bem no órgão e não pode se repetir entre equipamentos.

A opção 3 busca também pela ficha técnica (por parte do fabricante, do modelo,
da série, do patrimônio ou do sistema) e por CVE ou CWE. Na busca pela ficha,
cada equipamento achado aparece também com a ficha dele, numa linha, o que
deixa ver as versões lado a lado. A busca por CVE responde à pergunta de quando
sai uma falha nova: quais equipamentos a têm, e em que situação está cada um.

**A opção 16** consulta a base das CVEs que atacantes estão explorando, que
vem com o programa e funciona sem internet. Ela busca por palavras, como
`remote desktop` ou `fortinet vpn` (em inglês, como o catálogo), ou pelo
número da CVE; navega por fabricante e produto; sugere, pela ficha técnica de
um equipamento, as CVEs do fabricante e do produto dele; e atualiza a base
pela internet. Cada CVE aparece com uma explicação em português, montada a
partir dos dados (como se ataca, o impacto, o tipo de falha e a avaliação da
CISA), e com o que a CISA manda fazer, com os links do boletim. Qualquer CVE
mostrada pode ser registrada num equipamento, com os dados da base. Os
detalhes estão em [Base de CVEs exploradas](#base-de-cves-exploradas).

**A opção 17** monta o plano de correção: as falhas que ainda contam no risco
(abertas, em tratamento ou aceitas), em cada equipamento, da correção que mais
reduz o risco total da rede (a soma dos riscos efetivos) para a que menos
reduz, com a redução acumulada. A conta usa
o modelo de risco inteiro, inclusive quem herda risco de cada equipamento: na
base de exemplo, uma falha de nota 7,5 no roteador da sede, de que 73
equipamentos herdam risco, vale mais que o BlueKeep, de nota 9,8, num servidor
de que só uma estação depende. A coluna KEV marca as CVEs exploradas em
ataques. Digitando o número de uma correção, o programa mostra a conta dela e
o que fazer: numa CVE da base, a explicação em português e a ação da CISA,
com os links. A conta está em [Plano de correção](#plano-de-correção).

**A opção 12** mostra a árvore de dependências de um equipamento nos dois
sentidos: quem depende dele (quem herda parte do risco dele), direta e
indiretamente, e do que ele depende. Um equipamento pode depender de vários
outros, e dois podem depender um do outro; para a árvore não repetir ninguém,
cada equipamento aparece uma vez só, sob a ligação mais específica: a do
equipamento com menos dependentes, num sentido, ou com menos dependências, no
outro. Uma estação que depende do controlador de domínio e do roteador de
borda fica sob o controlador, de que menos equipamentos dependem. As outras
ligações de cada um vêm na linha "também", e os que têm as mesmas ligações e
nada abaixo viram um item só, com a lista deles. No fim vêm as dependências
diretas do equipamento, das quais se pode remover uma. Um trecho, da base de
exemplo:

```
  Do que PERICIA-PC01 depende (7 equipamentos, contando os indiretos)
  [28] PERICIA-PC01
  └─ [31] PERICIA-DB01  repassa 0,2
     ├─ [1] DRPC-SRV01  repassa 0,2
     │  │  também repassa 0,1 a [2] DRPC-SRV02 (ciclo)
     │  │  outras 3 dependências diretas aparecem em outros ramos
     │  └─ [3] DRPC-RT01  repassa 0,15
     │     │  também repassa 0,25 a [28] PERICIA-PC01, 0,2 a [30] PERICIA-SRV01
     │     │  e 0,15 a [2] DRPC-SRV02
  ...
```

"Herda 0,2" quer dizer que o equipamento herda 20% do risco efetivo do de
cima; "repassa 0,2", que o de cima herda 20% do risco efetivo dele. Os dois
descrevem a mesma entrada da matriz A, vista de um lado ou do outro. "(ciclo)"
marca dois equipamentos que dependem um do outro.

**A nota CVSS** de uma vulnerabilidade nova (opções 1 e 6) ou alterada
(opção 8) pode ser dada de três jeitos:

- **A nota**, como `7,5`.
- **O vetor**, colado da [calculadora do FIRST](https://www.first.org/cvss/calculator/4.0)
  ou de um boletim de segurança, nas versões 4.0, 3.1 ou 3.0, como
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. O programa calcula a nota
  (9,8) e guarda o vetor junto.
- **`calcular`**: o programa faz as perguntas do CVSS, uma a uma, e explica em
  português o que cada opção quer dizer. Responde-se com o número da opção ou
  com a letra do vetor; `anterior` volta uma pergunta e `cancelar` desiste do
  cálculo. No fim, o programa mostra o vetor e a nota e pergunta se pode usar
  (Enter aceita). A versão 4.0, a atual, é a padrão; a 3.1 também está
  disponível.

Um trecho da tela do `calcular`:

```
  [1/11] Vetor de ataque (AV)
  De onde o atacante consegue explorar a falha?

    1 - Rede (N)
        Pela rede, atravessando roteadores: da internet ou de outra sub-rede
        da rede interna. A parte vulnerável recebe dados pela rede, seja um
        serviço (RDP, um site) ou um programa cliente (o navegador), e a falha
        é chamada de "explorável remotamente". Só estar na rede interna, ou
        atrás de um firewall, não muda a resposta: continua sendo Rede.
    2 - Rede adjacente (A)
        Só da vizinhança, porque o próprio protocolo não passa de um roteador:
        o mesmo segmento de rede local (ARP, descoberta de vizinhos do IPv6),
        o mesmo meio sem fio (Bluetooth, NFC, Wi-Fi) ou uma zona
        administrativa restrita (MPLS, VPN segura). Ex.: inundação de ARP que
        derruba a rede local.
  ...
  Vetor: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
  Nota:  9,3 (Crítica)
```

As cores precisam de um terminal que interprete códigos ANSI. Com a variável de
ambiente `NO_COLOR` definida, o programa imprime texto puro.

## Requisitos do Trabalho 2

| # | Requisito | Peso | Onde está |
| --- | --- | --- | --- |
| 1 | Classe de equipamentos; cada ativo é um objeto individual criado a partir dela | 20% | `equipamentos.py`: a classe abstrata `Equipamento` e uma subclasse por tipo (`Servidor`, `Roteador`...); `criar_equipamento()` escolhe a subclasse. A classe "equipamentos" do enunciado é a `Equipamento`, no módulo `equipamentos.py`: o nome segue a convenção da PEP 8 para classes (CapWords) e está no singular, porque cada objeto é *um* equipamento. Cada equipamento tem uma `FichaTecnica` (`ficha_tecnica.py`), com fabricante, modelo, série, patrimônio, sistema e versão: composição. Os dados ficam protegidos por propriedades que conferem cada valor; veja [Orientação a objetos](#orientação-a-objetos). |
| 2 | Armazenamento em JSON formado por um array de objetos | 20% | `armazenamento.py` grava o que `Inventario.para_dict()` monta: um array JSON na raiz, um objeto por equipamento. Veja [o formato](#formato-do-arquivo-de-dados). |
| 3 | Aplicação em container, funcionando por no mínimo 24 h | 45% | `Dockerfile`, `compose.yaml`, `requirements.txt`, `.dockerignore`; ajustes de container em `main.py` (`preparar_container`). Veja [Em container Docker](#em-container-docker) e [No servidor do docente](#no-servidor-do-docente). Cumprido no servidor do docente: ligado em 27/10/2026, com 46 horas no ar na leitura de 29/10 (veja [Provas das 24 horas](#provas-das-24-horas)). |
| 4 | Risco efetivo pelo modelo linear, verificando a invertibilidade antes de resolver; risco próprio e efetivo consultáveis | 15% | `risco.py` (`ModeloRisco`); opções 13, 14 e 15 do menu, e a 17, que usa o mesmo modelo para ordenar as correções. A matriz A fica no mesmo JSON (campo `dependencias`), e o NumPy está declarado em `requirements.txt`, que o `Dockerfile` instala. Veja [o modelo de risco](#o-modelo-de-risco). |

Os requisitos do Trabalho 1 continuam valendo, como pede o enunciado. As
opções 1 a 10 do menu foram mantidas, com os mesmos números, as mesmas funções
e os mesmos comandos globais:

| # (T1) | Requisito | Onde está |
| --- | --- | --- |
| 1 | Menu e tratamento de erros | `main.py` (menu e ações) e `entrada.py` (teclado e comandos globais): entrada inválida é explicada e perguntada de novo, sem derrubar o programa |
| 2 | Tipos de ativo num `Enum`, com código inteiro | `classificacoes.py`: `TipoEquipamento`, de 1 a 7 |
| 3 | Cadastro gravado em arquivo | `armazenamento.py`: o arquivo JSON do requisito 2 acima |
| 4 | Busca por ID ou por hostname | Opção 3, itens 1 e 2 |
| 5 | Atualização | Opções 4 (equipamento) e 8 (vulnerabilidade) |
| 6 | Exclusão, com as vulnerabilidades do equipamento | Opção 5 (`Inventario.excluir_equipamento`): vão junto os vínculos com as vulnerabilidades e as dependências que apontavam para ele, e a vulnerabilidade que fica sem nenhum equipamento sai do catálogo |
| 7 | Vulnerabilidades com severidade e status | Opção 6; a severidade vem da nota CVSS, e o status é o `Enum` `SituacaoTratamento` |
| 8 | Visualização das vulnerabilidades | Opções 7 (de um equipamento) e 10 (as pendentes de todos) |
| 9 | Uso de dicionários | O `Inventario` guarda equipamentos e vulnerabilidades em `dict`, pelo id; cada equipamento guarda as suas vulnerabilidades (id → status) e as dependências (id → fração) em `dict` |
| 10 | Repositório Git com mais de duas branches e merge | Veja [Fluxo de trabalho no Git](#fluxo-de-trabalho-no-git) |

## Estrutura

| Arquivo | Responsabilidade |
| --- | --- |
| `main.py` | Classe `Aplicacao`: o menu e as ações. Liga as demais peças. É o ponto de partida |
| `equipamentos.py` | Classe abstrata `Equipamento`, com os dados protegidos por propriedades, as sete subclasses e o fator de exposição de cada tipo |
| `ficha_tecnica.py` | Classe `FichaTecnica`: fabricante, modelo, número de série, patrimônio, sistema e versão de um equipamento, todos opcionais |
| `vulnerabilidades.py` | Classe `Vulnerabilidade`: entrada do catálogo (descrição, CVE e CWE opcionais, origem, nota CVSS) |
| `inventario.py` | Classe `Inventario`: o conjunto dos equipamentos e das vulnerabilidades e as regras entre eles (hostname e patrimônio únicos, CVE única no catálogo, cascata, dependências, buscas) |
| `risco.py` | Classe `ModeloRisco`: monta M, v, A e b, verifica a invertibilidade (com o posto e o teorema de Rouché-Capelli), resolve o sistema e confere a solução; monta também o plano de correção, com o quanto cada correção reduz o risco total |
| `arvore.py` | A árvore de dependências de um equipamento (opção 12), nos dois sentidos: cada equipamento aparece uma vez, sob a ligação mais específica, com as outras ligações no item e os iguais agrupados |
| `armazenamento.py` | Classe `ArquivoInventario`: lê e grava o JSON, com gravação atômica |
| `migracao.py` | Converte uma base do Trabalho 1 para o formato novo |
| `base_cve.py` | Classe `BaseCVE`: a base das CVEs exploradas, com a busca por palavras, a navegação por fabricante e produto, as sugestões pela ficha técnica e a leitura e a gravação do arquivo da base |
| `atualizacao_cve.py` | A atualização da base de CVEs: baixa o catálogo KEV e os registros oficiais das CVEs, escolhe a nota e confere tudo. É o único módulo que usa a rede |
| `explicacao_cve.py` | A explicação de uma CVE em português, montada a partir dos dados: o vetor CVSS em frases, o nome do tipo de falha (CWE), a ação da CISA traduzida por uma tabela e a avaliação SSVC |
| `calculadora_cvss.py` | As perguntas do CVSS (versões 3.1 e 4.0) com as explicações em português; monta o vetor e confere um vetor digitado |
| `pergunta_cvss.py` | A pergunta da nota CVSS no cadastro e na atualização da vulnerabilidade: o número, o vetor colado ou o `calcular`, uma pergunta do CVSS de cada vez |
| `classificacoes.py` | Enums: tipo do equipamento; origem, severidade e status da vulnerabilidade |
| `validacao.py` | Conferência de dados vindos do arquivo |
| `entrada.py` | Leitura do teclado e comandos globais (`voltar`, `sair`...). Único módulo com `input()` |
| `telas.py` | Tabelas, fichas e relatórios impressos na tela |
| `formatacao.py`, `cores.py`, `banner.py`, `surpresa.py` | Padronização de texto, cores ANSI, logotipo e a animação-surpresa, herdados do Trabalho 1 |
| `testes.py` | Testes automáticos (`python testes.py`) |
| `Dockerfile`, `compose.yaml`, `.dockerignore`, `requirements.txt` | Container |
| `ruff.toml` | Regras de estilo conferidas pelo Ruff: PEP 8 e PEP 257 |
| `.github/workflows/verificacao.yml`, `.coveragerc` | Verificação automática no GitHub (estilo, testes e imagem Docker) e configuração da medida de cobertura |
| `base_cve/` | A base de CVEs que vem com o programa (`kev.json`) e os avisos de licença das fontes (`AVISOS.txt`) |
| `dados_exemplo/` | Base fictícia de 76 equipamentos, com ficha técnica, CVEs, CWEs e vetores CVSS, e dois cenários pequenos: um de 3 equipamentos, resolvido à mão, e um singular |

Só `entrada.py` chama `input()`, só `atualizacao_cve.py` usa a rede, e só
`armazenamento.py` lê e grava a base do inventário (a conversão manual de
`migracao.py`, executada como script, também grava o arquivo de destino; a base
de CVEs, um arquivo à parte, é lida e gravada por `base_cve.py`). As classes do
domínio (`Equipamento`, `FichaTecnica`, `Vulnerabilidade`, `Inventario`,
`ModeloRisco`) não sabem de teclado, tela nem arquivo, por isso cada módulo tem
um bloco de teste que roda sozinho (`python equipamentos.py`).

## Orientação a objetos

Cada equipamento do inventário é um objeto, criado a partir de uma das
subclasses de `Equipamento`. Os quatro pilares da orientação a objetos
aparecem assim:

| Pilar | Onde | Como |
| --- | --- | --- |
| Abstração | `Equipamento` (`equipamentos.py`) | Classe abstrata (`ABC`): diz o que todo equipamento tem e exige, com `@abstractmethod`, que cada tipo defina o seu `fator_exposicao`. Não se cria um `Equipamento` direto, só um objeto de uma subclasse; `criar_equipamento()` escolhe qual, pelo tipo |
| Herança | As 7 subclasses de `Equipamento` (`Servidor`, `Roteador`...) | Herdam da classe-mãe os dados, as validações e os métodos e acrescentam só o que muda: o tipo e o fator de exposição. Como não acrescentam atributos, herdam o `__init__` inteiro, sem precisar de `super()`. Os enums (de `Enum`) e as exceções (de `Exception`) também são subclasses |
| Polimorfismo | `fator_exposicao` | O modelo de risco (`risco.py`) chama `equipamento.fator_exposicao` sem saber o tipo do objeto, e cada subclasse responde com o seu valor: servidor 1,5, banco de dados 2,0, impressora 0,5... |
| Encapsulamento | `Equipamento` e `Inventario` | Os dados do equipamento ficam em atributos privados (`__hostname`...) e são lidos e alterados pelas propriedades (`@property`). Cada setter confere e padroniza o valor: `equipamento.hostname = "PC 01"` levanta `ValueError` em vez de gravar um nome inválido. O `id` não tem setter e não muda. As vulnerabilidades e as dependências saem da classe só para leitura (`MappingProxyType`) e mudam pelos métodos, que conferem as regras: a soma das frações menor que 1, que garante que `I − A` é invertível, não tem como ser contornada. O `Inventario` guarda os equipamentos e o catálogo em dicionários internos e só os expõe pelos métodos dele |

A composição completa o desenho: o equipamento *tem* uma `FichaTecnica`, em
vez de herdar dela. Os dois sublinhados, que o Python transforma em
`_Equipamento__hostname`, seguem a recomendação da PEP 8 para atributos de uma
classe feita para ter subclasses: as subclasses usam as propriedades, e não o
atributo guardado. Um dado inválido levanta `ValueError`, e quem chama decide o
que fazer: no menu, a pergunta é repetida com a explicação.

Os métodos especiais usados:

| Método | Onde | Para quê |
| --- | --- | --- |
| `__init__` | Todas as classes | Cria o objeto; no equipamento, os textos já passam pelos setters |
| `__str__` | `Equipamento`, `Vulnerabilidade`, `FichaTecnica`, `Inventario` | O texto para a tela, como `[65] INTEL-SRV01 - Servidor`: aparece nas confirmações de exclusão, no passo a passo do risco (opção 14), na busca pela ficha técnica e no aviso da base carregada |
| `__repr__` | `Equipamento`, `Vulnerabilidade`, `FichaTecnica` | O texto para depuração, como `Servidor(65, 'INTEL-SRV01')` |
| `__eq__` | `Equipamento`, `Vulnerabilidade`, `FichaTecnica` | Igualdade pelos dados, usada para conferir que o arquivo, lido e gravado de novo, devolve os mesmos objetos |
| `__len__`, `__iter__`, `__contains__`, `__getitem__` | `Inventario` (e `__len__` na `BaseCVE`) | O inventário funciona como uma coleção: `len(inventario)`, `for equipamento in inventario`, `65 in inventario` e `inventario[65]` |

Os construtores alternativos `de_dict()` (métodos de classe ou estáticos)
recriam os objetos a partir do arquivo. Operadores como `__add__` e `__lt__`
ficaram de fora de propósito: somar dois inventários, ou dizer que um
equipamento é "menor" que outro, não tem um significado único, e a ordem de
cada lista (pela nota, pelo risco) é escolhida onde a lista é mostrada.

## O modelo de risco

### Definição

Com *n* equipamentos e *m* vulnerabilidades:

| Símbolo | Tamanho | Significado |
| --- | --- | --- |
| **M** | n × m | Incidência: `M[i][j] = 1` se o equipamento *i* é afetado pela vulnerabilidade *j* e ela ainda não foi corrigida; senão 0 |
| **v** | m | Nota CVSS de cada vulnerabilidade |
| **F** | n × n | Matriz diagonal com o fator de exposição de cada equipamento, que depende do tipo |
| **b** | n | Risco próprio: `b = F (M v)`; com todos os fatores iguais a 1 (`F = I`), exatamente `b = M v` |
| **A** | n × n | Dependências: `A[i][j]` é a fração do risco do equipamento *j* que o equipamento *i* herda; `A[i][i] = 0` |
| **x** | n | Risco efetivo |

O risco efetivo é o próprio mais o herdado de quem se depende, e o que se herda
já é efetivo (inclui o que o outro herdou):

```
x = b + A x      <=>      (I − A) x = b
```

É um sistema linear em *x*. Duas dependências que se apontam entre si (um ciclo)
não impedem a solução, o que é o motivo de resolver o sistema em vez de somar
os riscos numa única passada.

Em termos de transformações lineares: M leva o vetor de severidades *v* (uma
nota por vulnerabilidade, em ℝᵐ) ao vetor *M v* (uma soma por equipamento, em
ℝⁿ), que é a imagem de *v*. F é diagonal: só muda a escala de cada componente,
e `F (M v) = (F M) v`. No código, F é guardada como o vetor da diagonal
(`fatores * (M @ v)`), o que dá o mesmo resultado sem montar a matriz cheia de
zeros. A opção 15 mostra M, v, M v, F e b.

M v pode ser lido de dois jeitos. Por linhas, cada componente é a soma das
notas das vulnerabilidades daquele equipamento. Por colunas, M v é a combinação
das colunas de M com as notas como pesos: cada vulnerabilidade soma a sua nota
em todos os equipamentos que afeta.

O núcleo de M é o conjunto dos vetores *u*, com um valor por vulnerabilidade,
tais que `M u = 0`: são as mudanças nas notas que não mudam a soma `M v` de
nenhum equipamento. Pelo teorema do núcleo e da imagem, o posto de M mais a
dimensão do núcleo dá o número de colunas (as vulnerabilidades). Na base de
exemplo, M é 76 × 88, com posto 56, então o núcleo tem dimensão 32
(56 + 32 = 88). Dezessete colunas são nulas: vulnerabilidades corrigidas em
todos os equipamentos em que aparecem, que continuam no catálogo mas não pesam
no risco. A opção 15 mostra o posto e a dimensão do núcleo.

O enunciado define `b = M v` e sugere que "cada tipo de equipamento pode definir
um fator de exposição que pondera o seu risco próprio". É o que `F` faz: `M v` é
a soma das notas das vulnerabilidades do equipamento, e o fator do tipo a
pondera. Para usar a definição literal, `b = M v`, basta trocar
`USAR_FATOR_DE_EXPOSICAO = True` por `False` no início de `risco.py`: todos os
fatores passam a valer 1. A
[validação à mão](#validação-à-mão-cenário-de-3-equipamentos) mostra a conta
dos dois jeitos.

Três siglas aparecem no programa. O **CVE** identifica uma falha específica
num produto: o CVE-2019-0708, por exemplo, é o BlueKeep, da Área de Trabalho
Remota do Windows. O **CWE** dá o tipo de fraqueza que causou a falha (no
BlueKeep, o CWE-416, uso de memória já liberada), e o **CVSS** dá a
severidade, de 0 a 10 (9,8, no BlueKeep). O modelo usa só a nota CVSS, que
vira o vetor *v*. A CVE e o CWE ficam na vulnerabilidade, os dois opcionais, e
identificam a falha, sem entrar na conta; a categoria (erro de configuração,
falta de atualização...) é a do requisito 7 do Trabalho 1.

Por que duas matrizes, e não só a nota de cada falha? O cenário da
[validação à mão](#validação-à-mão-cenário-de-3-equipamentos) mostra as duas
razões. A primeira é a **soma**: pela falha mais grave, o servidor (E2)
empataria com o banco de dados (E3), os dois com 6,0; `M v` soma as notas, e o
servidor, que tem uma falha a mais, fica com 10, contra 6 do banco. A segunda
é a **propagação**: quem invade um equipamento usa esse acesso para chegar aos
outros (é o movimento lateral, a tática TA0008 do MITRE ATT&CK), e `A` repassa
parte do risco pelas dependências. A estação (E1) tem uma falha só, de 4,0,
mas termina com risco efetivo 16, quatro vezes o próprio, porque herda metade
do risco do servidor, que por sua vez herda do banco.

### Decisões do modelo

- **Fator de exposição polimórfico.** Cada subclasse de `Equipamento` define
  `fator_exposicao`; o modelo chama `equipamento.fator_exposicao` sem saber de
  que tipo é o objeto. Os valores são didáticos e ajustáveis: estação 1,0
  (referência); servidor 1,5; roteador 1,2; impressora 0,5; sistema interno
  1,4; banco de dados 2,0; outro 1,0. Com todos os fatores iguais a 1, o risco
  próprio é exatamente `b = M v`.
- **Vulnerabilidade corrigida não entra em M.** Corrigir deve baixar o risco.
  As situações *Aberta*, *Em tratamento* e *Aceita como risco* contam: aceitar
  um risco não o elimina.
- **A severidade vem da nota CVSS**, pela escala do CVSS, que é a mesma na
  v3.1 e na v4.0 (0,1–3,9 baixa; 4,0–6,9 média; 7,0–8,9 alta; 9,0–10,0
  crítica), e não é gravada: assim a nota e a severidade nunca discordam. A
  escala oficial também tem o nível *Nenhuma* (0,0); o programa aceita notas de
  0,1 a 10,0, porque uma falha sem impacto não pesa no risco nem pede
  tratamento.
- **A nota tem uma casa decimal**, como as publicadas pela NVD. `8,25` é
  recusada em vez de arredondada: o `round()` do Python arredonda o empate para
  o número par (daria 8,2), enquanto o CVSS arredonda para cima (daria 8,3).
  Quem digitou escolhe a nota certa.
- **A nota pode vir do vetor CVSS**, e então os dois andam juntos: a nota é a
  que o vetor dá, como a severidade é a que a nota dá. A conta é a fórmula
  oficial, da biblioteca `cvss`, da equipe de segurança da Red Hat (a da versão
  4.0 usa tabelas grandes, que não faria sentido reescrever). A versão da
  biblioteca é fixa no `requirements.txt`, para o mesmo vetor dar sempre a mesma
  nota, e o cálculo não usa a rede.
- **Só as métricas base do CVSS.** Elas medem a falha em si. O contexto (o tipo
  do equipamento e as dependências) já entra pelo modelo de risco; as métricas
  de ambiente do CVSS o contariam duas vezes. Um vetor com outra métrica
  definida (de ameaça, temporal, de ambiente ou suplementar) é recusado, com a
  explicação; as que vêm com o valor X, "não definida", são só ignoradas.
- **As explicações seguem a especificação do FIRST**, inclusive nos pontos em
  que o leigo costuma errar: "Rede" vale mesmo para um serviço acessível só de
  dentro da rede interna; o impacto "Alto" inclui vazar uma parte só, se ela já
  causa dano direto e grave (como a senha do administrador); clicar num link
  enviado pelo atacante é interação "Ativa"; e uma configuração fora do padrão
  não conta como requisito de ataque, porque a pergunta já parte do sistema
  vulnerável.
- **A leitura do vetor é tolerante**: aceita as métricas em qualquer ordem e
  em minúsculas, e grava o vetor arrumado, na ordem oficial. A especificação
  4.0 chama de inválido o vetor fora de ordem; o programa prefere arrumar a
  recusar o que alguém copiou.
- **Resolve-se o sistema, não se inverte a matriz.** `numpy.linalg.solve` faz a
  fatoração LU: é mais preciso e mais rápido do que calcular a inversa de
  `I − A` e multiplicar por *b*. O `python risco.py` compara os dois num
  sistema mal condicionado e mostra o resíduo `‖(I − A) x − b‖` de cada um.
  Depois de resolver, a solução é conferida substituindo de volta, com
  `numpy.allclose`: `(I − A) x` tem de dar *b*, com uma tolerância que
  acompanha o tamanho de *x* (o arredondamento do produto cresce com ele).
- **O número de condição tem dois limites.** Ele mede quanto um erro
  relativo nos dados pode crescer na solução: um número de condição de 10ᵏ
  custa cerca de *k* dos 16 dígitos do `float64`. Acima de 1/ε (ε é o épsilon
  da máquina, cerca de 2,2 × 10⁻¹⁶, então o limite é cerca de 4,5 × 10¹⁵; na
  tela, o programa escreve "1/épsilon", por extenso), a matriz é singular ou
  quase singular para o computador, e o sistema é recusado. Acima de 10⁸, uma
  convenção que garante uns 8 dos 16 dígitos, a solução sai, com o aviso de
  que pode ter poucos dígitos confiáveis. Esse teste é mais confiável do que
  comparar o determinante com uma tolerância, porque o tamanho do
  determinante depende da escala da matriz. O posto completa a regra: o
  `matrix_rank` conta como zero os valores singulares menores que n × ε vezes
  o maior, porque o erro de arredondamento cresce com o tamanho da matriz.
  Com dezenas de equipamentos, o arredondamento pode deixar o número de
  condição de uma matriz singular logo abaixo de 1/ε (num teste com 6.000
  matrizes singulares montadas a partir da base de exemplo, isso aconteceu
  uma vez, e o `solve` falhou nessa matriz); com o posto menor que n, o
  programa recusa essas matrizes também.
- **Boas práticas de álgebra linear computacional**: `@` para produto de
  matrizes (o `*` só aparece na diagonal de F, de propósito, e o
  `python risco.py` confere que dá o mesmo que a matriz F inteira com `@`);
  `solve` em vez de `inv`; resultados de contas (o determinante, a solução, a
  soma das frações) comparados com tolerância, e não com `==`; o número de
  condição antes de confiar na solução; o posto para classificar o sistema; e
  matrizes em `float64`, sem inteiros de tamanho fixo, que "dão a volta". As
  notas CVSS são a exceção de propósito: digitadas, lidas do arquivo ou
  calculadas pelo vetor, elas sempre ficam com uma casa decimal, e por isso
  podem ser comparadas exatamente.

### Verificação de invertibilidade

Antes de resolver, `ModeloRisco.diagnosticar()` verifica se `I − A` é
invertível e `main.py` informa o usuário quando não é (nesse caso nada é
resolvido):

1. **Dominância diagonal.** Se cada linha de A soma menos que 1, `I − A` é
   estritamente diagonal dominante, o que garante que é invertível. Por isso o
   cadastro de dependências **impõe essa regra** (`Equipamento.
   definir_dependencia`): uma dependência que fizesse a soma da linha chegar a
   1 é recusada, com a mensagem de quanto ainda sobra. A soma é arredondada
   antes da comparação, porque em ponto flutuante `0,7 + 0,2 + 0,1` dá
   `0,9999999999999999`, que passaria no teste "menor que 1" por engano.
2. **Número de condição e posto.** Um arquivo editado à mão pode violar a
   regra. A dominância é um critério suficiente, mas não necessário: sem ela,
   `I − A` ainda pode ser invertível. Então, sem a garantia da dominância, o
   número de condição (`numpy.linalg.cond`) decide se `I − A` é tratada como
   invertível: acima de 1/ε (cerca de 4,5 × 10¹⁵), o sistema é recusado.
   O posto de `I − A` (`numpy.linalg.matrix_rank`) completa a regra: com
   posto menor que n, o sistema também é recusado, mesmo com o número de
   condição abaixo de 1/ε (veja [Decisões do modelo](#decisões-do-modelo)).
   Entre 10⁸ e 1/ε, com posto cheio, o sistema é resolvido, com o aviso de
   que a solução pode ter poucos dígitos confiáveis; esse aviso aparece
   também quando há dominância.
   O determinante também é calculado, mas só para informar: em ponto
   flutuante, um determinante teoricamente nulo raramente dá zero exato, e o
   tamanho de um determinante pequeno depende da escala da matriz. Quando o
   sistema é recusado, o posto diz o motivo: com posto menor que n, o
   programa classifica o sistema pelo teorema de Rouché-Capelli, comparando o
   posto de `I − A` com o da matriz ampliada `[I − A | b]`. Se o da ampliada é
   maior, o sistema é impossível (não tem solução); se os dois são iguais (e
   menores que n), é possível e indeterminado (tem infinitas soluções). Com
   posto cheio (n de n), o sistema é possível e determinado: a solução existe
   e é única, e a linha do posto, nas opções 13 a 15, diz isso.
3. **Conferência da solução.** Ser invertível não basta: com dependências em
   ciclo que repassam frações altas demais, `I − A` pode ser invertível e a
   solução dar a algum equipamento um risco efetivo *menor* que o próprio,
   até negativo. Herdar risco só pode somar, então, sem a garantia da
   dominância, a solução é conferida (`x ≥ b`). E, em todos os casos, depois
   do `solve`, a solução é substituída de volta: `(I − A) x` tem de dar *b*,
   com tolerância. Se uma conferência falhar, o programa avisa e não mostra
   nada, como no caso singular.

As opções 13, 14 e 15 mostram o resultado da verificação e, para conferência,
`det(I − A)`, o número de condição e o posto de `I − A`.

Exemplos de arquivo que a verificação recusa: três equipamentos em que cada
linha de A soma 1 (0,3 + 0,7), o que faz de (1, 1, 1) um vetor que `I − A` leva
a zero (singular: o determinante daria 0 no papel, mas o calculado sai da ordem
de 1e-16, e o programa avisa que é zero dentro da tolerância de 1e-12; o
posto de `I − A` é 2 e o de `[I − A | b]` é 3, então, pelo teorema de
Rouché-Capelli, o sistema não tem solução); e um
equipamento que herda 0,9 de dois outros, que herdam 0,9 dele (invertível, mas
a solução daria riscos efetivos negativos).

### Validação à mão (cenário de 3 equipamentos)

O arquivo `dados_exemplo/cenario_3_equipamentos.json` guarda um cenário pequeno
que se resolve no papel:

| Equipamento | Tipo (fator) | Vulnerabilidades | M v | b = fator · M v |
| --- | --- | --- | --- | --- |
| E1 | Estação (1,0) | V1 (4,0) | 4 | 4 |
| E2 | Servidor (1,5) | V1 (4,0), V2 (6,0) | 10 | 15 |
| E3 | Banco de dados (2,0) | V2 (6,0) | 6 | 12 |

Dependências: E1 herda 0,5 de E2; E2 herda 0,5 de E3; E3 herda 0,25 de E2.

```
x1 = 4  + 0,5  x2
x2 = 15 + 0,5  x3
x3 = 12 + 0,25 x2
```

Substituindo *x3* em *x2*: `x2 = 15 + 0,5 (12 + 0,25 x2) = 21 + 0,125 x2`, logo
`0,875 x2 = 21` e **x2 = 24**. Então **x3 = 12 + 6 = 18** e **x1 = 4 + 12 =
16**. O determinante de `I − A` é 0,875.

Sem o fator de exposição (`b = M v` = 4, 10 e 6, a definição literal do
enunciado), a mesma conta dá `x2 = 10 + 0,5 (6 + 0,25 x2) = 13 + 0,125 x2`,
logo `x2 = 13 / 0,875 = 104/7 ≈ 14,86`, `x3 = 6 + 0,25 x2 = 68/7 ≈ 9,71` e
`x1 = 4 + 0,5 x2 = 80/7 ≈ 11,43`. É o que o programa mostra com
`USAR_FATOR_DE_EXPOSICAO = False`.

Para conferir no programa:

```
INVENTARIO_DADOS=dados_exemplo/cenario_3_equipamentos.json python main.py
```

No PowerShell, a variável é definida numa linha à parte e vale até a janela ser
fechada. A última linha abaixo, depois de sair do programa, apaga a variável,
para o próximo `python main.py` voltar a abrir a sua base:

```
$env:INVENTARIO_DADOS = "dados_exemplo/cenario_3_equipamentos.json"
python main.py
Remove-Item Env:INVENTARIO_DADOS
```

No Docker, o cenário vem com a imagem e roda num container à parte, apagado
ao sair (`--rm`):

```
docker run --rm -it -e INVENTARIO_DADOS=/app/dados_exemplo/cenario_3_equipamentos.json inventario:1.0
```

Use as opções 15 (matrizes), 13 (risco de todos) e 14 (passo a passo). Direto
no computador, o que for alterado é gravado nesse arquivo: trabalhe numa cópia.
Na opção 15, as matrizes do cenário:

```
  M (linhas: equipamentos; colunas: vulnerabilidades):
        V1   V2
    E1  1    0
    E2  1    1
    E3  0    1

  v (notas CVSS): V1=4,0  V2=6,0

  M v (soma das notas de cada equipamento):  E1=4,0  E2=10,0  E3=6,0
  F (fator de exposição do tipo):            E1=1,0  E2=1,5  E3=2,0
  b = F (M v) (risco próprio):               E1=4,00  E2=15,00  E3=12,00

  A (linha i: fração herdada de cada equipamento j):
        E1     E2     E3
    E1  0      0,5    0
    E2  0      0      0,5
    E3  0      0,25   0
```

Na opção 13, a verificação de `I − A` e os riscos efetivos 24, 18 e 16, os da
conta acima, do maior para o menor:

```
  Verificação de I - A: I - A é estritamente diagonal dominante: a maior soma de linha de A é 0,5, menor que 1. Invertível.
  det(I - A) = 0,875 · número de condição de I - A = 2,56 (aviso acima de 1e+08; recusa acima de 1/épsilon = 4,5e+15)
  posto de I - A = 3 (de 3): posto cheio, então o sistema é possível e determinado

  ID  HOSTNAME     TIPO                 SOMA CVSS  FATOR  PRÓPRIO  EFETIVO
  ----------------------------------------------------------------------------------------------
   2  SERVIDOR-01  Servidor                  10,0    1,5    15,00    24,00  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   3  BANCO-01     Banco de dados             6,0    2,0    12,00    18,00  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   1  ESTACAO-01   Estação de trabalho        4,0    1,0     4,00    16,00  ▄▄▄▄▄▄▄▄▄▄▄▄▄
```

Na opção 14, a conta do servidor (E2), passo a passo:

```
  [2] SERVIDOR-01 - Servidor

  Risco próprio  b = fator x (M v)
    CVSS  6,0  [2] Vulnerabilidade V2 do cenário (Aberta)
    CVSS  4,0  [1] Vulnerabilidade V1 do cenário (Aberta)
    soma das notas que contam (M v) ... 10,0
    fator de exposição (Servidor) ... 1,5
    risco próprio b = 1,5 x 10,0 = 15,00

  Risco herdado  A x  (fração x risco efetivo de quem se depende)
       0,5 x    18,00  ([3] BANCO-01)  =      9,00
    total herdado ............... 9,00

  Risco efetivo  x = b + A x = 15,00 + 9,00 = 24,00
```

O `python risco.py` repete essa conta e mais outras: compara a solução do NumPy
com a série de Neumann (`x = b + A b + A² b + ...`, que converge quando cada
linha de A soma menos que 1) em 20 inventários aleatórios, e com uma solução em
frações exatas nos que têm até 6 equipamentos.

### Plano de correção

A opção 17 responde à pergunta que vem depois do risco: o que corrigir
primeiro? O risco total da rede é a soma dos riscos efetivos de todos os
equipamentos, `1ᵀ x`, com **1** o vetor só de uns. Corrigir a falha *j* no
equipamento *i* zera `M[i][j]`, e o risco próprio de *i* cai `F_i · v_j` (o
fator do tipo vezes a nota). Mas a queda não para aí: quem herda risco de *i*
também cai, e quem herda desses também. Para ter a queda do total de todas as
correções de uma vez, o programa resolve outro sistema, com a transposta de
`I − A`:

```
(I − A)ᵀ w = 1
```

Como `x = (I − A)⁻¹ b`, o total é `1ᵀ (I − A)⁻¹ b = wᵀ b`: o componente *w_i*
diz quanto o total sobe a cada ponto de risco próprio no equipamento *i*. O
mesmo sistema, escrito de outro jeito, é `w = 1 + Aᵀ w`, ou seja,
`w_i = 1 + Σ_k A[k][i] w_k`: o peso de um equipamento é 1 (o risco dele mesmo)
mais a fração que cada equipamento *k* herda dele, vezes o peso de *k*. Quem
não repassa risco a ninguém tem peso 1. A queda de uma correção é

```
redução = w_i · F_i · v_j
```

O modelo é linear, então as reduções se somam: corrigir tudo zera o risco
total, e a soma das reduções do plano dá exatamente o total. Por isso a coluna
ACUMULADO é exata, e não uma estimativa. A matriz `I − A` e a sua transposta
têm o mesmo determinante e os mesmos valores singulares, então a verificação
de invertibilidade da opção 13 vale também aqui. Com a regra do cadastro (cada
linha de A soma menos que 1), todo peso é pelo menos 1, e corrigir nunca piora
o risco. Num arquivo editado à mão, um ciclo que repassa mais risco do que
recebe pode dar um peso menor que 1: aí corrigir uma falha poderia aumentar o
risco total, e o plano é recusado, com a explicação.

No cenário da [validação à mão](#validação-à-mão-cenário-de-3-equipamentos),
quem herda de cada equipamento é a coluna dele em A:

```
w1 = 1                          (ninguém herda da estação)
w2 = 1 + 0,5 w1 + 0,25 w3       (a estação herda 0,5 do servidor; o banco, 0,25)
w3 = 1 + 0,5 w2                 (o servidor herda 0,5 do banco)
```

Substituindo *w3* em *w2*: `w2 = 1,75 + 0,125 w2`, logo **w2 = 2** e
**w3 = 2**. O peso 2 do banco se confere pela propagação: 1 ponto a mais no
risco próprio dele aumenta o risco efetivo dele em 1,14 (1/0,875: ele herda do
servidor, que herda dele), o do servidor em 0,57 e o da estação em 0,29; no
total, 2. As reduções:

| Correção | w | F | v | Redução |
| --- | --- | --- | --- | --- |
| V2 no banco (E3) | 2 | 2,0 | 6,0 | 24 |
| V2 no servidor (E2) | 2 | 1,5 | 6,0 | 18 |
| V1 no servidor (E2) | 2 | 1,5 | 4,0 | 12 |
| V1 na estação (E1) | 1 | 1,0 | 4,0 | 4 |
| **Soma** | | | | **58** = 16 + 24 + 18 |

Conferindo a primeira: sem a V2 no banco, `b = (4, 15, 0)`, e o sistema dá
`x ≈ (12,57; 17,14; 4,29)`, de total 34. Caiu 24, como a conta previu. Na
opção 17:

```
  Risco total da rede (soma dos riscos efetivos): 58,00

  #  REDUZ  ACUMULADO  VULNERABILIDADE                    CVSS  KEV  EQUIPAMENTO
  ----------------------------------------------------------------------------------
  1  24,00      41,4%  [2] Vulnerabilidade V2 do cenário   6,0       [3] BANCO-01
  2  18,00      72,4%  [2] Vulnerabilidade V2 do cenário   6,0       [2] SERVIDOR-01
  3  12,00      93,1%  [1] Vulnerabilidade V1 do cenário   4,0       [2] SERVIDOR-01
  4   4,00     100,0%  [1] Vulnerabilidade V1 do cenário   4,0       [1] ESTACAO-01

  Número da correção, para ver como fazer (Enter volta ao menu): 1

  Correção 1: [2] Vulnerabilidade V2 do cenário
  Equipamento ... [3] BANCO-01 - Banco de dados
  Status ........ Aberta
  Nota CVSS ..... 6,0 (Média)

  Reduz o risco total em 24,00 (41,4% de 58,00). O risco próprio de BANCO-01
  cai 2,0 x 6,0 = 12,00, e cada ponto de risco próprio nele pesa 2,00 no
  risco total, porque 2 equipamentos herdam risco dele, direta ou
  indiretamente.
```

Numa falha com CVE da base de CVEs exploradas, o detalhe traz também a
explicação da CVE em português e o que a CISA manda fazer, com os links (veja
[A explicação em português](#a-explicação-em-português)).

Na base de exemplo, o risco total é 1348,06, e o plano tem 78 correções; as
dez primeiras tiram 54,6% do risco. As duas primeiras são falhas de nota 7,5
no roteador da sede (`DRPC-RT01`), com 164,12 cada: 73 equipamentos herdam
risco dele, direta ou indiretamente, e o peso dele é 18,24. A senha padrão do
switch, de nota 9,8, vem em 4º (56,34), e o BlueKeep do `INTEL-SRV01`, também
de nota 9,8, só em 19º (17,64), porque apenas a estação `INTEL-PC01` herda dele
(peso 1,2). Pela nota CVSS, o BlueKeep viria antes das falhas do roteador; pelo
modelo, corrigir uma delas reduz o risco mais de nove vezes mais.

No código, `ModeloRisco.pesos_no_total()` resolve o sistema de *w* com
`numpy.linalg.solve`, confere a solução com `allclose` e recusa pesos menores
que 1; `plano_de_correcao()` monta uma correção para cada 1 de M e ordena da
maior redução para a menor; e `herdam_de()` acha, por uma busca em largura no
grafo das dependências, quem herda risco de um equipamento, direta ou
indiretamente, o número que o detalhe mostra. O `python risco.py` confere cada
redução resolvendo de novo o sistema com a falha corrigida, e que as reduções
somam o total, no cenário e em inventários aleatórios.

## Formato do arquivo de dados

Um **array JSON de objetos**: um objeto por equipamento, com as suas
vulnerabilidades e as suas dependências dentro dele.

```json
[
  {
    "id": 2,
    "tipo": 2,
    "hostname": "SERVIDOR-01",
    "custodiante": "Suporte de Informática",
    "lotacao": "Sala Técnica",
    "descricao": "Servidor",
    "ficha": {"fabricante": "Dell", "modelo": "PowerEdge R740",
              "patrimonio": "445566"},
    "vulnerabilidades": [
      {"id": 1, "descricao": "Vulnerabilidade V1", "origem": 6,
       "cvss": 4.0, "situacao": 1},
      {"id": 2, "descricao": "BlueKeep na Área de Trabalho Remota",
       "cve": "CVE-2019-0708", "cwe": "CWE-416", "origem": 2,
       "cvss": 9.8, "situacao": 1}
    ],
    "dependencias": [{"equipamento_id": 3, "fracao": 0.5}]
  }
]
```

(O arquivo real é gravado com indentação; aqui está compacto.)

- Os códigos de `tipo`, `origem` e `situacao` são os valores dos Enums de
  `classificacoes.py`; o rótulo com acento só existe na tela.
- Uma vulnerabilidade cuja nota veio do vetor CVSS tem também o campo
  `"vetor"`, por exemplo
  `"cvss": 9.8, "vetor": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`. O
  campo é opcional: sem vetor, ele simplesmente não aparece (um `null` vale
  como sem vetor), e os arquivos antigos continuam valendo. Na carga, a nota
  tem de ser a que o vetor dá; se não for, o arquivo é recusado.
- `"cve"` e `"cwe"` seguem a mesma regra: opcionais, só aparecem quando
  existem, e o formato é conferido na carga (`CVE-2019-0708`, `CWE-416`).
  Duas vulnerabilidades diferentes com a mesma CVE fazem o arquivo ser
  recusado: seriam a mesma falha, cadastrada duas vezes.
- `"ficha"` é a ficha técnica do equipamento, um objeto com até seis textos:
  `fabricante`, `modelo`, `numero_serie`, `patrimonio`, `sistema` e `versao`.
  Também é opcional, e só aparece se algum campo foi preenchido; um campo com
  outro nome faz o arquivo ser recusado, porque sumiria na próxima gravação.
  Dois equipamentos com o mesmo patrimônio também são recusados.
- `dependencias` é a linha do equipamento na matriz A: pares (equipamento do
  qual se herda, fração). A matriz A, portanto, é persistida no mesmo JSON dos
  demais dados, como o enunciado pede. A matriz M não é gravada: é montada,
  na hora, a partir de `vulnerabilidades` de cada equipamento.
- Uma mesma vulnerabilidade pode afetar vários equipamentos: ela aparece, com
  os mesmos dados (`id`, `descricao`, `cve`, `cwe`, `origem`, `cvss` e
  `vetor`), no objeto de cada um deles (é daí que vem a matriz M). Ao carregar,
  as cópias são reunidas num só objeto do catálogo; se duas cópias do mesmo
  `id` forem diferentes, o arquivo é recusado. A `situacao` do tratamento é de
  cada equipamento: o mesmo problema pode estar corrigido num e aberto em
  outro. Uma vulnerabilidade que nenhum equipamento tem não é gravada.
- Como o arquivo é só a lista, ele não guarda contador de ids: enquanto o
  programa roda, um id excluído nunca é entregue de novo, mas depois de
  reiniciar o próximo id é o maior existente mais 1.
- Na memória, os equipamentos ficam num dicionário (id → objeto), para a busca
  por id ser direta; a lista só existe no arquivo.
- O arquivo segue a RFC 8259, a norma do JSON: é gravado em UTF-8 sem BOM e
  nunca leva `NaN` nem `Infinity`, que não existem em JSON (a gravação usa
  `allow_nan=False`; o padrão do Python, `True`, gravaria esses valores). Na
  leitura, um BOM no início é aceito, como a RFC permite (o Bloco de Notas do
  Windows pode gravar um), e o mesmo nome duas vezes num objeto faz o arquivo
  ser recusado: sozinho, o módulo `json` do Python ficaria com o último valor,
  sem avisar.
- A gravação vai para um arquivo temporário que depois substitui o definitivo
  (`os.replace`): se ela for interrompida, a base anterior continua inteira.
- A carga confere o arquivo inteiro: tipos, ids repetidos, hostname ou
  patrimônio repetido, CVE repetida, CVE ou CWE fora do formato, dependência
  de equipamento que não existe, vulnerabilidade com dados diferentes em dois
  equipamentos, nota que não confere com o vetor, o mesmo nome duas vezes num
  objeto, NaN.
  Qualquer problema para o programa com uma mensagem que diz o que está
  errado e onde, em vez de carregar pela metade e apagar dados bons na
  próxima gravação. Descrição, responsável e lotação são mantidos como estão
  no arquivo (a padronização de maiúsculas é feita na digitação); o hostname
  é sempre guardado em maiúsculas.
- A regra "soma das frações de uma linha < 1" **não** é imposta na carga, de
  propósito: quem avalia um arquivo editado à mão é o modelo de risco, que
  avisa o usuário.

**Base do Trabalho 1.** Se o arquivo encontrado for do formato antigo, ele é
convertido ao abrir (`migracao.py`) e uma cópia da original fica ao lado dele
(`inventario.json.t1.bak`). Falhas iguais do T1 viram uma única vulnerabilidade
(com o mesmo `id` em cada equipamento que a tinha), e a gravidade vira uma nota
CVSS na mesma faixa (baixa 3,1; média 5,3; alta 7,5; crítica 9,8). Também dá
para converter à mão:
`python migracao.py antigo.json novo.json`.

## Base de CVEs exploradas

A opção 16 consulta uma base local das CVEs que **atacantes estão explorando
de verdade**: o catálogo KEV (*Known Exploited Vulnerabilities*) da CISA, a
agência de cibersegurança dos Estados Unidos. Uma falha entra no KEV quando
cumpre três condições: tem número de CVE, há prova confiável de que está sendo
explorada em ataques e existe uma correção clara, em geral a atualização do
fabricante.

Os órgãos civis do governo federal dos EUA têm prazo para corrigir cada uma, e
o catálogo traz esse prazo. A diretiva BOD 22-01, que criou o catálogo em
2021, foi revogada em 10/06/2026 pela BOD 26-04, que define o prazo pelo
risco, com quatro perguntas: o equipamento fica exposto na internet? A falha
está no KEV? O ataque pode ser automatizado? O atacante ganha controle total?
O prazo vai de 3 dias, no caso mais grave, a 60 dias, ou até a próxima
atualização do sistema, quando nenhuma resposta é sim. No catálogo, quase
todas as CVEs que entraram desde abril de 2026 têm prazo de 3 ou 14 dias; de
2022 até o começo de 2026, o prazo era em geral de três semanas. Aqui, o
prazo é só informação.

O KEV completa o que a nota CVSS não diz. A nota mede a gravidade de uma
falha, e não se alguém a explora (veja
[Limitações conhecidas](#limitações-conhecidas)); o KEV diz quais estão sendo
exploradas, que são as primeiras a corrigir.

### O que a base tem

| Dado | De onde vem |
| --- | --- |
| CVE, fabricante, produto, nome e descrição (em inglês) | Catálogo KEV |
| Data de entrada no catálogo e prazo da CISA | Catálogo KEV |
| Uso em campanhas de ransomware | Catálogo KEV |
| O que fazer: a ação exigida pela CISA e os links das notas (o boletim do fabricante, orientações da CISA e a página da NVD) | Catálogo KEV |
| CWE | Catálogo KEV; se ele não traz, o registro oficial da CVE |
| Nota e vetor CVSS, e quem deu a nota | Registro oficial da CVE, publicado pelo CVE Program |
| Avaliação SSVC da CISA: a falha é explorada? O ataque pode ser automatizado? O atacante ganha controle total? | Registro oficial da CVE, na parte que a CISA completa (o programa Vulnrichment) |

A base que vem com o programa é a do catálogo de 16/10/2026: 1.748 CVEs de
289 fabricantes, todas com nota CVSS (1.613 na versão 3.1, 77 na 4.0 e 58 na
3.0), com a ação exigida pela CISA, com links e com a avaliação SSVC; 1.639
têm CWE, e 361 foram usadas em campanhas de ransomware. O arquivo tem cerca de
1,6 MB e é lido em menos de um segundo, na primeira vez que a base é usada.

### A nota CVSS

O KEV não traz a nota. Ela vem do registro oficial de cada CVE, no formato CVE
JSON 5, que o CVE Program publica. Um registro pode ter mais de uma nota: a do
CNA (*CVE Numbering Authority*, quem publicou a CVE, em geral o próprio
fabricante) e as dos ADPs (*Authorized Data Publishers*, como a CISA, que
completam os registros de outros). O programa escolhe nesta ordem:

1. a versão 3.1; se não houver, a 4.0; se não houver, a 3.0. A 3.1 vem
   primeiro porque é a que quase todos os registros têm: assim as notas da base
   são comparáveis entre si, já que cada versão dá uma nota diferente para a
   mesma falha;
2. na mesma versão, a do CNA antes da dos ADPs.

Na base que vem com o programa, 756 notas são do CNA, 990 do ADP da CISA e 2
de outro ADP.

A nota não é copiada do registro: o programa a calcula do vetor, pela fórmula
oficial, com a mesma calculadora das outras vulnerabilidades, e guarda o vetor
junto. Antes, tira do vetor as métricas que não são base (as temporais, como
`E:F/RL:O/RC:C`, que 257 vetores traziam). Isso importa: em 22 registros, a
nota declarada não é a que o vetor dá. Em 18, o CNA publicou como nota base a
nota temporal, que desconta, por exemplo, a correção já disponível; em 1, a
nota declarada não é nem a base nem a temporal do vetor; nos outros 3, ela
difere da fórmula em 0,1. Calculada, toda nota da base é a nota base, a mesma
que o modelo de risco usa nas outras vulnerabilidades.

### Buscar, navegar e sugerir

**Buscar (item 1)**, por palavras ou pelo número da CVE:

- as palavras são em inglês, como no catálogo: `remote desktop`, e não
  `área de trabalho remota`;
- maiúsculas e acentos não importam;
- cada palavra vale pelo começo: `forti` acha FortiOS e FortiGate;
- todas as palavras têm de aparecer, em qualquer parte da CVE; palavras como
  `de`, `the` e `of` não contam;
- a ordem é pela relevância: uma palavra achada no fabricante ou no produto
  vale 3 pontos; no nome, 2; na descrição, no CWE ou no número, 1. No empate,
  vem antes a de maior nota e, depois, a que entrou no catálogo mais
  recentemente;
- um número de CVE, com ou sem o `CVE-` (`2019-0708`), acha só ela.

**Navegar (item 2)**: parte do nome do fabricante, ou Enter para todos. Os
fabricantes aparecem do que tem mais CVEs para o que tem menos; depois, os
produtos do escolhido (o passo é pulado se ele tem um só); por fim, as CVEs do
produto, da maior nota para a menor.

**Sugestões (item 3)**, para um equipamento com ficha técnica: as palavras do
fabricante, do modelo e do sistema da ficha são comparadas, inteiras, com as do
fabricante e do produto de cada CVE. Números, palavras de menos de 3 letras e
palavras genéricas, como `server`, `pro`, `enterprise`, `firmware` e `web`, não
contam. Uma palavra que combina com o produto vale mais que uma que combina com
o fabricante: `Windows` diz mais que `Microsoft`. O nome do fabricante repetido
no produto, como em `Cisco IP Phones`, conta uma vez só, como fabricante: senão,
qualquer produto com Cisco no nome passaria à frente do IOS, num roteador
Cisco. As CVEs que o equipamento já tem aparecem com `*`. **A combinação é
pelo nome, e não pela versão**: o KEV não diz que versões cada falha afeta.
Cada sugestão é uma pista, a conferir no boletim do fabricante.

Um trecho da tela, numa busca:

```
  Palavras (como fortinet vpn ou remote desktop) ou a CVE: remote desktop

  5 CVE(s) com "remote desktop", da mais relevante:

  #  CVE             NOTA  FABRICANTE  PRODUTO                   FALHA
  -------------------------------------------------------------------------------------------------
  1  CVE-2019-0708    9,8  Microsoft   Remote Desktop Services   Remote Code Execution
  2  CVE-2019-18988   7,0  TeamViewer  Desktop                   Bypass Remote Login
  ...
  Número da CVE (Enter sai): 1

  CVE-2019-0708 - Microsoft Remote Desktop Services Remote Code Execution Vulnerability
  Fabricante .... Microsoft
  Produto ....... Remote Desktop Services
  Nota CVSS ..... 9,8 (Crítica) (dada por CISA-ADP)
  Vetor CVSS .... CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  CWE ........... CWE-416 Uso de memória já liberada (use after free)
  No catálogo ... desde 03/11/2021; prazo da CISA (EUA): 03/05/2022
  Usada em campanhas de ransomware, segundo a CISA.
  ...
  Registrar esta CVE num equipamento? (s/N):
```

### A explicação em português

O nome, a descrição e a ação que a CISA exige vêm em inglês, como nas fontes
oficiais. Um tradutor automático poderia errar justamente no que importa:
"apply mitigations ... or discontinue use of the product" não é o mesmo que
"apply updates". Por isso a ficha de cada CVE traz uma explicação montada a
partir dos dados que têm significado fixo (`explicacao_cve.py`):

| Parte | De onde vem | Como vira português |
| --- | --- | --- |
| Como se ataca | Vetor CVSS: de onde (AV), com que conta (PR), com a ajuda de quem (UI), a complexidade (AC) e, na versão 4.0, os requisitos de ataque (AT) | Uma frase, com os termos que a calculadora do programa já usa, como "pela rede, sem conta no sistema e sem ação de outra pessoa" |
| Impacto | Vetor CVSS: confidencialidade, integridade e disponibilidade; o escopo, na 3.x, ou os outros sistemas, na 4.0 | Agrupado por nível, como "alto na disponibilidade; nenhum na confidencialidade e na integridade" |
| Tipo de falha | CWE | Um nome em português para os 30 tipos mais comuns do KEV e os da base de exemplo, que somam 78% das ocorrências; os outros ficam só com o número |
| Avaliação da CISA | SSVC | Os três pontos em português, com uma legenda para "automatizável" e "controle total" |
| O que fazer | A ação exigida pela CISA | Uma tabela com os 17 textos que se repetem no catálogo e cobrem 98,7% das CVEs; um texto fora dela aparece em inglês, com aviso |
| Links | As notas do catálogo | Separados em boletins (do fabricante ou da CISA) e na página da NVD, que reúne as referências e as versões afetadas |

O SSVC (*Stakeholder-Specific Vulnerability Categorization*) é o método com
que a CISA avalia a urgência de uma falha. Três pontos dele vêm no registro
oficial de cada CVE: a exploração (nenhuma, prova de conceito pública ou em
ataques), se o ataque é automatizável (sim ou não) e o impacto técnico
(controle parcial ou total do sistema). Os dois últimos são duas das quatro
perguntas com que a BOD 26-04 define o prazo de correção.

A tabela da ação compara os textos sem as diferenças que o catálogo tem entre
CVEs com a mesma ação, como o ponto final, as aspas ou "outlines" no lugar de
"outlined". A descrição oficial vem no fim, em inglês, como no catálogo. A
ficha de uma CVE, na opção 16:

```
  CVE-2023-20198 - Cisco IOS XE Web UI Privilege Escalation Vulnerability
  Fabricante .... Cisco
  Produto ....... IOS XE Web UI
  Nota CVSS ..... 10,0 (Crítica) (dada pelo CNA, quem publicou a CVE)
  Vetor CVSS .... CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  CWE ........... CWE-420 Canal alternativo desprotegido
  No catálogo ... desde 16/10/2023; prazo da CISA (EUA): 20/10/2023

  Em português (montado a partir dos dados)
    Como se ataca: pela rede, sem conta no sistema e sem ação de outra
    pessoa.
    Impacto: alto na confidencialidade, na integridade e na
    disponibilidade. O ataque atinge também o que está sob outra
    autoridade de segurança (escopo alterado).
    Avaliação da CISA (SSVC): explorada em ataques · ataque
    automatizável · controle total do sistema.
    Automatizável: o ataque pode ser feito em massa, sem intervenção
    humana, do reconhecimento à exploração. Controle total: o atacante
    passa a controlar o sistema ou a ver todas as informações dele.

  O que fazer, segundo a CISA
    Verificar se as instalações do Cisco IOS XE Web UI cumprem a BOD 23-02
    e aplicar as mitigações conforme as instruções do fabricante. Nos
    produtos afetados (Cisco IOS XE Web UI exposto à internet ou a redes
    não confiáveis), seguir as instruções do fabricante para verificar se
    o sistema pode ter sido comprometido e informar imediatamente à CISA o
    que for encontrado.
    Boletins e orientações indicados pela CISA:
      https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-dublin-17121/221128-software-fix-availability-for-cisco-ios.html
    Na NVD (referências e versões afetadas):
      https://nvd.nist.gov/vuln/detail/CVE-2023-20198

  Descrição oficial, em inglês:
    Cisco IOS XE Web UI contains a privilege escalation vulnerability in
    the web user interface that could allow a remote, unauthenticated
    attacker to create an account with privilege level 15 access. The
    attacker can then use that account to gain control of the affected
    device.
```

O mesmo aparece no detalhe de uma correção da opção 17, quando a falha tem uma
CVE da base.

### Registrar uma CVE da base

Escolhida uma CVE em qualquer dos três itens, o programa mostra tudo o que a
base sabe dela e oferece registrá-la num equipamento. A descrição (o nome da
falha), o CWE e a nota vêm da base; só a categoria e o status são perguntados
(e a nota, se a CVE não tiver), e o Enter na categoria escolhe "falta de
atualização", o caso mais comum de uma CVE do KEV. Se a CVE já está no
catálogo do inventário, em outro equipamento, é a mesma vulnerabilidade que
entra, como em todo o programa: uma CVE, uma vulnerabilidade (veja
[Decisões de projeto](#decisões-de-projeto)).

O mesmo vale no cadastro (opções 1 e 6): se a CVE digitada está na base, o
programa a mostra e oferece usar os dados dela.

### Atualizar (item 4)

A atualização precisa de internet e só acontece quando o usuário pede:

1. baixa o catálogo KEV mais novo (quase 2 MB), do espelho que a CISA mantém
   no GitHub ou, se ele falhar, do site da CISA. Dele vêm os dados de todas as
   CVEs, inclusive a ação exigida e os links, que assim ficam sempre em dia;
2. as CVEs que já estavam na base continuam com a nota e a avaliação SSVC que
   tinham; para as novas, baixa o registro oficial, do repositório do CVE
   Program no GitHub ou, se ele falhar, da API oficial. São no máximo 300 por
   atualização, das mais recentes para as mais antigas; as que sobrarem, ou
   que não tiverem nota, ficam para a próxima;
3. grava a base nova em `dados/base_cve.json`, junto com o inventário. O
   arquivo que vem com o programa, `base_cve/kev.json`, não muda.

Com um catálogo que não mudou, a atualização leva poucos segundos e termina
com "0 nova(s)".

O que vem da internet é tratado como suspeito, do mesmo jeito que um arquivo
editado à mão:

| Cuidado | Como |
| --- | --- |
| Só sites oficiais, por HTTPS | Os endereços são fixos, no código (`atualizacao_cve.py`). Um redirecionamento não pode sair do HTTPS, e o certificado do site é conferido, como o Python faz por padrão |
| Limites | No máximo 30 MB pelo catálogo e 10 MB por registro (o maior registro real tem 2,3 MB), e 30 segundos de espera por resposta |
| Tudo conferido | JSON pela RFC 8259 (sem `NaN` e sem o mesmo nome duas vezes num objeto) e cada campo no formato: CVE, datas, tamanho dos textos, caracteres de controle e a nota, que tem de conferir com o vetor. Um link das notas sem HTTPS ou com caractere que não cabe numa URL fica de fora (e ficam no máximo 10 por CVE), e uma avaliação SSVC com valor fora dos previstos é ignorada |
| Nada pela metade | A base nova vai para um arquivo temporário, que depois substitui o definitivo (`os.replace`). Se qualquer coisa falhar, o programa diz o motivo e continua com a base que tinha |
| Nada do inventário sai | Os pedidos levam só o endereço do catálogo, números de CVEs públicas e o nome do programa (no cabeçalho `User-Agent`): nada sobre os equipamentos, as fichas ou as vulnerabilidades cadastradas |

### Qual base vale

Na primeira vez que a base é usada (na opção 16 ou numa CVE digitada no
cadastro), o programa lê a mais nova das duas, pela data do catálogo: a
atualizada (`dados/base_cve.json`) ou a que vem com ele (`base_cve/kev.json`).
Assim, uma versão nova do programa, que traga uma base mais nova, não perde
para uma atualização antiga. Se o arquivo atualizado estiver estragado, o
programa avisa e usa o outro. A variável de ambiente `INVENTARIO_BASE_CVE`
muda o lugar da base atualizada (os testes a usam para gravar numa pasta
temporária).

**No container**, a base atualizada fica no volume dos dados
(`/app/dados/base_cve.json`), a única pasta em que o programa grava com
`--read-only`, e sobrevive a `docker rm` e à troca da imagem, como o
inventário. Num servidor sem internet, a atualização falha com um aviso, e a
base que vem na imagem continua valendo.

### O arquivo da base

Um objeto JSON com os dados do catálogo e a lista das CVEs, **uma por linha**,
em ordem de número: o arquivo fica legível, e a diferença entre duas versões,
no Git, mostra só as linhas das CVEs que mudaram.

```json
{
  "fonte": "Catálogo KEV da CISA (CC0 1.0) e registros do CVE Program (Termos de Uso do CVE): veja base_cve/AVISOS.txt",
  "catalogo": "2026.10.16",
  "publicado": "2026-10-16",
  "montado_em": "2026-10-20",
  "quantas": 1748,
  "cves": [
    ...
    {"cve": "CVE-2019-0708", "fabricante": "Microsoft", "produto": "Remote Desktop Services", "nome": "Microsoft Remote Desktop Services Remote Code Execution Vulnerability", "descricao": "Microsoft Remote Desktop Services, formerly known as Terminal Service, contains an unspecified vulnerability ...", "cwes": ["CWE-416"], "adicionada": "2021-11-03", "prazo": "2022-05-03", "ransomware": true, "cvss": 9.8, "vetor": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "fonte_nota": "CISA-ADP", "acao": "Apply updates per vendor instructions.", "links": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"], "ssvc": {"exploracao": "active", "automatizavel": "yes", "impacto": "total"}},
    ...
  ]
}
```

A leitura confere o arquivo inteiro, como a do inventário: os campos, o número
de cada CVE, as datas, os textos, os links, o SSVC, a nota contra o vetor e se
`quantas` bate com a lista. Um arquivo com qualquer problema é recusado
inteiro. Os campos `acao`, `links` e `ssvc` entraram depois: uma base gravada
por uma versão anterior do programa, sem eles, continua valendo.

Para pôr uma base mais nova no repositório, atualize pela opção 16 e copie
`dados/base_cve.json` por cima de `base_cve/kev.json`: o formato é o mesmo.

### Licenças

A CISA distribui o catálogo KEV sob a licença Creative Commons 0 1.0, de
domínio público. Os registros de CVE seguem os
[Termos de Uso do CVE](https://www.cve.org/Legal/TermsOfUse), que pedem que
toda cópia leve o aviso de copyright da MITRE e a licença: os dois estão em
`base_cve/AVISOS.txt`, ao lado da base. A avaliação SSVC vem da parte do
registro que a CISA completa, cujos dados ela também publica sob a CC0 1.0, no
repositório [Vulnrichment](https://github.com/cisagov/vulnrichment). O
programa não é endossado pela CISA nem pelo DHS.

## Decisões de projeto

- **Classe abstrata com uma subclasse por tipo.** `Equipamento` guarda o que é
  comum e declara `fator_exposicao` como método abstrato: não se cria um
  equipamento "genérico" (a classe não pode ser instanciada), e esquecer o
  fator numa subclasse nova é um erro na hora. A tabela `CLASSE_DO_TIPO` liga
  cada `TipoEquipamento` à sua classe; um tipo novo é uma subclasse e uma linha.
- **Composição para as relações.** O equipamento *tem* uma ficha técnica (um
  objeto `FichaTecnica`), um dicionário de vulnerabilidades (id → situação) e
  um de dependências (id → fração); não herda de nada além da base.
  Referenciar por id, e não por objeto, mantém o JSON simples e evita
  referências circulares entre equipamentos que dependem um do outro. A ficha
  é uma classe à parte porque os seis campos andam juntos (a mudança de tipo
  leva a ficha inteira) e são todos opcionais.
- **Quem sabe cuida.** A regra "soma das frações < 1" fica em `Equipamento`
  porque só depende dele, e o formato da CVE e do CWE, em `Vulnerabilidade`;
  "hostname único", "patrimônio único", "CVE única no catálogo" e "o destino
  da dependência existe" ficam em `Inventario`, que conhece os outros
  equipamentos e vulnerabilidades; a conta de risco fica em `ModeloRisco`, que
  não altera nenhum dado.
- **Uma CVE, uma vulnerabilidade.** Uma CVE identifica uma falha só, então
  aparece uma vez no catálogo, e os equipamentos afetados apontam para ela. Por
  isso, no cadastro de uma vulnerabilidade nova, a CVE é a primeira pergunta:
  se ela já existe, o programa oferece registrar a mesma, em vez de criar uma
  cópia que dividiria o histórico em dois.
- **Campos novos são opcionais.** CVE, CWE e ficha técnica só aparecem no
  arquivo quando existem. Uma base antiga abre como sempre, e a base de
  exemplo, regravada pelo programa, sai igual, letra por letra (um teste
  confere).
- **Base de CVEs pronta, atualização só quando pedida.** A base vem com o
  programa e funciona sem internet, como num servidor fechado; a atualização
  só acontece no item 4 da opção 16 e grava outro arquivo, na pasta dos
  dados: a base original nunca muda. A base tem só as CVEs exploradas: a lista
  inteira de CVEs tem centenas de milhares de registros, e as do KEV, menos de
  2 mil, são as que mais importa corrigir primeiro.
- **A internet num módulo só.** `base_cve.py` cuida da base (busca, navegação,
  arquivo) e não usa a rede; `atualizacao_cve.py` faz a atualização e é o único
  módulo que a usa. O código mais exposto fica num lugar só, fácil de revisar,
  e a atualização é testada sem internet: a função que abre os endereços é um
  parâmetro (`abrir`), e os testes passam uma que responde sozinha.
- **O plano ordena pela queda do risco total, e não pela nota.** A nota CVSS
  mede a falha sozinha; o modelo de risco sabe também onde ela está (o fator
  do tipo) e quem depende do equipamento (a matriz A). Por isso a pergunta "o
  que corrigir primeiro?" é respondida com o mesmo modelo que dá o risco, e as
  reduções somam o total, o que deixa a conta conferível.
- **A explicação em português vem dos dados, e não de um tradutor.** O vetor
  CVSS, o CWE, a ação da CISA e o SSVC têm significado fixo, e cada um vira
  português por uma regra ou uma tabela que se pode conferir. Um tradutor
  automático precisaria da internet e poderia errar justamente no que
  importa. O texto livre, a descrição, fica em inglês, como no original.
- **Árvore sem repetição.** As dependências formam um grafo, e não uma
  árvore: um equipamento depende de vários, e há ciclos. Repetir cada um sob
  cada equipamento de que ele depende faria a árvore do nobreak da base de
  exemplo ter 810 linhas, para 75 equipamentos. Por isso cada um aparece uma
  vez, sob a ligação mais específica, e as outras ligações vêm escritas no
  item: nenhuma some (um teste confere). A regra também garante que a
  montagem termina mesmo com ciclos: fora de um ciclo, quem fica em cima
  alcança mais equipamentos que quem fica embaixo, e a árvore não volta.
- **Tipo do equipamento é mudável**, mas um objeto não muda de classe:
  `Equipamento.converter_para()` cria outro objeto da subclasse certa, com o
  mesmo id e as mesmas relações, e o `Inventario` o coloca no lugar. Os textos
  passam como estão (`copiar_dados_de`), sem serem padronizados de novo.
- **Tudo ou nada.** Atualizações (`atualizar`) validam tudo antes de gravar
  qualquer campo; um dado inválido não deixa o objeto pela metade.
- **Exclusão em cascata ampliada.** Excluir um equipamento também remove as
  dependências de outros equipamentos que apontavam para ele (que apontariam
  para o nada) e tira do catálogo as vulnerabilidades que ficaram sem
  equipamento.
- **Erros esperados são exceções com mensagem.** `voltar` e `sair` são
  exceções que atravessam as funções até o menu; um erro inesperado numa ação
  é mostrado, a base é recarregada do disco e o menu continua.
- **Pronto para virar backend.** O enunciado espera que o programa seja o
  precursor do backend do trabalho final. As classes do domínio não leem
  teclado nem imprimem, e `para_dict()` e `de_dict()` já fazem a ida e a volta
  com o JSON: uma API web (Flask ou FastAPI) pode usar `Inventario`,
  `ModeloRisco` e `ArquivoInventario` como estão, trocando só o `main.py`.

## Segurança e LGPD

- **Menor privilégio.** No container, o programa roda com um usuário comum
  (`inventario`, UID 10001), sem ser root; o sistema de arquivos é só para
  leitura, menos o volume dos dados (`--read-only`); nenhum processo pode
  ganhar privilégio (`no-new-privileges`); e nenhuma porta de rede é aberta:
  não há serviço exposto a ataques pela rede.
- **Normas de segurança de containers.** O CIS Docker Benchmark e o guia NIST
  SP 800-190 recomendam o que o projeto faz: usuário que não é root, imagem
  oficial, `HEALTHCHECK`, nenhum segredo na imagem, sistema de arquivos só para
  leitura e `no-new-privileges`. Um desvio é consciente: o CIS recomenda a
  política de religamento `on-failure` com no máximo 5 tentativas, e o projeto
  usa `unless-stopped`, porque o requisito de 24 horas no ar pede que o
  container volte sozinho quando o servidor reinicia, o que o `on-failure` não
  faz. Limites de memória e de processos (`--memory`, `--pids-limit`), também
  recomendados, não foram fixados: dependem da máquina do docente.
- **Saída para a internet só quando pedida.** O programa só acessa a
  internet na atualização da base de CVEs, depois de o usuário confirmar, para
  baixar dados públicos por HTTPS, de endereços fixos, com limites de tamanho e
  de tempo. O que chega é conferido como um arquivo editado à mão, e nada do
  inventário é enviado. Veja [Atualizar](#atualizar-item-4). Os links dos
  boletins são só mostrados: o programa não abre nenhum, e quem usa decide se
  copia o endereço para o navegador.
- **Entrada tratada como suspeita.** O que vem do teclado e do arquivo é
  validado (tipos, faixas, hostname pelas RFC 952, 1123 e 1035, caracteres
  de controle recusados). Um arquivo adulterado é recusado, sem ser sobrescrito.
- **Dados pessoais (LGPD).** O único campo sobre pessoas é o responsável. O
  recomendado é registrar o cargo ou o setor ("Escrivão de Plantão", "Suporte
  de Informática"), e não o nome de alguém, como faz a base de exemplo: é o
  princípio da necessidade da LGPD (art. 6º, III), tratar o mínimo de dado
  pessoal que a finalidade exige. Mesmo assim, o campo merece cuidado: a lei
  protege também a pessoa *identificável* (art. 5º, I), e num setor pequeno o
  cargo junto com a lotação pode apontar alguém. As medidas desta seção são as
  que o princípio da segurança (art. 6º, VII) e o art. 46 pedem: proteger os
  dados de acesso não autorizado, de perda e de alteração.
- **Dependências conhecidas.** São só duas, ambas de projetos conhecidos: o
  NumPy e a `cvss` (com versão fixa, sem nenhuma dependência própria). Cada
  pacote a mais é código de terceiros rodando dentro do container. A
  atualização da base de CVEs usa só a biblioteca padrão do Python
  (`urllib`).
- **Nada sensível no repositório.** A pasta `dados/`, com a base real, fica
  fora do Git (`.gitignore`) e da imagem (`.dockerignore`); a base de exemplo
  é fictícia, inclusive as fichas técnicas e os números de série e de
  patrimônio; não há senhas nem chaves no código. A base real merece ainda
  mais cuidado com a ficha técnica e as CVEs: fabricante, modelo e versão de
  cada equipamento, junto com as falhas abertas, mostram a um atacante o que
  explorar e onde.
- **Sem login, por enquanto.** O programa não tem autenticação nem perfis de
  acesso: quem consegue dar `docker attach` (ou seja, quem acessa o servidor)
  pode alterar tudo. Autenticação e autorização ficam para o backend web do
  trabalho final; até lá, a proteção é o acesso ao servidor. No servidor do
  docente, compartilhado pela turma, os outros usuários com `sudo` também
  alcançam o container: por isso, lá roda só a base de exemplo, que é
  fictícia.
- **No servidor do docente.** O acesso é por chave SSH, e a senha inicial foi
  trocada; o container não publica nenhuma porta (a coluna `PORTS` do
  `docker ps` fica vazia); lá roda só a base de exemplo; nenhuma senha nem
  token fica gravado no servidor; e os nomes têm sufixo próprio, para não tocar
  no que é dos colegas. Num computador que não é seu, a entrada é por senha,
  sem deixar chave nem atalho (veja [Acessar o servidor](#acessar-o-servidor)).

## Normas seguidas

A tabela resume as normas e documentações oficiais que regem o projeto, como
cada uma foi aplicada e os desvios escolhidos de propósito.

| Norma | Assunto | Como o projeto segue |
| --- | --- | --- |
| [PEP 8](https://peps.python.org/pep-0008/) | Estilo do código Python | 79 colunas no código e 72 em comentários e docstrings; classes em CapWords; exceções que são erros terminam em `Error` (`BaseInvalidaError`, `SistemaSingularError`); imports no topo, em três grupos (os autotestes importam dentro do próprio bloco o que só eles usam). `VoltarAoMenu` e `SairDoPrograma` não levam o sufixo porque não são erros, são pedidos do usuário. O Ruff confere tudo (`ruff.toml`). |
| [PEP 257](https://peps.python.org/pep-0257/) | Docstrings | Todo módulo, classe e função pública tem docstring, com uma primeira linha curta. Desvio: a PEP pede a primeira linha como uma ordem ("Devolva..."); aqui ela está na 3ª pessoa ("Devolve..."), como é costume em português. |
| [PEP 20](https://peps.python.org/pep-0020/) | Princípios do Python | "Errors should never pass silently": base inválida, nota com duas casas decimais e nome repetido no JSON são recusados com mensagem, nunca corrigidos em silêncio. |
| [Versões do Python](https://devguide.python.org/versions/) | Versão em uso | Imagem e verificação automática no Python 3.14 (em manutenção completa); 3.11 ou superior fora do container. O 3.10 chegou ao fim da vida em 2026-10-01. |
| [NumPy](https://numpy.org/doc/stable/reference/generated/numpy.linalg.solve.html) | Álgebra linear | `linalg.solve` resolve o sistema sem inverter a matriz, e `allclose` confere a solução; `linalg.cond` decide a invertibilidade; `linalg.matrix_rank` dá o posto (Rouché-Capelli); `linalg.det` só informa; `LinAlgError` é tratado. |
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) e [módulo json](https://docs.python.org/3/library/json.html) | Formato do arquivo | Array JSON na raiz, UTF-8 sem BOM, sem `NaN` nem `Infinity`, nomes únicos em cada objeto. Veja [o formato](#formato-do-arquivo-de-dados). A base de CVEs e o que a atualização baixa são lidos com as mesmas regras. |
| [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) e [v4.0](https://www.first.org/cvss/v4.0/specification-document) | Nota e severidade | Escala qualitativa oficial (igual nas duas versões) e nota com uma casa decimal. A nota pode vir do vetor (versões 4.0, 3.1 e 3.0), pela fórmula oficial, com as perguntas das métricas base explicadas a partir da especificação. Desvios: 0,0 (*Nenhuma*) não é aceita, e o vetor é aceito fora de ordem e em minúsculas, mas gravado na forma oficial. As notas da base de CVEs também saem do vetor, só com as métricas base. |
| [Catálogo KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) e [BOD 22-01](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities-revoked) (revogada), da CISA | CVEs exploradas | Os critérios e os campos do catálogo, com a licença CC0 1.0, inclusive a ação exigida e os links das notas. O prazo de cada CVE é o do catálogo, que segue as diretivas e vale para os órgãos federais dos EUA (desde 10/06/2026, a BOD 26-04, que revogou a BOD 22-01): aqui, é só informação. Veja [Base de CVEs exploradas](#base-de-cves-exploradas). |
| [SSVC](https://github.com/cisagov/vulnrichment), no registro da CVE (programa Vulnrichment, da CISA) | Avaliação de cada CVE | Os três pontos que a CISA publica no registro (exploração, automatizável e impacto técnico), lidos com os valores previstos e mostrados em português. Veja [A explicação em português](#a-explicação-em-português). |
| [Registros de CVE](https://github.com/CVEProject/cvelistV5) (formato CVE JSON 5) e [Termos de Uso do CVE](https://www.cve.org/Legal/TermsOfUse) | Nota, vetor e CWE de cada CVE | A nota do contêiner do CNA ou de um ADP, calculada do vetor só com as métricas base; o aviso de copyright e a licença vão em `base_cve/AVISOS.txt`, como os termos pedem. |
| [RFC 952](https://www.rfc-editor.org/rfc/rfc952), [1123](https://www.rfc-editor.org/rfc/rfc1123) e [1035](https://www.rfc-editor.org/rfc/rfc1035) | Hostname | Veja [Limitações conhecidas](#limitações-conhecidas). |
| [LGPD](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm) (Lei 13.709/2018) | Dados pessoais | Art. 6º, III (necessidade); art. 6º, VII e art. 46 (segurança). Veja [Segurança e LGPD](#segurança-e-lgpd). |
| [Boas práticas do Docker](https://docs.docker.com/build/building/best-practices/) e [referência do Dockerfile](https://docs.docker.com/reference/dockerfile/) | Imagem | Imagem oficial `python:3.14-slim-trixie`, com a versão do Debian fixada no nome; dependências antes do código, para aproveitar o cache; usuário com UID fixo, sem ser root; `CMD` na forma exec e SIGTERM tratado; `VOLUME` para os dados; `.dockerignore`; `HEALTHCHECK` que termina com 0 ou 1. |
| [docker run](https://docs.docker.com/reference/cli/docker/container/run/) e [Compose](https://docs.docker.com/reference/compose-file/) | Execução | `-it` para o menu, `--restart unless-stopped`, volume com nome fixo, `compose.yaml` (o nome preferido) sem o campo `version`, que é obsoleto. |
| [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) e [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final) | Segurança de containers | Veja [Segurança e LGPD](#segurança-e-lgpd). Desvio: `unless-stopped` em vez de `on-failure`. |
| [GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use) | Verificação automática | Token só com leitura (`permissions: contents: read`) e versões atuais das actions oficiais (`checkout@v7`, `setup-python@v7`). |

## Limitações conhecidas

- **Um usuário por vez.** O arquivo é lido uma vez, ao abrir, e cada alteração
  é gravada na hora. Dois programas abertos sobre o mesmo arquivo se
  sobrescreveriam.
- **O programa é interativo.** O container precisa de `-it` (veja
  [Em container Docker](#em-container-docker)); não há API HTTP.
- **A escala do risco não é limitada.** O risco próprio e o efetivo são somas
  ponderadas de notas CVSS e podem passar de 10; servem para comparar
  equipamentos entre si, não são uma nota de 0 a 10.
- **Os fatores de exposição e as frações de dependência são estimativas** de
  quem usa o programa: o modelo não as deduz da rede real.
- **A nota CVSS mede a gravidade, e não a chance de ataque**: ela não diz se
  alguém vai explorar a falha. O modelo também é linear de propósito: as notas
  de um equipamento se somam, e o risco herdado é proporcional à fração da
  dependência. Serve para decidir o que corrigir primeiro, e não substitui uma
  análise de riscos completa, como a da
  [ISO/IEC 27005](https://www.iso.org/standard/80585.html).
- **Limites do número de condição.** O aviso acima de 10⁸ é uma convenção
  (garante uns 8 dos 16 dígitos do `float64`), e não um teorema. A
  recusa acima de 1/ε é o ponto em que o computador já não distingue a matriz
  de uma singular. O posto, com a tolerância do NumPy, é mais rigoroso: com
  muitos equipamentos, ele pode recusar uma matriz invertível em teoria, mas
  tão mal condicionada que a solução quase não teria dígito confiável.
- **A base tem só as CVEs exploradas**, as do catálogo KEV: uma pequena parte
  de todas as CVEs publicadas. Uma CVE que não está nele continua sendo
  cadastrada à mão, com a nota informada por quem cadastra (o programa confere
  o formato da CVE e do CWE).
- **As sugestões são pelo nome, e não pela versão.** O KEV não diz que versões
  cada falha afeta; isso exigiria as listas de produtos e versões da NVD (as
  CPEs). Cada sugestão precisa ser conferida no boletim do fabricante.
- **Nomes e descrições em inglês**, como no catálogo oficial, e por isso a
  busca também é em inglês. A explicação em português cobre só o que tem
  significado fixo: o vetor, o CWE (com nome em português em 78% das
  ocorrências; os outros tipos ficam só com o número), o SSVC e a ação da
  CISA, traduzida em 98,7% das CVEs da base; nas outras 23, a ação aparece em
  inglês, com aviso.
- **Boletim do fabricante só em parte das CVEs.** Os links vêm das notas do
  catálogo: 55,7% das CVEs da base têm um link além da página da NVD; nas
  outras, é a página da NVD que leva às referências e aos boletins.
- **A nota de uma CVE que já está na base não é baixada de novo**, nem a
  avaliação SSVC, para a atualização ser rápida: se o registro oficial mudar
  depois, a base continua com a anterior (a ação e os links, que vêm do
  catálogo, mudam junto com ele). A atualização também não muda o que já foi
  cadastrado: uma vulnerabilidade registrada a partir da base guarda os dados
  daquele momento.
- **Estar no KEV não muda a conta do risco.** O modelo usa só a nota CVSS: uma
  falha explorada pesa o mesmo que outra, de mesma nota, que ninguém explora.
  O plano de correção (opção 17) marca as do KEV, mas ordena só pela queda do
  risco; dar prioridade a elas fica a cargo de quem usa o programa.
- **O plano não conhece o custo das correções.** Ele ordena pela queda do
  risco, e não pelo esforço: trocar uma senha padrão leva minutos, e trocar um
  servidor sem suporte pode levar meses. A ordem é uma sugestão, e a decisão
  fica com quem usa o programa.
- **O hostname é um nome simples, sem domínio** (sem pontos): de 1 a 63
  caracteres, só letras sem acento, números e hífen, sem hífen nas pontas,
  pelas RFC 952, 1123 e 1035, como no Trabalho 1. Duas escolhas do projeto: um
  nome só de números é recusado (a RFC 1123 diz que um nome válido nunca é só
  de números no último trecho, para não ser confundido com um endereço IP); e
  um nome de uma letra é aceito (a RFC 952 o proibia, mas a 1035 permite).

## Testes

```
python testes.py
```

São 115 testes, só com a biblioteca padrão: o programa inteiro rodando por
dentro com o teclado simulado (do cadastro ao risco, incluindo o cenário de 3
equipamentos), o plano de correção (os pesos e as reduções do cenário, os da
conta à mão, e, na base de exemplo, cada redução do topo conferida corrigindo
a falha de verdade), a árvore de dependências (cada equipamento uma vez,
nenhuma ligação perdida, a ligação mais específica, o ciclo, uma cadeia de
1.100 equipamentos e as 80 colunas da tela), a nota CVSS pelo vetor e pelas
perguntas do `calcular`, a CVE e
o CWE (formato, CVE única no catálogo, busca, atualização), a ficha técnica
(cadastro, patrimônio único, busca, atualização), a base de CVEs exploradas
(busca, navegação, sugestões, cadastro com os dados da base, escolha da nota,
qual base vale, a ação, os links e o SSVC, a base sem eles, de uma versão
anterior, e a atualização com downloads simulados, sem internet: catálogo
novo, falta de internet, resposta grande demais, sem HTTPS, JSON fora da norma
e links e SSVC fora do formato), a explicação em português (o vetor em frases,
o nome do CWE, a ação traduzida ou, fora da tabela, em inglês, com aviso, e a
tela, que não parte um hostname no hífen nem um endereço longo), a recusa de
bases inválidas
(inclusive JSON fora da norma) e do sistema singular (com o posto e o teorema
de Rouché-Capelli), os dois limites do número de condição e o posto que
completa a regra, a conversão da base do Trabalho 1, o comportamento no
container (inclusive `sair` e Ctrl+D), a orientação a objetos (setters que
recusam dado inválido, id e relações que só mudam pelos métodos, `__str__` e o
inventário como coleção), o modelo de risco sobre os arquivos de exemplo, a
base de exemplo (fichas completas, números de série e de patrimônio
fictícios, CVEs iguais às da base de CVEs) e os passos do
[roteiro de demonstração](#roteiro-de-demonstração). O último teste roda o
autoteste de cada módulo, com a saída em cp1252, a codificação que o Windows
usa quando a saída vai para um arquivo ou para outro programa. Nada toca em
`dados/inventario.json` nem em `dados/base_cve.json`: os testes usam pastas
temporárias.

Os mesmos testes rodam no pytest, que entende os testes escritos com o
unittest:

```
pip install pytest
python -m pytest testes.py
```

Cobertura, com o coverage.py (configurado em `.coveragerc`): os testes passam
por 89% das linhas do programa, sem contar os autotestes dos módulos, que rodam
em outro processo.

```
pip install coverage
coverage run testes.py
coverage report
```

Estilo: o Ruff confere a PEP 8 (79 colunas no código e 72 em comentários e
docstrings, como a PEP pede) e a PEP 257 (docstrings), com a configuração em
`ruff.toml`, e não aponta nada:

```
pip install ruff
ruff check .
```

A regra D401, que pede a primeira linha da docstring como uma ordem, fica
desligada: as docstrings usam a 3ª pessoa ("Devolve...", "Verifica..."), e a
regra só reconhece verbos em inglês. O Ruff substitui o flake8 e o pydocstyle
usados antes: o pydocstyle foi descontinuado em 2023, e o próprio projeto
indica o Ruff no lugar.

O pylint, outra ferramenta de análise estática, dá nota 9,81 de 10
(`pip install pylint` e `pylint *.py`). Os avisos que restam foram mantidos de
propósito:

- os nomes `M` e `A`, iguais aos do enunciado;
- limites de tamanho, como funções com mais de cinco parâmetros
  (`registrar_vulnerabilidade` recebe um parâmetro por dado da
  vulnerabilidade), classes com mais de 20 métodos públicos ou com mais de
  sete atributos (a que monta a árvore de dependências guarda as ligações
  nos dois sentidos) e os dois arquivos com mais de 1.000 linhas
  (`main.py`, com uma ação por opção do menu, e `testes.py`, com um teste
  por comportamento);
- o `except Exception` do laço do menu, que impede um erro inesperado de
  derrubar o programa, e o `global` que desliga as cores;
- o import circular entre `armazenamento.py` e `migracao.py`, que é só
  aparente: `migracao.py` só importa o outro no bloco que roda quando ele é
  executado como script;
- trechos dos testes e dos autotestes, como as variáveis no nível do módulo
  e a tentativa proposital de criar um `Equipamento`, que prova que a classe
  abstrata não pode ser instanciada.

O GitHub roda o estilo e os testes sozinho a cada push: veja
[Fluxo de trabalho no Git](#fluxo-de-trabalho-no-git).

### Defeitos encontrados e corrigidos

Defeitos que os testes e as revisões pegaram durante o trabalho. Os que
estavam no código ganharam um teste, para não voltarem:

| Defeito | Correção | Como se confere |
| --- | --- | --- |
| A conferência da solução com `numpy.allclose` usava a tolerância padrão e recusava a solução certa de um sistema quase crítico (número de condição 4,5e8), com "Erro inesperado" na tela | A tolerância acompanha o tamanho de *x*, e uma solução que não confere vira aviso, sem erro | `test_sistema_quase_critico_mas_valido_e_resolvido` e `test_solucao_que_nao_confere_e_avisada_no_menu` |
| Com posto cheio e número de condição acima do limite, a mensagem dizia que `I − A` não era invertível, contra o teorema da matriz invertível | A mensagem separa o caso: posto cheio é invertível em teoria, só mal condicionado | `test_posto_cheio_mal_condicionado_nao_contradiz_o_teorema` |
| Uma matriz singular cujo número de condição o arredondamento deixava logo abaixo de 1/ε passava pela verificação, e o `solve` terminava a opção com "Erro inesperado" (achado num teste com 6.000 matrizes singulares) | O posto completa a regra do número de condição, e um pivô zero no `solve` vira recusa, com explicação | `test_posto_menor_que_n_recusa_abaixo_de_1_sobre_eps` e `test_pivo_zero_no_solve_e_recusado` |
| No Windows, o autoteste do `risco.py` terminava com `UnicodeEncodeError` quando a saída ia para outro programa, como no `python testes.py`: a mensagem do limite do número de condição tinha a letra grega ε, que não existe na codificação cp1252 | As mensagens escrevem "épsilon" por extenso, e os autotestes rodam com a saída em cp1252 em qualquer sistema, para o defeito aparecer também no Linux do GitHub | `test_autotestes_dos_modulos` |
| A base de CVEs atualizada valia sempre mais que a que vem com o programa: depois de uma versão nova do programa, com uma base mais nova, o programa continuaria com a atualização antiga | Vale a mais nova das duas, pela data do catálogo | `test_vale_a_base_mais_nova` |
| Uma CVE do catálogo (CVE-2024-20481, do Cisco ASA) ficava sem nota: o registro oficial dela tem 2,3 MB, porque lista centenas de versões afetadas, e passava do limite de 2 MB por download | O limite subiu para 10 MB | Conferido na montagem da base: todas as CVEs têm nota |
| Na opção 8, digitar a nota que a vulnerabilidade já tinha apagava o vetor CVSS dela | A mesma nota (e a mesma categoria) não conta como mudança, e o vetor continua | `test_atualizar_com_os_mesmos_valores_nao_muda_nada` |
| No fim do `calcular`, o Enter em "Usar esta nota?" descartava as 11 respostas | O Enter aceita a nota | `test_calcular_a_nota_respondendo_as_perguntas` |
| `limpar` numa pergunta do `calcular` apagava a pergunta da tela | A pergunta é desenhada de novo | `test_letra_anterior_e_cancelar_nas_perguntas` |
| Um vetor com métricas não definidas (valor `X`) era recusado | As métricas `X` são ignoradas | `test_vetor_com_metricas_nao_definidas_e_aceito` |
| `"vetor": null` no arquivo era recusado | `null` vale como sem vetor | `test_vetor_no_arquivo_tem_de_conferir_com_a_nota` |
| Nas sugestões da opção 16, `firmware` e `web` contavam como palavras da ficha: a câmera Hikvision, com sistema "Firmware", recebia antes as falhas de firmwares de outros fabricantes, e a da própria Hikvision vinha depois | `firmware` e `web` entraram nas palavras genéricas | `test_busca_sugestoes_e_nome_curto` |
| Nas sugestões da opção 16, o nome do fabricante repetido no produto contava duas vezes: no roteador Cisco, falhas de produtos como `Cisco IP Phones` passavam à frente da falha do IOS XE já registrada nele | O nome do fabricante conta uma vez só, como fabricante | `test_fabricante_repetido_no_produto_conta_uma_vez` |
| Na mudança de tipo (opção 4), os textos lidos do arquivo passavam de novo pela padronização: um responsável gravado como `NOC` virava `Noc` | Os textos são copiados como estão (`copiar_dados_de`) | `test_mudar_o_tipo_mantem_o_texto_do_arquivo` |
| Com o usuário do container trocado para o UID 10001, o programa não gravava no volume criado pela versão anterior | Um `chown` único no volume, descrito em [Em container Docker](#em-container-docker) | Conferido à mão, no container |
| A explicação da interação "Passiva" do CVSS dava como exemplo clicar num link, que a especificação do FIRST classifica como "Ativa" | Texto corrigido pela especificação | Revisão dos textos contra a especificação |
| No detalhe de uma correção (opção 17), a quebra de linha cortava o hostname no hífen: `DRPC-` no fim de uma linha e `RT01` no começo da outra; o `·` da avaliação SSVC podia começar uma linha; e, numa ação da CISA sem tradução, um endereço maior que a linha era partido no meio, o que estragava a cópia | A quebra não parte uma palavra, nem no hífen nem num endereço longo, e o `·` fica ligado à palavra de antes | `test_plano_na_base_de_exemplo_marca_as_cves_exploradas` e `test_acao_fora_da_tabela_aparece_em_ingles` |

## Fluxo de trabalho no Git

O requisito 10 do Trabalho 1 (repositório com mais de duas branches e merge)
continua valendo. Cada mudança é feita numa branch própria e integrada à `main`
por merge, com `git merge --no-ff`, que registra o ponto de junção no
histórico mesmo quando não há conflito:

| Prefixo | Uso | Exemplo neste repositório |
| --- | --- | --- |
| `feature/` | Funcionalidade nova | `feature/matrizes-e-diagnostico`, `feature/vetor-cvss`, `feature/posto-e-rouche-capelli`, `feature/cve-e-ficha-tecnica`, `feature/base-de-cves`, `feature/arvore-de-dependencias`, `feature/base-de-exemplo-completa`, `feature/encapsulamento-e-metodos-especiais`, `feature/plano-de-correcao-e-cve-em-portugues` |
| `fix/` | Correção de defeito | `fix/normas-oficiais`, `fix/barras-do-risco` |
| `docs/` | Documentação | `docs/revisao-requisitos`, `docs/normas-seguidas`, `docs/instrucoes-de-execucao`, `docs/revisao-final`, `docs/roteiro-do-servidor`, `docs/comando-unico`, `docs/servidor-implantado` |
| `ci/` | Integração contínua e container | `ci/verificacao-automatica`, `ci/python-3.14-e-container-seguro` |

`git log --graph --oneline --all` mostra as branches e os merges.

A partir da `feature/posto-e-rouche-capelli`, a integração é feita por Pull
Request no GitHub: a branch é enviada, o Pull Request descreve a mudança, a
verificação automática roda nele, e o merge só é feito com tudo verde.

A cada push e a cada pull request, o GitHub Actions
(`.github/workflows/verificacao.yml`) roda o Ruff e os testes no Python 3.14,
constrói a imagem Docker e roda, dentro dela e com o sistema de arquivos só para
leitura, o autoteste do modelo de risco. O token do workflow só pode ler o
repositório (`permissions: contents: read`), como recomenda a documentação de
segurança do GitHub. O resultado aparece na aba Actions do repositório.

## Dados de exemplo

`dados_exemplo/inventario_exemplo.json` é a base de exemplo do Trabalho 1,
convertida e completada com o que o Trabalho 2 acrescentou: 76 equipamentos,
todos com ficha técnica, 88 vulnerabilidades (103 registros
equipamento–vulnerabilidade), 9 delas com CVE, e 164 dependências. **Os dados
são fictícios**: os setores e os sistemas citados existem, mas hostnames,
fichas técnicas, vulnerabilidades, notas, situações e dependências foram
inventados e não descrevem a rede real da 1ª DRPC Uberlândia. Fabricantes e
modelos são de equipamentos comuns no mercado, escolhidos para o exemplo.

Para usar no computador, copie para o lugar da base:

```
mkdir dados
cp dados_exemplo/inventario_exemplo.json dados/inventario.json
```

(No PowerShell, os dois comandos funcionam como estão. No Prompt de Comando:
`copy dados_exemplo\inventario_exemplo.json dados\inventario.json`.) No
container, antes de ligá-lo pela primeira vez:

```
docker volume create inventario-dados
docker create --name semente -v inventario-dados:/app/dados inventario:1.0
docker cp dados_exemplo/inventario_exemplo.json semente:/app/dados/inventario.json
docker rm semente
```

Depois é só executar o `docker run` normal. Com o container já rodando, copie
com `docker cp dados_exemplo/inventario_exemplo.json
inventario:/app/dados/inventario.json` e reinicie com
`docker restart inventario`: a base é lida uma vez, ao abrir.

Isso substitui o inventário que estiver no volume. Para guardar o atual
antes: `docker cp inventario:/app/dados/inventario.json inventario_antigo.json`.

### O que a base de exemplo tem

| Parte | O que tem |
| --- | --- |
| Ficha técnica | Fabricante e modelo nos 76 equipamentos; sistema e versão nos que têm sistema. Servidores Dell PowerEdge com Windows Server, roteador e switch Cisco na sede, roteadores MikroTik e TP-Link nos outros setores, câmeras Hikvision, nobreaks APC, impressoras HP, Brother e Samsung e estações Dell, HP, Lenovo e Positivo. Nos bancos de dados, o sistema é o do servidor em que o banco roda |
| Série e patrimônio | Fictícios e fáceis de reconhecer: a série é `EX` (de exemplo), duas letras do fabricante e o ID (`EXDL0065`, um Dell); o patrimônio é 1011000 mais o ID (`1011065`). Os sistemas internos e os bancos de dados, que são programas, não têm nenhum dos dois. A `DP5-PC01` fica sem patrimônio de propósito: a falha registrada nela é "Estação sem etiqueta patrimonial" |
| Versões | Combinam com as falhas: Windows 7 nas duas estações com "Windows 7, sem suporte do fabricante"; Windows 11 24H2, cujo suporte nas edições Home e Pro acabou em 13/10/2026, nas três estações "sem atualizações" ainda não corrigidas; Windows Server 2008 R2 e 2012 R2, fora do suporte, nos servidores com o BlueKeep e o EternalBlue; RouterOS 6.40.5, anterior à correção da falha do Winbox (6.40.8), nos dois MikroTik em que ela está aberta ou em tratamento, e 6.49.10 no que já foi corrigido; IOS XE 17.9.4a, versão que corrige a CVE-2023-20198, no roteador da sede; firmware de 2017 na câmera em que a falha da Hikvision está aberta, e de 2022 na que foi corrigida |
| CVEs | Nove CVEs reais do catálogo KEV, as exploradas em ataques (tabela abaixo), registradas como a opção 16 registra: nome, CWE, nota e vetor da base que vem com o programa, e categoria "falta de atualização" |
| CWE | Em 45 vulnerabilidades: as nove CVEs e 36 falhas do Trabalho 1, como senha padrão de fábrica (CWE-1392), disco sem criptografia (CWE-311) e pasta com permissão para todos (CWE-732) |
| Vetor CVSS | Em 23 vulnerabilidades, sempre conferindo com a nota: as nove CVEs, com o vetor da base, e 14 falhas do Trabalho 1, com o vetor que dá a nota que elas já tinham |

| CVE | Falha | Equipamentos (status) |
| --- | --- | --- |
| CVE-2019-0708 | BlueKeep, na Área de Trabalho Remota do Windows | `INTEL-SRV01` (aberta), `DPLAN-PC02` (aberta), `DP4-PC01` (em tratamento) |
| CVE-2017-0144 | EternalBlue, no SMBv1 do Windows | `PERICIA-SRV01` (em tratamento) |
| CVE-2021-34527 | PrintNightmare, no spooler de impressão do Windows | `DRPC-SRV01` (corrigida) |
| CVE-2020-0618 | Reporting Services do SQL Server | `DRPC-DB01` (corrigida) |
| CVE-2023-20198 | Interface web do Cisco IOS XE | `DRPC-RT01` (corrigida) |
| CVE-2018-0171 | Smart Install do Cisco IOS | `DRPC-SW01` (aberta) |
| CVE-2018-14847 | Winbox do MikroTik RouterOS | `DP3-RT01` (aberta), `DP7-RT01` (em tratamento), `DP1-RT01` (corrigida) |
| CVE-2021-36260 | Servidor web das câmeras Hikvision | `DEIFRVA-CAM01` (aberta), `DPLAN-CAM01` (corrigida) |
| CVE-2023-38831 | WinRAR | `FRAUD-PC01` (aberta), `FRAUD-PC02` (corrigida) |

Os testes conferem a base: as fichas, o padrão dos números de série e de
patrimônio e as CVEs, iguais às da base de CVEs que vem com o programa.

### Roteiro de demonstração

A apresentação tem cinco minutos, com o programa rodando no seu computador, e
mostra o que funciona com base nos requisitos do Trabalho 2. Antes, ponha a
base de exemplo no volume, como acima, e ligue o container. Os números são os
da base de exemplo sem alterações; um teste confere os principais
(`test_roteiro_de_demonstracao_na_base_de_exemplo`).

**Em cinco minutos**, um passo para cada requisito, com o modelo de risco em
mais detalhe:

| # | O que fazer | O que mostrar | Requisito |
| --- | --- | --- | --- |
| 1 | `docker ps` | O container `inventario` no ar (`Up`) e saudável (`(healthy)`). No servidor do docente, do computador com a chave e na rede da universidade: `ssh ufu docker ps --filter name=inventario-heluiz`, em que o `Up` mostra há quanto tempo (as provas das 24 horas estão em [Provas das 24 horas](#provas-das-24-horas)) | 3 |
| 2 | `docker attach inventario` e Enter | A tela de abertura e "Base carregada: 76 equipamento(s), 88 vulnerabilidade(s).", lida do arquivo JSON | 2 |
| 3 | Opção 7, ID `65` | O `INTEL-SRV01`: um objeto da subclasse `Servidor`, com o fator de exposição dela (1,5), a ficha técnica (Dell PowerEdge R430, Windows Server 2008 R2) e as três vulnerabilidades, uma delas o BlueKeep, aberto | 1 |
| 4 | Opção 13 | A verificação de `I − A` antes da conta (diagonal dominante, determinante 0,98, número de condição 7,98, posto 76) e o risco próprio e o efetivo de todos: no topo, `PERICIA-SRV01` (40,61), `DRPC-SRV01` (40,01) e `INTEL-SRV01` (37,61) | 4 |
| 5 | Opção 14, ID `65` | A conta do `INTEL-SRV01`: b = 1,5 × 19,6 = 29,40; herdado de quem ele depende, 8,21; x = 29,40 + 8,21 = 37,61 | 4 |
| 6 | Opção 8, ID `65`, vulnerabilidade `80`, Enter cinco vezes e status `3`; depois a opção 14, ID `65` | Com o BlueKeep corrigido, o risco efetivo do `INTEL-SRV01` cai de 37,61 para 22,91 | 4 |
| 7 | Ctrl+P e Ctrl+Q; depois o comando do cenário singular (abaixo) e a opção 13 | A recusa: `I − A` não é invertível, o sistema não tem solução (teorema de Rouché-Capelli), e nada é calculado | 4 |
| 8 | `dados_exemplo/inventario_exemplo.json`, aberto no editor | O arquivo de dados: um array JSON de objetos, um por equipamento, com as dependências (a matriz A) no mesmo arquivo | 2 |

**Para as perguntas**, que vêm depois, sobre o código e o modelo de risco:

| O que fazer | O que mostrar |
| --- | --- |
| Opção 13, depois do passo 6 | O risco efetivo da `INTEL-PC01`, que herda 0,2 do `INTEL-SRV01`, também cai: de 28,85 para 25,91 (0,2 × 14,70 = 2,94) |
| Opção 15 | M é 76 × 88, com posto 56 e núcleo de dimensão 32; 17 colunas nulas. As matrizes não cabem na tela, mas a verificação de `I − A`, sim |
| O comando do cenário de 3 equipamentos (abaixo) e as opções 15, 13 e 14 | M, v, F, b e A na tela e os riscos efetivos 16, 24 e 18, a conta da [validação à mão](#validação-à-mão-cenário-de-3-equipamentos) |
| Opção 3, item 7, `CVE-2019-0708` | Onde está uma falha quando ela sai no noticiário: `DPLAN-PC02` e `INTEL-SRV01` (abertas) e `DP4-PC01` (em tratamento) |
| Opção 3, item 6, `MikroTik` | A busca pela ficha técnica: os três roteadores das delegacias, com a ficha de cada um. Os dois no RouterOS 6.40.5 são os que ainda têm a falha do Winbox |
| Opção 16, item 3, ID `3` | As CVEs exploradas que combinam com a ficha do roteador da sede (Cisco, IOS XE). A primeira, CVE-2023-20198, tem `*`: já está registrada nele. Para voltar ao menu, escolha uma e responda `n` |
| Opção 16, item 1, `remote desktop` | A busca na base de CVEs, sem internet: o BlueKeep em primeiro |
| Opção 12, ID `28`, e Enter | As duas árvores do `PERICIA-PC01`: quem depende dele e do que ele depende, com as frações. O Enter no fim não remove nada |
| Opção 17, depois do passo 6; depois `29` e Enter | O plano de correção: na frente, as duas falhas de nota 7,5 do roteador da sede (164,12 cada; juntas, 24,7% do risco total de 1330,42), porque 73 equipamentos herdam risco dele; o BlueKeep, de nota 9,8, só em 29º, na `DPLAN-PC02` (9,80), porque ninguém herda risco dela. O `29` mostra a conta, a CVE explicada em português e o que a CISA manda fazer |
| `python testes.py` e a aba Actions do GitHub | Os 115 testes e a verificação automática a cada push |
| `ssh ufu tail -n 5 uptime_inventario.log`, na rede da universidade | As últimas linhas do registro de hora em hora que o servidor grava sozinho: a hora, o tempo no ar e o `(healthy)` |
| `ssh -t ufu sudo ls -l /root/Heluiz.txt`, na rede da universidade | A prova de acesso administrativo pedida pelo docente: o arquivo pertence ao `root` |

Para as perguntas sobre o código, a tabela de
[Requisitos do Trabalho 2](#requisitos-do-trabalho-2) diz onde está cada
requisito, a de [Estrutura](#estrutura), o que cada arquivo faz, e a seção
[Orientação a objetos](#orientação-a-objetos), onde estão os pilares e os
métodos especiais.

Os dois cenários pequenos vêm com a imagem e rodam num container à parte,
apagado quando o programa termina (`--rm`), sem mexer no `inventario`, que
continua rodando:

```
docker run --rm -it -e INVENTARIO_DADOS=/app/dados_exemplo/cenario_singular.json inventario:1.0
docker run --rm -it -e INVENTARIO_DADOS=/app/dados_exemplo/cenario_3_equipamentos.json inventario:1.0
```

O passo 6 grava no volume. Para voltar à base de exemplo depois, copie-a de
novo, como acima.

`dados_exemplo/cenario_3_equipamentos.json` é o cenário resolvido à mão em
[Validação à mão](#validação-à-mão-cenário-de-3-equipamentos).

`dados_exemplo/cenario_singular.json` tem três equipamentos cujas frações de
dependência somam 1 em cada linha de A (0,3 + 0,7): o programa abre, mas o
modelo de risco avisa que `I − A` não é invertível e não calcula nada. Serve
para demonstrar a verificação, o número de condição, o determinante que dá
quase zero, mas não zero exato, e o teorema de Rouché-Capelli: o posto de
`I − A` é 2 e o de `[I − A | b]` é 3, então o sistema não tem solução.
