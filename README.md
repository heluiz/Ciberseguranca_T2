# Inventário de Equipamentos e Vulnerabilidades

Programa de linha de comando em Python para cadastro, consulta, atualização e
remoção (CRUD) de equipamentos de TI e das vulnerabilidades que os afetam, com
**cálculo do risco de cada equipamento por álgebra linear** e execução em
**container Docker**.

2ª atividade avaliativa (sprints 3, 4 e 5) do Bacharelado em Cibersegurança —
FEELT/UFU, 2026/2. Continuação do Trabalho 1: os requisitos dele continuam
valendo, e o programa foi reescrito em orientação a objetos.

## Sumário

- [Como executar](#como-executar)
- [Como usar](#como-usar)
- [Requisitos do Trabalho 2](#requisitos-do-trabalho-2)
- [Estrutura](#estrutura)
- [O modelo de risco](#o-modelo-de-risco)
- [Formato do arquivo de dados](#formato-do-arquivo-de-dados)
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
servidor do docente, onde ele precisa ficar 24 horas no ar (requisito 3).

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
é mais indicado. Os testes passaram do Python 3.11 ao 3.15, com NumPy 2.4 e
2.5; a imagem Docker usa o Python 3.14.

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
| `-v inventario-dados:/app/dados` | Os dados ficam num *volume*: sobrevivem a `docker rm` e à troca da imagem por uma versão nova. |

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
disponibilizado pelo docente. O caminho mais comum é entrar no servidor por
SSH e rodar lá os mesmos comandos do Docker. O servidor precisa ter o Docker,
o Git e acesso à internet, para construir a imagem, e o seu usuário precisa
ter permissão para usar o Docker. O endereço e o usuário vêm do docente.

**1. Entrar no servidor e conferir o Docker.**

```
ssh usuario@endereco-do-servidor
docker version
```

Se o `docker version` responder `permission denied`, o seu usuário não está
no grupo `docker`: use `sudo` antes de cada comando `docker` ou peça ao
docente para incluí-lo.

**2. Baixar o código e construir a imagem.**

```
git clone https://github.com/heluiz/Ciberseguranca_T2.git
cd Ciberseguranca_T2
docker build -t inventario:1.0 .
docker volume create inventario-dados
```

Se o repositório estiver privado, o `git clone` pede login: no lugar da senha,
use um token de acesso pessoal do GitHub.

**3. Pôr a base de exemplo, se quiser, antes de ligar o container.**

```
docker create --name semente -v inventario-dados:/app/dados inventario:1.0
docker cp dados_exemplo/inventario_exemplo.json semente:/app/dados/inventario.json
docker rm semente
```

**4. Ligar o container.**

```
docker run -dit --name inventario --restart unless-stopped \
  --read-only --security-opt no-new-privileges \
  -v inventario-dados:/app/dados inventario:1.0
```

**5. Conferir e sair.** O `docker ps` mostra `Up` e, depois de um minuto,
`(healthy)`. Para usar o menu, `docker attach inventario` e Enter; para sair
dele sem parar o programa, Ctrl+P e depois Ctrl+Q. Depois, `exit` fecha a
conexão SSH, e o container continua rodando no servidor.

Durante as 24 horas:

- **Não mexa no container.** `docker restart`, `docker stop` e `docker start`,
  a troca da imagem e um `sair` confirmado no menu fazem a contagem recomeçar.
  Por isso a base de exemplo entra antes do `docker run` (passo 3), e a versão
  do programa fica congelada: atualizá-la exige recriar o container. Um
  reinício do próprio servidor também zera a contagem, embora o Docker religue
  o container sozinho.
- **Servidor compartilhado.** Se outros alunos usam o mesmo servidor, troque
  os nomes da imagem, do container e do volume por nomes seus em todos os
  comandos, por exemplo `inventario-heluiz:1.0`, `inventario-heluiz` e
  `inventario-heluiz-dados`. Com os mesmos nomes, o `docker run` de um aluno
  dá conflito com o do outro, o `docker build` de um troca a imagem do outro,
  e dois containers com o mesmo volume misturam os dados. O `compose.yaml` usa
  nomes fixos; nesse caso, use o `docker run`.
- **Para comprovar o tempo no ar**, o `docker ps` mostra `Up 24 hours` (ou
  mais), `docker inspect -f '{{.State.StartedAt}}' inventario` mostra quando o
  programa ligou e `docker inspect -f '{{.RestartCount}}' inventario` mostra
  quantas vezes o Docker precisou religá-lo.

Dois outros caminhos:

**Servidor sem acesso à internet.** Construa a imagem no seu computador e
leve-a pronta, num arquivo, junto com a base de exemplo:

```
docker save -o inventario.tar inventario:1.0
scp inventario.tar dados_exemplo/inventario_exemplo.json usuario@endereco-do-servidor:
```

No servidor, `docker load -i inventario.tar` carrega a imagem; depois, siga os
passos 3 e 4, com `inventario_exemplo.json` no lugar de
`dados_exemplo/inventario_exemplo.json`. O processador do servidor precisa ser
do mesmo tipo do seu (em geral, x86-64).

**Comandar o servidor do seu computador.** O Docker do seu computador pode
mandar os comandos para o Docker do servidor, por SSH, com um *contexto*:

```
docker context create servidor --docker "host=ssh://usuario@endereco-do-servidor"
docker --context servidor build -t inventario:1.0 .
docker --context servidor ps
```

O `build` envia a pasta do projeto para o servidor, e os outros comandos desta
seção (`volume`, `create`, `cp`, `run`, `attach`) funcionam do mesmo jeito,
com `--context servidor`. Esse caminho exige login por chave SSH, porque o
Docker não aceita senha: `ssh-keygen` cria a chave, e o conteúdo do arquivo
`.pub` que ele gera vai para o `~/.ssh/authorized_keys` do seu usuário no
servidor.

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

## Como usar

O menu numerado dá acesso a todas as operações. Depois de cada uma, o
resultado fica na tela até o Enter. Além dos números, estas palavras valem em
qualquer pergunta do programa:

| Comando | Efeito |
| --- | --- |
| `voltar` | Abandona a tela atual e volta ao menu, sem gravar o que estava pela metade |
| `sair` | Fecha o programa |
| `limpar` | Limpa a tela; no menu, desenha o menu de novo |
| `ajuda` ou `?` | Mostra a lista de comandos |
| `lista` | Nas perguntas de ID de equipamento (e na escolha de uma vulnerabilidade do catálogo, na opção 6), mostra os registros e repete a pergunta |

Números decimais aceitam vírgula ou ponto (`7,5` ou `7.5`).

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

| Opção | Faz |
| --- | --- |
| 1 | Cadastra um equipamento (e, em seguida, suas vulnerabilidades iniciais) |
| 2 | Lista todos os equipamentos |
| 3 | Busca por ID, hostname, responsável, lotação ou tipo |
| 4 | Atualiza um equipamento (Enter mantém o valor atual); inclui mudar o tipo |
| 5 | Exclui um equipamento, com tudo que dependia dele |
| 6 | Registra uma vulnerabilidade num equipamento: uma nova ou uma já existente no catálogo |
| 7 | Mostra um equipamento e suas vulnerabilidades, da mais grave |
| 8 | Atualiza uma vulnerabilidade (descrição, categoria, nota ou vetor CVSS) ou o status dela naquele equipamento |
| 9 | Tira uma vulnerabilidade de um equipamento (cadastro errado ou duplicado) |
| 10 | Lista as vulnerabilidades pendentes de todos os equipamentos, da mais grave |
| 11 | Cadastra uma dependência entre dois equipamentos |
| 12 | Mostra as dependências de um equipamento e permite remover uma |
| 13 | Mostra o risco próprio e o efetivo de **todos** os equipamentos |
| 14 | Mostra, passo a passo, como o risco de **um** equipamento foi calculado |
| 15 | Mostra M, v, M v, F, b e A (para poucos equipamentos), o posto de M e a dimensão do seu núcleo, e a verificação de I − A, com o determinante, o número de condição e o posto |

As cores precisam de um terminal que interprete códigos ANSI. Com a variável de
ambiente `NO_COLOR` definida, o programa imprime texto puro.

## Requisitos do Trabalho 2

| # | Requisito | Peso | Onde está |
| --- | --- | --- | --- |
| 1 | Classe de equipamentos; cada ativo é um objeto individual criado a partir dela | 20% | `equipamentos.py`: a classe abstrata `Equipamento` e uma subclasse por tipo (`Servidor`, `Roteador`...); `criar_equipamento()` escolhe a subclasse. A classe "equipamentos" do enunciado é a `Equipamento`, no módulo `equipamentos.py`: o nome segue a convenção da PEP 8 para classes (CapWords) e está no singular, porque cada objeto é *um* equipamento. |
| 2 | Armazenamento em JSON formado por um array de objetos | 20% | `armazenamento.py` grava o que `Inventario.para_dict()` monta: um array JSON na raiz, um objeto por equipamento. Veja [o formato](#formato-do-arquivo-de-dados). |
| 3 | Aplicação em container, funcionando por no mínimo 24 h | 45% | `Dockerfile`, `compose.yaml`, `requirements.txt`, `.dockerignore`; ajustes de container em `main.py` (`preparar_container`). Veja [Em container Docker](#em-container-docker) e [No servidor do docente](#no-servidor-do-docente). |
| 4 | Risco efetivo pelo modelo linear, verificando a invertibilidade antes de resolver; risco próprio e efetivo consultáveis | 15% | `risco.py` (`ModeloRisco`); opções 13, 14 e 15 do menu. A matriz A fica no mesmo JSON (campo `dependencias`), e o NumPy está declarado em `requirements.txt`, que o `Dockerfile` instala. Veja [o modelo de risco](#o-modelo-de-risco). |

Os requisitos do Trabalho 1 (cadastro, busca por ID e por hostname,
atualização, exclusão com cascata, vulnerabilidades com categoria, severidade e
status, listagem por equipamento, validações e tratamento de erros) continuam
atendidos: as opções 1 a 10 do T1 foram mantidas, com os mesmos números e
funções, e com os mesmos comandos globais. O requisito do repositório com mais
de duas branches e merges também continua valendo: veja
[Fluxo de trabalho no Git](#fluxo-de-trabalho-no-git).

## Estrutura

| Arquivo | Responsabilidade |
| --- | --- |
| `main.py` | Classe `Aplicacao`: o menu e as ações. Liga as demais peças. É o ponto de partida |
| `equipamentos.py` | Classe abstrata `Equipamento`, as sete subclasses e o fator de exposição de cada tipo |
| `vulnerabilidades.py` | Classe `Vulnerabilidade`: entrada do catálogo (descrição, origem, nota CVSS) |
| `inventario.py` | Classe `Inventario`: o conjunto dos equipamentos e das vulnerabilidades e as regras entre eles (hostname único, cascata, dependências) |
| `risco.py` | Classe `ModeloRisco`: monta M, v, A e b, verifica a invertibilidade (com o posto e o teorema de Rouché-Capelli), resolve o sistema e confere a solução |
| `armazenamento.py` | Classe `ArquivoInventario`: lê e grava o JSON, com gravação atômica |
| `migracao.py` | Converte uma base do Trabalho 1 para o formato novo |
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
| `dados_exemplo/` | Base fictícia de 76 equipamentos e dois cenários pequenos: um de 3 equipamentos, resolvido à mão, e um singular |

Só `entrada.py` chama `input()` e só `armazenamento.py` lê e grava a base (a
conversão manual de `migracao.py`, executada como script, também grava o arquivo
de destino). As classes do domínio (`Equipamento`, `Vulnerabilidade`,
`Inventario`, `ModeloRisco`) não sabem de teclado, tela nem arquivo, por isso
cada módulo tem um bloco de teste que roda sozinho (`python equipamentos.py`).

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
exemplo, M é 76 × 79, com posto 56, então o núcleo tem dimensão 23
(56 + 23 = 79). Catorze colunas são nulas: vulnerabilidades corrigidas em todos
os equipamentos em que aparecem, que continuam no catálogo mas não pesam no
risco. A opção 15 mostra o posto e a dimensão do núcleo.

O enunciado define `b = M v` e sugere que "cada tipo de equipamento pode definir
um fator de exposição que pondera o seu risco próprio". É o que `F` faz: `M v` é
a soma das notas das vulnerabilidades do equipamento, e o fator do tipo a
pondera. Para usar a definição literal, `b = M v`, basta trocar
`USAR_FATOR_DE_EXPOSICAO = True` por `False` no início de `risco.py`: todos os
fatores passam a valer 1. A
[validação à mão](#validação-à-mão-cenário-de-3-equipamentos) mostra a conta
dos dois jeitos.

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
- **As boas práticas da aula de álgebra linear computacional** (S3_09 a
  S3_12): `@` para produto de matrizes (o `*` só aparece na diagonal de F, de
  propósito, e o `python risco.py` confere que dá o mesmo que a matriz F
  inteira com `@`); `solve` em vez de `inv`; resultados de contas (o
  determinante, a solução, a soma das frações) comparados com tolerância, e
  não com `==`; o número de condição antes de confiar na solução; o posto para
  classificar o sistema; e matrizes em `float64`, sem inteiros de tamanho fixo,
  que "dão a volta". As notas CVSS são a exceção de propósito: digitadas,
  lidas do arquivo ou calculadas pelo vetor, elas sempre ficam com uma casa
  decimal, e por isso podem ser comparadas exatamente.

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
2. **Número de condição.** Um arquivo editado à mão pode violar a regra. Sem a
   garantia da dominância, o número de condição (`numpy.linalg.cond`) decide se
   `I − A` é tratada como invertível: acima de 10¹², o sistema é tratado como
   singular.
   O determinante também é calculado, mas só para informar: em ponto
   flutuante, um determinante teoricamente nulo raramente dá zero exato, e o
   tamanho de um determinante pequeno depende da escala da matriz. Quando o
   número de condição passa do limite, o posto de `I − A`
   (`numpy.linalg.matrix_rank`) diz o motivo. Com posto cheio, `I − A` é
   invertível em teoria e a solução existe e é única, mas a matriz é tão mal
   condicionada que o computador não a calcula com confiança. Com posto menor
   que n, o programa diz quantas soluções o sistema tem, pelo teorema de
   Rouché-Capelli: compara o posto de `I − A` com o da matriz ampliada
   `[I − A | b]`. Se o da ampliada é maior, não há solução; se os dois são
   iguais (e menores que n), há infinitas.
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

Use as opções 15 (matrizes), 13 (risco de todos) e 14 (passo a passo). Se
alterar algo, o programa grava nesse arquivo: trabalhe numa cópia. O
`python risco.py` repete essa conta e mais outras: compara a solução do NumPy
com a série de Neumann (`x = b + A b + A² b + ...`, que converge quando cada
linha de A soma menos que 1) em 20 inventários aleatórios, e com uma solução em
frações exatas nos que têm até 6 equipamentos.

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
    "vulnerabilidades": [
      {"id": 1, "descricao": "Vulnerabilidade V1", "origem": 6,
       "cvss": 4.0, "situacao": 1}
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
- `dependencias` é a linha do equipamento na matriz A: pares (equipamento do
  qual se herda, fração). A matriz A, portanto, é persistida no mesmo JSON dos
  demais dados, como o enunciado pede. A matriz M não é gravada: é montada,
  na hora, a partir de `vulnerabilidades` de cada equipamento.
- Uma mesma vulnerabilidade pode afetar vários equipamentos: ela aparece, com os
  mesmos `id`, `descricao`, `origem`, `cvss` e `vetor`, no objeto de cada um deles (é
  daí que vem a matriz M). Ao carregar, as cópias são reunidas num só objeto do
  catálogo; se duas cópias do mesmo `id` forem diferentes, o arquivo é
  recusado. A `situacao` do tratamento é de cada equipamento: o mesmo problema
  pode estar corrigido num e aberto em outro. Uma vulnerabilidade que nenhum
  equipamento tem não é gravada.
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
- A carga confere o arquivo inteiro: tipos, ids repetidos, hostname repetido,
  dependência de equipamento que não existe, vulnerabilidade com dados
  diferentes em dois equipamentos, nota que não confere com o vetor, o mesmo
  nome duas vezes num objeto, NaN.
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

## Decisões de projeto

- **Classe abstrata com uma subclasse por tipo.** `Equipamento` guarda o que é
  comum e declara `fator_exposicao` como método abstrato: não se cria um
  equipamento "genérico" (a classe não pode ser instanciada), e esquecer o
  fator numa subclasse nova é um erro na hora. A tabela `CLASSE_DO_TIPO` liga
  cada `TipoEquipamento` à sua classe; um tipo novo é uma subclasse e uma linha.
- **Composição para as relações.** O equipamento *tem* um dicionário de
  vulnerabilidades (id → situação) e um de dependências (id → fração); não
  herda de nada além da base. Referenciar por id, e não por objeto, mantém o
  JSON simples e evita referências circulares entre equipamentos que dependem
  um do outro.
- **Quem sabe cuida.** A regra "soma das frações < 1" fica em `Equipamento`
  porque só depende dele; "hostname único" e "o destino da dependência existe"
  ficam em `Inventario`, que conhece os outros equipamentos; a conta de risco
  fica em `ModeloRisco`, que não altera nenhum dado.
- **Tipo do equipamento é mudável**, mas um objeto não muda de classe:
  `Equipamento.converter_para()` cria outro objeto da subclasse certa, com o
  mesmo id e as mesmas relações, e o `Inventario` o coloca no lugar.
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
  pacote a mais é código de terceiros rodando dentro do container.
- **Nada sensível no repositório.** A pasta `dados/`, com a base real, fica
  fora do Git (`.gitignore`) e da imagem (`.dockerignore`); a base de exemplo
  é fictícia; não há senhas nem chaves no código.
- **Sem login, por enquanto.** O programa não tem autenticação nem perfis de
  acesso: quem consegue dar `docker attach` (ou seja, quem acessa o servidor)
  pode alterar tudo. Autenticação e autorização ficam para o backend web do
  trabalho final; até lá, a proteção é o acesso ao servidor.

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
| [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) e [módulo json](https://docs.python.org/3/library/json.html) | Formato do arquivo | Array JSON na raiz, UTF-8 sem BOM, sem `NaN` nem `Infinity`, nomes únicos em cada objeto. Veja [o formato](#formato-do-arquivo-de-dados). |
| [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) e [v4.0](https://www.first.org/cvss/v4.0/specification-document) | Nota e severidade | Escala qualitativa oficial (igual nas duas versões) e nota com uma casa decimal. A nota pode vir do vetor (versões 4.0, 3.1 e 3.0), pela fórmula oficial, com as perguntas das métricas base explicadas a partir da especificação. Desvios: 0,0 (*Nenhuma*) não é aceita, e o vetor é aceito fora de ordem e em minúsculas, mas gravado na forma oficial. |
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
- **Limite do número de condição.** O valor 10¹² é uma escolha prática (deixa
  uns 4 dígitos confiáveis em ponto flutuante de 64 bits), não um teorema.
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

São 60 testes, só com a biblioteca padrão: o programa inteiro rodando por
dentro com o teclado simulado (do cadastro ao risco, incluindo o cenário de 3
equipamentos), a nota CVSS pelo vetor e pelas perguntas do `calcular`, a recusa
de bases inválidas (inclusive JSON fora da norma) e do sistema singular (com o
posto e o teorema de Rouché-Capelli), a conversão da base do Trabalho 1, o
comportamento no container (inclusive `sair` e Ctrl+D) e o modelo de risco
sobre os arquivos de exemplo. O último teste roda o autoteste de cada módulo.
Nada toca em `dados/inventario.json`: os testes usam pastas temporárias.

Os mesmos testes rodam no pytest, que entende os testes escritos com o
unittest:

```
pip install pytest
python -m pytest testes.py
```

Cobertura, com o coverage.py (configurado em `.coveragerc`): os testes passam
por 85% das linhas do programa, sem contar os autotestes dos módulos, que rodam
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

O pylint, outra ferramenta de análise estática, dá nota 9,77 de 10
(`pip install pylint` e `pylint *.py`). Os avisos que restam foram mantidos de
propósito:

- os nomes `M` e `A`, iguais aos do enunciado;
- limites de tamanho, como funções com mais de cinco parâmetros
  (`registrar_vulnerabilidade` recebe um parâmetro por dado da
  vulnerabilidade) e classes com mais de 20 métodos públicos;
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
| Na opção 8, digitar a nota que a vulnerabilidade já tinha apagava o vetor CVSS dela | A mesma nota (e a mesma categoria) não conta como mudança, e o vetor continua | `test_atualizar_com_os_mesmos_valores_nao_muda_nada` |
| No fim do `calcular`, o Enter em "Usar esta nota?" descartava as 11 respostas | O Enter aceita a nota | `test_calcular_a_nota_respondendo_as_perguntas` |
| `limpar` numa pergunta do `calcular` apagava a pergunta da tela | A pergunta é desenhada de novo | `test_letra_anterior_e_cancelar_nas_perguntas` |
| Um vetor com métricas não definidas (valor `X`) era recusado | As métricas `X` são ignoradas | `test_vetor_com_metricas_nao_definidas_e_aceito` |
| `"vetor": null` no arquivo era recusado | `null` vale como sem vetor | `test_vetor_no_arquivo_tem_de_conferir_com_a_nota` |
| Com o usuário do container trocado para o UID 10001, o programa não gravava no volume criado pela versão anterior | Um `chown` único no volume, descrito em [Em container Docker](#em-container-docker) | Conferido à mão, no container |
| A explicação da interação "Passiva" do CVSS dava como exemplo clicar num link, que a especificação do FIRST classifica como "Ativa" | Texto corrigido pela especificação | Revisão dos textos contra a especificação |

## Fluxo de trabalho no Git

O requisito 10 do Trabalho 1 (repositório com mais de duas branches e merge)
continua valendo. Cada mudança é feita numa branch própria e integrada à `main`
por merge, com `git merge --no-ff`, que registra o ponto de junção no
histórico mesmo quando não há conflito:

| Prefixo | Uso | Exemplo neste repositório |
| --- | --- | --- |
| `feature/` | Funcionalidade nova | `feature/matrizes-e-diagnostico`, `feature/vetor-cvss`, `feature/posto-e-rouche-capelli` |
| `fix/` | Correção de defeito | `fix/normas-oficiais` |
| `docs/` | Documentação | `docs/revisao-requisitos`, `docs/normas-seguidas` |
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
convertida e acrescida de dependências: 76 equipamentos, 79 vulnerabilidades
(88 registros equipamento–vulnerabilidade) e 164 dependências. **Os dados são
fictícios**: os setores e os sistemas citados existem, mas hostnames,
vulnerabilidades, notas, situações e dependências foram inventados e não
descrevem a rede real da 1ª DRPC Uberlândia.

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

`dados_exemplo/cenario_3_equipamentos.json` é o cenário resolvido à mão em
[Validação à mão](#validação-à-mão-cenário-de-3-equipamentos).

`dados_exemplo/cenario_singular.json` tem três equipamentos cujas frações de
dependência somam 1 em cada linha de A (0,3 + 0,7): o programa abre, mas o
modelo de risco avisa que `I − A` não é invertível e não calcula nada. Serve
para demonstrar a verificação, o número de condição, o determinante que dá
quase zero, mas não zero exato, e o teorema de Rouché-Capelli: o posto de
`I − A` é 2 e o de `[I − A | b]` é 3, então o sistema não tem solução.
