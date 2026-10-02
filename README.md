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
- [Limitações conhecidas](#limitações-conhecidas)
- [Testes](#testes)
- [Dados de exemplo](#dados-de-exemplo)

## Como executar

### Direto no computador

Requer Python 3.10 ou superior e o NumPy (a única dependência externa, usada
no modelo de risco). Foi desenvolvido e testado com Python 3.11 e NumPy 2.x; o
`Dockerfile` usa Python 3.12.

```
pip install -r requirements.txt
python main.py
```

O programa começa com a base vazia (`dados/inventario.json`, criado ao gravar
a primeira alteração). Para testá-lo com dados fictícios, veja
[Dados de exemplo](#dados-de-exemplo).

### Em container Docker

```
docker build -t inventario:1.0 .
docker volume create inventario-dados

docker run -dit --name inventario --restart unless-stopped \
  -v inventario-dados:/app/dados inventario:1.0

docker attach inventario
```

No `docker attach` a tela costuma aparecer vazia, porque o Docker não repete
o que já foi impresso: **tecle Enter e o menu é desenhado de novo.** Para sair
sem parar o programa, tecle **Ctrl+P e depois Ctrl+Q.** O container continua
rodando e dá para voltar com outro `docker attach`.

O `compose.yaml` é uma alternativa que faz a construção, o volume e a execução
de uma vez: `docker compose up -d --build`, seguido de
`docker attach inventario`.

| Opção | Por quê |
| --- | --- |
| `-d` | O container roda em segundo plano (*detached*). |
| `-i` e `-t` | Mantêm a entrada aberta e alocam um terminal. O processo principal é um menu que espera o teclado com `input()`; sem terminal, `input()` recebe fim de entrada e o programa terminaria na hora. Por isso é `-dit` e não só `-d`. Sem terminal, o programa explica isso e para. |
| `--restart unless-stopped` | O Docker religa o programa se ele cair ou se o servidor reiniciar, a não ser que alguém tenha parado o container de propósito (`docker stop`). |
| `-v inventario-dados:/app/dados` | Os dados ficam num *volume*: sobrevivem a `docker rm` e à troca da imagem por uma versão nova. |

Dentro do container o programa se comporta de forma diferente em quatro pontos,
ligados pela variável de ambiente `INVENTARIO_EM_CONTAINER` (definida no
`Dockerfile`):

- **Ctrl+C é ignorado.** No `docker attach` ele chegaria ao programa e o
  derrubaria; o menu lembra que Ctrl+P, Ctrl+Q é o caminho para sair.
- **Sair pede confirmação**, seja pela opção 0, seja digitando `sair` em
  qualquer pergunta, porque encerrar o programa para o container (o Docker o
  religa, mas o tempo de atividade recomeça).
- **Ctrl+D é ignorado** (com um aviso), pelo mesmo motivo.
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
`--restart unless-stopped` o Docker tentaria de novo sem parar. Para consertar:
`docker stop inventario`, depois corrija o arquivo dentro do volume (por
exemplo, `docker run --rm -it -v inventario-dados:/d alpine vi /d/inventario.json`)
ou mova-o para outro nome, e `docker start inventario`.

Para atualizar o programa, mantendo os dados:

```
docker build -t inventario:1.0 .
docker rm -f inventario
docker run -dit --name inventario --restart unless-stopped \
  -v inventario-dados:/app/dados inventario:1.0
```

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
| `lista` | Nas perguntas de ID, mostra os registros e repete a pergunta |

Números decimais aceitam vírgula ou ponto (`7,5` ou `7.5`).

| Opção | Faz |
| --- | --- |
| 1 | Cadastra um equipamento (e, em seguida, suas vulnerabilidades iniciais) |
| 2 | Lista todos os equipamentos |
| 3 | Busca por ID, hostname, responsável, lotação ou tipo |
| 4 | Atualiza um equipamento (Enter mantém o valor atual); inclui mudar o tipo |
| 5 | Exclui um equipamento, com tudo que dependia dele |
| 6 | Registra uma vulnerabilidade num equipamento: uma nova ou uma já existente no catálogo |
| 7 | Mostra um equipamento e suas vulnerabilidades, da mais grave |
| 8 | Atualiza uma vulnerabilidade (descrição, categoria, nota CVSS) ou o status dela naquele equipamento |
| 9 | Tira uma vulnerabilidade de um equipamento (cadastro errado ou duplicado) |
| 10 | Lista as vulnerabilidades pendentes de todos os equipamentos, da mais grave |
| 11 | Cadastra uma dependência entre dois equipamentos |
| 12 | Mostra as dependências de um equipamento e permite remover uma |
| 13 | Mostra o risco próprio e o efetivo de **todos** os equipamentos |
| 14 | Mostra, passo a passo, como o risco de **um** equipamento foi calculado |
| 15 | Mostra as matrizes M, v e A (para poucos equipamentos), para conferir à mão |

As cores precisam de um terminal que interprete códigos ANSI. Com a variável de
ambiente `NO_COLOR` definida, o programa imprime texto puro.

## Requisitos do Trabalho 2

| # | Requisito | Peso | Onde está |
| --- | --- | --- | --- |
| 1 | Classe de equipamentos; cada ativo é um objeto individual criado a partir dela | 20% | `equipamentos.py`: a classe abstrata `Equipamento` e uma subclasse por tipo (`Servidor`, `Roteador`...); `criar_equipamento()` escolhe a subclasse. |
| 2 | Armazenamento em JSON formado por um array de objetos | 20% | `armazenamento.py` grava o que `Inventario.para_dict()` monta: um array JSON na raiz, um objeto por equipamento. Veja [o formato](#formato-do-arquivo-de-dados). |
| 3 | Aplicação em container, funcionando por no mínimo 24 h | 45% | `Dockerfile`, `compose.yaml`, `requirements.txt`, `.dockerignore`; ajustes de container em `main.py` (`preparar_container`). Veja [Em container Docker](#em-container-docker). |
| 4 | Risco efetivo pelo modelo linear, verificando a invertibilidade antes de resolver; risco próprio e efetivo consultáveis | 15% | `risco.py` (`ModeloRisco`); opções 13, 14 e 15 do menu. Veja [o modelo de risco](#o-modelo-de-risco). |

Os requisitos do Trabalho 1 (cadastro, busca por ID e por hostname,
atualização, exclusão com cascata, vulnerabilidades com categoria, severidade e
status, listagem por equipamento, validações e tratamento de erros) continuam
atendidos: as opções 1 a 10 do T1 foram mantidas, com os mesmos números e
funções, e com os mesmos comandos globais.

## Estrutura

| Arquivo | Responsabilidade |
| --- | --- |
| `main.py` | Classe `Aplicacao`: o menu e as ações. Liga as demais peças. É o ponto de partida |
| `equipamentos.py` | Classe abstrata `Equipamento`, as sete subclasses e o fator de exposição de cada tipo |
| `vulnerabilidades.py` | Classe `Vulnerabilidade`: entrada do catálogo (descrição, origem, nota CVSS) |
| `inventario.py` | Classe `Inventario`: o conjunto dos equipamentos e das vulnerabilidades e as regras entre eles (hostname único, cascata, dependências) |
| `risco.py` | Classe `ModeloRisco`: monta M, v, A e b, verifica a invertibilidade e resolve o sistema |
| `armazenamento.py` | Classe `ArquivoInventario`: lê e grava o JSON, com gravação atômica |
| `migracao.py` | Converte uma base do Trabalho 1 para o formato novo |
| `classificacoes.py` | Enums: tipo do equipamento; origem, severidade e status da vulnerabilidade |
| `validacao.py` | Conferência de dados vindos do arquivo |
| `entrada.py` | Leitura do teclado e comandos globais (`voltar`, `sair`...). Único módulo com `input()` |
| `telas.py` | Tabelas, fichas e relatórios impressos na tela |
| `formatacao.py`, `cores.py`, `banner.py`, `surpresa.py` | Padronização de texto, cores ANSI, logotipo e a animação-surpresa, herdados do Trabalho 1 |
| `testes.py` | Testes automáticos (`python testes.py`) |
| `Dockerfile`, `compose.yaml`, `.dockerignore`, `requirements.txt` | Container |
| `dados_exemplo/` | Base fictícia de 76 equipamentos e um cenário de 3 equipamentos para validar o modelo |

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
| **F** | n | Fator de exposição de cada equipamento, que depende do tipo |
| **b** | n | Risco próprio: `b = F · (M v)`, produto elemento a elemento; com `F = 1`, exatamente `b = M v` |
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

O enunciado define `b = M v` e sugere que "cada tipo de equipamento pode definir
um fator de exposição que pondera o seu risco próprio". É o que `F` faz: `M v` é
a soma das notas das vulnerabilidades do equipamento, e o fator do tipo a
pondera. Quem conferir à mão sem o fator, com `b = M v`, encontra os mesmos
números ao fazer `F = 1` para todos.

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
- **A severidade vem da nota CVSS**, pela escala do CVSS v3.x (0,1–3,9 baixa;
  4,0–6,9 média; 7,0–8,9 alta; 9,0–10,0 crítica), e não é gravada: assim a nota
  e a severidade nunca discordam.
- **Resolve-se o sistema, não se inverte a matriz.** `numpy.linalg.solve` faz a
  fatoração LU: é mais preciso e mais rápido do que calcular a inversa de
  `I − A` e multiplicar por *b*.

### Verificação de invertibilidade

Antes de resolver, `ModeloRisco.diagnosticar()` verifica se `I − A` é
invertível e `main.py` informa o usuário quando não é (nesse caso nada é
resolvido):

1. **Dominância diagonal.** Se cada linha de A soma menos que 1, `I − A` é
   estritamente diagonal dominante, o que garante que é invertível. Por isso o
   cadastro de dependências **impõe essa regra** (`Equipamento.
   definir_dependencia`): uma dependência que fizesse a soma da linha chegar a
   1 é recusada, com a mensagem de quanto ainda sobra. A soma é arredondada
   antes da comparação, porque em ponto flutuante `0,7 + 0,3` pode dar
   `0,9999999999999999`.
2. **Número de condição.** Um arquivo editado à mão pode violar a regra. Sem a
   garantia da dominância, o número de condição (`numpy.linalg.cond`) decide se
   `I − A` é invertível: acima de 10¹², o sistema é tratado como singular.
   O determinante também é calculado, mas só para informar: em ponto
   flutuante, um determinante teoricamente nulo raramente dá zero exato, e o
   tamanho de um determinante pequeno depende da escala da matriz.
3. **Raio espectral.** Ser invertível não basta: `I − A` pode ser invertível e
   a solução ter riscos efetivos *menores* que o próprio, até negativos, o que
   não é um risco herdado. Como `A` não tem valores negativos, a solução faz
   sentido exatamente quando o raio espectral de `A` (o maior valor absoluto
   de seus autovalores) é menor que 1. Se não for, o programa avisa e não
   calcula, como no caso singular.

Exemplos de arquivo que a verificação recusa: três equipamentos que herdam 0,5
um do outro (cada linha de A soma 1), em que `I − A` tem o vetor (1, 1, 1) como
autovetor de autovalor 0 (singular); e um equipamento que herda 0,9 de dois
outros, que herdam 0,9 dele (invertível, mas com raio espectral 1,27 e riscos
efetivos negativos).

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

Para conferir no programa:

```
INVENTARIO_DADOS=dados_exemplo/cenario_3_equipamentos.json python main.py
```

(no PowerShell: `$env:INVENTARIO_DADOS="dados_exemplo/cenario_3_equipamentos.json"`)
e use as opções 15 (matrizes), 13 (risco de todos) e 14 (passo a passo). Se
alterar algo, o programa grava nesse arquivo: trabalhe numa cópia. O
`python risco.py` repete essa conta e mais outras: compara a solução do NumPy
com uma solução em frações exatas e com a série de Neumann
(`x = b + A b + A² b + ...`, que converge quando cada linha de A soma menos
que 1) em 20 inventários aleatórios.

## Formato do arquivo de dados

Um **array JSON de objetos**: um objeto por equipamento, com as suas
vulnerabilidades e as suas dependências dentro dele.

```json
[
  {
    "id": 2,
    "tipo": 2,
    "hostname": "SERVIDOR-01",
    "custodiante": "Fulano de Tal",
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
- `dependencias` é a linha do equipamento na matriz A: pares (equipamento do
  qual se herda, fração). A matriz A, portanto, é persistida no mesmo JSON dos
  demais dados, como o enunciado pede. A matriz M não é gravada: é montada,
  na hora, a partir de `vulnerabilidades` de cada equipamento.
- Uma mesma vulnerabilidade pode afetar vários equipamentos: ela aparece, com os
  mesmos `id`, `descricao`, `origem` e `cvss`, no objeto de cada um deles (é
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
- A gravação vai para um arquivo temporário que depois substitui o definitivo
  (`os.replace`): se ela for interrompida, a base anterior continua inteira.
- A carga confere o arquivo inteiro: tipos, ids repetidos, hostname repetido,
  dependência de equipamento que não existe, vulnerabilidade com dados
  diferentes em dois equipamentos, NaN. Qualquer problema para o programa com
  uma mensagem que diz o que está errado e onde, em vez de carregar pela
  metade e apagar dados bons na próxima gravação. O texto gravado é mantido
  como está (a padronização de maiúsculas é feita na digitação).
- A regra "soma das frações de uma linha < 1" **não** é imposta na carga, de
  propósito: quem avalia um arquivo editado à mão é o modelo de risco, que
  avisa o usuário.

**Base do Trabalho 1.** Se o arquivo encontrado for do formato antigo, ele é
convertido ao abrir (`migracao.py`) e uma cópia da original fica ao lado dele
(`inventario.json.t1.bak`). Falhas iguais do T1 viram uma única vulnerabilidade
(com o mesmo `id` em cada equipamento que a tinha), e a gravidade vira uma nota CVSS na mesma faixa (baixa 3,1; média
5,3; alta 7,5; crítica 9,8). Também dá para converter à mão:
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

## Limitações conhecidas

- **Um usuário por vez.** O arquivo é lido uma vez, ao abrir, e cada alteração
  é gravada na hora. Dois programas abertos sobre o mesmo arquivo se
  sobrescreveriam.
- **O programa é interativo.** O container precisa de `-it` (veja
  [Em container Docker](#em-container-docker)); não há API HTTP.
- **A nota CVSS é guardada com uma casa decimal**: `8,25` vira `8,2`, sem
  aviso, como no CVSS publicado.
- **A escala do risco não é limitada.** O risco próprio e o efetivo são somas
  ponderadas de notas CVSS e podem passar de 10; servem para comparar
  equipamentos entre si, não são uma nota de 0 a 10.
- **Os fatores de exposição e as frações de dependência são estimativas** de
  quem usa o programa: o modelo não as deduz da rede real.
- **Limite do número de condição.** O valor 10¹² é uma escolha prática (deixa
  uns 4 dígitos confiáveis em ponto flutuante de 64 bits), não um teorema.
- **Acentos em hostname** não são aceitos (regra de nome de máquina, RFC 952 e
  1123), como no Trabalho 1.

## Testes

```
python testes.py
```

São 36 testes, só com a biblioteca padrão: o programa inteiro rodando por
dentro com o teclado simulado (do cadastro ao risco, incluindo o cenário de 3
equipamentos), a recusa de bases inválidas e do sistema singular, a conversão da
base do Trabalho 1, o comportamento no container (inclusive `sair` e Ctrl+D) e o
modelo de risco sobre os arquivos de exemplo. O último teste roda o autoteste de cada módulo. Nada toca
em `dados/inventario.json`: os testes usam pastas temporárias.

Estilo: `flake8 --max-line-length 79` e `pydocstyle --convention=pep257
--add-ignore=D401` (a regra D401, que pede o verbo no imperativo, é desligada: as
docstrings usam "Devolve...", "Verifica...") não apontam nada.

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

(`copy` no lugar de `cp` no Prompt de Comando.) No container, antes de ligá-lo
pela primeira vez:

```
docker volume create inventario-dados
docker create --name semente -v inventario-dados:/app/dados inventario:1.0
docker cp dados_exemplo/inventario_exemplo.json semente:/app/dados/inventario.json
docker rm semente
```

Depois é só executar o `docker run` normal. Copiar o arquivo com o programa já
rodando não adianta, porque a base é lida uma vez, ao abrir.

`dados_exemplo/cenario_3_equipamentos.json` é o cenário resolvido à mão em
[Validação à mão](#validação-à-mão-cenário-de-3-equipamentos).

`dados_exemplo/cenario_singular.json` tem três equipamentos que herdam 0,5 um do
outro (cada linha de A soma 1): o programa abre, mas o modelo de risco avisa que
`I − A` não é invertível e não calcula nada. Serve para demonstrar a verificação.
