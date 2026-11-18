# Refatoração do Trabalho 02

Card S5_01. Regra seguida: **os testes passam antes e depois de cada passo**
(`python testes.py`, 115 testes no início da sprint, 125 no fim; `pytest`
na web), e cada passo muda a estrutura, não o comportamento.

## Code smells encontrados

| Smell | Onde | Situação |
| --- | --- | --- |
| Classe grande (*Large Class*) | `main.py`, classe `Aplicacao` (1.340 linhas, 57 métodos) | Dívida registrada (D1) |
| Método longo (*Long Method*) | `Aplicacao.atualizar_equipamento` (67 linhas), `views.collection` (136) | Dívida registrada (D2) |
| Verificação repetida de `None` (*Duplicated Code*) | `risco.py`: `if self.x is None: self.resolver()` em três métodos, e o mypy não sabia que depois disso `x` existia | **Refatorado** (R4) |
| Número mágico | Faixas dos `CHECK` do banco (1 a 7, 1 a 6, 1 a 4) repetiam os `Enum` | **Refatorado** (R5) |
| Variável reaproveitada com outro tipo | `armazenamento.py`: `f` arquivo de texto e depois binário no mesmo escopo | **Refatorado** (R3) |
| Falta de tipos | Domínio inteiro sem anotação; o mypy não conferia nada | **Refatorado** (R1) |
| Condicional sobre o tipo de armazenamento | Trocar JSON por banco exigiria `if` em `main.py` | **Evitado com polimorfismo** (R2) |
| Obsessão por primitivos | O formato do arquivo circula como `dict`/`list` (`para_dict`) | Mantido de propósito: é o contrato do arquivo JSON |
| Comentário que explica código confuso | Raro; os comentários dizem o porquê | — |

## Refatorações aplicadas (uma por commit)

### R1. Adicionar anotações de tipo (e rodar o mypy)

`classificacoes`, `validacao`, `ficha_tecnica`, `equipamentos`,
`vulnerabilidades`, `inventario`, `risco`, `armazenamento`, `migracao` e o novo
`repositorio_sql` anotados (`from __future__ import annotations`,
`ClassVar[TipoEquipamento]`, `dict[int, SituacaoTratamento]`, `str | None`...).
O que o mypy achou e foi corrigido:

| Achado do mypy | Correção |
| --- | --- |
| `desvincular_vulnerabilidade` e `remover_dependencia` anotados como `None` mas devolvendo `bool` | Tipo de retorno `bool` (o chamador usa o resultado) |
| Atributos da `FichaTecnica` inferidos como `None` | `str \| None` declarado na classe |
| `hostnames`, `patrimonios`, `donos`, `catalogo` sem tipo | `dict[str, int]` etc. |
| `x` do modelo de risco "pode ser `None`" ao indexar | R4 |
| `f.write(bytes)` num arquivo de texto | R3 |
| `migracao_feita` "pode ser `None`" no autoteste | `assert` explícito antes de desempacotar |

Relatório:

```text
$ mypy
Success: no issues found in 10 source files
```

`mypy.ini` liga `check_untyped_defs`, `disallow_incomplete_defs`,
`no_implicit_optional` e `warn_unused_ignores`. As telas (`main`, `telas`,
`arvore`) e a atualização de CVE ficam fora por enquanto (dívida D3).

### R2. Substituir condicional por polimorfismo: o repositório

Para ter o banco relacional (S5_06) sem `if banco: ... else: ...` espalhado
em `main.py`, `ArquivoInventario` e `BancoInventario` oferecem a mesma
interface (`carregar()`, `salvar()`, `caminho`, `migracao_feita`), e uma função
fábrica escolhe uma vez (`armazenamento.abrir_repositorio()`). `main.py` mudou
uma linha. O mesmo princípio já estava no domínio desde a Sprint 3: o fator de
exposição é um atributo de cada subclasse de `Equipamento` (`Servidor`,
`Roteador`...), não uma cadeia de `if tipo == ...`; e o menu usa um
dicionário número → método no lugar de `if/elif`.

### R3. Renomear variável

`armazenamento.py`, autoteste: o arquivo binário passou a se chamar `fb`; `f`
fica para o de texto. O mypy deixou de acusar `write(bytes)` num
`TextIOWrapper`.

### R4. Extrair variável explicativa (e remover duplicação)

```python
# antes, em relatorio(), contribuicoes() e risco_total()
if self.x is None:
    self.resolver()
return float(self.x.sum())          # mypy: "None" não tem .sum
# depois
x = self.x if self.x is not None else self.resolver()
return float(x.sum())
```

`resolver()` já devolvia o vetor; agora o código usa isso.

### R5. Substituir número mágico por constante derivada

```python
def _faixa(coluna, enumeracao):
    valores = [item.value for item in enumeracao]
    return f"{coluna} BETWEEN {min(valores)} AND {max(valores)}"

CheckConstraint(_faixa("tipo", TipoEquipamento), name="ck_equipamento_tipo")
```

Um tipo novo no `Enum` não esquece o banco. (A primeira versão tinha os
números à mão e estava errada: 1 a 6 para os tipos, que são 7. O autoteste
pegou.)

### R6. Extrair função (segurança)

`atualizacao_cve.abrir_url()` ganhou a verificação de `https://` que só quem a
chamava fazia: a regra fica onde o perigo está (achado do bandit).

## Pontos de inserção de testes

Para mexer em código antigo com segurança, os testes entram pelas costuras que
já existem: `Aplicacao(arquivo, base_cve, abrir)` recebe o repositório e a
função de download (os testes passam versões em memória);
`BancoInventario(engine=...)` recebe o banco; `ModeloRisco` recebe o
inventário. Nenhum teste precisa de internet nem toca em
`dados/inventario.json`.

## Dívida técnica

A lista está em [DIVIDA-TECNICA.md](DIVIDA-TECNICA.md), com os comandos para
abrir cada item como issue no GitHub.
