"""Exibição: tabelas, fichas e relatórios, tudo impresso na tela.

Só imprime: não lê do teclado e não altera nenhum dado. Recebe os
objetos já prontos (equipamentos, vulnerabilidades, resultados do
modelo de risco) e cuida de alinhamento, cores e números com vírgula.
"""

import textwrap

import cores
import formatacao
from arvore import QUEM_DEPENDE
from base_cve import nome_curto
from classificacoes import NivelGravidade
from formatacao import fracao_br, numero_br
from risco import LIMITE_AVISO_CONDICAO, LIMITE_CONDICAO

LARGURA_MENU = 62


def coluna(texto, largura, a_direita=False):
    """Encaixa o texto numa coluna de largura fixa.

    Texto longo é cortado e marcado com "..". Números vão à direita
    (a_direita=True), para as unidades ficarem alinhadas.
    """
    texto = str(texto)
    if len(texto) > largura:
        return texto[:largura - 2] + ".."
    if a_direita:
        return texto.rjust(largura)
    return texto.ljust(largura)


def linha_da_tabela(valores, larguras, a_direita):
    """Monta uma linha da tabela, com dois espaços entre as colunas."""
    celulas = [coluna(valor, largura, direita)
               for valor, largura, direita
               in zip(valores, larguras, a_direita, strict=True)]
    return "  " + "  ".join(celulas)


def imprimir_tabela(cabecalho, tetos, a_direita, linhas):
    """Imprime uma tabela: cabeçalho em negrito, traços e as linhas.

    Cada coluna tem a largura do maior valor, até o teto dela. Com
    todos os tetos, a linha mais larga das tabelas deste programa cabe
    nas 120 colunas do Windows Terminal. As linhas já vêm como tuplas de
    texto.
    """
    larguras = []
    for posicao, titulo in enumerate(cabecalho):
        maior = max([len(titulo)] + [len(linha[posicao]) for linha in linhas])
        larguras.append(min(maior, tetos[posicao]))

    # Pinta a linha já montada, para não afetar as larguras.
    titulos = linha_da_tabela(cabecalho, larguras, a_direita)
    print("\n" + cores.pintar(titulos, cores.NEGRITO))
    tracos = "-" * (sum(larguras) + 2 * (len(larguras) - 1))
    print("  " + cores.discreto(tracos))
    for linha in linhas:
        print(linha_da_tabela(linha, larguras, a_direita))


# ----------------------------------------------------------------------
# Equipamentos
# ----------------------------------------------------------------------

def mostrar_tabela(equipamentos):
    """Mostra equipamentos em tabela, uma linha por equipamento.

    Com todos os tetos, a linha mais larga tem 113 caracteres.
    """
    linhas = [(str(e.id), e.hostname, e.tipo.rotulo, e.custodiante,
               e.lotacao, str(len(e.vulnerabilidades)))
              for e in equipamentos]
    imprimir_tabela(
        ("ID", "HOSTNAME", "TIPO", "RESPONSÁVEL", "LOTAÇÃO", "VULNS"),
        (6, 24, 22, 24, 20, 5),
        (True, False, False, False, False, True), linhas)


def mostrar_equipamento(equipamento):
    """Mostra a ficha de um equipamento."""
    print(f"\n  ID ............ {equipamento.id}")
    print(f"  Hostname ...... {equipamento.hostname}")
    print(f"  Responsável ... {equipamento.custodiante}")
    print(f"  Lotação ....... {equipamento.lotacao}")
    print(f"  Tipo .......... {equipamento.tipo.rotulo} "
          + cores.discreto(f"(fator de exposição "
                           f"{numero_br(equipamento.fator_exposicao)})"))
    print(f"  Descrição ..... {equipamento.descricao}")
    for rotulo, valor in equipamento.ficha.preenchidos():
        print(f"  {rotulo} {'.' * (14 - len(rotulo))} {valor}")


# ----------------------------------------------------------------------
# Vulnerabilidades
# ----------------------------------------------------------------------

def imprimir_ocorrencias(itens, com_hostname=False):
    """Imprime vulnerabilidades em duas linhas cada, na ordem recebida.

    Cada item é (equipamento, vulnerabilidade, situação). Primeira
    linha: severidade e nota, id e descrição. Segunda: situação,
    origem e, se houver, a CVE e o CWE. Com com_hostname (relatório de
    pendentes), a segunda linha começa pelo hostname do equipamento. Se
    a nota veio de um vetor CVSS, ele aparece numa terceira linha.
    """
    # Largura do id tirada da própria lista, para alinhar [3] e [147].
    largura_id = max(len(f"[{v.id}]") for _, v, _ in itens)

    for equipamento, vuln, situacao in itens:
        marcador = f"[{vuln.id}]"
        partes = [cores.situacao(situacao.rotulo, situacao),
                  vuln.origem.rotulo]
        partes += [codigo for codigo in (vuln.cve, vuln.cwe)
                   if codigo is not None]
        legenda = " · ".join(partes)
        if com_hostname:
            legenda = f"{equipamento.hostname} · {legenda}"
        # Alinha a severidade antes de pintar, para a coluna não andar.
        nivel = vuln.gravidade
        severidade = cores.gravidade(
            f"{nivel.rotulo.upper():<7} {numero_br(vuln.cvss):>4}", nivel)
        recuo = f"    {'':<12} {'':<{largura_id}}"
        print(f"    {severidade} {marcador:<{largura_id}} {vuln.descricao}")
        print(f"{recuo} {legenda}")
        if vuln.vetor is not None:
            print(f"{recuo} {cores.discreto(vuln.vetor)}")
        print()


def mostrar_vulnerabilidades(pares):
    """Mostra as vulnerabilidades de um equipamento (requisito 8 do T1).

    pares são (vulnerabilidade, situação), da mais grave.
    """
    if not pares:
        print("\n  " + cores.aviso(
            "Este equipamento está sem vulnerabilidades registradas."))
        return
    print(f"\n  Vulnerabilidades ({len(pares)}), da mais grave:\n")
    imprimir_ocorrencias([(None, v, s) for v, s in pares])


def mostrar_vulnerabilidade_em_edicao(vuln, situacao, equipamento,
                                      afetados):
    """Mostra os dados atuais de uma vulnerabilidade, antes de editar.

    afetados são os equipamentos que a têm: com mais de um, avisa que
    descrição, CVE, CWE, categoria e nota mudam para todos.
    """
    print(f"\n  Descrição ..... {vuln.descricao}")
    print(f"  CVE ........... {vuln.cve or cores.discreto('nenhuma')}")
    print(f"  CWE ........... {vuln.cwe or cores.discreto('nenhum')}")
    print(f"  Categoria ..... {vuln.origem.rotulo}")
    print(f"  Nota CVSS ..... {numero_br(vuln.cvss)} "
          f"({vuln.gravidade.rotulo})")
    if vuln.vetor is not None:
        print(f"  Vetor CVSS .... {vuln.vetor}")
    print(f"  Status ........ {cores.situacao(situacao.rotulo, situacao)}"
          f" (em {equipamento.hostname})")
    if len(afetados) > 1:
        print("\n  " + cores.aviso(
            f"Descrição, CVE, CWE, categoria e nota valem para os "
            f"{len(afetados)} equipamentos que têm esta vulnerabilidade "
            f"({', '.join(e.hostname for e in afetados)}). O status vale "
            f"só para {equipamento.hostname}."))


def mostrar_catalogo(inventario):
    """Mostra o catálogo de vulnerabilidades, uma linha por entrada.

    Com todos os tetos, a linha mais larga tem 120 caracteres.
    """
    linhas = []
    for v in inventario.vulnerabilidades():
        linhas.append((str(v.id), numero_br(v.cvss), v.gravidade.rotulo,
                       v.origem.rotulo,
                       str(len(inventario.afetados_por(v.id))),
                       v.cve or "-", v.descricao))
    imprimir_tabela(
        ("ID", "CVSS", "SEVERIDADE", "ORIGEM", "EQUIP.", "CVE", "DESCRIÇÃO"),
        (5, 4, 10, 30, 6, 16, 35),
        (True, True, False, False, True, False, False), linhas)


def resumo_por_severidade(itens):
    """Monta a linha "Crítica 6 · Alta 21 · ..." com a contagem.

    Só aparecem as severidades presentes. Cada item é (equipamento,
    vulnerabilidade, situação), como em imprimir_ocorrencias.
    """
    contagem = {}
    for _, vuln, _ in itens:
        contagem[vuln.gravidade] = contagem.get(vuln.gravidade, 0) + 1

    mais_grave_primeiro = sorted(contagem, key=lambda nivel: nivel.value,
                                 reverse=True)
    partes = [cores.gravidade(f"{nivel.rotulo} {contagem[nivel]}", nivel)
              for nivel in mais_grave_primeiro]
    return " · ".join(partes)


# ----------------------------------------------------------------------
# Base de CVEs exploradas (opção 16)
# ----------------------------------------------------------------------

def resumo_da_base_cve(base):
    """Uma linha sobre a base: o catálogo, as CVEs e de onde veio."""
    quando = formatacao.data_br(base.publicado) if base.publicado else "?"
    if base.origem == "atualizada":
        de_onde = f"atualizada em {formatacao.data_br(base.montado_em)}"
    else:
        de_onde = "a que vem com o programa"
    total = formatacao.inteiro_br(len(base))
    com_nota = formatacao.inteiro_br(base.com_nota())
    return (f"Catálogo KEV da CISA de {quando}: {total} CVEs exploradas, "
            f"{com_nota} com nota CVSS ({de_onde}).")


def mostrar_registros_cve(registros, inicio, marcadas=()):
    """Mostra uma página de CVEs da base, numeradas de inicio + 1.

    marcadas são as CVEs que o equipamento já tem: o número delas leva
    um *. A coluna FALHA é o nome sem o fabricante e o produto, que já
    têm colunas próprias.
    """
    linhas = []
    for numero, registro in enumerate(registros, inicio + 1):
        marca = "*" if registro.cve in marcadas else ""
        nota = "-" if registro.cvss is None else numero_br(registro.cvss)
        linhas.append((f"{numero}{marca}", registro.cve, nota,
                       registro.fabricante, registro.produto,
                       nome_curto(registro)))
    imprimir_tabela(("#", "CVE", "NOTA", "FABRICANTE", "PRODUTO", "FALHA"),
                    (5, 16, 4, 14, 24, 34),
                    (True, False, True, False, False, False), linhas)
    if any(registro.cve in marcadas for registro in registros):
        print("  " + cores.discreto("* já registrada neste equipamento"))


def mostrar_registro_cve(registro):
    """Mostra uma CVE da base com tudo o que ela tem."""
    print(f"\n  {cores.titulo(registro.cve)} - {registro.nome}")
    print(f"  Fabricante .... {registro.fabricante}")
    print(f"  Produto ....... {registro.produto}")
    if registro.cvss is None:
        print(f"  Nota CVSS ..... "
              f"{cores.discreto('sem nota no registro oficial')}")
    else:
        nivel = NivelGravidade.do_cvss(registro.cvss)
        nota = f"{numero_br(registro.cvss)} ({nivel.rotulo})"
        # O CNA é quem publicou a CVE (em geral, o fabricante); um ADP,
        # como o da CISA, completa o registro de outro.
        fonte = ("pelo CNA, quem publicou a CVE"
                 if registro.fonte_nota == "CNA"
                 else f"por {registro.fonte_nota}")
        print(f"  Nota CVSS ..... {cores.gravidade(nota, nivel)}"
              + cores.discreto(f" (dada {fonte})"))
        print(f"  Vetor CVSS .... {registro.vetor}")
    cwes = ", ".join(registro.cwes) or cores.discreto("não informado")
    print(f"  CWE ........... {cwes}")
    print(f"  No catálogo ... desde "
          f"{formatacao.data_br(registro.adicionada)}")
    if registro.ransomware:
        print("  " + cores.aviso("Usada em campanhas de ransomware, segundo "
                                 "a CISA."))
    print()
    _paragrafo(registro.descricao, "  ", LARGURA_EXPLICACAO + 4)
    print("  " + cores.discreto("(Descrição em inglês, como no catálogo "
                                "oficial.)"))


def mostrar_nomes_numerados(itens, inicio):
    """Mostra [(nome, quantas CVEs)] numerados de inicio + 1."""
    largura = len(str(inicio + len(itens)))
    for numero, (nome, quantas) in enumerate(itens, inicio + 1):
        print(f"    {cores.destaque(str(numero).rjust(largura))} - {nome} "
              f"({quantas})")


# ----------------------------------------------------------------------
# Dependências
# ----------------------------------------------------------------------

def mostrar_dependencias(inventario, equipamento, quem_depende,
                         do_que_depende):
    """Mostra as árvores de dependência do equipamento (opção 12).

    quem_depende e do_que_depende são as Arvore montadas por
    arvore.montar(). Por último vêm as dependências diretas, com a soma
    das frações: é delas que a opção 12 remove uma, logo abaixo.
    """
    print()
    _paragrafo("Cada equipamento aparece uma vez, sob a ligação mais "
               "específica; as outras ligações dele vêm na linha "
               "\"também\". \"Herda 0,2\": herda 20% do risco efetivo do "
               "equipamento de cima. \"Repassa 0,2\": o de cima herda 20% "
               "do risco efetivo deste.", "  ", LARGURA_EXPLICACAO + 4,
               cores.discreto)
    mostrar_arvore(quem_depende)
    mostrar_arvore(do_que_depende)
    if not equipamento.dependencias:
        return
    print(f"\n  {cores.titulo('Dependências diretas')} "
          f"(linha {equipamento.hostname} da matriz A):")
    # Largura do id tirada da própria lista, para alinhar [3] e [31].
    largura_id = max(len(f"[{d}]") for d in equipamento.dependencias)
    for destino, fracao in sorted(equipamento.dependencias.items()):
        alvo = inventario.buscar_por_id(destino)
        ciclo = (cores.aviso(" (ciclo)")
                 if equipamento.id in alvo.dependencias else "")
        print(f"    {f'[{destino}]':<{largura_id}} {alvo.hostname:<24} "
              f"fração {fracao_br(fracao)}{ciclo}")
    soma = equipamento.soma_dependencias
    sobra = round(1 - soma, 9)
    print("    " + cores.discreto(
        f"soma {fracao_br(soma)} (precisa ficar abaixo de 1; "
        f"sobra menos que {fracao_br(sobra)})"))


# Largura das árvores: cabe no terminal de 80 colunas. Num ramo muito
# fundo, o texto ainda ganha ao menos LARGURA_MINIMA_ARVORE colunas.
LARGURA_ARVORE = 80
LARGURA_MINIMA_ARVORE = 30

# Traços da árvore, com 3 colunas cada, como os do comando tree: ramo,
# último ramo, linha que continua e espaço.
RAMO, ULTIMO_RAMO, CONTINUA, ESPACO = "├─ ", "└─ ", "│  ", "   "


def _juntar(partes):
    """Junta textos como numa frase: "a", "a e b", "a, b e c"."""
    if len(partes) <= 1:
        return "".join(partes)
    return ", ".join(partes[:-1]) + " e " + partes[-1]


# Espaço que não quebra linha: junta as palavras de uma ligação ("0,1 de
# [4] DRPC-SW01") para a quebra cair só entre uma ligação e outra. Vira
# espaço comum antes de imprimir.
_JUNTO = "\u00a0"


def _quebrar(texto, largura):
    """Quebra o texto em linhas, sem partir hostnames nem ligações."""
    return [linha.replace(_JUNTO, " ")
            for linha in textwrap.wrap(texto, largura,
                                       break_on_hyphens=False,
                                       break_long_words=False)]


def _ligacoes(ligacoes, preposicao):
    """'0,1 de [1] SRV01 (ciclo) e 0,1 de [4] SW01', para a linha."""
    return _juntar([_JUNTO.join([fracao_br(lig.fracao), preposicao,
                                 f"[{lig.equipamento.id}]",
                                 lig.equipamento.hostname]
                                + (["(ciclo)"] if lig.ciclo else []))
                    for lig in ligacoes])


def _nota_de_fora(item, desce):
    """O aviso dos vizinhos de baixo que estão em outros ramos."""
    n = item.fora
    if desce:
        if n == 1:
            texto = ("outro dependente direto aparece" if item.filhos
                     else "o dependente direto dele aparece")
            return texto + " em outro ramo"
        texto = (f"outros {n} dependentes diretos aparecem" if item.filhos
                 else f"os {n} dependentes diretos dele aparecem")
        return texto + " em outros ramos"
    if n == 1:
        texto = ("outra dependência direta aparece" if item.filhos
                 else "a dependência direta dele aparece")
        return texto + " em outro ramo"
    texto = (f"outras {n} dependências diretas aparecem" if item.filhos
             else f"as {n} dependências diretas dele aparecem")
    return texto + " em outros ramos"


def _textos_do_item(item, desce):
    """A linha principal do item e os textos de apoio, ainda sem quebra.

    Devolve (principal, também, nomes, nota); os três últimos ficam
    vazios quando não se aplicam.
    """
    fracao = fracao_br(item.fracao)
    if len(item.equipamentos) == 1:
        equipamento = item.equipamentos[0]
        verbo = "herda" if desce else "repassa"
        principal = (f"[{equipamento.id}] {equipamento.hostname}  "
                     f"{verbo} {fracao}")
        nomes = ""
    else:
        verbo = "herdam" if desce else "repassam"
        principal = (f"{len(item.equipamentos)} equipamentos {verbo} "
                     f"{fracao}")
        nomes = ", ".join(f"[{e.id}]{_JUNTO}{e.hostname}"
                          for e in item.equipamentos)
    tambem = ""
    if item.outras:
        tambem = (f"também {verbo} "
                  + _ligacoes(item.outras, "de" if desce else "a"))
    nota = _nota_de_fora(item, desce) if item.fora else ""
    return principal, tambem, nomes, nota


def _pintar_tambem(linha):
    """Linha de apoio apagada, com o "(ciclo)" em destaque."""
    return cores.aviso("(ciclo)").join(
        cores.discreto(parte) if parte else ""
        for parte in linha.split("(ciclo)"))


def _imprimir_item(item, prefixo, ultimo, desce):
    """Imprime um item da árvore: a linha dele e as de apoio, embaixo.

    As linhas de apoio (as outras ligações, os nomes de um grupo e a
    nota dos outros ramos) ficam alinhadas ao texto do item. Se o item
    tem filhos, a linha que desce até eles aparece também nelas.
    """
    principal, tambem, nomes, nota = _textos_do_item(item, desce)
    ciclo = cores.aviso(" (ciclo)") if item.ciclo else ""
    print(f"{prefixo}{ULTIMO_RAMO if ultimo else RAMO}{principal}{ciclo}")
    recuo = (prefixo + (ESPACO if ultimo else CONTINUA)
             + (CONTINUA if item.filhos else ESPACO))
    largura = max(LARGURA_MINIMA_ARVORE, LARGURA_ARVORE - len(recuo))
    for linha in _quebrar(tambem, largura):
        print(recuo + _pintar_tambem(linha))
    for linha in _quebrar(nomes, largura):
        print(recuo + linha)
    if nota:
        print(recuo + cores.discreto(nota))


def mostrar_arvore(arvore):
    """Imprime uma árvore de dependências (arvore.Arvore).

    Os itens são visitados com uma pilha, e não por recursão: uma cadeia
    longa de dependências não estoura a pilha do Python.
    """
    desce = arvore.sentido == QUEM_DEPENDE
    raiz = arvore.raiz
    titulo = (f"Quem depende de {raiz.hostname}" if desce
              else f"Do que {raiz.hostname} depende")
    quantos = (f"{arvore.total} equipamento{'s' if arvore.total > 1 else ''}"
               f", contando os indiretos")
    if not arvore.itens:
        print(f"\n  {cores.titulo(titulo)}")
        print("    " + cores.discreto(
            "ninguém depende dele" if desce
            else "não depende de nenhum equipamento"))
        return
    print(f"\n  {cores.titulo(titulo)} " + cores.discreto(f"({quantos})"))
    print(f"  [{raiz.id}] {raiz.hostname}")
    pilha = [(item, "  ", posicao == len(arvore.itens) - 1)
             for posicao, item in enumerate(arvore.itens)]
    pilha.reverse()
    while pilha:
        item, prefixo, ultimo = pilha.pop()
        _imprimir_item(item, prefixo, ultimo, desce)
        continua = prefixo + (ESPACO if ultimo else CONTINUA)
        for posicao in range(len(item.filhos) - 1, -1, -1):
            pilha.append((item.filhos[posicao], continua,
                          posicao == len(item.filhos) - 1))


# ----------------------------------------------------------------------
# Risco
# ----------------------------------------------------------------------

def mostrar_diagnostico(diagnostico):
    """Mostra o resultado da verificação de I - A.

    O determinante, o número de condição e o posto aparecem sempre,
    para conferência. Quem decide é a regra explicada no motivo: o
    determinante sozinho não serve (veja risco.py).
    """
    if diagnostico.utilizavel:
        print("\n  " + cores.sucesso("Verificação de I - A: ")
              + diagnostico.motivo)
    else:
        print("\n  " + cores.erro("! Verificação de I - A: ")
              + cores.erro(diagnostico.motivo))
    if diagnostico.aviso:
        print("  " + cores.aviso(diagnostico.aviso))
    compacto = formatacao.numero_compacto
    print("  " + cores.discreto(
        f"det(I - A) = {compacto(diagnostico.determinante)}"
        f" · número de condição de I - A = "
        f"{compacto(diagnostico.condicao)} (aviso acima de "
        f"{compacto(LIMITE_AVISO_CONDICAO)}; recusa acima de 1/épsilon = "
        f"{compacto(LIMITE_CONDICAO)})"))
    if diagnostico.ordem:
        if diagnostico.posto == diagnostico.ordem:
            sobre = "posto cheio, então o sistema é possível e determinado"
        else:
            sobre = (f"menor que {diagnostico.ordem}, então I - A não tem "
                     f"inversa")
        print("  " + cores.discreto(
            f"posto de I - A = {diagnostico.posto} (de "
            f"{diagnostico.ordem}): {sobre}"))


def mostrar_dimensoes(modelo):
    """Mostra o tamanho das matrizes e o posto de M (opção 15).

    Teorema do núcleo e da imagem: o posto de M mais a dimensão do
    núcleo dá o número de colunas (vulnerabilidades).
    """
    n, m = modelo.M.shape
    print(f"\n  {n} equipamento(s) e {m} vulnerabilidade(s): M é "
          f"{n} x {m}, v tem {m} valor(es) e A é {n} x {n}.")
    if not m:
        return
    posto, nulas = modelo.posto_e_colunas_nulas()
    colunas = "coluna" if m == 1 else "colunas"
    print(f"  Posto de M: {posto}; núcleo de M: dimensão {m - posto} "
          f"({posto} + {m - posto} = {m} {colunas}).")
    if nulas == 1:
        _paragrafo("1 coluna de M é nula: uma vulnerabilidade corrigida "
                   "em todos os equipamentos em que aparece, que por isso "
                   "não muda o risco.", "  ", LARGURA_EXPLICACAO + 4)
    elif nulas:
        _paragrafo(f"{nulas} colunas de M são nulas: vulnerabilidades "
                   f"corrigidas em todos os equipamentos em que aparecem, "
                   f"que por isso não mudam o risco.", "  ",
                   LARGURA_EXPLICACAO + 4)


# A barra usa o meio bloco de baixo (▄), e não o bloco cheio (█). O
# bloco cheio ocupa a célula inteira do terminal, e a barra de uma
# linha encostava na da linha seguinte: na tabela, que vem do maior
# risco para o menor, as barras viravam uma escada só. O meio bloco
# deixa vazia a metade de cima da célula e existe nas mesmas fontes do
# console do Windows (Consolas, Lucida Console) que o bloco cheio.
BLOCO_DA_BARRA = "▄"


def barra(valor, maximo, largura=20):
    """Barra horizontal proporcional ao valor, de 0 a largura blocos."""
    if maximo <= 0:
        return ""
    return BLOCO_DA_BARRA * max(1 if valor > 0 else 0,
                                round(largura * valor / maximo))


def mostrar_relatorio_risco(itens, residuo):
    """Mostra o risco próprio e o efetivo de todos os equipamentos.

    itens são RiscoEquipamento, já na ordem a mostrar. A barra mostra o
    risco efetivo em proporção ao maior. Embaixo vêm a legenda das
    colunas e o resíduo ||(I - A) x - b|| da solução.
    """
    maximo = max((i.efetivo for i in itens), default=0.0)
    linhas = []
    for i in itens:
        linhas.append((str(i.equipamento.id), i.equipamento.hostname,
                       i.equipamento.tipo.rotulo, numero_br(i.soma_cvss),
                       numero_br(i.fator), numero_br(i.proprio, 2),
                       numero_br(i.efetivo, 2),
                       barra(i.efetivo, maximo)))
    imprimir_tabela(
        ("ID", "HOSTNAME", "TIPO", "SOMA CVSS", "FATOR", "PRÓPRIO",
         "EFETIVO", ""),
        (5, 22, 20, 9, 5, 9, 9, 20),
        (True, False, False, True, True, True, True, False), linhas)
    print("\n  " + cores.discreto(
        "SOMA CVSS = M v (só vulnerabilidades não corrigidas) · "
        "PRÓPRIO = fator x soma"))
    print("  " + cores.discreto(
        "EFETIVO = próprio + risco herdado, da solução de "
        "(I - A) x = b"))
    print("  " + cores.discreto(
        f"Erro numérico da solução: ||(I - A) x - b|| = "
        f"{residuo:.1e}".replace(".", ",")))
    print("  Para ver como um deles foi calculado, use a opção 14.")


def mostrar_detalhe_risco(item, vulnerabilidades, parcelas):
    """Mostra como o risco de um equipamento foi calculado.

    item é o RiscoEquipamento; vulnerabilidades, os pares
    (vulnerabilidade, situação) dele; parcelas, o que devolve
    ModeloRisco.contribuicoes().
    """
    e = item.equipamento
    print(f"\n  {cores.titulo(str(e))}")

    print(f"\n  {cores.titulo('Risco próprio')}  b = fator x (M v)")
    if not vulnerabilidades:
        print("    " + cores.discreto("sem vulnerabilidades registradas"))
    for vuln, situacao in vulnerabilidades:
        nota = cores.gravidade(f"{numero_br(vuln.cvss):>4}", vuln.gravidade)
        marca = "" if situacao.conta_no_risco else cores.discreto(
            "  <- corrigida: não conta")
        print(f"    CVSS {nota}  [{vuln.id}] {vuln.descricao} "
              f"({situacao.rotulo}){marca}")
    print(f"    soma das notas que contam (M v) ... "
          f"{numero_br(item.soma_cvss)}")
    print(f"    fator de exposição ({e.tipo.rotulo}) "
          f"... {numero_br(item.fator)}")
    print(f"    risco próprio b = {numero_br(item.fator)} x "
          f"{numero_br(item.soma_cvss)} = "
          f"{cores.destaque(numero_br(item.proprio, 2))}")

    print(f"\n  {cores.titulo('Risco herdado')}  A x  "
          f"(fração x risco efetivo de quem se depende)")
    if not parcelas:
        print("    " + cores.discreto("não depende de nenhum equipamento"))
    herdado = 0.0
    for outro, fracao, efetivo, parcela in parcelas:
        herdado += parcela
        print(f"    {fracao_br(fracao):>6} x {numero_br(efetivo, 2):>8}  "
              f"([{outro.id}] {outro.hostname})  =  "
              f"{numero_br(parcela, 2):>8}")
    if parcelas:
        print(f"    total herdado ............... "
              f"{numero_br(herdado, 2)}")

    print(f"\n  Risco efetivo  x = b + A x = {numero_br(item.proprio, 2)} + "
          f"{numero_br(herdado, 2)} = "
          f"{cores.destaque(numero_br(item.efetivo, 2))}")


# ----------------------------------------------------------------------
# Calculadora CVSS: a nota respondendo às perguntas
# ----------------------------------------------------------------------

# Largura das explicações: com o recuo das opções, cabe em 80 colunas.
LARGURA_EXPLICACAO = 70


def _paragrafo(texto, recuo, largura=LARGURA_EXPLICACAO, pintar=None):
    """Imprime o texto quebrado em linhas, todas com o mesmo recuo.

    pintar, se dado, é a função de cores.py aplicada a cada linha (a
    quebra é feita antes, sobre o texto puro).
    """
    for linha in textwrap.wrap(texto, largura):
        print(f"{recuo}{pintar(linha) if pintar else linha}")


def mostrar_inicio_calculadora_cvss():
    """Explica a calculadora e mostra as versões do CVSS."""
    print("\n" + cores.titulo("--- CALCULAR A NOTA CVSS ---") + "\n")
    _paragrafo("Responda sobre a falha, e não sobre o equipamento: o CVSS "
               "mede o quanto a vulnerabilidade é grave em si. O contexto "
               "(o tipo do equipamento e as dependências) entra depois, "
               "no modelo de risco. As perguntas seguem as métricas da "
               "calculadora oficial do FIRST, explicadas em português.",
               "  ", LARGURA_EXPLICACAO + 4)
    print()
    _paragrafo("Em cada pergunta, digite o número da opção (ou a letra "
               "entre parênteses). \"anterior\" volta uma pergunta, "
               "\"cancelar\" desiste do cálculo e \"voltar\" abandona o "
               "cadastro desta vulnerabilidade.", "  ",
               LARGURA_EXPLICACAO + 4)
    print("\n  Versão do CVSS:")
    print(f"    {cores.destaque('1')} - 4.0, a versão atual (recomendada)")
    print(f"    {cores.destaque('2')} - 3.1, a anterior, ainda usada em "
          f"muitas notas publicadas")


def mostrar_pergunta_cvss(numero, total, metrica):
    """Mostra uma pergunta do CVSS e o que cada opção quer dizer."""
    titulo = f"[{numero}/{total}] {metrica.nome} ({metrica.codigo})"
    print(f"\n  {cores.titulo(titulo)}")
    _paragrafo(metrica.pergunta, "  ", LARGURA_EXPLICACAO + 4)
    print()
    for indice, opcao in enumerate(metrica.opcoes, start=1):
        print(f"    {cores.destaque(str(indice))} - {opcao.nome} "
              f"({opcao.codigo})")
        _paragrafo(opcao.explicacao, "        ")


def mostrar_resultado_cvss(vetor, nota):
    """Mostra o vetor montado com as respostas e a nota que ele dá."""
    nivel = NivelGravidade.do_cvss(nota)
    print(f"\n  Vetor: {cores.destaque(vetor)}")
    print("  Nota:  " + cores.gravidade(
        f"{numero_br(nota)} ({nivel.rotulo})", nivel))


def mostrar_matrizes(modelo):
    """Mostra M, v, M v, F, b e A, para conferir a conta à mão.

    Só para poucos equipamentos: com dezenas, a matriz não cabe na tela.
    """
    ids = [e.id for e in modelo.equipamentos]
    print("\n  M (linhas: equipamentos; colunas: vulnerabilidades):")
    cabecalho = "        " + " ".join(
        f"V{v.id:<3}" for v in modelo.vulnerabilidades)
    print(cores.discreto(cabecalho))
    for i, equipamento in enumerate(modelo.equipamentos):
        valores = " ".join(f"{int(x):<4}" for x in modelo.M[i])
        print(f"    E{equipamento.id:<3}{valores}")
    print("\n  v (notas CVSS): " + "  ".join(
        f"V{v.id}={numero_br(v.cvss)}" for v in modelo.vulnerabilidades))

    # M leva v (uma nota por vulnerabilidade) a M v (uma soma por
    # equipamento): é a transformação linear do modelo. F é diagonal
    # (só a diagonal aparece): multiplica cada linha pelo fator do tipo.
    equipamentos = modelo.equipamentos

    def por_equipamento(valores, casas):
        return "  ".join(f"E{e.id}={numero_br(valor, casas)}"
                         for e, valor in zip(equipamentos, valores,
                                             strict=True))

    print("\n  M v (soma das notas de cada equipamento):  "
          + por_equipamento(modelo.soma_cvss, 1))
    print("  F (fator de exposição do tipo):            "
          + por_equipamento(modelo.fatores, 1))
    print("  b = F (M v) (risco próprio):               "
          + por_equipamento(modelo.b, 2))
    print("\n  A (linha i: fração herdada de cada equipamento j):")
    print(cores.discreto("        " + " ".join(f"E{j:<5}" for j in ids)))
    for i, equipamento in enumerate(modelo.equipamentos):
        valores = " ".join(f"{formatacao.fracao_br(x):<6}"
                           for x in modelo.A[i])
        print(f"    E{equipamento.id:<3}{valores}")
