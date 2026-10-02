"""Exibição: tabelas, fichas e relatórios, tudo impresso na tela.

Só imprime: não lê do teclado e não altera nenhum dado. Recebe os
objetos já prontos (equipamentos, vulnerabilidades, resultados do
modelo de risco) e cuida de alinhamento, cores e números com vírgula.
"""

import cores
import formatacao
from formatacao import fracao_br, numero_br

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
               in zip(valores, larguras, a_direita)]
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


# ----------------------------------------------------------------------
# Vulnerabilidades
# ----------------------------------------------------------------------

def imprimir_ocorrencias(itens, com_hostname=False):
    """Imprime vulnerabilidades em duas linhas cada, na ordem recebida.

    Cada item é (equipamento, vulnerabilidade, situação). Primeira
    linha: severidade e nota, id e descrição. Segunda: situação e
    origem. Com com_hostname (relatório de pendentes), a segunda linha
    começa pelo hostname do equipamento.
    """
    # Largura do id tirada da própria lista, para alinhar [3] e [147].
    largura_id = max(len(f"[{v.id}]") for _, v, _ in itens)

    for equipamento, vuln, situacao in itens:
        marcador = f"[{vuln.id}]"
        legenda = (f"{cores.situacao(situacao.rotulo, situacao)} · "
                   f"{vuln.origem.rotulo}")
        if com_hostname:
            legenda = f"{equipamento.hostname} · {legenda}"
        # Alinha a severidade antes de pintar, para a coluna não andar.
        nivel = vuln.gravidade
        severidade = cores.gravidade(
            f"{nivel.rotulo.upper():<7} {numero_br(vuln.cvss):>4}", nivel)
        print(f"    {severidade} {marcador:<{largura_id}} {vuln.descricao}")
        print(f"    {'':<12} {'':<{largura_id}} {legenda}\n")


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


def mostrar_catalogo(inventario):
    """Mostra o catálogo de vulnerabilidades, uma linha por entrada."""
    linhas = []
    for v in inventario.vulnerabilidades():
        linhas.append((str(v.id), numero_br(v.cvss), v.gravidade.rotulo,
                       v.origem.rotulo,
                       str(len(inventario.afetados_por(v.id))),
                       v.descricao))
    imprimir_tabela(
        ("ID", "CVSS", "SEVERIDADE", "ORIGEM", "EQUIP.", "DESCRIÇÃO"),
        (5, 4, 10, 30, 6, 52),
        (True, True, False, False, True, False), linhas)


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
# Dependências
# ----------------------------------------------------------------------

def mostrar_dependencias(inventario, equipamento):
    """Mostra de quem o equipamento depende e quem depende dele."""
    print(f"\n  {cores.titulo('Depende de')} "
          f"(herda parte do risco destes; linha {equipamento.hostname} "
          f"na matriz A):")
    if equipamento.dependencias:
        for destino, fracao in sorted(equipamento.dependencias.items()):
            alvo = inventario.buscar_por_id(destino)
            print(f"    [{destino}] {alvo.hostname:<24} "
                  f"fração {fracao_br(fracao)}")
        soma = equipamento.soma_dependencias
        sobra = round(1 - soma, 9)
        print("    " + cores.discreto(
            f"soma {fracao_br(soma)} (precisa ficar abaixo de 1; "
            f"sobra menos que {fracao_br(sobra)})"))
    else:
        print("    " + cores.discreto("nenhuma"))

    print(f"\n  {cores.titulo('Dependem dele')} "
          f"(herdam parte do risco deste):")
    dependentes = inventario.dependentes_de(equipamento.id)
    if dependentes:
        for outro, fracao in dependentes:
            print(f"    [{outro.id}] {outro.hostname:<24} "
                  f"fração {fracao_br(fracao)}")
    else:
        print("    " + cores.discreto("nenhum"))


# ----------------------------------------------------------------------
# Risco
# ----------------------------------------------------------------------

def mostrar_diagnostico(diagnostico):
    """Mostra o resultado da verificação de I - A.

    O determinante e o número de condição aparecem sempre, para
    conferência. Quem decide é a regra explicada no motivo: o
    determinante sozinho não serve (veja risco.py).
    """
    if diagnostico.utilizavel:
        print("\n  " + cores.sucesso("Verificação de I - A: ")
              + diagnostico.motivo)
    else:
        print("\n  " + cores.erro("! Verificação de I - A: ")
              + cores.erro(diagnostico.motivo))
    print("  " + cores.discreto(
        f"det(I - A) = {formatacao.numero_compacto(diagnostico.determinante)}"
        f" · número de condição de I - A = "
        f"{formatacao.numero_compacto(diagnostico.condicao)}"))


def barra(valor, maximo, largura=20):
    """Barra horizontal proporcional ao valor, de 0 a largura blocos."""
    if maximo <= 0:
        return ""
    return "█" * max(1 if valor > 0 else 0,
                     round(largura * valor / maximo))


def mostrar_relatorio_risco(itens):
    """Mostra o risco próprio e o efetivo de todos os equipamentos.

    itens são RiscoEquipamento, já na ordem a mostrar. A barra mostra o
    risco efetivo em proporção ao maior.
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


def mostrar_detalhe_risco(item, vulnerabilidades, parcelas):
    """Mostra como o risco de um equipamento foi calculado.

    item é o RiscoEquipamento; vulnerabilidades, os pares (vulnerabilidade,
    situação) dele; parcelas, o que devolve ModeloRisco.contribuicoes().
    """
    e = item.equipamento
    print(f"\n  {cores.titulo(e.hostname)} - {e.tipo.rotulo}")

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


def mostrar_matrizes(modelo):
    """Mostra M, v, M v, F, b e A de um cenário pequeno, para conferir à mão.

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
    # equipamento): é a transformação linear do modelo. F é a diagonal de
    # uma matriz diagonal: multiplica cada linha pelo fator do tipo.
    equipamentos = modelo.equipamentos

    def por_equipamento(valores, casas):
        return "  ".join(f"E{e.id}={numero_br(valor, casas)}"
                         for e, valor in zip(equipamentos, valores))

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
