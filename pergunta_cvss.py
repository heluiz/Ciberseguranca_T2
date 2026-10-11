"""A pergunta da nota CVSS: o número, o vetor ou "calcular".

No cadastro (opções 1 e 6) e na atualização (opção 8) de uma
vulnerabilidade, a nota pode vir de três jeitos: digitada (7,5), pelo
vetor colado da calculadora do FIRST ou respondendo às perguntas do
CVSS, uma a uma ("calcular"). As perguntas e a conta ficam em
calculadora_cvss.py; aqui fica só a conversa com o usuário.
"""

import functools

import calculadora_cvss
import cores
import telas
from entrada import (
    confirmar,
    converter_decimal,
    ler_convertido,
    ler_resposta,
)
from formatacao import numero_br
from vulnerabilidades import CVSS_MINIMO, validar_cvss

# Na pergunta da nota CVSS, esta palavra abre as perguntas do CVSS.
PALAVRA_CALCULAR = "calcular"
# Nas perguntas do CVSS: volta uma pergunta / desiste do cálculo.
ANTERIOR = "anterior"
CANCELAR = "cancelar"
# Respostas aceitas na escolha da versão do CVSS (Enter: a 4.0).
VERSAO_DIGITADA = {"": "4.0", "1": "4.0", "4": "4.0", "4.0": "4.0",
                   "2": "3.1", "3": "3.1", "3.1": "3.1"}

# Mostrado antes da pergunta da nota, no cadastro da vulnerabilidade.
EXPLICACAO_NOTA = (
    "  Nota CVSS: digite a nota (0,1 a 10,0), cole o vetor da calculadora "
    "do\n  FIRST (CVSS:4.0/..., CVSS:3.1/... ou CVSS:3.0/...) ou digite\n"
    f"  \"{PALAVRA_CALCULAR}\" para chegar à nota respondendo às perguntas "
    "do CVSS,\n  com a explicação de cada uma.")


def ler_nota_cvss(mensagem, opcional=False):
    """Lê a nota CVSS: o número, o vetor ou "calcular".

    Devolve (nota, vetor), com vetor None quando a nota foi
    digitada, ou None quando opcional e o usuário tecla Enter.
    Repete a pergunta até vir uma resposta válida; desistir do
    "calcular" também a repete (_interpretar_nota devolve None).
    """
    return ler_convertido(mensagem, _interpretar_nota, opcional)


def _interpretar_nota(bruto):
    """Transforma a resposta em (nota, vetor); None se desistiu.

    Levanta ValueError, com o motivo, se a resposta não servir.
    """
    if bruto.casefold() == PALAVRA_CALCULAR:
        return _calcular_cvss()
    # ":" sem "CVSS:" é um vetor sem o começo: o motivo vem de lá.
    if bruto.upper().startswith("CVSS:") or ":" in bruto:
        vetor, nota = calculadora_cvss.analisar_vetor(bruto)
        _exigir_nota_com_impacto(nota)
        print("  " + cores.sucesso(
            f"Nota calculada pelo vetor: {numero_br(nota)}."))
        return nota, vetor
    try:
        numero = converter_decimal(bruto)
    except ValueError:
        raise ValueError(
            f"Digite a nota, como 7,5, cole o vetor CVSS ou digite "
            f"\"{PALAVRA_CALCULAR}\"") from None
    return validar_cvss(numero), None


def _exigir_nota_com_impacto(nota):
    """Recusa a nota 0,0, que o CVSS chama de "Nenhuma"."""
    if nota < CVSS_MINIMO:
        raise ValueError(
            f"O vetor dá nota {numero_br(nota)} (\"Nenhuma\" no CVSS): "
            f"a falha não tem impacto e não entra no inventário")


def _calcular_cvss():
    """Faz as perguntas do CVSS e devolve (nota, vetor), ou None.

    Cada pergunta mostra o que cada opção quer dizer. "anterior"
    volta uma pergunta e "cancelar" desiste do cálculo (None). No
    fim, mostra o vetor e a nota e pede confirmação.
    """
    telas.mostrar_inicio_calculadora_cvss()
    versao = _ler_versao_cvss()
    if versao is None:
        print("  " + cores.aviso("Cálculo cancelado."))
        return None
    metricas = calculadora_cvss.VERSOES[versao]
    escolhas = {}
    posicao = 0
    while posicao < len(metricas):
        metrica = metricas[posicao]
        redesenhar = functools.partial(
            telas.mostrar_pergunta_cvss, posicao + 1, len(metricas),
            metrica)
        redesenhar()
        resposta = _ler_opcao_cvss(metrica, redesenhar)
        if resposta == CANCELAR:
            print("  " + cores.aviso("Cálculo cancelado."))
            return None
        if resposta == ANTERIOR:
            posicao = max(posicao - 1, 0)
            continue
        escolhas[metrica.codigo] = resposta
        posicao += 1
    return _confirmar_nota_calculada(versao, escolhas)


def _ler_versao_cvss():
    """Lê a versão do CVSS: 1 (ou Enter) é a 4.0; 2, a 3.1.

    Devolve None se o usuário digitar "cancelar".
    """
    while True:
        bruto = ler_resposta("  Versão [1]: ").replace(",", ".")
        if bruto.casefold() == CANCELAR:
            return None
        versao = VERSAO_DIGITADA.get(bruto)
        if versao is not None:
            return versao
        print("  " + cores.erro(
            f"! Digite 1 (versão 4.0) ou 2 (versão 3.1), ou "
            f"\"{CANCELAR}\"."))


def _ler_opcao_cvss(metrica, redesenhar):
    """Lê a resposta de uma pergunta do CVSS.

    Aceita o número da opção ou a letra do vetor (N, L...) e devolve
    o código da opção, como "N"; "anterior" e "cancelar" voltam como
    estão. "limpar" redesenha a pergunta.
    """
    codigos = [opcao.codigo for opcao in metrica.opcoes]
    while True:
        bruto = ler_resposta("  Opção: ", depois_de_limpar=redesenhar)
        if bruto.casefold() in (ANTERIOR, CANCELAR):
            return bruto.casefold()
        if bruto.isdecimal() and 1 <= int(bruto) <= len(codigos):
            return codigos[int(bruto) - 1]
        if bruto.upper() in codigos:
            return bruto.upper()
        print("  " + cores.erro(
            f"! Digite um número de 1 a {len(codigos)} (ou a letra "
            f"entre parênteses), \"{ANTERIOR}\" ou \"{CANCELAR}\"."))


def _confirmar_nota_calculada(versao, escolhas):
    """Mostra o vetor e a nota das respostas e pede para usar.

    Devolve (nota, vetor), ou None se o usuário não quiser a nota ou
    se ela der 0,0.
    """
    vetor, nota = calculadora_cvss.analisar_vetor(
        calculadora_cvss.montar_vetor(versao, escolhas))
    if nota < CVSS_MINIMO:
        print(f"\n  Vetor: {vetor}")
        print("  " + cores.aviso(
            "As respostas dão nota 0,0 (\"Nenhuma\" no CVSS): a falha "
            "não tem impacto e não entra no inventário."))
        return None
    telas.mostrar_resultado_cvss(vetor, nota)
    if confirmar("\n  Usar esta nota?", padrao=True):
        return nota, vetor
    print("  " + cores.aviso(
        f"Nota descartada. Digite a nota, cole um vetor ou digite "
        f"\"{PALAVRA_CALCULAR}\" para responder de novo."))
    return None
