"""Cores da saída no terminal, com códigos ANSI.

Só a tela usa este módulo: nada colorido vai para o arquivo de dados.
As funções devolvem o texto pintado, não imprimem; quem imprime é o
main.py. O texto volta sem código nenhum quando a saída não é um
terminal (redirecionada para arquivo), quando o programa roda no IDLE
ou quando a variável de ambiente NO_COLOR está definida.
"""

import os
import sys

# Liga as cores só num terminal que as interpreta. O IDLE se declara
# terminal (isatty() devolve True), mas mostraria os códigos crus, como
# "[31m". NO_COLOR (no-color.org) desliga as cores em qualquer
# programa; pela convenção, só vale se não estiver vazia.
_LIGADAS = (sys.stdout.isatty()
            and "idlelib" not in sys.modules
            and not os.environ.get("NO_COLOR"))

_RESET = "\033[0m"
NEGRITO = "\033[1m"
APAGADO = "\033[2m"
VERMELHO = "\033[31m"
VERDE = "\033[32m"
AMARELO = "\033[33m"
AZUL = "\033[34m"
MAGENTA = "\033[35m"
CIANO = "\033[36m"


def ativar():
    """Prepara o console do Windows para interpretar os códigos ANSI.

    No cmd e no PowerShell antigos, os códigos apareceriam crus
    ("[31m") sem isto. Chamar os.system("") liga esse modo no console
    como efeito colateral. Nos outros sistemas não faz nada.
    """
    if _LIGADAS and os.name == "nt":
        os.system("")


def pintar(texto, *estilos):
    """Devolve o texto envolvido pelos estilos e pelo código de reset.

    Com as cores desligadas, devolve o texto como veio.
    """
    if not _LIGADAS or not estilos:
        return texto
    return "".join(estilos) + texto + _RESET


def erro(texto):
    """Mensagem de erro ou recusa."""
    return pintar(texto, VERMELHO)


def sucesso(texto):
    """Confirmação de que a ação foi concluída e gravada."""
    return pintar(texto, VERDE)


def aviso(texto):
    """Atenção, cancelamento ou ação sem efeito."""
    return pintar(texto, AMARELO)


def titulo(texto):
    """Título de tela ou de seção."""
    return pintar(texto, NEGRITO, CIANO)


def destaque(texto):
    """Números de opção e outros pontos de atenção."""
    return pintar(texto, AMARELO)


def discreto(texto):
    """Texto de apoio: rótulos, legendas e linhas de separação."""
    return pintar(texto, APAGADO)


# Cor de cada severidade, pelo valor do NivelGravidade (1 a 4). Pelo
# valor, e não pelo membro, para este módulo não depender de
# classificacoes.py.
_COR_GRAVIDADE = {
    1: (VERDE,),
    2: (AMARELO,),
    3: (VERMELHO,),
    4: (NEGRITO, VERMELHO),
}

# Cor de cada situação, pelo valor do SituacaoTratamento (1 a 4).
_COR_SITUACAO = {
    1: (AMARELO,),
    2: (CIANO,),
    3: (VERDE,),
    4: (MAGENTA,),
}


def gravidade(texto, nivel):
    """Pinta o texto com a cor da severidade (NivelGravidade).

    Texto alinhado com espaços deve ser alinhado antes de pintar: os
    códigos contam como caracteres em len() e desalinhariam a coluna.
    """
    return pintar(texto, *_COR_GRAVIDADE.get(nivel.value, ()))


def situacao(texto, estado):
    """Pinta o texto com a cor da situação (SituacaoTratamento)."""
    return pintar(texto, *_COR_SITUACAO.get(estado.value, ()))


# Teste rápido: roda só com "python cores.py", nunca no import.
if __name__ == "__main__":
    ativar()
    print(titulo("--- Amostra das cores ---"))
    print(erro("  ! Mensagem de erro"))
    print(sucesso("  Ativo cadastrado com o ID 7."))
    print(aviso("  Exclusão cancelada."))
    print(f"  {destaque(' 1')} - Opção de menu")
    print(discreto("  " + "-" * 30))

    from classificacoes import NivelGravidade, SituacaoTratamento
    for nivel in NivelGravidade:
        print("  " + gravidade(f"{nivel.rotulo.upper():<9}", nivel) + "|")
    for estado in SituacaoTratamento:
        print("  " + situacao(estado.rotulo, estado))

    # Com as cores desligadas, o texto não pode ganhar nenhum código.
    _LIGADAS = False
    assert pintar("texto", VERMELHO) == "texto"
    print("\nOK - sem cor, o texto sai limpo.")
