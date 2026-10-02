"""Logotipo da tela de abertura: escudo com cadeado e circuitos.

A arte é uma versão em caracteres (50 colunas por 25 linhas) do
logotipo do projeto, pequena o bastante para caber no terminal de 80
colunas e na largura de 62 do menu. O escudo usa o bloco sombreado e o
resto usa o bloco cheio, então as duas partes continuam distintas mesmo
sem cor. Só a tela usa este módulo: nada vai para o arquivo de dados.
As cores vêm de cores.py: o logotipo sai sem códigos quando a saída não
é um terminal, no IDLE ou com NO_COLOR definida.
"""

import cores

LARGURA_TELA = 62

ESCUDO = "▓"
CIRCUITO = "█"

ARTE = (
    '                       ████',
    '                       ████',
    '       ███              ██              ███',
    '      █████████████     ██     █████████████',
    '                 ██     ██     ██',
    ' ████            ██    ▓▓▓▓    ██            ████',
    ' ████            ██ ▓▓▓▓▓▓▓▓▓▓ ██            ████',
    '  ██          ▓▓▓▓▓▓▓▓      ▓▓▓▓▓▓▓▓          ██',
    '  █████████ ▓▓▓▓▓                ▓▓▓▓▓ █████████',
    '            ▓▓                      ▓▓',
    '            ▓▓         ████         ▓▓',
    '████        ▓▓        ██████        ▓▓        ████',
    '███████████ ▓▓        ██████        ▓▓ ███████████',
    '            ▓▓▓        ████        ▓▓▓',
    '             ▓▓        ████        ▓▓',
    '  ███████████ ▓▓                  ▓▓ ███████████',
    '  ██           ▓▓▓              ▓▓▓           ██',
    ' ████           ▓▓▓▓          ▓▓▓▓           ████',
    ' ████            █▓▓▓▓▓    ▓▓▓▓▓█            ████',
    '                 ██  ▓▓▓▓▓▓▓▓  ██',
    '       ███       ██     ██     ██       ███',
    '      ████████████      ██      ████████████',
    '                        ██',
    '                       ████',
    '                       ████',
)

_LARGURA_ARTE = max(len(linha) for linha in ARTE)


def _pintar_linha(linha):
    """Pinta o escudo de ciano e o circuito de azul, em trechos seguidos.

    Agrupa os caracteres iguais para gerar um código de cor por trecho,
    e não um por caractere.
    """
    pedacos = []
    inicio = 0
    while inicio < len(linha):
        caractere = linha[inicio]
        fim = inicio
        while fim < len(linha) and linha[fim] == caractere:
            fim += 1
        trecho = linha[inicio:fim]
        if caractere == ESCUDO:
            trecho = cores.pintar(trecho, cores.NEGRITO, cores.CIANO)
        elif caractere == CIRCUITO:
            trecho = cores.pintar(trecho, cores.AZUL)
        pedacos.append(trecho)
        inicio = fim
    return "".join(pedacos)


def montar():
    """Devolve o logotipo centralizado na largura da tela, pronto para print.

    O recuo é calculado sobre o texto puro, antes de pintar: os códigos
    de cor contam como caracteres e descentralizariam a arte.
    """
    recuo = " " * ((LARGURA_TELA - _LARGURA_ARTE) // 2)
    return "\n".join(recuo + _pintar_linha(linha) for linha in ARTE)


# Teste rápido: roda só com "python banner.py", nunca no import.
if __name__ == "__main__":
    cores.ativar()
    print(montar())
