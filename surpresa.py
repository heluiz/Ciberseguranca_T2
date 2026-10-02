"""Surpresa: digitar "barba" em qualquer pergunta mostra uma animação.

O estudante de cibersegurança do 1º ao 8º período: a cada quadro passa
um semestre, e a barba cresce até ele virar um barbudão. Só a tela usa
este módulo: nada vai para o arquivo de dados, e a palavra não vira
resposta da pergunta.

A animação só roda num terminal de verdade. Com a entrada ou a saída
redirecionada (testes automáticos), com o IDLE ou com NO_COLOR, ela é
pulada e "barba" é tratada como qualquer outro texto.

Para remover a surpresa: apague este arquivo, o "import surpresa" e o
bloco "if surpresa.e_pedido(...)" de ler_resposta(), no entrada.py.
"""

import sys
import time

import cores
import formatacao

PALAVRA = "barba"
LARGURA_TELA = 62
PAUSA = 1.0  # segundos em cada período

# Cada linha tem largura ímpar e é centralizada no rosto (19 colunas),
# então o desenho fica simétrico. {o} é o lugar dos olhos, que mudam
# de um período para outro (veja _OLHOS).
_LARGURA_ROSTO = 19

_ROSTO = (
    '_.-"""""-._',
    ".'  _     _  '.",
    "/   {o}   {o}   \\",
    "|        |        |",
    "|       _|_       |",
)

# Queixo de cada período, do 1º ao 8º: liso, sombra, por fazer, curta,
# média, cheia, grande e barbudão.
_QUEIXOS = (
    (   # 1º
        "\\     \\___/     /",
        "'.           .'",
        "'-._____.-'",
    ),
    (   # 2º
        "\\   ░ \\___/ ░   /",
        "'.  ░░░░░░░  .'",
        "'-.░░░░░.-'",
    ),
    (   # 3º
        "\\ ░░░ \\___/ ░░░ /",
        "'.░░░░░░░░░░░.'",
        "'-░░░░░░░-'",
    ),
    (   # 4º
        "\\▒▒▒▒ \\___/ ▒▒▒▒/",
        "'▒▒▒▒▒▒▒▒▒▒▒▒▒'",
        "▒▒▒▒▒▒▒▒▒",
    ),
    (   # 5º
        "\\▒▒▒▒ \\___/ ▒▒▒▒/",
        "'▒▒▒▒▒▒▒▒▒▒▒▒▒'",
        "▒▒▒▒▒▒▒▒▒▒▒▒▒",
        "▒▒▒▒▒▒▒▒▒",
    ),
    (   # 6º
        "\\▓▓▓▓▓\\___/▓▓▓▓▓/",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓",
    ),
    (   # 7º
        "\\▓▓▓▓▓\\___/▓▓▓▓▓/",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓",
        "▓▓▓",
    ),
    (   # 8º
        "\\▓▓▓▓▓\\___/▓▓▓▓▓/",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓▓▓",
        "▓▓▓▓▓▓▓",
        "▓▓▓▓▓",
        "▓▓▓",
        "▓",
    ),
)

# Olhos de cada período: do animado ao cansado.
_OLHOS = ("(o)", "(o)", "(o)", "(o)", "(°)", "(°)", "(-)", "(-)")

_LEGENDAS = (
    "1º período: calouro empolgado",
    "2º período: Python? Fácil...",
    "3º período: primeiros trabalhos",
    "4º período: o sono começa a pesar",
    "5º período: redes e firewalls",
    "6º período: pentest às 3h da manhã",
    "7º período: o TCC chegando",
    "8º período: o barbudão da cibersegurança!",
)

_ALTURA = len(_ROSTO) + max(len(q) for q in _QUEIXOS)
_PELOS = "░▒▓"


def ativa():
    """Diz se a animação pode rodar (terminal com cores ligadas)."""
    return (sys.stdin.isatty() and sys.stdout.isatty()
            and cores.pintar("x", cores.NEGRITO) != "x")


def e_pedido(texto):
    """Diz se o texto é a palavra da surpresa e se ela pode rodar."""
    return formatacao.para_busca(texto) == PALAVRA and ativa()


def _pintar(linha):
    """Pinta o rosto de amarelo e os pelos de branco negrito."""
    pedacos = []
    for caractere in linha:
        if caractere in _PELOS:
            pedacos.append(cores.pintar(caractere, cores.NEGRITO))
        elif caractere == " ":
            pedacos.append(caractere)
        else:
            pedacos.append(cores.pintar(caractere, cores.AMARELO))
    return "".join(pedacos)


def _quadro(periodo):
    """Monta o texto do quadro do período (0 a 7): rosto e legenda.

    A altura é sempre a mesma, para o desenho não pular de lugar.
    """
    linhas = [linha.replace("{o}", _OLHOS[periodo]) for linha in _ROSTO]
    linhas += _QUEIXOS[periodo]
    linhas += [""] * (_ALTURA - len(linhas))
    recuo = " " * ((LARGURA_TELA - _LARGURA_ROSTO) // 2)
    saida = []
    for linha in linhas:
        miolo = " " * ((_LARGURA_ROSTO - len(linha)) // 2)
        saida.append(recuo + miolo + _pintar(linha))
    saida.append("")
    saida.append(cores.titulo(_LEGENDAS[periodo].center(LARGURA_TELA)))
    return "\n".join(saida)


def executar(limpar):
    """Roda a animação; "limpar" é a função que limpa a tela."""
    try:
        for periodo in range(len(_LEGENDAS)):
            limpar()
            print("\n" + cores.discreto(
                "Estudante de Cibersegurança".center(LARGURA_TELA)))
            print(_quadro(periodo))
            time.sleep(PAUSA)
        time.sleep(1.2)
    except KeyboardInterrupt:
        pass  # Ctrl+C na animação só a interrompe
    limpar()


# Teste rápido: roda só com "python surpresa.py", nunca no import.
if __name__ == "__main__":
    cores.ativar()
    if ativa():
        import os
        executar(lambda: os.system("cls" if os.name == "nt" else "clear"))
    else:
        print("Sem terminal: mostrando só os quadros, sem animação.")
        for periodo in (0, 3, 7):
            print(_quadro(periodo))
