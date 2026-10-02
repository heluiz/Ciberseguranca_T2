"""Padronização do texto digitado e comparação para buscas.

Texto todo em maiúsculas ou todo em minúsculas é padronizado; texto
com caixa misturada foi escrito assim de propósito e é mantido, o que
preserva siglas como TI e RDP. Na padronização, as siglas de SIGLAS
voltam à grafia certa. O módulo só trata texto: não conhece equipamentos
nem vulnerabilidades.
"""

import string
import unicodedata

# Ficam em minúscula quando não são a primeira palavra do nome.
PARTICULAS = ("de", "da", "do", "das", "dos", "e")

# Siglas na grafia certa. Sem esta lista, a padronização trocaria
# "DEAM" por "Deam" e "1ª DP" por "1ª Dp". Sigla nova entra aqui.
SIGLAS = ("BNMP", "DAJEC", "DEAM", "DEIFRVA", "DP", "DRPC", "GAOP",
          "PCNet", "RDP", "REDS", "SIP", "TI", "USB", "VPN")

# Acha a sigla pela forma minúscula: "pcnet" -> "PCNet".
_SIGLA_POR_MINUSCULA = {sigla.lower(): sigla for sigla in SIGLAS}


def _sem_ordinais(texto):
    """Devolve o texto sem ª e º, só para testar a caixa.

    O Python trata ª e º como minúsculas: sem isto, "1ª DELEGACIA" não
    seria reconhecido como texto todo em maiúsculas.
    """
    return texto.replace("ª", "").replace("º", "")


def ja_formatado(texto):
    """Diz se o texto mistura maiúsculas e minúsculas."""
    letras = _sem_ordinais(texto)
    return not letras.isupper() and not letras.islower()


def _grafia_de_sigla(palavra):
    """Devolve a palavra na grafia de SIGLAS, se ela for uma sigla.

    A pontuação em volta fica: "(reds)," vira "(REDS),". Palavra que
    não é sigla conhecida volta como veio.
    """
    nucleo = palavra.strip(string.punctuation)
    sigla = _SIGLA_POR_MINUSCULA.get(nucleo.lower())
    if sigla is None:
        return palavra
    return palavra.replace(nucleo, sigla)


def titulo(texto):
    """Formata nome de pessoa ou de lugar com iniciais maiúsculas.

    Espaços repetidos viram um só, as partículas (de, da, do...) ficam
    em minúscula e as siglas de SIGLAS, na grafia certa. Se o texto já
    mistura maiúsculas e minúsculas, a caixa é mantida.
    """
    texto = " ".join(texto.split())
    if ja_formatado(texto):
        return texto

    palavras = texto.lower().split()
    saida = []
    for posicao, palavra in enumerate(palavras):
        if posicao > 0 and palavra in PARTICULAS:
            saida.append(palavra)
        else:
            saida.append(_grafia_de_sigla(palavra.capitalize()))
    return " ".join(saida)


def frase(texto):
    """Formata descrição: só a primeira letra vira maiúscula.

    Espaços repetidos viram um só e o resto fica como veio, para
    preservar siglas. Texto todo em maiúsculas é rebaixado antes,
    porque ali não há como distinguir sigla de palavra: só as de
    SIGLAS voltam à grafia certa, como no texto todo em minúsculas.
    A inicial não muda se a primeira palavra já tiver maiúscula
    (iDRAC, pfSense).
    """
    texto = " ".join(texto.split())
    if not texto:
        return texto
    if not ja_formatado(texto):
        palavras = texto.lower().split()
        texto = " ".join(_grafia_de_sigla(palavra) for palavra in palavras)
    if texto.split()[0].islower():
        texto = texto[0].upper() + texto[1:]
    return texto


def numero_br(valor, casas=1):
    """Formata o número com vírgula decimal, como se escreve no Brasil.

    O JSON e o Python usam ponto; só a tela usa a vírgula.
    """
    return f"{valor:.{casas}f}".replace(".", ",")


def fracao_br(valor):
    """Formata uma fração sem zeros inúteis: 0.3 -> "0,3", 0.25 -> "0,25".

    Mostra até quatro casas, que é a precisão guardada para as frações
    das dependências.
    """
    texto = f"{valor:.4f}".rstrip("0").rstrip(".")
    return texto.replace(".", ",")


def para_busca(texto):
    """Devolve a forma do texto usada só para comparar em buscas.

    Sem acento, sem diferença de caixa e sem espaço sobrando: assim
    "plantao" encontra "Plantão". O texto gravado não muda.
    """
    # casefold() é o lower() próprio para comparação; NFD separa cada
    # letra do seu acento, e o filtro descarta os acentos soltos.
    limpo = " ".join(texto.split()).casefold()
    decomposto = unicodedata.normalize("NFD", limpo)
    return "".join(c for c in decomposto if not unicodedata.combining(c))


# Teste rápido: roda só com "python formatacao.py", nunca no import.
if __name__ == "__main__":
    casos_titulo = [
        ("escrivão de plantão", "Escrivão de Plantão"),
        ("ESCRIVÃO DE PLANTÃO", "Escrivão de Plantão"),
        ("Setor de TI", "Setor de TI"),
        ("sala   de  máquinas", "Sala de Máquinas"),
        ("cartório", "Cartório"),
        ("1ª DELEGACIA REGIONAL", "1ª Delegacia Regional"),
        ("Setor  de  TI", "Setor de TI"),
        ("DEAM", "DEAM"),
        ("1ª DP", "1ª DP"),
        ("cartório da deam", "Cartório da DEAM"),
        ("1ª DRPC UBERLÂNDIA", "1ª DRPC Uberlândia"),
    ]
    casos_frase = [
        ("porta RDP exposta", "Porta RDP exposta"),
        ("PORTA RDP EXPOSTA", "Porta RDP exposta"),
        # Sigla fora de SIGLAS não tem como ser reconhecida.
        ("PORTA SSH EXPOSTA", "Porta ssh exposta"),
        ("senha padrão de fábrica", "Senha padrão de fábrica"),
        ("Já estava certo", "Já estava certo"),
        ("iDRAC com senha padrão", "iDRAC com senha padrão"),
        ("pfSense desatualizado", "pfSense desatualizado"),
        ("sessão do reds aberta", "Sessão do REDS aberta"),
        ("PCNET (REDS) LENTO", "PCNet (REDS) lento"),
    ]
    casos_busca = [
        ("Setor de Informática", "setor de informatica"),
        ("  PLANTÃO ", "plantao"),
        ("Cartório", "cartorio"),
    ]

    print("--- titulo() ---")
    for entrada, esperado in casos_titulo:
        obtido = titulo(entrada)
        marca = "ok " if obtido == esperado else "ERRO"
        print(f"  {marca} {entrada!r:28} -> {obtido!r}")
        assert obtido == esperado, f"esperava {esperado!r}"

    print("\n--- frase() ---")
    for entrada, esperado in casos_frase:
        obtido = frase(entrada)
        marca = "ok " if obtido == esperado else "ERRO"
        print(f"  {marca} {entrada!r:28} -> {obtido!r}")
        assert obtido == esperado, f"esperava {esperado!r}"

    print("\n--- para_busca() ---")
    for entrada, esperado in casos_busca:
        obtido = para_busca(entrada)
        marca = "ok " if obtido == esperado else "ERRO"
        print(f"  {marca} {entrada!r:28} -> {obtido!r}")
        assert obtido == esperado, f"esperava {esperado!r}"

    print("\n--- numero_br() ---")
    assert numero_br(7.5) == "7,5"
    assert numero_br(0.3, 2) == "0,30"
    assert numero_br(10, 1) == "10,0"
    assert fracao_br(0.3) == "0,3"
    assert fracao_br(0.25) == "0,25"
    assert fracao_br(0.5) == "0,5"
    assert fracao_br(0.0001) == "0,0001"
    print("  ok  7.5 -> '7,5'; 0.3 (2 casas) -> '0,30'; "
          "fracao_br(0.25) -> '0,25'")

    print("\nOK - formatação passou em todos os casos.")
