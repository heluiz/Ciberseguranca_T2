"""Leitura do teclado: comandos globais e perguntas com validação.

É o único módulo que chama input(). As funções ler_*() repetem a
pergunta até vir uma resposta válida, e todas passam por uma única
porta, ler_resposta(), que atende os comandos globais: voltar, sair,
limpar e ajuda (e a surpresa, veja surpresa.py).

O caminho de uma resposta é:

  1. ler_resposta() lê a linha e procura a palavra em COMANDOS.
  2. Não é comando: devolve o texto, e a pergunta segue normal.
  3. É "limpar" ou "ajuda": executa e faz a mesma pergunta de novo.
  4. É "voltar" ou "sair": levanta uma exceção, que atravessa todas as
     funções abertas até ser capturada no laço do menu (main.py). É o
     mesmo mecanismo de sys.exit(), que também encerra o programa
     levantando uma exceção (SystemExit).

Sem exceção, cada ler_*() teria de devolver um valor especial e cada
ação teria de testá-lo depois de cada pergunta.
"""

import math
import os

import cores
import surpresa


class VoltarAoMenu(Exception):
    """Pedido de "voltar": abandona a ação e retorna ao menu.

    Deriva de Exception, como a documentação do Python recomenda para
    exceções próprias. Por isso o menu a captura antes do
    "except Exception" genérico, que a confundiria com um erro.
    """


class SairDoPrograma(Exception):
    """Pedido de "sair": encerra o programa de qualquer tela."""


def pedir_voltar():
    """Atende "voltar"."""
    raise VoltarAoMenu


def pedir_saida():
    """Atende "sair"."""
    raise SairDoPrograma


def limpar_tela():
    """Atende "limpar": limpa o terminal com o comando do sistema."""
    os.system("cls" if os.name == "nt" else "clear")


def mostrar_ajuda():
    """Atende "ajuda": lista os comandos a partir de COMANDOS."""
    print("\n  " + cores.titulo("Comandos aceitos em qualquer pergunta:"))
    for palavras, _, efeito in COMANDOS:
        nomes = ", ".join(palavras).ljust(9)
        print(f"    {cores.destaque(nomes)} {efeito}")
    # "lista" fica fora de COMANDOS: só vale nas perguntas de ID.
    print(f"    {cores.destaque('lista'.ljust(9))} nas perguntas de ID, "
          "mostra os registros e pergunta de novo")
    print("  " + cores.discreto(
        "O que ainda não foi gravado é descartado ao voltar ou sair.") + "\n")


# Fonte única dos comandos: a mesma tabela decide o que cada palavra
# faz e monta o texto da ajuda, então comando novo é uma linha aqui.
# Só a resposta inteira vale como comando: "Sair do sistema" continua
# sendo uma descrição normal.
COMANDOS = (
    (("voltar",), pedir_voltar, "abandona a tela atual e volta ao menu"),
    (("sair",), pedir_saida, "fecha o programa"),
    (("limpar",), limpar_tela, "limpa a tela"),
    (("ajuda", "?"), mostrar_ajuda, "mostra esta lista"),
)

# Palavra digitada -> função, montado da tabela acima: "?" e "ajuda"
# apontam para a mesma função.
_FUNCAO_DO_COMANDO = {palavra: funcao
                      for palavras, funcao, _ in COMANDOS
                      for palavra in palavras}


def ler_resposta(mensagem, depois_de_limpar=None):
    """Lê uma linha do teclado e atende os comandos globais.

    Devolve o texto digitado quando ele não é comando. Maiúsculas não
    importam: "SAIR" e "sair" são o mesmo comando. Com
    depois_de_limpar, essa função redesenha a tela depois de "limpar"
    (o menu usa isso para não sumir).
    """
    while True:
        valor = input(mensagem).strip()
        if surpresa.e_pedido(valor):
            surpresa.executar(limpar_tela)
            continue  # a palavra não é resposta: repete a pergunta
        comando = _FUNCAO_DO_COMANDO.get(valor.casefold())
        if comando is None:
            return valor
        comando()  # voltar e sair levantam exceção e não retornam
        if comando is limpar_tela and depois_de_limpar is not None:
            depois_de_limpar()


def ler_texto(mensagem, obrigatorio=True):
    """Lê um texto; se obrigatório, repete a pergunta até vir algo.

    Recusa caracteres de controle, como ESC: gravados, eles alterariam
    o terminal toda vez que o texto fosse exibido.
    """
    while True:
        valor = ler_resposta(mensagem)
        if not valor.isprintable():
            print("  " + cores.erro("! Use apenas caracteres visíveis."))
        elif valor or not obrigatorio:
            return valor
        else:
            print("  " + cores.erro("! Este campo não pode ficar vazio."))


# Texto mais curto que isto pede confirmação: "TI" pode ser um setor,
# mas "a" costuma ser engano de digitação.
MINIMO_SEM_CONFIRMAR = 3


def ler_campo(mensagem, obrigatorio=True):
    """Lê responsável, lotação ou descrição.

    Recusa texto sem nenhuma letra ("12") e pede confirmação para texto
    curto ("TI"). Com obrigatorio=False, Enter vazio devolve "" (manter
    o valor atual).
    """
    while True:
        valor = ler_texto(mensagem, obrigatorio)
        if not valor:
            return valor
        if not any(c.isalpha() for c in valor):
            print("  " + cores.erro("! Use pelo menos uma letra."))
            continue
        pergunta = f'  "{valor}" ficou curto. É isso mesmo?'
        if len(valor) < MINIMO_SEM_CONFIRMAR and not confirmar(pergunta):
            continue
        return valor


def ler_inteiro(mensagem, opcional=False, mostrar_lista=None):
    """Lê um número inteiro, repetindo a pergunta até vir um válido.

    Com opcional=True, Enter vazio devolve None (manter o valor atual).
    Com mostrar_lista, a resposta "lista" chama essa função (que mostra
    os registros) e repete a pergunta.
    """
    while True:
        bruto = ler_resposta(mensagem)
        if not bruto and opcional:
            return None
        if mostrar_lista is not None and bruto.casefold() == "lista":
            mostrar_lista()
            continue
        try:
            return int(bruto)
        except ValueError:
            print("  " + cores.erro("! Digite apenas números."))


def ler_decimal(mensagem, opcional=False):
    """Lê um número decimal, com vírgula ou ponto: "7,5" e "7.5" valem.

    Repete a pergunta até vir um número finito: float() aceitaria
    "nan" e "inf", que estragariam as contas. Com opcional=True, Enter
    vazio devolve None (manter o valor atual).
    """
    while True:
        bruto = ler_resposta(mensagem)
        if not bruto and opcional:
            return None
        try:
            numero = float(bruto.replace(",", "."))
        except ValueError:
            numero = math.nan
        if math.isfinite(numero):
            return numero
        print("  " + cores.erro(
            "! Digite um número, como 7,5 (use vírgula ou ponto)."))


def ler_enum(mensagem, classe_enum, opcional=False):
    """Mostra as opções do Enum e só aceita um código da lista.

    Com opcional=True, Enter vazio devolve None.
    """
    print(f"\n{mensagem}")
    for item in classe_enum:
        print(f"    {cores.destaque(str(item.value))} - {item.rotulo}")

    while True:
        codigo = ler_inteiro("  Código: ", opcional=opcional)
        if codigo is None:
            return None
        try:
            return classe_enum(codigo)
        except ValueError:
            print("  " + cores.erro(
                "! Código inválido. Escolha um da lista acima."))


def confirmar(mensagem):
    """Devolve True se o usuário responder 's' ou 'sim'."""
    resposta = ler_resposta(f"{mensagem} (s/N): ")
    return resposta.lower() in ("s", "sim")


def ler_hostname(mensagem, validar, obrigatorio=True):
    """Lê um hostname e repete a pergunta até vir um nome válido.

    validar(texto) devolve None se o nome serve, ou o motivo da recusa
    (é Inventario.problema_no_hostname, que cuida da regra de formato e
    da de nome repetido). Vazio só é aceito com obrigatorio=False (na
    atualização, manter o atual).
    """
    while True:
        valor = ler_texto(mensagem, obrigatorio)
        if not valor:
            return valor
        problema = validar(valor)
        if problema is None:
            return valor
        print("  " + cores.erro(f"! Hostname inválido: {problema}."))
