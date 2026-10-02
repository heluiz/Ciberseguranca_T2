"""Conferência de dados vindos do arquivo JSON.

O arquivo pode ser editado fora do programa, então nada que vem dele é
tomado como certo. Cada função confere um tipo e devolve o valor, ou
levanta ValueError com uma frase que diz o que está errado e onde
("equipamento 3: campo 'hostname' ..."). O argumento "nome" é essa
localização. As classes usam estas funções em de_dict(), e o
armazenamento transforma o ValueError em BaseInvalidaError.
"""

import math


def exigir_objeto(valor, nome):
    """Garante que o valor é um objeto JSON (dict) e o devolve."""
    if not isinstance(valor, dict):
        raise ValueError(f"{nome}: deveria ser um objeto JSON, "
                         f"veio {type(valor).__name__}")
    return valor


def exigir_lista(valor, nome):
    """Garante que o valor é uma lista JSON (array) e a devolve."""
    if not isinstance(valor, list):
        raise ValueError(f"{nome}: deveria ser uma lista, "
                         f"veio {type(valor).__name__}")
    return valor


def exigir_campo(objeto, campo, nome):
    """Devolve objeto[campo], ou ValueError se o campo não existir.

    Sem isto o KeyError diria só 'hostname', sem dizer em qual registro.
    """
    if campo not in objeto:
        raise ValueError(f"{nome}: falta o campo '{campo}'")
    return objeto[campo]


def exigir_texto(valor, nome):
    """Garante texto visível: um nulo no arquivo é recusado na carga.

    Recusa também caractere de controle, como ESC: é a mesma regra da
    digitação, e vale aqui porque o caractere seria enviado ao
    terminal toda vez que o texto aparecesse na tela.
    """
    if not isinstance(valor, str):
        raise ValueError(f"{nome}: deveria ser texto, "
                         f"veio {type(valor).__name__}")
    if not valor.isprintable():
        invisivel = next(c for c in valor if not c.isprintable())
        raise ValueError(f"{nome}: tem caractere de controle "
                         f"({invisivel!r})")
    return valor


def exigir_inteiro(valor, nome, minimo=None):
    """Garante um inteiro de verdade (10.0 e True não valem).

    bool é subclasse de int e precisa ser recusado à parte.
    """
    if isinstance(valor, bool) or not isinstance(valor, int):
        raise ValueError(f"{nome}: deveria ser um número inteiro, "
                         f"veio {valor!r}")
    if minimo is not None and valor < minimo:
        raise ValueError(f"{nome}: deveria ser pelo menos {minimo}, "
                         f"veio {valor}")
    return valor


def exigir_enum(classe, valor, nome):
    """Devolve o membro do Enum que tem esse código, ou ValueError.

    O erro do próprio Enum ("99 is not a valid X") não diz onde, nem
    está em português.
    """
    codigo = exigir_inteiro(valor, nome)
    try:
        return classe(codigo)
    except ValueError:
        validos = ", ".join(str(item.value) for item in classe)
        raise ValueError(f"{nome}: código {codigo} inexistente "
                         f"(válidos: {validos})") from None


def exigir_numero(valor, nome):
    """Garante um número finito (int ou float) e o devolve como float.

    O módulo json aceita NaN e Infinity, que não são JSON padrão e
    estragariam a álgebra linear: são recusados aqui.
    """
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ValueError(f"{nome}: deveria ser um número, "
                         f"veio {valor!r}")
    if not math.isfinite(valor):
        raise ValueError(f"{nome}: deveria ser um número finito, "
                         f"veio {valor!r}")
    return float(valor)


# Teste rápido: roda só com "python validacao.py", nunca no import.
if __name__ == "__main__":
    assert exigir_inteiro(3, "x") == 3
    assert exigir_numero(7, "x") == 7.0
    assert exigir_texto("Cartório", "x") == "Cartório"

    recusas = (
        (exigir_inteiro, 10.0), (exigir_inteiro, True),
        (exigir_inteiro, "3"), (exigir_inteiro, 0),
        (exigir_numero, "7,5"), (exigir_numero, None),
        (exigir_numero, float("nan")), (exigir_numero, float("inf")),
        (exigir_texto, None), (exigir_texto, "PC\x1b[2J"),
        (exigir_objeto, []), (exigir_lista, {}),
    )
    from classificacoes import TipoEquipamento
    assert exigir_enum(TipoEquipamento, 2, "x") is TipoEquipamento.SERVIDOR
    for ruim in (99, "2", 2.0):
        try:
            exigir_enum(TipoEquipamento, ruim, "tipo")
            raise AssertionError(f"exigir_enum aceitou {ruim!r}")
        except ValueError as erro:
            print(f"Recusado exigir_enum({ruim!r:5}) {erro}")
    for funcao, valor in recusas:
        try:
            if funcao is exigir_inteiro and valor == 0:
                funcao(valor, "campo", minimo=1)
            else:
                funcao(valor, "campo")
            raise AssertionError(f"{funcao.__name__} aceitou {valor!r}")
        except ValueError as erro:
            print(f"Recusado {funcao.__name__}({valor!r:12}) {erro}")
    try:
        exigir_campo({}, "hostname", "equipamento 3")
    except ValueError as erro:
        print(f"Recusado exigir_campo: {erro}")
    print("\nOK - validações exercitadas.")
