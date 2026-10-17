"""A classe FichaTecnica: os dados que identificam o equipamento.

Fabricante, modelo, número de série, número de patrimônio, sistema
(operacional ou firmware) e versão do sistema. São os dados que ligam
um equipamento às vulnerabilidades publicadas, que valem para um
produto numa versão, e o patrimônio é o número do bem no órgão. Todos
são opcionais: um equipamento cadastrado só com os dados do Trabalho 1
tem a ficha vazia.

O Equipamento tem uma FichaTecnica (composição): a ficha não sabe de
qual equipamento é, e a regra do patrimônio único, que depende dos
outros equipamentos, fica no Inventario.

A classe não lê do teclado nem grava em disco.
"""

from validacao import exigir_objeto, exigir_texto

# Campo -> rótulo na tela, na ordem em que aparecem.
ROTULOS = {
    "fabricante": "Fabricante",
    "modelo": "Modelo",
    "numero_serie": "Nº de série",
    "patrimonio": "Patrimônio",
    "sistema": "Sistema",
    "versao": "Versão",
}
CAMPOS = tuple(ROTULOS)

# Um nome de modelo ou de sistema cabe folgado nisto.
TAMANHO_MAXIMO = 60


def validar_valor(rotulo, texto):
    """Devolve o texto de um campo da ficha, arrumado, ou ValueError.

    Tira os espaços repetidos e mantém maiúsculas e minúsculas como
    foram digitadas ("HP LaserJet" não vira "Hp Laserjet"). Precisa ter
    ao menos uma letra ou número e caber em TAMANHO_MAXIMO caracteres.
    """
    if not isinstance(texto, str):
        raise ValueError(f"{rotulo}: deveria ser texto, veio {texto!r}")
    arrumado = " ".join(texto.split())
    if not arrumado.isprintable():
        raise ValueError(f"{rotulo}: use apenas caracteres visíveis")
    if not any(c.isalnum() for c in arrumado):
        raise ValueError(f"{rotulo}: use pelo menos uma letra ou número")
    if len(arrumado) > TAMANHO_MAXIMO:
        raise ValueError(f"{rotulo}: tem {len(arrumado)} caracteres, o "
                         f"máximo é {TAMANHO_MAXIMO}")
    return arrumado


class FichaTecnica:
    """Fabricante, modelo, série, patrimônio, sistema e versão.

    Cada campo é um texto ou None (não informado).
    """

    def __init__(self, dados=None):
        """Cria a ficha a partir de {campo: texto}.

        Sem dados, a ficha fica vazia. Levanta ValueError se algum
        campo for inválido.
        """
        self.fabricante = None
        self.modelo = None
        self.numero_serie = None
        self.patrimonio = None
        self.sistema = None
        self.versao = None
        self.atualizar(dados or {})

    @property
    def vazia(self):
        """True se nenhum campo foi informado."""
        return all(getattr(self, campo) is None for campo in CAMPOS)

    def atualizar(self, alteracoes):
        """Aplica {campo: texto}; None ou "" apaga o campo.

        Levanta ValueError em campo que não existe ou valor inválido;
        nesse caso nada muda (tudo ou nada).
        """
        novos = {}
        for campo, valor in alteracoes.items():
            if campo not in ROTULOS:
                raise ValueError(f"A ficha técnica não tem o campo "
                                 f"'{campo}'")
            if valor is None or (isinstance(valor, str)
                                 and not valor.strip()):
                novos[campo] = None
            else:
                novos[campo] = validar_valor(ROTULOS[campo], valor)
        for campo, valor in novos.items():
            setattr(self, campo, valor)

    def preenchidos(self):
        """Devolve os pares (rótulo, valor) dos campos informados."""
        return [(ROTULOS[campo], getattr(self, campo)) for campo in CAMPOS
                if getattr(self, campo) is not None]

    def para_dict(self):
        """Devolve o objeto JSON da ficha: só os campos informados."""
        return {campo: getattr(self, campo) for campo in CAMPOS
                if getattr(self, campo) is not None}

    @classmethod
    def de_dict(cls, dados, nome):
        """Reconstrói a ficha a partir do objeto do arquivo.

        nome diz onde está o objeto, para a mensagem de erro. Um campo
        desconhecido é recusado: um nome escrito errado no arquivo
        sumiria com o dado na próxima gravação.
        """
        exigir_objeto(dados, nome)
        for campo, valor in dados.items():
            if campo not in ROTULOS:
                raise ValueError(f"{nome}: campo '{campo}' desconhecido "
                                 f"(válidos: {', '.join(CAMPOS)})")
            exigir_texto(valor, f"{nome}: campo '{campo}'")
        try:
            return cls(dados)
        except ValueError as erro:
            raise ValueError(f"{nome}: {erro}") from erro

    def copia(self):
        """Devolve outra ficha com os mesmos dados."""
        return FichaTecnica(self.para_dict())

    def __eq__(self, outra):
        """Fichas com os mesmos dados são iguais."""
        if not isinstance(outra, FichaTecnica):
            return NotImplemented
        return self.para_dict() == outra.para_dict()

    def __str__(self):
        """Texto para a tela, com os campos informados.

        Como "Dell PowerEdge R430 · Windows Server 2019 1809 · série
        ABC123 · patrimônio 1011065", ou "sem ficha técnica".
        """
        partes = [
            " ".join(v for v in (self.fabricante, self.modelo) if v),
            " ".join(v for v in (self.sistema, self.versao) if v),
            f"série {self.numero_serie}" if self.numero_serie else "",
            f"patrimônio {self.patrimonio}" if self.patrimonio else ""]
        return " · ".join(p for p in partes if p) or "sem ficha técnica"

    def __repr__(self):
        """Texto para depuração: FichaTecnica(fabricante='Dell')."""
        campos = ", ".join(f"{c}={v!r}" for c, v in self.para_dict().items())
        return f"FichaTecnica({campos})"


# Teste: exercita a classe sem ninguém digitar nada.
if __name__ == "__main__":
    vazia = FichaTecnica()
    assert vazia.vazia and vazia.para_dict() == {}

    ficha = FichaTecnica({"fabricante": "  Dell ", "modelo": "OptiPlex  7010",
                          "patrimonio": "123456"})
    print(f"{ficha!r}")
    assert ficha.modelo == "OptiPlex 7010", "espaço repetido ficou"
    assert ficha.para_dict() == {"fabricante": "Dell",
                                 "modelo": "OptiPlex 7010",
                                 "patrimonio": "123456"}
    assert ficha.preenchidos()[2] == ("Patrimônio", "123456")

    # Tudo ou nada: o campo inválido derruba a alteração inteira.
    try:
        ficha.atualizar({"sistema": "Windows 11", "versao": "---"})
        raise AssertionError("aceitou versão sem letra nem número")
    except ValueError as erro:
        print(f"Recusada inteira: {erro}")
    assert ficha.sistema is None
    ficha.atualizar({"sistema": "Windows 11 Pro", "versao": "23H2",
                     "modelo": None})
    assert (ficha.sistema, ficha.versao, ficha.modelo) == (
        "Windows 11 Pro", "23H2", None)
    for ruim in ({"cor": "preta"}, {"modelo": "x" * 61},
                 {"modelo": "ok\u001b[2J"}, {"modelo": 7010}):
        try:
            FichaTecnica(ruim)
            raise AssertionError(f"aceitou {ruim!r}")
        except ValueError as erro:
            print(f"Recusado: {erro}")

    # Ida e volta pelo formato do arquivo.
    copia = FichaTecnica.de_dict(ficha.para_dict(), "ficha")
    assert copia == ficha and copia is not ficha
    assert ficha.copia() == ficha
    for nome, dados in (("lista", ["Dell"]), ("campo novo", {"cor": "x"}),
                        ("nulo", {"modelo": None}),
                        ("número", {"patrimonio": 123456})):
        try:
            FichaTecnica.de_dict(dados, "ficha")
            raise AssertionError(f"aceitou o objeto adulterado: {nome}")
        except ValueError as erro:
            print(f"Recusado ({nome}): {erro}")
    print("\nOK - FichaTecnica exercitada.")
