"""A classe Vulnerabilidade: um item do catálogo de vulnerabilidades.

Uma vulnerabilidade existe uma vez só, com a descrição, a origem e a
nota CVSS, e pode afetar vários equipamentos. Quem diz quais é o
próprio equipamento (equipamentos.py), junto com a situação do
tratamento naquele equipamento. É essa relação "equipamento i tem a
vulnerabilidade j" que vira a matriz M do modelo de risco (risco.py).

A classe não lê do teclado nem grava em disco.
"""

import math

import formatacao
from classificacoes import NivelGravidade, OrigemVulnerabilidade
from validacao import (
    exigir_campo,
    exigir_enum,
    exigir_inteiro,
    exigir_numero,
    exigir_objeto,
    exigir_texto,
)

CVSS_MINIMO = 0.1   # 0,0 significa "nenhum impacto": não é vulnerabilidade
CVSS_MAXIMO = 10.0


def validar_cvss(valor):
    """Devolve a nota CVSS como float, ou levanta ValueError.

    A nota vai de 0,1 a 10,0 e tem uma casa decimal, como as notas
    publicadas pelo FIRST e pela NVD: 8,25 é recusada, e não
    arredondada em silêncio. bool e NaN são recusados: float() aceitaria
    "nan" digitado, e um NaN na matriz estragaria o cálculo de risco.
    """
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ValueError(f"A nota CVSS deve ser um número, veio {valor!r}")
    if not math.isfinite(valor):
        raise ValueError("A nota CVSS deve ser um número finito")
    nota = float(valor)
    if round(nota, 1) != nota:
        raise ValueError("A nota CVSS tem uma casa decimal só, como 7,5")
    if not CVSS_MINIMO <= nota <= CVSS_MAXIMO:
        raise ValueError(f"A nota CVSS deve ficar entre "
                         f"{formatacao.numero_br(CVSS_MINIMO)} e "
                         f"{formatacao.numero_br(CVSS_MAXIMO)}")
    return nota


class Vulnerabilidade:
    """Vulnerabilidade do catálogo: descrição, origem e nota CVSS.

    A severidade (baixa, média, alta, crítica) não é guardada: é
    calculada da nota quando pedida, para as duas nunca discordarem.
    """

    # O id fica de fora: os equipamentos apontam para ele.
    CAMPOS_EDITAVEIS = ("descricao", "origem", "cvss")

    def __init__(self, id_vulnerabilidade, descricao, origem, cvss):
        """Cria a vulnerabilidade; dado inválido levanta ValueError."""
        if not isinstance(origem, OrigemVulnerabilidade):
            raise ValueError("A origem deve ser uma OrigemVulnerabilidade")
        if not descricao.strip():
            raise ValueError("A descrição não pode ficar vazia")
        self.id = id_vulnerabilidade
        self.descricao = formatacao.frase(descricao)
        self.origem = origem
        self.cvss = validar_cvss(cvss)

    @property
    def gravidade(self):
        """Nível de severidade, derivado da nota CVSS."""
        return NivelGravidade.do_cvss(self.cvss)

    def atualizar(self, alteracoes):
        """Aplica as alterações {campo: valor} à vulnerabilidade.

        Levanta ValueError em campo protegido ou valor inválido; nesse
        caso nada muda: a validação termina antes de qualquer
        atribuição.
        """
        for campo in alteracoes:
            if campo not in self.CAMPOS_EDITAVEIS:
                raise ValueError(f"Campo não editável: '{campo}'")

        # Valida tudo primeiro; só depois grava (tudo ou nada).
        novos = {}
        if "descricao" in alteracoes:
            if not alteracoes["descricao"].strip():
                raise ValueError("A descrição não pode ficar vazia")
            novos["descricao"] = formatacao.frase(alteracoes["descricao"])
        if "origem" in alteracoes:
            if not isinstance(alteracoes["origem"], OrigemVulnerabilidade):
                raise ValueError("A origem deve ser uma "
                                 "OrigemVulnerabilidade")
            novos["origem"] = alteracoes["origem"]
        if "cvss" in alteracoes:
            novos["cvss"] = validar_cvss(alteracoes["cvss"])

        for campo, valor in novos.items():
            setattr(self, campo, valor)

    def para_dict(self):
        """Devolve o objeto JSON da vulnerabilidade (só tipos JSON)."""
        return {
            "id": self.id,
            "descricao": self.descricao,
            "origem": self.origem.value,
            "cvss": self.cvss,
        }

    @classmethod
    def de_dict(cls, dados):
        """Reconstrói a vulnerabilidade a partir do objeto do arquivo.

        Levanta ValueError, com a localização do problema, se o objeto
        estiver fora do formato.
        """
        exigir_objeto(dados, "vulnerabilidade")
        id_vuln = exigir_inteiro(
            exigir_campo(dados, "id", "vulnerabilidade"),
            "vulnerabilidade: campo 'id'", minimo=1)
        nome = f"vulnerabilidade {id_vuln}"
        descricao = exigir_texto(
            exigir_campo(dados, "descricao", nome),
            f"{nome}: campo 'descricao'")
        origem = exigir_enum(
            OrigemVulnerabilidade, exigir_campo(dados, "origem", nome),
            f"{nome}: campo 'origem'")
        cvss = exigir_numero(
            exigir_campo(dados, "cvss", nome), f"{nome}: campo 'cvss'")
        try:
            vulnerabilidade = cls(id_vuln, descricao, origem, cvss)
        except ValueError as erro:
            raise ValueError(f"{nome}: {erro}") from erro
        # Vale o texto gravado: formatar de novo mudaria o arquivo a
        # cada leitura (a formatação é feita na digitação).
        vulnerabilidade.descricao = " ".join(descricao.split())
        return vulnerabilidade

    def __eq__(self, outro):
        """Vulnerabilidades com os mesmos dados são iguais."""
        if not isinstance(outro, Vulnerabilidade):
            return NotImplemented
        return self.para_dict() == outro.para_dict()

    def __repr__(self):
        """Texto para depuração, como Vulnerabilidade(3, CVSS 7.5)."""
        return f"Vulnerabilidade({self.id}, CVSS {self.cvss})"


# Teste: exercita a classe sem ninguém digitar nada.
if __name__ == "__main__":
    v = Vulnerabilidade(1, "porta RDP exposta na rede interna",
                        OrigemVulnerabilidade.SERVICO_EXPOSTO, 7.5)
    print(f"{v!r}: {v.descricao} | {v.gravidade.rotulo}")
    assert v.cvss == 7.5
    assert v.descricao == "Porta RDP exposta na rede interna"
    assert v.gravidade is NivelGravidade.ALTA

    # A severidade acompanha a nota, sem ninguém atualizá-la.
    v.atualizar({"cvss": 9.8})
    print(f"Depois de atualizar: {v!r} -> {v.gravidade.rotulo}")
    assert v.gravidade is NivelGravidade.CRITICA

    # Tudo ou nada: a nota inválida derruba a alteração inteira.
    try:
        v.atualizar({"descricao": "Outra", "cvss": 11})
    except ValueError as erro:
        print(f"Recusada inteira: {erro}")
    assert v.descricao == "Porta RDP exposta na rede interna"

    try:
        v.atualizar({"id": 5})
    except ValueError as erro:
        print(f"Campo protegido: {erro}")

    for ruim in (0, 0.04, 8.25, 10.5, -3, float("nan"), float("inf"),
                 "7.5", None, True):
        try:
            validar_cvss(ruim)
            raise AssertionError(f"aceitou a nota {ruim!r}")
        except ValueError:
            pass
    print("Notas inválidas (0, 8.25, 10.5, NaN, texto...) recusadas.")

    # Ida e volta pelo formato do arquivo.
    copia = Vulnerabilidade.de_dict(v.para_dict())
    assert copia == v, "a cópia lida difere da original"
    print(f"Ida e volta pelo JSON: {copia.para_dict()}")

    for nome, dados in (
            ("sem id", {"descricao": "x", "origem": 1, "cvss": 5}),
            ("origem 99", {"id": 1, "descricao": "x", "origem": 99,
                           "cvss": 5}),
            ("cvss texto", {"id": 1, "descricao": "x", "origem": 1,
                            "cvss": "alto"}),
            ("descrição nula", {"id": 1, "descricao": None, "origem": 1,
                                "cvss": 5})):
        try:
            Vulnerabilidade.de_dict(dados)
            raise AssertionError(f"aceitou o objeto adulterado: {nome}")
        except ValueError as erro:
            print(f"Recusado ({nome}): {erro}")
    print("\nOK - Vulnerabilidade exercitada.")
