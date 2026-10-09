"""A classe Vulnerabilidade: um item do catálogo de vulnerabilidades.

Uma vulnerabilidade existe uma vez só, com a descrição, a origem, a
nota CVSS e, se houver, o vetor CVSS de onde a nota saiu, e pode
afetar vários equipamentos. Quem diz quais é o
próprio equipamento (equipamentos.py), junto com a situação do
tratamento naquele equipamento. É essa relação "equipamento i tem a
vulnerabilidade j" que vira a matriz M do modelo de risco (risco.py).

A classe não lê do teclado nem grava em disco.
"""

import math

import formatacao
from calculadora_cvss import analisar_vetor
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


def conferir_vetor(vetor, nota):
    """Devolve o vetor CVSS arrumado, se ele der exatamente a nota.

    Levanta ValueError se o vetor for inválido ou se a nota for outra:
    com vetor, a nota é a que ele dá, e as duas nunca discordam.
    """
    arrumado, nota_do_vetor = analisar_vetor(vetor)
    if nota_do_vetor != nota:
        raise ValueError(
            f"A nota {formatacao.numero_br(nota)} não confere com o vetor "
            f"CVSS, que dá {formatacao.numero_br(nota_do_vetor)}")
    return arrumado


class Vulnerabilidade:
    """Vulnerabilidade do catálogo: descrição, origem e nota CVSS.

    A severidade (baixa, média, alta, crítica) não é guardada: é
    calculada da nota quando pedida, para as duas nunca discordarem.
    O vetor CVSS é opcional; quando existe, a nota é a que ele dá.
    """

    # O id fica de fora: os equipamentos apontam para ele.
    CAMPOS_EDITAVEIS = ("descricao", "origem", "cvss", "vetor")

    def __init__(self, id_vulnerabilidade, descricao, origem, cvss,
                 vetor=None):
        """Cria a vulnerabilidade; dado inválido levanta ValueError."""
        if not isinstance(origem, OrigemVulnerabilidade):
            raise ValueError("A origem deve ser uma OrigemVulnerabilidade")
        if not descricao.strip():
            raise ValueError("A descrição não pode ficar vazia")
        nota = validar_cvss(cvss)
        if vetor is not None:
            vetor = conferir_vetor(vetor, nota)
        self.id = id_vulnerabilidade
        self.descricao = formatacao.frase(descricao)
        self.origem = origem
        self.cvss = nota
        self.vetor = vetor

    @property
    def gravidade(self):
        """Nível de severidade, derivado da nota CVSS."""
        return NivelGravidade.do_cvss(self.cvss)

    def atualizar(self, alteracoes):
        """Aplica as alterações {campo: valor} à vulnerabilidade.

        "vetor" com um texto troca o vetor e a nota passa a ser a dele;
        "vetor" None tira o vetor. Levanta ValueError em campo
        protegido, valor inválido ou nota que não confere com o vetor
        que fica; nesse caso nada muda: a validação termina antes de
        qualquer atribuição.
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
        novos["cvss"], novos["vetor"] = self._nota_e_vetor(alteracoes)

        for campo, valor in novos.items():
            setattr(self, campo, valor)

    def _nota_e_vetor(self, alteracoes):
        """Devolve a nota e o vetor que ficam depois das alterações.

        Um vetor novo dá a nota; uma nota digitada vale se não houver
        vetor ou se for a mesma que o vetor que fica dá.
        """
        vetor = alteracoes.get("vetor", self.vetor)
        nota = self.cvss
        if alteracoes.get("vetor") is not None:
            vetor, nota = analisar_vetor(vetor)
        if "cvss" in alteracoes:
            nota = alteracoes["cvss"]
        nota = validar_cvss(nota)
        if vetor is not None:
            vetor = conferir_vetor(vetor, nota)
        return nota, vetor

    def para_dict(self):
        """Devolve o objeto JSON da vulnerabilidade (só tipos JSON).

        O campo "vetor" só aparece quando existe: um arquivo sem
        vetores fica igual ao de antes deste campo existir.
        """
        objeto = {
            "id": self.id,
            "descricao": self.descricao,
            "origem": self.origem.value,
            "cvss": self.cvss,
        }
        if self.vetor is not None:
            objeto["vetor"] = self.vetor
        return objeto

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
        # Campo opcional: ausente ou null quer dizer "sem vetor".
        vetor = dados.get("vetor")
        if vetor is not None:
            vetor = exigir_texto(vetor, f"{nome}: campo 'vetor'")
        try:
            vulnerabilidade = cls(id_vuln, descricao, origem, cvss, vetor)
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

    # Com vetor, a nota é a que ele dá; nota digitada tira o vetor.
    rdp = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v.atualizar({"vetor": rdp})
    assert (v.cvss, v.vetor) == (9.8, rdp)
    try:
        Vulnerabilidade(2, "x", OrigemVulnerabilidade.OUTRA, 7.0, rdp)
        raise AssertionError("aceitou nota que não confere com o vetor")
    except ValueError as erro:
        print(f"Nota contra o vetor: {erro}")
    try:
        v.atualizar({"cvss": 7.0})
        raise AssertionError("aceitou nota diferente com o vetor mantido")
    except ValueError:
        assert v.cvss == 9.8
    v.atualizar({"cvss": 7.0, "vetor": None})
    assert (v.cvss, v.vetor) == (7.0, None)
    v.atualizar({"vetor": rdp})
    print(f"Pelo vetor: {v.para_dict()}")

    # "vetor": null no arquivo vale como sem vetor.
    sem_vetor = Vulnerabilidade.de_dict({"id": 3, "descricao": "x",
                                         "origem": 1, "cvss": 5.0,
                                         "vetor": None})
    assert sem_vetor.vetor is None and "vetor" not in sem_vetor.para_dict()

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
                                "cvss": 5}),
            ("vetor contra a nota", {"id": 1, "descricao": "x",
                                     "origem": 1, "cvss": 5.0,
                                     "vetor": rdp}),
            ("vetor número", {"id": 1, "descricao": "x", "origem": 1,
                              "cvss": 5.0, "vetor": 5})):
        try:
            Vulnerabilidade.de_dict(dados)
            raise AssertionError(f"aceitou o objeto adulterado: {nome}")
        except ValueError as erro:
            print(f"Recusado ({nome}): {erro}")
    print("\nOK - Vulnerabilidade exercitada.")
