"""Listas fechadas do sistema: tipos de equipamento e classificação de falhas.

Cada lista é um Enum: o valor inteiro vai para o arquivo, e o rótulo
com acento, para a tela. Atende aos requisitos 2 e 7 do Trabalho 1 e,
no Trabalho 2, liga a severidade à nota CVSS da vulnerabilidade.
"""

from enum import Enum


class TipoEquipamento(Enum):
    """Tipo de equipamento de TI, com código inteiro.

    Cada tipo tem uma subclasse de Equipamento (equipamentos.py).
    Código fora da lista levanta ValueError, que o menu trata.
    """

    ESTACAO_TRABALHO = 1
    SERVIDOR = 2
    ROTEADOR = 3
    IMPRESSORA_REDE = 4
    SISTEMA_INTERNO = 5
    BANCO_DADOS = 6
    OUTRO = 7  # para exceções; a descrição obrigatória diz o que é

    @property
    def rotulo(self):
        """Nome com acento, para mostrar na tela."""
        return _ROTULOS_TIPO[self]


# Os rótulos ficam depois de cada classe porque usam os membros dela
# como chave; a propriedade rotulo só consulta o dicionário quando é
# lida, e aí ele já existe.
_ROTULOS_TIPO = {
    TipoEquipamento.ESTACAO_TRABALHO: "Estação de trabalho",
    TipoEquipamento.SERVIDOR: "Servidor",
    TipoEquipamento.ROTEADOR: "Roteador",
    TipoEquipamento.IMPRESSORA_REDE: "Impressora de rede",
    TipoEquipamento.SISTEMA_INTERNO: "Sistema interno",
    TipoEquipamento.BANCO_DADOS: "Banco de dados",
    TipoEquipamento.OUTRO: "Outro (ver descrição)",
}


class OrigemVulnerabilidade(Enum):
    """Origem da vulnerabilidade: a categoria pedida no requisito 7."""

    ERRO_CONFIGURACAO = 1
    FALTA_ATUALIZACAO = 2
    SENHA_FRACA = 3
    SERVICO_EXPOSTO = 4
    PERMISSAO_INDEVIDA = 5
    OUTRA = 6  # a lista do enunciado é só de exemplos

    @property
    def rotulo(self):
        """Nome com acento, para mostrar na tela."""
        return _ROTULOS_ORIGEM[self]


_ROTULOS_ORIGEM = {
    OrigemVulnerabilidade.ERRO_CONFIGURACAO: "Erro de configuração",
    OrigemVulnerabilidade.FALTA_ATUALIZACAO: "Falta de atualização",
    OrigemVulnerabilidade.SENHA_FRACA: "Senha fraca",
    OrigemVulnerabilidade.SERVICO_EXPOSTO: "Serviço exposto indevidamente",
    OrigemVulnerabilidade.PERMISSAO_INDEVIDA: "Permissão de acesso inadequada",
    OrigemVulnerabilidade.OUTRA: "Outra (ver descrição)",
}


class NivelGravidade(Enum):
    """Severidade da vulnerabilidade; valor maior é mais grave.

    No Trabalho 2 o nível não é digitado: sai da nota CVSS, pela escala
    qualitativa do CVSS v3.x (do_cvss). A ordem dos valores é usada para
    ordenar e colorir.
    """

    BAIXA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4

    @property
    def rotulo(self):
        """Nome com acento, para mostrar na tela."""
        return _ROTULOS_GRAVIDADE[self]

    @classmethod
    def do_cvss(cls, nota):
        """Devolve o nível da nota CVSS (0,1 a 10,0).

        Escala do CVSS v3.x: 0,1-3,9 baixa; 4,0-6,9 média; 7,0-8,9
        alta; 9,0-10,0 crítica. A nota tem uma casa decimal, então os
        limites são testados com ">=" sem risco de uma nota cair entre
        duas faixas.
        """
        if nota >= 9.0:
            return cls.CRITICA
        if nota >= 7.0:
            return cls.ALTA
        if nota >= 4.0:
            return cls.MEDIA
        return cls.BAIXA


_ROTULOS_GRAVIDADE = {
    NivelGravidade.BAIXA: "Baixa",
    NivelGravidade.MEDIA: "Média",
    NivelGravidade.ALTA: "Alta",
    NivelGravidade.CRITICA: "Crítica",
}


class SituacaoTratamento(Enum):
    """Situação do tratamento: os quatro estados do requisito 7."""

    ABERTA = 1
    EM_TRATAMENTO = 2
    CORRIGIDA = 3
    ACEITA_COMO_RISCO = 4

    @property
    def rotulo(self):
        """Nome com acento, para mostrar na tela."""
        return _ROTULOS_SITUACAO[self]

    @property
    def pendente(self):
        """Corrigida e aceita como risco já foram decididas.

        O resto pede ação: é a base do relatório de pendentes.
        """
        return self in (SituacaoTratamento.ABERTA,
                        SituacaoTratamento.EM_TRATAMENTO)

    @property
    def conta_no_risco(self):
        """Diz se a vulnerabilidade entra na matriz M do modelo de risco.

        Só a corrigida sai: corrigir deve baixar o risco. A aceita como
        risco continua entrando, porque aceitar não elimina a falha.
        """
        return self is not SituacaoTratamento.CORRIGIDA


_ROTULOS_SITUACAO = {
    SituacaoTratamento.ABERTA: "Aberta",
    SituacaoTratamento.EM_TRATAMENTO: "Em tratamento",
    SituacaoTratamento.CORRIGIDA: "Corrigida",
    SituacaoTratamento.ACEITA_COMO_RISCO: "Aceita como risco",
}


# Teste rápido: roda só com "python classificacoes.py", nunca no import.
if __name__ == "__main__":
    for classe in (TipoEquipamento, OrigemVulnerabilidade,
                   NivelGravidade, SituacaoTratamento):
        print(f"\n--- {classe.__name__} ---")
        for item in classe:
            print(f"  {item.value} - {item.rotulo}")

    # Código inexistente levanta ValueError: é o que o menu trata.
    print("\nTeste de busca por código:")
    print("  código 2 ->", TipoEquipamento(2).rotulo)
    try:
        TipoEquipamento(99)
    except ValueError:
        print("  código 99 -> ValueError (correto: não existe)")

    # Escala qualitativa do CVSS v3.x: os limites de cada faixa.
    print("\nNota CVSS -> nível:")
    esperados = ((0.1, NivelGravidade.BAIXA), (3.9, NivelGravidade.BAIXA),
                 (4.0, NivelGravidade.MEDIA), (6.9, NivelGravidade.MEDIA),
                 (7.0, NivelGravidade.ALTA), (8.9, NivelGravidade.ALTA),
                 (9.0, NivelGravidade.CRITICA), (10.0, NivelGravidade.CRITICA))
    for nota, nivel in esperados:
        obtido = NivelGravidade.do_cvss(nota)
        print(f"  {nota:>4} -> {obtido.rotulo}")
        assert obtido is nivel, f"nota {nota}: esperava {nivel}"

    # Corrigida sai do risco; aceita como risco continua nele.
    assert not SituacaoTratamento.CORRIGIDA.conta_no_risco
    assert SituacaoTratamento.ACEITA_COMO_RISCO.conta_no_risco
    assert SituacaoTratamento.ABERTA.pendente
    assert not SituacaoTratamento.ACEITA_COMO_RISCO.pendente
    print("\nOK - classificações exercitadas.")
