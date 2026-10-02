"""A classe Equipamento e uma subclasse para cada tipo de equipamento.

Cada equipamento do inventário é um objeto individual, criado a partir
de uma das subclasses. A classe-mãe é abstrata: guarda tudo o que os
tipos têm em comum (identificação, vulnerabilidades, dependências) e
exige que cada subclasse defina o seu fator de exposição, que pondera o
risco próprio no modelo de risco (risco.py). É o polimorfismo do
trabalho: o modelo chama equipamento.fator_exposicao sem saber de qual
tipo é o objeto.

Relações (composição, sem herança):
  - vulnerabilidades: {id da vulnerabilidade: SituacaoTratamento}.
    Diz quais vulnerabilidades do catálogo afetam este equipamento e em
    que situação está o tratamento aqui.
  - dependencias: {id de outro equipamento: fração}. A fração é a
    parte do risco do outro equipamento que este herda: é uma entrada
    da linha deste equipamento na matriz A.

A classe não lê do teclado nem grava em disco.
"""

import string
from abc import ABC, abstractmethod

import formatacao
from classificacoes import SituacaoTratamento, TipoEquipamento
from validacao import (
    exigir_campo,
    exigir_enum,
    exigir_inteiro,
    exigir_lista,
    exigir_numero,
    exigir_objeto,
    exigir_texto,
)

# Regras de nome de máquina (RFC 952 e RFC 1123): letras sem acento,
# dígitos e hífen, sem hífen nas pontas, até 63 caracteres e não só
# dígitos. Ponto fica de fora porque o campo é o nome da máquina, não
# o nome completo no domínio.
_CARACTERES_HOSTNAME = set(string.ascii_letters + string.digits + "-")

# A soma das frações de dependência de um equipamento precisa ficar
# abaixo deste valor. Soma menor que 1 em cada linha de A torna I - A
# estritamente diagonal dominante, e portanto invertível.
LIMITE_SOMA_DEPENDENCIAS = 1.0

# Casas decimais guardadas nas frações: 0,3333 vale; 0,33333333 não.
CASAS_DA_FRACAO = 4

# A menor fração aceita (0,0001). Se a soma de uma linha já deixa só
# isso de sobra, não cabe mais nenhuma dependência nela.
MENOR_FRACAO = 10 ** -CASAS_DA_FRACAO


def validar_fracao(valor):
    """Devolve a fração arredondada, ou levanta ValueError.

    A fração é a parte do risco repassada: de 0 (exclusive) a 1
    (exclusive), como pede A[i][j] em [0, 1). O zero também é recusado:
    uma dependência que não repassa nada não é dependência.
    """
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ValueError(f"A fração deve ser um número, veio {valor!r}")
    fracao = round(float(valor), CASAS_DA_FRACAO)
    if not 0.0 < fracao < 1.0:
        raise ValueError(
            "A fração deve ser maior que 0 e menor que 1 "
            f"(mínimo {formatacao.fracao_br(MENOR_FRACAO)})")
    return fracao


class Equipamento(ABC):
    """Equipamento de TI: base de todos os tipos.

    Não se cria um Equipamento diretamente (a classe é abstrata): usa-se
    a subclasse do tipo, ou criar_equipamento(tipo, ...).
    """

    # Cada subclasse define o seu tipo; é o valor gravado no arquivo.
    TIPO = None

    # O id fica de fora: dependências e vínculos apontam para ele. O
    # tipo também: mudá-lo troca a classe do objeto, o que é tarefa do
    # Inventario (converter_para).
    CAMPOS_EDITAVEIS = ("hostname", "custodiante", "lotacao", "descricao")

    def __init__(self, id_equipamento, hostname, custodiante, lotacao,
                 descricao):
        """Cria o equipamento; ValueError se algum dado for inválido."""
        problema = self.problema_no_hostname(hostname)
        if problema:
            raise ValueError(f"Hostname inválido: {problema}")
        for nome, valor in (("responsável", custodiante),
                            ("lotação", lotacao),
                            ("descrição", descricao)):
            if not valor.strip():
                raise ValueError(f"O campo {nome} não pode ficar vazio")

        self.id = id_equipamento
        self.hostname = hostname.strip().upper()
        self.custodiante = formatacao.titulo(custodiante)
        self.lotacao = formatacao.titulo(lotacao)
        self.descricao = formatacao.frase(descricao)
        self.vulnerabilidades = {}
        self.dependencias = {}

    # ------------------------------------------------------------------
    # Polimorfismo: o que muda de um tipo para outro
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def fator_exposicao(self):
        """Peso do risco próprio deste tipo de equipamento (positivo).

        1,0 é a referência (a estação de trabalho). Acima de 1, o tipo
        amplia o impacto de uma vulnerabilidade; abaixo de 1, reduz.
        Os valores são didáticos e ajustáveis, e cada subclasse explica
        o seu.
        """

    @property
    def tipo(self):
        """O TipoEquipamento deste objeto."""
        return self.TIPO

    # ------------------------------------------------------------------
    # Hostname
    # ------------------------------------------------------------------

    @staticmethod
    def problema_no_hostname(hostname):
        """Devolve None se o formato do hostname é válido, ou o motivo.

        Devolve a frase em vez de levantar erro para o menu perguntar de
        novo na hora. A unicidade (nome já usado por outro equipamento)
        depende dos outros equipamentos e fica no Inventario.
        """
        h = hostname.strip()
        if not h:
            return "não pode ficar vazio"
        if len(h) > 63:
            return f"tem {len(h)} caracteres, o máximo é 63"
        invalidos = sorted(set(h) - _CARACTERES_HOSTNAME)
        if invalidos:
            mostrados = " ".join(repr(c) for c in invalidos)
            return (f"caractere(s) não permitido(s): {mostrados} - use "
                    f"apenas letras sem acento, números e hífen")
        if h[0] == "-" or h[-1] == "-":
            return "não pode começar nem terminar com hífen"
        # Depois do teste de caracteres: isdigit() aceita dígitos "²".
        if h.isdigit():
            return "não pode ser composto só de números"
        return None

    # ------------------------------------------------------------------
    # Atualização dos dados do equipamento
    # ------------------------------------------------------------------

    def atualizar(self, alteracoes):
        """Aplica as alterações {campo: valor} ao equipamento.

        Levanta ValueError em campo protegido ou valor inválido; nesse
        caso nada muda. A unicidade do hostname é conferida antes pelo
        Inventario.
        """
        for campo in alteracoes:
            if campo not in self.CAMPOS_EDITAVEIS:
                raise ValueError(f"Campo não editável: '{campo}'")

        # Valida tudo primeiro; só depois grava (tudo ou nada).
        novos = {}
        for campo, valor in alteracoes.items():
            if campo == "hostname":
                problema = self.problema_no_hostname(valor)
                if problema:
                    raise ValueError(f"Hostname inválido: {problema}")
                novos[campo] = valor.strip().upper()
                continue
            if not valor.strip():
                raise ValueError(f"O campo '{campo}' não pode ficar vazio")
            if campo == "descricao":
                novos[campo] = formatacao.frase(valor)
            else:
                novos[campo] = formatacao.titulo(valor)

        for campo, valor in novos.items():
            setattr(self, campo, valor)

    def converter_para(self, tipo):
        """Devolve um equipamento de outro tipo com os mesmos dados.

        Um objeto não muda de classe: muda-se o tipo criando outro
        objeto, da subclasse certa, com o mesmo id, os mesmos dados e as
        mesmas relações. Quem chama substitui o objeto antigo.
        """
        novo = criar_equipamento(tipo, self.id, self.hostname,
                                 self.custodiante, self.lotacao,
                                 self.descricao)
        novo.vulnerabilidades = dict(self.vulnerabilidades)
        novo.dependencias = dict(self.dependencias)
        return novo

    # ------------------------------------------------------------------
    # Vulnerabilidades (quais afetam este equipamento)
    # ------------------------------------------------------------------

    def vincular_vulnerabilidade(self, id_vulnerabilidade, situacao):
        """Registra que a vulnerabilidade afeta este equipamento."""
        if not isinstance(situacao, SituacaoTratamento):
            raise ValueError("A situação deve ser uma SituacaoTratamento")
        if id_vulnerabilidade in self.vulnerabilidades:
            raise ValueError(f"A vulnerabilidade {id_vulnerabilidade} já "
                             f"está registrada neste equipamento")
        self.vulnerabilidades[id_vulnerabilidade] = situacao

    def alterar_situacao(self, id_vulnerabilidade, situacao):
        """Muda a situação do tratamento de uma vulnerabilidade."""
        if id_vulnerabilidade not in self.vulnerabilidades:
            raise ValueError(f"A vulnerabilidade {id_vulnerabilidade} não "
                             f"está registrada neste equipamento")
        if not isinstance(situacao, SituacaoTratamento):
            raise ValueError("A situação deve ser uma SituacaoTratamento")
        self.vulnerabilidades[id_vulnerabilidade] = situacao

    def desvincular_vulnerabilidade(self, id_vulnerabilidade):
        """Remove o vínculo; devolve False se ele não existia."""
        return self.vulnerabilidades.pop(id_vulnerabilidade, None) is not None

    # ------------------------------------------------------------------
    # Dependências (linha deste equipamento na matriz A)
    # ------------------------------------------------------------------

    @property
    def soma_dependencias(self):
        """Soma das frações de dependência (a soma da linha em A)."""
        return round(sum(self.dependencias.values()), 9)

    def definir_dependencia(self, id_destino, fracao):
        """Registra que o equipamento herda parte do risco do destino.

        Se a dependência já existe, a fração é substituída. Levanta
        ValueError se o destino for o próprio equipamento (A[i][i] = 0),
        se a fração for inválida ou se a soma das frações deste
        equipamento deixasse de ser menor que 1: essa é a regra que
        garante que I - A seja invertível. Nesse caso nada muda.

        Que o destino exista é conferido pelo Inventario, que conhece os
        outros equipamentos.
        """
        if id_destino == self.id:
            raise ValueError("Um equipamento não pode depender de si "
                             "mesmo")
        fracao = validar_fracao(fracao)

        # Sem a dependência que está sendo substituída, se houver.
        outras = round(sum(f for destino, f in self.dependencias.items()
                           if destino != id_destino), 9)
        # Arredonda a soma: em ponto flutuante, 0,7 + 0,2 + 0,1 dá
        # 0,9999999999999999, que passaria no teste "< 1" por engano.
        if round(outras + fracao, 9) >= LIMITE_SOMA_DEPENDENCIAS:
            sobra = round(LIMITE_SOMA_DEPENDENCIAS - outras, 9)
            if sobra <= MENOR_FRACAO:
                raise ValueError(
                    f"A soma das frações de {self.hostname} já está em "
                    f"{formatacao.fracao_br(outras)}, sem espaço para "
                    f"outra dependência; remova uma das existentes")
            raise ValueError(
                f"A soma das frações de {self.hostname} precisa ficar "
                f"abaixo de {formatacao.fracao_br(LIMITE_SOMA_DEPENDENCIAS)}"
                f": já está em {formatacao.fracao_br(outras)}, então esta "
                f"fração deve ser menor que {formatacao.fracao_br(sobra)}")
        self.dependencias[id_destino] = fracao

    def remover_dependencia(self, id_destino):
        """Remove a dependência; devolve False se ela não existia."""
        return self.dependencias.pop(id_destino, None) is not None

    # ------------------------------------------------------------------
    # Formato do arquivo
    # ------------------------------------------------------------------

    def para_dict(self):
        """Devolve o objeto JSON do equipamento (só tipos do JSON).

        As relações viram listas de objetos, em ordem de id, para o
        arquivo sair sempre igual para os mesmos dados.
        """
        return {
            "id": self.id,
            "tipo": self.TIPO.value,
            "hostname": self.hostname,
            "custodiante": self.custodiante,
            "lotacao": self.lotacao,
            "descricao": self.descricao,
            "vulnerabilidades": [
                {"id": id_vuln, "situacao": situacao.value}
                for id_vuln, situacao in sorted(self.vulnerabilidades.items())
            ],
            "dependencias": [
                {"equipamento_id": destino, "fracao": fracao}
                for destino, fracao in sorted(self.dependencias.items())
            ],
        }

    @staticmethod
    def de_dict(dados):
        """Reconstrói um equipamento a partir do objeto do arquivo.

        Devolve um objeto da subclasse que o campo "tipo" indica.
        Levanta ValueError, com a localização do problema, se o objeto
        estiver fora do formato. Confere cada objeto isoladamente; que
        os ids apontados existam é conferido pelo Inventario.

        A regra "soma das frações < 1" não é imposta aqui, de propósito:
        um arquivo editado à mão pode violá-la, e quem decide o que
        fazer com uma matriz não invertível é o modelo de risco, que
        avisa o usuário (veja ModeloRisco.diagnosticar).
        """
        exigir_objeto(dados, "equipamento")
        id_eq = exigir_inteiro(exigir_campo(dados, "id", "equipamento"),
                               "equipamento: campo 'id'", minimo=1)
        nome = f"equipamento {id_eq}"
        tipo = exigir_enum(TipoEquipamento,
                           exigir_campo(dados, "tipo", nome),
                           f"{nome}: campo 'tipo'")
        textos = {}
        for campo in ("hostname", "custodiante", "lotacao", "descricao"):
            textos[campo] = exigir_texto(exigir_campo(dados, campo, nome),
                                         f"{nome}: campo '{campo}'")
        try:
            equipamento = criar_equipamento(tipo, id_eq, **textos)
        except ValueError as erro:
            raise ValueError(f"{nome}: {erro}") from erro
        # O texto gravado já passou pela formatação quando foi digitado.
        # Formatar de novo mudaria o que está no arquivo a cada leitura
        # ("TI Setor" -> "Ti setor"), então vale o que veio, só sem
        # espaços repetidos.
        for campo in ("custodiante", "lotacao", "descricao"):
            setattr(equipamento, campo, " ".join(textos[campo].split()))

        lista = exigir_lista(
            exigir_campo(dados, "vulnerabilidades", nome),
            f"{nome}: campo 'vulnerabilidades'")
        for posicao, item in enumerate(lista, start=1):
            rotulo = f"{nome}: vulnerabilidade nº {posicao}"
            exigir_objeto(item, rotulo)
            id_vuln = exigir_inteiro(exigir_campo(item, "id", rotulo),
                                     f"{rotulo}: campo 'id'", minimo=1)
            situacao = exigir_enum(SituacaoTratamento,
                                   exigir_campo(item, "situacao", rotulo),
                                   f"{rotulo}: campo 'situacao'")
            if id_vuln in equipamento.vulnerabilidades:
                raise ValueError(f"{nome}: vulnerabilidade {id_vuln} "
                                 f"repetida")
            equipamento.vulnerabilidades[id_vuln] = situacao

        lista = exigir_lista(
            exigir_campo(dados, "dependencias", nome),
            f"{nome}: campo 'dependencias'")
        for posicao, item in enumerate(lista, start=1):
            rotulo = f"{nome}: dependência nº {posicao}"
            exigir_objeto(item, rotulo)
            destino = exigir_inteiro(
                exigir_campo(item, "equipamento_id", rotulo),
                f"{rotulo}: campo 'equipamento_id'", minimo=1)
            fracao = exigir_numero(exigir_campo(item, "fracao", rotulo),
                                   f"{rotulo}: campo 'fracao'")
            if destino == id_eq:
                raise ValueError(f"{rotulo}: um equipamento não pode "
                                 f"depender de si mesmo")
            if destino in equipamento.dependencias:
                raise ValueError(f"{nome}: dependência de {destino} "
                                 f"repetida")
            try:
                equipamento.dependencias[destino] = validar_fracao(fracao)
            except ValueError as erro:
                raise ValueError(f"{rotulo}: {erro}") from erro
        return equipamento

    def __eq__(self, outro):
        """Dois equipamentos são iguais se tiverem os mesmos dados."""
        if not isinstance(outro, Equipamento):
            return NotImplemented
        return self.para_dict() == outro.para_dict()

    def __repr__(self):
        """Texto para depuração, como Servidor(1, 'DRPC-SRV01')."""
        return f"{type(self).__name__}({self.id}, {self.hostname!r})"


# ----------------------------------------------------------------------
# Um tipo de equipamento por subclasse
# ----------------------------------------------------------------------

class EstacaoTrabalho(Equipamento):
    """Computador de uso individual."""

    TIPO = TipoEquipamento.ESTACAO_TRABALHO

    @property
    def fator_exposicao(self):
        """1,0: a referência. Atinge o usuário e o que ele acessa."""
        return 1.0


class Servidor(Equipamento):
    """Servidor de arquivos, de domínio ou de aplicação."""

    TIPO = TipoEquipamento.SERVIDOR

    @property
    def fator_exposicao(self):
        """1,5: concentra serviços e dados de muitos usuários."""
        return 1.5


class Roteador(Equipamento):
    """Roteador ou outro equipamento de borda de rede."""

    TIPO = TipoEquipamento.ROTEADOR

    @property
    def fator_exposicao(self):
        """1,2: por ele passa o tráfego de toda a unidade."""
        return 1.2


class ImpressoraRede(Equipamento):
    """Impressora ou multifuncional ligada à rede."""

    TIPO = TipoEquipamento.IMPRESSORA_REDE

    @property
    def fator_exposicao(self):
        """0,5: alcance limitado, mas guarda cópias digitalizadas."""
        return 0.5


class SistemaInterno(Equipamento):
    """Sistema de informação interno, como o REDS ou o PCNet."""

    TIPO = TipoEquipamento.SISTEMA_INTERNO

    @property
    def fator_exposicao(self):
        """1,4: acessa dados sensíveis de inquéritos e ocorrências."""
        return 1.4


class BancoDados(Equipamento):
    """Banco de dados."""

    TIPO = TipoEquipamento.BANCO_DADOS

    @property
    def fator_exposicao(self):
        """2,0: o dado sensível se concentra aqui, o impacto dobra."""
        return 2.0


class OutroEquipamento(Equipamento):
    """Equipamento fora dos tipos acima; a descrição diz o que é."""

    TIPO = TipoEquipamento.OUTRO

    @property
    def fator_exposicao(self):
        """1,0: sem informação do tipo, vale a referência."""
        return 1.0


# Tipo -> classe: ligar um tipo novo é uma subclasse e uma linha aqui.
CLASSE_DO_TIPO = {
    classe.TIPO: classe
    for classe in (EstacaoTrabalho, Servidor, Roteador, ImpressoraRede,
                   SistemaInterno, BancoDados, OutroEquipamento)
}


def criar_equipamento(tipo, id_equipamento, hostname, custodiante, lotacao,
                      descricao):
    """Cria o objeto da subclasse que corresponde ao tipo.

    É a única função que conhece a tabela CLASSE_DO_TIPO: o resto do
    programa pede um equipamento "do tipo X" sem saber qual classe usar.
    """
    classe = CLASSE_DO_TIPO.get(tipo)
    if classe is None:
        raise ValueError(f"Tipo de equipamento sem classe: {tipo!r}")
    return classe(id_equipamento, hostname, custodiante, lotacao,
                  descricao)


# Teste: exercita a classe sem ninguém digitar nada.
if __name__ == "__main__":
    # --- Uma subclasse para cada tipo, e o polimorfismo ---------------
    assert set(CLASSE_DO_TIPO) == set(TipoEquipamento), \
        "algum tipo ficou sem classe"
    try:
        Equipamento(1, "PC-01", "A", "B", "C")
        raise AssertionError("a classe abstrata foi instanciada")
    except TypeError as erro:
        print(f"Equipamento é abstrata: {erro}")

    print("\nFator de exposição por tipo (polimorfismo):")
    for tipo in TipoEquipamento:
        objeto = criar_equipamento(tipo, 1, "TESTE-01", "Fulano", "Setor",
                                   "Descrição")
        print(f"  {type(objeto).__name__:16} {objeto.fator_exposicao}")
        assert objeto.fator_exposicao > 0
        assert objeto.tipo is tipo

    # --- Dados e normalização -----------------------------------------
    srv = criar_equipamento(TipoEquipamento.SERVIDOR, 2, " srv-arquivo ",
                            "chefe de equipe", "SALA TÉCNICA",
                            "servidor de arquivos")
    print(f"\n{srv!r} | {srv.custodiante} | {srv.lotacao} | {srv.descricao}")
    assert srv.hostname == "SRV-ARQUIVO"
    assert srv.custodiante == "Chefe de Equipe"
    assert srv.lotacao == "Sala Técnica"

    for ruim in ("pc cartorio", "pc/cartorio", "-pc", "pc-", "12345",
                 "pcção", ""):
        try:
            criar_equipamento(TipoEquipamento.SERVIDOR, 9, ruim, "X", "Y",
                              "Z")
            raise AssertionError(f"aceitou hostname inválido: {ruim!r}")
        except ValueError as erro:
            print(f"Recusado {ruim!r:15} {erro}")
    assert Equipamento.problema_no_hostname("10-ANDAR") is None

    # Tudo ou nada na atualização.
    try:
        srv.atualizar({"custodiante": "Outro", "hostname": "pc cartorio"})
    except ValueError as erro:
        print(f"Atualização recusada inteira: {erro}")
    assert srv.custodiante == "Chefe de Equipe", "mudou pela metade"
    try:
        srv.atualizar({"id": 50})
    except ValueError as erro:
        print(f"Campo protegido: {erro}")
    srv.atualizar({"custodiante": "investigador de plantão"})
    assert srv.custodiante == "Investigador de Plantão"

    # --- Vulnerabilidades ---------------------------------------------
    srv.vincular_vulnerabilidade(7, SituacaoTratamento.ABERTA)
    try:
        srv.vincular_vulnerabilidade(7, SituacaoTratamento.ABERTA)
    except ValueError as erro:
        print(f"\nVínculo repetido recusado: {erro}")
    srv.alterar_situacao(7, SituacaoTratamento.CORRIGIDA)
    assert srv.vulnerabilidades == {7: SituacaoTratamento.CORRIGIDA}
    assert srv.desvincular_vulnerabilidade(7) is True
    assert srv.desvincular_vulnerabilidade(7) is False

    # --- Dependências: a regra da soma < 1 ----------------------------
    print("\nDependências de SRV-ARQUIVO (id 2):")
    srv.definir_dependencia(3, 0.5)
    try:
        srv.definir_dependencia(4, 0.5)   # 0,5 + 0,5 = 1: não vale
        raise AssertionError("aceitou soma igual a 1")
    except ValueError as erro:
        print(f"  soma 1,0 recusada: {erro}")
    srv.definir_dependencia(4, 0.49)      # 0,99: vale
    assert srv.soma_dependencias == 0.99
    srv.definir_dependencia(3, 0.3)       # substitui; sobra espaço
    assert srv.dependencias == {3: 0.3, 4: 0.49}
    for fracao in (0, 1, 1.5, -0.2, float("nan"), "0.3", True):
        try:
            srv.definir_dependencia(5, fracao)
            raise AssertionError(f"aceitou a fração {fracao!r}")
        except ValueError:
            pass
    try:
        srv.definir_dependencia(2, 0.1)   # de si mesmo
        raise AssertionError("aceitou dependência de si mesmo")
    except ValueError as erro:
        print(f"  auto-dependência recusada: {erro}")
    # 0,7 + 0,2 + 0,1 dá 0,9999999999999999 em ponto flutuante: sem o
    # arredondamento da soma, a regra "< 1" deixaria passar.
    assert 0.7 + 0.2 + 0.1 < 1, "o exemplo de erro de ponto flutuante mudou"
    outro = criar_equipamento(TipoEquipamento.ROTEADOR, 6, "RT-01", "X",
                              "Y", "Z")
    outro.definir_dependencia(1, 0.7)
    outro.definir_dependencia(2, 0.2)
    try:
        outro.definir_dependencia(3, 0.1)
        raise AssertionError("0,7 + 0,2 + 0,1 passou pela regra da soma")
    except ValueError:
        print("  0,7 + 0,2 + 0,1 recusado (a soma é 1, mesmo que o float "
              "dê 0,9999999999999999)")
    # Sobra de 0,0001: não cabe nenhuma fração (a menor é 0,0001).
    quase = criar_equipamento(TipoEquipamento.ROTEADOR, 7, "RT-02", "X",
                              "Y", "Z")
    quase.definir_dependencia(1, 0.9999)
    try:
        quase.definir_dependencia(2, 0.0001)
        raise AssertionError("aceitou dependência sem espaço na linha")
    except ValueError as erro:
        assert "sem espaço" in str(erro), erro
    assert srv.remover_dependencia(3) is True
    assert srv.remover_dependencia(3) is False

    # --- Mudança de tipo: outro objeto, mesmos dados ------------------
    srv.vincular_vulnerabilidade(8, SituacaoTratamento.ABERTA)
    banco = srv.converter_para(TipoEquipamento.BANCO_DADOS)
    print(f"\n{srv!r} virou {banco!r}; fator {srv.fator_exposicao} -> "
          f"{banco.fator_exposicao}")
    assert isinstance(banco, BancoDados) and banco.id == srv.id
    assert banco.vulnerabilidades == srv.vulnerabilidades
    assert banco.dependencias == srv.dependencias
    assert banco.dependencias is not srv.dependencias, "dict compartilhado"

    # --- Ida e volta pelo formato do arquivo --------------------------
    for tipo in TipoEquipamento:
        original = criar_equipamento(tipo, 3, "EQ-01", "Fulano", "Setor",
                                     "Descrição")
        original.vulnerabilidades = {4: SituacaoTratamento.EM_TRATAMENTO}
        original.dependencias = {1: 0.25, 2: 0.5}
        copia = Equipamento.de_dict(original.para_dict())
        assert type(copia) is type(original), "voltou com outra classe"
        assert copia == original, "a cópia lida difere da original"
    print("Ida e volta pelo JSON: as 7 subclasses voltam como eram.")
    print(f"Exemplo: {srv.para_dict()}")

    # --- Objetos adulterados ------------------------------------------
    base = srv.para_dict()
    adulterados = {
        "sem tipo": {k: v for k, v in base.items() if k != "tipo"},
        "tipo 99": dict(base, tipo=99),
        "hostname com espaço": dict(base, hostname="PC 01"),
        "ESC no texto": dict(base, descricao="ok\u001b[2J"),
        "vulnerabilidades nulas": dict(base, vulnerabilidades=None),
        "vulnerabilidade repetida": dict(base, vulnerabilidades=[
            {"id": 1, "situacao": 1}, {"id": 1, "situacao": 2}]),
        "situação 9": dict(base, vulnerabilidades=[
            {"id": 1, "situacao": 9}]),
        "fração 1": dict(base, dependencias=[
            {"equipamento_id": 1, "fracao": 1}]),
        "fração em texto": dict(base, dependencias=[
            {"equipamento_id": 1, "fracao": "0,3"}]),
        "dependência de si mesmo": dict(base, dependencias=[
            {"equipamento_id": base["id"], "fracao": 0.2}]),
        "dependência repetida": dict(base, dependencias=[
            {"equipamento_id": 1, "fracao": 0.2},
            {"equipamento_id": 1, "fracao": 0.3}]),
        "id 0": dict(base, id=0),
        "id decimal": dict(base, id=2.0),
    }
    print()
    for nome, objeto in adulterados.items():
        try:
            Equipamento.de_dict(objeto)
            raise AssertionError(f"aceitou o objeto adulterado: {nome}")
        except ValueError as erro:
            print(f"Recusado ({nome}): {erro}")
    print("\nOK - Equipamento e as 7 subclasses exercitados.")
