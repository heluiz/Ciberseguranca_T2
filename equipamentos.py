"""A classe Equipamento e uma subclasse para cada tipo de equipamento.

Cada equipamento do inventário é um objeto individual, criado a partir
de uma das subclasses. A classe-mãe é abstrata: guarda tudo o que os
tipos têm em comum (identificação, vulnerabilidades, dependências) e
exige que cada subclasse defina o seu fator de exposição, que pondera o
risco próprio no modelo de risco (risco.py). É o polimorfismo do
trabalho: o modelo chama equipamento.fator_exposicao sem saber de qual
tipo é o objeto.

Relações (composição, sem herança):
  - ficha: a FichaTecnica (fabricante, modelo, série, patrimônio,
    sistema e versão), toda opcional.
  - vulnerabilidades: {id da vulnerabilidade: SituacaoTratamento}.
    Diz quais vulnerabilidades do catálogo afetam este equipamento e em
    que situação está o tratamento aqui.
  - dependencias: {id de outro equipamento: fração}. A fração é a
    parte do risco do outro equipamento que este herda: é uma entrada
    da linha deste equipamento na matriz A.

Encapsulamento: os dados ficam em atributos privados (dois sublinhados)
e são acessados pelas propriedades. Cada setter confere e padroniza o
valor, então um dado inválido não entra nem por atribuição direta
(equipamento.hostname = "PC 01" levanta ValueError). O id não muda. As
vulnerabilidades e as dependências chegam a quem está fora da classe só
para leitura e mudam pelos métodos, que conferem as regras: a soma das
frações menor que 1, que garante que I - A é invertível, não pode ser
contornada.

A classe não lê do teclado nem grava em disco.
"""

import string
from abc import ABC, abstractmethod
from types import MappingProxyType

import formatacao
from classificacoes import SituacaoTratamento, TipoEquipamento
from ficha_tecnica import FichaTecnica
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

# Os campos de texto obrigatórios além do hostname: o nome usado nas
# mensagens e a padronização aplicada ao que é digitado.
_CAMPOS_DE_TEXTO = {
    "custodiante": ("responsável", formatacao.titulo),
    "lotacao": ("lotação", formatacao.titulo),
    "descricao": ("descrição", formatacao.frase),
}

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
    a subclasse do tipo, ou criar_equipamento(tipo, ...). Os dados são
    lidos e alterados pelas propriedades, que conferem cada valor (veja
    o encapsulamento, no começo do módulo).
    """

    # Cada subclasse define o seu tipo; é o valor gravado no arquivo.
    TIPO = None

    # O id fica de fora: dependências e vínculos apontam para ele. O
    # tipo também: mudá-lo troca a classe do objeto, o que é tarefa do
    # Inventario (converter_para).
    CAMPOS_EDITAVEIS = ("hostname", "custodiante", "lotacao", "descricao")

    def __init__(self, id_equipamento, hostname, custodiante, lotacao,
                 descricao):
        """Cria o equipamento; ValueError se algum dado for inválido.

        Os quatro textos passam pelos setters das propriedades, que
        conferem e padronizam cada um.
        """
        self.__id = id_equipamento
        self.hostname = hostname
        self.custodiante = custodiante
        self.lotacao = lotacao
        self.descricao = descricao
        self.__ficha = FichaTecnica()
        self.__vulnerabilidades = {}
        self.__dependencias = {}

    # ------------------------------------------------------------------
    # Encapsulamento: os dados, pelas propriedades
    # ------------------------------------------------------------------

    @property
    def id(self):
        """O identificador. Não muda: vínculos e dependências o usam."""
        return self.__id

    @property
    def hostname(self):
        """O nome da máquina, em maiúsculas."""
        return self.__hostname

    @hostname.setter
    def hostname(self, valor):
        self.__hostname = self._padronizar("hostname", valor)

    @property
    def custodiante(self):
        """O responsável: de preferência o cargo ou o setor (LGPD)."""
        return self.__custodiante

    @custodiante.setter
    def custodiante(self, valor):
        self.__custodiante = self._padronizar("custodiante", valor)

    @property
    def lotacao(self):
        """O setor onde o equipamento está."""
        return self.__lotacao

    @lotacao.setter
    def lotacao(self, valor):
        self.__lotacao = self._padronizar("lotacao", valor)

    @property
    def descricao(self):
        """Para que serve o equipamento."""
        return self.__descricao

    @descricao.setter
    def descricao(self, valor):
        self.__descricao = self._padronizar("descricao", valor)

    @property
    def ficha(self):
        """A FichaTecnica do equipamento (composição)."""
        return self.__ficha

    @ficha.setter
    def ficha(self, nova):
        if not isinstance(nova, FichaTecnica):
            raise ValueError("A ficha técnica deve ser uma FichaTecnica")
        self.__ficha = nova

    @property
    def vulnerabilidades(self):
        """{id da vulnerabilidade: situação}, só para leitura.

        Muda pelos métodos vincular_vulnerabilidade, alterar_situacao e
        desvincular_vulnerabilidade, que conferem os dados.
        """
        return MappingProxyType(self.__vulnerabilidades)

    @property
    def dependencias(self):
        """{id do equipamento de que este depende: fração}, só leitura.

        Muda por definir_dependencia, que confere a regra da soma das
        frações, e por remover_dependencia.
        """
        return MappingProxyType(self.__dependencias)

    @staticmethod
    def _padronizar(campo, valor):
        """Confere o valor de um campo de texto e o devolve padronizado.

        Levanta ValueError se ele for inválido. Os setters e o
        atualizar() usam a mesma regra. A unicidade do hostname depende
        dos outros equipamentos e fica no Inventario.
        """
        if campo == "hostname":
            if not isinstance(valor, str):
                raise ValueError("O hostname deve ser um texto")
            problema = Equipamento.problema_no_hostname(valor)
            if problema:
                raise ValueError(f"Hostname inválido: {problema}")
            return valor.strip().upper()
        rotulo, padronizar = _CAMPOS_DE_TEXTO[campo]
        if not isinstance(valor, str):
            raise ValueError(f"O campo {rotulo} deve ser um texto")
        if not valor.strip():
            raise ValueError(f"O campo {rotulo} não pode ficar vazio")
        return padronizar(valor)

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
        caso nada muda (tudo ou nada): todos os valores são conferidos
        antes de o primeiro ser gravado pelo setter. A unicidade do
        hostname é conferida antes pelo Inventario.
        """
        for campo in alteracoes:
            if campo not in self.CAMPOS_EDITAVEIS:
                raise ValueError(f"Campo não editável: '{campo}'")
        for campo, valor in alteracoes.items():
            self._padronizar(campo, valor)
        for campo, valor in alteracoes.items():
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
        novo.copiar_dados_de(self)
        return novo

    def copiar_dados_de(self, outro):
        """Copia de outro equipamento os textos, a ficha e as relações.

        Os textos vêm como estão: padronizar de novo poderia mudar o que
        veio do arquivo ("NOC" viraria "Noc"). A ficha e os dicionários
        são copiados, e não compartilhados. O id e o tipo não mudam. Só
        vale de outro Equipamento, cujos dados já foram conferidos.
        """
        if not isinstance(outro, Equipamento):
            raise ValueError("Os dados só podem vir de outro Equipamento")
        self.__hostname = outro.hostname
        self.__custodiante = outro.custodiante
        self.__lotacao = outro.lotacao
        self.__descricao = outro.descricao
        self.__ficha = outro.ficha.copia()
        self.__vulnerabilidades = dict(outro.vulnerabilidades)
        self.__dependencias = dict(outro.dependencias)

    # ------------------------------------------------------------------
    # Vulnerabilidades (quais afetam este equipamento)
    # ------------------------------------------------------------------

    def vincular_vulnerabilidade(self, id_vulnerabilidade, situacao):
        """Registra que a vulnerabilidade afeta este equipamento."""
        if not isinstance(situacao, SituacaoTratamento):
            raise ValueError("A situação deve ser uma SituacaoTratamento")
        if id_vulnerabilidade in self.__vulnerabilidades:
            raise ValueError(f"A vulnerabilidade {id_vulnerabilidade} já "
                             f"está registrada neste equipamento")
        self.__vulnerabilidades[id_vulnerabilidade] = situacao

    def alterar_situacao(self, id_vulnerabilidade, situacao):
        """Muda a situação do tratamento de uma vulnerabilidade."""
        if id_vulnerabilidade not in self.__vulnerabilidades:
            raise ValueError(f"A vulnerabilidade {id_vulnerabilidade} não "
                             f"está registrada neste equipamento")
        if not isinstance(situacao, SituacaoTratamento):
            raise ValueError("A situação deve ser uma SituacaoTratamento")
        self.__vulnerabilidades[id_vulnerabilidade] = situacao

    def desvincular_vulnerabilidade(self, id_vulnerabilidade):
        """Remove o vínculo; devolve False se ele não existia."""
        return (self.__vulnerabilidades.pop(id_vulnerabilidade, None)
                is not None)

    # ------------------------------------------------------------------
    # Dependências (linha deste equipamento na matriz A)
    # ------------------------------------------------------------------

    @property
    def soma_dependencias(self):
        """Soma das frações de dependência (a soma da linha em A)."""
        return round(sum(self.__dependencias.values()), 9)

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
        outras = round(sum(f for destino, f in self.__dependencias.items()
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
        self.__dependencias[id_destino] = fracao

    def remover_dependencia(self, id_destino):
        """Remove a dependência; devolve False se ela não existia."""
        return self.__dependencias.pop(id_destino, None) is not None

    # ------------------------------------------------------------------
    # Formato do arquivo
    # ------------------------------------------------------------------

    def para_dict(self):
        """Devolve o objeto JSON do equipamento (só tipos do JSON).

        As relações viram listas de objetos, em ordem de id, para o
        arquivo sair sempre igual para os mesmos dados. A ficha técnica
        só aparece quando tem algum campo: um arquivo sem fichas fica
        igual ao de antes de ela existir.
        """
        objeto = {
            "id": self.id,
            "tipo": self.TIPO.value,
            "hostname": self.hostname,
            "custodiante": self.custodiante,
            "lotacao": self.lotacao,
            "descricao": self.descricao,
        }
        if not self.ficha.vazia:
            objeto["ficha"] = self.ficha.para_dict()
        objeto["vulnerabilidades"] = [
            {"id": id_vuln, "situacao": situacao.value}
            for id_vuln, situacao in sorted(self.vulnerabilidades.items())]
        objeto["dependencias"] = [
            {"equipamento_id": destino, "fracao": fracao}
            for destino, fracao in sorted(self.dependencias.items())]
        return objeto

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
        # Daqui em diante o próprio Equipamento monta o objeto lido,
        # direto nos atributos privados: o arquivo vale como está. O
        # pylint não reconhece o objeto como da própria classe.
        # pylint: disable=protected-access,unused-private-member
        # O texto gravado já passou pela formatação quando foi digitado.
        # Formatar de novo mudaria o que está no arquivo a cada leitura
        # ("TI Setor" -> "Ti setor"), então vale o que veio, só sem
        # espaços repetidos.
        equipamento.__custodiante = " ".join(textos["custodiante"].split())
        equipamento.__lotacao = " ".join(textos["lotacao"].split())
        equipamento.__descricao = " ".join(textos["descricao"].split())
        # Campo opcional: ausente ou null quer dizer ficha vazia.
        if dados.get("ficha") is not None:
            equipamento.ficha = FichaTecnica.de_dict(
                dados["ficha"], f"{nome}: campo 'ficha'")

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
            if id_vuln in equipamento.__vulnerabilidades:
                raise ValueError(f"{nome}: vulnerabilidade {id_vuln} "
                                 f"repetida")
            equipamento.__vulnerabilidades[id_vuln] = situacao

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
            if destino in equipamento.__dependencias:
                raise ValueError(f"{nome}: dependência de {destino} "
                                 f"repetida")
            try:
                # Direto no dicionário: o arquivo pode violar a regra da
                # soma, e quem trata é o modelo de risco.
                equipamento.__dependencias[destino] = validar_fracao(fracao)
            except ValueError as erro:
                raise ValueError(f"{rotulo}: {erro}") from erro
        return equipamento

    def __eq__(self, outro):
        """Dois equipamentos são iguais se tiverem os mesmos dados."""
        if not isinstance(outro, Equipamento):
            return NotImplemented
        return self.para_dict() == outro.para_dict()

    def __str__(self):
        """Texto para a tela, como [1] DRPC-SRV01 - Servidor."""
        return f"[{self.id}] {self.hostname} - {self.tipo.rotulo}"

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
    srv.ficha.atualizar({"fabricante": "Dell", "patrimonio": "123456"})
    banco = srv.converter_para(TipoEquipamento.BANCO_DADOS)
    print(f"\n{srv!r} virou {banco!r}; fator {srv.fator_exposicao} -> "
          f"{banco.fator_exposicao}")
    assert isinstance(banco, BancoDados) and banco.id == srv.id
    assert banco.vulnerabilidades == srv.vulnerabilidades
    assert banco.dependencias == srv.dependencias
    alvo = next(iter(srv.dependencias))
    banco.remover_dependencia(alvo)
    assert alvo in srv.dependencias, "dicionário compartilhado"
    assert banco.ficha == srv.ficha and banco.ficha is not srv.ficha

    # --- Ida e volta pelo formato do arquivo --------------------------
    for tipo in TipoEquipamento:
        original = criar_equipamento(tipo, 3, "EQ-01", "Fulano", "Setor",
                                     "Descrição")
        original.vincular_vulnerabilidade(4, SituacaoTratamento.EM_TRATAMENTO)
        original.definir_dependencia(1, 0.25)
        original.definir_dependencia(2, 0.5)
        original.ficha.atualizar({"modelo": "Modelo X"})
        copia = Equipamento.de_dict(original.para_dict())
        assert type(copia) is type(original), "voltou com outra classe"
        assert copia == original, "a cópia lida difere da original"
    print("Ida e volta pelo JSON: as 7 subclasses voltam como eram.")
    sem_ficha = criar_equipamento(TipoEquipamento.OUTRO, 4, "EQ-02", "A",
                                  "B", "C")
    assert "ficha" not in sem_ficha.para_dict(), "ficha vazia gravada"
    assert Equipamento.de_dict(dict(sem_ficha.para_dict(),
                                    ficha=None)).ficha.vazia
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
        "ficha com campo desconhecido": dict(base, ficha={"cor": "preta"}),
        "ficha que não é objeto": dict(base, ficha="Dell"),
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
