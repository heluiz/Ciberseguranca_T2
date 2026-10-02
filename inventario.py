"""A classe Inventario: o conjunto dos equipamentos e das vulnerabilidades.

Coordena as regras que envolvem mais de um objeto: hostname único,
exclusão em cascata, vulnerabilidades compartilhadas entre
equipamentos e dependências que apontam para equipamentos que existem.
Os equipamentos ficam num dicionário (id -> objeto), o que torna a
busca por id direta; o formato do arquivo, uma lista de objetos JSON,
só aparece em para_dict() e de_dict().

Como as demais classes, não lê do teclado nem grava em disco.
"""

from collections import namedtuple

import formatacao
from classificacoes import SituacaoTratamento, TipoEquipamento
from equipamentos import Equipamento, criar_equipamento
from validacao import (
    exigir_campo,
    exigir_lista,
    exigir_objeto,
)
from vulnerabilidades import Vulnerabilidade

# Campos que aceitam busca por texto. O tipo fica de fora: é escolhido
# numa lista (buscar_por_tipo).
CAMPOS_DE_BUSCA = ("hostname", "custodiante", "lotacao")

# O que a exclusão de um equipamento levou junto, para a tela contar.
ResultadoExclusao = namedtuple(
    "ResultadoExclusao",
    "vinculos dependencias_removidas vulnerabilidades_sem_uso")


class Inventario:
    """Equipamentos, catálogo de vulnerabilidades e as regras entre eles."""

    def __init__(self):
        """Cria um inventário vazio."""
        self._equipamentos = {}
        self._vulnerabilidades = {}
        # Maior id já entregue em cada coleção (marca d'água): enquanto o
        # programa roda, um id excluído nunca volta a ser usado. O
        # arquivo é só uma lista de equipamentos e não guarda esse
        # número; ao carregar, vale o maior id que existe nele.
        self._marca = {"equipamentos": 0, "vulnerabilidades": 0}

    # ------------------------------------------------------------------
    # Identificadores
    # ------------------------------------------------------------------

    def _novo_id(self, colecao, nome):
        """Devolve um id novo, que nunca repete um id já entregue.

        Usa a marca d'água, e não só o maior id existente: com {1, 2},
        excluir o 2 faria max() + 1 devolver 2 de novo.
        """
        novo = max(max(colecao, default=0), self._marca[nome]) + 1
        self._marca[nome] = novo
        return novo

    # ------------------------------------------------------------------
    # Equipamentos: consulta
    # ------------------------------------------------------------------

    def __len__(self):
        """Quantidade de equipamentos."""
        return len(self._equipamentos)

    def todos(self):
        """Devolve os equipamentos em ordem de id."""
        return [self._equipamentos[i] for i in sorted(self._equipamentos)]

    def buscar_por_id(self, id_equipamento):
        """Devolve o equipamento, ou None se o id não existir.

        Busca direta pela chave do dicionário, sem percorrer a coleção.
        """
        return self._equipamentos.get(id_equipamento)

    def buscar_por_texto(self, campo, termo):
        """Devolve os equipamentos cujo campo contém o termo.

        A busca é parcial e ignora acento e caixa: "cart" encontra
        "PC-CARTORIO-01". Percorre todos os equipamentos, ao contrário
        da busca por id. Levanta ValueError se o campo não aceitar
        busca por texto.
        """
        if campo not in CAMPOS_DE_BUSCA:
            raise ValueError(f"Campo sem busca por texto: '{campo}'")
        alvo = formatacao.para_busca(termo)
        return [e for e in self.todos()
                if alvo in formatacao.para_busca(getattr(e, campo))]

    def buscar_por_tipo(self, tipo):
        """Devolve os equipamentos do tipo, em ordem de id."""
        return [e for e in self.todos() if e.tipo is tipo]

    def problema_no_hostname(self, hostname, ignorar_id=None):
        """Devolve None se o hostname serve, ou o motivo da recusa.

        Junta a regra de formato (Equipamento) com a de unicidade, que
        só o inventário pode conferir. ignorar_id tira o próprio
        equipamento da checagem numa atualização.
        """
        problema = Equipamento.problema_no_hostname(hostname)
        if problema:
            return problema
        alvo = hostname.strip().lower()
        for equipamento in self._equipamentos.values():
            if (equipamento.id != ignorar_id
                    and equipamento.hostname.lower() == alvo):
                return "já é usado por outro equipamento"
        return None

    # ------------------------------------------------------------------
    # Equipamentos: cadastro, atualização e exclusão
    # ------------------------------------------------------------------

    def cadastrar_equipamento(self, tipo, hostname, custodiante, lotacao,
                              descricao):
        """Cadastra um equipamento e o devolve (requisito 3 do T1).

        Levanta ValueError se o hostname for inválido ou já estiver em
        uso: duas máquinas com o mesmo nome são um conflito real na
        rede. O objeto criado é da subclasse do tipo.
        """
        problema = self.problema_no_hostname(hostname)
        if problema:
            raise ValueError(f"Hostname inválido: {problema}")
        equipamento = criar_equipamento(
            tipo, self._novo_id(self._equipamentos, "equipamentos"),
            hostname, custodiante, lotacao, descricao)
        self._equipamentos[equipamento.id] = equipamento
        return equipamento

    def atualizar_equipamento(self, id_equipamento, alteracoes):
        """Aplica as alterações {campo: valor} ao equipamento.

        Além dos campos de Equipamento.CAMPOS_EDITAVEIS, aceita "tipo"
        (um TipoEquipamento): o objeto é então substituído por outro, da
        subclasse do novo tipo, com os mesmos dados e relações.

        Devolve True se atualizou e False se o id não existe. Levanta
        ValueError em campo protegido, hostname inválido ou repetido, ou
        tipo inválido; nesse caso nada muda.
        """
        equipamento = self._equipamentos.get(id_equipamento)
        if equipamento is None:
            return False

        dados = {c: v for c, v in alteracoes.items() if c != "tipo"}
        novo_tipo = alteracoes.get("tipo")
        if "tipo" in alteracoes and not isinstance(novo_tipo,
                                                   TipoEquipamento):
            raise ValueError("O tipo deve ser um TipoEquipamento")
        if "hostname" in dados:
            problema = self.problema_no_hostname(dados["hostname"],
                                                 id_equipamento)
            if problema:
                raise ValueError(f"Hostname inválido: {problema}")

        # Equipamento.atualizar() confere tudo antes de gravar; se
        # levantar erro, nada mudou e a troca de tipo nem começa.
        equipamento.atualizar(dados)
        if novo_tipo is not None and novo_tipo is not equipamento.tipo:
            self._equipamentos[id_equipamento] = (
                equipamento.converter_para(novo_tipo))
        return True

    def excluir_equipamento(self, id_equipamento):
        """Exclui o equipamento e tudo que dependia da existência dele.

        É a cascata do requisito 6 do T1, ampliada para o T2:
          - os vínculos de vulnerabilidade vão junto com o objeto;
          - as dependências de outros equipamentos que apontavam para
            ele são removidas (senão apontariam para o nada);
          - vulnerabilidades que ficaram sem nenhum equipamento saem do
            catálogo.

        Devolve um ResultadoExclusao, ou None se o id não existia.
        """
        equipamento = self._equipamentos.pop(id_equipamento, None)
        if equipamento is None:
            return None

        removidas = 0
        for outro in self._equipamentos.values():
            if outro.remover_dependencia(id_equipamento):
                removidas += 1

        sem_uso = 0
        for id_vuln in equipamento.vulnerabilidades:
            if not self.afetados_por(id_vuln):
                del self._vulnerabilidades[id_vuln]
                sem_uso += 1
        return ResultadoExclusao(len(equipamento.vulnerabilidades),
                                 removidas, sem_uso)

    # ------------------------------------------------------------------
    # Vulnerabilidades
    # ------------------------------------------------------------------

    def buscar_vulnerabilidade(self, id_vulnerabilidade):
        """Devolve a vulnerabilidade do catálogo, ou None."""
        return self._vulnerabilidades.get(id_vulnerabilidade)

    def vulnerabilidades(self):
        """Devolve o catálogo inteiro, em ordem de id."""
        return [self._vulnerabilidades[i]
                for i in sorted(self._vulnerabilidades)]

    def afetados_por(self, id_vulnerabilidade):
        """Devolve os equipamentos afetados pela vulnerabilidade."""
        return [e for e in self.todos()
                if id_vulnerabilidade in e.vulnerabilidades]

    def vulnerabilidades_do(self, id_equipamento):
        """Devolve os pares (vulnerabilidade, situação) do equipamento.

        Da mais grave para a menos grave (maior nota CVSS primeiro; no
        empate, a mais antiga). Lista vazia significa equipamento sem
        vulnerabilidades registradas (requisito 8 do T1). Levanta
        ValueError se o equipamento não existir.
        """
        equipamento = self._exigir_equipamento(id_equipamento)
        pares = [(self._vulnerabilidades[i], situacao)
                 for i, situacao in equipamento.vulnerabilidades.items()]
        pares.sort(key=lambda par: (-par[0].cvss, par[0].id))
        return pares

    def registrar_vulnerabilidade(self, id_equipamento, descricao, origem,
                                  cvss, situacao):
        """Cria uma vulnerabilidade nova e a registra no equipamento.

        Devolve a Vulnerabilidade criada (requisito 7 do T1). Tudo é
        conferido antes de gravar, então um dado inválido não deixa
        vulnerabilidade solta no catálogo.
        """
        equipamento = self._exigir_equipamento(id_equipamento)
        if not isinstance(situacao, SituacaoTratamento):
            raise ValueError("A situação deve ser uma SituacaoTratamento")
        # Cria o objeto primeiro, com id provisório: se algum dado for
        # inválido, o erro sai aqui, antes de o id ser gasto e de
        # qualquer mudança.
        vulnerabilidade = Vulnerabilidade(0, descricao, origem, cvss)
        vulnerabilidade.id = self._novo_id(self._vulnerabilidades,
                                           "vulnerabilidades")
        equipamento.vincular_vulnerabilidade(vulnerabilidade.id, situacao)
        self._vulnerabilidades[vulnerabilidade.id] = vulnerabilidade
        return vulnerabilidade

    def registrar_vulnerabilidade_existente(self, id_equipamento,
                                            id_vulnerabilidade, situacao):
        """Registra, no equipamento, uma vulnerabilidade já do catálogo.

        É assim que uma mesma vulnerabilidade passa a afetar vários
        equipamentos. Levanta ValueError se o equipamento ou a
        vulnerabilidade não existirem, ou se ela já estiver nele.
        """
        equipamento = self._exigir_equipamento(id_equipamento)
        if id_vulnerabilidade not in self._vulnerabilidades:
            raise ValueError(
                f"Nenhuma vulnerabilidade com o ID {id_vulnerabilidade}")
        equipamento.vincular_vulnerabilidade(id_vulnerabilidade, situacao)

    def atualizar_vulnerabilidade(self, id_vulnerabilidade, alteracoes):
        """Altera descrição, origem ou nota CVSS no catálogo.

        Vale para todos os equipamentos afetados. Devolve False se o id
        não existe; levanta ValueError em campo protegido ou valor
        inválido (nada muda).
        """
        vulnerabilidade = self._vulnerabilidades.get(id_vulnerabilidade)
        if vulnerabilidade is None:
            return False
        vulnerabilidade.atualizar(alteracoes)
        return True

    def alterar_situacao(self, id_equipamento, id_vulnerabilidade,
                         situacao):
        """Muda a situação do tratamento da vulnerabilidade no equipamento.

        Vale só para este equipamento: o mesmo problema pode estar
        corrigido num e aberto em outro.
        """
        equipamento = self._exigir_equipamento(id_equipamento)
        equipamento.alterar_situacao(id_vulnerabilidade, situacao)

    def remover_vulnerabilidade(self, id_equipamento, id_vulnerabilidade):
        """Tira a vulnerabilidade do equipamento.

        Serve para cadastro errado ou duplicado. Falha resolvida não se
        remove: marca-se como Corrigida, para manter o histórico. Se
        nenhum outro equipamento a tem, ela sai do catálogo.

        Devolve (existia, saiu_do_catalogo).
        """
        equipamento = self._exigir_equipamento(id_equipamento)
        if not equipamento.desvincular_vulnerabilidade(id_vulnerabilidade):
            return (False, False)
        if not self.afetados_por(id_vulnerabilidade):
            del self._vulnerabilidades[id_vulnerabilidade]
            return (True, True)
        return (True, False)

    def pendentes(self):
        """Devolve as ocorrências pendentes de todos os equipamentos.

        Cada item é (equipamento, vulnerabilidade, situação), da mais
        grave (maior nota CVSS) para a menos grave: base do relatório da
        opção 10. No empate, a ordem é a de cadastro.
        """
        itens = []
        for equipamento in self.todos():
            for id_vuln, situacao in equipamento.vulnerabilidades.items():
                if situacao.pendente:
                    itens.append((equipamento,
                                  self._vulnerabilidades[id_vuln],
                                  situacao))
        itens.sort(key=lambda item: (-item[1].cvss, item[0].id, item[1].id))
        return itens

    # ------------------------------------------------------------------
    # Dependências entre equipamentos
    # ------------------------------------------------------------------

    def registrar_dependencia(self, id_origem, id_destino, fracao):
        """Registra que a origem herda uma fração do risco do destino.

        Devolve a fração anterior, se a dependência já existia e foi
        substituída, ou None se é nova. Levanta ValueError se algum dos
        equipamentos não existir ou se a regra da soma das frações
        (Equipamento.definir_dependencia) for violada.
        """
        origem = self._exigir_equipamento(id_origem)
        self._exigir_equipamento(id_destino)
        anterior = origem.dependencias.get(id_destino)
        origem.definir_dependencia(id_destino, fracao)
        return anterior

    def remover_dependencia(self, id_origem, id_destino):
        """Remove a dependência; devolve False se ela não existia."""
        return self._exigir_equipamento(id_origem).remover_dependencia(
            id_destino)

    def dependentes_de(self, id_equipamento):
        """Devolve os pares (equipamento, fração) que dependem deste.

        É o sentido contrário de Equipamento.dependencias: quem herda
        risco do equipamento.
        """
        return [(e, e.dependencias[id_equipamento]) for e in self.todos()
                if id_equipamento in e.dependencias]

    # ------------------------------------------------------------------
    # Apoio
    # ------------------------------------------------------------------

    def _exigir_equipamento(self, id_equipamento):
        """Devolve o equipamento ou levanta ValueError se não existir."""
        equipamento = self._equipamentos.get(id_equipamento)
        if equipamento is None:
            raise ValueError(f"Nenhum equipamento com o ID {id_equipamento}")
        return equipamento

    # ------------------------------------------------------------------
    # Formato do arquivo
    # ------------------------------------------------------------------

    def para_dict(self):
        """Devolve o conteúdo do arquivo: uma lista de objetos JSON.

        Cada objeto é um equipamento, já com as suas vulnerabilidades
        (dados completos e situação neste equipamento) e as suas
        dependências. Uma vulnerabilidade compartilhada aparece, igual,
        em cada equipamento que a tem; de_dict() a reúne de volta num
        só objeto do catálogo.
        """
        lista = []
        for equipamento in self.todos():
            objeto = equipamento.para_dict()
            objeto["vulnerabilidades"] = [
                dict(self._vulnerabilidades[id_vuln].para_dict(),
                     situacao=situacao.value)
                for id_vuln, situacao in sorted(
                    equipamento.vulnerabilidades.items())]
            lista.append(objeto)
        return lista

    @classmethod
    def de_dict(cls, dados):
        """Reconstrói o inventário a partir do conteúdo do arquivo.

        Levanta ValueError, dizendo o que está errado e onde, se o
        conteúdo estiver fora do formato. Além de cada objeto, confere
        o que só se vê no conjunto: ids repetidos, hostname repetido,
        a mesma vulnerabilidade com dados diferentes em dois
        equipamentos e dependência de equipamento inexistente. Carregar
        pela metade faria a próxima gravação apagar os dados bons.
        """
        itens = exigir_lista(dados, "arquivo")
        inventario = cls()
        hostnames = {}
        for item in itens:
            exigir_objeto(item, "equipamento")
            id_item = item.get("id", "?")
            nome = f"equipamento {id_item}"
            reduzido = dict(item)
            reduzido["vulnerabilidades"] = []
            for vuln in exigir_lista(
                    exigir_campo(item, "vulnerabilidades", nome),
                    f"{nome}: campo 'vulnerabilidades'"):
                try:
                    vulnerabilidade = Vulnerabilidade.de_dict(vuln)
                except ValueError as erro:
                    raise ValueError(f"{nome}: {erro}") from erro
                conhecida = inventario._vulnerabilidades.setdefault(
                    vulnerabilidade.id, vulnerabilidade)
                if conhecida != vulnerabilidade:
                    raise ValueError(
                        f"{nome}: a vulnerabilidade {vulnerabilidade.id} "
                        f"aparece em outro equipamento com descrição, "
                        f"origem ou nota diferente")
                reduzido["vulnerabilidades"].append(
                    {c: vuln[c] for c in ("id", "situacao") if c in vuln})

            equipamento = Equipamento.de_dict(reduzido)
            if equipamento.id in inventario._equipamentos:
                raise ValueError(f"equipamento {equipamento.id}: "
                                 f"id repetido")
            chave = equipamento.hostname.lower()
            if chave in hostnames:
                raise ValueError(
                    f"equipamento {equipamento.id}: o hostname "
                    f"{equipamento.hostname} já é usado pelo equipamento "
                    f"{hostnames[chave]}")
            hostnames[chave] = equipamento.id
            inventario._equipamentos[equipamento.id] = equipamento

        # Integridade referencial: a dependência precisa ter para onde.
        for equipamento in inventario.todos():
            for destino in equipamento.dependencias:
                if destino not in inventario._equipamentos:
                    raise ValueError(
                        f"equipamento {equipamento.id}: depende do "
                        f"equipamento {destino}, que não existe")

        inventario._marca["equipamentos"] = max(inventario._equipamentos,
                                                default=0)
        inventario._marca["vulnerabilidades"] = max(
            inventario._vulnerabilidades, default=0)
        return inventario


# Teste: exercita as regras sem ninguém digitar nada.
if __name__ == "__main__":
    import json

    from classificacoes import OrigemVulnerabilidade

    inv = Inventario()
    ESTACAO = TipoEquipamento.ESTACAO_TRABALHO
    SERVIDOR = TipoEquipamento.SERVIDOR
    ABERTA = SituacaoTratamento.ABERTA
    FALTA_ATUALIZACAO = OrigemVulnerabilidade.FALTA_ATUALIZACAO

    # --- Cadastro e hostname único --------------------------------------
    pc = inv.cadastrar_equipamento(ESTACAO, "PC-CARTORIO-01",
                                   "escrivão de plantão", "cartório",
                                   "estação de atendimento")
    srv = inv.cadastrar_equipamento(SERVIDOR, "SRV-ARQUIVO",
                                    "chefe de equipe", "sala técnica",
                                    "servidor de arquivos")
    print(f"Cadastrados: {pc!r} e {srv!r}")
    assert (pc.id, srv.id) == (1, 2)
    assert type(srv).__name__ == "Servidor", "classe do tipo errada"
    try:
        inv.cadastrar_equipamento(SERVIDOR, "srv-arquivo", "X", "Y", "Z")
        raise AssertionError("aceitou hostname repetido")
    except ValueError as erro:
        print(f"Hostname repetido recusado: {erro}")
    assert inv.problema_no_hostname("SRV-ARQUIVO", ignorar_id=2) is None

    # --- Buscas ---------------------------------------------------------
    assert inv.buscar_por_id(2) is srv and inv.buscar_por_id(99) is None
    assert inv.buscar_por_texto("hostname", "cart") == [pc]
    assert inv.buscar_por_texto("custodiante", "escrivao") == [pc]
    assert inv.buscar_por_tipo(SERVIDOR) == [srv]
    try:
        inv.buscar_por_texto("descricao", "x")
        raise AssertionError("aceitou campo sem busca por texto")
    except ValueError:
        pass

    # --- Vulnerabilidades compartilhadas --------------------------------
    v1 = inv.registrar_vulnerabilidade(
        1, "sistema sem atualização há 8 meses", FALTA_ATUALIZACAO, 7.5,
        ABERTA)
    inv.registrar_vulnerabilidade_existente(2, v1.id, ABERTA)
    v2 = inv.registrar_vulnerabilidade(
        2, "compartilhamento aberto para todos",
        OrigemVulnerabilidade.PERMISSAO_INDEVIDA, 9.1,
        SituacaoTratamento.EM_TRATAMENTO)
    print(f"\nCatálogo: {inv.vulnerabilidades()}")
    assert inv.afetados_por(v1.id) == [pc, srv]
    assert [v.id for v, _ in inv.vulnerabilidades_do(2)] == [v2.id, v1.id]
    try:
        inv.registrar_vulnerabilidade_existente(2, v1.id, ABERTA)
        raise AssertionError("aceitou vínculo repetido")
    except ValueError:
        pass
    try:
        inv.registrar_vulnerabilidade(1, "x", FALTA_ATUALIZACAO, 11, ABERTA)
    except ValueError:
        pass
    assert len(inv.vulnerabilidades()) == 2, "sobrou vulnerabilidade solta"
    assert inv.vulnerabilidades_do(1)[0][0] is v1

    # A situação é por equipamento; a nota, do catálogo.
    inv.alterar_situacao(1, v1.id, SituacaoTratamento.CORRIGIDA)
    assert inv.pendentes()[0][1] is v2 and len(inv.pendentes()) == 2
    assert [(e.id, v.id) for e, v, _ in inv.pendentes()] == [(2, v2.id),
                                                             (2, v1.id)]
    inv.atualizar_vulnerabilidade(v1.id, {"cvss": 5.0})
    assert inv.vulnerabilidades_do(1)[0][0].cvss == 5.0
    assert inv.vulnerabilidades_do(2)[1][0].cvss == 5.0, \
        "a nota deveria valer para todos os equipamentos"

    # --- Atualização, inclusive troca de tipo ---------------------------
    inv.atualizar_equipamento(1, {"custodiante": "outro escrivão"})
    assert inv.buscar_por_id(1).custodiante == "Outro Escrivão"
    try:
        inv.atualizar_equipamento(1, {"hostname": "srv-arquivo"})
        raise AssertionError("aceitou hostname de outro equipamento")
    except ValueError:
        pass
    assert inv.atualizar_equipamento(99, {"descricao": "x"}) is False
    inv.atualizar_equipamento(1, {"tipo": TipoEquipamento.BANCO_DADOS})
    assert type(inv.buscar_por_id(1)).__name__ == "BancoDados"
    assert inv.buscar_por_id(1).vulnerabilidades, "perdeu os vínculos"
    try:
        inv.atualizar_equipamento(1, {"descricao": "novo", "tipo": 3})
        raise AssertionError("aceitou tipo que não é TipoEquipamento")
    except ValueError:
        pass
    assert inv.buscar_por_id(1).descricao == "Estação de atendimento"

    # --- Dependências ---------------------------------------------------
    assert inv.registrar_dependencia(1, 2, 0.4) is None
    assert inv.registrar_dependencia(1, 2, 0.6) == 0.4   # substituiu
    assert inv.dependentes_de(2) == [(inv.buscar_por_id(1), 0.6)]
    try:
        inv.registrar_dependencia(1, 99, 0.1)
        raise AssertionError("aceitou destino inexistente")
    except ValueError:
        pass
    inv.registrar_dependencia(2, 1, 0.3)

    # --- Ida e volta pelo formato do arquivo ----------------------------
    texto = json.dumps(inv.para_dict(), ensure_ascii=False)
    copia = Inventario.de_dict(json.loads(texto))
    assert copia.para_dict() == inv.para_dict(), "ida e volta mudou o dado"
    assert [type(e) for e in copia.todos()] == [type(e) for e in inv.todos()]

    # --- Cascata da exclusão --------------------------------------------
    res = inv.excluir_equipamento(2)
    print(f"\nExcluído o 2: {res}")
    # Perdeu o vínculo do v2 (só o 2 o tinha, saiu do catálogo); o v1
    # continua no 1; a dependência 1 -> 2 foi removida.
    assert res == ResultadoExclusao(vinculos=2, dependencias_removidas=1,
                                    vulnerabilidades_sem_uso=1)
    assert inv.buscar_por_id(1).dependencias == {}
    assert [v.id for v in inv.vulnerabilidades()] == [v1.id]
    assert inv.excluir_equipamento(2) is None
    novo = inv.cadastrar_equipamento(ESTACAO, "PC-NOVO", "X", "Y", "Z")
    assert novo.id == 3, "o id 2 foi reaproveitado"
    # O mesmo vale para as vulnerabilidades.
    assert inv.remover_vulnerabilidade(1, v1.id) == (True, True)
    assert inv.remover_vulnerabilidade(1, v1.id) == (False, False)
    v3 = inv.registrar_vulnerabilidade(
        1, "nova", FALTA_ATUALIZACAO, 3.0, ABERTA)
    assert v3.id == 3, f"id de vulnerabilidade reaproveitado: {v3.id}"
    print("Ids de equipamento e de vulnerabilidade não são reaproveitados.")

    # --- Arquivos adulterados -------------------------------------------
    # Um inventário com dois equipamentos que compartilham a vulnerabilidade.
    bom = Inventario()
    bom.cadastrar_equipamento(ESTACAO, "PC-A", "X", "Y", "Z")
    bom.cadastrar_equipamento(SERVIDOR, "SRV-A", "X", "Y", "Z")
    vc = bom.registrar_vulnerabilidade(1, "falha comum", FALTA_ATUALIZACAO,
                                       7.5, ABERTA)
    bom.registrar_vulnerabilidade_existente(2, vc.id, ABERTA)
    bom.registrar_dependencia(1, 2, 0.4)
    bom = bom.para_dict()
    assert isinstance(bom, list) and len(bom) == 2

    def com(indice, **mudancas):
        """Cópia do conteúdo bom com o equipamento alterado."""
        copia = json.loads(json.dumps(bom))
        copia[indice].update(mudancas)
        return copia

    def sem_campo(campo):
        """Cópia do conteúdo bom sem um campo do primeiro equipamento."""
        copia = json.loads(json.dumps(bom))
        del copia[0][campo]
        return copia

    outra_nota = json.loads(json.dumps(bom))
    outra_nota[1]["vulnerabilidades"][0]["cvss"] = 2.0
    adulterados = {
        "raiz é objeto": {"equipamentos": bom},
        "item que não é objeto": [None],
        "sem lista de vulnerabilidades": sem_campo("vulnerabilidades"),
        "vulnerabilidades que não é lista": com(0, vulnerabilidades={}),
        "id de equipamento repetido": [bom[0], bom[0]],
        "hostname repetido": [bom[0], dict(bom[1], hostname="pc-a")],
        "vulnerabilidade sem situação": com(0, vulnerabilidades=[
            {k: v for k, v in bom[0]["vulnerabilidades"][0].items()
             if k != "situacao"}]),
        "vulnerabilidade com dados diferentes": outra_nota,
        "dependência de equipamento inexistente": com(0, dependencias=[
            {"equipamento_id": 99, "fracao": 0.2}]),
    }
    print()
    for nome, conteudo in adulterados.items():
        try:
            Inventario.de_dict(conteudo)
            raise AssertionError(f"aceitou o arquivo adulterado: {nome}")
        except ValueError as erro:
            print(f"Recusado ({nome}): {erro}")

    # Ida e volta: a vulnerabilidade compartilhada volta como um só objeto.
    volta = Inventario.de_dict(json.loads(json.dumps(bom)))
    assert volta.buscar_vulnerabilidade(vc.id) is not None
    assert len(volta.vulnerabilidades()) == 1
    assert volta.para_dict() == bom
    print("\nOK - Inventario exercitado.")
