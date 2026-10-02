"""Programa principal: o menu e as ações do usuário.

A classe Aplicacao liga as peças: pergunta ao usuário (entrada.py),
chama as regras do Inventario, calcula o risco (risco.py), grava
(armazenamento.py) e mostra o resultado (telas.py). É o ponto de
partida do programa: python main.py.

Trabalho 2: o programa inteiro foi reescrito em orientação a objetos
(equipamentos.py, vulnerabilidades.py, inventario.py), guarda os dados
em JSON como lista de objetos, calcula o risco de cada equipamento com
álgebra linear e roda em container Docker.
"""

import os
import signal
import sys
import time

import banner
import cores
import telas
from armazenamento import ArquivoInventario, BaseInvalida
from classificacoes import (
    OrigemVulnerabilidade,
    SituacaoTratamento,
    TipoEquipamento,
)
from entrada import (
    SairDoPrograma,
    VoltarAoMenu,
    confirmar,
    ler_campo,
    ler_decimal,
    ler_enum,
    ler_hostname,
    ler_inteiro,
    ler_resposta,
    ler_texto,
    limpar_tela,
)
from equipamentos import MENOR_FRACAO
from formatacao import fracao_br, numero_br
from risco import ModeloRisco
from vulnerabilidades import validar_cvss

# Com a variável definida (o Dockerfile a define), o programa avisa como
# sair do container sem derrubá-lo e não morre com Ctrl+C.
VARIAVEL_CONTAINER = "INVENTARIO_EM_CONTAINER"

# Acima disto, a matriz não cabe na tela e a opção 15 mostra só o tamanho.
MAXIMO_PARA_MOSTRAR_MATRIZES = 12

# Buscas por texto da opção 3: número da opção -> (campo, pergunta).
BUSCAS_POR_TEXTO = {
    2: ("hostname", "  Hostname (ou parte dele): "),
    3: ("custodiante", "  Responsável (ou parte do nome): "),
    4: ("lotacao", "  Lotação (ou parte dela): "),
}

# Texto de cada opção, na ordem do menu, em blocos. A opção 0 fica por
# último. O número de cada ação está em Aplicacao.__init__.
OPCOES_MENU = (
    ("Equipamentos", (
        (1, "Cadastrar equipamento"),
        (2, "Listar todos os equipamentos"),
        (3, "Buscar equipamento (por ID, hostname, responsável...)"),
        (4, "Atualizar equipamento"),
        (5, "Excluir equipamento (e o que depende dele)"),
    )),
    ("Vulnerabilidades", (
        (6, "Cadastrar vulnerabilidade em um equipamento"),
        (7, "Ver vulnerabilidades de um equipamento"),
        (8, "Atualizar vulnerabilidade"),
        (9, "Excluir vulnerabilidade de um equipamento"),
        (10, "Vulnerabilidades pendentes (todas, da mais grave)"),
    )),
    ("Dependências e risco", (
        (11, "Cadastrar dependência entre equipamentos"),
        (12, "Ver ou remover dependências de um equipamento"),
        (13, "Risco de todos os equipamentos (próprio e efetivo)"),
        (14, "Risco de um equipamento (passo a passo)"),
        (15, "Matrizes do modelo (M, v, F, A) e verificação de I - A"),
    )),
    ("", ((0, "Sair"),)),
)


def em_container():
    """Diz se o programa foi iniciado pelo Dockerfile."""
    return bool(os.environ.get(VARIAVEL_CONTAINER))


class Aplicacao:
    """O programa: carrega a base e repete o menu até o usuário sair."""

    def __init__(self, arquivo):
        """Recebe o ArquivoInventario de onde a base é lida e gravada."""
        self.arquivo = arquivo
        self.inventario = None
        # Fins de entrada seguidos (Ctrl+D), para não girar sem parar.
        self._eofs_seguidos = 0
        # Número da opção -> método que a executa. Substitui uma cadeia
        # de if/elif: ligar uma opção nova custa uma linha aqui e uma em
        # OPCOES_MENU.
        self.acoes = {
            1: self.cadastrar_equipamento,
            2: self.listar_equipamentos,
            3: self.buscar_equipamento,
            4: self.atualizar_equipamento,
            5: self.excluir_equipamento,
            6: self.cadastrar_vulnerabilidade,
            7: self.ver_vulnerabilidades,
            8: self.atualizar_vulnerabilidade,
            9: self.excluir_vulnerabilidade,
            10: self.listar_pendentes,
            11: self.cadastrar_dependencia,
            12: self.ver_dependencias,
            13: self.risco_de_todos,
            14: self.risco_de_um,
            15: self.ver_matrizes,
        }

    # ------------------------------------------------------------------
    # Apoio: perguntas e mensagens que várias ações repetem
    # ------------------------------------------------------------------

    def _salvar(self):
        """Grava a base. Chamado depois de cada alteração."""
        self.arquivo.salvar(self.inventario)

    @staticmethod
    def _erro(texto):
        """Imprime uma recusa."""
        print("\n  " + cores.erro(f"! {texto}"))

    def _listar_para_id(self):
        """Mostra os equipamentos quando o usuário digita "lista"."""
        if not len(self.inventario):
            print("\n  " + cores.aviso(
                "Nenhum equipamento cadastrado ainda.\n"))
            return
        telas.mostrar_tabela(self.inventario.todos())
        print()

    def _ler_id_equipamento(self, mensagem="  ID do equipamento: "):
        """Lê o ID de um equipamento; "lista" mostra a tabela e repete."""
        return ler_inteiro(mensagem, mostrar_lista=self._listar_para_id)

    def _ler_equipamento(self, mensagem="  ID do equipamento: "):
        """Lê um ID e devolve o equipamento; None (e avisa) se não existe."""
        id_equipamento = self._ler_id_equipamento(mensagem)
        equipamento = self.inventario.buscar_por_id(id_equipamento)
        if equipamento is None:
            self._erro(f"Nenhum equipamento com o ID {id_equipamento}.")
        return equipamento

    @staticmethod
    def _ler_nota_cvss(mensagem, opcional=False):
        """Lê uma nota CVSS válida, repetindo até vir uma. Enter: None."""
        while True:
            nota = ler_decimal(mensagem, opcional=opcional)
            if nota is None:
                return None
            try:
                return validar_cvss(nota)
            except ValueError as erro:
                print("  " + cores.erro(f"! {erro}."))

    # ------------------------------------------------------------------
    # Equipamentos (opções 1 a 5)
    # ------------------------------------------------------------------

    def cadastrar_equipamento(self):
        """Opção 1: cadastra um equipamento e as vulnerabilidades iniciais."""
        print("\n" + cores.titulo("--- CADASTRAR EQUIPAMENTO ---") + "\n")
        hostname = ler_hostname("  Hostname: ",
                                self.inventario.problema_no_hostname)
        custodiante = ler_campo("  Responsável: ")
        lotacao = ler_campo("  Lotação (setor): ")
        descricao = ler_campo("  Descrição: ")
        tipo = ler_enum("  Tipo de equipamento:", TipoEquipamento)

        try:
            equipamento = self.inventario.cadastrar_equipamento(
                tipo, hostname, custodiante, lotacao, descricao)
        except ValueError as erro:
            self._erro(str(erro))
            return

        self._salvar()
        print("\n  " + cores.sucesso(
            f"Equipamento cadastrado com o ID {equipamento.id}."))

        # A lista inicial de vulnerabilidades do requisito 3 do T1.
        while confirmar("\n  Cadastrar uma vulnerabilidade para este "
                        "equipamento?"):
            self._registrar_vulnerabilidade(equipamento)

    def listar_equipamentos(self):
        """Opção 2: mostra todos os equipamentos em tabela."""
        print("\n" + cores.titulo("--- EQUIPAMENTOS CADASTRADOS ---"))

        if not len(self.inventario):
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return

        telas.mostrar_tabela(self.inventario.todos())
        # No fim, porque numa lista longa o título já saiu da tela.
        print(f"\n  Total: {len(self.inventario)} equipamento(s).")

    def buscar_equipamento(self):
        """Opção 3: busca equipamentos por id, hostname ou outros campos.

        O requisito 4 do T1 pede id e hostname; responsável, lotação e
        tipo vão além. Um resultado mostra a ficha completa; vários, a
        tabela.
        """
        print("\n" + cores.titulo("--- BUSCAR EQUIPAMENTO ---") + "\n")
        print(f"    {cores.destaque('1')} - Por ID")
        print(f"    {cores.destaque('2')} - Por hostname")
        print(f"    {cores.destaque('3')} - Por responsável")
        print(f"    {cores.destaque('4')} - Por lotação")
        print(f"    {cores.destaque('5')} - Por tipo")
        opcao = ler_inteiro("  Opção: ")

        if opcao == 1:
            id_equipamento = self._ler_id_equipamento("  ID: ")
            achado = self.inventario.buscar_por_id(id_equipamento)
            encontrados = [achado] if achado is not None else []
        elif opcao in BUSCAS_POR_TEXTO:
            campo, pergunta = BUSCAS_POR_TEXTO[opcao]
            termo = ler_texto(pergunta)
            encontrados = self.inventario.buscar_por_texto(campo, termo)
        elif opcao == 5:
            tipo = ler_enum("  Tipo de equipamento:", TipoEquipamento)
            encontrados = self.inventario.buscar_por_tipo(tipo)
        else:
            self._erro("Opção inválida.")
            return

        if not encontrados:
            self._erro("Nenhum equipamento encontrado.")
        elif len(encontrados) == 1:
            self._mostrar_ficha_completa(encontrados[0])
        else:
            print(f"\n  {len(encontrados)} equipamentos encontrados:")
            telas.mostrar_tabela(encontrados)
            print("\n  Para ver a ficha e as vulnerabilidades de um deles, "
                  "use a opção 7.")

    def _mostrar_ficha_completa(self, equipamento):
        """Ficha do equipamento e as suas vulnerabilidades."""
        telas.mostrar_equipamento(equipamento)
        telas.mostrar_vulnerabilidades(
            self.inventario.vulnerabilidades_do(equipamento.id))

    def atualizar_equipamento(self):
        """Opção 4: altera os campos de um equipamento (requisito 5 do T1).

        Enter mantém o valor atual. As mudanças vão juntas para o
        inventário, que recusa todas se alguma for inválida.
        """
        print("\n" + cores.titulo("--- ATUALIZAR EQUIPAMENTO ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return

        telas.mostrar_equipamento(equipamento)
        print("\n  Deixe em branco para manter o valor atual.\n")

        alteracoes = {}

        novo = ler_hostname(
            f"  Hostname [{equipamento.hostname}]: ",
            lambda texto: self.inventario.problema_no_hostname(
                texto, equipamento.id),
            obrigatorio=False)
        if novo:
            alteracoes["hostname"] = novo

        novo = ler_campo(f"  Responsável [{equipamento.custodiante}]: ",
                         obrigatorio=False)
        if novo:
            alteracoes["custodiante"] = novo

        novo = ler_campo(f"  Lotação [{equipamento.lotacao}]: ",
                         obrigatorio=False)
        if novo:
            alteracoes["lotacao"] = novo

        novo = ler_campo(f"  Descrição [{equipamento.descricao}]: ",
                         obrigatorio=False)
        if novo:
            alteracoes["descricao"] = novo

        novo_tipo = ler_enum(
            f"  Tipo (atual: {equipamento.tipo.rotulo})"
            " - Enter para manter:",
            TipoEquipamento, opcional=True)
        if novo_tipo is not None and novo_tipo is not equipamento.tipo:
            alteracoes["tipo"] = novo_tipo

        if not alteracoes:
            print("\n  " + cores.aviso("Nada foi alterado."))
            return

        try:
            self.inventario.atualizar_equipamento(equipamento.id, alteracoes)
        except ValueError as erro:
            self._erro(str(erro))
            return

        self._salvar()
        print("\n  " + cores.sucesso(
            f"Equipamento atualizado ({len(alteracoes)} campo(s))."))

    def excluir_equipamento(self):
        """Opção 5: exclui o equipamento e o que dependia dele.

        Requisito 6 do T1, ampliado: as dependências de outros
        equipamentos que apontavam para ele também saem.
        """
        print("\n" + cores.titulo("--- EXCLUIR EQUIPAMENTO ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return

        self._mostrar_ficha_completa(equipamento)
        dependentes = self.inventario.dependentes_de(equipamento.id)
        if dependentes:
            print("\n  " + cores.aviso(
                f"{len(dependentes)} equipamento(s) dependem deste: "
                + ", ".join(e.hostname for e, _ in dependentes)
                + ". A dependência deles será removida."))

        if not confirmar("\n  Confirma a exclusão do equipamento e do que "
                         "está ligado a ele?"):
            print("\n  " + cores.aviso("Exclusão cancelada."))
            return

        resultado = self.inventario.excluir_equipamento(equipamento.id)
        self._salvar()
        mensagem = (f"Equipamento excluído, junto com "
                    f"{resultado.vinculos} vulnerabilidade(s) registrada(s) "
                    f"nele e {resultado.dependencias_removidas} "
                    f"dependência(s) que apontavam para ele.")
        if resultado.vulnerabilidades_sem_uso:
            mensagem += (f" {resultado.vulnerabilidades_sem_uso} "
                         f"vulnerabilidade(s) ficaram sem equipamento e "
                         f"saíram do catálogo.")
        print("\n  " + cores.sucesso(mensagem))

    # ------------------------------------------------------------------
    # Vulnerabilidades (opções 6 a 10)
    # ------------------------------------------------------------------

    def _ler_vulnerabilidade_do_catalogo(self, equipamento):
        """Pergunta o ID de uma vulnerabilidade já cadastrada.

        Só aceita uma que o equipamento ainda não tenha. "lista" mostra
        o catálogo.
        """
        def listar():
            print()
            telas.mostrar_catalogo(self.inventario)
            print()

        while True:
            id_vuln = ler_inteiro("  ID da vulnerabilidade: ",
                                  mostrar_lista=listar)
            if self.inventario.buscar_vulnerabilidade(id_vuln) is None:
                self._erro(f"Nenhuma vulnerabilidade com o ID {id_vuln}.")
            elif id_vuln in equipamento.vulnerabilidades:
                self._erro("Este equipamento já tem essa vulnerabilidade.")
            else:
                return id_vuln

    def _registrar_vulnerabilidade(self, equipamento):
        """Pergunta os campos de uma vulnerabilidade, registra e grava.

        Usada no cadastro do equipamento (requisito 3 do T1) e na opção
        6 (requisito 7), para as duas telas se comportarem igual. A
        vulnerabilidade pode ser nova ou uma que já existe no catálogo e
        afeta outros equipamentos.
        """
        disponiveis = [v for v in self.inventario.vulnerabilidades()
                       if v.id not in equipamento.vulnerabilidades]
        id_existente = None
        if disponiveis:
            print(f"\n    {cores.destaque('1')} - Escolher uma "
                  f"vulnerabilidade já cadastrada ({len(disponiveis)} "
                  f"disponível(is))")
            print(f"    {cores.destaque('2')} - Cadastrar uma nova")
            escolha = ler_inteiro("  Opção: ")
            while escolha not in (1, 2):
                print("  " + cores.erro("! Digite 1 ou 2."))
                escolha = ler_inteiro("  Opção: ")
            if escolha == 1:
                id_existente = self._ler_vulnerabilidade_do_catalogo(
                    equipamento)

        if id_existente is None:
            descricao = ler_campo("  Descrição da vulnerabilidade: ")
            origem = ler_enum("  Categoria:", OrigemVulnerabilidade)
            nota = self._ler_nota_cvss("\n  Nota CVSS (0,1 a 10,0): ")
        situacao = ler_enum("  Status neste equipamento:",
                            SituacaoTratamento)

        # Tudo foi perguntado: só agora o inventário muda.
        try:
            if id_existente is None:
                vuln = self.inventario.registrar_vulnerabilidade(
                    equipamento.id, descricao, origem, nota, situacao)
            else:
                self.inventario.registrar_vulnerabilidade_existente(
                    equipamento.id, id_existente, situacao)
                vuln = self.inventario.buscar_vulnerabilidade(id_existente)
        except ValueError as erro:
            self._erro(str(erro))
            return

        self._salvar()
        print("\n  " + cores.sucesso(
            f"Vulnerabilidade {vuln.id} registrada em {equipamento.hostname}"
            f" (severidade {vuln.gravidade.rotulo}, nota "
            f"{numero_br(vuln.cvss)})."))

    def cadastrar_vulnerabilidade(self):
        """Opção 6: cadastra uma vulnerabilidade num equipamento."""
        print("\n" + cores.titulo("--- CADASTRAR VULNERABILIDADE ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is not None:
            self._registrar_vulnerabilidade(equipamento)

    def ver_vulnerabilidades(self):
        """Opção 7: mostra o equipamento e as vulnerabilidades dele."""
        print("\n" + cores.titulo(
            "--- VULNERABILIDADES DE UM EQUIPAMENTO ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is not None:
            self._mostrar_ficha_completa(equipamento)

    def _ler_vulnerabilidade_do_equipamento(self, equipamento):
        """Mostra as do equipamento e pergunta qual. None se não houver."""
        pares = self.inventario.vulnerabilidades_do(equipamento.id)
        if not pares:
            print("\n  " + cores.aviso(
                "Este equipamento está sem vulnerabilidades registradas."))
            return None
        telas.mostrar_vulnerabilidades(pares)
        id_vuln = ler_inteiro("  ID da vulnerabilidade: ")
        if id_vuln not in equipamento.vulnerabilidades:
            self._erro(f"{equipamento.hostname} não tem a vulnerabilidade "
                       f"{id_vuln}.")
            return None
        return self.inventario.buscar_vulnerabilidade(id_vuln)

    def atualizar_vulnerabilidade(self):
        """Opção 8: corrige uma vulnerabilidade ou muda o tratamento.

        Mesma mecânica da opção 4: Enter mantém o valor atual. Descrição,
        categoria e nota são da vulnerabilidade e valem para todos os
        equipamentos que a têm; o status é de cada equipamento.
        """
        print("\n" + cores.titulo("--- ATUALIZAR VULNERABILIDADE ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return
        vuln = self._ler_vulnerabilidade_do_equipamento(equipamento)
        if vuln is None:
            return

        situacao_atual = equipamento.vulnerabilidades[vuln.id]
        afetados = self.inventario.afetados_por(vuln.id)
        print(f"\n  Descrição ..... {vuln.descricao}")
        print(f"  Categoria ..... {vuln.origem.rotulo}")
        print(f"  Nota CVSS ..... {numero_br(vuln.cvss)} "
              f"({vuln.gravidade.rotulo})")
        print(f"  Status ........ "
              f"{cores.situacao(situacao_atual.rotulo, situacao_atual)}"
              f" (em {equipamento.hostname})")
        if len(afetados) > 1:
            print("\n  " + cores.aviso(
                f"Descrição, categoria e nota valem para os "
                f"{len(afetados)} equipamentos que têm esta vulnerabilidade"
                f" ({', '.join(e.hostname for e in afetados)}). "
                f"O status vale só para {equipamento.hostname}."))
        print("\n  Deixe em branco para manter o valor atual.\n")

        alteracoes = {}
        novo = ler_campo(f"  Descrição [{vuln.descricao}]: ",
                         obrigatorio=False)
        if novo:
            alteracoes["descricao"] = novo
        nova_origem = ler_enum(
            f"  Categoria (atual: {vuln.origem.rotulo})"
            " - Enter para manter:",
            OrigemVulnerabilidade, opcional=True)
        if nova_origem is not None:
            alteracoes["origem"] = nova_origem
        nova_nota = self._ler_nota_cvss(
            f"\n  Nota CVSS [{numero_br(vuln.cvss)}]: ", opcional=True)
        if nova_nota is not None:
            alteracoes["cvss"] = nova_nota
        nova_situacao = ler_enum(
            f"  Status (atual: {situacao_atual.rotulo})"
            " - Enter para manter:",
            SituacaoTratamento, opcional=True)

        mudou_situacao = (nova_situacao is not None
                          and nova_situacao is not situacao_atual)
        if not alteracoes and not mudou_situacao:
            print("\n  " + cores.aviso("Nada foi alterado."))
            return

        try:
            # A alteração do catálogo vem primeiro: é a que pode falhar.
            if alteracoes:
                self.inventario.atualizar_vulnerabilidade(vuln.id,
                                                          alteracoes)
            if mudou_situacao:
                self.inventario.alterar_situacao(equipamento.id, vuln.id,
                                                 nova_situacao)
        except ValueError as erro:
            self._erro(str(erro))
            return

        self._salvar()
        print("\n  " + cores.sucesso(
            f"Vulnerabilidade atualizada "
            f"({len(alteracoes) + int(mudou_situacao)} campo(s))."))

    def excluir_vulnerabilidade(self):
        """Opção 9: tira uma vulnerabilidade cadastrada por engano.

        Falha resolvida deve ser marcada como Corrigida (opção 8), não
        excluída, para não perder o histórico; a tela avisa isso.
        """
        print("\n" + cores.titulo("--- EXCLUIR VULNERABILIDADE ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return
        vuln = self._ler_vulnerabilidade_do_equipamento(equipamento)
        if vuln is None:
            return

        print("\n  " + cores.aviso(
            "Atenção: exclua apenas cadastro errado ou duplicado."))
        print("  " + cores.aviso(
            "Se a vulnerabilidade foi resolvida, use a opção 8 e marque"))
        print("  " + cores.aviso(
            "como Corrigida - apagar destrói o histórico."))

        if not confirmar(f"\n  Confirma a exclusão de [{vuln.id}] em "
                         f"{equipamento.hostname}?"):
            print("\n  " + cores.aviso("Exclusão cancelada."))
            return

        _, saiu = self.inventario.remover_vulnerabilidade(equipamento.id,
                                                          vuln.id)
        self._salvar()
        mensagem = "Vulnerabilidade excluída."
        if saiu:
            mensagem += " Nenhum outro equipamento a tinha: saiu do catálogo."
        print("\n  " + cores.sucesso(mensagem))

    def listar_pendentes(self):
        """Opção 10: lista as vulnerabilidades pendentes de todos.

        Vai além do enunciado do T1: mostra o que corrigir primeiro sem
        abrir a ficha de cada equipamento.
        """
        print("\n" + cores.titulo("--- VULNERABILIDADES PENDENTES ---"))
        pendentes = self.inventario.pendentes()

        if not pendentes:
            print("\n  " + cores.sucesso(
                "Nenhuma vulnerabilidade aberta ou em tratamento."))
            return

        print(f"\n  {len(pendentes)} aberta(s) ou em tratamento, da mais "
              f"grave:")
        print("  " + telas.resumo_por_severidade(pendentes) + "\n")
        telas.imprimir_ocorrencias(pendentes, com_hostname=True)

    # ------------------------------------------------------------------
    # Dependências e risco (opções 11 a 15)
    # ------------------------------------------------------------------

    def cadastrar_dependencia(self):
        """Opção 11: registra que um equipamento herda risco de outro."""
        print("\n" + cores.titulo("--- CADASTRAR DEPENDÊNCIA ---") + "\n")
        print("  Se o equipamento B for comprometido, o equipamento A "
              "herda uma fração\n  do risco de B (a fração fica na "
              "matriz A do modelo de risco).\n")
        origem = self._ler_equipamento("  ID do equipamento A (que depende): ")
        if origem is None:
            return
        destino = self._ler_equipamento(
            "  ID do equipamento B (de que A depende): ")
        if destino is None:
            return
        if origem.id == destino.id:
            self._erro("Um equipamento não pode depender de si mesmo.")
            return

        atual = origem.dependencias.get(destino.id)
        if atual is not None:
            print("\n  " + cores.aviso(
                f"{origem.hostname} já depende de {destino.hostname} "
                f"(fração {fracao_br(atual)})."))
            if not confirmar("  Substituir a fração?"):
                print("\n  " + cores.aviso("Nada foi alterado."))
                return
        # Soma sem a dependência que está sendo substituída.
        usada = round(origem.soma_dependencias - (atual or 0.0), 9)
        print(f"\n  Frações já usadas por {origem.hostname}: "
              f"{fracao_br(usada)} (a soma precisa ficar abaixo de 1).")
        if round(1 - usada, 9) <= MENOR_FRACAO:
            self._erro("Não há espaço para outra dependência: remova uma "
                       "das existentes (opção 12).")
            return
        # Fração recusada (zero, 1 ou acima do que cabe): pergunta de novo.
        while True:
            fracao = ler_decimal(
                f"  Fração do risco de {destino.hostname} que "
                f"{origem.hostname} herda (de 0 a 1, ex.: 0,3): ")
            try:
                self.inventario.registrar_dependencia(
                    origem.id, destino.id, fracao)
                break
            except ValueError as erro:
                self._erro(str(erro) + ".")

        self._salvar()
        print("\n  " + cores.sucesso(
            f"Dependência registrada: {origem.hostname} herda "
            f"{fracao_br(origem.dependencias[destino.id])} do risco de "
            f"{destino.hostname}. Soma das frações de {origem.hostname}: "
            f"{fracao_br(origem.soma_dependencias)}."))

    def ver_dependencias(self):
        """Opção 12: mostra as dependências e permite remover uma."""
        print("\n" + cores.titulo("--- DEPENDÊNCIAS DE UM EQUIPAMENTO ---")
              + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return

        telas.mostrar_equipamento(equipamento)
        telas.mostrar_dependencias(self.inventario, equipamento)
        if not equipamento.dependencias:
            return

        id_remover = ler_inteiro(
            "\n  ID do equipamento cuja dependência remover "
            "(Enter para só ver): ", opcional=True)
        if id_remover is None:
            return
        if id_remover not in equipamento.dependencias:
            self._erro(f"{equipamento.hostname} não depende do equipamento "
                       f"{id_remover}.")
            return
        if not confirmar(f"\n  Confirma remover a dependência de "
                         f"{equipamento.hostname} em [{id_remover}]?"):
            print("\n  " + cores.aviso("Remoção cancelada."))
            return
        self.inventario.remover_dependencia(equipamento.id, id_remover)
        self._salvar()
        print("\n  " + cores.sucesso("Dependência removida."))

    def _montar_modelo(self):
        """Monta o modelo de risco e mostra a verificação de I - A.

        Devolve o ModeloRisco, ou None (já explicado na tela) se não há
        equipamentos ou se o sistema não é invertível: nesse caso nada é
        resolvido, e o usuário é informado.
        """
        if not len(self.inventario):
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return None
        modelo = ModeloRisco(self.inventario)
        diagnostico = modelo.diagnosticar()
        telas.mostrar_diagnostico(diagnostico)
        if not diagnostico.utilizavel:
            print("  " + cores.erro(
                "! Nenhum risco efetivo foi calculado. Corrija as "
                "dependências (opção 12) e tente de novo."))
            return None
        return modelo

    def risco_de_todos(self):
        """Opção 13: risco próprio e efetivo de todos os equipamentos."""
        print("\n" + cores.titulo("--- RISCO DOS EQUIPAMENTOS ---"))
        modelo = self._montar_modelo()
        if modelo is None:
            return

        # Do mais para o menos arriscado; no empate, a ordem de cadastro.
        itens = sorted(modelo.relatorio(),
                       key=lambda i: (-i.efetivo, i.equipamento.id))
        telas.mostrar_relatorio_risco(itens)
        print("\n  " + cores.discreto(
            "SOMA CVSS = M v (só vulnerabilidades não corrigidas) · "
            "PRÓPRIO = fator x soma"))
        print("  " + cores.discreto(
            "EFETIVO = próprio + risco herdado, da solução de "
            "(I - A) x = b"))
        print("  " + cores.discreto(
            f"Erro numérico da solução: ||(I - A) x - b|| = "
            f"{modelo.residuo:.1e}".replace(".", ",")))
        print("  Para ver como um deles foi calculado, use a opção 14.")

    def risco_de_um(self):
        """Opção 14: risco próprio e efetivo de um equipamento, em passos."""
        print("\n" + cores.titulo("--- RISCO DE UM EQUIPAMENTO ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return
        modelo = self._montar_modelo()
        if modelo is None:
            return
        telas.mostrar_detalhe_risco(
            modelo.risco_de(equipamento.id),
            self.inventario.vulnerabilidades_do(equipamento.id),
            modelo.contribuicoes(equipamento.id))

    def ver_matrizes(self):
        """Opção 15: mostra as matrizes e a verificação de I - A."""
        print("\n" + cores.titulo("--- MATRIZES DO MODELO DE RISCO ---"))
        if not len(self.inventario):
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return
        modelo = ModeloRisco(self.inventario)
        n, m = modelo.M.shape
        print(f"\n  {n} equipamento(s) e {m} vulnerabilidade(s): M é "
              f"{n} x {m}, v tem {m} valor(es) e A é {n} x {n}.")
        if max(n, m) > MAXIMO_PARA_MOSTRAR_MATRIZES:
            # As matrizes não cabem na tela; a verificação de I - A, sim.
            print("  " + cores.aviso(
                f"Grande demais para mostrar as matrizes (mostro até "
                f"{MAXIMO_PARA_MOSTRAR_MATRIZES} equipamentos e "
                f"{MAXIMO_PARA_MOSTRAR_MATRIZES} vulnerabilidades). Um "
                f"cenário pequeno está em dados_exemplo/cenario_3_"
                f"equipamentos.json."))
        else:
            telas.mostrar_matrizes(modelo)
        telas.mostrar_diagnostico(modelo.diagnosticar())

    # ------------------------------------------------------------------
    # O laço do programa
    # ------------------------------------------------------------------

    def exibir_menu(self):
        """Mostra o menu, com os números alinhados à direita.

        O número é alinhado antes de ser pintado: os códigos de cor
        contam como caracteres e desalinhariam a coluna.
        """
        print("\n" + cores.discreto("=" * telas.LARGURA_MENU))
        for bloco, opcoes in OPCOES_MENU:
            if bloco:
                print(cores.discreto(f" {bloco}"))
            for numero, texto in opcoes:
                print(f"  {cores.destaque(f'{numero:>2}')} - {texto}")
        print(cores.discreto("=" * telas.LARGURA_MENU))
        print(cores.discreto("  Em qualquer pergunta: voltar · sair · "
                             "limpar · ajuda"))
        if em_container():
            print(cores.discreto("  No container: Ctrl+P e Ctrl+Q saem sem "
                                 "parar o programa"))

    def ler_opcao_do_menu(self):
        """Lê a opção do menu principal.

        Aqui "limpar" limpa a tela e desenha o menu de novo, e "voltar"
        não tem para onde voltar: a pergunta só se repete.
        """
        while True:
            try:
                bruto = ler_resposta("  Opção: ",
                                     depois_de_limpar=self.exibir_menu)
            except VoltarAoMenu:
                continue
            try:
                opcao = int(bruto)
            except ValueError:
                # Enter sozinho ou texto: desenha o menu de novo. Depois
                # de um "docker attach" a tela está vazia (o Docker não
                # repete o que já foi impresso), e o Enter é como o
                # usuário pede para vê-la. No container, o Enter sozinho
                # limpa a tela e traz também o logotipo, como na abertura.
                if not bruto and em_container():
                    limpar_tela()
                    self.exibir_abertura()
                self.exibir_menu()
                if bruto:
                    print("  " + cores.erro("! Digite apenas números."))
                continue
            self._eofs_seguidos = 0
            return opcao

    @staticmethod
    def pausar():
        """Espera o Enter antes de o menu voltar, para o resultado ser lido.

        Sem a pausa, o menu seria impresso logo abaixo do resultado e
        empurraria o começo de uma listagem longa para fora da tela.
        Com a entrada vinda de um arquivo (testes automáticos), não há
        quem leia e a pausa é pulada.
        """
        if not sys.stdin.isatty():
            return
        try:
            ler_resposta(cores.discreto("\n  Enter para voltar ao menu... "))
        except VoltarAoMenu:
            pass  # "voltar" aqui é o próprio Enter

    def executar(self, acao):
        """Executa uma ação do menu.

        Ponto de isolamento (requisito 1 do T1): um erro inesperado não
        derruba o programa, e a base é recarregada, porque a ação pode
        ter parado entre a memória e o disco. "voltar" não precisa
        recarregar: as ações só mexem na base depois da última pergunta.
        """
        # A ordem dos except importa: o Python usa o primeiro que servir.
        # Os pedidos do usuário vêm antes do "except Exception" genérico,
        # senão "voltar" e "sair" seriam tratados como erro inesperado.
        try:
            acao()
        except VoltarAoMenu:
            # Sem pausa: o usuário acabou de pedir para voltar.
            print("\n  " + cores.aviso(
                "Voltando ao menu. O que não foi gravado foi descartado."))
            return
        except (SairDoPrograma, EOFError):
            raise  # EOFError: Ctrl+Z ou Ctrl+D, encerramento limpo
        except Exception as erro:
            # O tipo diz o que houve mesmo quando a mensagem é curta: um
            # KeyError('x') sozinho apareceria só como "'x'".
            print("\n  " + cores.erro(
                f"! Erro inesperado ({type(erro).__name__}): {erro}"))
            self.inventario = self.arquivo.carregar()
            print("  " + cores.erro(
                "! Base recarregada do disco: o que não chegou a ser "
                "gravado foi descartado."))
        self.pausar()

    @staticmethod
    def exibir_abertura():
        """Mostra o logotipo do cadeado e o título do programa."""
        print("\n" + banner.montar())
        print("\n" + cores.titulo("=" * telas.LARGURA_MENU))
        print(cores.titulo("INVENTÁRIO DE EQUIPAMENTOS E VULNERABILIDADES"
                           .center(telas.LARGURA_MENU)))
        print(cores.titulo("=" * telas.LARGURA_MENU))

    def iniciar(self):
        """Carrega a base e repete o menu até o usuário escolher 0."""
        cores.ativar()
        self.exibir_abertura()

        # A base é lida uma vez; cada alteração é gravada na hora.
        self.inventario = self.arquivo.carregar()
        self._avisar_da_carga()

        while True:
            try:
                self._repetir_menu()
                break
            except SairDoPrograma:
                # "sair" digitado em qualquer pergunta. No container
                # pede a mesma confirmação da opção 0.
                if self._confirmar_saida():
                    break
            except EOFError:
                # Ctrl+D / fim da entrada. Fora do container encerra
                # (main trata); dentro, não pode derrubar o programa.
                self._eofs_seguidos += 1
                if not em_container() or self._eofs_seguidos > 10:
                    raise
                print("\n  " + cores.aviso(
                    "Ctrl+D não encerra o programa dentro do container. "
                    "Use a opção 0."))
                time.sleep(0.2)

        print("\n  " + cores.titulo("Até logo.") + "\n")

    def _repetir_menu(self):
        """Mostra o menu e executa as opções até a saída ser confirmada."""
        while True:
            self.exibir_menu()
            opcao = self.ler_opcao_do_menu()

            if opcao == 0:
                if self._confirmar_saida():
                    return
                continue

            acao = self.acoes.get(opcao)
            if acao is None:
                self._erro("Opção inexistente. Escolha um número do menu.")
                continue
            self.executar(acao)

    def _avisar_da_carga(self):
        """Conta o que foi carregado e avisa de qualquer problema."""
        print(f"\n  Base carregada: {len(self.inventario)} equipamento(s), "
              f"{len(self.inventario.vulnerabilidades())} "
              f"vulnerabilidade(s).")

        if self.arquivo.migracao_feita is not None:
            copia, avisos = self.arquivo.migracao_feita
            self._salvar()
            print("  " + cores.aviso(
                "A base era do Trabalho 1 e foi convertida para o novo "
                "formato."))
            print("  " + cores.discreto(f"Cópia da original: {copia}"))
            for aviso in avisos:
                print("  " + cores.aviso(aviso))

        # Um arquivo editado à mão pode ter dependências sem solução.
        diagnostico = ModeloRisco(self.inventario).diagnosticar()
        if not diagnostico.utilizavel:
            print("  " + cores.erro(
                "! As dependências gravadas deixam o modelo de risco sem "
                "solução (opção 13 explica)."))

    @staticmethod
    def _confirmar_saida():
        """Pede confirmação ao sair, se o programa roda em container.

        No Docker, encerrar o programa para o container (o Docker o
        religa, mas o tempo de atividade recomeça). Para deixar o
        programa rodando, o caminho é Ctrl+P e Ctrl+Q.
        """
        if not em_container():
            return True
        print("\n  " + cores.aviso(
            "Este programa roda num container: sair o encerra."))
        print("  " + cores.aviso(
            "Para deixá-lo rodando, use Ctrl+P e depois Ctrl+Q."))
        try:
            return confirmar("  Encerrar mesmo assim?")
        except VoltarAoMenu:
            return False  # "voltar" aqui é o mesmo que dizer não
        except SairDoPrograma:
            return True   # insistiu: "sair" duas vezes é um sim
        except EOFError:
            return False  # Ctrl+D na confirmação: não encerra


def preparar_container():
    """Ajusta o programa para rodar como processo principal do Docker.

    Dois ajustes. Ctrl+C no "docker attach" chega ao programa e o
    derrubaria: é ignorado, e o aviso do menu diz o que usar no lugar. E
    o "docker stop" envia SIGTERM, que o processo número 1 de um
    container ignora se não tiver tratador: sem isto o Docker esperaria
    10 segundos e o mataria à força.

    Sem terminal (docker run -d, sem -t), input() receberia fim de
    entrada e o programa terminaria na hora; por isso o programa
    explica o que fazer e para, em vez de falhar em silêncio.
    """
    if not sys.stdin.isatty():
        sys.exit(
            "Este programa é interativo e precisa de um terminal. Inicie "
            "o container com 'docker run -dit ...' (ou 'docker compose "
            "up -d') e use 'docker attach' para operar o menu.")
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, lambda numero, quadro: sys.exit(0))


def main():
    """Ponto de entrada: cria a aplicação e a inicia."""
    if em_container():
        preparar_container()
    aplicacao = Aplicacao(ArquivoInventario())
    try:
        aplicacao.iniciar()
    except BaseInvalida as erro:
        # Não abre base ruim: a primeira gravação apagaria o original.
        print("\n  " + cores.erro(
            f"! Não foi possível carregar a base de dados: {erro}"))
        print("  " + cores.erro(f"! Arquivo: {aplicacao.arquivo.caminho}"))
        print("  " + cores.erro(
            "! O programa para aqui, para não sobrescrever dados bons."))
        print("  " + cores.erro(
            "! Corrija o arquivo, ou mova-o para fora da pasta"))
        print(cores.erro("    e o programa começa uma base nova.") + "\n")
        sys.exit(1)
    except OSError as erro:
        # Só chega aqui um erro de arquivo durante a carga (nas ações
        # do menu, executar() trata): pasta sem permissão, disco cheio...
        print("\n  " + cores.erro(
            f"! Não foi possível ler ou gravar o arquivo de dados: {erro}")
            + "\n")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Encerrado pelo usuário.\n")


if __name__ == "__main__":
    main()
