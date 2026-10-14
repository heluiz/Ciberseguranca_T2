"""Programa principal: o menu e as ações do usuário.

A classe Aplicacao liga as peças: pergunta ao usuário (entrada.py e,
para a nota CVSS, pergunta_cvss.py), chama as regras do Inventario,
calcula o risco (risco.py), grava (armazenamento.py) e mostra o
resultado (telas.py). Para rodar: python main.py.

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
from armazenamento import ArquivoInventario, BaseInvalidaError
from classificacoes import (
    OrigemVulnerabilidade,
    SituacaoTratamento,
    TipoEquipamento,
)
from entrada import (
    SairDoPrograma,
    VoltarAoMenu,
    confirmar,
    ler_alteracao_opcional,
    ler_campo,
    ler_convertido,
    ler_decimal,
    ler_enum,
    ler_hostname,
    ler_inteiro,
    ler_opcao,
    ler_resposta,
    ler_texto,
    limpar_tela,
)
from equipamentos import MENOR_FRACAO
from ficha_tecnica import ROTULOS as ROTULOS_DA_FICHA
from ficha_tecnica import validar_valor
from formatacao import fracao_br, frase, numero_br
from pergunta_cvss import EXPLICACAO_NOTA, PALAVRA_CALCULAR, ler_nota_cvss
from risco import ModeloRisco, SistemaSingularError
from vulnerabilidades import validar_cve, validar_cwe, validar_referencia

# Com a variável definida (o Dockerfile a define), o programa avisa como
# sair do container sem derrubá-lo e não morre com Ctrl+C.
VARIAVEL_CONTAINER = "INVENTARIO_EM_CONTAINER"

# Acima disto a matriz não cabe na tela: a opção 15 mostra só o tamanho.
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
        """Recebe o ArquivoInventario onde a base é lida e gravada."""
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
        if not self.inventario:
            print("\n  " + cores.aviso(
                "Nenhum equipamento cadastrado ainda.\n"))
            return
        telas.mostrar_tabela(self.inventario.todos())
        print()

    def _ler_id_equipamento(self, mensagem="  ID do equipamento: "):
        """Lê o ID; "lista" mostra a tabela e pergunta de novo."""
        return ler_inteiro(mensagem, mostrar_lista=self._listar_para_id)

    def _ler_equipamento(self, mensagem="  ID do equipamento: "):
        """Lê um ID e devolve o equipamento, ou avisa e devolve None."""
        id_equipamento = self._ler_id_equipamento(mensagem)
        equipamento = self.inventario.buscar_por_id(id_equipamento)
        if equipamento is None:
            self._erro(f"Nenhum equipamento com o ID {id_equipamento}.")
        return equipamento

    # ------------------------------------------------------------------
    # Equipamentos (opções 1 a 5)
    # ------------------------------------------------------------------

    def cadastrar_equipamento(self):
        """Opção 1: cadastra um equipamento e suas vulnerabilidades."""
        print("\n" + cores.titulo("--- CADASTRAR EQUIPAMENTO ---") + "\n")
        hostname = ler_hostname("  Hostname: ",
                                self.inventario.problema_no_hostname)
        custodiante = ler_campo("  Responsável: ")
        lotacao = ler_campo("  Lotação (setor): ")
        descricao = ler_campo("  Descrição: ")
        tipo = ler_enum("  Tipo de equipamento:", TipoEquipamento)
        ficha = {}
        if confirmar("\n  Preencher a ficha técnica (fabricante, modelo, "
                     "patrimônio...)?"):
            ficha = self._ler_ficha_nova()

        try:
            equipamento = self.inventario.cadastrar_equipamento(
                tipo, hostname, custodiante, lotacao, descricao, ficha=ficha)
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

        if not self.inventario:
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return

        telas.mostrar_tabela(self.inventario.todos())
        # No fim, porque numa lista longa o título já saiu da tela.
        print(f"\n  Total: {len(self.inventario)} equipamento(s).")

    def buscar_equipamento(self):
        """Opção 3: acha equipamentos por id, hostname ou outros campos.

        O requisito 4 do T1 pede id e hostname; responsável, lotação,
        tipo, ficha técnica, CVE e CWE vão além. Um resultado mostra a
        ficha completa; vários, a tabela. A busca por CVE ou CWE mostra
        as ocorrências, com a situação em cada equipamento.
        """
        print("\n" + cores.titulo("--- BUSCAR EQUIPAMENTO ---") + "\n")
        print(f"    {cores.destaque('1')} - Por ID")
        print(f"    {cores.destaque('2')} - Por hostname")
        print(f"    {cores.destaque('3')} - Por responsável")
        print(f"    {cores.destaque('4')} - Por lotação")
        print(f"    {cores.destaque('5')} - Por tipo")
        print(f"    {cores.destaque('6')} - Por fabricante, modelo, série, "
              f"patrimônio ou sistema")
        print(f"    {cores.destaque('7')} - Por CVE ou CWE (onde a "
              f"vulnerabilidade aparece)")
        opcao = ler_inteiro("  Opção: ")

        if opcao == 7:
            self._buscar_referencia()
            return
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
        elif opcao == 6:
            termo = ler_texto("  Fabricante, modelo, série, patrimônio ou "
                              "sistema (ou parte): ")
            encontrados = self.inventario.buscar_na_ficha(termo)
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

    def _buscar_referencia(self):
        """Opção 3, item 7: os equipamentos com uma CVE ou um CWE.

        Responde a pergunta de quando sai uma falha nova: quais
        equipamentos a têm, e em que situação está cada um.
        """
        referencia = ler_convertido("  CVE ou CWE: ", validar_referencia)
        itens = self.inventario.ocorrencias_da_referencia(referencia)
        if not itens:
            self._erro(f"Nenhum equipamento tem a {referencia}.")
            return
        print(f"\n  {referencia} em {len(itens)} equipamento(s), da mais "
              f"grave:\n")
        telas.imprimir_ocorrencias(itens, com_hostname=True)

    def _mostrar_ficha_completa(self, equipamento):
        """Ficha do equipamento e as suas vulnerabilidades."""
        telas.mostrar_equipamento(equipamento)
        telas.mostrar_vulnerabilidades(
            self.inventario.vulnerabilidades_do(equipamento.id))

    def atualizar_equipamento(self):
        """Opção 4: altera campos de um equipamento (requisito 5 do T1).

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

        if confirmar("\n  Alterar a ficha técnica?"):
            mudancas = self._ler_alteracoes_da_ficha(equipamento)
            if mudancas:
                alteracoes["ficha"] = mudancas

        if not alteracoes:
            print("\n  " + cores.aviso("Nada foi alterado."))
            return

        try:
            self.inventario.atualizar_equipamento(equipamento.id, alteracoes)
        except ValueError as erro:
            self._erro(str(erro))
            return

        self._salvar()
        # Cada campo da ficha conta como um campo.
        campos = (len(alteracoes) - ("ficha" in alteracoes)
                  + len(alteracoes.get("ficha", {})))
        print("\n  " + cores.sucesso(
            f"Equipamento atualizado ({campos} campo(s))."))

    def _conversor_da_ficha(self, campo, id_equipamento=None):
        """Devolve a função que confere o texto de um campo da ficha.

        A função devolve o texto arrumado ou levanta ValueError com o
        motivo. No patrimônio, confere também que nenhum outro
        equipamento o tem.
        """
        rotulo = ROTULOS_DA_FICHA[campo]

        def converter(texto):
            valor = validar_valor(rotulo, texto)
            if campo == "patrimonio":
                problema = self.inventario.problema_no_patrimonio(
                    valor, id_equipamento)
                if problema:
                    raise ValueError(f"Patrimônio: {problema}")
            return valor

        return converter

    def _ler_ficha_nova(self):
        """Pergunta os campos da ficha técnica; Enter pula cada um."""
        print("\n  Ficha técnica: Enter pula o campo.")
        ficha = {}
        for campo, rotulo in ROTULOS_DA_FICHA.items():
            valor = ler_convertido(f"  {rotulo}: ",
                                   self._conversor_da_ficha(campo),
                                   opcional=True)
            if valor is not None:
                ficha[campo] = valor
        return ficha

    def _ler_alteracoes_da_ficha(self, equipamento):
        """Pergunta cada campo da ficha; Enter mantém, "-" apaga.

        Devolve {campo: valor novo} só com o que mudou (None apaga).
        """
        print("\n  Ficha técnica: Enter mantém o campo, \"-\" apaga.")
        mudancas = {}
        for campo, rotulo in ROTULOS_DA_FICHA.items():
            atual = getattr(equipamento.ficha, campo)
            alterou, valor = ler_alteracao_opcional(
                f"  {rotulo} [{atual or 'vazio'}]: ",
                self._conversor_da_ficha(campo, equipamento.id))
            if alterou and valor != atual:
                mudancas[campo] = valor
        return mudancas

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
            if ler_opcao("  Opção: ", 2) == 1:
                id_existente = self._ler_vulnerabilidade_do_catalogo(
                    equipamento)

        cve = None
        if id_existente is None:
            cve, id_existente = self._ler_cve_nova(equipamento)
        if id_existente is None:
            descricao = ler_campo("  Descrição da vulnerabilidade: ")
            origem = ler_enum("  Categoria:", OrigemVulnerabilidade)
            cwe = ler_convertido(
                "  CWE, o tipo de fraqueza (opcional, como CWE-416; Enter "
                "pula): ", validar_cwe, opcional=True)
            print("\n" + EXPLICACAO_NOTA)
            nota, vetor = ler_nota_cvss("  Nota CVSS: ")
        situacao = ler_enum("  Status neste equipamento:",
                            SituacaoTratamento)

        # Tudo foi perguntado: só agora o inventário muda.
        try:
            if id_existente is None:
                vuln = self.inventario.registrar_vulnerabilidade(
                    equipamento.id, descricao, origem, nota, situacao,
                    vetor, cve=cve, cwe=cwe)
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

    def _ler_cve_nova(self, equipamento):
        """Pergunta a CVE de uma vulnerabilidade nova (opcional).

        Devolve (cve, id_existente). Uma CVE já do catálogo não pode ser
        cadastrada de novo: o programa oferece registrar a que existe
        neste equipamento (e devolve o id dela) ou pergunta outra.
        """
        while True:
            cve = ler_convertido(
                "  CVE (opcional, como CVE-2019-0708; Enter pula): ",
                validar_cve, opcional=True)
            if cve is None:
                return None, None
            existente = self.inventario.vulnerabilidade_com_cve(cve)
            if existente is None:
                return cve, None
            if existente.id in equipamento.vulnerabilidades:
                self._erro(f"{equipamento.hostname} já tem a {cve} "
                           f"(vulnerabilidade {existente.id}).")
                continue
            print("  " + cores.aviso(
                f"A {cve} já está no catálogo: [{existente.id}] "
                f"{existente.descricao}."))
            if confirmar("  Registrar essa vulnerabilidade neste "
                         "equipamento?", padrao=True):
                return None, existente.id

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
        """Mostra as do equipamento e pede uma. None se não houver."""
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

        Mesma mecânica da opção 4: Enter mantém o valor atual.
        Descrição, CVE, CWE, categoria e nota são da vulnerabilidade e
        valem para todos os equipamentos que a têm; o status é de cada
        equipamento.
        """
        print("\n" + cores.titulo("--- ATUALIZAR VULNERABILIDADE ---") + "\n")
        equipamento = self._ler_equipamento()
        if equipamento is None:
            return
        vuln = self._ler_vulnerabilidade_do_equipamento(equipamento)
        if vuln is None:
            return

        situacao_atual = equipamento.vulnerabilidades[vuln.id]
        tinha_vetor = vuln.vetor is not None
        telas.mostrar_vulnerabilidade_em_edicao(
            vuln, situacao_atual, equipamento,
            self.inventario.afetados_por(vuln.id))
        print("\n  Deixe em branco para manter o valor atual.\n")

        alteracoes = self._ler_alteracoes_do_catalogo(vuln)
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
        # Nota e vetor contam como um campo só: mudam sempre juntos.
        campos = len(alteracoes.keys() - {"vetor"}) + int(mudou_situacao)
        print("\n  " + cores.sucesso(
            f"Vulnerabilidade atualizada ({campos} campo(s))."))
        if tinha_vetor and vuln.vetor is None:
            print("  " + cores.aviso(
                "A nota agora é digitada: o vetor antigo foi retirado."))

    def _ler_alteracoes_do_catalogo(self, vuln):
        """Pergunta descrição, CVE, CWE, categoria e nota.

        Enter mantém cada uma; na CVE e no CWE, "-" apaga. Devolve o
        dicionário de alterações para Inventario.
        atualizar_vulnerabilidade(): nota e vetor vão juntos.
        """
        alteracoes = {}
        novo = ler_campo(f"  Descrição [{vuln.descricao}]: ",
                         obrigatorio=False)
        if novo and frase(novo) != vuln.descricao:
            alteracoes["descricao"] = novo

        def cve_livre(texto):
            """A CVE digitada, se nenhuma outra vulnerabilidade tem."""
            cve = validar_cve(texto)
            outra = self.inventario.vulnerabilidade_com_cve(cve, vuln.id)
            if outra is not None:
                raise ValueError(f"A {cve} já está na vulnerabilidade "
                                 f"{outra.id}")
            return cve

        for campo, rotulo, converter in (("cve", "CVE", cve_livre),
                                         ("cwe", "CWE", validar_cwe)):
            atual = getattr(vuln, campo)
            alterou, valor = ler_alteracao_opcional(
                f"  {rotulo} [{atual or 'nenhum'}] - Enter mantém, \"-\" "
                f"apaga: ", converter)
            if alterou and valor != atual:
                alteracoes[campo] = valor

        nova_origem = ler_enum(
            f"  Categoria (atual: {vuln.origem.rotulo})"
            " - Enter para manter:",
            OrigemVulnerabilidade, opcional=True)
        if nova_origem not in (None, vuln.origem):
            alteracoes["origem"] = nova_origem
        resposta = ler_nota_cvss(
            f"\n  Nota CVSS [{numero_br(vuln.cvss)}] - número, vetor ou "
            f"\"{PALAVRA_CALCULAR}\": ", opcional=True)
        # A mesma nota digitada não muda nada: o vetor dela continua.
        if resposta not in (None, (vuln.cvss, None), (vuln.cvss, vuln.vetor)):
            alteracoes["cvss"], alteracoes["vetor"] = resposta
        return alteracoes

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
        """Opção 11: registra uma dependência (herança de risco)."""
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
        # Fração recusada (0, 1 ou além do que cabe): pergunta de novo.
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
        """Monta o modelo de risco, verifica I - A e resolve o sistema.

        Devolve o ModeloRisco já resolvido, ou None (já explicado na
        tela) se não há equipamentos, se o sistema não é invertível ou
        se a solução não confere: nesses casos nada é mostrado.
        """
        if not self.inventario:
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return None
        modelo = ModeloRisco(self.inventario)
        diagnostico = modelo.diagnosticar()
        telas.mostrar_diagnostico(diagnostico)
        if diagnostico.utilizavel:
            try:
                modelo.resolver()
                return modelo
            except SistemaSingularError as erro:
                self._erro(str(erro))
        print("  " + cores.erro(
            "! Nenhum risco efetivo foi calculado. Corrija as "
            "dependências (opção 12) e tente de novo."))
        return None

    def risco_de_todos(self):
        """Opção 13: risco próprio e efetivo de cada equipamento."""
        print("\n" + cores.titulo("--- RISCO DOS EQUIPAMENTOS ---"))
        modelo = self._montar_modelo()
        if modelo is None:
            return

        # Do mais ao menos arriscado; no empate, a ordem de cadastro.
        itens = sorted(modelo.relatorio(),
                       key=lambda i: (-i.efetivo, i.equipamento.id))
        telas.mostrar_relatorio_risco(itens, modelo.residuo)

    def risco_de_um(self):
        """Opção 14: o risco de um equipamento, passo a passo."""
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
        if not self.inventario:
            print("\n  " + cores.aviso("Nenhum equipamento cadastrado ainda."))
            return
        modelo = ModeloRisco(self.inventario)
        telas.mostrar_dimensoes(modelo)
        if max(modelo.M.shape) > MAXIMO_PARA_MOSTRAR_MATRIZES:
            # As matrizes não cabem; a verificação de I - A, sim.
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
                # Enter sozinho ou texto: desenha o menu de novo.
                # Depois de um "docker attach" a tela está vazia (o
                # Docker não repete o que já foi impresso), e o Enter é
                # como o usuário pede para vê-la. No container, o Enter
                # sozinho limpa a tela e traz também o logotipo, como
                # na abertura.
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
        """Espera o Enter antes de o menu voltar à tela.

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
        # A ordem dos except importa: o Python usa o primeiro que
        # servir. Os pedidos do usuário vêm antes do "except Exception"
        # genérico, senão "voltar" e "sair" seriam tratados como erro
        # inesperado.
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
        """Mostra o menu e executa as opções até confirmar a saída."""
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
                "solução confiável (opção 13 explica)."))

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
    except BaseInvalidaError as erro:
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
        # Só chega aqui um erro de arquivo durante a carga (nas
        # ações do menu, executar() trata): pasta sem permissão,
        # disco cheio...
        print("\n  " + cores.erro(
            f"! Não foi possível ler ou gravar o arquivo de dados: {erro}")
            + "\n")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Encerrado pelo usuário.\n")


if __name__ == "__main__":
    main()
