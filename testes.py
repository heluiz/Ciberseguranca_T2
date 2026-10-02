"""Testes automáticos: python testes.py (ou python -m unittest testes).

Reúne o que os autotestes de cada módulo não cobrem: o programa inteiro
rodando por dentro, com as respostas do teclado simuladas, e o arquivo
de dados conferido no disco. Usa só a biblioteca padrão (unittest) e
uma pasta temporária: nunca toca em dados/inventario.json.

Os autotestes de cada módulo (python equipamentos.py, por exemplo)
também rodam aqui, como último teste.
"""

import contextlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import cores
import main
from armazenamento import ArquivoInventario, BaseInvalidaError
from classificacoes import (
    OrigemVulnerabilidade,
    SituacaoTratamento,
    TipoEquipamento,
)
from equipamentos import criar_equipamento
from inventario import Inventario
from risco import ModeloRisco, SistemaSingularError

PASTA = os.path.dirname(os.path.abspath(__file__))

# Sem cores: a saída capturada vira texto puro, mesmo rodando num
# terminal. NO_COLOR vale para os autotestes, que rodam em outro
# processo; desligar() vale para este, que já importou cores.py.
os.environ["NO_COLOR"] = "1"
cores.desligar()


class EntradaAcabou(EOFError):
    """As respostas simuladas acabaram antes de o programa terminar."""


class TesteDoPrograma(unittest.TestCase):
    """Roda o menu real, com teclado simulado e base temporária."""

    def setUp(self):
        """Cria uma pasta temporária para a base de cada teste."""
        self._pasta = tempfile.TemporaryDirectory()
        self.addCleanup(self._pasta.cleanup)
        self.caminho = os.path.join(self._pasta.name, "dados",
                                    "inventario.json")

    def rodar(self, respostas):
        """Roda o programa com as respostas e devolve a saída impressa.

        As respostas são as linhas digitadas, na ordem. O programa é
        encerrado pela última, que deve ser "0" (ou o teste falha por
        a entrada ter acabado).
        """
        fila = list(respostas)

        def teclado(_mensagem=""):
            if not fila:
                raise EntradaAcabou("o programa pediu mais respostas")
            resposta = fila.pop(0)
            if resposta is EOFError:      # simula Ctrl+D
                raise EOFError
            return resposta

        saida = io.StringIO()
        arquivo = ArquivoInventario(self.caminho)
        aplicacao = main.Aplicacao(arquivo)
        # stdin falso: não é terminal, então a pausa do Enter é pulada.
        with (mock.patch("builtins.input", teclado),
              mock.patch("sys.stdin", io.StringIO()),
              mock.patch("time.sleep"),
              contextlib.redirect_stdout(saida)):
            aplicacao.iniciar()
        self.assertEqual(fila, [], "sobraram respostas não usadas")
        self.aplicacao = aplicacao
        return saida.getvalue()

    def lido(self):
        """Lê o JSON gravado, como um arquivo qualquer."""
        with open(self.caminho, encoding="utf-8") as f:
            return json.load(f)

    # --- cenário do enunciado, pelo menu ------------------------------

    CENARIO = [
        # E1 estação com V1 (4,0)
        "1", "ESTACAO-01", "Fulano de Tal", "Cartório", "Estação", "1",
        "s", "Vulnerabilidade V1", "6", "4", "1", "n",
        # E2 servidor: V1 (já existente) e V2 (6,0)
        "1", "SERVIDOR-01", "Fulano de Tal", "Sala técnica", "Servidor",
        "2", "s", "1", "1", "1", "s", "Vulnerabilidade V2", "6", "6", "1",
        "n",
        # E3 banco com V2 (já existente)
        "1", "BANCO-01", "Fulano de Tal", "Sala técnica", "Banco", "6",
        "s", "1", "2", "1", "n",
        # dependências: 1 herda 0,5 de 2; 2 herda 0,5 de 3;
        # 3 herda 0,25 de 2
        "11", "1", "2", "0,5",
        "11", "2", "3", "0,5",
        "11", "3", "2", "0,25",
    ]

    def test_cenario_de_3_equipamentos_pelo_menu(self):
        """Do cadastro ao risco: a conta feita à mão (16, 24, 18)."""
        saida = self.rodar(self.CENARIO + ["13", "0"])

        self.assertIn("estritamente diagonal dominante", saida)
        tabela = {}
        for linha in saida.splitlines():
            achado = re.match(r"\s+\d+\s+(\S+-01)\s.*?\s(\d+,\d\d)\s+"
                              r"(\d+,\d\d)\s", linha)
            if achado:
                tabela[achado.group(1)] = (achado.group(2),
                                           achado.group(3))
        self.assertEqual(tabela, {"ESTACAO-01": ("4,00", "16,00"),
                                  "SERVIDOR-01": ("15,00", "24,00"),
                                  "BANCO-01": ("12,00", "18,00")})

        # O arquivo é um array de objetos, um por equipamento, com as
        # vulnerabilidades e as dependências dentro.
        dados = self.lido()
        self.assertIsInstance(dados, list)
        self.assertEqual([e["hostname"] for e in dados],
                         ["ESTACAO-01", "SERVIDOR-01", "BANCO-01"])
        servidor = dados[1]
        self.assertEqual(
            [(v["id"], v["cvss"], v["situacao"])
             for v in servidor["vulnerabilidades"]],
            [(1, 4.0, 1), (2, 6.0, 1)])
        self.assertEqual(servidor["dependencias"],
                         [{"equipamento_id": 3, "fracao": 0.5}])
        # As três classes certas, de volta do arquivo.
        recarregado = ArquivoInventario(self.caminho).carregar()
        self.assertEqual([type(e).__name__ for e in recarregado.todos()],
                         ["EstacaoTrabalho", "Servidor", "BancoDados"])
        # A vulnerabilidade compartilhada volta como um só objeto.
        self.assertEqual(len(recarregado.vulnerabilidades()), 2)

    def test_detalhe_do_risco_mostra_a_conta(self):
        """A opção 14 mostra b, a parcela herdada e x do servidor."""
        saida = self.rodar(self.CENARIO + ["14", "2", "0"])
        self.assertIn("risco próprio b = 1,5 x 10,0 = 15,00", saida)
        self.assertRegex(saida, r"0,5 x\s+18,00")
        self.assertIn("Risco efetivo  x = b + A x = 15,00 + 9,00 = 24,00",
                      saida)

    def test_corrigir_vulnerabilidade_baixa_o_risco(self):
        """Marcar V2 como Corrigida no servidor tira V2 de M."""
        saida = self.rodar(self.CENARIO + [
            "8", "2", "2", "", "", "", "3", "13", "0"])
        # b2 = 1,5 x 4 = 6; x2 = 12 / 0,875 = 13,71
        self.assertRegex(saida, r"SERVIDOR-01\s+Servidor\s+4,0\s+1,5\s+"
                                r"6,00\s+13,71")

    # --- regras de dependência ----------------------------------------

    def test_soma_das_fracoes_nao_pode_chegar_a_1(self):
        """0,5 + 0,5 é recusado e nada é gravado; 0,49 passa."""
        saida = self.rodar(self.CENARIO + [
            "11", "2", "1", "0,5",     # 2 já tem 0,5 (para o 3): soma 1
            "0,49",                    # recusado, pergunta de novo: 0,99
            "0"])
        self.assertIn("precisa ficar abaixo de 1", saida)
        self.assertIn("Soma das frações de SERVIDOR-01: 0,99", saida)
        servidor = self.lido()[1]
        self.assertEqual(servidor["dependencias"], [
            {"equipamento_id": 1, "fracao": 0.49},
            {"equipamento_id": 3, "fracao": 0.5}])

    def test_dependencia_de_si_mesmo_e_destino_inexistente(self):
        """A[i][i] = 0, sem auto-dependência; o destino deve existir."""
        saida = self.rodar(self.CENARIO + [
            "11", "1", "1",            # de si mesmo
            "11", "1", "99",           # destino inexistente
            "0"])
        self.assertIn("não pode depender de si mesmo", saida)
        self.assertIn("Nenhum equipamento com o ID 99", saida)

    def test_fracao_com_virgula_ponto_e_lixo(self):
        """Frações 0,3 e 0.3 valem; nan, abc, 1 e 0 são recusados."""
        saida = self.rodar(self.CENARIO + [
            "11", "1", "3", "nan", "abc", "0,3",
            "11", "3", "1", "0.2",
            "11", "2", "1", "1",       # fração 1: recusada, pergunta de novo
            "voltar", "0"])
        self.assertEqual(saida.count("Digite um número"), 2)
        self.assertIn("deve ser maior que 0 e menor que 1", saida)
        dados = self.lido()
        self.assertEqual(dados[0]["dependencias"], [
            {"equipamento_id": 2, "fracao": 0.5},
            {"equipamento_id": 3, "fracao": 0.3}])
        self.assertEqual(dados[2]["dependencias"], [
            {"equipamento_id": 1, "fracao": 0.2},
            {"equipamento_id": 2, "fracao": 0.25}])

    # --- sistema singular ---------------------------------------------

    def test_sistema_singular_e_informado_e_nao_resolvido(self):
        """Arquivo editado com linhas somando 1: avisa, não calcula."""
        self.rodar(self.CENARIO + ["0"])
        dados = self.lido()
        for equipamento in dados:
            equipamento["dependencias"] = [
                {"equipamento_id": e["id"], "fracao": 0.5}
                for e in dados if e["id"] != equipamento["id"]
            ]
        with open(self.caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f)

        saida = self.rodar(["13", "14", "1", "0"])
        # Avisa já na abertura, e de novo nas duas opções de risco.
        self.assertEqual(saida.count("I - A não é invertível"), 2)
        self.assertIn("As dependências gravadas deixam o modelo de risco "
                      "sem solução", saida)
        self.assertEqual(saida.count("Nenhum risco efetivo foi calculado"),
                         2)
        self.assertNotIn("EFETIVO", saida)
        self.assertNotIn("Traceback", saida)

    # --- exclusão em cascata ------------------------------------------

    def test_excluir_equipamento_leva_o_que_estava_ligado(self):
        """Excluir o servidor remove as dependências ligadas a ele."""
        saida = self.rodar(self.CENARIO + ["5", "2", "s", "0"])
        self.assertIn("2 vulnerabilidade(s) registrada(s) nele e 2 "
                      "dependência(s)", saida)
        dados = self.lido()
        self.assertEqual([e["id"] for e in dados], [1, 3])
        self.assertTrue(all(e["dependencias"] == [] for e in dados))
        # V1 continua (o equipamento 1 a tem); V2, do banco, também.
        self.assertEqual([[v["id"] for v in e["vulnerabilidades"]]
                          for e in dados], [[1], [2]])

    def test_excluir_a_ultima_ocorrencia_tira_do_catalogo(self):
        """Sem equipamento nenhum, a vulnerabilidade sai do catálogo."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1",
            "s", "Vuln única", "1", "5", "1", "n",
            "9", "1", "1", "s", "0"])
        self.assertIn("Nenhum outro equipamento a tinha", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"], [])

    def test_id_excluido_nao_volta_enquanto_o_programa_roda(self):
        """O id 3, excluído, não é reaproveitado no próximo cadastro."""
        self.rodar(self.CENARIO + [
            "5", "3", "s",
            "1", "NOVO-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "0"])
        self.assertEqual([e["id"] for e in self.lido()], [1, 2, 4])

    # --- validações do cadastro ---------------------------------------

    def test_hostname_invalido_e_repetido_perguntam_de_novo(self):
        """O menu insiste até vir um hostname válido e único."""
        saida = self.rodar([
            "1", "PC 01", "-pc", "12345", "PC-01", "Fulano de Tal",
            "Setor", "Descrição", "1", "n",
            "1", "pc-01", "PC-02", "Fulano de Tal", "Setor", "Descrição",
            "1", "n", "0"])
        self.assertIn("caractere(s) não permitido(s)", saida)
        self.assertIn("não pode começar nem terminar com hífen", saida)
        self.assertIn("não pode ser composto só de números", saida)
        self.assertIn("já é usado por outro equipamento", saida)
        self.assertEqual([e["hostname"] for e in self.lido()],
                         ["PC-01", "PC-02"])

    def test_nota_cvss_invalida_pergunta_de_novo(self):
        """Fora da faixa, 2 casas, NaN e texto não passam; 7,5 passa."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1",
            "s", "Falha qualquer", "6", "0", "11", "8,25", "nan", "abc",
            "7,5", "1", "n", "0"])
        self.assertIn("A nota CVSS deve ficar entre 0,1 e 10,0", saida)
        self.assertIn("A nota CVSS tem uma casa decimal só", saida)
        self.assertIn("severidade Alta, nota 7,5", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"][0]["cvss"], 7.5)

    def test_mudar_o_tipo_troca_a_classe_e_mantem_as_relacoes(self):
        """Servidor que vira banco muda o fator, mas não os dados."""
        saida = self.rodar(self.CENARIO + [
            "4", "2", "", "", "", "", "6", "13", "0"])
        self.assertIn("Equipamento atualizado (1 campo(s))", saida)
        self.assertEqual(self.lido()[1]["tipo"], 6)
        # fator 2,0: b2 = 2 x 10 = 20
        self.assertRegex(saida, r"SERVIDOR-01\s+Banco de dados\s+10,0\s+2,0"
                                r"\s+20,00")

    # --- comandos globais e robustez ----------------------------------

    def test_voltar_descarta_o_que_nao_foi_gravado(self):
        """Digitar voltar no meio de um cadastro não grava nada."""
        saida = self.rodar(["1", "PC-01", "Fulano de Tal", "voltar", "0"])
        self.assertIn("Voltando ao menu", saida)
        self.assertFalse(os.path.exists(self.caminho))

    def test_sair_funciona_em_qualquer_pergunta(self):
        """Digitar sair numa pergunta encerra o programa."""
        saida = self.rodar(["1", "PC-01", "sair"])
        self.assertIn("Até logo", saida)

    def test_erro_inesperado_nao_derruba_e_recarrega_a_base(self):
        """Uma exceção numa ação é mostrada, e o menu continua."""
        with mock.patch.object(Inventario, "pendentes",
                               side_effect=RuntimeError("falha de teste")):
            saida = self.rodar(["10", "0"])
        self.assertIn("Erro inesperado (RuntimeError): falha de teste",
                      saida)
        self.assertIn("Base recarregada do disco", saida)

    def test_matrizes_so_para_cenarios_pequenos(self):
        """A opção 15 mostra M, v e A de 3 equipamentos."""
        saida = self.rodar(self.CENARIO + ["15", "0"])
        self.assertIn("M é 3 x 2", saida)
        self.assertIn("V1=4,0  V2=6,0", saida)
        self.assertRegex(saida, r"E3\s+0\s+0,25\s+0")
        # M v, a diagonal de F e b = F (M v), feitos à mão no README.
        self.assertRegex(saida, r"M v .*E1=4,0  E2=10,0  E3=6,0")
        self.assertRegex(saida, r"F .*E1=1,0  E2=1,5  E3=2,0")
        self.assertRegex(saida, r"b = F \(M v\).*E1=4,00  E2=15,00  E3=12,00")
        self.assertIn("det(I - A) = 0,875", saida)

    def test_matrizes_de_base_grande_mostram_so_a_verificacao(self):
        """Base grande: a opção 15 não desenha M, mas verifica I - A."""
        os.makedirs(os.path.dirname(self.caminho))
        with open(os.path.join(PASTA, "dados_exemplo",
                               "inventario_exemplo.json"),
                  encoding="utf-8") as origem:
            conteudo = origem.read()
        with open(self.caminho, "w", encoding="utf-8") as destino:
            destino.write(conteudo)
        saida = self.rodar(["15", "0"])
        self.assertIn("Grande demais para mostrar as matrizes", saida)
        self.assertIn("estritamente diagonal dominante", saida)
        self.assertIn("det(I - A) = 0,98", saida)

    # --- consultas do T1 pelo menu ------------------------------------

    def test_listar_e_buscar_por_id_e_por_hostname(self):
        """Opções 2 e 3: lista e acha por ID e por parte do hostname."""
        saida = self.rodar(self.CENARIO + [
            "2",
            "3", "1", "2",            # busca pelo ID 2
            "3", "2", "banco",        # busca por parte do hostname
            "3", "1", "99",           # ID que não existe
            "0"])
        self.assertIn("Total: 3 equipamento(s).", saida)
        self.assertEqual(saida.count("Hostname ...... SERVIDOR-01"), 1)
        self.assertEqual(saida.count("Hostname ...... BANCO-01"), 1)
        self.assertIn("Nenhum equipamento encontrado.", saida)

    def test_pendentes_da_mais_grave_para_a_menos_grave(self):
        """Opção 10: as 4 ocorrências abertas, 6,0 antes de 4,0."""
        saida = self.rodar(self.CENARIO + ["10", "0"])
        self.assertIn("4 aberta(s) ou em tratamento", saida)
        self.assertLess(saida.index("6,0 [2]"), saida.index("4,0 [1]"))

    def test_ver_e_remover_dependencia(self):
        """Opção 12: tira a dependência de E1 em E2, com confirmação."""
        saida = self.rodar(self.CENARIO + ["12", "1", "2", "s", "0"])
        self.assertIn("Dependência removida.", saida)
        self.assertEqual(self.lido()[0]["dependencias"], [])

    def test_verificacao_mostra_determinante_e_condicao(self):
        """A opção 13 mostra det(I - A) e o número de condição."""
        saida = self.rodar(self.CENARIO + ["13", "0"])
        self.assertIn("det(I - A) = 0,875 · número de condição de I - A = "
                      "2,56", saida)

    # --- base do Trabalho 1 e base ruim -------------------------------

    def test_base_do_trabalho_1_e_convertida_com_copia(self):
        """Base do T1: convertida ao abrir, com a original guardada."""
        t1 = {"ativos": {"1": {"hostname": "PC-01", "custodiante": "A",
                               "lotacao": "B", "descricao": "C",
                               "categoria": 2}},
              "falhas": {"1": {"ativo_id": 1, "descricao": "Falha",
                               "origem": 1, "gravidade": 3,
                               "situacao": 2}},
              "ultimo_id_ativo": 4, "ultimo_id_falha": 1}
        os.makedirs(os.path.dirname(self.caminho))
        with open(self.caminho, "w", encoding="utf-8") as f:
            json.dump(t1, f)

        saida = self.rodar(["7", "1", "0"])
        self.assertIn("A base era do Trabalho 1 e foi convertida", saida)
        self.assertRegex(saida, r"ALTA\s+7,5")
        dados = self.lido()
        self.assertIsInstance(dados, list)
        self.assertEqual(dados[0]["tipo"], 2)
        self.assertEqual(dados[0]["vulnerabilidades"][0]["cvss"], 7.5)
        with open(self.caminho + ".t1.bak", encoding="utf-8") as f:
            self.assertEqual(json.load(f), t1)

    def test_base_invalida_para_o_programa_sem_sobrescrever(self):
        """Base corrompida: aviso claro, código 1 e arquivo intacto."""
        os.makedirs(os.path.dirname(self.caminho))
        with open(self.caminho, "w", encoding="utf-8") as f:
            f.write('[{"id": 1, "tipo": ')
        saida = io.StringIO()
        with (mock.patch.dict(os.environ,
                              {"INVENTARIO_DADOS": self.caminho}),
              contextlib.redirect_stdout(saida),
              self.assertRaises(SystemExit) as parada):
            main.main()
        self.assertEqual(parada.exception.code, 1)
        self.assertIn("Não foi possível carregar a base de dados",
                      saida.getvalue())
        with open(self.caminho, encoding="utf-8") as f:
            self.assertEqual(f.read(), '[{"id": 1, "tipo": ')

    # --- container ----------------------------------------------------

    def test_container_sem_terminal_explica_e_para(self):
        """Sem terminal (docker run -d): aviso claro, não EOFError."""
        with (mock.patch.dict(os.environ,
                              {main.VARIAVEL_CONTAINER: "1"}),
              mock.patch("sys.stdin", io.StringIO()),
              self.assertRaises(SystemExit) as parada):
            main.preparar_container()
        self.assertIn("docker run -dit", str(parada.exception))

    def test_container_ignora_ctrl_c_e_trata_sigterm(self):
        """Ctrl+C no attach não derruba; docker stop sai com 0."""
        terminal = mock.Mock()
        terminal.isatty.return_value = True
        with (mock.patch("sys.stdin", terminal),
              mock.patch("signal.signal") as registrar):
            main.preparar_container()
        tratadores = {chamada.args[0]: chamada.args[1]
                      for chamada in registrar.call_args_list}
        self.assertIs(tratadores[signal.SIGINT], signal.SIG_IGN)
        with self.assertRaises(SystemExit) as parada:
            tratadores[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(parada.exception.code, 0)

    def test_container_pede_confirmacao_para_sair(self):
        """No container, a opção 0 avisa e só sai com confirmação."""
        with mock.patch.dict(os.environ, {main.VARIAVEL_CONTAINER: "1"}):
            saida = self.rodar(["0", "n", "0", "s"])
        self.assertEqual(saida.count("Este programa roda num container"), 2)
        self.assertIn("Até logo", saida)

    def test_container_sair_digitado_tambem_pede_confirmacao(self):
        """O comando sair, no container, também pede confirmação."""
        with mock.patch.dict(os.environ, {main.VARIAVEL_CONTAINER: "1"}):
            saida = self.rodar(["sair", "n", "1", "PC-01", "sair", "n",
                                "0", "s"])
        self.assertEqual(saida.count("Este programa roda num container"), 3)
        self.assertIn("Até logo", saida)
        self.assertFalse(os.path.exists(self.caminho))  # nada gravado

    def test_container_ctrl_d_e_ignorado(self):
        """No container, Ctrl+D (fim da entrada) não encerra o menu."""
        with mock.patch.dict(os.environ, {main.VARIAVEL_CONTAINER: "1"}):
            saida = self.rodar([EOFError, "1", "PC-01", EOFError, "0", "s"])
        self.assertEqual(saida.count("Ctrl+D não encerra"), 2)
        self.assertIn("Até logo", saida)

    def test_ctrl_d_fora_do_container_encerra(self):
        """Fora do container, o fim da entrada continua encerrando."""
        with self.assertRaises(EOFError):
            self.rodar([EOFError])

    def test_enter_sozinho_redesenha_o_menu(self):
        """Após o attach a tela está vazia: o Enter mostra o menu."""
        saida = self.rodar(["", "0"])
        self.assertEqual(saida.count("Cadastrar equipamento"), 2)
        self.assertNotIn("Digite apenas números", saida)
        saida = self.rodar(["abc", "0"])
        self.assertEqual(saida.count("Cadastrar equipamento"), 2)
        self.assertIn("Digite apenas números", saida)

    def test_container_enter_mostra_logotipo_e_menu(self):
        """No container, Enter no menu traz de volta a abertura."""
        with (mock.patch.dict(os.environ, {main.VARIAVEL_CONTAINER: "1"}),
              mock.patch("main.limpar_tela") as limpou):
            saida = self.rodar(["", "0", "s"])
        limpou.assert_called_once()
        # Uma vez na abertura do programa e outra depois do Enter.
        self.assertEqual(saida.count("INVENTÁRIO DE EQUIPAMENTOS E "
                                     "VULNERABILIDADES"), 2)
        self.assertEqual(saida.count("▓▓▓▓▓▓▓▓▓▓"), 2)
        self.assertEqual(saida.count("Cadastrar equipamento"), 2)

    def test_fora_do_container_enter_mostra_so_o_menu(self):
        """Fora do container, Enter redesenha só o menu, sem limpar."""
        with mock.patch("main.limpar_tela") as limpou:
            saida = self.rodar(["", "0"])
        limpou.assert_not_called()
        self.assertEqual(saida.count("▓▓▓▓▓▓▓▓▓▓"), 1)

    def test_matriz_invertivel_mas_sem_sentido_nao_e_resolvida(self):
        """Invertível, mas com risco efetivo negativo: só avisa."""
        self.rodar(self.CENARIO + ["0"])
        dados = self.lido()
        # 1 herda 0,9 de 2 e de 3; 2 e 3 herdam 0,9 de 1.
        dados[0]["dependencias"] = [
            {"equipamento_id": 2, "fracao": 0.9},
            {"equipamento_id": 3, "fracao": 0.9}]
        dados[1]["dependencias"] = [{"equipamento_id": 1, "fracao": 0.9}]
        dados[2]["dependencias"] = [{"equipamento_id": 1, "fracao": 0.9}]
        with open(self.caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f)

        saida = self.rodar(["13", "0"])
        self.assertIn("risco efetivo menor que o próprio", saida)
        self.assertIn("Nenhum risco efetivo foi calculado", saida)
        self.assertNotIn("EFETIVO", saida)

    def test_substituir_fracao_considera_a_soma_sem_a_antiga(self):
        """Ao substituir, a fração antiga não conta na soma da linha."""
        self.rodar(self.CENARIO + ["0"])
        dados = self.lido()
        dados[0]["dependencias"] = [
            {"equipamento_id": 2, "fracao": 0.6},
            {"equipamento_id": 3, "fracao": 0.4}]
        with open(self.caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f)
        saida = self.rodar(["11", "1", "2", "s", "0,1", "0"])
        # Substituir 0,6 por algo cabe (resta 0,6); o laço aceita 0,1.
        self.assertIn("Dependência registrada", saida)
        saida = self.rodar(["11", "1", "2", "s", "0,7", "0,5", "0"])
        self.assertIn("precisa ficar abaixo de 1", saida)
        self.assertIn("Dependência registrada", saida)


class TesteDoModelo(unittest.TestCase):
    """O modelo de risco sobre os arquivos de exemplo do projeto."""

    def carregar(self, nome):
        """Lê um arquivo de dados_exemplo/."""
        return ArquivoInventario(
            os.path.join(PASTA, "dados_exemplo", nome)).carregar()

    def test_cenario_de_validacao(self):
        """cenario_3_equipamentos.json dá x = (16, 24, 18)."""
        modelo = ModeloRisco(self.carregar("cenario_3_equipamentos.json"))
        self.assertEqual([round(i.proprio, 9) for i in modelo.relatorio()],
                         [4.0, 15.0, 12.0])
        self.assertEqual([round(i.efetivo, 9) for i in modelo.relatorio()],
                         [16.0, 24.0, 18.0])

    def test_cenario_singular_e_recusado_pelo_modelo(self):
        """cenario_singular.json carrega, mas não se resolve."""
        modelo = ModeloRisco(self.carregar("cenario_singular.json"))
        diagnostico = modelo.diagnosticar()
        self.assertFalse(diagnostico.invertivel)
        self.assertFalse(diagnostico.utilizavel)
        with self.assertRaises(SistemaSingularError):
            modelo.resolver()

    def test_base_de_exemplo_tem_solucao(self):
        """Base de exemplo (76 equipamentos): invertível e coerente."""
        inventario = self.carregar("inventario_exemplo.json")
        self.assertEqual(len(inventario), 76)
        modelo = ModeloRisco(inventario)
        diagnostico = modelo.diagnosticar()
        self.assertTrue(diagnostico.invertivel and diagnostico.dominante)
        modelo.resolver()
        self.assertLess(modelo.residuo, 1e-9)
        # O risco efetivo nunca é menor que o próprio.
        for item in modelo.relatorio():
            self.assertGreaterEqual(item.efetivo, item.proprio - 1e-9)

    def test_exemplo_regravado_e_igual(self):
        """Ler e gravar a base de exemplo não muda nenhum dado."""
        original = self.carregar("inventario_exemplo.json")
        with tempfile.TemporaryDirectory() as pasta:
            arquivo = ArquivoInventario(os.path.join(pasta, "x.json"))
            arquivo.salvar(original)
            self.assertEqual(arquivo.carregar().para_dict(),
                             original.para_dict())

    def test_ler_e_gravar_nao_muda_o_texto(self):
        """Textos como X Y e a SSH voltam do arquivo sem mudança."""
        inventario = Inventario()
        pc = inventario.cadastrar_equipamento(
            TipoEquipamento.OUTRO, "PC-01", "TI SETOR", "TI Setor", "x Y")
        inventario.registrar_vulnerabilidade(
            pc.id, "a SSH", OrigemVulnerabilidade.OUTRA, 5.0,
            SituacaoTratamento.ABERTA)
        antes = inventario.para_dict()
        for _ in range(3):
            inventario = Inventario.de_dict(
                json.loads(json.dumps(inventario.para_dict())))
            self.assertEqual(inventario.para_dict(), antes)

    def test_sem_fator_de_exposicao_b_e_m_v(self):
        """Com USAR_FATOR_DE_EXPOSICAO = False, b = M v do enunciado."""
        with mock.patch("risco.USAR_FATOR_DE_EXPOSICAO", False):
            modelo = ModeloRisco(self.carregar("cenario_3_equipamentos.json"))
        itens = modelo.relatorio()
        self.assertEqual([round(i.proprio, 9) for i in itens],
                         [4.0, 10.0, 6.0])
        # Resolvido à mão no README: 80/7, 104/7 e 68/7.
        for item, exato in zip(itens, (80 / 7, 104 / 7, 68 / 7),
                               strict=True):
            self.assertAlmostEqual(item.efetivo, exato, places=9)

    def test_soma_com_erro_de_ponto_flutuante_e_recusada(self):
        """0,7 + 0,2 + 0,1 dá 0,9999999999999999, mas é recusado."""
        inventario = Inventario()
        ids = [inventario.cadastrar_equipamento(
            TipoEquipamento.OUTRO, f"EQ-0{k}", "A", "B", "C").id
            for k in range(4)]
        inventario.registrar_dependencia(ids[0], ids[1], 0.7)
        inventario.registrar_dependencia(ids[0], ids[2], 0.2)
        self.assertLess(0.7 + 0.2 + 0.1, 1)        # o float engana...
        with self.assertRaises(ValueError):         # ...a regra, não
            inventario.registrar_dependencia(ids[0], ids[3], 0.1)

    def test_todo_tipo_tem_classe_e_fator(self):
        """Cada TipoEquipamento tem uma subclasse com fator positivo."""
        for tipo in TipoEquipamento:
            equipamento = criar_equipamento(tipo, 1, "EQ-01", "A", "B", "C")
            self.assertGreater(equipamento.fator_exposicao, 0)
            self.assertIs(equipamento.tipo, tipo)

    def test_matriz_invalida_do_arquivo_e_recusada(self):
        """Arquivo com dependência para id inexistente não carrega."""
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "x.json")
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(json.dumps([{
                    "id": 1, "tipo": 1, "hostname": "PC-01",
                    "custodiante": "A", "lotacao": "B",
                    "descricao": "C", "vulnerabilidades": [],
                    "dependencias": [{"equipamento_id": 9,
                                      "fracao": 0.3}]}]))
            with self.assertRaises(BaseInvalidaError):
                ArquivoInventario(caminho).carregar()

    def test_nome_repetido_num_objeto_e_recusado(self):
        """RFC 8259: "cvss" duas vezes no mesmo objeto é recusado."""
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "x.json")
            with open(caminho, "w", encoding="utf-8") as f:
                f.write('[{"id": 1, "tipo": 1, "hostname": "PC-01", '
                        '"custodiante": "A", "lotacao": "B", '
                        '"descricao": "C", "dependencias": [], '
                        '"vulnerabilidades": [{"id": 1, "descricao": "D", '
                        '"origem": 1, "cvss": 9.8, "cvss": 1.0, '
                        '"situacao": 1}]}]')
            with self.assertRaises(BaseInvalidaError) as erro:
                ArquivoInventario(caminho).carregar()
        self.assertIn("'cvss' aparece duas vezes", str(erro.exception))

    def test_arquivo_gravado_e_json_estrito(self):
        """O JSON gravado é UTF-8 sem BOM e relido pelo json estrito."""
        inventario = Inventario()
        inventario.cadastrar_equipamento(TipoEquipamento.OUTRO, "PC-01",
                                         "Suporte", "Sala", "Estação")
        with tempfile.TemporaryDirectory() as pasta:
            arquivo = ArquivoInventario(os.path.join(pasta, "x.json"))
            arquivo.salvar(inventario)
            with open(arquivo.caminho, "rb") as f:
                bruto = f.read()

        def recusar(constante):
            raise ValueError(f"constante fora do JSON: {constante}")

        self.assertFalse(bruto.startswith(b"\xef\xbb\xbf"))   # sem BOM
        dados = json.loads(bruto.decode("utf-8"),
                           parse_constant=recusar)  # NaN, Infinity
        self.assertEqual(dados[0]["hostname"], "PC-01")


class TesteDosAutotestes(unittest.TestCase):
    """Roda o autoteste de cada módulo, como "python modulo.py"."""

    def test_autotestes_dos_modulos(self):
        """Cada módulo com bloco de teste termina com código 0."""
        for modulo in ("classificacoes", "formatacao", "validacao",
                       "vulnerabilidades", "equipamentos", "inventario",
                       "armazenamento", "risco"):
            with self.subTest(modulo=modulo):
                resultado = subprocess.run(
                    [sys.executable, os.path.join(PASTA, modulo + ".py")],
                    capture_output=True, text=True, cwd=PASTA, timeout=120)
                self.assertEqual(resultado.returncode, 0,
                                 resultado.stdout[-800:] + resultado.stderr)
                self.assertIn("OK", resultado.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
