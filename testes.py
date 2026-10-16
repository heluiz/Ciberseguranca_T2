"""Testes automáticos: python testes.py (ou python -m pytest testes.py).

Reúne o que os autotestes de cada módulo não cobrem: o programa inteiro
rodando por dentro, com as respostas do teclado simuladas, e o arquivo
de dados conferido no disco. Usa só a biblioteca padrão (unittest) e
uma pasta temporária: nunca toca em dados/inventario.json.

Os autotestes de cada módulo (python equipamentos.py, por exemplo)
também rodam aqui, como último teste.
"""

import contextlib
import datetime
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

from numpy.linalg import LinAlgError

import base_cve
import cores
import main
from armazenamento import ArquivoInventario, BaseInvalidaError
from atualizacao_cve import (
    AtualizacaoError,
    baixar_primeiro,
    nota_do_registro,
)
from base_cve import BaseCVE, RegistroCVE, nome_curto
from classificacoes import (
    OrigemVulnerabilidade,
    SituacaoTratamento,
    TipoEquipamento,
)
from equipamentos import criar_equipamento
from ficha_tecnica import FichaTecnica
from inventario import Inventario
from risco import ModeloRisco, SistemaSingularError

PASTA = os.path.dirname(os.path.abspath(__file__))

# Sem cores: a saída capturada vira texto puro, mesmo rodando num
# terminal. NO_COLOR vale para os autotestes, que rodam em outro
# processo; desligar() vale para este, que já importou cores.py.
os.environ["NO_COLOR"] = "1"
cores.desligar()


# Base de CVEs dos testes: pequena e fixa, para os testes não dependerem
# da base real, que muda a cada atualização do catálogo.
RDP_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"      # 9,8
TOTAL_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"    # 10,0


def registro_cve(cve, fabricante, produto, nome, cvss=None, vetor=None,
                 cwes=(), ransomware=False, dia="2024-01-10"):
    """Um RegistroCVE para a base dos testes."""
    return RegistroCVE(
        cve=cve, fabricante=fabricante, produto=produto, nome=nome,
        descricao=f"{nome}. It allows remote attackers to run code.",
        cwes=tuple(cwes), adicionada=dia, prazo=dia, ransomware=ransomware,
        cvss=cvss, vetor=vetor, fonte_nota=None if cvss is None else "CNA")


def base_de_teste():
    """Quatro CVEs: RDP, FortiOS e dois produtos Cisco (um sem nota)."""
    return BaseCVE([
        registro_cve("CVE-2019-0708", "Microsoft", "Remote Desktop Services",
                     "Microsoft Remote Desktop Services Remote Code "
                     "Execution Vulnerability", 9.8, RDP_31, ["CWE-416"],
                     ransomware=True, dia="2021-11-03"),
        registro_cve("CVE-2024-21762", "Fortinet", "FortiOS",
                     "Fortinet FortiOS Out-of-Bound Write Vulnerability",
                     9.8, RDP_31, ["CWE-787"], dia="2024-02-09"),
        registro_cve("CVE-2023-20198", "Cisco", "IOS XE Web UI",
                     "Cisco IOS XE Web UI Privilege Escalation "
                     "Vulnerability", 10.0, TOTAL_31, ["CWE-420"],
                     dia="2023-10-16"),
        registro_cve("CVE-2024-20481", "Cisco", "Adaptive Security Appliance",
                     "Cisco ASA Missing Release of Resource Vulnerability",
                     dia="2024-10-24"),
    ], catalogo="2026.10.13", publicado="2026-10-13",
        montado_em="2026-10-14", origem="inicial")


class RespostaSimulada(io.BytesIO):
    """A resposta de um download simulado, como a de urlopen()."""

    def __init__(self, corpo, url):
        """Guarda o corpo (bytes, ou um objeto, que vira JSON)."""
        if not isinstance(corpo, bytes):
            corpo = json.dumps(corpo).encode()
        super().__init__(corpo)
        self.url = url

    def geturl(self):
        """O endereço de onde a resposta veio."""
        return self.url


def abrir_simulado(catalogo, oficiais):
    """Uma função abrir(url) que responde sem usar a internet.

    catalogo é o KEV; oficiais, {cve: registro oficial}. CVE fora de
    oficiais responde 404, como o servidor de verdade.
    """
    def abrir(url):
        """Responde com o catálogo ou com o registro da CVE."""
        if url.endswith("known_exploited_vulnerabilities.json"):
            return RespostaSimulada(catalogo, url)
        cve = url.rsplit("/", 1)[1].removesuffix(".json")
        if cve not in oficiais:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        return RespostaSimulada(oficiais[cve], url)

    return abrir


def entrada_do_kev(cve, fabricante, produto, nome, dia):
    """Uma entrada do catálogo KEV, com os campos que o programa lê."""
    return {"cveID": cve, "vendorProject": fabricante, "product": produto,
            "vulnerabilityName": nome, "shortDescription": f"{nome}.",
            "dateAdded": dia, "dueDate": dia, "cwes": [],
            "knownRansomwareCampaignUse": "Unknown", "notes": ""}


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
        # A base de CVEs é vazia: o teste que usa a base põe a sua em
        # self.base_cve, e o que atualiza põe em self.abrir o download
        # simulado. A base atualizada iria para a pasta temporária.
        self.base_cve = BaseCVE()
        self.abrir = None
        variavel = mock.patch.dict(os.environ, {
            "INVENTARIO_BASE_CVE": os.path.join(self._pasta.name, "dados",
                                                "base_cve.json")})
        variavel.start()
        self.addCleanup(variavel.stop)

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
        aplicacao = main.Aplicacao(arquivo, base_cve=self.base_cve,
                                   abrir=self.abrir)
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
        # E1 estação com V1 (4,0). Depois do tipo, "n" pula a ficha
        # técnica; na vulnerabilidade nova, "" pula a CVE e o CWE.
        "1", "ESTACAO-01", "Fulano de Tal", "Cartório", "Estação", "1",
        "n", "s", "", "Vulnerabilidade V1", "6", "", "4", "1", "n",
        # E2 servidor: V1 (já existente) e V2 (6,0)
        "1", "SERVIDOR-01", "Fulano de Tal", "Sala técnica", "Servidor",
        "2", "n", "s", "1", "1", "1", "s", "", "Vulnerabilidade V2", "6",
        "", "6", "1", "n",
        # E3 banco com V2 (já existente)
        "1", "BANCO-01", "Fulano de Tal", "Sala técnica", "Banco", "6",
        "n", "s", "1", "2", "1", "n",
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
            "8", "2", "2", "", "", "", "", "", "3", "13", "0"])
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
        # Rouché-Capelli: b = (4, 15, 12) não está na imagem de I - A.
        self.assertIn("Pelo teorema de Rouché-Capelli, o sistema não tem "
                      "solução", saida)
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
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "", "Vuln única", "1", "", "5", "1", "n",
            "9", "1", "1", "s", "0"])
        self.assertIn("Nenhum outro equipamento a tinha", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"], [])

    def test_id_excluido_nao_volta_enquanto_o_programa_roda(self):
        """O id 3, excluído, não é reaproveitado no próximo cadastro."""
        self.rodar(self.CENARIO + [
            "5", "3", "s",
            "1", "NOVO-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "n", "0"])
        self.assertEqual([e["id"] for e in self.lido()], [1, 2, 4])

    # --- validações do cadastro ---------------------------------------

    def test_hostname_invalido_e_repetido_perguntam_de_novo(self):
        """O menu insiste até vir um hostname válido e único."""
        saida = self.rodar([
            "1", "PC 01", "-pc", "12345", "PC-01", "Fulano de Tal",
            "Setor", "Descrição", "1", "n", "n",
            "1", "pc-01", "PC-02", "Fulano de Tal", "Setor", "Descrição",
            "1", "n", "n", "0"])
        self.assertIn("caractere(s) não permitido(s)", saida)
        self.assertIn("não pode começar nem terminar com hífen", saida)
        self.assertIn("não pode ser composto só de números", saida)
        self.assertIn("já é usado por outro equipamento", saida)
        self.assertEqual([e["hostname"] for e in self.lido()],
                         ["PC-01", "PC-02"])

    def test_nota_cvss_invalida_pergunta_de_novo(self):
        """Fora da faixa, 2 casas, NaN e texto não passam; 7,5 passa."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "", "Falha qualquer", "6", "", "0", "11", "8,25", "nan",
            "abc", "7,5", "1", "n", "0"])
        self.assertIn("A nota CVSS deve ficar entre 0,1 e 10,0", saida)
        self.assertIn("A nota CVSS tem uma casa decimal só", saida)
        self.assertIn("severidade Alta, nota 7,5", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"][0]["cvss"], 7.5)

    # --- nota CVSS pelo vetor e pelas perguntas -----------------------

    # Um equipamento cadastrado, até a pergunta da nota CVSS.
    ATE_A_NOTA = ["1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1",
                  "n", "s", "", "Falha qualquer", "6", ""]
    # Respostas da calculadora: Enter (versão 4.0) e as 11 perguntas,
    # que dão o vetor de uma falha explorável pela rede, sem login.
    PERGUNTAS_40 = ["", "1", "1", "1", "1", "1", "1", "1", "1",
                    "3", "3", "3"]
    VETOR_40 = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/"
                "SI:N/SA:N")
    VETOR_31 = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_calcular_a_nota_respondendo_as_perguntas(self):
        """Com "calcular", o programa faz as perguntas do CVSS 4.0."""
        saida = self.rodar(self.ATE_A_NOTA + ["calcular"]
                           + self.PERGUNTAS_40 + ["", "1", "n", "0"])
        # O Enter em "Usar esta nota? (S/n)" aceitou a nota.
        self.assertIn("[1/11] Vetor de ataque (AV)", saida)
        self.assertIn("De onde o atacante consegue explorar a falha?", saida)
        self.assertIn("explorável remotamente", saida)
        self.assertIn("[11/11] Disponibilidade nos sistemas subsequentes",
                      saida)
        self.assertIn(f"Vetor: {self.VETOR_40}", saida)
        self.assertIn("severidade Crítica, nota 9,3", saida)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual((vuln["cvss"], vuln["vetor"]), (9.3, self.VETOR_40))

    def test_letra_anterior_e_cancelar_nas_perguntas(self):
        """Letra vale como resposta; anterior volta; cancelar sai."""
        # Versão "4.0"; AV pela letra (A), "anterior" e AV de novo (N);
        # "limpar" redesenha a pergunta; o resto pela primeira opção,
        # com os impactos nos outros sistemas em N.
        respostas = ["4.0", "a", "anterior", "n", "limpar", "l", "1",
                     "1", "1", "1", "1", "1", "n", "n", "n", "s"]
        saida = self.rodar(self.ATE_A_NOTA + ["calcular", "cancelar",
                                              "calcular"] + respostas
                           + ["1", "n", "0"])
        self.assertIn("Cálculo cancelado.", saida)
        # A 2ª pergunta aparece 3 vezes: a primeira, depois do
        # "anterior" e depois do "limpar", que a desenha de novo.
        self.assertEqual(saida.count("[2/11] Complexidade do ataque"), 3)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual((vuln["cvss"], vuln["vetor"]), (9.3, self.VETOR_40))

    def test_colar_o_vetor_da_calculadora(self):
        """O vetor colado (3.1) vira a nota 8,8 e fica gravado."""
        saida = self.rodar(self.ATE_A_NOTA + [self.VETOR_31.lower(), "1",
                                              "n", "7", "1", "0"])
        self.assertIn("Nota calculada pelo vetor: 8,8", saida)
        self.assertIn("severidade Alta, nota 8,8", saida)
        self.assertIn(self.VETOR_31, saida)          # a ficha mostra
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual((vuln["cvss"], vuln["vetor"]), (8.8, self.VETOR_31))

    def test_vetor_com_metricas_nao_definidas_e_aceito(self):
        """Métricas X (não definidas) são ignoradas no vetor."""
        saida = self.rodar(self.ATE_A_NOTA + [
            self.VETOR_31 + "/E:X/RL:X/RC:X", "1", "n", "0"])
        self.assertIn("Nota calculada pelo vetor: 8,8", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"][0]["vetor"],
                         self.VETOR_31)

    def test_vetor_invalido_e_nota_zero_perguntam_de_novo(self):
        """Vetor incompleto, sem começo, com sobra ou nota 0,0: não."""
        saida = self.rodar(self.ATE_A_NOTA + [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            self.VETOR_31 + "/E:U", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "abc",
            "7,5", "1", "n", "0"])
        self.assertIn("Faltam métricas no vetor: A", saida)
        self.assertIn("E:U é uma métrica temporal", saida)
        self.assertIn("O vetor deve começar com CVSS:4.0/, CVSS:3.1/", saida)
        self.assertIn("O vetor dá nota 0,0", saida)
        self.assertIn('cole o vetor CVSS ou digite "calcular"', saida)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual(vuln["cvss"], 7.5)
        self.assertNotIn("vetor", vuln)

    def test_desistir_do_calculo_volta_a_pergunta(self):
        """Nota recusada (3.1) ou nota 0,0: a pergunta volta."""
        perguntas_31 = ["2", "2", "1", "1", "1", "1", "1", "1", "1"]
        sem_impacto = ["", "1", "1", "1", "1", "1", "3", "3", "3",
                       "3", "3", "3"]
        saida = self.rodar(self.ATE_A_NOTA + ["calcular"] + perguntas_31
                           + ["n", "calcular"] + sem_impacto
                           + ["4,0", "1", "n", "0"])
        self.assertIn("[8/8] Disponibilidade (A)", saida)
        self.assertIn(f"Vetor: {self.VETOR_31}", saida)
        self.assertIn("Nota descartada", saida)
        self.assertIn("As respostas dão nota 0,0", saida)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual(vuln["cvss"], 4.0)
        self.assertNotIn("vetor", vuln)

    def test_nota_digitada_na_atualizacao_tira_o_vetor(self):
        """Opção 8: o vetor novo muda a nota; a nota digitada o tira."""
        saida = self.rodar(self.ATE_A_NOTA + [
            self.VETOR_31, "1", "n",
            "8", "1", "1", "", "", "", "", "calcular"] + self.PERGUNTAS_40
            + ["s", "",
               "8", "1", "1", "", "", "", "", "6,5", ""] + ["0"])
        self.assertIn("Vetor CVSS .... " + self.VETOR_31, saida)
        self.assertIn("Vetor CVSS .... " + self.VETOR_40, saida)
        self.assertIn("o vetor antigo foi retirado", saida)
        self.assertEqual(saida.count("Vulnerabilidade atualizada "
                                     "(1 campo(s))"), 2)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual(vuln["cvss"], 6.5)
        self.assertNotIn("vetor", vuln)

    def test_atualizar_com_os_mesmos_valores_nao_muda_nada(self):
        """Mesma descrição, categoria e nota: nada muda."""
        saida = self.rodar(self.ATE_A_NOTA + [
            self.VETOR_31, "1", "n",
            "8", "1", "1", "falha qualquer", "", "", "6", "8,8", "", "0"])
        self.assertIn("Nada foi alterado.", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"][0]["vetor"],
                         self.VETOR_31)

    def test_mudar_o_tipo_troca_a_classe_e_mantem_as_relacoes(self):
        """Servidor que vira banco muda o fator, mas não os dados."""
        saida = self.rodar(self.CENARIO + [
            "4", "2", "", "", "", "", "6", "n", "13", "0"])
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
        # Posto: M tem 2 colunas independentes; I - A, posto cheio.
        self.assertIn("Posto de M: 2; núcleo de M: dimensão 0", saida)
        self.assertIn("posto de I - A = 3 (de 3)", saida)

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
        # Teorema do núcleo e da imagem, na base de exemplo.
        self.assertIn("Posto de M: 56; núcleo de M: dimensão 23 (56 + 23 = "
                      "79 colunas)", saida)
        self.assertIn("14 colunas de M são nulas", saida)

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

    def test_solucao_que_nao_confere_e_avisada_no_menu(self):
        """Opção 13: se (I - A) x não der b, avisa e não mostra nada."""
        self.rodar(self.CENARIO + ["0"])
        with mock.patch("risco.np.linalg.solve",
                        return_value=[0.0, 0.0, 0.0]):
            saida = self.rodar(["13", "0"])
        self.assertIn("A solução não confere", saida)
        self.assertIn("Nenhum risco efetivo foi calculado", saida)
        self.assertNotIn("Erro inesperado", saida)
        self.assertNotIn("EFETIVO", saida)

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

    # --- número de condição alto --------------------------------------

    def test_aviso_de_condicao_alta_no_menu(self):
        """Condição acima de 1e8: o risco sai, com o aviso."""
        inventario = Inventario()
        ids = [inventario.cadastrar_equipamento(
            TipoEquipamento.OUTRO, f"Q-0{k}", "A", "B", "C").id
            for k in (1, 2, 3)]
        inventario.registrar_vulnerabilidade(
            ids[0], "x", OrigemVulnerabilidade.OUTRA, 5.0,
            SituacaoTratamento.ABERTA)
        for (i, j), fracao in {(0, 1): 0.5, (0, 2): 0.5001,
                               (1, 0): 0.9999, (2, 0): 0.9999}.items():
            inventario.buscar_por_id(ids[i]).dependencias[ids[j]] = fracao
        ArquivoInventario(self.caminho).salvar(inventario)
        saida = self.rodar(["13", "0"])
        self.assertIn("a solução pode ter poucos dígitos confiáveis", saida)
        self.assertIn("EFETIVO", saida)

    # --- CVE, CWE e ficha técnica -------------------------------------

    def test_cve_e_cwe_no_cadastro_e_na_busca(self):
        """A CVE já cadastrada é reaproveitada; a busca acha os dois."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "cve-2019-0708", "BlueKeep no servidor", "2", "416",
            "9,8", "1", "n",
            # No servidor, "nova" com a mesma CVE: vira a já cadastrada.
            "1", "SRV-01", "Fulano de Tal", "Setor", "Servidor", "2", "n",
            "s", "2", "CVE-2019-0708", "", "1", "n",
            "3", "7", "2019-0708",
            "3", "7", "bluekeep", "CWE-798",
            "0"])
        self.assertIn("A CVE-2019-0708 já está no catálogo: [1]", saida)
        self.assertIn("CVE-2019-0708 em 2 equipamento(s)", saida)
        busca = saida[saida.index("CVE-2019-0708 em 2"):]
        self.assertIn("PC-01 · Aberta · Falta de atualização · "
                      "CVE-2019-0708 · CWE-416", busca)
        self.assertIn("SRV-01 · Aberta", busca)
        self.assertIn("! Digite uma CVE, como CVE-2019-0708, ou um CWE, "
                      "como CWE-416.", saida)
        self.assertIn("Nenhum equipamento tem a CWE-798.", saida)
        dados = self.lido()
        vuln = dados[0]["vulnerabilidades"][0]
        self.assertEqual((vuln["cve"], vuln["cwe"], vuln["cvss"]),
                         ("CVE-2019-0708", "CWE-416", 9.8))
        self.assertEqual(dados[1]["vulnerabilidades"],
                         [dict(vuln, situacao=1)])
        recarregado = ArquivoInventario(self.caminho).carregar()
        self.assertEqual(len(recarregado.vulnerabilidades()), 1)

    def test_cve_invalida_repetida_e_recusada(self):
        """Formato errado e CVE que o equipamento já tem: de novo."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "CVE-2014-0160", "Heartbleed", "2", "", "7,5", "1", "n",
            "6", "1", "CVE-21-1", "CVE-2014-0160", "",
            "Outra falha", "1", "", "5", "1",
            # No servidor: recusa a já cadastrada e cadastra outra.
            "1", "SRV-01", "Fulano de Tal", "Setor", "Servidor", "2", "n",
            "s", "2", "CVE-2014-0160", "n", "",
            "Falha do servidor", "1", "", "6", "1", "n",
            "0"])
        self.assertIn("! A CVE tem o formato CVE-ano-número, como "
                      "CVE-2019-0708.", saida)
        self.assertIn("PC-01 já tem a CVE-2014-0160 (vulnerabilidade 1).",
                      saida)
        dados = self.lido()
        self.assertEqual([v.get("cve") for v in dados[0]["vulnerabilidades"]],
                         ["CVE-2014-0160", None])
        self.assertEqual([v["id"] for v in dados[1]["vulnerabilidades"]],
                         [3])
        self.assertNotIn("cve", dados[1]["vulnerabilidades"][0])

    def test_atualizar_cve_e_apagar_cwe(self):
        """Opção 8: CVE de outra recusada, nova aceita, "-" apaga."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "CVE-2019-0708", "BlueKeep", "2", "", "9,8", "1",
            "s", "2", "CVE-2014-0160", "Heartbleed", "2", "CWE-125", "7,5",
            "1", "n",
            "8", "1", "2", "", "CVE-2019-0708", "CVE-2024-3094", "-",
            "", "", "", "0"])
        self.assertIn("CVE ........... CVE-2014-0160", saida)
        self.assertIn("CWE ........... CWE-125", saida)
        self.assertIn("! A CVE-2019-0708 já está na vulnerabilidade 1.",
                      saida)
        self.assertIn("Vulnerabilidade atualizada (2 campo(s)).", saida)
        vuln = self.lido()[0]["vulnerabilidades"][1]
        self.assertEqual(vuln["cve"], "CVE-2024-3094")
        self.assertNotIn("cwe", vuln)

    def test_ficha_tecnica_no_cadastro_na_busca_e_na_atualizacao(self):
        """Fabricante, modelo, série, patrimônio, sistema e versão."""
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "s",
            "Dell", "OptiPlex  7010", "ABC123", "445566", "Windows 11 Pro",
            "23H2", "n",
            # Patrimônio repetido: pergunta de novo.
            "1", "PC-02", "Fulano de Tal", "Setor", "Estação", "1", "s",
            "", "", "", "445566", "445567", "", "", "n",
            "3", "6", "optiplex",
            # Opção 4: mantém tudo, menos modelo (apagado) e versão.
            "4", "1", "", "", "", "", "", "s",
            "", "-", "", "445567", "", "", "24H2",
            "0"])
        self.assertIn("! Patrimônio: o patrimônio 445566 já é do "
                      "equipamento 1 (PC-01).", saida)
        self.assertIn("Modelo ........ OptiPlex 7010", saida)
        self.assertIn("Patrimônio .... 445566", saida)
        self.assertIn("Versão ........ 23H2", saida)
        self.assertIn("! Patrimônio: o patrimônio 445567 já é do "
                      "equipamento 2 (PC-02).", saida)
        self.assertIn("Equipamento atualizado (2 campo(s)).", saida)
        dados = self.lido()
        self.assertEqual(dados[0]["ficha"], {
            "fabricante": "Dell", "numero_serie": "ABC123",
            "patrimonio": "445566", "sistema": "Windows 11 Pro",
            "versao": "24H2"})
        self.assertEqual(dados[1]["ficha"], {"patrimonio": "445567"})
        self.assertEqual(list(dados[0])[:7], [
            "id", "tipo", "hostname", "custodiante", "lotacao",
            "descricao", "ficha"])

    def test_sem_ficha_o_arquivo_nao_ganha_o_campo(self):
        """Equipamento sem ficha técnica: o JSON fica como antes."""
        self.rodar(self.CENARIO + ["0"])
        dados = self.lido()
        self.assertTrue(all("ficha" not in e for e in dados))
        self.assertTrue(all("cve" not in v and "cwe" not in v
                            for e in dados for v in e["vulnerabilidades"]))

    # --- base de CVEs exploradas (opção 16) ---------------------------

    UM_PC = ["1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
             "n"]

    def test_busca_na_base_e_registro_da_cve(self):
        """Opção 16: busca por palavras, detalhes e registro no PC."""
        self.base_cve = base_de_teste()
        saida = self.rodar(self.UM_PC + [
            "16", "1", "remote desktop", "1", "s", "1", "", "1", "0"])
        self.assertIn("Catálogo KEV da CISA de 13/10/2026: 4 CVEs "
                      "exploradas, 3 com nota CVSS", saida)
        self.assertIn('1 CVE(s) com "remote desktop"', saida)
        self.assertRegex(saida, r"1\s+CVE-2019-0708\s+9,8\s+Microsoft\s+"
                                r"Remote Desktop Services\s+Remote Code "
                                r"Execution")
        self.assertIn("Usada em campanhas de ransomware", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"], [{
            "id": 1, "descricao": "Microsoft Remote Desktop Services Remote "
                                  "Code Execution Vulnerability",
            "cve": "CVE-2019-0708", "cwe": "CWE-416", "origem": 2,
            "cvss": 9.8, "vetor": RDP_31, "situacao": 1}])

    def test_busca_sem_resultado_lembra_que_a_base_esta_em_ingles(self):
        """Em português não acha; sem acento e pelo começo, acha."""
        self.base_cve = base_de_teste()
        saida = self.rodar(["16", "1", "área de trabalho remota", "0"])
        self.assertIn("estão em inglês", saida)
        saida = self.rodar(["16", "1", "REMÓTE DESK", "", "0"])
        self.assertIn("CVE-2019-0708", saida)

    def test_navegar_por_fabricante_e_produto(self):
        """Fabricante com dois produtos: escolhe o produto e a CVE."""
        self.base_cve = base_de_teste()
        saida = self.rodar(["16", "2", "", "1", "2", "1", "n", "0"])
        # A Cisco tem 2 CVEs e vem primeiro; os produtos vêm em ordem.
        self.assertRegex(saida, r"1 - Cisco \(2\)")
        self.assertIn("Produtos de Cisco:", saida)
        self.assertRegex(saida, r"2 - IOS XE Web UI \(1\)")
        self.assertIn("CVE-2023-20198 - Cisco IOS XE Web UI Privilege", saida)
        self.assertIn("10,0 (Crítica)", saida)
        # Com um produto só, a lista das CVEs vem direto.
        saida = self.rodar(["16", "2", "forti", "1", "", "0"])
        self.assertNotIn("Produtos de Fortinet", saida)
        self.assertIn("Fortinet FortiOS: 1 CVE(s)", saida)

    def test_sugestoes_pela_ficha_marcam_as_ja_registradas(self):
        """Ficha com Fortinet e FortiOS: a CVE do FortiOS é sugerida."""
        self.base_cve = base_de_teste()
        saida = self.rodar([
            "1", "FW-01", "Fulano de Tal", "Sala técnica", "Firewall", "3",
            "s", "Fortinet", "FortiGate 60F", "", "", "FortiOS", "7.2", "n",
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n", "n",
            "16", "3", "1", "1", "s", "", "1",
            "16", "3", "1", "",
            "16", "3", "2",
            "0"])
        self.assertIn("1 CVE(s) combinam com a ficha de FW-01 (fortinet, "
                      "fortios)", saida)
        self.assertIn("não pela versão", saida)
        self.assertRegex(saida, r"1\*\s+CVE-2024-21762")
        self.assertIn("* já registrada neste equipamento", saida)
        self.assertIn("PC-01 não tem ficha técnica", saida)
        self.assertEqual(self.lido()[0]["vulnerabilidades"][0]["cve"],
                         "CVE-2024-21762")

    def test_cadastro_com_cve_da_base_usa_os_dados_dela(self):
        """No cadastro, a CVE da base traz descrição, CWE e nota."""
        self.base_cve = base_de_teste()
        saida = self.rodar([
            "1", "PC-01", "Fulano de Tal", "Setor", "Estação", "1", "n",
            "s", "cve-2019-0708", "", "", "1", "n",
            # Outra, recusando os dados da base: tudo é perguntado.
            "6", "1", "CVE-2024-21762", "n", "Falha no firewall", "2", "",
            "7,5", "1",
            "0"])
        self.assertIn("A CVE-2019-0708 está na base de CVEs exploradas",
                      saida)
        primeira, segunda = self.lido()[0]["vulnerabilidades"]
        self.assertEqual((primeira["cve"], primeira["cwe"], primeira["cvss"],
                          primeira["vetor"]),
                         ("CVE-2019-0708", "CWE-416", 9.8, RDP_31))
        self.assertEqual(segunda, {"id": 2, "descricao": "Falha no firewall",
                                   "cve": "CVE-2024-21762", "origem": 2,
                                   "cvss": 7.5, "situacao": 1})

    def test_cve_da_base_sem_nota_pergunta_a_nota(self):
        """A CVE sem nota no registro oficial: a nota é perguntada."""
        self.base_cve = base_de_teste()
        saida = self.rodar(self.UM_PC + [
            "16", "1", "CVE-2024-20481", "1", "s", "1", "", "5,8", "1", "0"])
        self.assertIn("sem nota no registro oficial", saida)
        vuln = self.lido()[0]["vulnerabilidades"][0]
        self.assertEqual((vuln["cve"], vuln["cvss"]), ("CVE-2024-20481", 5.8))
        self.assertNotIn("vetor", vuln)
        self.assertNotIn("cwe", vuln)

    def test_registrar_cve_que_ja_esta_no_catalogo_reaproveita(self):
        """A mesma CVE em dois equipamentos é uma vulnerabilidade só."""
        self.base_cve = base_de_teste()
        saida = self.rodar(self.UM_PC + [
            "1", "PC-02", "Fulano de Tal", "Setor", "Estação", "1", "n", "n",
            "16", "1", "CVE-2019-0708", "1", "s", "1", "", "1",
            "16", "1", "CVE-2019-0708", "1", "s", "2", "2",
            "16", "1", "CVE-2019-0708", "1", "s", "1",
            "0"])
        self.assertIn("A CVE-2019-0708 já está no catálogo: [1]", saida)
        self.assertIn("PC-01 já tem a CVE-2019-0708 (vulnerabilidade 1).",
                      saida)
        dados = self.lido()
        self.assertEqual(dados[1]["vulnerabilidades"][0]["id"], 1)
        self.assertEqual(dados[1]["vulnerabilidades"][0]["situacao"], 2)

    def test_atualizar_sem_internet_mantem_a_base(self):
        """Sem internet, a atualização avisa e nada muda."""
        self.base_cve = base_de_teste()

        def sem_internet(url):
            """Simula a falta de internet."""
            raise urllib.error.URLError(f"sem conexão com {url}")

        self.abrir = sem_internet
        saida = self.rodar(["16", "4", "", "16", "1", "forti", "", "0"])
        self.assertIn("A base não foi atualizada", saida)
        self.assertIn("continua com a base que já tem", saida)
        self.assertIn("CVE-2024-21762", saida)          # a base continua
        self.assertFalse(os.path.exists(os.environ["INVENTARIO_BASE_CVE"]))

    def test_atualizar_grava_a_base_nova_e_passa_a_usar(self):
        """Catálogo novo (simulado): grava, conta o que mudou e usa."""
        self.base_cve = base_de_teste()
        # Uma semana depois do catálogo da base que vem com o programa:
        # a atualizada só vale se for mais nova que ela.
        with open(base_cve.ARQUIVO_INICIAL, encoding="utf-8") as arquivo:
            dia = datetime.date.fromisoformat(
                json.load(arquivo)["publicado"]) + datetime.timedelta(7)
        catalogo = {
            "catalogVersion": dia.strftime("%Y.%m.%d"),
            "dateReleased": f"{dia.isoformat()}T15:00:00.000Z",
            "vulnerabilities": [
                entrada_do_kev("CVE-2019-0708", "Microsoft",
                               "Remote Desktop Services", "BlueKeep",
                               "2021-11-03"),
                entrada_do_kev("CVE-2025-0001", "Exemplo", "Roteador X",
                               "Exemplo Roteador X Command Injection",
                               "2026-10-20")]}
        oficiais = {"CVE-2025-0001": {
            "cveMetadata": {"cveId": "CVE-2025-0001"},
            "containers": {"cna": {
                "metrics": [{"cvssV3_1": {"vectorString": TOTAL_31}}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}]}}}}
        self.abrir = abrir_simulado(catalogo, oficiais)
        saida = self.rodar(["16", "4", "", "16", "1", "CVE-2025-0001", "1",
                            "n", "0"])
        corrido = " ".join(saida.split())
        self.assertIn(f"Base atualizada: catálogo {dia:%Y.%m.%d}, 2 CVEs "
                      f"(1 nova(s), 3 saíram); 1 nota(s) buscada(s).",
                      corrido)
        self.assertRegex(saida, r"\(atualizada em \d{2}/\d{2}/\d{4}\)")
        self.assertIn("10,0 (Crítica)", saida)
        self.assertIn("CWE ........... CWE-78", saida)
        lida, aviso = BaseCVE.carregar()
        self.assertEqual((len(lida), lida.origem, aviso),
                         (2, "atualizada", ""))
        # A nota que a CVE já tinha foi aproveitada, sem baixar de novo.
        self.assertEqual(lida.buscar_cve("CVE-2019-0708").cvss, 9.8)


class TesteDaBaseCVE(unittest.TestCase):
    """A base de CVEs: a que vem com o programa, a nota e o download."""

    def test_base_inicial_confere(self):
        """A base que vem com o programa abre e é coerente."""
        base, aviso = BaseCVE.carregar(
            os.path.join(tempfile.gettempdir(), "nao-existe.json"))
        self.assertEqual((aviso, base.origem), ("", "inicial"))
        self.assertGreater(len(base), 1500)
        self.assertGreaterEqual(base.com_nota(), 0.99 * len(base))
        bluekeep = base.buscar_cve("CVE-2019-0708")
        self.assertEqual((bluekeep.cvss, bluekeep.cwes, bluekeep.fonte_nota),
                         (9.8, ("CWE-416",), "CISA-ADP"))
        # Regravada, a base sai igual, letra por letra: formato fixo.
        with open(base_cve.ARQUIVO_INICIAL, encoding="utf-8") as arquivo:
            self.assertEqual(base.para_texto(), arquivo.read())

    def test_nota_do_registro_oficial(self):
        """A 3.1 vem antes da 4.0, o CNA antes do ADP; E:P sai."""
        v40 = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/"
               "SA:N")

        def oficial(cna, adp=()):
            """Um registro oficial com as métricas do CNA e do ADP."""
            return {"containers": {
                "cna": {"metrics": cna},
                "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                         "metrics": list(adp)}]}}

        def metrica(versao, vetor):
            """Uma métrica no formato dos registros oficiais."""
            return {versao: {"vectorString": vetor}}

        self.assertEqual(nota_do_registro(oficial(
            [metrica("cvssV4_0", v40)], [metrica("cvssV3_1", RDP_31)])),
            (9.8, RDP_31, "CISA-ADP"))
        self.assertEqual(nota_do_registro(oficial(
            [metrica("cvssV3_1", TOTAL_31)], [metrica("cvssV3_1", RDP_31)])),
            (10.0, TOTAL_31, "CNA"))
        # A nota é a base, e não a temporal que alguns registros dão.
        self.assertEqual(nota_do_registro(oficial(
            [metrica("cvssV3_1", RDP_31 + "/E:P/RL:U/RC:C")])),
            (9.8, RDP_31, "CNA"))
        self.assertEqual(nota_do_registro(oficial([metrica("cvssV4_0", v40)])),
                         (9.3, v40, "CNA"))
        self.assertEqual(nota_do_registro(oficial([metrica(
            "cvssV2_0", "AV:N/AC:L/Au:N/C:P/I:P/A:P")])), (None, None, None))

    def test_download_recusado(self):
        """Resposta grande demais, sem HTTPS ou JSON fora da norma."""
        for corpo, final, motivo in (
                (b" " * 101, "https://x/a.json", "passou de"),
                (b"{}", "http://x/a.json", "sem HTTPS"),
                (b'{"a": NaN}', "https://x/a.json", "NaN"),
                (b'{"a": 1, "a": 2}', "https://x/a.json", "duas vezes")):
            with self.subTest(motivo=motivo):
                def abrir(_url, corpo=corpo, final=final):
                    """Responde com o corpo dado, vindo de final."""
                    return RespostaSimulada(corpo, final)

                with self.assertRaisesRegex(AtualizacaoError, motivo):
                    baixar_primeiro(["https://x/a.json"], 100, abrir)

    def test_atualizada_ruim_volta_para_a_inicial(self):
        """Arquivo atualizado estragado: avisa e usa a base inicial."""
        with tempfile.TemporaryDirectory() as pasta:
            ruim = os.path.join(pasta, "base_cve.json")
            with open(ruim, "w", encoding="utf-8") as arquivo:
                arquivo.write('{"fonte": ')
            base, aviso = BaseCVE.carregar(ruim)
        self.assertEqual(base.origem, "inicial")
        self.assertIn("não pôde ser lida", aviso)

    def test_vale_a_base_mais_nova(self):
        """A atualizada vale só se não for mais velha que a inicial."""
        def gravar(caminho, dia):
            """Grava a base dos testes com o catálogo do dia dado."""
            base = base_de_teste()
            BaseCVE(base.registros.values(), catalogo=dia.replace("-", "."),
                    publicado=dia, montado_em=dia).salvar(caminho)

        with tempfile.TemporaryDirectory() as pasta:
            atualizada = os.path.join(pasta, "base_cve.json")
            inicial = os.path.join(pasta, "kev.json")
            gravar(inicial, "2026-10-13")
            for dia, origem in (("2026-10-12", "inicial"),
                                ("2026-10-13", "atualizada"),
                                ("2026-10-20", "atualizada")):
                with self.subTest(dia=dia):
                    gravar(atualizada, dia)
                    base, aviso = BaseCVE.carregar(atualizada, inicial)
                    self.assertEqual((base.origem, aviso), (origem, ""))
            # Sem a inicial, vale a atualizada; sem as duas, é erro.
            os.remove(inicial)
            self.assertEqual(
                BaseCVE.carregar(atualizada, inicial)[0].origem,
                "atualizada")
            os.remove(atualizada)
            with self.assertRaises(base_cve.BaseCVEInvalidaError):
                BaseCVE.carregar(atualizada, inicial)

    def test_busca_sugestoes_e_nome_curto(self):
        """Começo da palavra, ordem pela nota e a ficha técnica."""
        base = base_de_teste()
        self.assertEqual([r.cve for r in base.buscar("forti")],
                         ["CVE-2024-21762"])
        # Empate em relevância: a de nota 10,0 antes da sem nota.
        self.assertEqual([r.cve for r in base.buscar("cisco")],
                         ["CVE-2023-20198", "CVE-2024-20481"])
        self.assertEqual(base.buscar("o de the"), [])
        self.assertEqual(base.fabricantes("cis"), [("Cisco", 2)])
        ficha = FichaTecnica({"fabricante": "Cisco",
                              "modelo": "Catalyst 9300",
                              "sistema": "IOS XE 17.9"})
        self.assertEqual([(r.cve, p) for r, p in base.sugestoes(ficha)],
                         [("CVE-2023-20198", ["cisco", "ios"]),
                          ("CVE-2024-20481", ["cisco"])])
        self.assertEqual(nome_curto(base.buscar_cve("CVE-2019-0708")),
                         "Remote Code Execution")


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
        # Rouché-Capelli: posto 2 em I - A, 3 na ampliada: sem solução.
        self.assertEqual((diagnostico.ordem, diagnostico.posto), (3, 2))
        self.assertIn("não tem solução", diagnostico.motivo)
        self.assertIn("[I - A | b] é 3", diagnostico.motivo)
        with self.assertRaises(SistemaSingularError):
            modelo.resolver()

    def montar(self, fracoes):
        """Três equipamentos, nota 5,0 no primeiro e as frações dadas.

        fracoes: {(i, j): fração que o equipamento i herda do j}, com
        i e j de 1 a 3. As frações vão direto no dicionário, como num
        arquivo editado à mão: o cadastro recusaria somas maiores que 1.
        """
        inventario = Inventario()
        ids = [inventario.cadastrar_equipamento(
            TipoEquipamento.OUTRO, f"SING-0{k}", "A", "B", "C").id
            for k in (1, 2, 3)]
        inventario.registrar_vulnerabilidade(
            ids[0], "x", OrigemVulnerabilidade.OUTRA, 5.0,
            SituacaoTratamento.ABERTA)
        for (i, j), fracao in fracoes.items():
            inventario.buscar_por_id(ids[i - 1]).dependencias[ids[j - 1]] = \
                fracao
        return ModeloRisco(inventario)

    def test_sistema_quase_critico_mas_valido_e_resolvido(self):
        """Condição 4,5e8: a solução confere e é aceita, com aviso."""
        modelo = self.montar({(1, 2): 0.5, (1, 3): 0.5001,
                              (2, 1): 0.9999, (3, 1): 0.9999})
        diagnostico = modelo.diagnosticar()
        self.assertTrue(diagnostico.utilizavel)
        # Acima de 1e8: poucos dígitos confiáveis.
        self.assertIn("poucos dígitos confiáveis", diagnostico.aviso)
        self.assertIn("perde cerca de 8 dos 16", diagnostico.aviso)
        x = modelo.resolver()                    # não levanta erro
        self.assertGreater(min(x), 1e4)          # x grande...
        self.assertLess(modelo.residuo, 1e-6)    # ...e o erro pequeno

    def test_posto_cheio_mal_condicionado_nao_contradiz_o_teorema(self):
        """Posto cheio, condição 6e12 < 1/épsilon: resolve e avisa."""
        modelo = self.montar({(1, 2): 0.9998, (1, 3): 0.0001,
                              (2, 1): 0.9999, (2, 3): 0.0001,
                              (3, 1): 0.5001, (3, 2): 0.9999})
        diagnostico = modelo.diagnosticar()
        self.assertTrue(diagnostico.invertivel and diagnostico.utilizavel)
        self.assertEqual(diagnostico.posto, 3)
        self.assertIn("perde cerca de 12 dos 16", diagnostico.aviso)
        self.assertNotIn("não é invertível", diagnostico.motivo)
        self.assertNotIn("zero dentro da tolerância", diagnostico.motivo)
        modelo.resolver()                        # a solução confere

    def test_quase_singular_e_recusado(self):
        """Linhas de A somando 1: condição acima de 1/épsilon, recusa.

        Cada linha soma 1 (0,15 + 0,85; 0,45 + 0,55; 0,35 + 0,65),
        então I - A é singular em teoria; no computador, o determinante
        sai perto de 1e-16, e não zero, e o número de condição, perto
        de 1e18.
        """
        modelo = self.montar({(1, 2): 0.15, (1, 3): 0.85,
                              (2, 1): 0.45, (2, 3): 0.55,
                              (3, 1): 0.35, (3, 2): 0.65})
        diagnostico = modelo.diagnosticar()
        self.assertFalse(diagnostico.invertivel)
        self.assertEqual(diagnostico.posto, 2)
        self.assertGreater(diagnostico.condicao, 1e16)
        self.assertIn("acima do limite 1/épsilon", diagnostico.motivo)
        self.assertIn("zero dentro da tolerância", diagnostico.motivo)
        self.assertEqual(diagnostico.aviso, "")
        with self.assertRaises(SistemaSingularError):
            modelo.resolver()

    def test_posto_menor_que_n_recusa_abaixo_de_1_sobre_eps(self):
        """Posto menor que n recusa, mesmo abaixo de 1/épsilon.

        Com dezenas de equipamentos, o arredondamento pode deixar o
        número de condição de uma matriz singular logo abaixo de
        1/épsilon.
        O teste simula isso no cenário singular (posto 2 de 3).
        """
        modelo = ModeloRisco(self.carregar("cenario_singular.json"))
        with mock.patch("risco.np.linalg.cond", return_value=4e15):
            diagnostico = modelo.diagnosticar()
        self.assertFalse(diagnostico.invertivel or diagnostico.utilizavel)
        self.assertEqual((diagnostico.ordem, diagnostico.posto), (3, 2))
        self.assertIn("o posto de I - A é menor que 3", diagnostico.motivo)
        self.assertIn("não chega ao limite 1/épsilon", diagnostico.motivo)
        self.assertIn("Rouché-Capelli", diagnostico.motivo)
        self.assertEqual(diagnostico.aviso, "")
        with self.assertRaises(SistemaSingularError):
            modelo.resolver()

    def test_pivo_zero_no_solve_e_recusado(self):
        """Se a eliminação de Gauss achar um pivô zero, recusa."""
        # Soma 1,8 na linha de E1, sem ciclo: posto cheio e condição
        # baixa, mas o solve é forçado a falhar.
        modelo = self.montar({(1, 2): 0.9, (1, 3): 0.9})
        with mock.patch("risco.np.linalg.solve",
                        side_effect=LinAlgError("Singular matrix")):
            diagnostico = modelo.diagnosticar()
        self.assertFalse(diagnostico.invertivel or diagnostico.utilizavel)
        self.assertEqual(diagnostico.posto, 3)
        self.assertIn("pivô zero", diagnostico.motivo)

    def test_solucao_que_nao_confere_e_recusada(self):
        """Se (I - A) x não der b, com tolerância, nada é mostrado."""
        modelo = ModeloRisco(self.carregar("cenario_3_equipamentos.json"))
        with (mock.patch("risco.np.linalg.solve",
                         return_value=[0.0, 0.0, 0.0]),
              self.assertRaisesRegex(SistemaSingularError,
                                     "A solução não confere")):
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

    def test_exemplos_regravados_saem_iguais_letra_por_letra(self):
        """Os campos novos são opcionais: os exemplos não mudam."""
        for nome in ("inventario_exemplo.json", "cenario_3_equipamentos.json",
                     "cenario_singular.json"):
            with self.subTest(arquivo=nome):
                caminho = os.path.join(PASTA, "dados_exemplo", nome)
                with open(caminho, encoding="utf-8") as f:
                    original = f.read().replace("\r\n", "\n")
                with tempfile.TemporaryDirectory() as pasta:
                    arquivo = ArquivoInventario(os.path.join(pasta, "x.json"))
                    arquivo.salvar(ArquivoInventario(caminho).carregar())
                    with open(arquivo.caminho, encoding="utf-8") as f:
                        self.assertEqual(f.read(), original)

    def test_arquivo_com_cve_ou_patrimonio_repetido_e_recusado(self):
        """Duas vulnerabilidades com a mesma CVE ou dois patrimônios."""
        inventario = Inventario()
        for nome in ("PC-01", "PC-02"):
            pc = inventario.cadastrar_equipamento(
                TipoEquipamento.OUTRO, nome, "A", "B", "C")
            inventario.registrar_vulnerabilidade(
                pc.id, f"falha de {nome}", OrigemVulnerabilidade.OUTRA, 5.0,
                SituacaoTratamento.ABERTA)
        bom = inventario.para_dict()
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "base.json")
            for nome, mudar in (
                    ("CVE", lambda d: [e["vulnerabilidades"][0].update(
                        cve="CVE-2024-3094") for e in d]),
                    ("patrimônio", lambda d: [e.update(
                        ficha={"patrimonio": "0001"}) for e in d])):
                with self.subTest(repetido=nome):
                    dados = json.loads(json.dumps(bom))
                    mudar(dados)
                    with open(caminho, "w", encoding="utf-8") as f:
                        json.dump(dados, f)
                    with self.assertRaisesRegex(BaseInvalidaError, "0001|"
                                                "CVE-2024-3094"):
                        ArquivoInventario(caminho).carregar()

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

    def test_vetor_no_arquivo_tem_de_conferir_com_a_nota(self):
        """Com vetor no arquivo, a nota é a dele; senão, é recusado."""
        vetor = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        inventario = Inventario()
        pc = inventario.cadastrar_equipamento(
            TipoEquipamento.SERVIDOR, "SRV-01", "TI", "Sala", "Servidor")
        outro = inventario.cadastrar_equipamento(
            TipoEquipamento.ESTACAO_TRABALHO, "PC-01", "TI", "Sala", "PC")
        v = inventario.registrar_vulnerabilidade(
            pc.id, "RDP exposto", OrigemVulnerabilidade.SERVICO_EXPOSTO,
            9.8, SituacaoTratamento.ABERTA, vetor)
        inventario.registrar_vulnerabilidade_existente(
            outro.id, v.id, SituacaoTratamento.ABERTA)
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "x.json")
            ArquivoInventario(caminho).salvar(inventario)
            with open(caminho, encoding="utf-8") as f:
                dados = json.load(f)
            self.assertEqual(dados[0]["vulnerabilidades"][0]["vetor"], vetor)
            self.assertEqual(
                ArquivoInventario(caminho).carregar().para_dict(), dados)

            # A nota adulterada não confere com o vetor.
            dados[0]["vulnerabilidades"][0]["cvss"] = 5.0
            dados[1]["vulnerabilidades"][0]["cvss"] = 5.0
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump(dados, f)
            with self.assertRaisesRegex(BaseInvalidaError,
                                        "não confere com o vetor"):
                ArquivoInventario(caminho).carregar()

            # "vetor": null nas duas cópias vale como sem vetor.
            for copia in (dados[0], dados[1]):
                copia["vulnerabilidades"][0].update(cvss=9.8, vetor=None)
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump(dados, f)
            carregado = ArquivoInventario(caminho).carregar()
            self.assertIsNone(carregado.buscar_vulnerabilidade(v.id).vetor)
            for copia in (dados[0], dados[1]):
                copia["vulnerabilidades"][0]["vetor"] = vetor

            # O vetor tirado de uma só das cópias: as duas discordam.
            dados[0]["vulnerabilidades"][0]["cvss"] = 9.8
            dados[1]["vulnerabilidades"][0]["cvss"] = 9.8
            del dados[1]["vulnerabilidades"][0]["vetor"]
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump(dados, f)
            with self.assertRaisesRegex(BaseInvalidaError,
                                        "com dados diferentes"):
                ArquivoInventario(caminho).carregar()

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
        """Cada módulo com bloco de teste termina com código 0.

        A saída de cada autoteste vai para um cano (capture_output). No
        Windows, o Python grava o que vai para um cano em cp1252, que
        não tem, por exemplo, as letras gregas. Os autotestes rodam com
        cp1252 em qualquer sistema: um texto que o Windows não consegue
        gravar falha aqui também no Linux, e não só no Windows.
        """
        ambiente = dict(os.environ, PYTHONIOENCODING="cp1252")
        for modulo in ("classificacoes", "formatacao", "validacao",
                       "calculadora_cvss", "vulnerabilidades",
                       "ficha_tecnica", "equipamentos", "inventario",
                       "armazenamento", "risco", "base_cve",
                       "atualizacao_cve"):
            with self.subTest(modulo=modulo):
                resultado = subprocess.run(
                    [sys.executable, os.path.join(PASTA, modulo + ".py")],
                    capture_output=True, encoding="cp1252", env=ambiente,
                    cwd=PASTA, timeout=120)
                self.assertEqual(resultado.returncode, 0,
                                 resultado.stdout[-800:] + resultado.stderr)
                self.assertIn("OK", resultado.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
