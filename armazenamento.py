"""Gravação e leitura do inventário em um arquivo JSON.

Único módulo que acessa o disco: trocar o formato do arquivo mexeria
só aqui. O arquivo é um array (lista) de objetos JSON, um por
equipamento, cada um com as suas vulnerabilidades e dependências. O
conteúdo é montado e conferido por
Inventario.para_dict() e Inventario.de_dict(); este módulo só lê, grava
e traduz erros de leitura em BaseInvalidaError.

Onde fica o arquivo: dados/inventario.json ao lado do código, ou o
caminho da variável de ambiente INVENTARIO_DADOS (é o que o Docker usa,
para o arquivo ficar num volume).
"""

import json
import os
import shutil

import migracao
from inventario import Inventario


class BaseInvalidaError(Exception):
    """A base em disco está ilegível, corrompida ou adulterada."""


def _objeto_sem_nome_repetido(pares):
    """Monta um objeto JSON e recusa nome repetido nele.

    A RFC 8259 (seção 4) pede nomes únicos num objeto; sozinho, o módulo
    json ficaria em silêncio com o último valor de um nome repetido.
    """
    objeto = {}
    for nome, valor in pares:
        if nome in objeto:
            raise ValueError(f"o nome {nome!r} aparece duas vezes no "
                             f"mesmo objeto")
        objeto[nome] = valor
    return objeto


# Caminho absoluto: a base fica ao lado do código, de onde quer que o
# programa seja executado.
PASTA_DO_PROJETO = os.path.dirname(os.path.abspath(__file__))
VARIAVEL_DO_CAMINHO = "INVENTARIO_DADOS"


def caminho_padrao():
    """Devolve onde a base fica: a variável de ambiente, se definida."""
    return (os.environ.get(VARIAVEL_DO_CAMINHO)
            or os.path.join(PASTA_DO_PROJETO, "dados", "inventario.json"))


class ArquivoInventario:
    """O arquivo JSON do inventário: salvar() e carregar()."""

    def __init__(self, caminho=None):
        """Define o caminho (o padrão, se não for dado).

        migracao_feita guarda o que carregar() fez com um arquivo do
        Trabalho 1, para a tela contar ao usuário: None, ou uma tupla
        (caminho da cópia de segurança, avisos).
        """
        self.caminho = caminho or caminho_padrao()
        self.migracao_feita = None

    def salvar(self, inventario):
        """Grava o inventário no arquivo JSON.

        A escrita vai para um arquivo temporário, que depois substitui o
        definitivo: se a gravação for interrompida, a base anterior
        continua inteira.
        """
        pasta = os.path.dirname(self.caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)

        temporario = self.caminho + ".tmp"
        with open(temporario, "w", encoding="utf-8") as f:
            # allow_nan=False: NaN e Infinity não existem em JSON (RFC
            # 8259, seção 6); o json do Python os gravaria por padrão.
            json.dump(inventario.para_dict(), f, indent=2,
                      ensure_ascii=False, allow_nan=False)
            f.write("\n")
            # Garante o conteúdo no disco antes da troca de nome.
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporario, self.caminho)  # troca atômica

    def carregar(self):
        """Lê a base e devolve um Inventario.

        Sem arquivo, devolve um inventário vazio (primeira execução).
        Um arquivo do Trabalho 1 é convertido (migracao.py), depois de
        uma cópia de segurança ao lado dele. Levanta BaseInvalidaError
        se o arquivo existir mas não puder ser lido ou estiver fora do
        formato: carregar pela metade faria a próxima gravação apagar
        os dados bons.
        """
        self.migracao_feita = None
        if not os.path.exists(self.caminho):
            return Inventario()

        # utf-8-sig aceita o arquivo com ou sem BOM (o Bloco de Notas
        # põe um). A RFC 8259 permite ignorar o BOM na leitura; ao
        # gravar, o json do Python não põe BOM.
        try:
            with open(self.caminho, encoding="utf-8-sig") as f:
                dados = json.load(
                    f, object_pairs_hook=_objeto_sem_nome_repetido)
        except OSError as erro:
            raise BaseInvalidaError(
                f"não foi possível abrir o arquivo ({erro})") from erro
        except UnicodeDecodeError as erro:
            # Vem antes do ValueError, do qual é subclasse.
            raise BaseInvalidaError("o arquivo não está em UTF-8 - foi "
                                    "salvo em outra codificação") from erro
        except (ValueError, RecursionError) as erro:
            # JSON malformado ou aninhado demais.
            raise BaseInvalidaError(
                f"não é um JSON válido ({erro})") from erro

        avisos = None
        try:
            if migracao.eh_formato_t1(dados):
                dados, avisos = migracao.converter(dados)
            inventario = Inventario.de_dict(dados)
        except (KeyError, ValueError, TypeError, AttributeError) as erro:
            raise BaseInvalidaError(
                f"conteúdo fora do formato esperado ({erro})") from erro

        if avisos is not None:
            try:
                self.migracao_feita = (self._guardar_copia_t1(), avisos)
            except OSError as erro:
                raise BaseInvalidaError(
                    f"a base é do Trabalho 1 e não foi possível guardar a "
                    f"cópia de segurança antes de converter ({erro})"
                ) from erro
        return inventario

    def _guardar_copia_t1(self):
        """Copia o arquivo do T1 para junto dele e devolve o caminho.

        A cópia só é feita uma vez: se já existe, ela é a original e
        não é sobrescrita.
        """
        copia = self.caminho + ".t1.bak"
        if not os.path.exists(copia):
            shutil.copy2(self.caminho, copia)
        return copia


# Teste rápido: grava, lê de volta e confere que nada se perdeu.
if __name__ == "__main__":
    import tempfile

    from classificacoes import (
        OrigemVulnerabilidade,
        SituacaoTratamento,
        TipoEquipamento,
    )

    # O teste usa uma pasta temporária e nunca toca na base real.
    pasta = tempfile.mkdtemp(prefix="inventario_teste_")
    arquivo = ArquivoInventario(os.path.join(pasta, "dados",
                                             "inventario.json"))
    assert arquivo.carregar().todos() == [], "sem arquivo deveria vir vazio"

    inv = Inventario()
    pc = inv.cadastrar_equipamento(
        TipoEquipamento.ESTACAO_TRABALHO, "PC-CARTORIO-01",
        "Escrivão de plantão", "Cartório", "Estação de atendimento")
    srv = inv.cadastrar_equipamento(
        TipoEquipamento.SERVIDOR, "SRV-ARQUIVO", "Chefe de equipe",
        "Sala técnica", "Servidor de arquivos")
    v = inv.registrar_vulnerabilidade(
        pc.id, "Sistema sem atualização", OrigemVulnerabilidade.
        FALTA_ATUALIZACAO, 7.5, SituacaoTratamento.ABERTA)
    inv.registrar_vulnerabilidade_existente(srv.id, v.id,
                                            SituacaoTratamento.CORRIGIDA)
    inv.registrar_dependencia(pc.id, srv.id, 0.4)

    arquivo.salvar(inv)           # cria a pasta dados/ sozinho
    print(f"Gravado em: {arquivo.caminho}\n")
    with open(arquivo.caminho, encoding="utf-8") as f:
        bruto = json.load(f)
    assert isinstance(bruto, list), "a raiz não é um array"
    assert all(isinstance(e, dict) for e in bruto)
    print(f"O arquivo é um array de {len(bruto)} objeto(s), um por "
          f"equipamento.")
    assert not os.path.exists(arquivo.caminho + ".tmp"), "sobrou .tmp"

    lido = arquivo.carregar()
    assert lido.para_dict() == inv.para_dict(), "o lido difere do gravado"
    assert [type(e) for e in lido.todos()] == [type(e) for e in inv.todos()]
    print("OK - o que saiu e o que voltou são idênticos.")

    # Excluído o último equipamento, o id volta depois de reiniciar: o
    # arquivo é só a lista e não guarda contador (ver README).
    lido.excluir_equipamento(srv.id)
    arquivo.salvar(lido)
    reiniciado = arquivo.carregar()
    assert [e.id for e in reiniciado.todos()] == [pc.id]

    # Bases adulteradas: todas recusadas com mensagem, sem traceback.
    adulteradas = {
        "JSON malformado": b'[{"id": 1,',
        "salva em ANSI": '[{"lotacao": "Cartório"}]'.encode("cp1252"),
        "raiz é objeto": b'{"versao": 2}',
        "equipamento nulo": b"[null]",
        "NaN na fração": (json.dumps(inv.para_dict())
                          .replace("0.4", "NaN")).encode(),
    }
    print()
    for nome, conteudo in adulteradas.items():
        with open(arquivo.caminho, "wb") as f:
            f.write(conteudo)
        try:
            arquivo.carregar()
            raise AssertionError(f"aceitou a base adulterada: {nome}")
        except BaseInvalidaError as erro:
            print(f"Recusada ({nome}): {erro}")

    # Arquivo do Trabalho 1: convertido, com cópia de segurança.
    t1 = {"ativos": {"1": {"hostname": "PC-01", "custodiante": "A",
                           "lotacao": "B", "descricao": "C",
                           "categoria": 1}},
          "falhas": {"1": {"ativo_id": 1, "descricao": "D", "origem": 1,
                           "gravidade": 4, "situacao": 1}},
          "ultimo_id_ativo": 5, "ultimo_id_falha": 1}
    with open(arquivo.caminho, "w", encoding="utf-8") as f:
        json.dump(t1, f)
    convertido = arquivo.carregar()
    copia, avisos = arquivo.migracao_feita
    assert os.path.exists(copia), "faltou a cópia de segurança"
    assert convertido.buscar_por_id(1).hostname == "PC-01"
    assert convertido.vulnerabilidades_do(1)[0][0].cvss == 9.8
    assert convertido.cadastrar_equipamento(
        TipoEquipamento.ROTEADOR, "RT-02", "X", "Y", "Z").id == 2
    print(f"\nBase do Trabalho 1 convertida; cópia em {copia}")

    shutil.rmtree(pasta)
    print("\nOK - base adulterada é recusada com mensagem, sem traceback.")
    print("A base real (dados/inventario.json) não foi tocada.")
