"""Leituras que o programa de terminal já fazia, preparadas para as telas web.

Nada aqui grava no banco nem conhece requisição: as funções recebem o
inventário do domínio (``Inventario``) ou a base de CVEs (``BaseCVE``) e
devolvem dicionários e listas simples para os templates. As regras são as
do terminal (``arvore.py``, ``explicacao_cve.py``, ``calculadora_cvss.py``,
``risco.py``), e não uma segunda versão delas.
"""

import os
import threading

import arvore
import explicacao_cve
from base_cve import ARQUIVO_INICIAL, BaseCVE, caminho_padrao
from calculadora_cvss import VERSOES, analisar_vetor, montar_vetor
from classificacoes import NivelGravidade

_CACHE_LOCK = threading.Lock()
_CACHE: dict = {}


def cve_base():
    """A base de CVEs (BaseCVE, aviso), relida só quando um arquivo muda.

    A base tem mais de mil registros e um índice de palavras; montá-la a cada
    requisição custaria mais que a própria consulta. A chave do cache é a
    data de modificação dos dois arquivos que ``BaseCVE.carregar`` considera.
    """

    def mtime(path):
        try:
            return os.stat(path).st_mtime_ns
        except OSError:
            return None

    key = (mtime(caminho_padrao()), mtime(ARQUIVO_INICIAL))
    with _CACHE_LOCK:
        if _CACHE.get("key") != key:
            _CACHE["value"] = BaseCVE.carregar()
            _CACHE["key"] = key
        return _CACHE["value"]


# ----------------------------------------------------------------------
# Explicação de uma CVE ou de uma vulnerabilidade, em português
# ----------------------------------------------------------------------


def explanation(vetor=None, ssvc=None, acao=None, links=(), cwes=()):
    """O que o terminal imprime em "Em português" e "O que fazer".

    Devolve um dicionário com as frases do vetor, o SSVC, a ação da CISA
    (traduzida quando está na tabela), os links separados e os CWEs com nome.
    Um vetor que não sirva não derruba a tela: só não gera frases.
    """
    sentences = []
    if vetor:
        try:
            sentences = explicacao_cve.explicar_vetor(vetor)
        except ValueError:
            sentences = []
    action, translated = (None, False)
    if acao:
        action, translated = explicacao_cve.acao_em_portugues(acao)
    bulletins, nvd = explicacao_cve.separar_links(links or ())
    return {
        "sentences": sentences,
        "ssvc": explicacao_cve.ssvc_em_portugues(ssvc) if ssvc else None,
        "ssvc_legend": explicacao_cve.LEGENDA_SSVC if ssvc else None,
        "action": action,
        "action_translated": translated,
        "bulletins": bulletins,
        "nvd": nvd,
        "cwes": [explicacao_cve.cwe_com_nome(c) for c in cwes or ()],
    }


def record_explanation(record):
    """explanation() de um RegistroCVE da base."""
    return explanation(
        record.vetor, record.ssvc, record.acao, record.links, record.cwes
    )


def matching_assets(record, inventory):
    """Ativos cuja ficha técnica combina com a CVE (o inverso das sugestões).

    Usa a mesma regra de ``BaseCVE.sugestoes``, numa base com só este
    registro: o que combina aqui é exatamente o que a ficha do ativo sugere.
    """
    single = BaseCVE([record])
    rows = []
    for equipment in inventory:
        found = single.sugestoes(equipment.ficha)
        if found:
            rows.append(
                {
                    "equipamento": equipment,
                    "palavras": found[0][1],
                    "vinculada": any(
                        inventory.buscar_vulnerabilidade(v).cve == record.cve
                        for v in equipment.vulnerabilidades
                    ),
                }
            )
    rows.sort(key=lambda r: (-len(r["palavras"]), r["equipamento"].id))
    return rows


def suggestions(base, equipment, inventory, limit=15):
    """Opção 16, item 3: as CVEs da base que combinam com a ficha do ativo.

    Cada item traz o registro, as palavras que combinaram, a vulnerabilidade
    do catálogo com a mesma CVE (ou None) e se ela já está no ativo.
    """
    by_cve = {v.cve: v for v in inventory.vulnerabilidades() if v.cve}
    rows = []
    found = base.sugestoes(equipment.ficha)
    for record, words in found[:limit]:
        vuln = by_cve.get(record.cve)
        rows.append(
            {
                "registro": record,
                "palavras": words,
                "vulnerabilidade": vuln,
                "no_ativo": vuln is not None
                and vuln.id in equipment.vulnerabilidades,
            }
        )
    return rows, len(found)


# ----------------------------------------------------------------------
# Árvore de dependências (opção 12)
# ----------------------------------------------------------------------


def tree_rows(inventory, root_id, direction, dependency_ids):
    """A árvore de ``arvore.montar`` achatada em linhas com profundidade.

    dependency_ids é {(origem, destino): pk} das dependências gravadas, para
    a linha oferecer a remoção da ligação com o item de cima, como o terminal.
    Origem é quem depende (herda) e destino, de quem se depende.
    """
    tree = arvore.montar(inventory, root_id, direction)
    root = inventory.buscar_por_id(root_id)
    rows = []

    def edge(child, parent):
        if direction == arvore.QUEM_DEPENDE:
            return dependency_ids.get((child.id, parent.id))
        return dependency_ids.get((parent.id, child.id))

    def walk(items, parent, depth):
        for item in items:
            rows.append(
                {
                    "depth": depth,
                    "indent": depth * 1.5,
                    "equipamentos": item.equipamentos,
                    "fracao": item.fracao,
                    "ciclo": item.ciclo,
                    "outras": item.outras,
                    "fora": item.fora,
                    "pai": parent,
                    "remover": edge(item.equipamentos[0], parent)
                    if len(item.equipamentos) == 1
                    else None,
                }
            )
            walk(item.filhos, item.equipamentos[0], depth + 1)

    walk(tree.itens, root, 0)
    return {"total": tree.total, "rows": rows}


# ----------------------------------------------------------------------
# Risco passo a passo (opção 14)
# ----------------------------------------------------------------------


def risk_steps(row, pairs, contributions):
    """As contas de ``telas.mostrar_detalhe_risco`` em dados para a tela."""
    inherited = sum(part for *_, part in contributions)
    return {
        "vulnerabilidades": [
            {
                "vulnerabilidade": vuln,
                "situacao": status,
                "conta": status.conta_no_risco,
            }
            for vuln, status in pairs
        ],
        "soma": row.soma_cvss,
        "fator": row.fator,
        "proprio": row.proprio,
        "herdado": inherited,
        "efetivo": row.efetivo,
    }


# ----------------------------------------------------------------------
# Detalhe de uma correção do plano (opção 17)
# ----------------------------------------------------------------------


def correction_detail(model, inventory, item, total, record):
    """Por que a correção reduz o risco e como fazer (``telas.mostrar_correcao``)."""
    equipment, vuln = item.equipamento, item.vulnerabilidade
    heirs = model.herdam_de(equipment.id)
    if not heirs:
        reason = "porque nenhum equipamento herda risco dele"
    elif len(heirs) == 1:
        reason = "porque 1 equipamento herda risco dele"
    else:
        reason = (
            f"porque {len(heirs)} equipamentos herdam risco dele, "
            "direta ou indiretamente"
        )
    vetor = vuln.vetor or (record.vetor if record else None)
    if record is not None:
        info = explanation(
            vetor, record.ssvc, record.acao, record.links, record.cwes
        )
        warning = ""
    else:
        info = explanation(vetor, cwes=[vuln.cwe] if vuln.cwe else ())
        warning = (
            f"A {vuln.cve} não está na base de CVEs exploradas: não há ação "
            "nem boletim indicados pela CISA. Procure o boletim do fabricante."
            if vuln.cve
            else "Sem CVE, não há boletim oficial: a correção depende do caso, "
            "como trocar uma senha ou mudar uma configuração."
        )
    return {
        "item": item,
        "situacao": equipment.vulnerabilidades[vuln.id],
        "total": total,
        "percentual": 100 * item.reducao / total if total else 0.0,
        "queda_propria": item.fator * vuln.cvss,
        "motivo": reason,
        "herdeiros": [inventory.buscar_por_id(i) for i in heirs],
        "explicacao": info,
        "aviso": warning,
        "registro": record,
    }


# ----------------------------------------------------------------------
# Calculadora CVSS (pergunta_cvss.py / calculadora_cvss.py)
# ----------------------------------------------------------------------

CALCULATOR_VERSIONS = ("4.0", "3.1")


def calculator(version, answers):
    """As perguntas da versão e, com todas respondidas, o vetor e a nota.

    answers é {código da métrica: código da opção}, vindo da query string;
    valores desconhecidos são ignorados (a pergunta fica sem resposta).
    """
    metrics = VERSOES[version]
    chosen = {}
    questions = []
    for metric in metrics:
        valid = {option.codigo for option in metric.opcoes}
        value = answers.get(metric.codigo)
        if value in valid:
            chosen[metric.codigo] = value
        questions.append({"metrica": metric, "escolha": chosen.get(metric.codigo)})
    result = None
    if len(chosen) == len(metrics):
        vector, score = analisar_vetor(montar_vetor(version, chosen))
        result = vector_result(vector, score)
    return questions, result


def vector_result(vector, score):
    """Vetor arrumado, nota, gravidade e as frases do vetor."""
    return {
        "vetor": vector,
        "nota": score,
        "gravidade": NivelGravidade.do_cvss(score) if score else None,
        "frases": explanation(vector)["sentences"],
    }
