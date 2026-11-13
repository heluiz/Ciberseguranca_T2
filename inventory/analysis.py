"""Casos de uso de leitura sobre o domínio original.

Nada aqui conhece Django nem PostgreSQL: as funções recebem um repositório
(qualquer objeto com ``load()`` que devolva um ``Inventario``) ou o próprio
inventário. O mesmo código roda com o banco real e com a memória, o que
permite testar a regra sem banco e trocar a persistência sem tocar na regra.
"""

import json
from pathlib import Path

from academic.algorithms import bfs_levels, dfs_cycles, merge_sort
from inventario import Inventario
from risco import ModeloRisco, SistemaSingularError

BASE_DIR = Path(__file__).resolve().parent.parent
# Cenários somente de leitura para demonstrar o modelo: um pequeno, que se
# confere à mão, e um singular, que o sistema deve recusar.
SCENARIOS = {
    "exemplo": (
        "Cenário de 3 equipamentos (conferível à mão)",
        "dados_exemplo/cenario_3_equipamentos.json",
    ),
    "singular": (
        "Cenário singular (I − A sem inversa)",
        "dados_exemplo/cenario_singular.json",
    ),
}
# Acima disso as matrizes não cabem na tela; o resultado continua disponível.
MATRIX_DISPLAY_LIMIT = 8
SORT_KEYS = {
    "efetivo": lambda row: (-row["efetivo"], row["equipamento"].id),
    "proprio": lambda row: (-row["proprio"], row["equipamento"].id),
    "hostname": lambda row: (row["equipamento"].hostname.lower(),),
}


def load_scenario(name):
    """Inventário de um cenário de demonstração; não toca no banco."""
    path = BASE_DIR / SCENARIOS[name][1]
    return Inventario.de_dict(json.loads(path.read_text(encoding="utf-8")))


def propagation_graph(inventory):
    """Lista de adjacência no sentido do risco: origem -> quem herda dela.

    Se A depende de B, o risco de B chega a A; a aresta é B -> A.
    """
    graph = {equipment.id: [] for equipment in inventory}
    for equipment in inventory:
        for source in equipment.dependencias:
            graph[source].append(equipment.id)
    return graph


def reachability(inventory, asset_id):
    """Ativos que herdam risco de asset_id, com o número de saltos (BFS)."""
    levels = bfs_levels(propagation_graph(inventory), asset_id)
    rows = [
        {"equipamento": inventory.buscar_por_id(other), "saltos": hops}
        for other, hops in levels.items()
    ]
    return merge_sort(
        rows, key=lambda r: (r["saltos"], r["equipamento"].hostname.lower())
    )


def dependency_cycles(inventory):
    """Arestas de retorno do grafo de propagação (DFS): cada uma fecha um ciclo."""
    return [
        (inventory.buscar_por_id(a), inventory.buscar_por_id(b))
        for a, b in dfs_cycles(propagation_graph(inventory))
    ]


def risk_analysis(repository, order="efetivo"):
    """Diagnóstico de I − A e risco de todos os equipamentos.

    Verifica a invertibilidade ANTES de resolver. Se o sistema for recusado,
    ``rows`` fica vazio e ``error`` traz a explicação para o usuário.
    """
    inventory = repository.load()
    model = ModeloRisco(inventory)
    diagnostic = model.diagnosticar()
    rows, error, total, residual = [], "", None, None
    try:
        # Merge Sort próprio (estável) ordena o ranking de prioridades.
        rows = merge_sort(
            [
                {
                    "equipamento": r.equipamento,
                    "soma_cvss": r.soma_cvss,
                    "fator": r.fator,
                    "proprio": r.proprio,
                    "herdado": r.efetivo - r.proprio,
                    "efetivo": r.efetivo,
                }
                for r in model.relatorio()
            ],
            key=SORT_KEYS.get(order, SORT_KEYS["efetivo"]),
        )
        total, residual = model.risco_total(), model.residuo
    except SistemaSingularError as exc:
        error = str(exc)
    return {
        "inventory": inventory,
        "model": model,
        "diagnostic": diagnostic,
        "rows": rows,
        "error": error,
        "total": total,
        "residual": residual,
        "cycles": dependency_cycles(inventory),
        "matrices": matrices(model)
        if len(model.equipamentos) <= MATRIX_DISPLAY_LIMIT
        else None,
    }


def matrices(model):
    """M, v, b, A e I − A em listas simples, cada linha com o seu hostname."""
    names = [e.hostname for e in model.equipamentos]
    n = len(names)
    identity_minus_a = [
        [(1.0 if i == j else 0.0) - float(model.A[i][j]) for j in range(n)]
        for i in range(n)
    ]
    return {
        "equipamentos": names,
        "vulnerabilidades": [
            v.cve or f"V{v.id}" for v in model.vulnerabilidades
        ],
        "M": list(
            zip(names, [[int(x) for x in row] for row in model.M.tolist()])
        ),
        "v": model.v.tolist(),
        "A": list(zip(names, model.A.tolist())),
        "I_menos_A": list(zip(names, identity_minus_a)),
    }
