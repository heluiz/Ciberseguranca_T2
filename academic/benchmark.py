"""Medições reproduzíveis dos algoritmos e do modelo de risco.

Uso: python -m academic.benchmark > docs/web/MEDICOES.md

Não usa o banco nem dados reais: os inventários são gerados aqui, com
semente fixa, pelas mesmas classes do programa.
"""

import cProfile
import io
import platform
import pstats
import random
import timeit

import numpy as np

from inventario import Inventario
from risco import ModeloRisco

from .algorithms import (
    BST,
    ChainedHash,
    binary_search,
    bubble_sort,
    fibonacci_memo,
    fibonacci_naive,
    insertion_sort,
    linear_search,
    merge_sort,
    quick_sort,
    selection_sort,
)


def best(function, number=1):
    """Menor tempo de três repetições, em segundos."""
    return min(timeit.repeat(function, number=number, repeat=3))


def table(title, header, rows):
    print(f"\n## {title}\n")
    print("| " + " | ".join(header) + " |")
    print("|" + "---:|" * len(header))
    for row in rows:
        print("| " + " | ".join(str(cell) for cell in row) + " |")


def synthetic_inventory(n, seed=42):
    """Inventário de n equipamentos, 2 vulnerabilidades e até 3 dependências cada."""
    rng = random.Random(seed)
    catalog = [
        {
            "id": i,
            "descricao": f"Falha de teste {i}",
            "origem": 1,
            "cvss": round(rng.uniform(1, 10), 1),
            "cve": None,
            "cwe": None,
            "vetor": None,
        }
        for i in range(1, max(4, n // 2) + 1)
    ]
    records = []
    for i in range(1, n + 1):
        others = [j for j in range(1, n + 1) if j != i]
        records.append(
            {
                "id": i,
                "tipo": rng.randrange(1, 8),
                "hostname": f"EQ-{i:05d}",
                "custodiante": "Equipe de testes",
                "lotacao": f"Setor {i % 10}",
                "descricao": "Equipamento gerado para medição",
                "ficha": {},
                "vulnerabilidades": [
                    dict(v, situacao=1) for v in rng.sample(catalog, 2)
                ],
                "dependencias": [
                    {"equipamento_id": j, "fracao": 0.2}
                    for j in rng.sample(others, min(3, len(others)))
                ],
            }
        )
    return Inventario.de_dict(records)


def full_pipeline(inventory):
    """O que a tela de análise faz: montar, diagnosticar, resolver e ordenar."""
    model = ModeloRisco(inventory)
    model.diagnosticar()
    return merge_sort(model.relatorio(), key=lambda row: -row.efetivo)


def main():
    rng = random.Random(42)
    print("# Medições dos algoritmos e do modelo de risco\n")
    print(
        f"Python {platform.python_version()}, NumPy {np.__version__}. "
        "Tempos em segundos, medidos em uma única máquina (menor de três "
        "repetições). Servem para comparar ordens de crescimento, não como "
        "garantia de desempenho.\n\n"
        "Para refazer: `python -m academic.benchmark > docs/web/MEDICOES.md`."
    )

    rows = []
    for n in [10, 1000, 100000]:
        items = list(range(n))
        own, native = ChainedHash(), {}
        for i in items:
            own[i] = native[i] = i
        rows.append(
            [
                n,
                f"{best(lambda: linear_search(items, n - 1), 100):.6f}",
                f"{best(lambda: binary_search(items, n - 1), 100):.6f}",
                f"{best(lambda: own[n - 1], 100):.6f}",
                f"{best(lambda: native[n - 1], 100):.6f}",
            ]
        )
    table(
        "Busca do último item (100 buscas)",
        [
            "n",
            "Lista, busca linear O(n)",
            "Lista ordenada, busca binária O(log n)",
            "Hash próprio O(1)",
            "dict O(1)",
        ],
        rows,
    )

    rows = []
    for n in [10, 1000, 5000]:
        values = [rng.randrange(1000000) for _ in range(n)]
        rows.append(
            [n]
            + [
                f"{best(lambda: f(values)):.6f}"
                for f in (
                    bubble_sort,
                    selection_sort,
                    insertion_sort,
                    merge_sort,
                    quick_sort,
                    sorted,
                )
            ]
        )
    table(
        "Ordenação de valores aleatórios",
        [
            "n",
            "Bubble O(n²)",
            "Selection O(n²)",
            "Insertion O(n²)",
            "Merge O(n log n)",
            "Quick O(n log n)",
            "sorted nativo",
        ],
        rows,
    )

    values = list(range(2000))
    rows = [
        ["Já ordenada"]
        + [
            f"{best(lambda: f(values)):.6f}"
            for f in (bubble_sort, insertion_sort, merge_sort, quick_sort)
        ],
        ["Ordem inversa"]
        + [
            f"{best(lambda: f(values[::-1])):.6f}"
            for f in (bubble_sort, insertion_sort, merge_sort, quick_sort)
        ],
    ]
    table(
        "Melhor e pior caso com 2000 itens",
        ["Entrada", "Bubble", "Insertion", "Merge", "Quick (pivô aleatório)"],
        rows,
    )

    rows = []
    for n in [100, 1000]:
        ordered, shuffled = BST(), BST()
        keys = list(range(n))
        for key in keys:
            ordered.insert(key)
        rng.shuffle(keys)
        for key in keys:
            shuffled.insert(key)
        rows.append(
            [
                n,
                ordered.height(),
                shuffled.height(),
                int(np.ceil(np.log2(n + 1))),
            ]
        )
    table(
        "Altura da árvore binária de busca",
        [
            "n",
            "Inserção em ordem (degenera)",
            "Inserção aleatória",
            "Mínimo possível",
        ],
        rows,
    )

    rows = [
        [
            n,
            f"{best(lambda: fibonacci_naive(n)):.6f}",
            f"{best(lambda: fibonacci_memo(n)):.6f}",
        ]
        for n in [10, 20, 25]
    ]
    table(
        "Recursão com e sem memorização (Fibonacci)",
        ["n", "Recursão direta O(2^n)", "Com memorização O(n)"],
        rows,
    )

    rows = []
    for n in [10, 100, 400]:
        inventory = synthetic_inventory(n)
        model = ModeloRisco(inventory)
        system = np.eye(n) - model.A
        solved = np.linalg.solve(system, model.b)
        inverted = np.linalg.inv(system) @ model.b
        rows.append(
            [
                n,
                f"{best(lambda: full_pipeline(inventory)):.6f}",
                f"{best(lambda: np.linalg.solve(system, model.b), 10) / 10:.7f}",
                f"{best(lambda: np.linalg.inv(system) @ model.b, 10) / 10:.7f}",
                f"{np.linalg.norm(system @ solved - model.b):.2e}",
                f"{np.linalg.norm(system @ inverted - model.b):.2e}",
            ]
        )
    table(
        "Modelo de risco com inventário gerado (n equipamentos)",
        [
            "n",
            "Análise completa",
            "Só solve",
            "Só inversa × b",
            "Resíduo com solve",
            "Resíduo com inversa",
        ],
        rows,
    )

    profile = cProfile.Profile()
    profile.runcall(full_pipeline, synthetic_inventory(200))
    output = io.StringIO()
    pstats.Stats(profile, stream=output).strip_dirs().sort_stats(
        "cumulative"
    ).print_stats(10)
    print("\n## Perfil da análise completa (200 equipamentos)\n")
    print("```text\n" + output.getvalue().strip() + "\n```")

    print(
        "\n## Leitura dos resultados\n\n"
        "- A busca linear cresce junto com n; a binária e as tabelas hash quase não mudam. "
        "A binária exige a lista ordenada.\n"
        "- Bubble, Selection e Insertion multiplicam o tempo por cerca de 25 quando n "
        "multiplica por 5 (crescimento quadrático). Merge e Quick crescem pouco mais que n.\n"
        "- Com a lista já ordenada, Bubble e Insertion terminam em uma passada; em ordem "
        "inversa caem no pior caso. O Merge Sort não depende da ordem de entrada.\n"
        "- A árvore sem balanceamento vira uma lista quando as chaves chegam em ordem: a "
        "altura fica igual a n.\n"
        "- Resolver o sistema com solve é mais rápido do que calcular a inversa e "
        "multiplicar; os resíduos dos dois ficam na mesma ordem de grandeza, a do erro "
        "de arredondamento. Por isso o programa usa solve.\n"
        "- O custo da análise completa é dominado pelas rotinas de álgebra linear do "
        "diagnóstico (posto e número de condição), que são O(n³) em matriz densa."
    )


if __name__ == "__main__":
    main()
