"""Medições reproduzíveis: python -m academic.benchmark (sem dados pessoais)."""

import cProfile
import io
import platform
import pstats
import random
import timeit
import numpy as np
from .algorithms import ChainedHash, merge_sort, quick_sort


def main():
    print("# Medições didáticas\n")
    print(
        f"Python {platform.python_version()}, NumPy {np.__version__}. Tempos locais em segundos; não são SLA.\n"
    )
    print(
        "## Busca por chave\n\n| n | Hash próprio (1000 buscas) | dict (1000 buscas) |\n|---:|---:|---:|"
    )
    for n in [10, 1000, 100000]:
        table, native = ChainedHash(), {}
        for i in range(n):
            table[i] = native[i] = i
        own = min(timeit.repeat(lambda: table[n - 1], number=1000, repeat=3))
        builtin = min(
            timeit.repeat(lambda: native[n - 1], number=1000, repeat=3)
        )
        print(f"| {n} | {own:.7f} | {builtin:.7f} |")
    print(
        "\n## Ordenação\n\n| n | Merge Sort | Quick Sort | sorted |\n|---:|---:|---:|---:|"
    )
    rng = random.Random(42)
    for n in [10, 1000, 10000]:
        values = [rng.randrange(1000000) for _ in range(n)]
        results = [
            min(timeit.repeat(lambda: function(values), number=1, repeat=3))
            for function in (merge_sort, quick_sort, sorted)
        ]
        print(f"| {n} | " + " | ".join(f"{t:.7f}" for t in results) + " |")
    print(
        "\n## Sistema linear\n\n| n | solve de matriz diagonal dominante densa |\n|---:|---:|"
    )
    for n in [10, 100, 1000]:
        matrix = np.eye(n) * 2
        vector = np.ones(n)
        elapsed = min(
            timeit.repeat(
                lambda: np.linalg.solve(matrix, vector), number=1, repeat=3
            )
        )
        print(f"| {n} | {elapsed:.7f} |")
    profile = cProfile.Profile()
    profile.runcall(merge_sort, [rng.randrange(10000) for _ in range(1000)])
    output = io.StringIO()
    pstats.Stats(profile, stream=output).sort_stats("cumulative").print_stats(
        8
    )
    print(
        "\n## Perfil Merge Sort (1000 itens)\n\n```text\n"
        + output.getvalue()
        + "```"
    )
    print(
        "\nHash depende de colisões; BST sem balanceamento pode degenerar. Merge Sort preserva empates; Quick Sort Lomuto não é estável e com muitos valores iguais pode chegar a O(n²). NumPy usa rotinas compiladas; tempo pequeno não altera a complexidade O(n³) geral da solução densa. O diagnóstico completo de ModeloRisco também faz análises matriciais e custa mais que este solve isolado."
    )


if __name__ == "__main__":
    main()
