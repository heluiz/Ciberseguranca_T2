# Medições dos algoritmos e do modelo de risco

Python 3.13.18, NumPy 2.5.4. Tempos em segundos, medidos em uma única máquina (menor de três repetições). Servem para comparar ordens de crescimento, não como garantia de desempenho.

Para refazer: `python -m academic.benchmark > docs/web/MEDICOES.md`.

## Busca do último item (100 buscas)

| n | Lista, busca linear O(n) | Lista ordenada, busca binária O(log n) | Hash próprio O(1) | dict O(1) |
|---:|---:|---:|---:|---:|
| 10 | 0.000036 | 0.000027 | 0.000009 | 0.000003 |
| 1000 | 0.003179 | 0.000078 | 0.000011 | 0.000004 |
| 100000 | 0.334784 | 0.000126 | 0.000012 | 0.000004 |

## Ordenação de valores aleatórios

| n | Bubble O(n²) | Selection O(n²) | Insertion O(n²) | Merge O(n log n) | Quick O(n log n) | sorted nativo |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.000004 | 0.000003 | 0.000003 | 0.000005 | 0.000016 | 0.000000 |
| 1000 | 0.034569 | 0.021821 | 0.017082 | 0.001154 | 0.001007 | 0.000067 |
| 5000 | 0.952382 | 0.551503 | 0.454831 | 0.007173 | 0.006213 | 0.000460 |

## Melhor e pior caso com 2000 itens

| Entrada | Bubble | Insertion | Merge | Quick (pivô aleatório) |
|---:|---:|---:|---:|---:|
| Já ordenada | 0.000102 | 0.000155 | 0.001627 | 0.002059 |
| Ordem inversa | 0.169941 | 0.140138 | 0.001683 | 0.002032 |

## Altura da árvore binária de busca

| n | Inserção em ordem (degenera) | Inserção aleatória | Mínimo possível |
|---:|---:|---:|---:|
| 100 | 100 | 13 | 7 |
| 1000 | 1000 | 23 | 10 |

## Recursão com e sem memorização (Fibonacci)

| n | Recursão direta O(2^n) | Com memorização O(n) |
|---:|---:|---:|
| 10 | 0.000005 | 0.000001 |
| 20 | 0.000531 | 0.000002 |
| 25 | 0.006081 | 0.000003 |

## Modelo de risco com inventário gerado (n equipamentos)

| n | Análise completa | Só solve | Só inversa × b | Resíduo com solve | Resíduo com inversa |
|---:|---:|---:|---:|---:|---:|
| 10 | 0.000209 | 0.0000040 | 0.0000053 | 1.27e-14 | 1.36e-14 |
| 100 | 0.001608 | 0.0000458 | 0.0001797 | 7.24e-14 | 5.23e-14 |
| 400 | 0.032341 | 0.0016550 | 0.0078137 | 1.77e-13 | 1.49e-13 |

## Perfil da análise completa (200 equipamentos)

```text
10783 function calls (10385 primitive calls) in 0.009 seconds

   Ordered by: cumulative time
   List reduced from 101 to 10 due to restriction <10>

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.000    0.000    0.009    0.009 benchmark.py:88(full_pipeline)
        2    0.000    0.000    0.006    0.003 risco.py:198(diagnosticar)
        1    0.000    0.000    0.006    0.006 risco.py:210(_verificar)
        1    0.000    0.000    0.003    0.003 _linalg.py:1923(cond)
        1    0.002    0.002    0.003    0.003 _linalg.py:1909(_cond_svdvals)
        1    0.000    0.000    0.002    0.002 _linalg.py:2051(matrix_rank)
        1    0.002    0.002    0.002    0.002 _linalg.py:1666(svd)
    399/1    0.001    0.000    0.002    0.002 algorithms.py:168(merge_sort)
        1    0.001    0.001    0.001    0.001 risco.py:154(__init__)
        1    0.000    0.000    0.001    0.001 risco.py:468(relatorio)
```

## Leitura dos resultados

- A busca linear cresce junto com n; a binária e as tabelas hash quase não mudam. A binária exige a lista ordenada.
- Bubble, Selection e Insertion multiplicam o tempo por cerca de 25 quando n multiplica por 5 (crescimento quadrático). Merge e Quick crescem pouco mais que n.
- Com a lista já ordenada, Bubble e Insertion terminam em uma passada; em ordem inversa caem no pior caso. O Merge Sort não depende da ordem de entrada.
- A árvore sem balanceamento vira uma lista quando as chaves chegam em ordem: a altura fica igual a n.
- Resolver o sistema com solve é mais rápido do que calcular a inversa e multiplicar; os resíduos dos dois ficam na mesma ordem de grandeza, a do erro de arredondamento. Por isso o programa usa solve.
- O custo da análise completa é dominado pelas rotinas de álgebra linear do diagnóstico (posto e número de condição), que são O(n³) em matriz densa.
