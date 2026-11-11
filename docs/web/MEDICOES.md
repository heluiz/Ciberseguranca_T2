# Medições didáticas

Python 3.12.14, NumPy 2.5.4. Tempos locais em segundos; não são SLA.

## Busca por chave

| n | Hash próprio (1000 buscas) | dict (1000 buscas) |
|---:|---:|---:|
| 10 | 0.0001700 | 0.0000409 |
| 1000 | 0.0001554 | 0.0000569 |
| 100000 | 0.0001550 | 0.0000589 |

## Ordenação

| n | Merge Sort | Quick Sort | sorted |
|---:|---:|---:|---:|
| 10 | 0.0000066 | 0.0000159 | 0.0000003 |
| 1000 | 0.0014612 | 0.0013777 | 0.0000426 |
| 10000 | 0.0202022 | 0.0194814 | 0.0009999 |

## Sistema linear

| n | solve de matriz diagonal dominante densa |
|---:|---:|
| 10 | 0.0000076 |
| 100 | 0.0000613 |
| 1000 | 0.0210719 |

## Perfil Merge Sort (1000 itens)

```text
         50114 function calls (48116 primitive calls) in 0.009 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
   1999/1    0.006    0.000    0.009    0.009 /workspace/scratch/108e9e80e36e/sentinel-web/academic/algorithms.py:131(merge_sort)
    21933    0.001    0.000    0.001    0.000 {built-in method builtins.len}
     8727    0.001    0.000    0.001    0.000 {method 'append' of 'list' objects}
    17454    0.001    0.000    0.001    0.000 /workspace/scratch/108e9e80e36e/sentinel-web/academic/algorithms.py:131(<lambda>)
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}


```

Hash depende de colisões; BST sem balanceamento pode degenerar. Merge Sort preserva empates; Quick Sort Lomuto não é estável e com muitos valores iguais pode chegar a O(n²). NumPy usa rotinas compiladas; tempo pequeno não altera a complexidade O(n³) geral da solução densa. O diagnóstico completo de ModeloRisco também faz análises matriciais e custa mais que este solve isolado.
