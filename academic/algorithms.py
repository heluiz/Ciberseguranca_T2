"""Implementações para comparação didática com as estruturas nativas."""

from collections import deque
import random


class ChainedHash:
    """Hash com encadeamento e redimensionamento; busca média O(1), pior O(n)."""

    def __init__(self, capacity=16):
        self.buckets = [[] for _ in range(max(1, capacity))]
        self.size = 0

    def __setitem__(self, key, value):
        bucket = self.buckets[hash(key) % len(self.buckets)]
        for i, (k, _) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))
        self.size += 1
        if self.size > len(self.buckets) * 0.75:
            old = self.buckets
            self.buckets = [[] for _ in range(len(old) * 2)]
            self.size = 0
            for bucket in old:
                for k, v in bucket:
                    self[k] = v

    def __getitem__(self, key):
        for k, v in self.buckets[hash(key) % len(self.buckets)]:
            if k == key:
                return v
        raise KeyError(key)


class BST:
    """Árvore de busca sem balanceamento. Entrada ordenada pode gerar altura n."""

    def __init__(self):
        self.root = None

    def insert(self, key):
        node = [key, None, None]
        if self.root is None:
            self.root = node
            return
        current = self.root
        while True:
            side = 1 if key < current[0] else 2
            if current[side] is None:
                current[side] = node
                return
            current = current[side]

    def search(self, key):
        """Busca O(altura): desce à esquerda ou à direita até achar ou acabar."""
        current = self.root
        while current:
            if key == current[0]:
                return True
            current = current[1] if key < current[0] else current[2]
        return False

    def level_order(self):
        """Percurso em largura (por nível), com fila."""
        result, queue = [], deque([self.root] if self.root else [])
        while queue:
            node = queue.popleft()
            result.append(node[0])
            queue.extend(child for child in node[1:] if child)
        return result

    def inorder(self):
        result, stack, node = [], [], self.root
        while stack or node:
            while node:
                stack.append(node)
                node = node[1]
            node = stack.pop()
            result.append(node[0])
            node = node[2]
        return result

    def preorder(self):
        result, stack = [], [self.root] if self.root else []
        while stack:
            node = stack.pop()
            result.append(node[0])
            stack.extend(child for child in (node[2], node[1]) if child)
        return result

    def postorder(self):
        result, stack = [], [(self.root, False)] if self.root else []
        while stack:
            node, visited = stack.pop()
            if visited:
                result.append(node[0])
            else:
                stack.append((node, True))
                stack.extend(
                    (child, False) for child in (node[2], node[1]) if child
                )
        return result

    def height(self):
        stack = [(self.root, 1)] if self.root else []
        height = 0
        while stack:
            node, depth = stack.pop()
            height = max(height, depth)
            stack.extend((child, depth + 1) for child in node[1:] if child)
        return height


def bfs(graph, start):
    """Alcançabilidade no sentido das arestas, O(V+E)."""
    seen, queue, order = {start}, deque([start]), []
    while queue:
        node = queue.popleft()
        order.append(node)
        for neighbor in graph.get(node, []):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return order


def bfs_levels(graph, start):
    """Distância em saltos de start a cada nó alcançável, O(V+E).

    Devolve {nó: saltos}, sem o próprio start. A fila garante que cada nó
    é visitado pela primeira vez pelo caminho mais curto.
    """
    levels, queue = {start: 0}, deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, []):
            if neighbor not in levels:
                levels[neighbor] = levels[node] + 1
                queue.append(neighbor)
    del levels[start]
    return levels


def dfs_cycles(graph):
    """DFS iterativa com três cores: encontra arestas de retorno em O(V+E)."""
    colors, back_edges = {}, []
    for start in graph:
        if colors.get(start):
            continue
        colors[start] = 1
        stack = [(start, iter(graph.get(start, [])))]
        while stack:
            node, edges = stack[-1]
            neighbor = next(edges, None)
            if neighbor is None:
                colors[node] = 2
                stack.pop()
            elif colors.get(neighbor) == 1:
                back_edges.append((node, neighbor))
            elif not colors.get(neighbor):
                colors[neighbor] = 1
                stack.append((neighbor, iter(graph.get(neighbor, []))))
    return back_edges


def merge_sort(items, key=lambda x: x):
    """Merge Sort estável: O(n log n) em tempo, O(n) auxiliar."""
    if len(items) < 2:
        return list(items)
    mid = len(items) // 2
    left, right = merge_sort(items[:mid], key), merge_sort(items[mid:], key)
    result, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        if key(left[i]) <= key(right[j]):
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    return result + left[i:] + right[j:]


def quick_sort(items, key=lambda x: x, rng=None):
    """Lomuto com pivô aleatório; média O(n log n), pior O(n²), instável."""
    values = list(items)
    rng = rng or random.Random()
    stack = [(0, len(values) - 1)]
    while stack:
        low, high = stack.pop()
        if low >= high:
            continue
        pivot = rng.randrange(low, high + 1)
        values[pivot], values[high] = values[high], values[pivot]
        i = low
        for j in range(low, high):
            if key(values[j]) <= key(values[high]):
                values[i], values[j] = values[j], values[i]
                i += 1
        values[i], values[high] = values[high], values[i]
        stack.extend([(low, i - 1), (i + 1, high)])
    return values


class LinkedList:
    """Lista simplesmente encadeada: cada nó guarda o valor e o próximo nó.

    Inserir no início é O(1); buscar, remover e inserir no fim são O(n),
    porque é preciso percorrer os nós um a um.
    """

    class _Node:
        __slots__ = ("value", "next")

        def __init__(self, value, next=None):
            self.value, self.next = value, next

    def __init__(self, values=()):
        self.head, self.size = None, 0
        for value in values:
            self.append(value)

    def prepend(self, value):
        self.head = self._Node(value, self.head)
        self.size += 1

    def append(self, value):
        node = self._Node(value)
        if self.head is None:
            self.head = node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = node
        self.size += 1

    def remove(self, value):
        """Remove a primeira ocorrência; devolve True se removeu."""
        previous, current = None, self.head
        while current:
            if current.value == value:
                if previous is None:
                    self.head = current.next
                else:
                    previous.next = current.next
                self.size -= 1
                return True
            previous, current = current, current.next
        return False

    def __contains__(self, value):
        return any(item == value for item in self)

    def __iter__(self):
        current = self.head
        while current:
            yield current.value
            current = current.next

    def __len__(self):
        return self.size


class LinkedQueue:
    """Fila (FIFO) sobre nós encadeados: entra no fim, sai do início, O(1)."""

    def __init__(self):
        self.first = self.last = None
        self.size = 0

    def enqueue(self, value):
        node = [value, None]
        if self.last is None:
            self.first = node
        else:
            self.last[1] = node
        self.last = node
        self.size += 1

    def dequeue(self):
        if self.first is None:
            raise IndexError("fila vazia")
        value, self.first = self.first
        if self.first is None:
            self.last = None
        self.size -= 1
        return value

    def __len__(self):
        return self.size


def bubble_sort(items, key=lambda x: x):
    """Troca vizinhos fora de ordem; O(n²), O(n) se já ordenado. Estável."""
    values = list(items)
    for end in range(len(values) - 1, 0, -1):
        swapped = False
        for i in range(end):
            if key(values[i]) > key(values[i + 1]):
                values[i], values[i + 1] = values[i + 1], values[i]
                swapped = True
        if not swapped:
            break
    return values


def selection_sort(items, key=lambda x: x):
    """Escolhe o menor do trecho restante; sempre O(n²). Instável."""
    values = list(items)
    for start in range(len(values) - 1):
        smallest = start
        for i in range(start + 1, len(values)):
            if key(values[i]) < key(values[smallest]):
                smallest = i
        values[start], values[smallest] = values[smallest], values[start]
    return values


def insertion_sort(items, key=lambda x: x):
    """Insere cada item no trecho já ordenado; O(n²), O(n) se ordenado. Estável."""
    values = list(items)
    for i in range(1, len(values)):
        current, j = values[i], i - 1
        while j >= 0 and key(values[j]) > key(current):
            values[j + 1] = values[j]
            j -= 1
        values[j + 1] = current
    return values


def linear_search(items, target, key=lambda x: x):
    """Índice do primeiro item com a chave procurada, ou -1. O(n)."""
    for index, item in enumerate(items):
        if key(item) == target:
            return index
    return -1


def binary_search(items, target, key=lambda x: x):
    """Índice de um item com a chave procurada em lista ORDENADA, ou -1. O(log n)."""
    low, high = 0, len(items) - 1
    while low <= high:
        middle = (low + high) // 2
        value = key(items[middle])
        if value == target:
            return middle
        if value < target:
            low = middle + 1
        else:
            high = middle - 1
    return -1


def factorial_iterative(n):
    result = 1
    for factor in range(2, n + 1):
        result *= factor
    return result


def factorial_recursive(n):
    return 1 if n < 2 else n * factorial_recursive(n - 1)


def fibonacci_naive(n):
    """Recursão direta: recalcula os mesmos termos, O(2^n)."""
    return n if n < 2 else fibonacci_naive(n - 1) + fibonacci_naive(n - 2)


def fibonacci_memo(n, cache=None):
    """Mesma recursão com memorização: cada termo é calculado uma vez, O(n)."""
    cache = {} if cache is None else cache
    if n < 2:
        return n
    if n not in cache:
        cache[n] = fibonacci_memo(n - 1, cache) + fibonacci_memo(n - 2, cache)
    return cache[n]
