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
