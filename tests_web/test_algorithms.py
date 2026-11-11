import random
import pytest
from academic.algorithms import (
    ChainedHash,
    BST,
    bfs,
    dfs_cycles,
    merge_sort,
    quick_sort,
)


def test_hash_collisions_resize_and_update():
    class Key:
        def __init__(self, n):
            self.n = n

        def __hash__(self):
            return 0

        def __eq__(self, other):
            return self.n == other.n

    table = ChainedHash(1)
    for n in range(100):
        table[Key(n)] = n
    table[Key(30)] = 99
    assert table.size == 100
    assert table[Key(30)] == 99
    with pytest.raises(KeyError):
        _ = table[Key(101)]


def test_bst_degenerate_and_random():
    tree = BST()
    for n in range(100):
        tree.insert(n)
    assert tree.height() == 100
    assert tree.inorder() == list(range(100))
    values = list(range(100))
    random.Random(42).shuffle(values)
    tree = BST()
    for n in values:
        tree.insert(n)
    assert tree.height() < 30
    assert tree.inorder() == sorted(values)


def test_graph_cycle_and_direction():
    graph = {1: [2], 2: [3], 3: [2], 4: []}
    assert bfs(graph, 1) == [1, 2, 3]
    assert bfs(graph, 3) == [3, 2]
    assert dfs_cycles(graph) == [(3, 2)]


@pytest.mark.parametrize(
    "values",
    [
        [],
        [1],
        [3, 1, 2, 1],
        list(range(200)),
        list(range(200, -1, -1)),
        [5] * 100,
    ],
)
def test_sorts(values):
    assert merge_sort(values) == sorted(values)
    assert quick_sort(values, rng=random.Random(42)) == sorted(values)


def test_merge_stability():
    values = [(2, "a"), (1, "b"), (2, "c"), (1, "d")]
    assert merge_sort(values, key=lambda x: x[0]) == [
        (1, "b"),
        (1, "d"),
        (2, "a"),
        (2, "c"),
    ]


def test_tree_traversals():
    tree = BST()
    for n in [4, 2, 6, 1, 3, 5, 7]:
        tree.insert(n)
    assert tree.preorder() == [4, 2, 1, 3, 6, 5, 7]
    assert tree.postorder() == [1, 3, 2, 5, 7, 6, 4]
