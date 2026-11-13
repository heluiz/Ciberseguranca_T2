import random
import pytest
from academic.algorithms import (
    ChainedHash,
    BST,
    LinkedList,
    LinkedQueue,
    bfs,
    bfs_levels,
    binary_search,
    bubble_sort,
    dfs_cycles,
    factorial_iterative,
    factorial_recursive,
    fibonacci_memo,
    fibonacci_naive,
    insertion_sort,
    linear_search,
    merge_sort,
    quick_sort,
    selection_sort,
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


def test_bst_search_and_level_order():
    tree = BST()
    assert tree.search(1) is False and tree.level_order() == []
    for n in [50, 30, 70, 20, 40, 60, 80]:
        tree.insert(n)
    assert all(tree.search(n) for n in [50, 20, 80, 40])
    assert not tree.search(55)
    assert tree.level_order() == [50, 30, 70, 20, 40, 60, 80]


def test_bfs_levels_shortest_hops_with_cycle():
    graph = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": ["a"], "e": []}
    assert bfs_levels(graph, "a") == {"b": 1, "c": 1, "d": 2}
    assert bfs_levels(graph, "e") == {}


def test_linked_list_operations():
    items = LinkedList([2, 3])
    items.prepend(1)
    items.append(4)
    assert list(items) == [1, 2, 3, 4] and len(items) == 4
    assert 3 in items and 9 not in items
    assert items.remove(1) and items.remove(3) and not items.remove(9)
    assert list(items) == [2, 4] and len(items) == 2
    assert items.remove(4) and items.remove(2) and list(items) == []
    items.append(7)
    assert list(items) == [7]


def test_linked_queue_is_fifo():
    queue = LinkedQueue()
    with pytest.raises(IndexError):
        queue.dequeue()
    for n in range(5):
        queue.enqueue(n)
    assert len(queue) == 5
    assert [queue.dequeue() for _ in range(5)] == [0, 1, 2, 3, 4]
    assert len(queue) == 0
    queue.enqueue("x")
    assert queue.dequeue() == "x"


@pytest.mark.parametrize("sort", [bubble_sort, selection_sort, insertion_sort])
@pytest.mark.parametrize(
    "values", [[], [1], [3, 1, 2], [5, 4, 3, 2, 1], [1, 2, 3], [2, 2, 1, 1]]
)
def test_basic_sorts(sort, values):
    original = list(values)
    assert sort(values) == sorted(values)
    assert values == original  # não altera a lista recebida
    assert sort(values, key=lambda x: -x) == sorted(values, reverse=True)


def test_basic_sorts_random_and_stability():
    rng = random.Random(7)
    values = [rng.randrange(50) for _ in range(200)]
    for sort in (bubble_sort, selection_sort, insertion_sort):
        assert sort(values) == sorted(values)
    pairs = [(1, "a"), (0, "b"), (1, "c"), (0, "d")]
    for stable in (bubble_sort, insertion_sort):
        assert stable(pairs, key=lambda p: p[0]) == [
            (0, "b"),
            (0, "d"),
            (1, "a"),
            (1, "c"),
        ]


def test_linear_and_binary_search_agree():
    values = list(range(0, 100, 3))
    for target in (0, 3, 51, 99, 100, -1, 50):
        expected = values.index(target) if target in values else -1
        assert linear_search(values, target) == expected
        assert binary_search(values, target) == expected
    assert binary_search([], 1) == -1
    records = [{"id": n} for n in (1, 4, 9)]
    assert binary_search(records, 9, key=lambda r: r["id"]) == 2
    assert linear_search(records, 4, key=lambda r: r["id"]) == 1


def test_recursion_and_memoization():
    for n in range(10):
        assert factorial_iterative(n) == factorial_recursive(n)
    assert factorial_recursive(10) == 3628800
    assert [fibonacci_naive(n) for n in range(10)] == [
        fibonacci_memo(n) for n in range(10)
    ]
    assert fibonacci_memo(90) == 2880067194370816120
