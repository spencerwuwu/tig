import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
from typing import List, Tuple, Dict, Set
from tig.bininfo import Function


def compute_dominator_tree(func: Function) -> Tuple[defaultdict[int, Set[int]], int]:
    """Compute the dominator tree of a control flow graph (CFG)

    Args:
        blocks (Function): Function to compute dominator tree for

    Returns:
        defaultdict[int, Set[int]]: Map from block addr to descendents in dominator tree
    """
    cfg: Dict[int, Set[int]] = {
        block.start_vaddr: set(block.exit_vaddrs) for block in func.blocks
    }
    entry = func.blocks[0].start_vaddr

    nodes = set(cfg.keys())
    dominators = {node: nodes.copy() for node in nodes}
    dominators[entry] = {entry}

    changed = True
    while changed:
        changed = False
        for node in nodes - {entry}:
            preds = {pred for pred in nodes if node in cfg.get(pred, set())}
            new_dom = (
                {node} | set.intersection(*(dominators[p] for p in preds))
                if preds
                else {node}
            )
            if dominators[node] != new_dom:
                dominators[node] = new_dom
                changed = True

    dom_tree: defaultdict[int, Set[int]] = defaultdict(set)
    for node in nodes:
        for dom in dominators[node] - {node}:
            if all(
                dom not in dominators[other] for other in dominators[node] - {node, dom}
            ):
                dom_tree[dom].add(node)

    return dom_tree, entry


def preorder_traversal(
    dom_tree: defaultdict[int, Set[int]], node: int, verbose: bool = False
) -> List[int]:
    """Compute preorder traversal of a dominator tree starting from a given node

    Args:
        dom_tree (defaultdict[int, Set[int]]): Tree to traverse
        node (int): Node to start at
        verbose (bool, optional): Print traversal. Defaults to False.

    Returns:
        List[int]: List containing nodes in preorder with respect to [dom_tree]
    """
    if verbose:
        print(hex(node))

    out = [node]
    for child in sorted(dom_tree[node]):
        out.extend(preorder_traversal(dom_tree, child, verbose=verbose))
    return out


def draw_dominator_tree(dom_tree: defaultdict[int, Set[int]], func: Function):
    """Draw a dominator tree with instruction details as a top-down tree

    Args:
        dom_tree (defaultdict[int, Set[int]]): Tree to draw
        func (Function): Function containing [dom_tree] BasicBlocks
    """
    G: nx.DiGraph = nx.DiGraph()
    labels = {}

    block_map = {block.start_vaddr: block for block in func.blocks}

    for parent, children in dom_tree.items():
        parent_instrs = "\n".join(
            instr.instr_str for instr in block_map[parent].instructions
        )
        parent_label = f"=={hex(parent)}==\n{parent_instrs}"
        labels[parent] = parent_label
        for child in children:
            child_instrs = "\n".join(
                instr.instr_str for instr in block_map[child].instructions
            )
            child_label = f"=={hex(child)}==\n{child_instrs}"
            labels[child] = child_label
            G.add_edge(parent, child)

    pos = nx.nx_agraph.graphviz_layout(
        G, prog="dot"
    )  # Use hierarchical layout for a tree structure

    plt.figure(figsize=(12, 8))
    nx.draw(
        G,
        pos,
        with_labels=True,
        labels=labels,
        node_size=6000,
        node_color="lightblue",
        edge_color="gray",
        font_size=8,
    )
    plt.show()
