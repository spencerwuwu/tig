from tig.time_of_riscv_func import time_of_BasicBlock
from tig.bininfo import Instruction, BasicBlock, Function
from typing import Dict, Any, List


class TimingTreeNode:
    def __init__(self, block, constraint_node=None):
        self.constraint_node = constraint_node      
        self.block = block

        self.child = None
        self.is_branching = False
        self.true_child = None
        self.false_child = None

        self.block_time = None
        self.true_time = None
        self.false_time = None

    def set_time(self, block_time, true_time, false_time) -> None:
        self.block_time = block_time
        self.true_time = true_time
        self.false_time = false_time

    def get_constraint_repr(self) -> str:
        if self.constraint_node is None:
            return ""
        return self.constraint_node.repr


def build_timing_tree(function, traces: List[List[int]], constraint_nodes: List):
    # Assert that all traces start with function.entry_point
    for t in traces:
        if t[0] != function.entry_point:
            # ERROR
            raise ValueError(f"Traces not sync with Function Data")

    root_node = TimingTreeNode(function.blocks[0])
    for trace in traces[::-1]:
        cur_node = root_node
        prev_node = None
        for idx, block_addr in enumerate(trace):
            #if idx == 0:
            #    continue
            # Not initialized, create a new node

            # TODO: here
            if prev_node is not None:
                if prev_node.is_branching:
                    if block_addr == prev_node.constraint_node.true_jmp_target:
                        cur_node = prev_node.true_child
                    elif block_addr == prev_node.constraint_node.false_jmp_target:
                        cur_node = prev_node.false_child
                    else:
                        # ERROR
                        raise ValueError(f"Block address {hex(block_addr)} not found in constraint node {prev_node.constraint_node}")
                else:
                    cur_node = prev_node.child

            if cur_node.block_time is None:
                cur_block = function.get_block(block_addr)
                cur_trace = trace[:idx]
                block_t, condition, true_t, false_t = time_of_BasicBlock(cur_block, cur_trace, traces)
                cur_node.set_time(block_t, true_t, false_t)
                if condition:
                    # Sync with constraint_node
                    # if not presented in constraint_node, failed
                    target_cn = None
                    for cn in constraint_nodes:
                        if trace[:idx+1] == cn.history:
                            target_cn = cn
                            break
                    if target_cn is not None :
                        cur_node.constraint_node = target_cn
                        cur_node.is_branching = True
                        # TODO: init here?
                        if target_cn.true_jmp_target:
                            cur_node.true_child = TimingTreeNode(function.get_block(target_cn.true_jmp_target))
                        if target_cn.false_jmp_target:
                            cur_node.false_child = TimingTreeNode(function.get_block(target_cn.false_jmp_target))
                    else:
                        # ERROR
                        h = ", ".join(f"{hex(addr)}" for addr in trace[:idx+1])
                        raise ValueError(f"Cannot find ConstraintNode for trace {h}")
                else:
                    if idx != len(trace) - 1:
                        cur_node.child = TimingTreeNode(function.get_block(trace[idx+1]))
            prev_node = cur_node

    return root_node


def dfs_timing_tree(node: TimingTreeNode, 
                    cur_trace: List[int]=[], 
                    all_traces: List[List[int]]=[], 
                    depth: int=0,
                    verbose: bool=True):
    if verbose:
        print(f"{node.block.start_vaddr:#x} ", end="")

    indent = "  " * depth 
    addr_indent = len("(* 0x80001234 *) ")
    addr_text = f"(* {node.block.start_vaddr:#x} *)"
    findent = indent + " " * addr_indent

    if not node.block_time:
        if verbose:
            print(f" xxx", end="")
        return f"\n{addr_text} {indent}time_inf"

    formula = f"\n{addr_text} {indent}{node.block_time}"

    if not (node.true_child or node.false_child or node.child):
        if cur_trace in all_traces:
            if verbose:
                print(" <END>", end="")
            return formula
        else:
            if verbose:
                print(" xxx", end="")
            return formula + " + time_inf"

    if node.is_branching:
        formula += f"\n{findent}+ (if {node.get_constraint_repr()}"

        if verbose:
            print(f"\n{indent}- True : ", end="")

        formula += f"\n{findent}  then"
        formula += f"\n{findent}    {node.true_time} + "
        if node.true_child:
            true_time = dfs_timing_tree(node.true_child, cur_trace+[node.true_child.block.start_vaddr], all_traces, depth + 2)
        else:
            true_time = f"\n{findent}  time_inf"
        formula += f"{true_time}"

        if verbose:
            print(f"\n{indent}- False: ", end="")

        formula += f"\n{findent}  else"
        formula += f"\n{findent}    {node.false_time} + "
        if node.false_child:
            false_time = dfs_timing_tree(node.false_child, cur_trace+[node.false_child.block.start_vaddr], all_traces, depth + 2)
        else:
            false_time = f"\n{findent}  time_inf"
        formula += f"{false_time}"
        formula += f"\n{findent}  )"
    else:
        if node.child:
            child_time = dfs_timing_tree(node.child, cur_trace+[node.child.block.start_vaddr], all_traces, depth + 1)
            formula += f" +{child_time}"
    return formula


def gen_function_time_formula(function: Function, sym_traces: List[Dict], verbose: bool=False) -> str:
    root = build_timing_tree(function, [t["history"] for t in sym_traces], sym_traces[0]["branch_constraints"])
    if verbose:
        print(f"+++ Timing tree for {function.name} +++")
        print("-- Guard tree")
    formula = dfs_timing_tree(root, [function.entry_point], [t["history"] for t in sym_traces], 1, verbose=verbose)
    time_of  = f"Definition time_of_{function.name} (t : trace) (gp : N) (mem : addr -> N) : Prop :=\n"
    time_of += f"  cycle_count_of_trace t ="
    time_of += formula
    time_of += "."
    if verbose:
        print("\n\n-- Formula:\n")
        print(time_of)
        print()
    return time_of

