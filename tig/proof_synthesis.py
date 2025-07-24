from tig.time_of_riscv_func import time_of_BasicBlock
from tig.bininfo import Instruction, BasicBlock, Function
from typing import Dict, Any, List, Tuple
from jinja2 import Environment, FileSystemLoader



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


def build_timing_tree(function, 
                      traces: List[List[int]], 
                      instruction_args: List[Dict],
                      constraint_nodes: List):
    # Assert that all traces start with function.entry_point
    for t in traces:
        if t[0] != function.entry_point:
            # ERROR
            raise ValueError(f"Traces not sync with Function Data")

    root_node = TimingTreeNode(function.blocks[0])
    for trace_id, trace in enumerate(traces[::-1],start=1):
        trace_id = - trace_id  # Reverse order for traces[::-1]
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
                cur_instr_args = instruction_args[trace_id]
                block_t, condition, true_t, false_t = time_of_BasicBlock(cur_block, 
                                                                         cur_trace, 
                                                                         cur_instr_args,
                                                                         traces)
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
                    verbose: bool=False):
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


def _gen_reg_args(sym_info: Dict[str, Any]) -> Tuple[str, str]:
    params = []
    variables = []
    for reg in sym_info["registers"]:
        for v in sym_info["variables"]:
            if v.startswith(f"reg_init_{reg.lower()}"):
                params.append(f"  ({v} : N)\t(* {reg} *)\n")
                variables.append(v)
    return "".join(params), " ".join(variables)


def gen_function_postcondition(function: Function, 
                              sym_info: Dict[str, Any],
                              sym_traces: List[Dict], 
                              verbose: bool=False) -> str:

    root = build_timing_tree(function, 
                             [t["history"] for t in sym_traces], 
                             [t["instruction_args"] for t in sym_traces], 
                             sym_info["branch_constraints"])
    if verbose:
        print(f"+++ Timing tree for {function.name} +++")
        print("-- Guard tree")

    has_mem_ref = any(len(t["memory_regions"]) > 0 for t in sym_traces)
    if has_mem_ref and len(sym_info["branch_constraints"]) > 0:
        mem_param = "  (mem : addr -> N)\n"
    else:
        mem_param = ""

    formula = dfs_timing_tree(root, [function.entry_point], [t["history"] for t in sym_traces], 1, verbose=verbose)
    time_of  = f"Definition time_of_{function.name} (t : trace)\n"
    time_of += mem_param
    time_of += _gen_reg_args(sym_info)[0]
    time_of += "  : Prop :=\n"
    time_of += f"    cycle_count_of_trace t ="
    time_of += formula
    time_of += "."
    if verbose:
        print("\n\n-- Formula:\n")
        print(time_of)
        print()
    return time_of


def gen_function_memory_regions(function: Function,
                                sym_info: Dict[str, Any],
                                sym_traces: List[Dict],
                                verbose: bool=False) -> str:
    memory_regions = set()
    for t in sym_traces:
        for m in t["memory_regions"]:
            memory_regions.add((m))

    param_regs, var_regs = _gen_reg_args(sym_info)

    text  = "Definition memory_regions\n"
    text += "  (mem : addr -> N)\n" 
    text += param_regs
    text += "    := map (fun x => (4, x)) [\n"
    text += "\t\t" + ";\n\t\t".join(memory_regions)
    text += "\n"
    text += "      ].\n\n"
    text += "Definition noverlaps\n"
    text += "  (mem : addr -> N)\n" 
    text += param_regs
    text += f"    :=  create_noverlaps (memory_regions mem {var_regs})."
    

    return text


def synthesize_noverlaps(function: Function,
                         sym_info: Dict[str, Any],
                         sym_traces: List[Dict], 
                         verbose: bool=False
                         ):
    entry_addr = hex(function.entry_point)
    end_addrs = "| ".join(set(hex(t["history"][-1]) for t in sym_traces))

    postcondition = gen_function_postcondition(function, sym_info, sym_traces, verbose=verbose)

    memory_regions = gen_function_memory_regions(function, sym_info, sym_traces, verbose=verbose)

    # TODO:
    invariants = "(* TODO *)"
    proof = "(* TODO *)"

    # Loading Jinja modules and templates
    jinja_env = Environment(loader=FileSystemLoader("tig/jinja_templates"))
    noverlaps_temp = jinja_env.get_template("noverlaps.template.v")

    return noverlaps_temp.render(
        func_name=function.name,
        entry_addr=entry_addr,
        end_addrs=end_addrs,
        postcondition=postcondition,
        memory_regions=memory_regions,
        invariants=invariants,
        proof=proof,
    )


