
""" Overwrite Pcode's clz handler """
from angr.engines.pcode.behavior import OpBehaviorLzcount
from claripy.ast.bv import BV, BVS

orig_evaluate_unary = OpBehaviorLzcount.evaluate_unary

def sym_eval_lzcount(self, size_out: int, size_in: int, in1: BV) -> BV:
    extracted_expr,_ = in1.args
    return BVS("CLZ_{"+extracted_expr+"}", size_out * 8)

OpBehaviorLzcount.evaluate_unary = sym_eval_lzcount


""" Object to support recursive memory ref """

# Create sym_mem as plugin so that it can be deep-copied when state forks
import re
from typing import List, Tuple
from copy import deepcopy
from angr import SimStatePlugin
from claripy.operations import infix, prefix

class SymMemPlugin(SimStatePlugin):
    """ Plugin to track symbolic memory references, path constraints (and more!)

    Args:
        symbolic_references: { <symbolic_var:str>: <symbolic_var:addr> }
        constraints:         [<path_constraint:str>]
        history:             { <bb_addr>: [<TODO_info>] }
        memory_regions:      { <symbolic_addr:str>: {"read":  [<instr_addr:int>],
                                                     "write": [<instr_addr:int>]
                                                    }
                             }
                                    
    Functions:
    - get_repr(entry: BV) -> str
        * Get a string representation of a symbolic value.

    - record_memory_read(instr_addr: int, symbolic_addr: BV, symbolic_value: BV) -> str
        * Updates `memory_regions`
        * Record a memory read for address <repr(symbolic_addr)> at <instr_addr> 
        * Map symbolic_references[symbolic_value: str] = <symbolic_addr: str> .
        * Hooked to state.inspect.b("mem_read")
        
    - record_write_read(instr_addr: int, symbolic_addr: BV, symbolic_value: BV) -> str
        * Updates `memory_regions`
        * Record a memory write to address <repr(symbolic_addr)> at <instr_addr> 
        * Hooked to state.inspect.b("mem_write")

    - get_constraint_reprs(constraints: List[BV])-> List[str]:
        * get_repr for list of BV constraints (from `s.solver.constraints`) 

    - record_constraint(constraints: Tuple[BV])-> List[str]:
        * Record a constraint in `path_constraints` if it is not already present.
        * Hooked to state.inspect.b("constraints")
    """
    def __init__(self, 
                 symbolic_references={}, 
                 constraints=[],
                 history={}, 
                 memory_regions={}):
        super().__init__()
        self.symbolic_references = symbolic_references
        self.history = history
        self.path_constraints = constraints
        self.memory_regions = memory_regions

    def record_memory_read(self, instr_addr: int, symbolic_addr: BV, symbolic_value: BV)-> str:
        addr_repr = self.get_repr(symbolic_addr)
        if symbolic_value.depth == 1 and len(symbolic_value.variables) == 1:
            symbolic_name = list(symbolic_value.variables)[0]
            self.symbolic_references[symbolic_name] = addr_repr
        if addr_repr not in self.memory_regions:
            self.memory_regions[addr_repr] = {"read":[instr_addr], "write":[]}
        else:
            self.memory_regions[addr_repr]["read"].append(instr_addr)
        return addr_repr

    def record_memory_write(self, instr_addr: int, symbolic_addr: BV)-> str:
        addr_repr = self.get_repr(symbolic_addr)
        if addr_repr not in self.memory_regions:
            self.memory_regions[addr_repr] = {"read":[], "write":[instr_addr]}
        else:
            self.memory_regions[addr_repr]["write"].append(instr_addr)
        return addr_repr

    def copy(self, memo):
        return SymMemPlugin(deepcopy(self.symbolic_references),
                            deepcopy(self.path_constraints),
                            deepcopy(self.history),
                            deepcopy(self.memory_regions))

    def get_repr(self, entry: BV)-> str:
        if entry.depth > 1: 
            # Expand non-terminals
            if len(entry.args) > 1:
                return f" {infix[entry.op]} ".join(self.get_repr(arg) for arg in entry.args)
            else:
                return f" {prefix[entry.op]} " + self.get_repr(entry.args[0])
        else: 
            # Terminals
            value = entry.args[0]
            if type(value) == str:
                if re.match(r"((data)|(bss)|(reg))_init_", value):
                    return value
                elif "CLZ" in value:
                    match_group = re.match(r"CLZ_{(.+)}.+", value)
                    if not match_group:
                        raise NotImplementedError(f"Cannot parse CLZ symbolic reference {value}")
                    clz_arg = match_group.group(1)
                    if clz_arg in self.symbolic_references:
                        return f"CLZ(mem Ⓓ [{self.symbolic_references[clz_arg]}])"
                    else:
                        raise NotImplementedError(f"Cannot find symbolic reference for {clz_arg}")
                else:
                    return f"mem Ⓓ [{self.symbolic_references[value]}]"
            else:
                return f"0x{value:x}"
        
    def get_constraint_reprs(self, constraints: List[BV])-> List[str]:
        return [self.get_repr(c) for c in constraints]

    def record_constraint(self, constraints: Tuple)-> List[str]:
        ret = []
        for c in constraints:
            # if no variable in c and eval to true, skip
            if len(c.variables) == 0 and c.is_true():
                continue
            repr = self.get_repr(c)
            if repr not in self.path_constraints:
                self.path_constraints.append(repr)
            ret.append(repr)
        return ret
