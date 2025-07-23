
""" Overwrite Pcode's clz handler """
from angr.engines.pcode.behavior import OpBehaviorLzcount
from angr.state_plugins import history
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


class ConstraintNode():
    def __init__(self, history: List[int], constraint: BV, repr: str, inv_repr: str):
        self.history = history
        self.bvv = constraint
        self.repr = repr
        self.inv_repr = inv_repr

        self.true_jmp_target = 0
        self.false_jmp_target = 0

    def add_jmp_target(self, target: int, branch: bool):
        if branch:
            self.true_jmp_target = target
        else:
            self.false_jmp_target = target

    def __repr__(self):
        #return "[" + ", ".join(f"{hex(addr)}" for addr in self.history) + "]:\n\t" + self.repr
        guard_str = self.repr
        if len(guard_str) > 150:
            guard_str = guard_str[:150] + "..."
        return f"  0x{self.history[-1]:x} => <0x{self.true_jmp_target:x}|0x{self.false_jmp_target:x}>:\n\t" + guard_str

    def __str__(self):
        #return "[" + ", ".join(f"{hex(addr)}" for addr in self.history) + "]: " + self.repr
        return f"  0x{self.history[-1]:x} => <0x{self.true_jmp_target:x}|0x{self.false_jmp_target:x}>: " + self.repr


class SymMemPlugin(SimStatePlugin):
    """ Plugin to track symbolic memory references, path constraints (and more!)

    Args:
        symbolic_references: { <symbolic_var:str>: <symbolic_var:addr> }
        path_constraints:    [ <path_constraint:str> ] 
        branch_constraints:  [ <branch_constraint:ConstraintNode> ]   # shared between states
        recorded_history:    [ <instr_addr:int> ]   # shared between states
        variables:           [ <symbolic_var:str> }  # shared between states, variables used as parameters
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

    - record_constraint(constraints: Tuple[BV])-> str | None:
        * Record a constraint in `path_constraints` if it is not already present.
        * Hooked to state.inspect.b("constraints")
    """
    def __init__(self, 
                 symbolic_references={}, 
                 path_constraints=[],
                 branch_constraints=[],
                 recorded_history=[],
                 variables=[],
                 history={}, 
                 memory_regions={}):
        super().__init__()
        self.symbolic_references = symbolic_references
        self.history = history
        self.path_constraints = path_constraints
        self.branch_constraints = branch_constraints
        self.variables = variables
        self.recorded_history = recorded_history
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
                            self.branch_constraints,
                            self.recorded_history,
                            self.variables,
                            deepcopy(self.history),
                            deepcopy(self.memory_regions))

    def get_repr(self, entry: BV)-> str:
        if entry.depth > 1: 
            # Expand non-terminals
            if len(entry.args) > 1:
                if str(infix[entry.op]) == "==":
                    op = "=?"
                    negate = False
                elif str(infix[entry.op]) == "!=":
                    op = "=?"
                    negate = True
                else:
                    op = str(infix[entry.op])
                    negate = False
                repr = f" {op} ".join(self.get_repr(arg) for arg in entry.args)
                if negate:
                    repr = f"negb({repr})"
                return repr
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
                        return f"CLZ(mem Ⓓ[{self.symbolic_references[clz_arg]}])"
                    else:
                        raise NotImplementedError(f"Cannot find symbolic reference for {clz_arg}")
                else:
                    return f"mem Ⓓ[{self.symbolic_references[value]}]"
            else:
                return f"0x{value:x}"
        
    def get_constraint_reprs(self, constraints: List[BV])-> List[str]:
        return [self.get_repr(c) for c in constraints]

    def record_path_constraint(self, history:List[int], constraints: Tuple[BV])-> str | None:
        c = constraints[0] if len(constraints) == 1 else None
        if c is None:
            h = ", ".join(f"{hex(addr)}" for addr in history)
            raise ValueError(f"Expected a single constraint, got {len(constraints)}: {constraints} for trace {h}")

        # if no variable in c and eval to true, skip
        if len(c.variables) == 0 and c.is_true():
            return None

        repr = self.get_repr(c)
        if repr not in self.path_constraints:
            self.path_constraints.append(repr)
            return repr
        else:
            return " (x Recorded) " + repr[:5] + "..."


    def record_branch_jump(self, 
                           history:List[int], 
                           guard: BV, 
                           jmp_target: int)-> ConstraintNode | None:
        # if no variable in c and eval to true, skip
        if len(guard.variables) == 0 and guard.is_true():
            return None

        for v in guard.variables:
            if v not in self.variables and \
                v not in self.symbolic_references and \
                not v.startswith("CLZ"):
                if not v.startswith("reg_init"):
                    raise NotImplementedError(f"Symbolic variable {v} not expected in constraints")
                self.variables.append(v)

        repr = self.get_repr(guard)
        if repr not in self.path_constraints:
            self.path_constraints.append(repr)

        if history not in self.recorded_history:
            cn = ConstraintNode(history, guard, repr, self.get_repr(guard.__invert__()))
            cn.add_jmp_target(jmp_target, True)
            self.branch_constraints.append(cn)
            self.recorded_history.append(history)
            return cn
        else:
            target_cn = None
            for cn in self.branch_constraints:
                if history == cn.history:
                    target_cn = cn
                    break
            if target_cn is None :
                # ERROR
                h = ", ".join(f"{hex(addr)}" for addr in history)
                raise ValueError(f"Cannot find ConstraintNode for history {h}")

            if target_cn.inv_repr == repr:
                target_cn.add_jmp_target(jmp_target, False)
            else:
                # ERROR
                h = ", ".join(f"{hex(addr)}" for addr in history)
                raise NotImplementedError(f"ConstraintNode {repr} misbehave at history {h}")
        return target_cn
