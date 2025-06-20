
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



# NOTE: (legacy?) we can just use AVOID_MULTIVALUED_READS (?)
# """ Overwrite PagedMemoryMixin.load to always(?) use symbolic memroy pointers """
#from angr.storage.memory_mixins.paged_memory.paged_memory_mixin import PagedMemoryMixin
#from angr.storage.memory_mixins.paged_memory.pages.cooperation import SimMemoryObject
#
#orig_load = PagedMemoryMixin.load
#
#def symmem_load(self, addr: int, size: int | None = None, *, endness=None, **kwargs):
#    if endness is None:
#        endness = self.endness
#
#    if not isinstance(size, int):
#        raise TypeError("Need size to be resolved to an int by this point")
#
#    if not isinstance(addr, int):
#        raise TypeError("Need addr to be resolved to an int by this point")
#
#    pageno, pageoff = self._divide_addr(addr)
#
#    if kwargs["condition"] is not None:
#        cond = kwargs["condition"]
#        from claripy.ast.base import Base
#        match_mem = False
#        for child in cond.children_asts():
#            if not isinstance(child.args[0], Base):
#                if isinstance(child.args[0], str):
#                    if child.args[0].startswith("mem_") or\
#                        child.args[0].startswith("reg_"):
#                        match_mem = True
#                        break
#        if match_mem:
#            page_addr = pageno * self.page_size
#            page = self._get_page(pageno, False, **kwargs)
#            global_start_addr = page_addr + addr + size
#            new_ast = self._default_value(
#                global_start_addr,
#                size,  # pylint: disable=assignment-from-no-return
#                key=(self.category, global_start_addr),
#                memory=self,
#                endness=endness,
#                **kwargs,
#            )
#            new_item = SimMemoryObject(new_ast, global_start_addr, endness=endness)
#            page.symbolic_data[global_start_addr - page_addr] = new_item
#            out = self.PAGE_TYPE._compose_objects([[(global_start_addr, new_item)]], size, endness, memory=self, **kwargs)
#            return out
#    return orig_load(self, addr=addr, size=size, **kwargs)
#
#PagedMemoryMixin.load = symmem_load

