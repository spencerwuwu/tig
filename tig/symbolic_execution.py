import pypcode, archinfo, angr, claripy
from typing import List
from tig.bininfo import Function
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


def get_project(bin_path: str, lang: str = "RISCV:LE:32:default") -> angr.Project:
    """Get an angr Project using pypcode

    Args:
        bin_path (str): Path to binary of output Project
        lang (str, optional): SPARC identifier for assembly language.
                              See https://api.angr.io/projects/pypcode/en/latest/languages.html.
                              Defaults to "RISCV:LE:32:default".

    Raises:
        Exception: If SPARC identifier is unsupported by pypcode

    Returns:
        angr.Project: Project object for provided binary
    """
    sparc_lang = None
    for arch in pypcode.Arch.enumerate():
        for l in arch.languages:
            if l.id == lang:
                sparc_lang = l
                break
        if sparc_lang is not None:
            break
    if sparc_lang is None:
        raise Exception(f"Unable to find SPARC language for {lang}")

    pcode_arch = archinfo.ArchPcode(sparc_lang)

    return angr.Project(bin_path, arch=pcode_arch, auto_load_libs=False)


class StashMonitor(angr.exploration_techniques.ExplorationTechnique):
    """Exploration technique that prints stashes before and after each step"""

    def __init__(self, verbose=True):
        super().__init__()
        self.verbose = verbose

    def step(self, simgr, stash="active", **kwargs):
        # Print pre-step information
        if self.verbose:
            print("\nBefore step:")
            self._print_stashes(simgr)

        # Execute the step
        simgr = simgr.step(stash=stash, **kwargs)

        # Print post-step information
        if self.verbose:
            print("\nAfter step:")
            self._print_stashes(simgr)

        return simgr

    def _print_stashes(self, simgr):
        for stash_name, states in simgr.stashes.items():
            if states:
                print(f"{stash_name} ({len(states)}): [", end="")
                for s in states:
                    try:
                        print(f"{hex(s.addr)},", end="")
                    except:
                        print("<symbolic>,", end="")
                print("]")


def make_static_memory_symbolic(
    project: angr.Project, state: angr.SimState, chunk_size: int = 4
):
    """Overwrite .data and .bss sections with symbolic values

    Args:
        project (angr.Project): Project for target binary
        state (angr.SimState): State to write into
        chunk_size (int, optional): Size in bytes of symbolic chunks. Defaults to 4.
    """
    # Get section information
    data_section = project.loader.main_object.sections_map[".data"]
    bss_section = project.loader.main_object.sections_map[".bss"]

    # Process .data section
    for addr in range(data_section.min_addr, data_section.max_addr, chunk_size):
        sym_name = f"data_{hex(addr)}"
        symbolic_value = state.solver.BVS(sym_name, chunk_size * 8)
        state.memory.store(addr, symbolic_value)

    # Process .bss section
    for addr in range(bss_section.min_addr, bss_section.max_addr, chunk_size):
        sym_name = f"bss_{hex(addr)}"
        symbolic_value = state.solver.BVS(sym_name, chunk_size * 8)
        state.memory.store(addr, symbolic_value)

    return state


def make_registers_symbolic(
    project: angr.Project, state: angr.SimState, chunk_size: int = 4
):
    # TODO: ugly
    lang = "RISCV:LE:32:default"
    sparc_lang = None
    for arch in pypcode.Arch.enumerate():
        for l in arch.languages:
            if l.id == lang:
                sparc_lang = l
                break
        if sparc_lang is not None:
            break
    if sparc_lang is None:
        raise Exception(f"Unable to find SPARC language for {lang}")
    arch = archinfo.ArchPcode(sparc_lang)

    import re

    # make registers symbolic: sp, ra, gp; a0...a?, s0...s?
    for reg_name in arch.registers:
        if not (re.match(r"(a|s)\d+", reg_name) or reg_name in ["sp", "ra", "gp"]):
            continue
        offset, size_bytes = arch.registers[reg_name]
        size_bits = size_bytes * 8

        sym_val = claripy.BVS(f"reg_{reg_name}", size_bits)

        # Write symbolic value to register
        state.registers.store(reg_name, sym_val)
    return state


def is_clz(expr):
    """Determines if a given claripy AST expression implements a Count Leading Zeros (CLZ) operation.

    Returns:
        The operand if it is a CLZ operation, otherwise None.
    """
    if expr.op != "If":
        return None

    expected_value = 0  # Expected return value for leading zeros
    bit_extracted_expr = None  # Placeholder for the extracted bitvector

    while expr.op == "If":
        cond, true_branch, false_branch = expr.args

        # Condition should check a specific bit equality to 1
        if cond.op != "__eq__" or len(cond.args) != 2:
            return None

        bit_check, one_value = cond.args
        if one_value is not claripy.BVV(1, 1):
            return None

        # The bit check should be an extract operation
        if bit_check.op != "Extract" or len(bit_check.args) != 3:
            return None

        high, low, extracted_expr = bit_check.args
        if high != low:  # Ensures it's a single-bit extract
            return None

        # Ensure we are decrementing from the highest bit downwards
        expected_bit = 32 - 1 - expected_value
        if high != expected_bit:
            return None

        # Check the true branch returns the expected count of leading zeros
        if (
            not isinstance(true_branch, claripy.ast.BV)
            or true_branch.concrete_value is None
        ):
            return None

        if true_branch.concrete_value != expected_value:
            return None

        # Move to the next condition in the nested If-Else structure
        expr = false_branch
        expected_value += 1

        # Store the bitvector if we haven't already
        if bit_extracted_expr is None:
            bit_extracted_expr = extracted_expr
        elif bit_extracted_expr is not extracted_expr:
            return None  # Ensure the same bitvector is used throughout

    # Final check: The last branch should return bit_width (full zero case)
    if not isinstance(expr, claripy.ast.BV) or expr.concrete_value is None:
        return None

    if expr.concrete_value == 32:
        return bit_extracted_expr  # Return the operand of CLZ
    else:
        return None


def replace_clz(expr):
    new_vars = []
    args = list(expr.args)  # Copy to avoid modifying the tuple directly

    for i, arg in enumerate(expr.args):
        if isinstance(arg, claripy.ast.Base):  # Check if it's another AST node
            clz_target = is_clz(arg)
            if clz_target is not None:
                new_bvs = claripy.BVS(f"CLZ_{clz_target}", 11)
                args[i] = new_bvs  # Replace CLZ expression
                new_vars.append(new_bvs)  # Store new variable
            else:
                sub_vars = replace_clz(arg)
                new_vars.extend(sub_vars)

    if new_vars:  # If modifications were made, create a new expression
        expr.args = args
        return expr, new_vars
    return expr, []


class TIGSimplify(angr.exploration_techniques.ExplorationTechnique):
    """Exploration technique that simplifies constraints as steps occur"""

    def __init__(self, verbose=True):
        super().__init__()
        self.verbose = verbose

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        for i in range(len(getattr(simgr, stash))):
            s = getattr(simgr, stash)[i]
            new_constraints = []

            for c in s.solver._solver.constraints:
                new_c, new_vars = replace_clz(c)  # Replace CLZ patterns

                # Add new symbolic variables to solver
                for var in new_vars:
                    s.solver.add(
                        var == var
                    )  # This ensures the solver tracks the variable

                new_constraints.append(new_c)

            # Replace old constraints
            s.solver._solver.constraints = new_constraints

            getattr(simgr, stash)[i] = s  # Update the state in the stash

        return simgr


def exec_func(p: angr.Project, func: Function) -> List[claripy.ast.bool.Bool]:
    """Symbolically executes a function and computes input constraints

    Args:
        p (angr.Project): Project for target binary
        func (Function): Function to run

    Returns:
        List[claripy.ast.bool.Bool]: Constraints corresponding to control-flow paths through the function
    """
    # Reference: https://docs.angr.io/en/latest/appendix/options.html
    #  - angr.options.CONSERVATIVE_READ_STRATEGY sounds good but oddly useless
    state: angr.SimState = p.factory.blank_state(
        addr=func.entry_point,
        mode="symbolic",
        add_options={
            # angr.options.LAZY_SOLVES, # TODO: Maybe helpful?
            angr.options.CACHELESS_SOLVER,
            angr.options.CALLLESS,
            # angr.options.AVOID_MULTIVALUED_READS,
            # angr.options.SYMBOLIC_WRITE_ADDRESSES,
            # angr.options.CONSERVATIVE_READ_STRATEGY
        },
    )

    # state.memory.write_strategies = [SymbolicOnlyConcretization()]
    # state.memory.read_strategies = [SymbolicOnlyConcretization()]
    # state.registers.write_strategies = [NoConcretizeSPGP()]
    # state.registers.read_strategies = [NoConcretizeSPGP()]

    state = make_static_memory_symbolic(p, state, chunk_size=4)

    state = make_registers_symbolic(p, state, chunk_size=4)

    def print_mem_write(state):
        print(
            "Write", state.inspect.mem_write_expr, "to", state.inspect.mem_write_address
        )

    def print_reg_write(state):
        reg_offset = state.inspect.reg_write_offset  # Get the register offset
        reg_name = state.arch.register_names.get(reg_offset, f"Unknown({reg_offset})")
        print("Write", state.inspect.reg_write_expr, "to", reg_name)

    def print_mem_read(state):
        print("Read", state.inspect.mem_read_expr, "to", state.inspect.mem_read_address)

    def print_reg_read(state):
        reg_offset = state.inspect.reg_write_offset  # Get the register offset
        reg_name = state.arch.register_names.get(reg_offset, f"Unknown({reg_offset})")
        print("Write", state.inspect.reg_write_expr, "to", reg_name)

    def print_addr(state):
        print(hex(state.inspect.instruction))

    # state.inspect.b("instruction", when=angr.BP_BEFORE, action=print_addr)
    # state.inspect.b("mem_write", when=angr.BP_AFTER, action=print_mem_write)
    # state.inspect.b("reg_write", when=angr.BP_AFTER, action=print_reg_write)
    # state.inspect.b("mem_read", when=angr.BP_AFTER, action=print_mem_read)
    # state.inspect.b("reg_read", when=angr.BP_AFTER, action=print_reg_read)
    state.memory.unconstrained_use_addr = True

    sm = p.factory.simgr(state)

    regions = [(func.entry_point, ret) for ret in func.return_addrs]
    in_regions = lambda addr: any([e <= addr <= r for e, r in regions])
    cfg = p.analyses.CFGFast()
    f = cfg.kb.functions.function(name=func.name)
    if f is None:
        print("Can't find function", func.name)
        return set()
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))
    sm.use_technique(StashMonitor())
    sm.use_technique(TIGSimplify())

    sm.explore(
        find=func.return_addrs,
        # avoid=(lambda s: not (in_regions(s.addr))), # change this eventually, we do want function calls but we want to step over them if possible
        num_find=100,
    )
    # sm.step()

    def dedup_constraints(constraint_list):
        out = []
        seen = set()
        for c in constraint_list:
            if str(c) not in seen:
                seen.add(repr(c))
                out.append(c)
        return out

    for s in sm.active + sm.found:
        s.solver.simplify()

    return dedup_constraints([s.solver.constraints for s in sm.found])
