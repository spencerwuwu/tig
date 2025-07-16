import pypcode, archinfo, angr, claripy
from typing import List, Dict
from tig.bininfo import Function
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("ailment").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

# NOTE: Customize CLZ, SimStatePlugin (and legacy memory overwrite)
import tig.memory_mixins

def get_project(bin_path: str, 
                base_addr: int,
                lang: str = "RISCV:LE:32:default") -> angr.Project:
    """vGet an angr Project using pypcode

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

    return angr.Project(bin_path, 
                        arch=pcode_arch, 
                        load_options={'auto_load_libs': False, 
                                      'main_opts': {'base_addr': base_addr}
                                      }
                        )


class StashMonitor(angr.exploration_techniques.ExplorationTechnique):
    """ Exploration technique that prints stashes before and after each step 

    Usage:
        sm = p.factory.simgr(state)
        sm.use_technique(StashMonitor(verbose=verbose))
    """

    def __init__(self, verbose=True):
        super().__init__()
        self.verbose = verbose

    def step(self, simgr, stash="active", **kwargs):
        # Print pre-step information
        #if self.verbose:
        #    print("\nBefore step:")
        #    self._print_stashes(simgr)

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
    """ Overwrite .data and .bss sections with symbolic values

    Args:
        project (angr.Project): Project for target binary
        state (angr.SimState): State to write into
        chunk_size (int, optional): Size in bytes of symbolic chunks. Defaults to 4.
    Note: the naming convention is used in .tig.memory_mixins
    """
    # Get section information
    data_section = project.loader.main_object.sections_map[".data"]
    bss_section = project.loader.main_object.sections_map[".bss"]

    # Process .data section
    for addr in range(data_section.min_addr, data_section.max_addr, chunk_size):
        sym_name = f"data_init_{hex(addr)}"
        symbolic_value = state.solver.BVS(sym_name, chunk_size * 8)
        state.memory.store(addr, symbolic_value)

    # Process .bss section
    for addr in range(bss_section.min_addr, bss_section.max_addr, chunk_size):
        sym_name = f"bss_init_{hex(addr)}"
        symbolic_value = state.solver.BVS(sym_name, chunk_size * 8)
        state.memory.store(addr, symbolic_value)


def make_registers_symbolic(
    project: angr.Project, state: angr.SimState, reg_size: int = 8
):
    """ Overwrite .data and .bss sections with symbolic values

    Args:
        project (angr.Project): Project for target binary
        state (angr.SimState): State to write into
        reg_size (int, optional): Size in bytes of symbolic registers. Defaults to 8
    Note: the naming convention is used in .tig.memory_mixins
    """
    import re
    arch = project.arch
    # make registers symbolic: sp, ra, gp; a0...a?, s0...s?
    for reg_name in arch.registers:
        if not (re.match(r"(a|s)\d+", reg_name) or reg_name in ["sp", "ra", "gp"]):
            continue
        _, size_bytes = arch.registers[reg_name]
        size_bits = size_bytes * reg_size

        sym_val = claripy.BVS(f"reg_init_{reg_name}", size_bits)
        # Write symbolic value to register
        state.registers.store(reg_name, sym_val)


class NonTermAvoid(angr.exploration_techniques.ExplorationTechnique):
    """ Directly remove a state if calling non-terminated functions 

    Usage:
        sm = p.factory.simgr(state)
        sm.use_technique(NonTermAvoid(non_term_funcs, verbose=verbose))
    """

    def __init__(self, non_term_funcs=[], verbose=True):
        super().__init__()
        self.verbose = verbose
        self.non_term_funcs = non_term_funcs


    def step(self, simgr, stash="active", **kwargs):
        # Execute the step
        simgr = simgr.step(stash=stash, **kwargs)

        for state in simgr.stashes.get(stash, []):
            self._attach_hook(state)

        simgr.move(
            from_stash=stash,
            to_stash='avoid',
            filter_func=lambda s: s.globals.get('move_to_avoid', False)
        )

        return simgr
    
    def _attach_hook(self, state):
        if state.globals.get('hook_attached'):
            return
        state.globals['hook_attached'] = True

        def check_calling_non_term(state):
            addr = state.solver.eval(state.inspect.function_address)
            if addr in self.non_term_funcs:
                if self.verbose:
                    print(" ++ killing", hex(addr))
                state.globals['move_to_avoid'] = True

        state.inspect.b("call", when=angr.BP_BEFORE, action=check_calling_non_term)


def hook_symmem(state: angr.SimState, verbose: bool = False) -> None:
    """ Hook tig.memory_mixins.SymMemPlugin operations """
    state.register_plugin('sym_mem', tig.memory_mixins.SymMemPlugin())

    # Mapping 
    def symmem_add(state):
        if verbose:
            print(" + NEW", state.inspect.symbolic_name)
        state.get_plugin("sym_mem").symbolic_references[state.inspect.symbolic_name] = None

    def symmem_mem_read(state):
        repr = state.get_plugin("sym_mem").record_memory_read(state.inspect.instruction, state.inspect.mem_read_address, state.inspect.mem_read_expr)
        if verbose:
            print(" MEM Read ", state.inspect.mem_read_expr, "from:", repr)
            print(f"               ({state.inspect.mem_read_address})")

    def symmem_mem_write(state):
        repr = state.get_plugin("sym_mem").record_memory_write(state.inspect.instruction, state.inspect.mem_write_address)
        if verbose:
            print(" MEM Write", state.inspect.mem_write_expr, "to:", repr)
            print(f"               ({state.inspect.mem_write_address})")

    def skip_memory_constraints(state):
        state.inspect.address_concretization_add_constraints = False
        # NOTE: Don't check memory constraints for symbolic addresses
        #if verbose:
        #    c = str(state.inspect.address_concretization_expr)
        #    if len(c) > 20:
        #        c = c[:20] + "..."
        #    print("   Skip adding:", c)

    def symmem_path_constraint(state):
        repr = state.get_plugin("sym_mem").record_path_constraint(list(state.history.bbl_addrs), state.inspect.added_constraints)
        if repr is not None and verbose:
            if not repr.startswith(" (x Recorded)"):
                print(" Path constraint:", repr)
                print(f"                  ({state.inspect.added_constraints})")

    def symmem_reg_write(state):
        reg_offset = state.inspect.reg_write_offset  # Get the register offset
        reg_name = state.arch.register_names.get(reg_offset, f"Unknown({reg_offset})")
        if verbose:
            print(" REG Write", state.inspect.reg_write_expr, "to", reg_name)

    def symmem_reg_read(state):
        reg_offset = state.inspect.reg_read_offset  # Get the register offset
        reg_name = state.arch.register_names.get(reg_offset, f"Unknown({reg_offset})")
        if verbose:
            print(" REG Read ", state.inspect.reg_read_expr, "from ", reg_name)

    def symmem_exit(state):
        #if state.inspect.exit_jumpkind == "Ijk_Boring":
        jmp_target = state.inspect.exit_target
        guard = state.inspect.exit_guard
        cn = state.get_plugin("sym_mem").record_branch_jump(list(state.history.bbl_addrs), guard, jmp_target)
        if verbose:
            print("*", hex(state.inspect.instruction), "->", hex(jmp_target), f"({state.inspect.exit_jumpkind})")
            print(" Guard", cn)
            #guard_str = guard.__repr__()
            #if len(guard_str) > 150:
            #    guard = guard[:150] + "..."
            #print("\t", state.inspect.exit_jumpkind, guard)

    def record_addr(state):
        if verbose:
            print("\n->", hex(state.inspect.instruction))
        # TODO: May be useful for fine-grained records
        state.get_plugin("sym_mem").history[state.inspect.instruction] = []

    state.inspect.b("instruction", when=angr.BP_BEFORE, action=record_addr)
    state.inspect.b("symbolic_variable", when=angr.BP_AFTER, action=symmem_add)
    state.inspect.b("mem_read", when=angr.BP_AFTER, action=symmem_mem_read)
    state.inspect.b("mem_write", when=angr.BP_AFTER, action=symmem_mem_write)
    state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=skip_memory_constraints)
    state.inspect.b("constraints", when=angr.BP_AFTER, action=symmem_path_constraint)
    state.inspect.b("exit", when=angr.BP_AFTER, action=symmem_exit)
    # No operations for register read/write (yet)
    state.inspect.b("reg_read", when=angr.BP_AFTER, action=symmem_reg_read)
    state.inspect.b("reg_write", when=angr.BP_AFTER, action=symmem_reg_write)


def exec_func(p: angr.Project, 
              func: Function, 
              non_term_funcs: List[int], 
              verbose: bool = False) -> List[Dict]:
    """Symbolically executes a function and computes input constraints

    Args:
        p (angr.Project): Project for target binary
        func (Function): Function to run
        non_term_funcs (List[int]): list of non-terminated function addresses
        verbose (bool): debug printing

    Returns:
        List[claripy.ast.bool.Bool]: Constraints corresponding to control-flow paths through the function
    """
    # Reference: https://docs.angr.io/en/latest/appendix/options.html
    #  - angr.options.CONSERVATIVE_READ_STRATEGY sounds good but oddly useless
    state: angr.SimState = p.factory.blank_state(
        addr=func.entry_point,
        mode="symbolic",
        add_options={
            angr.options.CACHELESS_SOLVER,
            angr.options.AVOID_MULTIVALUED_READS, # This creates new symbolic value when dereferencing address with symbolic values
            angr.options.CALLLESS,
            angr.options.SYMBOLIC_INITIAL_VALUES,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY
        },
    )

    make_static_memory_symbolic(p, state, chunk_size=4)

    make_registers_symbolic(p, state, reg_size=8)

    hook_symmem(state, verbose)

    sm = p.factory.simgr(state)

    # Boundaries of the function
    regions = [(func.entry_point, ret) for ret in func.return_addrs]
    if verbose:
        print("Entry:", hex(func.entry_point))
        print("Regions:", [f"({hex(a)}, {hex(b)})" for a,b in regions])
        print()

    in_regions = lambda addr: any([e <= addr <= r for e, r in regions])
    cfg = p.analyses.CFGFast()

    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))
    # NonTermAvoid check and move states to avoid, must come first
    sm.use_technique(NonTermAvoid(non_term_funcs, verbose=verbose))
    sm.use_technique(StashMonitor(verbose=verbose))

    sm.explore(
        find=func.return_addrs,
        # change this eventually, we do want function calls but we want to step over them if possible
        avoid=(lambda s: not (in_regions(s.addr))), 
        num_find=100,
    )

    # NOTE: Currently I just return angr's default history
    #       for the traversed blocks of each trace.
    #       Alternatively, we can potentially collect more fine-grained
    #       info with sym_mem's history>
    #       We can also cover the constraints at the end, 
    #       but I'm not sure if there's anything that changes
    #       for the symbolic variable expansion.
    #
    #   "history": s.get_plugin("sym_mem").history, 
    #   "path_constraints": s.get_plugin("sym_mem").get_constraint_reprs(s.solver.constraints)        
    results = []

    for s in sm.found:
        results.append({
            "end_address": s.addr,
            "history": list(s.history.bbl_addrs), 
            "memory_regions": list(s.get_plugin("sym_mem").memory_regions.keys()),
            "path_constraints": s.get_plugin("sym_mem").path_constraints,
            "branch_constraints": s.get_plugin("sym_mem").branch_constraints,
            "branch_history": s.get_plugin("sym_mem").recorded_history,
        })
    #s = sm.found[-1]
    #cns = s.get_plugin("sym_mem").branch_constraints
    #for cn in cns:
    #    print(cn.repr)
    #    print(f"    - True: {hex(cn.true_jmp_target)}, False: {hex(cn.false_jmp_target)}, History: {', '.join(hex(addr) for addr in cn.history)}")

    return results
