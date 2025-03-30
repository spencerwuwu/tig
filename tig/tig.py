import argparse
import json
import os
from typing import Tuple, Optional, Dict
from tig.extract_basic_blocks import extract_bb
from tig.bininfo import Instruction, BasicBlock, Function
from tig.tree import compute_dominator_tree, preorder_traversal
from tig.symbolic_execution import get_project, ConstraintType, exec_bb, exec_func


def time_of_riscv_instr(
    instr: Instruction,
) -> Tuple[str, Optional[Tuple[str, str, str]]]:
    """Compute time and branch information given a RISC-V instruction

    Args:
        instr (Instruction): Instruction to time

    Returns:
        Tuple[str, Optional[Tuple[str, str, str]]]: Time, condition,
    """

    store_name = "s"
    ML = "ML"

    time = "err_time"
    condition, true_time, false_time = None, "err_time", "err_time"

    args = instr.operands

    # Preprocess args into Picinae registers
    for i in range(len(args)):
        arg = args[i]
        if arg in [
            "ra",
            "sp",
            "gp",
            "tp",
            "t0",
            "t1",
            "t2",
            "t3",
            "t4",
            "t5",
            "t6",
            "s0",
            "s1",
            "s2",
            "s3",
            "s4",
            "s5",
            "s6",
            "s7",
            "s8",
            "s9",
            "s10",
            "s11",
            "a0",
            "a1",
            "a2",
            "a3",
            "a4",
            "a5",
            "a6",
            "a7",
        ]:
            arg = f"R_{arg.upper()}"
        args[i] = arg

    if instr.mnem in [
        "add",
        "sub",
        "xor",
        "or",
        "and",
        "slt",
        "sltu",
        "addi",
        "xori",
        "ori",
        "andi",
        "slti",
        "sltiu",
        "lui",
        "auipc",
    ]:
        time = "2"
    elif instr.mnem in ["srl", "sll", "sra"]:
        time = f"3 + ({store_name} {args[2]} / 4 + {store_name} {args[2]} mod 4)"
    elif instr.mnem == "clz":
        time = f"3 + clz ({store_name} {args[1]}) 32"
    elif instr.mnem in ["srli", "slli", "srai"]:
        time = f"3 + args[2] / 4 + args[2] mod 4"
    elif instr.mnem in ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]:
        time = f"5 + ({ML} - 2)"
    elif instr.mnem in ["beq", "bne", "blt", "bge", "bltu", "bgeu"]:
        true_time = f"5 + ({ML} - 1)"
        false_time = "3"
        op1 = "0" if args[0] == "zero" else f"{store_name} {args[0]}"
        op2 = "0" if args[1] == "zero" else f"{store_name} {args[1]}"
        if instr.mnem == "beq":
            condition = f"{op1} =? {op2}"
        elif instr.mnem == "bne":
            condition = f"negb ({op1} =? {op2})"
        elif instr.mnem == "blt":
            condition = f"Z.ltb (toZ 32 {op1}) (toZ 32 {op2})"
        elif instr.mnem == "bge":
            condition = f"Z.geb (toZ 32 {op1}) (toZ 32 {op2})"
        elif instr.mnem == "bltu":
            condition = f"{op1} <? {op2}"
        elif instr.mnem == "bgeu":
            condition = f"negb ({op1} <? {op2})"
        time = f"if {condition} then {true_time} else {false_time}"
    elif instr.mnem in ["jal", "jalr"]:
        time = f"5 + ({ML} - 1)"
    elif instr.mnem in ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]:
        time = f"36"
    else:
        # TODO : last few else ifs in Rocq RISCV timing function
        time = f"(* ERROR: {instr.mnem} {args} *) err_time"

    condition_info = (
        (condition, true_time, false_time) if condition is not None else None
    )
    return (time, condition_info)


# Return time of basic block, final instruction info extracted if it's a branch
def time_of_basic_block(
    block: BasicBlock,
) -> Tuple[str, Optional[Tuple[str, str, str]]]:
    """Compute time of basic block, extracting final instruction if it is a branch

    Args:
        block (BasicBlock): Block to time

    Returns:
        Tuple[str, Optional[Tuple[str, str, str]]]: Basic block timing string, conditional information if [block] has mutiple exit points
    """
    times = [time_of_riscv_instr(instr)[0] for instr in block.instructions[:-1]]
    parens = lambda s: f"({s})" if " " in s else s
    times = [parens(time) for time in times]

    # Check final instruction for branching
    final_time, condition_info = time_of_riscv_instr(block.instructions[-1])

    if block.branches:
        return f"{' + '.join(times)}", condition_info
    else:
        return f"{' + '.join(times + [parens(final_time)])}", None


def generate_timing_invariants(bin_path: str, func: Function) -> Dict[int, str]:
    # Start up angr

    # Invariant points are:
    # - Function entry point (just True)
    # - Function exit points
    # - Everywhere more than one control-flow paths merge

    # Do preorder traversal of dominator tree to visit all nodes
    # before a control-flow merge before the merge point

    # For each node

    p = get_project(bin_path)
    print(exec_func(p, func))
    # for block in func:
    #     print(f"====={block.start_vaddr}=====")
    #     print(exec_bb(p, block, []))

    return {}


def main():
    parser = argparse.ArgumentParser(
        "tig.py", description="Generate Picinae timing invariants for binary code"
    )
    parser.add_argument("bin", type=str)
    parser.add_argument("func", type=str)
    parser.add_argument(
        "--riscv-objdump", default="riscv32-unknown-elf-objdump", type=str
    )
    parser.add_argument("--addr-offset", default=None, type=int)
    parser.add_argument("--out-file", default=None, type=str)
    args = parser.parse_args()

    # Preprocess and load binary information
    preproc_fn = f"{args.bin}.json"
    if not os.path.exists(preproc_fn):
        data = extract_bb(args.bin, preproc_fn, objdump=args.riscv_objdump)
    else:
        with open(preproc_fn, "r") as file:
            data = json.load(file)
    func = Function([x for x in data if x["function_name"] == args.func][0])

    # Add offset
    if args.addr_offset is not None:
        for block in func:
            block.start_vaddr += args.addr_offset
            block.exit_vaddrs = [a + args.addr_offset for a in block.exit_vaddrs]
            block.source_vaddrs = [a + args.addr_offset for a in block.source_vaddrs]
            for instr in block:
                instr.offset += args.addr_offset

    invs = generate_timing_invariants(args.bin, func)

    # invs = rocq_of_invariants(args.func, invs)
    # if args.out_file is None:
    #     print(invs)
    # else:
    #     with open(args.out_file, "w") as file:
    #         file.write(invs)


if __name__ == "__main__":
    main()
