import argparse
import json
import os
import subprocess
from typing import Tuple, Optional, Dict, List
from tig.extract_basic_blocks import extract_bb, get_non_terminated_functions
from tig.bininfo import Instruction, BasicBlock, Function
from tig.symbolic_execution import get_project, exec_func
from tig.proof_synthesis import synthesize_noverlaps_proof


def symexec_function(bin_path: str, 
                     func: Function,
                     base_addr: int,
                     no_term_func_addrs: List[int],
                     verbose: bool = False
                               ) -> Dict: # {"results": [Dict], "info": Dict}
    # Start up angr

    # Invariant points are:
    # - Function entry point (just True)
    # - Function exit points
    # - Everywhere more than one control-flow paths merge

    # For each node

    p = get_project(bin_path, base_addr)
    f = exec_func(p, func, no_term_func_addrs, verbose=verbose)

    return f


def main():
    parser = argparse.ArgumentParser(
        "tig.py", description="Generate Picinae timing invariants for binary code"
    )
    parser.add_argument("bin", type=str)
    parser.add_argument("func", type=str)
    parser.add_argument("--objdump", default="riscv32-unknown-elf-objdump", type=str)
    parser.add_argument("--disas", action="store_true")
    parser.add_argument("--out-file", default=None, type=str)

    args = parser.parse_args()

    if args.disas:
        result = subprocess.run(
            [
                args.objdump,
                "-d",
                "-M",
                "no-aliases",
                args.bin,
                f"--disassemble={args.func}",
            ],
            capture_output=True,
        )
        print(result.stdout.decode("utf-8"))
        return

    # Preprocess and load binary information
    preproc_fn = f"{args.bin}.json"
    if not os.path.exists(preproc_fn):
        data = extract_bb(args.bin, preproc_fn, objdump=args.objdump)
    else:
        with open(preproc_fn, "r") as file:
            data = json.load(file)

    no_term_funcs = get_non_terminated_functions(data)
    no_term_func_addrs = [addr for _,addr in no_term_funcs]

    func = Function([x for x in data if x["function_name"] == args.func][0])

    base_addr = data[0]["blocks"][0]["bb_start_vaddr"]

    result = symexec_function(args.bin, func, base_addr, no_term_func_addrs, verbose=False)

    rocq = synthesize_noverlaps_proof(func, result["info"], result["results"], verbose=False)

    #if args.out_file is None:
    #    print(rocq)
    #else:
    #    with open(args.out_file, "w") as file:
    #        file.write(rocq)


if __name__ == "__main__":
    main()
