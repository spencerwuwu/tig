#!/usr/bin/env python3
from capstone import *
import json
import argparse


if __name__ ==  "__main__":
    parser = argparse.ArgumentParser('capstone_pass.py', description='add capstone disassembly')
    parser.add_argument("arch", help='riscv32, riscv64, riscvc, x86')
    parser.add_argument("input_json")
    parser.add_argument("output_json")
    args = parser.parse_args()

    with open(args.input_json, "r") as fd:
        orig_data = json.load(fd)

    # TODO: more arch
    arch = args.arch
    if arch == "riscv32":
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    elif arch == "riscv64":
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    elif arch == "riscvc":
        md = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC)
    elif arch == "x86":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        raise NotImplementedError(f"Unknown arch {arch}")

    for func_data in orig_data:
        for block in func_data["blocks"]:
            for instr in block["instructions"]:
                orig_instr = instr["instruction_str"] 
                code = bytes.fromhex(instr["instruction_byte"])
                if len(list(md.disasm(code, instr["instr_offset"]))) > 1:
                    print(list(md.disasm(code, instr["instr_offset"])))
                    raise NotImplementedError(f"Address {instr['instr_offset']:x} unfolded")
                for i in md.disasm(code, instr["instr_offset"]):
                    instr["mnem"] = i.mnemonic
                    op_str = i.op_str.replace(" ", "")
                    instr["operands"] = op_str
                    new_instr = f"{i.mnemonic} {op_str}".strip()
                    instr["instruction_str"] = new_instr
    
    with open(args.output_json, "w") as fd:
        json.dump(orig_data, fd)

#'CS_ARCH_ARM',
#'CS_ARCH_AARCH64',
#'CS_ARCH_MIPS',
#'CS_ARCH_X86',
#'CS_ARCH_PPC',
#'CS_ARCH_SPARC',
#'CS_ARCH_SYSTEMZ',
#'CS_ARCH_XCORE',
#'CS_ARCH_M68K',
#'CS_ARCH_TMS320C64X',
#'CS_ARCH_M680X',
#'CS_ARCH_EVM',
#'CS_ARCH_MOS65XX',
#'CS_ARCH_WASM',
#'CS_ARCH_BPF',
#'CS_ARCH_RISCV',
#'CS_ARCH_SH',
#'CS_ARCH_TRICORE',
#'CS_ARCH_ALPHA',
#'CS_ARCH_HPPA',
#'CS_ARCH_LOONGARCH',
#'CS_ARCH_XTENSA',
#'CS_ARCH_ARC',
#'CS_ARCH_ALL',
#
#'CS_MODE_LITTLE_ENDIAN',
#'CS_MODE_BIG_ENDIAN',
#'CS_MODE_16',
#'CS_MODE_32',
#'CS_MODE_64',
#'CS_MODE_ARM',
#'CS_MODE_THUMB',
#'CS_MODE_MCLASS',
#'CS_MODE_V8',
#'CS_MODE_V9',
#'CS_MODE_QPX',
#'CS_MODE_SPE',
#'CS_MODE_BOOKE',
#'CS_MODE_PS',
#'CS_MODE_MIPS16',
#'CS_MODE_MIPS32',
#'CS_MODE_MIPS64',
#'CS_MODE_MICRO',
#'CS_MODE_MIPS1',
#'CS_MODE_MIPS2',
#'CS_MODE_MIPS32R2',
#'CS_MODE_MIPS32R3',
#'CS_MODE_MIPS32R5',
#'CS_MODE_MIPS32R6',
#'CS_MODE_MIPS3',
#'CS_MODE_MIPS4',
#'CS_MODE_MIPS5',
#'CS_MODE_MIPS64R2',
#'CS_MODE_MIPS64R3',
#'CS_MODE_MIPS64R5',
#'CS_MODE_MIPS64R6',
#'CS_MODE_OCTEON',
#'CS_MODE_OCTEONP',
#'CS_MODE_NANOMIPS',
#'CS_MODE_NMS1',
#'CS_MODE_I7200',
#'CS_MODE_MIPS_NOFLOAT',
#'CS_MODE_MIPS_PTR64',
#'CS_MODE_MICRO32R3',
#'CS_MODE_MICRO32R6',
#'CS_MODE_M68K_000',
#'CS_MODE_M68K_010',
#'CS_MODE_M68K_020',
#'CS_MODE_M68K_030',
#'CS_MODE_M68K_040',
#'CS_MODE_M68K_060',
#'CS_MODE_M680X_6301',
#'CS_MODE_M680X_6309',
#'CS_MODE_M680X_6800',
#'CS_MODE_M680X_6801',
#'CS_MODE_M680X_6805',
#'CS_MODE_M680X_6808',
#'CS_MODE_M680X_6809',
#'CS_MODE_M680X_6811',
#'CS_MODE_M680X_CPU12',
#'CS_MODE_M680X_HCS08',
#'CS_MODE_BPF_CLASSIC',
#'CS_MODE_BPF_EXTENDED',
#'CS_MODE_RISCV32',
#'CS_MODE_RISCV64',
#'CS_MODE_RISCVC',
#'CS_MODE_MOS65XX_6502',
#'CS_MODE_MOS65XX_65C02',
#'CS_MODE_MOS65XX_W65C02',
#'CS_MODE_MOS65XX_65816',
#'CS_MODE_MOS65XX_65816_LONG_M',
#'CS_MODE_MOS65XX_65816_LONG_X',
#'CS_MODE_MOS65XX_65816_LONG_MX',
#'CS_MODE_SH2',
#'CS_MODE_SH2A',
#'CS_MODE_SH3',
#'CS_MODE_SH4',
#'CS_MODE_SH4A',
#'CS_MODE_SHFPU',
#'CS_MODE_SHDSP',
#'CS_MODE_TRICORE_110',
#'CS_MODE_TRICORE_120',
#'CS_MODE_TRICORE_130',
#'CS_MODE_TRICORE_131',
#'CS_MODE_TRICORE_160',
#'CS_MODE_TRICORE_161',
#'CS_MODE_TRICORE_162',
#"CS_MODE_TRICORE_180",
#'CS_MODE_HPPA_11',
#'CS_MODE_HPPA_20',
#'CS_MODE_HPPA_20W',
#'CS_MODE_LOONGARCH32',
#'CS_MODE_LOONGARCH64',
#'CS_MODE_SYSTEMZ_ARCH8',
#'CS_MODE_SYSTEMZ_ARCH9',
#'CS_MODE_SYSTEMZ_ARCH10',
#'CS_MODE_SYSTEMZ_ARCH11',
#'CS_MODE_SYSTEMZ_ARCH12',
#'CS_MODE_SYSTEMZ_ARCH13',
#'CS_MODE_SYSTEMZ_ARCH14',
#'CS_MODE_SYSTEMZ_Z10',
#'CS_MODE_SYSTEMZ_Z196',
#'CS_MODE_SYSTEMZ_ZEC12',
#'CS_MODE_SYSTEMZ_Z13',
#'CS_MODE_SYSTEMZ_Z14',
#'CS_MODE_SYSTEMZ_Z15',
#'CS_MODE_SYSTEMZ_Z16',
#'CS_MODE_SYSTEMZ_GENERIC',
