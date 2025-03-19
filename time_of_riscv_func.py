#!/usr/bin/env python3
import json
import sys
import argparse
import os
import subprocess

#GHIDRA_ADDR_OFFSET = 0x100000
GHIDRA_ADDR_OFFSET = 0

def time_of_riscv_instr(mnem, args, store_name, ML):
	# Preprocess args into Picinae registers
	for i in range(len(args)):
		arg = args[i]
		if arg in "ra sp gp tp t0 t1 t2 t3 t4 t5 t6 s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 a0 a1 a2 a3 a4 a5 a6 a7".split(" "):
			arg = f"R_{arg.upper()}"
		args[i] = arg

	if mnem in ["add", "sub", "xor", "or", "and", "slt", "sltu",
				"addi", "xori", "ori", "andi", "slti", "sltiu", 
				"lui", "auipc"]:
		return "2"
	if mnem in ["srl", "sll", "sra"]:
		return f"3 + ({store_name} {args[2]} / 4 + {store_name} {args[2]} mod 4)"
	if mnem == "clz":
		return f"3 + clz ({store_name} {args[1]}) 32"
	if mnem in ["srli", "slli", "srai"]:
		return f"3 + args[2] / 4 + args[2] mod 4"
	if mnem in ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]:
		return f"5 + ({ML} - 2)"
	if mnem in ["beq", "bne", "blt", "bge", "bltu", "bgeu"]:
		op1 = '0' if args[0] == 'zero' else f"{store_name} {args[0]}"
		op2 = '0' if args[1] == 'zero' else f"{store_name} {args[1]}"
		letin = f"let rs1, rs2 := ({op1}, {op2}) in"
		if mnem == "beq":
			x = f"if rs1 =? rs2 then 5 + ({ML} - 1) else 3"
		elif mnem == "bne":
			x = f"if negb (rs1 =? rs2) then 5 + ({ML} - 1) else 3"
		elif mnem == "blt":
			x = f"if Z.ltb (toZ 32 rs1) (toZ 32 rs2) then 5 + ({ML - 1}) else 3"
		elif mnem == "bge":
			x = f"if Z.geb (toZ 32 rs1) (toZ 32 rs2) then 5 + ({ML - 1}) else 3"
		elif mnem == "bltu":
			x = f"if rs1 <? rs2 then 5 + ({ML} - 1) else 3"
		elif mnem == "bgeu":
			x = f"if negb (rs1 <? rs2) then 5 + ({ML} - 1) else 3"
		return f"{letin} {x}"
	if mnem in ["jal", "jalr"]:
		return f"5 + ({ML} - 1)"
	if mnem in ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]:
		return f"36"

	# TODO : last few else ifs in Rocq RISCV timing function
	return f"(* ERROR: {mnem} {args} *) err_time"
	

def print_bb(results, function_name=""):
    if function_name != "":
	    results = [x for x in results if x["function_name"] == function_name]
    for func_data in results:
        func_name = func_data["function_name"]
        blocks = func_data["blocks"]
        if not len(blocks):
            continue
        block_addr = blocks[0]['bb_start_vaddr'] + GHIDRA_ADDR_OFFSET
        print(f"{block_addr:010x}  <{func_name}>:")

        for block in blocks:
            preblock = "    > Src: " + ", ".join(f"{addr+GHIDRA_ADDR_OFFSET:x}" for addr in block["source_vaddrs"])
            if block["is_entry_point"]:
                preblock += "(entry)"
            print(preblock)
            block_addr = block["bb_start_vaddr"] + GHIDRA_ADDR_OFFSET
            for instr in block["instructions"]:
                byte_instr = instr["instruction_byte"]
                str_instr = instr["instruction_str"]
                addr = instr["instr_offset"] + GHIDRA_ADDR_OFFSET
                print(f"{addr:7x}:   {byte_instr:20s} {str_instr}") # - {time_of_riscv_instr(instr['mnem'], instr['operands'], 's', 'ML')}")

            problock = "    > Dst: " + ", ".join(f"{addr+GHIDRA_ADDR_OFFSET:x}" for addr in block["exit_vaddrs"])
            if block["is_exit_point"]:
                problock += "(exit)"
            print(problock)

            print(time_of_basic_block(block))

            print()
        print()

def time_of_basic_block(block):
	times = ['(' + time_of_riscv_instr(instr['mnem'], instr['operands'], 's', 'ML') + ')' for instr in block['instructions']]
	return f"{' + '.join(times)}"

def time_of_function_basic_blocks(results, function_name):
	func = [x for x in results if x["function_name"] == function_name][0]
	out = f"Definition basic_block_times_{function_name} (s : store) (ML : nat) (addr : N) : option nat :=\n"
	out += "  let err_time := 999 in\n"
	out += "  match addr with\n"
	for block in func["blocks"]:
		out += f"  | {hex(block['instructions'][-1]['instr_offset'] + GHIDRA_ADDR_OFFSET)} => {time_of_basic_block(block)}\n"
	out += "  end.\n\n"
	return out

def preprocess_data(results, function_name):
	for i in range(len(results)):
		if results[i]['function_name'] == function_name:
			break

	blocks = results[i]["blocks"]
	
	for block in blocks:
		for instr in block["instructions"]:
			instr["operands"] = instr["operands"].split(",")
	
	results[i]["blocks"] = blocks

if __name__ ==  "__main__":
	parser = argparse.ArgumentParser('time_of_riscv_function.py', description='pretty print parsed json file')
	parser.add_argument("bin")
	parser.add_argument("--riscv_objdump", default="riscv32-unknown-linux-gnu-objdump")
	parser.add_argument("--function_name", default="")
	parser.add_argument("--addr_offset", default=0, type=int)
	args = parser.parse_args()

	GHIDRA_ADDR_OFFSET = args.addr_offset

	# If preproc file doesn't exist, generate
	preproc_fn = f"{args.bin}.preprocessed.json"
	objdump_pass_fn = f"{args.bin}.preprocessed.objdump.json"
	if not os.path.exists(objdump_pass_fn):
		result = subprocess.run(["sh", "get_ghidra_basicblocks.sh", args.bin, "x.json"], capture_output=True)
		json_string = result.stdout.splitlines()[1]
		data = json.loads(json_string)
		with open(preproc_fn, "w") as file:
			file.write(json.dumps(data, indent=2))

		# Run objdump pass
		# python ./objdump_pass.py example/RTOSDemo.elf example/RTOSDemo.elf.preprocessed.json example/RTOSDemo.elf.preprocessed.objdump.json  --objdump riscv32-unknown-linux-gnu-objdump
		import objdump_pass
		class Object:
			pass
		objdump_args = Object()
		objdump_args.binary = args.riscv_objdump
		objdump_args.input_json = preproc_fn
		objdump_args.output_json = objdump_pass_fn
		objdump_pass(objdump_args, imported=True)
	else:
		with open(objdump_pass_fn, "r") as file:
			data = json.load(file)

	preprocess_data(data, args.function_name)
	#print_bb(data, args.function_name)
	print(time_of_function_basic_blocks(data, args.function_name))
