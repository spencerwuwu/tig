# Ghidra Headless Basic Block Extractor

## Dependencies
1. Docker (for hosting headless **Ghidra**)
2. llvm (for **llvm-objdump**)
3. capstone >= 5.0.0 (install through pip)


## Usage

1. Build the Docker image (`ghidra-bbextract`). 
```bash
make build  
```

2. Collect basic blocks information from **Ghidra** and store in json file
```bash
./get_ghidra_basicblocks.sh <binary> <out_json>
```
For example, `example/example.json` is created with `./get_ghidra_basicblocks.sh example/example.clang.0.o example/example.json`

3. Get different dissamble results from **objdump** and **capstone** with the json file generated from Ghidra.   
  This updates each instruction's `mnem`, `operands`, `instruction_str` and store to a new json file.   
  Note that for **objdump**, I group all instructions not matched with **Ghidra** into a psedu function block `_OBJDUMP_ORPHANS`.   
```bash
# Collect dissambly from objdump for the same basic blocks
# OBJ_BIN: riscv64-linux-gnu-objdump, llvm-objdump (default)
./llvm-objdump_pass.py [--objdump OBJ_BIN] <binary> <input_json> <output_json>

# Collect dissambly from capstone for the same basic blocks
./capstone_pass.py <arch> <input_json> <output_json>
```

4. Quickview the extracted json file with `parse_result_json.py`.   
  I use this to generate files in `disassembly_diff/` to compare the results of differentt dissamblers.


## Json format
```
[
    {
        "function_name": "xx",
        "blocks": [
            {
                "bb_start_vaddr": (long),       # basic block virtual start address
                "bbsize": (long),               # basic block size
                "is_exit_point": (boolean),     # end of function? 
                "exit_vaddrs": [(long), ...],   # addresses of the successor blocks
                "is_entry_point": (boolean),    # start of function?
                "source_vaddrs": [(long), ...], # addresses of the predecessor blocks
                "instr_mode": (str)         # Thumb mode? vle mode? Or `none`
                "instructions": [
                    {
                        "instr_offset": (long),    # instruction address
                        "instr_size": (long),      # length of the instruction
                        "mnem": (str),             # get the mnemonic for this code unit, e.g., MOV, JMP
                        "operands": (str),         # maybe more than 1, seperated with ,
                        "regs_read": (str),        # ..
                        "regs_written": (str),     # ..
                        "results": (str),          # registers/addresses affected by this instruction
                        "instruction_str": (str),
                        "instruction_byte": (str), # instruction byte string
                        "is_big_endian": (boolean)
                    }, ...
                ]
            }, ...
        ]
    }, ...
]
```
