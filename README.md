# Ghidra Headless Basic Block Exactor

## Usage

1. Build the Docker image (`ghidra-bbextract`). 
```bash
make build  
```

2. Collect basic blocks information and store in json file
```bash
./get_ghidra_basicblocks.sh <binary> <out_json>
```
For example, `example/example.json` is created with ```./get_ghidra_basicblocks.sh example/example.clang.0.o example/example.json```


3. Quickview the extracted json file with `parse_result_json.py`

## Json format
```
[
    {
        "function_name": "xx",
        "blocks": [
            {
                "bb_start_vaddr": (long),       # basic block starting virtual address
                "bbsize": (long),               # basic block size
                "is_exit_point": (boolean),     # end of function? 
                                                #  if true then `exit_vaddr` should be ignored
                "exit_vaddr": (long),           # address of the successor block
                "is_entry_point": (boolean),    # start of function?
                "source_vaddrs": [(long), ...], # addresses of the predecessor blocks
                "instr_mode": (boolean)         # Thumb mode? vle mode? Or `none`
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
