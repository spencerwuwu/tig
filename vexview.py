from tig.symbolic_execution import get_project
import json
from tig.bininfo import Function

p = get_project("examples/RTOSDemo.elf")

with open("examples/RTOSDemo.elf.json", "r") as file:
    data = json.load(file)
func = Function([x for x in data if x["function_name"] == "vTaskSwitchContext"][0])

def print_block_vex(addr):
    block = p.factory.block(addr).vex
    block.pp()

for block in func:
    print(block)
    print_block_vex(block.start_vaddr)

print_block_vex(0x800013e8)
