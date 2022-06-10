#!/usr/bin/python3
from unicorn import *
from unicorn.arm_const import *
from capstone import *
from tqdm import tqdm
from tabulate import tabulate
from collections import Counter

# Settings
VERBOSE = False
BIN = "bl1.bin"

# Memory(mapped) addresses
SYSTEM_BUS   = 0x11000000
STAGE2       = 0x32000000
STAGE2_SIZE  = 0x1000
BASE_ADDRESS = 0x80000000
ROM          = BASE_ADDRESS
ROM_SIZE     = 0x20000
STACK        = 0x80100000
STACK_SIZE   = 0x10000
TRIGGER      = 0xAA01000

# Data
EXPECTED_DATA = b"Test Payload!!!!"
ALT_DATA      = b"!! Pwned boot !!"

def hook_mem(uc, access, address, size, value, data):
    """
    Stops emulation when a value is written to the trigger address
    """
    if address == TRIGGER:
        uc.emu_stop()

def trigger_status(emu):
    """
    Checks what value has been written to the trigger address
    """
    return emu.mem_read(TRIGGER, 1) == b'\x01'

def run_emu(data, bytecode):
    try:
        # Initialize emulator in ARM mode
        emu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # Map memory for this emulation
        emu.mem_map(SYSTEM_BUS, 0x400)
        emu.mem_map(TRIGGER, 0x400)
        emu.mem_map(STAGE2, STAGE2_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        emu.mem_map(ROM, ROM_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        emu.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        # Write machine code to be emulated to memory
        emu.mem_write(ROM, bytecode)

        # Write data to next boot stage mem
        emu.mem_write(STAGE2, data)

        # Initialize stack pointer
        emu.reg_write(UC_ARM_REG_SP, STACK + STACK_SIZE)

        # Tracing trigger
        emu.hook_add(UC_HOOK_MEM_WRITE, hook_mem, TRIGGER)

        # Start emulation
        emu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(bytecode), 1000)

        return trigger_status(emu), False

    except UcError as e:
        return False, e

def validate(bytecode):
    """
    Check if the program behaves as expected
    """
    e_status, err = run_emu(EXPECTED_DATA, bytecode)
    a_status, err = run_emu(ALT_DATA, bytecode)
    return e_status == True and a_status == False

def disasm_inst(inst, adress):
    """
    Disassemble a single instruction
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    d = list(md.disasm(inst, adress))[0]
    return d

def cashed_bitflip(bytecode):
    """
    Flips all bits one by one
    """
    report_table = []
    for bit in tqdm(range(len(bytecode)*8)):
        patched_code = bytearray(bytecode)
        byte, inst = bit//8,  bit//8//4
        patched_code[byte] ^= 2**(bit%8)
        patched_code = bytes(patched_code)
        a_status, err = run_emu(ALT_DATA, patched_code)
        if a_status:
            offset = (inst*4)
            # Disassemble and log the original and patched instructions
            do = disasm_inst(bytecode[offset:offset+4], BASE_ADDRESS+offset)
            dp = disasm_inst(patched_code[offset:offset+4], BASE_ADDRESS+offset)
            report_table.append([do.address, do.mnemonic, do.op_str , dp.mnemonic, dp.op_str])
    return(report_table)

def cashed_patch(bytecode, patch):
    """
    Replaces instructions one by one with a given patch
    """
    report_table = []
    for offset in tqdm(range(0, len(bytecode)-4, 4)):
        patched_code = bytearray(bytecode)
        patched_code[offset:offset+4] = patch
        a_status, err = run_emu(ALT_DATA, bytes(patched_code))
        if a_status:
            # Disassemble and log the original and patched instructions
            do = disasm_inst(bytecode[offset:offset+4], BASE_ADDRESS+offset)
            dp = disasm_inst(patched_code[offset:offset+4], BASE_ADDRESS+offset)
            report_table.append([do.address, do.mnemonic, do.op_str , dp.mnemonic, dp.op_str])
    return(report_table)

def draw_table(report_table, verbose=False):
    """
    Prints the discovered glitches in formatted table
    """
    counts = Counter([x[0] for x in report_table])
    final_table = []
    adr = 0
    for row in sorted(report_table):
        if adr != row[0]:
            adr = row[0]
            final_table.append([F"{adr:02x}:".upper(), row[1].upper(), row[2], "-->", row[3].upper(), row[4], F"({counts[adr]}x)"])
        else:
            if verbose:
                final_table.append(["",  row[1], row[2], "-->", row[3], row[4], ""])
    print(tabulate(final_table, tablefmt="plain")+"\n")

if __name__ == '__main__':
    # Load and validate code
    print('VALIDATION:')
    with open(BIN, "br") as infile:
        bytecode = infile.read()
    if validate(bytecode):
        print("Passed!\n")
    else:
        print("Failed!\n")
        exit(-1)

    # Cashed Nop Model
    nop_bytecode = [0, 240, 32, 227]
    print('CASHED NOP GLITCHES:')
    nop_table = cashed_patch(bytecode, nop_bytecode)
    draw_table(nop_table, VERBOSE)

    # Cashed BitFlip Model
    print('CASHED BITFLIP GLITCHES:')
    bitflip_table = cashed_bitflip(bytecode)
    draw_table(bitflip_table, VERBOSE)

    # Report total glitches found
    print(F"{len(nop_table)+len(bitflip_table)} glitches found")
