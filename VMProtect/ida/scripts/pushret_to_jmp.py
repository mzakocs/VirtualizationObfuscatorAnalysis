# Replaces a push+ret jump obfuscation with a jmp+nop
# Allows IDA to accurately represent the control flow graph
# Mitch Zakocs, 2021

# Gets the address of where the IDA cursor currently is
address = here();
instruction_bytes = idc.get_bytes(address, 5)
# Checks if the third byte is 0x34, a push instruction
if instruction_bytes[2] == int('0x34', 16) and instruction_bytes[4] == int('0xC3', 16): # hexadecimal conversion
    # Undefine the code so we can replace bytes
    ida_bytes.del_items(address);
    # If it is, replace 0x34 (push) with 0x24 (jmp)
    idc.patch_byte(address + 2, int('0x24', 16));
    # Also replace the ret with a nop
    idc.patch_byte(address + 4, 0);
else:
    print("Can't find a push instruction here!");