import idaapi
import ida_ua
import ida_bytes
import idc
from keystone import *

# This plugin requires the Keystone assembler library and its Python bindings
# You can find download and installation instructions here: https://www.keystone-engine.org/docs/

# Conversion from IDA Register Numbers to register name strings
register_name = {
    0: b'rax',
    1: b'rcx',
    2: b'rdx',
    3: b'rbx',
    4: b'rsp',
    5: b'rbp',
    6: b'rsi',
    7: b'rdi',
    8: b'r8',
    9: b'r9',
    10: b'r10',
    11: b'r11',
    12: b'r12',
    13: b'r13',
    14: b'r14',
    15: b'r15',
    16: b'efl'
}
# Constant Declaration
nop = 0x90

class InstructionSwapPlugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "InstructionSwap"
    wanted_hotkey = "Ctrl-Shift-S"
    comment = "Swaps obfuscated x86_64 instructions for their deobfuscated forms"
    help = ""
    initialized = False
    
    # Utility Functions
    def hideRange(self, start, end):
        ida_bytes.add_hidden_range(start, end, "", "hidden", "hidden", 0x2d2d2d)
    
    # Instruction Deobfuscators
    def movAdd8RSPToPop(self):
        """
            mov r14, [rsp]
            add rsp, 8
                |
                V
            pop r14
        """
        # Assemble our new instruction (pop reg)
        newInstruction, count = self.ks.asm(b"pop " + register_name[self.ins.Op1.reg])
        # Checks that we have enough space
        if len(newInstruction) > self.total_size:
            print("Not enough space to remove obfuscation! Exiting...")
            return False
        # Overwrite bytes with the new instruction, nops for the extra bytes
        for i in range(0, self.total_size):
            # Gets address of the byte we want to overwrite
            byte = self.address + i
            # Adds the new instruction first
            if i < len(newInstruction):
                idc.patch_byte(byte, newInstruction[i])
            # Then nops the rest of the bytes
            else:
                idc.patch_byte(byte, nop)
        # Redefines the instructions where the patch was performed
        ida_ua.create_insn(self.address)
        # Hides all of the nops
        self.hideRange((self.address + len(newInstruction)), self.end_address)
        # Returns succesfully
        return True
            
    # IDA Plugin Methods
    def init(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        print("InstructionSwap initialized!")
        return idaapi.PLUGIN_OK

    def run(self, args):
        # Does this transformation wherever the cursor is
        self.address = idc.here()    
        # Grabs instruction info at the cursor
        self.ins = ida_ua.insn_t()    
        # Decodes and grabs info about it
        idaapi.decode_insn(self.ins, self.address)
        self.mnem = self.ins.get_canon_mnem()
        self.size = self.ins.size
        # Grabs info about the following instruction, needed for some detections
        self.second_address = self.address + self.size
        self.second_ins = ida_ua.insn_t()
        idaapi.decode_insn(self.second_ins, self.second_address)
        self.second_mnem = self.second_ins.get_canon_mnem()
        self.second_size = self.second_ins.size
        # Calculates some info about both instructions
        self.end_address = self.second_address + self.second_size
        self.total_size = self.size + self.second_size
        # Undefine the data here so we can modify instructions
        ida_bytes.del_items(self.address)
        # Run detections
        success = False
        if self.mnem == 'mov':
            if self.second_mnem == 'add':
                success = self.movAdd8RSPToPop()
        # Success handler
        if success:
            print("Succesfully deobfuscated the instruction(s)!")
            print("Start Address: " + hex(self.address))
            print("End Address: " + hex(self.end_address))
        else:
            print("Could not deobfuscate instruction(s)!")


    def term(self):
        print("Terminating InstructionSwap...")
        self.initialized = False


def PLUGIN_ENTRY():
    return InstructionSwapPlugin()
