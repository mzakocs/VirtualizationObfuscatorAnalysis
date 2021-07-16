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
    # IDA Plugin Variables
    flags = 0  # Normal Plugin
    wanted_name = "InstructionSwap"
    wanted_hotkey = "Ctrl-Shift-S"
    comment = "Swaps obfuscated x86_64 instructions for their deobfuscated forms"
    help = ""
    initialized = False
    
    
    # Utility Functions
    
    def hide_range(self, start, end):
        ida_bytes.add_hidden_range(start, end, "", "hidden", "hidden", 0x2d2d2d)
    
    def get_nth_instruction_after(self, n):
        temp_instruction = ida_ua.insn_t()
        temp_address = idc.here()
        count = 0
        while(True):
            try:
                idaapi.decode_insn(temp_instruction, temp_address)
                temp_address += temp_instruction.size
                if (count == n):
                    break    
            except:
                break
        return temp_instruction
        
    def get_instruction_array(self, n, base):
        instruction_array = []
        address = base
        for i in range(0, n):
            temp_instruction = ida_ua.insn_t()
            idaapi.decode_insn(temp_instruction, address)
            address += temp_instruction.size
            instruction_array.append(temp_instruction)
        return instruction_array
        
    def get_instruction_sizes(self, n):
        size = 0
        for i in range(0, n):
            size += self.ins[n].size
        return size
        
    def patch_bytes_and_nop(self, newInstruction, block_size):
        # Overwrite bytes with the new instruction, nops for the extra bytes
        newInstructionSize = len(newInstruction)
        for i in range(0, block_size):
            # Gets address of the byte we want to overwrite
            byte = self.address + i
            # Adds the new instruction first
            if i < newInstructionSize:
                idc.patch_byte(byte, newInstruction[i])
            # Then nops the rest of the bytes
            else:
                idc.patch_byte(byte, nop)
        # Hides all of the nops
        self.hide_range((self.address + newInstructionSize), (self.address + block_size))
    
    
    # Instruction Deobfuscators
    
    def mov_add_8_rsp_to_pop(self):
        """
            mov x, [rsp]
            add rsp, 8
                |
                V
            pop x
        """
        # Gets sizing info for the larger instruction sequence
        size = self.get_instruction_sizes(2)
        # Assemble our new instruction (pop reg)
        newInstruction, count = self.ks.asm(b"pop " + register_name[self.ins[0].Op1.reg])
        # Overwrite bytes with the new instruction, nops for the extra bytes
        self.patch_bytes_and_nop(newInstruction, size)
        # Returns succesfully
        return True
     
    def xor_swap_to_add_8_rsp(self):
        """
            push x
            mov x, rsp
            add x, 8
            add x, 8
            xor x, [rsp]
            xor [rsp], x
            xor x, [rsp]
            pop rsp
                |
                V
            add rsp, 8
        """
        # Gets sizing info for the larger instruction sequence
        size = self.get_instruction_sizes(8)
        # Assemble our new instruction (add rsp, 8)
        newInstruction, count = self.ks.asm(b"add rsp, 8")
        # Overwrite bytes with the new instruction, nops for the extra bytes
        self.patch_bytes_and_nop(newInstruction, size)
        # Returns succesfully
        return True
        
    def xchg_swap_to_add_8_rsp(self):
        """
            push x
            mov x, rsp
            add x, 8
            add x, 8
            xchg x, [rsp]
            pop rsp
                |
                V
            add rsp, 8
        """
        # Gets sizing info for the larger instruction sequence
        size = self.get_instruction_sizes(6)
        # Assemble our new instruction (add rsp, 8)
        newInstruction, count = self.ks.asm(b"add rsp, 8")
        # Overwrite bytes with the new instruction, nops for the extra bytes
        self.patch_bytes_and_nop(newInstruction, size)
        # Returns succesfully
        return True
        
    def push_iv_mov_register_to_push_register(self):
        """
            push IV
            mov [rsp], x
                |
                V
            push x
        """
        # Assemble our new instruction (pop reg)
        newInstruction, count = self.ks.asm(b"push " + register_name[self.ins[1].Op1.reg])
        size = self.get_instruction_sizes(2)
        # Overwrite bytes with the new instruction, nops for the extra bytes
        self.patch_bytes_and_nop(newInstruction, size)
        # Returns succesfully
        return True
        
            
    # IDA Plugin Methods
    
    def init(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        print("InstructionSwap initialized!")
        return idaapi.PLUGIN_OK

    def run(self, args):
        # Starts optimizing wherever the cursor is
        self.start_address = idc.here()    
        self.address = self.start_address  
        # Undefine the instructions here so we can modify them
        ida_bytes.del_items(self.start_address)
        # Loops through each instruction until we hit jmp or call
        while(True):
            # Grabs info about the following instructions
            self.ins = self.get_instruction_array(10, self.address)
            # Run detections
            success = False
            try:
                if self.ins[0].get_canon_mnem() == 'mov':
                    if self.ins[1].get_canon_mnem() == 'add':
                        if register_name[self.ins[0].Op2.reg] == 'rsp' and self.ins[1].Op2.type == 5: # immediate value
                            success = self.mov_add_8_rsp_to_pop()
                elif self.ins[0].get_canon_mnem() == 'push':
                    if self.ins[1].get_canon_mnem() == 'mov':
                        if len(self.ins) >= 3:
                            if self.ins[3].get_canon_mnem() == 'xor':
                                success == self.xor_swap_to_add_8_rsp()
                            elif self.ins[3].get_canon_mnem() == 'xchg':
                                success == self.xchg_swap_to_add_8_rsp()
                        if self.ins[0].Op1.type == 5: # immediate value
                            success == self.push_iv_mov_register_to_push_register()
                # Break the loop once we hit a jmp or call instruction
                elif self.ins[0].get_canon_mnem() == 'jmp' or self.ins[0].get_canon_mnem() == 'call':
                    break
            except Exception as e:
                print("Something went wrong: " + str(e))
                break
            # Set the current address to the next instruction
            self.address = self.ins[1].ea
            # Success handler
            if success:
                print("Succesfully deobfuscated the instruction(s)!")
                print("Start Address: " + hex(self.address))
                print("End Address: " + hex(self.end_address))
            else:
                print("Could not deobfuscate instruction(s)!")
        # Redefines the instructions where the patch was performed
        ida_ua.create_insn(self.start_address)


    def term(self):
        print("Terminating InstructionSwap...")
        self.initialized = False


def PLUGIN_ENTRY():
    return InstructionSwapPlugin()
