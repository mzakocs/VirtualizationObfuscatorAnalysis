import idaapi
import ida_ua
import ida_bytes
import idc

class NOPnHIDEPlugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "NOPnHIDE"
    wanted_hotkey = "Ctrl-Shift-N"
    comment = "NOPS and HIDES an Instruction"
    help = ""
    initialized = False

    # IDA API methods: init, run, term
    def init(self):
        print("NOPnHIDE initialized!")
        return idaapi.PLUGIN_OK


    def run(self, args):
        # Does this transformation wherever the cursor is
        address = idc.here()    
        # Grabs instruction info at the cursor
        ins = ida_ua.insn_t()    
        # Decodes it and grabs its size
        idaapi.decode_insn(ins, address)
        size = ins.size
        # Undefine the data here so we can modify instructions
        ida_bytes.del_items(address)
        # Modify all of the bytes to 0
        print("Hiding: " + ins.get_canon_mnem())
        for byte in range(0, size):
            idc.patch_byte(address + byte, 0x90)
            ida_ua.create_insn(address + byte)
        # Hides the bytes
        print("Start Address: " + str(address))
        print("End Address: " + str(address + size))
        ida_bytes.add_hidden_range(address, address + size, "", "hidden nop", "hidden nop", 0x2d2d2d)


    def term(self):
        print("Terminating NOPnHIDE...")
        self.initialized = False


def PLUGIN_ENTRY():
    return NOPnHIDEPlugin()
