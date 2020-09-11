import os

import ida_lines
import ida_netnode
import ida_kernwin

def hexrays_available():
    """
    Return True if an IDA decompiler is loaded and available for use.
    """
    try:
        import ida_hexrays
        return ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False

def tag_text(text, color):
    """
    Return a 'tagged' (colored) version of the given string.
    """
    return "%c%c%s%c%c" % (ida_lines.COLOR_ON, color, text, ida_lines.COLOR_OFF, color)

def get_pdb_name():
    """
    Return the PDB filename as stored in the PE header.
    """
    pe_nn = ida_netnode.netnode('$ PE header', 0, False)
    if pe_nn == ida_netnode.BADNODE:
        return ""

    pdb_filepath = pe_nn.supstr(0xFFFFFFFFFFFFFFF7)
    if not pdb_filepath:
        return ""

    pdb_name = os.path.basename(pdb_filepath)
    return pdb_name

class IDACtxEntry(ida_kernwin.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        ida_kernwin.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function(ctx)
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS

class UIHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        pass
