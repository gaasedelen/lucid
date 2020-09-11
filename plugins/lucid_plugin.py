import sys

import ida_idaapi
import ida_kernwin

import lucid
from lucid.util.python import reload_package

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return LucidPlugin()

class LucidPlugin(ida_idaapi.plugin_t):

    #
    # Plugin flags:
    # - PLUGIN_PROC: Load/unload this plugin when an IDB opens / closes
    # - PLUGIN_HIDE: Hide this plugin from the IDA plugin menu
    #

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "Hex-Rays Microcode Explorer"
    help = ""
    wanted_name = "Lucid"
    wanted_hotkey = ""

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # initialize the plugin
        self.core = lucid.LucidCore(defer_load=True)

        # add lucid to the IDA python console scope, for test/dev/cli access
        sys.modules["__main__"].lucid = self

        # mark the plugin as loaded
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        self.core.unload()

    #--------------------------------------------------------------------------
    # Development Helpers
    #--------------------------------------------------------------------------

    def reload(self):
        """
        Hot-reload the plugin core.
        """
        print("Reloading...")
        self.core.unload()
        reload_package(lucid)
        self.core = lucid.LucidCore()
        self.core.interactive_view_microcode()

    def test(self):
        """
        Run some basic tests of the plugin core against this database.
        """
        self.reload()
        self.core.test()
