import ida_idaapi
import ida_kernwin

from lucid.util.ida import UIHooks, IDACtxEntry, hexrays_available
from lucid.ui.explorer import MicrocodeExplorer

#------------------------------------------------------------------------------
# Lucid Plugin Core
#------------------------------------------------------------------------------
#
#    The plugin core constitutes the traditional 'main' plugin class. It
#    will host all of the plugin's objects and integrations, taking
#    responsibility for their initialization/teardown/lifetime. 
#
#    This pattern of splitting out the plugin core from the IDA plugin_t stub
#    is primarily to help separate the plugin functionality from IDA's and
#    make it easier to 'reload' for development / testing purposes.
#

class LucidCore(object):

    PLUGIN_NAME = "Lucid"
    PLUGIN_VERSION = "0.2.3"
    PLUGIN_AUTHORS = "Markus Gaasedelen, Fireboyd78"
    PLUGIN_DATE = "2024"

    def __init__(self, defer_load=False):
        self.loaded = False
        self.explorer = None

        #
        # we can 'defer' the load of the plugin core a little bit. this
        # ensures that all the other plugins (eg, decompilers) can get loaded
        # and initialized when opening an idb/bin 
        #

        class UIHooks(ida_kernwin.UI_Hooks):
            def ready_to_run(self):
                pass

        self._startup_hooks = UIHooks()
        self._startup_hooks.ready_to_run = self.load
        
        if defer_load:
            self._startup_hooks.hook()
            return

        # plugin loading was not deferred (eg, hot reload), load immediately
        self.load()

    #-------------------------------------------------------------------------
    # Initialization / Teardown
    #-------------------------------------------------------------------------

    def load(self):
        """
        Load the plugin core.
        """
        self._startup_hooks.unhook()

        # the plugin will only load for decompiler-capabale IDB's / installs
        if not hexrays_available():
            return

        # print plugin banner
        print("Loading %s v%s - (c) %s" % (self.PLUGIN_NAME, self.PLUGIN_VERSION, self.PLUGIN_AUTHORS))

        # initialize the the plugin integrations
        self._init_action_view_microcode()
        self._install_hexrays_hooks()

        # all done, mark the core as loaded
        self.loaded = True
    
    def get_hotload_state(self):
        """
        Gets persistent parameters that can be used to restore after a hotload.
        """
        state = {}
        # TODO: Let the classes handle their state data.
        if self.explorer:
            explorer_params = {
                "active": self.explorer.view.visible,
            }
            state["explorer"] = explorer_params
        return state
    
    def set_hotload_state(self, state):
        """
        Restores saved parameters that were retrieved prior to a hotload.
        """
        explorer_params = state.get("explorer", {})
        # TODO: Let the classes handle their state data.
        if explorer_params:
            if explorer_params.get("active", False):
                self.interactive_view_microcode()
    
    def unload(self, from_ida=False):
        """
        Unload the plugin core.
        """

        # unhook just in-case load() was never actually called...
        self._startup_hooks.unhook()

        # if the core was never fully loaded, there's nothing else to do
        if not self.loaded:
            return

        print("Unloading %s..." % self.PLUGIN_NAME)
        
        if self.explorer:
            self.explorer.unload()
            del self.explorer

        # mark the core as 'unloaded' and teardown its components
        self.loaded = False

        self._remove_hexrays_hooks()
        self._del_action_view_microcode()

    #--------------------------------------------------------------------------
    # UI Actions
    #--------------------------------------------------------------------------

    def interactive_view_microcode(self, ctx=None):
        """
        Open the Microcode Explorer window.
        """
        current_address = ida_kernwin.get_screen_ea()
        if current_address == ida_idaapi.BADADDR:
            ida_kernwin.warning("Could not open Microcode Explorer (bad cursor address)")
            return

        #
        # if the microcode window is open & visible, we should just refresh
        # it but at the current IDA cursor address
        #

        if self.explorer and self.explorer.view.visible:
            self.explorer.select_function(current_address)
            return

        # no microcode window in use, create a new one and show it
        self.explorer = MicrocodeExplorer()
        self.explorer.show(current_address)

    #--------------------------------------------------------------------------
    # Action Registration
    #--------------------------------------------------------------------------

    ACTION_VIEW_MICROCODE  = "lucid:view_microcode"

    def _init_action_view_microcode(self):
        """
        Register the 'View microcode' action with IDA.
        """

        # describe the action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_VIEW_MICROCODE,                    # The action name
            "View microcode",                              # The action text
            IDACtxEntry(self.interactive_view_microcode),  # The action handler
            "Ctrl-Shift-M",                                # Optional: action shortcut
            "Open the Lucid Microcode Explorer",           # Optional: tooltip
            -1                                             # Optional: the action icon
        )

        # register the action with IDA
        assert ida_kernwin.register_action(action_desc), "Action registration failed"

    def _del_action_view_microcode(self):
        """
        Delete the 'View microcode' action from IDA.
        """
        ida_kernwin.unregister_action(self.ACTION_VIEW_MICROCODE)

    #--------------------------------------------------------------------------
    # Hex-Rays Hooking
    #--------------------------------------------------------------------------

    def _install_hexrays_hooks(self):
        """
        Install the Hex-Rays hooks used by the plugin core.
        """
        import ida_hexrays

        class CoreHxeHooks(ida_hexrays.Hexrays_Hooks):
            def populating_popup(_, *args):
                self._hxe_popuplating_popup(*args)
                return 0

        self._hxe_hooks = CoreHxeHooks()
        self._hxe_hooks.hook()

    def _remove_hexrays_hooks(self):
        """
        Remove the Hex-Rays hooks used by the plugin core.
        """
        self._hxe_hooks.unhook()
        self._hxe_hooks = None

    def _hxe_popuplating_popup(self, widget, popup, vdui):
        """
        Handle a Hex-Rays popup menu event.

        When the user right clicks within a decompiler window, we use this
        callback to insert the 'View microcode' menu entry into the ctx menu.
        """
        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            self.ACTION_VIEW_MICROCODE,
            None,
            ida_kernwin.SETMENU_APP
        )
    
    #--------------------------------------------------------------------------
    # Plugin Testing
    #--------------------------------------------------------------------------

    def test(self):
        """
        TODO/TESTING: move this to a dedicated module/file

        just some misc stuff for testing the plugin...
        """
        import time
        import idautils
        from lucid.util.hexrays import get_mmat_levels, get_mmat_name

        for address in list(idautils.Functions()):
         
            print("0x%08X: DECOMPILING" % address)
            self.explorer.select_function(address)
            self.explorer.view.refresh()

            # change the codeview to a starting maturity levels
            for src_maturity in get_mmat_levels():
                self.explorer.select_maturity(get_mmat_name(src_maturity))

                # select each line in the current 'starting' maturity context
                for idx, line in enumerate(self.explorer.model.mtext.lines):
                    self.explorer.select_position(idx, 0, 0)

                    # 
                    maturity_traversal = get_mmat_levels()
                    maturity_traversal = maturity_traversal[maturity_traversal.index(src_maturity)+1:] + get_mmat_levels()[::-1][1:]

                    # scroll up / down the maturity traversal
                    for dst_maturity in maturity_traversal:
                        #print("%-60s -- %s" % ("S_MAT: %s E_MAT: %s IDX: %u" % (get_mmat_name(src_maturity), get_mmat_name(dst_maturity), idx), line.text))
                        self.explorer.select_maturity(get_mmat_name(dst_maturity))
                        #ida_kernwin.refresh_idaview_anyway()
                        #time.sleep(0.05)

                    self.explorer.select_maturity(get_mmat_name(src_maturity))
    
