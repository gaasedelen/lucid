import ida_hexrays
import ida_kernwin
from PyQt5 import QtWidgets

from lucid.util.hexrays import get_all_vdui, map_line2citem, map_line2ea

#------------------------------------------------------------------------------
# Microcode Cursor Syncing
#------------------------------------------------------------------------------
#
#    TODO: This file is super messy/hacky and needs to be cleaned up.
#
#    the TL;DR is that this file is responsible for 'syncing' the cursor
#    between our Microcode Explorer <--> Hex-Rays and highlighting the 
#    relevant lines in each view.
#
#    IDA provides mechanisms for syncing 'views', but none of that
#    infrastructure is really usable from idapython. for that reason,
#    we kind of implement our own which is probably for the best anyway.
#

class MicroCursorHighlight(object):

    class HxeHooks(ida_hexrays.Hexrays_Hooks):
        def curpos(self, vdui):
            pass
        def refresh_pseudocode(self, vdui):
            pass
        def close_pseudocode(self, vdui):
            pass

    class UIHooks(ida_kernwin.UI_Hooks):
        def get_lines_rendering_info(self, lines_out, widget, lines_in):
            pass

    def __init__(self, controller, model):
        self.model = model
        self.controller = controller

        self._item_maps = {}
        self._address_maps = {}
        self._hexrays_addresses = []
        self._hexrays_origin = False
        self._sync_status = False
        self._last_vdui = None
        self._code_widget = None
        self._ignore_move = False
     
        # create hooks
        self._hxe_hooks = self.HxeHooks() 
        self._ui_hooks = self.UIHooks()
     
        # link signals to this master class to help keep things uniform
        self._hxe_hooks.curpos = self.hxe_curpos
        self._hxe_hooks.refresh_pseudocode = self.hxe_refresh_pseudocode
        self._hxe_hooks.close_pseudocode = self.hxe_close_pseudocode
        self._ui_hooks.get_lines_rendering_info = self.render_lines
        self.model.position_changed(self.refresh_hexrays_cursor)

    def hook(self):
        self._ui_hooks.hook()

    def unhook(self):
        self._ui_hooks.unhook()
        self.enable_sync(False)

    def track_view(self, widget):
        self._code_widget = widget # TODO / temp

    def enable_sync(self, status):

        # nothing to do
        if status == self._sync_status:
            return

        # update sync status to enabled / disabled
        self._sync_status = status

        # syncing enabled
        if status:
            self._hxe_hooks.hook()
            self._cache_active_vdui()
            if self._last_vdui and (self.model.current_function != self._last_vdui.cfunc.entry_ea):
                self._sync_microtext(self._last_vdui)

        # syncing disabled
        else:
            self._hxe_hooks.unhook()
            self._hexrays_origin = False
            self._item_maps = {}
            self._address_maps = {}
            self._last_vdui = None

        self.refresh_hexrays_cursor()

    def refresh_hexrays_cursor(self):
        self._hexrays_origin = False
        self._hexrays_addresses = []

        if not (self._sync_status and self._last_vdui):
            ida_kernwin.refresh_idaview_anyway() # TODO should this be here?
            return

        if not self.model.current_line or self.model.current_line.type: # special line
            ida_kernwin.refresh_idaview_anyway() # TODO should this be here?
            return 

        vdui = self._last_vdui

        addr_map = self._get_vdui_address_map(vdui)
        current_address = self.model.current_address

        for line_num, addresses in addr_map.items():
            if current_address in addresses:
                break
        else:
            self._hexrays_addresses = []
            ida_kernwin.refresh_idaview_anyway() # TODO should this be here?
            return

        place, x, y = ida_kernwin.get_custom_viewer_place(self._last_vdui.ct, False)
        splace = ida_kernwin.place_t_as_simpleline_place_t(place)
        splace.n = line_num

        self._ignore_move = True
        ida_kernwin.jumpto(self._last_vdui.ct, splace, x, y)
        self._ignore_move = False

        self._hexrays_addresses = addr_map[line_num]
        ida_kernwin.refresh_idaview_anyway() # TODO should this be here?

    #--------------------------------------------------------------------------
    # Signals
    #--------------------------------------------------------------------------

    def hxe_close_pseudocode(self, vdui):
        """
        (Event) A Hex-Rays pseudocode window was closed.
        """
        if self._last_vdui == vdui:
            self._last_vdui = None
        self._item_maps.pop(vdui, None)
        self._address_maps.pop(vdui, None)
        return 0

    def hxe_refresh_pseudocode(self, vdui):
        """
        (Event) A Hex-Rays pseudocode window was refreshed/changed.
        """
        if self.model.current_function != vdui.cfunc.entry_ea:
            self._sync_microtext(vdui)
        return 0

    def hxe_curpos(self, vdui):
        """
        (Event) The user cursor position changed in a Hex-Rays pseudocode window.
        """
        self._hexrays_origin = False
        self._hexrays_addresses = self._get_active_vdui_addresses(vdui)

        if self.model.current_function != vdui.cfunc.entry_ea:
            self._sync_microtext(vdui)

        if self._ignore_move:
            # TODO put a refresh here ?
            return 0
        self._hexrays_origin = True
        if not self._hexrays_addresses:
            ida_kernwin.refresh_idaview_anyway()
            return 0
        self.controller.select_address(self._hexrays_addresses[0])
        return 0

    def render_lines(self, lines_out, widget, lines_in):
        """
        (Event) IDA is about to render code viewer lines.
        """
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE and self._sync_status:
            self._highlight_hexrays(lines_out, widget, lines_in)
        elif widget == self._code_widget:
            self._highlight_microcode(lines_out, widget, lines_in)
        return

    #--------------------------------------------------------------------------
    # Vdui Helpers
    #--------------------------------------------------------------------------

    def _cache_active_vdui(self):
        """
        Enumerate and cache all the open Hex-Rays pseudocode windows (vdui).
        """
        vdui_map = get_all_vdui()

        for name, vdui in vdui_map.items():
            widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(vdui.ct)
            if widget.isVisible():
                break
        else:
            return

        self._cache_vdui_maps(vdui)
        self._last_vdui = vdui

    def _cache_vdui_maps(self, vdui):
        """
        Generate and cache the citem & address line maps for the given vdui.
        """
        item_map = map_line2citem(vdui.cfunc.get_pseudocode())
        self._item_maps[vdui] = item_map
        address_map = map_line2ea(vdui.cfunc, item_map)
        self._address_maps[vdui] = address_map
        return (address_map, item_map)

    def _get_active_vdui_addresses(self, vdui):
        """
        Return the active addresses (current line) from the given vdui.
        """
        address_map = self._get_vdui_address_map(vdui)
        return address_map[vdui.cpos.lnnum]

    def _get_vdui_address_map(self, vdui):
        """
        Return the vdui line_num --> [ea1, ea2, ... ] address map.
        """
        address_map = self._address_maps.get(vdui, None)
        if not address_map:
            address_map, _ = self._cache_vdui_maps(vdui)
        self._last_vdui = vdui
        return address_map
    
    def _get_vdui_item_map(self, vdui):
        """
        Return the vdui line_num --> [citem_id1, citem_id2, ... ] citem map.
        """
        item_map = self._item_maps.get(vdui, None)
        if not item_map:
            item_map, _ = self._cache_vdui_maps(vdui)
        self._last_vdui = vdui
        return item_map
    
    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def _highlight_lines(self, lines_out, to_paint, lines_in):
        """
        Highlight the IDA viewer line numbers specified in to_paint.
        """
        assert len(lines_in.sections_lines) == 1, "Simpleviews should only have one section!?"
        color = ida_kernwin.CK_EXTRA1 if self.model.current_cursor.mapped else 0x400000FF
        for line in lines_in.sections_lines[0]:
            splace = ida_kernwin.place_t_as_simpleline_place_t(line.at)
            if splace.n in to_paint:
                entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
                lines_out.entries.push_back(entry)
                to_paint.remove(splace.n)
            if not to_paint:
                break

    def _highlight_hexrays(self, lines_out, widget, lines_in):
        """
        Highlight lines in the given Hex-Rays window according to the synchronized addresses.
        """
        vdui = ida_hexrays.get_widget_vdui(widget)
        if self._hexrays_addresses or self._hexrays_origin:
            self._highlight_lines(lines_out, set([vdui.cpos.lnnum]), lines_in)

    def _highlight_microcode(self, lines_out, widget, lines_in):
        """
        Highlight lines in the given microcode window according to the synchronized addresses.
        """
        if not self.model.mtext.lines:
            return
        
        to_paint = set()

        #
        # hexrays syncing is enabled, use the addresses from the current
        # line to highlight all the microcode lines that contain any of 
        # these 'target addresses'
        #

        if self._hexrays_origin or self._hexrays_addresses:
            target_addresses = self._hexrays_addresses
        
        # if not syncing with hexrays...
        else:

            # special case, only highlight the currently selected microcode line (a special line / block header)
            if self.model.current_line.type:
                to_paint.add(self.model.current_position[0])
                target_addresses = []

            # 'default' case, target all lines containing the address under the cursor
            else:
                target_addresses = [self.model.current_address]

        #
        # enumerate all the lines containing a target address, and mark it
        # for painting (save line idx to to_paint)
        #

        for address in target_addresses:
            for line_num in self.model.mtext.get_line_nums_for_address(address):

                # ignore special lines (eg, block header lines)
                if self.model.mtext.lines[line_num].type:
                    continue

                to_paint.add(line_num)

        self._highlight_lines(lines_out, to_paint, lines_in)

    def _sync_microtext(self, vdui):
        """
        TODO: this probably should just be a func in the controller
        """
        self.controller.select_function(vdui.cfunc.entry_ea)
        self.controller.view.refresh()