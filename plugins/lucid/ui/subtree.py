import ida_graph
import ida_moves
import ida_hexrays
import ida_kernwin

from PyQt5 import QtWidgets, QtCore

from lucid.util.hexrays import get_mcode_name, get_mopt_name

#------------------------------------------------------------------------------
# Microinstruction Sub-trees
#------------------------------------------------------------------------------
#
#    The Hex-Rays microcode can nest microinstructions into trees of sub-
#    instructions and sub-operands. Because of this, it can be useful to
#    unfold these trees visualize their components.
#
#    This is particularly important when developing microcode plugins
#    to generalize expressions or identify graph / microcode patterns.
#
#    For the time being, this file only serves as a crude viewer of a given
#    microinstruction subtree. But in the future, hopefully it can be
#    developed further towards an interactive graph / microcode pattern_t rule
#    editor through the generalization of a given graph.
#
#    Please note, this is roughly based off code from genmc.py @
#     - https://github.com/patois/genmc/blob/master/genmc.py
#
#    TODO: This file is REALLY hacky/dirty at the moment, but I'll try to
#    clean it up when motivation and time permits.....
#

class MicroSubtreeView(ida_graph.GraphViewer):
    """
    Render the subtree of an instruction.
    """
    WINDOW_TITLE = "Sub-instruction Graph"

    def __init__(self, insn):
        super(MicroSubtreeView, self).__init__(self.WINDOW_TITLE, True)
        self.insn = insn
        self._populated = False

    def show(self):
        self.Show()
        ida_kernwin.set_dock_pos(self.WINDOW_TITLE, "Microcode Explorer", ida_kernwin.DP_INSIDE)

        # XXX: bit of a hack for now... lool
        QtCore.QTimer.singleShot(50, self._center_graph)

    def _center_graph(self):
        """
        Center the sub-tree graph, and set an appropriate zoom level.
        """
        widget = self.GetWidget()
        gv = ida_graph.get_graph_viewer(widget)
        g = ida_graph.get_viewer_graph(gv)

        ida_graph.viewer_fit_window(gv)
        ida_graph.refresh_viewer(gv)

        gli = ida_moves.graph_location_info_t()
        ida_graph.viewer_get_gli(gli, gv, ida_graph.GLICTL_CENTER) 
        if gli.zoom > 1.5:
            gli.zoom = 1.5
        else:
            gli.zoom = gli.zoom * 0.9

        ida_graph.viewer_set_gli(gv, gli, ida_graph.GLICTL_CENTER)
        #ida_graph.refresh_viewer(gv)

    def _insert_mop(self, mop, parent):
        if mop.t == 0:
            return -1

        text = " " + get_mopt_name(mop.t)
        if mop.is_insn():
            text += " (%s)" % get_mcode_name(mop.d.opcode)
        text += ' \n ' + mop._print() + " "
        node_id = self.AddNode(text)
        self.AddEdge(parent, node_id)

        # result of another instruction
        if mop.t == ida_hexrays.mop_d: 
            insn = mop.d
            self._insert_mop(insn.l, node_id)
            self._insert_mop(insn.r, node_id)
            self._insert_mop(insn.d, node_id)

        # list of arguments
        elif mop.t == ida_hexrays.mop_f: 
            for arg in mop.f.args:
                self._insert_mop(arg, node_id)

        # mop_addr_t: address of operand
        elif mop.t == ida_hexrays.mop_a: 
            self._insert_mop(mop.a, node_id)

        # operand pair
        elif mop.t == ida_hexrays.mop_p: 
            self._insert_mop(mop.pair.lop, node_id)
            self._insert_mop(mop.pair.hop, node_id)

        return node_id

    def _insert_insn(self, insn):
        if not insn:
            return None
        text = " %s \n %s " % (get_mcode_name(insn.opcode), insn._print())
        node_id = self.AddNode(text)
        self._insert_mop(insn.l, node_id)
        self._insert_mop(insn.r, node_id)
        self._insert_mop(insn.d, node_id)
        return node_id

    def OnRefresh(self):
        if self._populated:
            return

        self.Clear()
        twidget = self.GetWidget()
        if not twidget:
            return False

        widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(twidget)
        bg_color = widget.property("line_bg_default") # disassembler bg color
        self._node_color = bg_color.blue() << 16 | bg_color.green() << 8 | bg_color.red()
        node_id = self._insert_insn(self.insn)
        self._populated = True
        return True

    def OnGetText(self, node_id):
        return (self._nodes[node_id], self._node_color)