import ida_graph
import ida_moves
import ida_hexrays
import ida_hexrays as hr
import ida_kernwin

from PyQt5 import QtWidgets, QtCore

from lucid.util.hexrays import get_mcode_name, get_mopt_name
from lucid.microtext import MicrocodeOptions

class MOPHelper:
    
    MOP_RESOLVERS = {
        hr.mnumber_t: lambda mnum: mnum.value,
        hr.minsn_t: lambda minsn: minsn.dstr(),
        hr.stkvar_ref_t: lambda stkvar: stkvar.off,
        hr.mcallinfo_t: lambda mcall: mcall.dstr(),
        hr.lvar_ref_t: lambda lvar: f"{lvar.off}:{lvar.idx}",
        hr.mop_addr_t: lambda maddr: f"({maddr.insize},{maddr.outsize})",
        hr.fnumber_t: lambda fnum: f"{fnum.fnum}({fnum.nbytes})",
        hr.scif_t: lambda scif: scif.name,
    }
    
    MOP_TYPES = {
        hr.mop_z:   None,
        hr.mop_r:   int,
        hr.mop_n:   hr.mnumber_t,
        hr.mop_d:   hr.minsn_t,
        hr.mop_S:   hr.stkvar_ref_t,
        hr.mop_v:   int,
        hr.mop_b:   int,
        hr.mop_f:   hr.mcallinfo_t,
        hr.mop_l:   hr.lvar_ref_t,
        hr.mop_a:   hr.mop_addr_t,
        hr.mop_h:   str,
        hr.mop_str: str,
        hr.mop_c:   hr.mcases_t,
        hr.mop_fn:  hr.fnumber_t,
        hr.mop_p:   hr.mop_pair_t,
        hr.mop_sc:  hr.scif_t,
    }
    
    MOP_FIELDS = {
        hr.mop_z:   None,
        hr.mop_r:   'r',        # register number [mreg_t]
        hr.mop_n:   'nnn',      # immediate value [mnumber_t]
        hr.mop_d:   'd',        # result (destination) of another instruction [minsn_t]
        hr.mop_S:   's',        # stack variable [stkvar_ref_t]
        hr.mop_v:   'g',        # global variable (its linear address) [ea_t]
        hr.mop_b:   'b',        # block number (used in jmp,call instructions) [int]
        hr.mop_f:   'f',        # function call information [mcallinfo_t]
        hr.mop_l:   'l',        # local variable [lvar_ref_t]
        hr.mop_a:   'a',        # variable whose address is taken [mop_addr_t]
        hr.mop_h:   'helper',   # helper function name [string]
        hr.mop_str: 'cstr',     # utf8 string constant, user representation [string]
        hr.mop_c:   'c',        # cases [mcases_t]
        hr.mop_fn:  'fpc',      # floating point constant [fnumber_t]
        hr.mop_p:   'pair',     # operand pair [mop_pair_t]
        hr.mop_sc:  'scif',     # scattered operand info [scif_t]
    }
    
    @classmethod
    def valid_for(cls, mop, value):
        type = cls.MOP_TYPES[mop.t]
        return isinstance(value, type)
    
    @classmethod
    def get_value(cls, mop):
        attr = cls.MOP_FIELDS[mop.t]
        if attr:
            return getattr(mop, attr)
        return None
    
    @classmethod
    def to_string(cls, mop):
        if mop.t == hr.mop_p:
            return f"mop_pair<{cls.to_string(mop.pair.lop)},{cls.to_string(mop.pair.hop)}>"
        elif mop.t == hr.mop_r:
            return f"reg<{mop.r}({hr.get_mreg_name(mop.r, mop.size)}.{mop.size})>"
        
        value = cls.get_value(mop)
        
        if value == None:
            return "<nil>"
        
        val_type = type(value)
        if val_type in cls.MOP_RESOLVERS:
            resolver = cls.MOP_RESOLVERS[val_type]
            value = resolver(value)
        
        return str(value)

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

    def __init__(self, insn, controller):
        super(MicroSubtreeView, self,).__init__(self.WINDOW_TITLE, True)
        self.insn = insn
        self.next_insn = None
        self.controller = controller
        self._populated = False
        
        # XXX: these will cause crashes if placed here!
        #self.controller.model.position_changed += self.update_insn
        #self.controller.model.maturity_changed += self.update_insn
        
    def update_insn(self):
        insn_token = self.controller.model.mtext.get_ins_for_line(self.controller.model.current_line)
        if insn_token is None or insn_token.insn == self.insn:
            return
        
        self.next_insn = insn_token.insn
        
        gv = ida_graph.get_graph_viewer(self.GetWidget())
        
        self.Refresh()
        self._center_graph()
        
        ida_graph.viewer_fit_window(gv)

    def show(self):
        self.Show()
        ida_kernwin.set_dock_pos(self.WINDOW_TITLE, self.controller.view.WINDOW_TITLE, ida_kernwin.DP_BOTTOM)

        gv = ida_graph.get_graph_viewer(self.GetWidget())
        ida_graph.viewer_set_titlebar_height(gv, 15)

        self.Refresh()
        self._center_graph()
        
        # XXX: absolute hackery fuckery, but it works!
        ida_graph.viewer_fit_window(gv)
    
    def _center_graph(self, fit_window = False):
        """
        Center the sub-tree graph, and set an appropriate zoom level.
        """
        widget = self.GetWidget()
        gv = ida_graph.get_graph_viewer(widget)
        g = ida_graph.get_viewer_graph(gv)

        #ida_graph.viewer_fit_window(gv)
        #ida_graph.refresh_viewer(gv)

        gli = ida_moves.graph_location_info_t()
        ida_graph.viewer_get_gli(gli, gv, ida_graph.GLICTL_CENTER) 
        if gli.zoom > 1.5:
            gli.zoom = 1.5
        else:
            gli.zoom = round(gli.zoom * 0.9, 1)

        ida_graph.viewer_set_gli(gv, gli, ida_graph.GLICTL_CENTER)
        
        if fit_window:
            ida_graph.viewer_fit_window(gv)
        #ida_graph.refresh_viewer(gv)

    def _get_mop_oprops(self, mop):
        text = ""
        for oprop, name in [(getattr(ida_hexrays, x), x) for x in filter(lambda y: y.startswith('OPROP_'), dir(ida_hexrays))]:
            if mop.oprops & oprop:
                text += f" +{name[6:]}"
        return text          
    def _insert_mop(self, mop, parent):
        if mop.t == 0:
            return -1

        text = " " + get_mopt_name(mop.t)
        
        #if mop.is_insn():
        #    text += " (%s)" % get_mcode_name(mop.d.opcode)
        
        if MicrocodeOptions.developer_mode:
            text += f" := {MOPHelper.to_string(mop)}"
            oprops = self._get_mop_oprops(mop)
            if oprops:
                text += ' \n' + self._get_mop_oprops(mop)
        
        if mop.is_insn():
            text += ' \n ' + mop.d._print() + " "
        else:
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

    def OnClose(self):
        self.controller.free_subtree()

    def OnViewKeydown(self, key, state):
        c = chr(key & 0xFF)

        if c == 'C':
            self._center_graph(fit_window=True)
        
        return True

    def OnRefresh(self):
        if self.next_insn:
            self.insn = self.next_insn
            self.next_insn = None
            self._populated = False
        
        if self._populated:
            return False

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
        return (self[node_id], self._node_color)