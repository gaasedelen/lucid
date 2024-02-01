import ctypes

import ida_ida
import ida_funcs
import ida_graph
import ida_idaapi
import ida_kernwin
import ida_hexrays

from PyQt5 import QtWidgets, QtGui, QtCore, sip

from lucid.ui.sync import MicroCursorHighlight
from lucid.ui.subtree import MicroSubtreeView
from lucid.util.python import register_callback, notify_callback, CallbackHandler
from lucid.util.hexrays import get_microcode, get_mmat, get_mmat_name, get_mmat_levels 
from lucid.util.options import OptionListener, OptionProvider
from lucid.microtext import MicrocodeOptions, MicrocodeText, MicroInstructionToken, MicroOperandToken, AddressToken, BlockNumberToken, translate_mtext_position, remap_mtext_position

#------------------------------------------------------------------------------
# Microcode Explorer
#------------------------------------------------------------------------------
#
#    The Microcode Explorer UI is mostly implemented following a standard
#    Model-View-Controller pattern. This is a little abnormal for Qt, but 
#    I've come to appreciate it more for its portability and testability.
#

class MicrocodeExplorer(object):
    """
    The controller component of the microcode explorer.

    The role of the controller is to handle user gestures, map user actions to
    model updates, and change views based on controls. In theory, the
    controller should be able to drive the 'view' headlessly or simulate user
    UI interaction.
    """
    
    def __init__(self):
        self.graph = None
        self.model = MicrocodeExplorerModel()
        self.view = MicrocodeExplorerView(self, self.model)
        self.view._code_sync.enable_sync(True) # XXX/HACK
    
    def unload(self):
        if self.graph:
            self.graph.Close()
            del self.graph
        
        self.view.unload()
        self.model.unload()
    
    def show(self, address=None):
        """
        Show the microcode explorer.
        """
        if address is None:
            address = ida_kernwin.get_screen_ea()
        self.select_function(address)
        self.view.show()

    def show_subtree(self, insn_token):
        """
        Show the sub-instruction graph for the given instruction token.
        """
        if self.graph:
            self.graph.show()
            return
        
        graph = MicroSubtreeView(insn_token.insn, self)
        graph.show()
        
        self.graph = graph
    
    def update_subtree(self):
        """
        Updates the sub-instruction graph if it is currently opened.
        """
        if self.graph:
            self.graph.update_insn()
    
    def free_subtree(self):
        """
        Frees references to the sub-instruction graph.
        """
        self.graph = None

    #-------------------------------------------------------------------------
    # View Toggles
    #-------------------------------------------------------------------------

    def set_highlight_mutual(self, status):
        """
        Toggle the highlighting of lines containing the same active address.
        """
        if status:
            self.view._code_sync.hook()
        else:
            self.view._code_sync.unhook()
        ida_kernwin.refresh_idaview_anyway()

    def set_option(self, name, value):
        """
        Sets the named microcode option with the given value.
        """
        if not isinstance(name, str):
            raise TypeError(name)
        MicrocodeOptions[name] = value
    
    #-------------------------------------------------------------------------
    # View Controls
    #-------------------------------------------------------------------------

    def select_function(self, address):
        """
        Switch the microcode view to the specified function.
        """
        func = ida_funcs.get_func(address)
        if not func:
            return False
        
        for maturity in get_mmat_levels():
            self.model.init_function(func, maturity)

        self.view.refresh()
        ida_kernwin.refresh_idaview_anyway()
        return True

    def select_maturity(self, maturity):
        """
        Switch the microcode view to the specified maturity level.
        """
        self.model.active_maturity = maturity

    def select_address(self, address):
        """
        Select a token in the microcode view matching the given address.
        """
        token = self.model.mtext.get_first_token_for_address(address)
        if not token:
            return None

        token_line_num, token_x = self.model.mtext.get_pos_of_token(token)
        rel_y = self.model.current_position[2]

        if rel_y == 0:
            rel_y = 30

        self.select_position(token_line_num, token_x, rel_y)
        
        return token

    def select_position(self, line_num, x, y):
        """
        Select the given text position in the microcode view.
        """
        self.model.current_position = (line_num, x, y)
        #print(" - hovered token: %s" % self.model.current_token.text)
        #print(" - hovered taddr: 0x%08X" % self.model.current_token.address)
        #print(" - hovered laddr: 0x%08X" % self.model.current_address)

    def activate_position(self, line_num, x, y):
        """
        Activate (eg. double click) the given text position in the microcode view.
        """
        token = self.model.mtext.get_token_at_position(line_num, x)
        if not token:
            return

        if isinstance(token, AddressToken):
            ida_kernwin.jumpto(token.target_address, -1, 0)
        else:
            blk_idx = None
            
            if isinstance(token, BlockNumberToken):
                blk_idx = token.blk_idx
            elif isinstance(token, MicroOperandToken) and token.mop.t == ida_hexrays.mop_b:
                blk_idx = token.mop.b
            
            if blk_idx is None:
                return
            
            blk_token = self.model.mtext.blks[blk_idx]
            blk_line_num, _ = self.model.mtext.get_pos_of_token(blk_token.lines[0])
            
            self.select_position(blk_line_num, 0, y)
    
    def regenerate_microtext(self):
        self.model.queue_rebuild(active_only=False)
        self.view.refresh()
    
    def synchronize_microtext(self, vdui: ida_hexrays.vdui_t):
        address = vdui.cfunc.entry_ea
        self.select_function(address)

class MicrocodeExplorerModel(object):
    """
    The model component of the microcode explorer.
    
    The role of the model is to encapsulate application state, respond to
    state queries, and notify views of changes. Ideally, the model could be
    serialized / unserialized to save and restore state.
    """

    def __init__(self):
        
        #
        # 'mtext' is short for MicrocodeText objects (see microtext.py)
        #
        # this dictionary will contain a mtext object (the renderable text
        # mapping of a given hexrays mba_t) for each microcode maturity level
        # of the current function. 
        #
        # at any given time, one mtext will be 'active' in the model, and
        # therefore visible in the UI/Views 
        #

        self._mtext = {x: None for x in get_mmat_levels()}

        # 
        # there is a 'cursor' (ViewCursor) for each microcode maturity level /
        # mtext object. cursors don't actually contain the 'position' in the
        # rendered text (line_num, x), but also information to position the
        # cursor within the line view (y)
        #

        self._view_cursors = {x: None for x in get_mmat_levels()}

        #
        # the currently active / selected maturity level of the model. this
        # determines which mtext is currently visible / active in the
        # microcode view, and which cursor will be used
        #

        self._active_maturity = ida_hexrays.MMAT_GENERATED
        
        self._rebuild_queue = {x: False for x in get_mmat_levels()}
        self._refresh_queue = {x: False for x in get_mmat_levels()}

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------
        
        self.mtext_changed = CallbackHandler(self, name="mtext changed")
        self.position_changed = CallbackHandler(self, name="position changed")
        self.maturity_changed = CallbackHandler(self, name="maturity changed")
    
    def unload(self):
        del self.maturity_changed
        del self.position_changed
        del self.mtext_changed
    
    #-------------------------------------------------------------------------
    # Read-Only Properties
    #-------------------------------------------------------------------------

    @property
    def mtext(self) -> MicrocodeText:
        """
        Return the microcode text mapping for the current maturity level.
        """
        return self._mtext[self._active_maturity]

    @mtext.setter
    def mtext(self, mtext):
        """
        Set the microcode text mapping for the current maturity level.
        """
        self._mtext[self._active_maturity] = mtext
        self.mtext_changed()

    @property
    def current_line(self):
        """
        Return the line token at the current viewport cursor position.
        """
        if not self.mtext:
            return None
        line_num, _, _ = self.current_position
        return self.mtext.lines[line_num] 

    @property
    def current_function(self):
        """
        Return the current function address.
        """
        if not self.mtext:
            return ida_idaapi.BADADDR
        return self.mtext.mba.entry_ea

    @property
    def current_token(self):
        """
        Return the token at the current viewport cursor position.
        """
        return self.mtext.get_token_at_position(*self.current_position[:2])
    
    @property
    def current_address(self):
        """
        Return the address at the current viewport cursor position.
        """
        return self.mtext.get_address_at_position(*self.current_position[:2])

    @property
    def current_cursor(self):
        """
        Return the current viewport cursor.
        """
        return self._view_cursors[self._active_maturity]

    #-------------------------------------------------------------------------
    # Mutable Properties
    #-------------------------------------------------------------------------

    @property
    def current_position(self):
        """
        Return the current viewport cursor position (line_num, view_x, view_y).
        """
        if not self.current_cursor:
            return (0, 0, 0) # lol
        
        return self.current_cursor.viewport_position

    @current_position.setter
    def current_position(self, value):
        """
        Set the cursor position of the viewport.
        """
        self._gen_cursors(value, self.active_maturity)
        self.position_changed()
    
    @property
    def active_maturity(self):
        """
        Return the active microcode maturity level.
        """
        return self._active_maturity
    
    @active_maturity.setter
    def active_maturity(self, new_maturity):
        """
        Set the active microcode maturity level.
        """
        old_maturity = self._active_maturity
        if new_maturity == old_maturity:
            return
        
        self._active_maturity = new_maturity
        self.maturity_changed(old_maturity)

    #----------------------------------------------------------------------
    # Misc
    #----------------------------------------------------------------------
    
    def queue_rebuild(self, active_only = False):
        if not active_only:
            # queue all maturities for a full rebuild
            # they will only be rebuilt once active
            for maturity in get_mmat_levels():
                self._rebuild_queue[maturity] = True
        else:
            # force the active maturity to be rebuilt
            self._rebuild_queue[self.active_maturity] = True
    
    def queue_refresh(self, active_only = False):
        if not active_only:
            # queue all maturities for a full rebuild
            # they will only be rebuilt once active
            for maturity in get_mmat_levels():
                self._refresh_queue[maturity] = True
        else:
            # force the active maturity to be rebuilt
            self._refresh_queue[self.active_maturity] = True
    
    def init_function(self, func, maturity):
        mtext = MicrocodeText.create(func, maturity)
        self.update_mtext(mtext, maturity)
    
    def update_mtext(self, mtext, maturity):
        """
        Set the mtext for a given microcode maturity level.
        """
        self._mtext[maturity] = mtext
        self._rebuild_queue[maturity] = True # needs to be generated
        self._view_cursors[maturity] = ViewCursor(0, 0, 0)
    
    def redraw_mtext(self, maturity):
        """
        Redraws the rendered text for the microcode maturity level.
        """
        if maturity != self.active_maturity:
            return False # XXX: Performance optimization.
        
        self._mtext[maturity].refresh()
        self._refresh_queue[maturity] = False
        
        return True
    
    def rebuild_mtext(self, maturity):
        """
        Regenerate the rendered text for the microcode maturity level.
        """
        if maturity != self.active_maturity:
            return False # XXX: Performance optimization.
        
        if maturity in self._rebuild_queue:
            # fully rebuild our active maturity
            self.mtext.reinit()
            self._rebuild_queue[maturity] = False
            self._refresh_queue[maturity] = False # no need to redraw since it was rebuilt
        else:
            # make a new copy of it and translate the active cursor
            # this will ensure a proper refresh of the microcode
            old_mtext = self.mtext
            new_mtext = old_mtext.copy()
            self.update_mtext(new_mtext, maturity)
            self.current_position = translate_mtext_position(self.current_position, old_mtext, new_mtext)
        
        return True
    
    def refresh_mtext(self, old_maturity = None):
        """
        Updates the rendered text for the microcode as needed.
        """
        for maturity, needs_rebuild in self._rebuild_queue.items():
            if not needs_rebuild:
                continue
            self.rebuild_mtext(maturity)
        for maturity, needs_redraw in self._refresh_queue.items():
            if not needs_redraw:
                continue
            self.redraw_mtext(maturity)
        
        if old_maturity is None:
            # we don't need to move the cursor since no other maturities are loaded
            return
        
        # transition from this maturity to the next one
        self._transfer_cursor(old_maturity, self.active_maturity)    
        
    def _gen_cursors(self, position, mmat_src):
        """
        Generate the cursors for all levels from a source position and maturity.
        """
        mmat_levels = []
        
        for maturity, mtext in self._mtext.items():
            if not mtext or mtext.is_pending():
                continue
            mmat_levels.append(maturity)
        
        if not mmat_levels:
            return
        
        mmat_first = mmat_levels[0]
        mmat_final = mmat_levels[-1]
        
        #print(f"**** MATURITY: first={mmat_first}, final={mmat_final}")
        #print(f" - levels: [{','.join([str(n) for n in mmat_levels])}]")
        
        # save the starting cursor
        line_num, x, y = position
        
        # clear out all the existing cursor mappings 
        self._view_cursors = {x: None for x in get_mmat_levels()}        
        self._view_cursors[mmat_src] = ViewCursor(line_num, x, y, True)
        
        # map the cursor backwards from the source maturity
        mmat_lower = [mmat for mmat in range(mmat_first, mmat_src) if mmat in mmat_levels][::-1]
        
        # map the cursor forward from the source maturity
        mmat_higher = [mmat for mmat in range(mmat_src+1, mmat_final+1) if mmat in mmat_levels]
        
        for mmat_range in (mmat_lower, mmat_higher):
            current_maturity = mmat_src
            for next_maturity in mmat_range:
                self._transfer_cursor(current_maturity, next_maturity)
                current_maturity = next_maturity

    def _transfer_cursor(self, mmat_src, mmat_dst):
        """
        Translate the cursor position from one maturity to the next.
        """
        if self._mtext[mmat_src].is_pending() or self._mtext[mmat_dst].is_pending():
            return
        
        position = self._view_cursors[mmat_src].viewport_position
        mapped = self._view_cursors[mmat_src].mapped

        # attempt to translate the position in one mtext to another
        projection = translate_mtext_position(position, self._mtext[mmat_src], self._mtext[mmat_dst])

        # if translation failed, we will generate an approximate cursor
        if not projection:
            mapped = False
            projection = remap_mtext_position(position, self._mtext[mmat_src], self._mtext[mmat_dst])

        # save the generated cursor
        line_num, x, y = projection
        self._view_cursors[mmat_dst] = ViewCursor(line_num, x, y, mapped)

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------


#-----------------------------------------------------------------------------
# UI Components
#-----------------------------------------------------------------------------

class MicrocodeExplorerView(OptionListener, QtWidgets.QWidget, providers = [ MicrocodeOptions ]):
    """
    The view component of the Microcode Explorer.
    """

    WINDOW_TITLE = "Microcode Explorer"

    def __init__(self, controller: MicrocodeExplorer, model: MicrocodeExplorerModel):
        super(MicrocodeExplorerView, self).__init__()
        self.visible = False

        # the backing model, and controller for this view (eg, mvc pattern)
        self.model = model
        self.controller = controller

        # initialize the plugin UI
        self._ui_init()
        self._ui_init_signals()
    
    def unload(self):
        ida_kernwin.close_widget(self._twidget, ida_kernwin.PluginForm.WCLS_DELETE_LATER)
        self._code_sync.unload()
        self._ui_hooks.unhook()
    
    def notify_change(self, option_name, option_value, **kwargs):
        """
        Implementation of OptionListener.notify_change for when a microcode option has been updated.
        """
        #print(f"**** notify_change {option_name} = {option_value} (IN OPTIONS={bool(option_name in MicrocodeOptions)})")
        self.model.queue_refresh()
        self.refresh()

    #--------------------------------------------------------------------------
    # Pseudo Widget Functions
    #--------------------------------------------------------------------------

    def show(self):
        self.refresh()

        # show the dockable widget
        flags = ida_kernwin.PluginForm.WOPN_DP_RIGHT | 0x200 # WOPN_SZHINT
        ida_kernwin.display_widget(self._twidget, flags)
        ida_kernwin.set_dock_pos(self.WINDOW_TITLE, "IDATopLevelDockArea", ida_kernwin.DP_RIGHT)

        self._code_sync.hook()

    def _cleanup(self):
        self.visible = False
        self._twidget = None
        self.widget = None
        self._code_sync.unhook()
        self._ui_hooks.unhook()
        # TODO cleanup controller / model

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self._ui_init_widget()

        # initialize our ui elements
        self._ui_init_list()
        self._ui_init_code()
        self._ui_init_settings()

        # layout the populated ui just before showing it
        self._ui_layout()

    def _ui_init_widget(self):
        """
        Initialize an IDA widget for this UI control.
        """

        # create a dockable widget, and save a reference to it for later use
        self._twidget = ida_kernwin.create_empty_widget(self.WINDOW_TITLE)

        # cast the IDA 'twidget' to a less opaque QWidget object
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)

        # hooks to help track the container/widget lifetime 
        class ExplorerUIHooks(ida_kernwin.UI_Hooks):
            def widget_invisible(_, twidget):
                if twidget == self._twidget:
                    self.visible = False
                    self._cleanup()
            def widget_visible(_, twidget):
                if twidget == self._twidget:
                    self.visible = True
            def postprocess_action(_, *args):
                # XXX: seemingly the only way to allow the explorer to navigate via keyboard events...
                # (maybe this should be hooked elsewhere?)
                if not self._code_view or not self._code_view.IsFocused():
                    return
                
                old_line = self.model.current_line
                new_line = self._code_view.GetLineNo()
            
                if new_line != old_line:
                    self.controller.select_position(*self._code_view.GetPos())

        # install the widget lifetime hooks 
        self._ui_hooks = ExplorerUIHooks()
        self._ui_hooks.hook()

    def _ui_init_list(self):
        """
        Initialize the microcode maturity list.
        """
        self._maturity_list = LayerListWidget()

    def _ui_init_code(self):
        """
        Initialize the microcode view(s).
        """
        self._code_view = MicrocodeView(self.model)
        self._code_sync = MicroCursorHighlight(self.controller, self.model)
        self._code_sync.track_view(self._code_view)

    def _ui_init_settings(self):
        """
        Initialize the explorer settings groupbox.
        """
        self._checkbox_cursor = QtWidgets.QCheckBox("Highlight mutual")
        self._checkbox_cursor.setCheckState(QtCore.Qt.Checked)
        self._checkbox_verbose = QtWidgets.QCheckBox("Show use/def")
        self._checkbox_sync = QtWidgets.QCheckBox("Sync hexrays")
        self._checkbox_sync.setCheckState(QtCore.Qt.Checked)
        self._checkbox_devmode = QtWidgets.QCheckBox("Developer mode")
        
        self._refresh_button = QtWidgets.QPushButton("Refresh view")
        self._refresh_button.setFixedSize(120, 60)
        
        self._groupbox_settings = QtWidgets.QGroupBox("Settings")
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self._checkbox_cursor)
        layout.addWidget(self._checkbox_verbose)
        layout.addWidget(self._checkbox_sync)
        layout.addWidget(self._checkbox_devmode)
        layout.addWidget(self._refresh_button)
        self._groupbox_settings.setLayout(layout)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QGridLayout()

        # arrange the widgets in a 'grid'         row  col  row span  col span
        layout.addWidget(self._code_view.widget,    0,   0,        0,        1)
        layout.addWidget(self._maturity_list,       0,   1,        1,        1)
        layout.addWidget(self._groupbox_settings,   1,   1,        1,        1)

        # apply the layout to the widget
        self.widget.setLayout(layout)
        
    def _ui_init_signals(self):
        """
        Connect UI signals.
        """
        
        def _maturity_changed(item):
            maturity = self._maturity_list.row(item) + 1
            self.controller.select_maturity(maturity)
        
        
        self._maturity_list.currentItemChanged.connect(_maturity_changed)
        self._code_view.connect_signals(self.controller)
        self._code_view.OnClose = self.hide # HACK
        
        self._refresh_button.clicked.connect(lambda: self.reinit())

        # checkboxes
        self._checkbox_cursor.stateChanged.connect(lambda x: self.controller.set_highlight_mutual(bool(x)))
        self._checkbox_verbose.stateChanged.connect(lambda x: self.controller.set_option('verbose', bool(x)))
        self._checkbox_sync.stateChanged.connect(lambda x: self._code_sync.enable_sync(bool(x)))
        self._checkbox_devmode.stateChanged.connect(lambda x: self.controller.set_option('developer_mode', bool(x)))

        # model signals
        self.model.mtext_changed += self.reinit
        self.model.maturity_changed += self.refresh
        
    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def reinit(self):
        """
        Fully reinitializes the microcode explorer UI based on the model state.
        """
        self.model.queue_rebuild(active_only=True)
        self.refresh()
    
    def refresh(self, old_maturity = None):
        """
        Refresh the microcode explorer UI based on the model state.
        """
        self.model.refresh_mtext(old_maturity=old_maturity)
        self._code_view.refresh()
        self.controller.update_subtree()

class LayerListWidget(QtWidgets.QListWidget):
    """
    The microcode maturity list widget
    """

    def __init__(self):
        super(LayerListWidget, self).__init__()

        # populate the list widget with the microcode maturity levels
        self.addItems([get_mmat_name(x) for x in get_mmat_levels()])

        # select the first maturity level, by default
        self.setCurrentRow(0)

        # make the list widget a fixed size, slightly wider than it needs to be
        width = self.sizeHintForColumn(0)
        self.setMaximumWidth(int(width + width * 0.10))

    def wheelEvent(self, event):
        """
        Handle mouse wheel scroll events.
        """
        y = event.angleDelta().y()

        # scrolling down, clamp to last row
        if y < 0:
            next_row = min(self.currentRow()+1, self.count()-1)

        # scrolling up, clamp to first row (0)
        elif y > 0:
            next_row = max(self.currentRow()-1, 0)
        
        # horizontal scroll ? nothing to do..
        else:
            return

        self.setCurrentRow(next_row)

class MicrocodeView(ida_kernwin.simplecustviewer_t):
    """
    An IDA-based text area that will render the Hex-Rays microcode.

    TODO: I'll probably rip this out in the future, as I'll have finer
    control over the interaction / implementation if I just roll my own
    microcode text widget.

    For that reason, excuse its hacky-ness / lack of comments.
    """

    def __init__(self, model):
        super(MicrocodeView, self).__init__()
        self.model = model
        self.new_line = None
        self.Create()

    def connect_signals(self, controller):
        self.controller = controller
        self.OnCursorPosChanged = lambda: controller.select_position(*self.GetPos())
        self.OnDblClick = lambda _: controller.activate_position(*self.GetPos())
        
        self.model.position_changed += self.refresh_cursor
        self.model.position_changed += self.controller.update_subtree

    def refresh(self):
        self.ClearLines()
        for line in self.model.mtext.lines:
            self.AddLine(line.tagged_text)
        self.refresh_cursor()

    def refresh_cursor(self):
        if not self.model.current_cursor or not self.model.current_position:
            return
        self.Jump(*self.model.current_position)

    def Create(self):
        if not super(MicrocodeView, self).Create(None):
            return False
        self._twidget = self.GetWidget()
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)
        return True

    def OnClose(self):
        pass

    def OnCursorPosChanged(self):
        pass

    def OnDblClick(self, shift):
        pass
    
    def OnPopup(self, form, popup_handle):
        controller = self.controller

        #
        # so, i'm pretty picky about my UI / interactions. IDA puts items in
        # the right click context menus of custom (code) viewers.
        #
        # these items aren't really relevant (imo) to the microcode viewer,
        # so I do some dirty stuff here to filter them out and ensure only
        # my items will appear in the context menu.
        #
        # there's only one right click context item right now, but in the
        # future i'm sure there will be more.
        #

        class FilterMenu(QtCore.QObject):
            def __init__(self, qmenu):
                super(QtCore.QObject, self).__init__()
                self.qmenu = qmenu
        
            def eventFilter(self, obj, event):
                if event.type() != QtCore.QEvent.Polish:
                    return False
                for action in self.qmenu.actions():
                    if action.text() in ["&Font...", "&Synchronize with"]: # lol..
                        qmenu.removeAction(action)
                self.qmenu.removeEventFilter(self)
                self.qmenu = None
                return True

        p_qmenu = ctypes.cast(int(popup_handle), ctypes.POINTER(ctypes.c_void_p))[0]
        qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)
        self.filter = FilterMenu(qmenu)
        qmenu.installEventFilter(self.filter)

        # only handle right clicks on lines containing micro instructions
        ins_token = self.model.mtext.get_ins_for_line(self.model.current_line)
        if not ins_token:
            return False

        class MyHandler(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                controller.show_subtree(ins_token)
            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_ALWAYS

        # inject the 'View subtree' action into the right click context menu
        desc = ida_kernwin.action_desc_t(None, 'View subtree', MyHandler())
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc, None)
        
        return True

#-----------------------------------------------------------------------------
# Util
#-----------------------------------------------------------------------------

class ViewCursor(object):
    """
    TODO
    """
    def __init__(self, line_num, x, y, mapped=True):
        self.line_num = line_num
        self.x = x
        self.y = y
        self.mapped = mapped

    @property 
    def text_position(self):
        return (self.line_num, self.x)

    @property
    def viewport_position(self):
        return (self.line_num, self.x, self.y)
