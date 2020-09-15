import ida_lines
import ida_idaapi
import ida_hexrays

from lucid.text import TextCell, TextToken, TextLine, TextBlock
from lucid.util.ida import tag_text
from lucid.util.hexrays import get_mmat_name

#-----------------------------------------------------------------------------
# Microtext
#-----------------------------------------------------------------------------
#
#    This file contains the microcode specific text (token) classes. Each
#    text class defined in this file roughly equates to a microcode
#    structure / class found in hexrays.hpp (the microcode SDK).
#
#    The purpose of these microcode text classes is to 'wrap' the underlying
#    microcode structures, and print/render them as human readable text. More
#    importantly, these text structures provide a number of API's to map
#    the rendered text back to the underlying microcode objects.
#
#    This text --> microcode object mapping is necessary for building an
#    interactive text interface that allows one to explore or manipulate
#    the microcode. For more information about the Text* classes, see text.py
#

#-----------------------------------------------------------------------------
# Annotation Tokens
#-----------------------------------------------------------------------------
#
#    These 'annotation' tokens aren't wrappers around real microcode
#    structures, but provide auxillary information / interactive elements
#    to the rendered microcode text.
#

# TODO: ehh this should probably get refactored out
MAGIC_BLK_INFO = 0x1230
MAGIC_BLK_EDGE = 0x1231
MAGIC_BLK_UDNR = 0x1232
MAGIC_BLK_USE  = 0x1233
MAGIC_BLK_DEF  = 0x1234
MAGIC_BLK_DNU  = 0x1235
MAGIC_BLK_VAL  = 0x1236
MAGIC_BLK_TERM = 0x1237

class BlockHeaderLine(TextLine):
    """
    A line container for mblock_t comment/annotation tokens.
    """

    def __init__(self, items, line_type, parent=None):
        super(BlockHeaderLine, self).__init__([TextCell("; ")] + items, line_type, parent)

    @property
    def tagged_text(self):
        return tag_text(super(BlockHeaderLine, self).tagged_text, ida_lines.COLOR_RPTCMT)

class LinePrefixToken(TextCell):
    """
    A token to display the relative position of a minsn_t within an mblock_t.
    """

    def __init__(self, blk_idx, insn_idx, parent=None):
        prefix_text = "%d.%2d " % (blk_idx, insn_idx)
        tagged_text = tag_text(prefix_text, ida_lines.COLOR_PREFIX)
        super(LinePrefixToken, self).__init__(tagged_text, parent=parent)

class BlockNumberToken(TextCell):
    """
    An interactive token for mblock_t serial (blk_idx) references.
    """
    
    def __init__(self, blk_idx, parent=None):
        tagged_text = tag_text(blk_idx, ida_lines.COLOR_MACRO)
        super(BlockNumberToken, self).__init__(tagged_text, parent=parent)
        self.blk_idx = blk_idx

class AddressToken(TextCell):
    """
    An interactive token for data/code-based text addresses.
    """
    
    def __init__(self, address, prefix=False, parent=None):
        address_text = "0x%08X" % address if prefix else "%08X" % address
        super(AddressToken, self).__init__(address_text, parent=parent)
        self.target_address = address

#------------------------------------------------------------------------------
# Microcode Operands (mop_t)
#------------------------------------------------------------------------------

class MicroOperandToken(TextToken):
    """
    High level text wrapper of a micro-operand (mop_t).
    """

    def __init__(self, mop, items=None, parent=None):
        super(MicroOperandToken, self).__init__(mop._print(), items, parent)
        self.mop = mop
        self._generate_from_op()
        self._generate_token_ranges()

    def _generate_from_op(self):
        """
        Populate this object from a mop_t.
        """
        mop = self.mop
        
        # nested instruction
        if mop.is_insn(): 
            self._create_subop(mop.d.l)
            self._create_subop(mop.d.r)
            self._create_subop(mop.d.d)
            self.address = mop.d.ea
 
        # call args
        elif mop.is_arglist():
            for arg in mop.f.args:
                subop = self._create_subop(arg)
                if arg.ea == ida_idaapi.BADADDR:
                    continue
                if subop.address != ida_idaapi.BADADDR:
                    continue
                #assert (subop.address == ida_idaapi.BADADDR or subop.address == arg.ea), "sub: 0x%08X arg: 0x%08X" % (subop.address, arg.ea)
                subop.address = arg.ea

        # address of op
        elif mop.t == ida_hexrays.mop_a: 
            self._create_subop(mop.a)

        # op pair
        elif mop.t == ida_hexrays.mop_p:
            self._create_subop(mop.pair.lop)
            self._create_subop(mop.pair.hop)

        # numbers
        elif mop.is_constant():
            self.address = mop.nnn.ea

    def _create_subop(self, mop):
        """
        Create a child op, from the given op.
        """
        if mop.empty():
            return None

        subop = MicroOperandToken(mop, parent=self)
        self.items.append(subop)

        return subop

#------------------------------------------------------------------------------
# Microcode Instructions (minsn_t)
#------------------------------------------------------------------------------

class MicroInstructionToken(TextToken):
    """
    High level text wrapper of a micro-instruction (minsn_t).
    """
    FLAGS = ida_hexrays.SHINS_VALNUM | ida_hexrays.SHINS_SHORT

    def __init__(self, insn, index, parent_token):
        super(MicroInstructionToken, self).__init__(insn._print(self.FLAGS), parent=parent_token)
        self.index = index
        self.insn = insn
        self._generate_from_insn()
        self._generate_token_ranges()

    def _generate_from_insn(self):
        """
        Populate this object from a minsn_t.
        """
        insn = self.insn

        # generate tree of ops / sub-ops and save them
        for mop in [insn.l, insn.r, insn.d]:
            self._create_subop(mop)

        # save a ref of the minsn_t for later use
        self.address = insn.ea

    def _create_subop(self, mop):
        """
        Create a child op, from the given op.
        
        TODO: ripped from the op class... w/e
        """
        if mop.empty():
            return None

        subop = MicroOperandToken(mop, parent=self)
        self.items.append(subop)

        return subop

class InstructionCommentToken(TextToken):
    """
    A container token for micro-instruction comment text.
    """
    
    def __init__(self, blk, insn, usedef=False):
        super(InstructionCommentToken, self).__init__()
        self._generate_from_ins(blk, insn, usedef)
        self._generate_token_ranges()

    def _generate_from_ins(self, blk, insn, usedef):
        """
        Populate this object from a given minsn_t.
        """
        items = [TextCell("; ")]

        # append the instruction address
        items.append(AddressToken(insn.ea))

        # append the use/def list
        if usedef:
            use_def_tokens = self._generate_use_def(blk, insn)
            items.extend(use_def_tokens)

        # (re-)parent orphan tokens to this line
        for item in items:
            if not item.parent:
                item.parent = self

        # all done
        self.items = items

    def _generate_use_def(self, blk, insn):
        """
        Generate use/def strings for this micro-instruction comment.
        """
        items = []

        # use list
        must_use = blk.build_use_list(insn, ida_hexrays.MUST_ACCESS)
        may_use = blk.build_use_list(insn, ida_hexrays.MAY_ACCESS)

        use_str = generate_mlist_str(must_use, may_use)
        items.append(TextCell(" u=%-13s" % use_str))

        # def list
        must_def = blk.build_def_list(insn, ida_hexrays.MUST_ACCESS)
        may_def = blk.build_def_list(insn, ida_hexrays.MAY_ACCESS)
        def_str = generate_mlist_str(must_def, may_def)
        items.append(TextCell(" d=%-13s" % def_str))

        return items

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def text(self):
        return ''.join([item.text for item in self.items])

    @property
    def tagged_text(self):
        return tag_text(''.join([item.tagged_text for item in self.items]), ida_lines.COLOR_AUTOCMT)

#------------------------------------------------------------------------------
# Microcode Block (mblock_t)
#------------------------------------------------------------------------------

class MicroBlockText(TextBlock):
    """
    High level text wrapper of a micro-block (mblock_t).
    """
    
    def __init__(self, blk, verbose=False):
        super(MicroBlockText, self).__init__()
        self.instructions = []
        self.verbose = verbose
        self.blk = blk
        self.refresh()

    def refresh(self, verbose=None):
        """
        Regenerate the micro-block text.
        """
        if verbose is not None:
            self.verbose = verbose
        self._generate_from_blk()
        self._generate_lines()
        self._generate_token_address_map()

    def _generate_from_blk(self):
        """
        Populate this object from a mblock_t.
        """
        insn, insn_idx = self.blk.head, 0
        instructions = []

        # loop through all the instructions in this micro-block
        while insn and insn != self.blk.tail:

            # generate a token for the current top-instruction
            insn_token = MicroInstructionToken(insn, insn_idx, self)
            instructions.append(insn_token)

            # iterate to the next instruction
            insn, insn_idx = insn.next, insn_idx + 1

        # save a ref of the mblock_t for later use
        self.address = self.blk.start
        self.instructions = instructions

    def _generate_header_lines(self):
        """
        Generate 'header' annotation lines for the mblock_t, similar to IDA's.
        """
        blk, mba = self.blk, self.blk.mba
        lines = []

        # block type names
        type_names = \
        {
            ida_hexrays.BLT_NONE: "????",
            ida_hexrays.BLT_STOP: "STOP",
            ida_hexrays.BLT_0WAY: "0WAY",
            ida_hexrays.BLT_1WAY: "1WAY",
            ida_hexrays.BLT_2WAY: "2WAY",
            ida_hexrays.BLT_NWAY: "NWAY",
            ida_hexrays.BLT_XTRN: "XTRN",
        } 

        blk_type = type_names[blk.type]

        # block properties
        prop_tokens = []

        if blk.flags & ida_hexrays.MBL_DSLOT:
            prop_tokens.append(TextCell("DSLOT"))
        if blk.flags & ida_hexrays.MBL_NORET:
            prop_tokens.append(TextCell("NORET"))
        if blk.needs_propagation():
            prop_tokens.append(TextCell("PROP"))
        if blk.flags & ida_hexrays.MBL_COMB:
            prop_tokens.append(TextCell("COMB"))
        if blk.flags & ida_hexrays.MBL_PUSH:
            prop_tokens.append(TextCell("PUSH"))
        if blk.flags & ida_hexrays.MBL_TCAL:
            prop_tokens.append(TextCell("TAILCALL"))
        if blk.flags & ida_hexrays.MBL_FAKE:
            prop_tokens.append(TextCell("FAKE"))

        # misc block info
        prop_tokens = [x for prop in prop_tokens for x in (prop, TextCell(" "))]
        shape_tokens = [TextCell("[START="), AddressToken(blk.start), TextCell(" END="), AddressToken(blk.end), TextCell("] "), TextCell("STK=%X/ARG=%X, MAXBSP: %X" % (blk.minbstkref, blk.minbargref, blk.maxbsp))]

        # assemble the 'main' block header line
        all_tokens = [TextCell("%s-BLOCK " % blk_type), BlockNumberToken(blk.serial), TextCell(" ")] + prop_tokens + shape_tokens
        lines.append(BlockHeaderLine(all_tokens, MAGIC_BLK_INFO, parent=self))

        # inbound edges
        idx_tokens = [x for i in range(blk.npred()) for x in (BlockNumberToken(blk.pred(i)), TextCell(", "))][:-1]
        inbound_tokens = [TextCell("INBOUND: [")] + idx_tokens + [TextCell("] ")] if idx_tokens else []

        # outbound edges 
        idx_tokens = [x for i in range(blk.nsucc()) for x in (BlockNumberToken(blk.succ(i)), TextCell(", "))][:-1]
        outbound_tokens = [TextCell("OUTBOUND: [")] + idx_tokens + [TextCell("]")] if idx_tokens else []

        # only emit the block inbound/outbound edges line if there are any...
        if inbound_tokens or outbound_tokens:
            edge_tokens = [TextCell("- ")] + inbound_tokens + outbound_tokens
            lines.append(BlockHeaderLine(edge_tokens, MAGIC_BLK_EDGE, parent=self))

        # only generate use/def comments if in verbose mode
        if self.verbose:
            if not blk.lists_ready():
                lines.append(BlockHeaderLine([TextCell("- USE-DEF LISTS ARE NOT READY")], MAGIC_BLK_UDNR, parent=self))
            else:
                lines.extend(self._generate_use_def(blk))

        return lines

    def _generate_use_def(self, blk):
        """
        Generate use/def comments for this block.
        """
        lines = []

        # use list
        use_str = generate_mlist_str(blk.mustbuse, blk.maybuse)
        if use_str:
            lines.append(BlockHeaderLine([TextCell("- USE: %s" % use_str)], MAGIC_BLK_USE, parent=self))

        # def list
        def_str = generate_mlist_str(blk.mustbdef, blk.maybdef)
        if def_str:
            lines.append(BlockHeaderLine([TextCell("- DEF: %s" % def_str)], MAGIC_BLK_DEF, parent=self))

        # dnu list
        dnu_str = generate_mlist_str(blk.dnu)
        if dnu_str:
            lines.append(BlockHeaderLine([TextCell("- DNU: %s" % dnu_str)], MAGIC_BLK_DNU, parent=self))

        return lines

    def _generate_token_line(self, idx, ins_token):
        """
        Generate a block/index prefixed line for a given instruction token.
        """
        prefix_token = LinePrefixToken(self.blk.serial, idx)
        cmt_token = InstructionCommentToken(self.blk, ins_token.insn, self.verbose)

        cmt_padding = max(50 - (len(prefix_token.text) + len(ins_token.text)), 1)
        padding_token = TextCell(" " * cmt_padding)

        # create the line 
        line_token = TextLine(items=[prefix_token, ins_token, padding_token, cmt_token], parent=self)

        # give the line token the address of the associated instruction index
        line_token.address = self.instructions[idx].address

        # return the completed instruction line token
        return line_token

    def _generate_lines(self):
        """
        Populate the line array for this mblock_t.
        """
        lines, idx = [], 0

        # generate lines for the block header
        lines += self._generate_header_lines()

        # generate lines for the block instructions
        for idx, insn in enumerate(self.instructions):
            line_token = self._generate_token_line(idx, insn)
            lines.append(line_token)

        # add a blank line after the end of the block
        lines.append(TextLine(line_type=MAGIC_BLK_TERM, parent=self))

        # save the list of generate lines to this text block
        self.lines = lines

    def get_special_line(self, line_type):
        """
        Return the speical line from this block that matches the given line type.

        TODO: ehh, this 'speical line' stuff should probably get refactored
        """
        for line in self.lines:
            if line.type == line_type:
                return line
        return None

#------------------------------------------------------------------------------
# Microcode Text (mba_t)
#------------------------------------------------------------------------------

class MicrocodeText(TextBlock):
    """
    High level text wrapper of a micro-block-array (mba_t).
    """
    
    def __init__(self, mba, verbose=False):
        super(MicrocodeText, self).__init__()
        self.verbose = verbose
        self.mba = mba
        self.refresh()

    def refresh(self, verbose=None):
        """
        Regenerate the microcode text.
        """
        if verbose is not None:
            self.verbose = verbose
        self._generate_from_mba()
        self._generate_lines()
        self._generate_token_address_map()

    def _generate_from_mba(self):
        """
        Populate this object from a mba_t.
        """
        blks = []
        
        for blk_idx in range(self.mba.qty):
            blk = self.mba.get_mblock(blk_idx)
            blk_token = MicroBlockText(blk, self.verbose)
            blks.append(blk_token)

        self.blks = blks

    def _generate_lines(self):
        """
        Populate the line array for this mba_t.
        """
        lines = []

        for blk in self.blks:
            lines.extend(blk.lines)
        
        self.lines = lines

    def get_block_for_line(self, line):
        """
        Return the MicroBlockText containing the given line token.
        """
        if not issubclass(type(line), TextLine):
            raise ValueError("Argument must be a line token type object")
        
        for blk_token in self.blks:
            if line in blk_token.lines:
                return blk_token

        return None

    def get_block_for_line_num(self, line_num):
        """
        Return the MicroBlockText that owns the given line number.
        """
        if not(line_num < len(self.lines)):
            return None
        return self.get_block_by_line(self.lines[line_num])

    def get_ins_for_line(self, line):
        """
        Return the MicroInstructionToken in the given line token.
        """
        for item in line.items:
            if isinstance(item, MicroInstructionToken):
                return item
        return None

    def get_ins_for_line_num(self, line_num):
        """
        Return the MicroInstructionToken at the given line number.
        """
        return self.get_ines_for_line(self.lines[line_num])

#-----------------------------------------------------------------------------
# Microtext Util
#-----------------------------------------------------------------------------

def generate_mlist_str(must, maybe=None):
    """
    Generate the use/def string given must-use and maybe-use lists.
    """
    must_regs = must.reg.dstr().split(",")
    must_mems = must.mem.dstr().split(",")

    maybe_regs = maybe.reg.dstr().split(",") if maybe else []
    maybe_mems = maybe.mem.dstr().split(",") if maybe else []

    for splits in [must_regs, must_mems, maybe_regs, maybe_mems]:
        splits[:] = list(filter(None, splits))[:] # lol

    maybe_regs = list(filter(lambda x: x not in must_regs, maybe_regs))
    maybe_mems = list(filter(lambda x: x not in must_mems, maybe_mems))

    must_str = ', '.join(must_regs + must_mems)
    maybe_str = ', '.join(maybe_regs + maybe_mems)

    if must_str and maybe_str:
        full_str = "%s (%s)" % (must_str, maybe_str)
    elif must_str:
        full_str = must_str
    elif maybe_str:
        full_str = "(%s)" % maybe_str
    else:
        full_str = ""
    
    return full_str

def find_similar_block(blk_token_src, mtext_dst):
    """
    Return a block from mtext_dst that is similar to the foreign blk_token_src.
    """
    blk_src = blk_token_src.blk
    fallbacks = []

    # search through all the blocks in the target mba/mtext for a similar block
    for blk_token_dst in mtext_dst.blks:
        blk_dst = blk_token_dst.blk

        # 1 for 1 block match (start addr, end addr)
        if (blk_dst.start == blk_src.start and blk_dst.end == blk_src.end):
            return blk_token_dst

        # matching block starts
        # TODO/COMMENT: explain the serial != 0 case
        elif (blk_dst.start == blk_src.start and blk_dst.serial != 0):
            fallbacks.append(blk_token_dst)

        # block got merged into another block
        elif (blk_dst.start < blk_src.start < blk_dst.end):
            fallbacks.append(blk_token_dst)

    #
    # there doesn't appear to be any blocks in this mtext that seem similar to
    # the given block. this should seldom happen.. if ever ?
    #

    if not fallbacks:
        return None

    #
    # return a fallback block, which is a 'similar' / related block but not
    # a 1-for-1 match with the given block. it is usually still a good result
    # as blocks generally transform as they move through the microcode layers
    #

    return fallbacks[0]

#-----------------------------------------------------------------------------
# Position Translation
#-----------------------------------------------------------------------------
#
#    These translation functions will try to 'strictly' translate the text
#    position of a cursor from one Microtext (a printed mba_t) to another.
#
#    The goal of the translation (and remapping) functions is a best effort
#    attempt at following microcode blocks, instructions, or operands across
#    the entire maturity process.
#
#    While this code is a bit messy right now... it's the source of the
#    magic behind lucid.
#

def translate_mtext_position(position, mtext_src, mtext_dst):
    """
    Translate the given text position from one mtext to another.
    """
    line_num, x, y = position

    #
    # while this isn't strictly required, let's enforce it. this basically
    # means that we won't allow you to translate a position from maturity
    # levels that are more than one degree apart.
    #
    # eg, no hopping from maturity 0 --> 7 instead, you must translate
    # through each layer 0 -> 1 -> 2 -> ... -> 7
    # 

    assert abs(mtext_src.mba.maturity - mtext_dst.mba.maturity) <= 1

    # get the line the cursor falls on
    line = mtext_src.lines[line_num]

    # TODO: ehh should change this to 'special/generated lines'
    if line.type:
        return translate_block_header_position(position, mtext_src, mtext_dst)

    return translate_instruction_position(position, mtext_src, mtext_dst)

def translate_block_header_position(position, mtext_src, mtext_dst):
    """
    Translate a block-header position from one mtext to another.
    """
    line_num, x, y = position

    # get the line the given position falls within on the source mtext
    line = mtext_src.lines[line_num]

    # get the block the given position falls within on the source mtext
    blk_token_src = mtext_src.get_block_for_line(line)

    # find a block in the dest mtext that seems to match the source block
    blk_token_dst = find_similar_block(blk_token_src, mtext_dst)

    if blk_token_dst:
        ins_src = set([x.address for x in blk_token_src.instructions])
        ins_dst = set([x.address for x in blk_token_dst.instructions]) 
        translate_header = (ins_src == ins_dst or blk_token_dst.blk.start == blk_token_src.blk.start)
    else:
        translate_header = False

    #
    # if we think we have found a suitable matching block, translate the given
    # position from the src block header to the destination one
    #

    if translate_header:

        # get the equivalent header line from the destination block
        line_dst = blk_token_dst.get_special_line(line.type)

        #
        # if a matching header line doesn't exist in the dest, attempt
        # to match the line 'depth' into the header instead.. this will
        # help with the illusion of the 'stationary' user cursor
        #

        if not line_dst:
            line_idx = blk_token_src.lines.index(line)

            try:

                line_dst = blk_token_dst.lines[line_idx]
                if not line_dst.type:
                    raise
            #
            # either the destination block didn't have enough lines
            # to fufill the 'stationary' illusion, or the target
            # line wasn't a block header line. in these cases, just
            # fallback to mapping the cursor to the top of the block
            #

            except:
                line_dst = blk_token_dst.lines[0]

        # return the target/
        line_num_dst = mtext_dst.lines.index(line_dst)
        return (line_num_dst, 0, y)
    
    #
    # if the block header the cursor was on in the source mtext has
    # been merged into another block in the dest mtext, we should try
    # to place the cursor address onto the 'first' instruction(s)
    # from the source block, which is now somewhere in the middle of
    # the 'dest' block
    #
    # since instructions can get discarded, we should try all of
    # them from the source block to find a viable 'donor' address
    # that we can remap onto
    #

    for ins_token in blk_token_src.instructions:
        tokens_dst = mtext_dst.get_tokens_for_address(ins_token.address)
        if tokens_dst:
            line_num, x = mtext_dst.get_pos_of_token(tokens_dst[0])
            return (line_num, x, y)

    #
    # lol, so no instructions in the source block showed up in the
    # dest block that 'contains' it? let's just bail
    #
    
    return None

def translate_instruction_position(position, mtext_src, mtext_dst):
    """
    Translate an instruction position from one mtext to another.
    """
    line_num, x, y = position
    token_src = mtext_src.get_token_at_position(line_num, x)
    address_src = mtext_src.get_address_at_position(line_num, x)

    #
    # find all the lines in the destination text that claim to contain the
    # current address
    #

    line_nums_dst = mtext_dst.get_line_nums_for_address(address_src)
    if not line_nums_dst:
        return None

    # get the line the given position falls within on the source mtext
    line = mtext_src.lines[line_num]

    # get the block the given position falls within on the source mtext
    blk_token_src = mtext_src.get_block_for_line(line)
    blk_src = blk_token_src.blk

    # find a block in the dest mtext that seems to match the source block
    blk_token_dst = find_similar_block(blk_token_src, mtext_dst)

    #
    # if a similar block was found in the destination mtext, that means we
    # want to search it and see if our address is still in the block. if
    # it is, those instances are probably going to be the most relevant to
    # our position in the source mtext.
    #

    if blk_token_dst:
        blk_dst = blk_token_dst.blk
        tokens = blk_token_dst.get_tokens_for_address(address_src)
    else:
        tokens = []

    #
    # no tokens matching the target address in the 'similar' dest block (or
    # maybe there wasn't even a matching block), so we just fallback to
    # searching the whole dest mtext
    #

    if not tokens:
        tokens = mtext_dst.get_tokens_for_address(address_src)
        assert tokens, "This should never happen because line_nums_dst... ?"

    # compute the relative cursor address into the token text
    _, x_base_src = mtext_src.get_pos_of_token(token_src)
    x_rel = (x - x_base_src)

    # 1 for 1 token match
    for token in tokens:
        if token.text == token_src.text:
            line_num_dst, x_dst = mtext_dst.get_pos_of_token(token)
            x_dst += x_rel
            return (line_num_dst, x_dst, y)

    # common 'ancestor', eg the target token actually got its address from an ancestor  
    token_src_ancestor = token_src.ancestor_with_address()
    for token in tokens:
        line_num, x_dst = mtext_dst.get_pos_of_token(token)
        if token.text == token_src_ancestor.text:
            line_num, x_dst = mtext_dst.get_pos_of_token(token)
            x_dst_base = token.text.index(token_src.text)
            x_dst += x_dst_base + x_rel # oof
            return (line_num, x_dst, y)

    # last ditch effort, try to land on a text that matches the target token
    for token in tokens:
        line_num, x_dst = mtext_dst.get_pos_of_token(token)
        if token_src.text in token.text:
            line_num, x_dst = mtext_dst.get_pos_of_token(token)
            x_dst_base = token.text.index(token_src.text)
            x_dst += x_dst_base + x_rel # oof
            return (line_num, x_dst, y)
    
    # yolo, just land on whatever token available 
    line_num, x = mtext_dst.get_pos_of_token(tokens[0])
    return (line_num, x, y)

#-----------------------------------------------------------------------------
# Position Remapping
#-----------------------------------------------------------------------------
#
#    Remapping functions are similar to the translation functions, but they
#    serve as a 'fallback' when a position translation cannot be guaranteed.
#
#    For example, if a micro-instruction gets optimized away / discarded in
#    a later phase of the microcode maturation pipeline, there is no way we 
#    can map the cursor to an instruction or block that no longer exists.
#
#    In these cases, we attempt to 'remap' the cursor onto the closest 
#    instruction / block to try and maintain a similar cursor context.
#
#    Please note, these functions are also... kind of dirty at the moment.
#

def remap_mtext_position(position, mtext_src, mtext_dst):
    """
    Remap the given position from one mtext to a *similar* position in another.
    """
    line_num, x, y = position
    line = mtext_src.lines[line_num]

    # TODO: ehh should change this to 'speical/generated lines'
    if line.type:
        projection = remap_block_header_position(position, mtext_src, mtext_dst)
    else:
        projection = remap_instruction_position(position, mtext_src, mtext_dst)

    if projection:
        return projection

    #
    # translation & remapping REALLY failed... just try to maintain the same
    # viewport position I guess ? shouldn't really matter (or occur) often
    #

    line_max = len(mtext_dst.lines)
    if position[0] < line_max:
        line_num = position[0]
    else:
        line_num = max(line_max - 1, 0)

    return (line_num, position[1], position[2])

def remap_block_header_position(position, mtext_src, mtext_dst):
    """
    Remap a block header position from one mtext to a *similar* position in another.
    """
    line_num, x, y = position
    line = mtext_src.lines[line_num]

    # the block in the source mtext where the given position resides
    blk_token_src = mtext_src.get_block_for_line(line)

    blks_to_visit, blks_visited = [blk_token_src], []
    while blks_to_visit:
        blk_token = blks_to_visit.pop(0)

        # ignore blocks we have already seen
        if blk_token in blks_visited:
            continue

        blk_token_dst = find_similar_block(blk_token, mtext_dst)
        if blk_token_dst:
            line_num, x = mtext_dst.get_pos_of_token(blk_token_dst.lines[0])
            return (line_num, x, y)

        remap_tokens = [blk_token.instructions[0]] if blk_token.instructions else []

        for token in remap_tokens:
            insn_line_num, insn_x = mtext_src.get_pos_of_token(token)
            projection = remap_instruction_position((insn_line_num, insn_x, y), mtext_src, mtext_dst)
            if projection:
                return (projection[0], projection[1], y)

        for blk_serial in range(blk_token.blk.nsucc()):
            blk_token_succ = mtext_src.blks[blk_token.blk.succ(blk_serial)]
            if blk_token_succ in blks_visited or blk_token_succ in blks_to_visit:
                continue
            blks_to_visit.append(blk_token_succ)
    
    return None

def remap_instruction_position(position, mtext_src, mtext_dst):
    """
    Remap an instruction position from one mtext to a *similar* position in another.
    """
    line_num, x, y = position
    line = mtext_src.lines[line_num]

    # the block in the source mtext where the given position resides
    blk_token_src = mtext_src.get_block_for_line(line)
    blk_src = blk_token_src.blk

    ins_token_src = mtext_src.get_ins_for_line(line)
    pred_addresses = [x.address for x in blk_token_src.instructions[:ins_token_src.index]]
    succ_addresses = [x.address for x in blk_token_src.instructions[ins_token_src.index+1:]]
    remap_targets = succ_addresses + pred_addresses[::-1]

    for blk_serial in range(blk_src.nsucc()):
        remap_targets += [x.address for x in mtext_src.blks[blk_src.succ(blk_serial)].instructions]

    for address in remap_targets:
        new_tokens = mtext_dst.get_tokens_for_address(address)
        if new_tokens:
            line_num, x = mtext_dst.get_pos_of_token(new_tokens[0])
            return (line_num, x, y)

    #
    # in this case, there have been no hits on *any* of the instructions in
    # the block... that means they are all gone
    #
    # in some cases, all the instructions in a block can get optimized away,
    # and an empty version of the block will be around for the next maturity
    # level, so let's see if we can find it...
    #

    blk_token_dst = find_similar_block(blk_token_src, mtext_dst)
    if not blk_token_dst:
        return None

    #
    # we found a matching block, but it is presumably empty... so we will
    # just return the text position of its first block header line
    #

    line_num, x = mtext_dst.get_pos_of_token(blk_token_dst.lines[0])
    return (line_num, x, y)