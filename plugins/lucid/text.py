import collections

import ida_lines
import ida_idaapi

#-----------------------------------------------------------------------------
# Text Abstractions
#-----------------------------------------------------------------------------
#
#    This file contains a number of 'text abstractions' that will serve as
#    the foundation of our interactive microcode text. 
#
#    These classes are primarily built on the notion of 'nesting' which
#    allows more complex text structures to composed of child text objects,
#    grouped, and traversed in various manners.
#

class TextCell(object):
    """
    Base abstraction that all printable text classes will derive from.

    A text cell is the simplest and smallest text object. Think of it
    like a word in a paragraph.
    """

    def __init__(self, text="", parent=None):
        self._text = ida_lines.tag_remove(text)
        self._tagged_text = text

        # public attributes
        self.parent = parent
        self.address = ida_idaapi.BADADDR

    def ancestor_with_address(self):
        """
        Return the first parent of this cell that has a valid address.
        """
        address = ida_idaapi.BADADDR
        token = self.parent

        # iterate upwards through the target token parents until an address is found
        while token:
            if token.address != ida_idaapi.BADADDR:
                return token
            token = token.parent

        # no ancestor of this token had a defined address...
        return None

    @property
    def text(self):
        """
        Return a human-readable representation of this text cell.
        """
        return self._text

    @property
    def tagged_text(self):
        """
        Return a colored/formatted representation of this text cell.
        """
        return self._tagged_text

class TextToken(TextCell):
    """
    A text element that can nest similar text-based elements.

    Tokens are more powerful than cells as they allow for nesting of cells,
    or other text tokens. Tokens cannot span more than one printable line,
    and do not natively generate text based on their child tokens.

    Classes derived from a TextToken can define custom behavior as to how
    their text should be generated (if necessary).
    """

    def __init__(self, text="", items=None, parent=None):
        super(TextToken, self).__init__(text, parent)
        self.items = items if items else []
        self._token_ranges = []

        if items:
            self._generate_token_ranges()

    def _generate_token_ranges(self):
        """
        Generate the text span indexes (start:end) for each child token.
        """
        token_ranges = []
        parsing_offset = 0

        for token in self.items:
            token_index = self.text[parsing_offset:].index(token.text)
            token_start = parsing_offset + token_index
            token_end = token_start + len(token.text)
            token_ranges.append((range(token_start, token_end), token))
            parsing_offset = token_end

        self._token_ranges = token_ranges
    
    #-------------------------------------------------------------------------
    # Textual APIs
    #-------------------------------------------------------------------------

    def get_tokens_for_address(self, address):
        """
        Return all (child) tokens matching the given address.
        """
        found = [self] if self.address == address else []
        for token in self.items:
            if not issubclass(type(token), TextToken):
                if token.address == address:
                    found.append(token)
                continue
            found.extend(token.get_tokens_for_address(address))
        return found

    def get_index_of_token(self, target_token):
        """
        Return the index of the given (child) token into this token's text.
        """
        if target_token == self:
            return 0

        for token_range, token in self._token_ranges:
            if token == target_token:
                return token_range[0]
            if not issubclass(type(token), TextToken):
                continue
            found = token.get_index_of_token(target_token)
            if found is not None:
                return found + token_range[0]

        return None

    def get_token_at_index(self, x_index):
        """
        Return the (child) token at the given text index into this token's text.
        """
        assert 0 <= x_index < len(self.text)

        #
        # search all the stored token text ranges for our child tokens to see
        # if the given index falls within any of them
        #

        for token_range, token in self._token_ranges:
            
            # skip 'blank' children
            if not token.text:
                continue 

            if x_index in token_range:
                break

        #
        # if the given index does not fall within a child token range, the
        # given index must fall on text that makes up this token itself
        #

        else:
            return self

        #
        # if the matching child token does not derive from a TextToken, it is
        # probably a TextCell which cannot nest other tokens. so we can simply
        # return the found token as it is a leaf
        #

        if not issubclass(type(token), TextToken):
            return token

         #
         # the matching token must derive from a TextToken or something
         # capable of nesting tokens, so recurse downwards through the text
         # structure to see if there is a deeper, more precise token that
         # can be returned
         #

        return token.get_token_at_index(x_index - token_range[0])

    def get_address_at_index(self, x_index):
        """
        Return the mapped address of the given text index.
        """
        token = self.get_token_at_index(x_index)

        #
        # iterate upwards through the parents of the targeted token until a
        # valid 'mapped' / inherited address can be returned 
        #

        while token.address == ida_idaapi.BADADDR and token != self:
            token = token.parent

        # return the found address (or BADADDR...)
        return token.address

class TextLine(TextToken):
    """
    A line of printable text tokens.

    The main feature of this class (vs a TextToken) is that it will
    automatically generate its text based on its child tokens. This is done
    by simply sequentially joining the text of its child tokens into a line
    of printable text.
    """

    def __init__(self, items=None, line_type=None, parent=None):
        super(TextLine, self).__init__(items=items, parent=parent)
        self.type = line_type

        # (re-)parent orphan tokens to this line
        for item in self.items:
            if not item.parent:
                item.parent = self

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def text(self):
        return ''.join([item.text for item in self.items])

    @property
    def tagged_text(self):
        return ''.join([item.tagged_text for item in self.items])
    
    #-------------------------------------------------------------------------
    # Textual APIs
    #-------------------------------------------------------------------------

    def get_token_at_index(self, x_index):
        """
        Return the (child) token at the given text index into this token's text.

        This is overridden specifically to handle the case where an index past
        the end of the printable text line is given. In such cases, we simply
        return the TextLine itself, as the token at the given 'invalid' index.
        
        We do this because a 10 character TextLine might be rendered in a 
        100 character wide text / code window. 
        """
        if x_index >= len(self.text):
            return self
        token = super(TextLine, self).get_token_at_index(x_index)
        if not token:
            token = self
        return token

class TextBlock(TextCell):
    """
    A collection of tokens organized as lines, making a block of text.

    A TextBlock is analogous to a paragraph, or collection of TextLines. It
    provides a few helper functions to locate tokens / addresses using a
    given position in the form of (line_num, x) into the block.
    """

    def __init__(self):
        super(TextBlock, self).__init__()
        self.lines = []
        self._ea2token = {}
        self._line2token = {}

    def _generate_token_address_map(self):
        """
        Generate a map of token --> address.
        """
        to_visit = []
        for line_idx, line in enumerate(self.lines):
            to_visit.append((line_idx, line))

        line_map = collections.defaultdict(list)
        addr_map = collections.defaultdict(list)

        while to_visit:
            line_idx, token = to_visit.pop(0)
            line_map[line_idx].append(token)
            for subtoken in token.items:
                line_map[line_idx].append(subtoken)
                if not issubclass(type(subtoken), TextToken):
                    continue
                to_visit.append((line_idx, subtoken))
                if subtoken.address == ida_idaapi.BADADDR:
                    continue
                addr_map[subtoken.address].append(subtoken)

        self._ea2token = addr_map
        self._line2token = line_map
    
    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def text(self):
        return '\n'.join([line.text for line in self.lines])

    @property
    def tagged_text(self):
        return '\n'.join([line.tagged_text for line in self.lines])

    #-------------------------------------------------------------------------
    # Textual APIs
    #-------------------------------------------------------------------------

    def get_token_at_position(self, line_num, x_index):
        """
        Return the token at the given text position.
        """
        if not(0 <= line_num < len(self.lines)):
            return None
        return self.lines[line_num].get_token_at_index(x_index)

    def get_address_at_position(self, line_num, x_index):
        """
        Return the mapped address of the given text position.
        """
        if not(0 <= line_num < len(self.lines)):
            return ida_idaapi.BADADDR
        return self.lines[line_num].get_address_at_index(x_index)

    def get_pos_of_token(self, target_token):
        """
        Return the text position of the given token.
        """
        for line_num, tokens in self._line2token.items():
            if target_token in tokens:
                return (line_num, self.lines[line_num].get_index_of_token(target_token))
        return None

    def get_tokens_for_address(self, address):
        """
        Return the list of tokens matching the given address.
        """
        return self._ea2token.get(address, [])

    def get_line_nums_for_address(self, address):
        """
        Return a list of line numbers which contain tokens matching the given address.
        """
        line_nums = set()
        for line_idx, tokens in self._line2token.items():
            for token in tokens:
                if token.address == address:
                    line_nums.add(line_idx)
        return list(line_nums)

    def get_addresses_for_line_num(self, line_num):
        """
        Return a list of addresses contained by tokens on the given line number.
        """
        addresses = set()
        for token in self._line2token.get(line_num, []):
            addresses.add(token.address)
        return list(addresses)