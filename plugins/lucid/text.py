import collections
from collections.abc import Iterable

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
    
    def get_children(self):
        """
        Returns any children of this text cell. Default behavior is to return nothing.
        """
        return None

    def ancestor_with_address(self):
        """
        Return the first parent of this cell that has a valid address.
        """
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


class TokenAddressIterator:
    """
    Custom helper class for iterating over tokens that exist at a specific address.
    """
    
    @staticmethod
    def is_valid(token):
        return token and issubclass(type(token), TextCell)
    
    def __init__(self, items, address, max_count = 0):
        addrmap = False
        
        if isinstance(items, dict):
            if addresses := items.get(address, []):
                items = addresses
                addrmap = True
            else:
                items = items.items()
        
        if issubclass(type(items), Iterable):
            items = list(items)
        else:
            raise TypeError(items)
        
        self._addrmap = addrmap
        self._items = items
        self._address = address
        
        assert max_count >= 0, "max_count cannot be a negative number"
        
        self._max_count = max_count
        self._setup_iter()
    
    def _setup_iter(self):
        self._myiter = filter(self.is_valid, self._items)
        self._subiter = None
        self._exhausted = False
        self._remain = self._max_count if self._max_count else 0
        
    def __iter__(self):
        self._setup_iter()
        return self

    def _get_next_token(self):
        if self._subiter:
            # try to return the next sub-token
            try:
                return next(self._subiter)
            except StopIteration as e:
                # no more sub-tokens are left :(
                self._subiter = None
        
        if not self._myiter:
            # well, this is strange...I'm sure it'll happen lol
            raise Exception("iterator undefined?!")
        
        # grab the next token
        return next(self._myiter)

    def __next__(self):
        addrmap = self._addrmap # items already of the target address?
        while not self._exhausted:
            try:
                token = self._get_next_token()
                if not token:
                    # end of subtokens
                    continue
                
                if not addrmap and token.address > self._address:
                    # too far ahead, stop iterating through our tokens
                    raise StopIteration
                
                if issubclass(type(token), TextToken):
                    # prepare to check its subtokens next
                    if items := token.get_token_items():
                        self._subiter = TokenAddressIterator(items, self._address)
                
                if addrmap or token.address == self._address:
                    # only get up to max_count tokens, if specified
                    if self._remain:
                        self._remain -= 1
                        if not self._remain:
                            self._exhausted = True
                    # we found a match!
                    return token
            except StopIteration as e:
                # we're all out of tokens now :(
                self._exhausted = True
        if self._exhausted:
            raise StopIteration


class TokenRange:
    """
    Custom helper class for managing token ranges.
    """
    
    def __init__(self, token, start, end):
        self._token = token
        self._issubclass = issubclass(type(token), TextToken)
        self._start = start
        self._end = end
    
    def __contains__(self, index):
        return index >= self._start and index < self._end
    
    def empty(self):
        return not self._token
    
    def get_index(self, token):
        """
        Returns the index of the specified token, if it exists; otherwise, None
        """
        
        if self._token == token:
            return self._start
        if self._issubclass:
            if index := self._token.get_index_of_token(token) is not None:
                return self._start + index
        return None
    
    def get_token(self, x_index):
        """
        Returns the token at the specified index, if it exists; otherwise, None
        """
        
        if self.empty() or x_index not in self:
            return None

        token = self._token
        
        #
        # if the matching child token does not derive from a TextToken, it is
        # probably a TextCell which cannot nest other tokens. so we can simply
        # return the found token as it is a leaf
        #

        if not self._issubclass:
            return token

        #
        # the matching token must derive from a TextToken or something
        # capable of nesting tokens, so recurse downwards through the text
        # structure to see if there is a deeper, more precise token that
        # can be returned
        #

        return token.get_token_at_index(x_index - self._start)
    
    
    @property
    def token(self):
        return self._token
    
    @property
    def start(self):
        return self._start
    
    @property
    def end(self):
        return self._end
    
    @property
    def length(self):
        return self._end - self._start


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

        debug_lines = [f"**** {len(self.items)} tokens"]
        for token in self.items:
            debug_lines.append(f"** find token '{token.text}' in '{self.text}'\n\tat {parsing_offset}: '{self.text[parsing_offset:]}'")
            
            token_start = self.text.index(token.text, parsing_offset)
            token_end = token_start + len(token.text)
            
            debug_lines.append(f"** - start={token_start}, end={token_end} => '{self.text[token_start:token_end]}'")
            
            token_range = TokenRange(token, token_start, token_end)
            token_ranges.append(token_range)
            
            if token_start > 2 and self.text.find(',', parsing_offset, token_start) > parsing_offset:
                debug_lines.append("**** skipped setting the parsing offset!")
                continue
            
            parsing_offset = token_end
        
        #print('\n'.join(debug_lines))

        self._token_ranges = token_ranges
    
    #-------------------------------------------------------------------------
    # Textual APIs
    #-------------------------------------------------------------------------
    
    def get_token_items(self):
        return self.items
    
    def get_tokens_for_address(self, address, max_count = 0):
        """
        Return all (child) tokens matching the given address.
        """
        it = TokenAddressIterator(self.get_token_items(), address, max_count=max_count)
        return list(it)
    
    def get_first_token_for_address(self, address):
        """
        Return first (child) token matching the given address.
        """
        return next(iter(self.get_tokens_for_address(address, 1) + [None]))

    def get_index_of_token(self, target_token):
        """
        Return the index of the given (child) token into this token's text.
        """
        if target_token == self:
            return 0

        for token_range in self._token_ranges:
            if (index := token_range.get_index(target_token)) is not None:
                return index

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

        for token_range in self._token_ranges:
            if (token := token_range.get_token(x_index)) is not None:
                #print(f"**** token '{token.text}' found at {x_index} in '{self.text}'")
                return token

        #print(f"**** token not found at {x_index} in '{self.text}'")
        return self

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
        
        addr_map = collections.defaultdict(list)
        
        def _iter_token(token):
            yield token
            for subtoken in token.items:
                yield subtoken
                if issubclass(type(subtoken), TextToken):
                    if subtoken.address != ida_idaapi.BADADDR:
                        addr_map[subtoken.address].append(subtoken)
                    yield from _iter_token(subtoken)
        
        self._ea2token = addr_map
        self._line2token = {
            line_idx:list(_iter_token(token)) for line_idx, token in enumerate(self.lines)
        }
    
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

    def get_line_token(self, line_num):
        """
        Return the token at the given line number.
        """
        if not (0 <= line_num < len(self.lines)):
            return None
        return self.lines[line_num]

    def get_token_at_position(self, line_num, x_index):
        """
        Return the token at the given text position.
        """
        if line := self.get_line_token(line_num):
            return line.get_token_at_index(x_index)
        return None

    def get_address_at_position(self, line_num, x_index):
        """
        Return the mapped address of the given text position.
        """
        if line := self.get_line_token(line_num):
            return line.get_address_at_index(x_index)
        # TODO: explain why ?
        return ida_idaapi.BADADDR

    def get_pos_of_token(self, target_token):
        """
        Return the text position of the given token.
        """
        for line_num, tokens in self._line2token.items():
            if target_token in tokens:
                return (line_num, self.lines[line_num].get_index_of_token(target_token))
        raise Exception(f"**** target_token '{target_token.text}' NOT found!!!")
        return None

    def get_tokens_for_address(self, address, max_count = 0):
        """
        Return all (child) tokens matching the given address.
        """
        it = TokenAddressIterator(self._ea2token, address, max_count=max_count)
        return list(it)
    
    def get_first_token_for_address(self, address):
        """
        Return first (child) token matching the given address.
        """
        return next(iter(self.get_tokens_for_address(address, 1) + [None]))

    def line_nums_contain_address(self, address):
        """
        Returns whether the address exists within any of the line numbers.
        """
        for _,tokens in self._line2token.items():
            for token in tokens:
                if token.address == address:
                    return True
        return False

    def get_line_nums_for_address(self, address):
        """
        Return a list of line numbers which contain tokens matching the given address.
        """
        line_nums = set()
        if items := self._line2token.items():
            line_nums = {line for line,tokens in items \
                for _ in filter(lambda t: t.address == address, tokens)}
        return line_nums

    def get_addresses_for_line_num(self, line_num):
        """
        Return a list of addresses contained by tokens on the given line number.
        """
        return set(token.address for token in self._line2token.get(line_num, []))