"""
This code based on:
http://www.daniweb.com/software-development/python/code/367871/
assembler-for-little-computer-3-lc-3-in-python

Order of BRanch flags relaxed, BR without flags interpreted as BRnzp
(always).
"""

from array import array
import sys
try:
    from IPython.display import HTML
except:
    pass

def ascii_str(i):
    if i < 256:
        if i < 32 or i > 127: # integers
            return "(or %s)" % i
        else: # int, or ASCII
            return "(or %s, %s)" % (i, repr(chr(i)))
    else:
        return "" 

class HEX(int):
    def __repr__(self):
        return lc_hex(self)

def lc_hex(h):
    """ Format the value in the form xFFFF """
    try:
        return 'x%04X' % lc_bin(h)
    except:
        return h

def lc_bin(v):
    """ Truncate any extra bytes """
    return v & 0xFFFF

def is_composed_of(s, letters):
    return len(s) > 0 and sum([s.count(letter) for letter in letters]) == len(s)

def is_hex(s):
    if len(s) > 1:
        if s[0] == "x":
            if s[1] == "-":
                return is_composed_of(s[2:].upper(), "0123456789ABCDEF")
            else:
                return is_composed_of(s[1:].upper(), "0123456789ABCDEF")
    return False

def is_bin(s):
    return is_composed_of(s, "01")

def sext(binary, bits):
    """ 
    Sign-extend the binary number, check the most significant
    bit 
    """
    neg = binary & (1 << (bits - 1))
    if neg:
        mask = 0
        for i in range(bits, 16):
            mask |= (0b1 << i)
        return (mask | binary)
    else:
        return binary

def lc_int(v):
    if v & (1 << 15): # negative
        return -((~(v & 0xFFFF) + 1) & 0xFFFF)
    else:
        return v

def plus(v1, v2):
    """
    Add two values together, return a positive or negative value.
    """
    return lc_int(v1) + lc_int(v2)

class LC3(object):
    """
    The LC3 Computer. This object can assemble, disassemble, and execute
    LC3 programs.
    """
    # if RX is used in an instruction, these are the positions:
    # 0000111222000333
    reg_pos = [9, 6, 0]
    special_reg_pos = {"JSRR": [6]} ## JSRR R1
    flags = {'n': 1 << 11, 'z': 1 << 10, 'p': 1 << 9}
    # All variations of instructions:
    # Note that the following are handled in code:
    #    * two modes of ADD and AND
    #    * variations of BR (BRn, BRnp, etc)
    # as they have the same mnemonic
    instruction_info = {
        'ADD': 0b1 << 12,
        'AND': 0b0101 << 12,
        'BR': 0b0,
        'GETC': (0b1111 << 12) + 0x20,
        'HALT': (0b1111 << 12) + 0x25,
        'IN': (0b1111 << 12) + 0x23,
        'JMP': 0b1100 << 12,
        'JMPT': (0b1100000 << 9) + 1,
        'JSR':  0b01001 << 11,
        'JSRR': 0b01000 << 11,
        'LD':  0b0010 << 12,
        'LDI': 0b1010 << 12,
        'LDR': 0b0110 << 12,
        'LEA': 0b1110 << 12,
        'NOT': (0b1001 << 12) + 0b111111,
        'OUT': (0b1111 << 12) + 0x21,
        'PUTS': (0b1111 << 12) + 0x22,
        'PUTSP': (0b1111 << 12) + 0x24,
        'RET': 0b1100000111000000,
        'RTI': 0b1000 << 12,
        'RTT': 0b1100000111000001,
        'ST': 0b0011 << 12,
        'STI': 0b1011 << 12,
        'STR': 0b0111 << 12,
        'TRAP': 0b1111 << 12,
        'SHIFT': 0b1101 << 12,
    }
    # bits of immediate mode field:
    immediate = {
        'ADD': 5,
        'AND': 5,
        'BR': 9,
        'GETC': 0,
        'HALT': 0,
        'IN': 0,
        'JMP': 0,
        'JMPT': 0,
        'JSR': 11,
        'JSRR': 0,
        'LD': 9,
        'LDI': 9,
        'LDR': 6,
        'LEA': 9,
        'NOT': 9,
        'OUT': 0,
        'PUTS': 0,
        'PUTSP': 0,
        'RET': 0,
        'RTI': 0,
        'RTT': 0,
        'ST': 9,
        'STI': 9,
        'STR': 6,
        'TRAP': 8,
        'SHIFT': 6,  ## SHIFT R2, #1
    }
    # Based on appendix figure C.2 and C.7 states, and 1 cycle for each memory read
    cycles = {
            0b0000: 5  + 1, # BR
            0b0001: 5  + 1, # ADD
            0b0010: 7  + 3, # LD, + 2 memory reads
            0b0011: 7  + 2, # ST, + 1 memory read, one store
            0b0100: 6  + 1, # JSR
            0b0101: 5  + 1, # AND
            0b0110: 7  + 2, # LDR
            0b0111: 7  + 3, # STR
            0b1000: 12 + 3, # RTI
            0b1001: 5  + 1, # NOT
            0b1010: 9  + 3, # LDI
            0b1011: 9  + 3, # STI
            0b1100: 5  + 1, # JMP and RET
            0b1101: 5  + 1, # SHIFT
            0b1110: 5  + 1, # LEA
            0b1111: 7  + 2, # TRAP
        }
    mnemonic = {
        0b0000: "BR",
        0b0001: "ADD",
        0b0010: "LD",
        0b0011: "ST",
        0b0100: "JSR",
        0b0101: "AND",
        0b0110: "LDR",
        0b0111: "STR",
        0b1000: "RTI",
        0b1001: "NOT",
        0b1010: "LDI",
        0b1011: "STI",
        0b1100: "JMP",
        0b1101: "SHIFT",
        0b1110: "LEA",
        0b1111: "TRAP",
    }

    def __init__(self, kernel=None):
        # Functions for interpreting instructions:
        self.kernel = kernel
        self.char_buffer = []
        self.breakpoints = {}
        self.dump_mode = "dis"
        self.apply = {
            0b0000: self.BR,
            0b0001: self.ADD,
            0b0010: self.LD,
            0b0011: self.ST,
            0b0100: self.JSR,
            0b0101: self.AND,
            0b0110: self.LDR,
            0b0111: self.STR,
            0b1000: self.RTI,
            0b1001: self.NOT,
            0b1010: self.LDI,
            0b1011: self.STI,
            0b1100: self.JMP, # and RET
            0b1101: self.SHIFT,
            0b1110: self.LEA,
            0b1111: self.TRAP,
        }
        # Functions for formatting instructions:
        self.format = {
            0b0000: self.BR_format,
            0b0001: self.ADD_format,
            0b0010: self.LD_format,
            0b0011: self.ST_format,
            0b0100: self.JSR_format,
            0b0101: self.AND_format,
            0b0110: self.LDR_format,
            0b0111: self.STR_format,
            0b1000: self.RTI_format,
            0b1001: self.NOT_format,
            0b1010: self.LDI_format,
            0b1011: self.STI_format,
            0b1100: self.JMP_format, # and RET_format
            0b1101: self.SHIFT_format,
            0b1110: self.LEA_format,
            0b1111: self.TRAP_format,
        }
        self.initialize()

    #### The following allow different hardware implementations:
    #### memory, register, nzp, and pc can be implemented in different
    #### means.
    def initialize(self, runit=False):
        self.filename = ""
        self.debug = False
        self.meta = False
        self.warn = True
        self.noop_error = True
        self.source = {}
        self.cycle = 0
        self.orig = 0x3000
        self.line_count = 1
        self.set_pc(HEX(0x3000))
        self.cont = True
        self.suspended = False
        self.instruction_count = 0
        self.immediate_mask = {}
        for im in self.immediate:
            self.immediate_mask[im] = (1 << self.immediate[im]) - 1
        self.instructions = self.instruction_info.keys()
        self.regs = dict(('R%1i' % r, r) for r in range(8))
        self.labels = {}
        self.label_location = {}
        self.register = {0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0}
        self.reset_memory(runit=runit) # assembles OS
        self.reset_registers()

    def reset_memory(self, filename=None, runit=False):
        text = get_os()
        debug = self.debug 
        self.debug = self.meta
        self.memory = array('i', [0] * (1 << 16))
        self.breakpoints = {}
        # We reset these items here and below because of 
        # bug (related to hack in interpreter?)
        self.assemble(text)
        self.debug = debug
        if runit:
            self.set_pc(0x0200)
            self.run()
        self.source = {}
        self.labels = {}
        self.label_location = {}
        self.set_pc(0x3000)
        self.orig = HEX(0x3000)
        self.line_count = 1

    def reset_registers(self):
        debug = self.debug
        self.debug = self.meta
        for i in range(8):
            self.set_register(i, 0)
        self.set_nzp(0)
        self.debug = debug
        
    def set_nzp(self, value):
        self.nzp = (int(value & (1 << 15) > 0), 
                    int(value == 0), 
                    int((value & (1 << 15) == 0) and value != 0))
        if self.debug:
            self.Print("    NZP <=", self.get_nzp())

    def get_nzp(self, register=None):
        if register is not None:
            value = self.nzp[register]
        else:
            value = self.nzp
        if self.meta:
            if register:
                self.Print("    %s => %s" % ("NZP"[register], lc_hex(value)))
            else:
                self.Print("    NZP => %s" % (lc_hex(value), ))
        return value

    def get_pc(self):
        return self.pc

    def set_pc(self, value):
        self.pc = HEX(value)
        if self.debug:
            self.Print("    PC <= %s" % lc_hex(value))

    def increment_pc(self, value=1):
        self.set_pc(self.get_pc() + value)

    def get_register(self, position):
        value = self.register[position]
        if self.meta:
            self.Print("    R%d => %s" % (position, lc_hex(value)))
        return value

    def set_register(self, position, value):
        self.register[position] = value
        if self.debug:
            self.Print("    R%d <= %s" % (position, lc_hex(value)))

    def set_instruction(self, location, n, line):
        """
        Put n into memory[location]; also checks to to make sure represented 
        correctly.
        """
        self.set_memory(location, lc_bin(n))

    def get_memory(self, location):
        value = self.memory[location]
        if self.meta:
            self.Print("    memory[%s] => %s" % (lc_hex(location), lc_hex(value)))
        return value

    def set_memory(self, location, value):
        self.memory[location] = value
        if self.debug:
            self.Print("    memory[%s] <= %s" % (lc_hex(location), lc_hex(value)))

    def memory_tofile(self, start, stop, f):
        self.memory[start:stop].tofile(f)

    def memory_byteswap(self):
        self.memory.byteswap()

    #### End of overridden methods

    def make_label(self, label):
        return label.replace(":", "").upper()

    def in_range(self, n, bits):
        """
        Is n in range? -2**bits <= n < 2**bits
        """
        return -(1 << (bits-1)) <= n < (1 << (bits-1))
   
    def get_mem_str(self, loc):
        return 'x{0:04X}: {1:016b} {1:04x} '.format(loc, self.get_memory(loc))

    #def reg(self, s, n=1):
    #    return self.registers[s.rstrip(', ')] << self.reg_pos[n]

    def undefined(self, data):
        raise ValueError('Undefined Instruction: "%s"' % data)

    def valid_label(self, word):
        if word[0] == 'x' and word[1].isdigit():
            return False
        return (word[0].isalpha() and
                all(c.isalpha() or c.isdigit() or c in ['_', ':'] for c in word))

    def bitwise_and(self, value, mask):
        if value >= 0:
            if (value & ~mask) and self.warn:
                self.Error("Warning: Possible overflow of immediate: %s at line %s\n" % (value, self.source.get(self.get_pc(), "unknown")))
        else:
            if (-value & ~(mask >> 1)) and self.warn:
                self.Error("Warning: Possible overflow of immediate: %s at line %s\n" % (value, self.source.get(self.get_pc(), "unknown")))
        return (value & mask)

    def get_immediate(self, word, mask=0xFFFF):
        if (word.startswith('x') and
            all(n in '-0123456789abcdefgABCDEF' for n in word[1:])):
            if word[1] == "-":
                raw = (-int('0x' + word[2:], 0)) 
                return self.bitwise_and(raw, mask)
            else:
                raw = int('0' + word, 0)
                return  self.bitwise_and(raw, mask)
        elif word.startswith('#'):
            if word[1] == "-":
                raw = -int(word[2:])
                return self.bitwise_and(raw, mask)
            else:
                raw = int(word[1:])
                return self.bitwise_and(raw, mask)
        else:
            try:
                if word[0] == "-":
                    raw = -int(word[1:])
                    return self.bitwise_and(raw, mask)
                else:
                    raw = int(word)
                    return self.bitwise_and(raw, mask)
            except ValueError:
                # could be a label
                return

    def set_assembly_mode(self, mode):
        # clear out spare instructions
        for key in list(self.instruction_info.keys()):
            if (self.instruction_info[key] >> 12) == 0b1101:
                del self.instruction_info[key]
        for key in list(self.immediate.keys()):
            if (self.immediate[key] >> 12) == 0b1101:
                del self.immediate[key]
        # Add new instructions
        ## SHIFT DST, SRC, immed6
        ## TERMINAL SRC, 0/1=clear
        if mode == "SHIFT":
            # assembler:
            self.instruction_info["SHIFT"] = 0b1101 << 12
            self.immediate["SHIFT"] = 6
            # interpreter:
            self.cycles[0b1101] = 5  + 1
            self.apply[0b1101] = self.SHIFT
            self.format[0b1101] = self.SHIFT_format
        elif mode == "TERMINAL":
            # assembler:
            self.instruction_info["TERMINAL"] = 0b1101 << 12
            self.immediate["TERMINAL"] = 8
            # interpreter:
            self.cycles[0b1101] = 10  + 1
            self.apply[0b1101] = self.TERMINAL
            self.format[0b1101] = self.TERMINAL_format
        elif mode == "GRAPHICS":
            # assembler:
            self.instruction_info["CLEAR"]  = (0b1101 << 12) + (0b010 << 3)
            self.instruction_info["GETCUR"] = (0b1101 << 12) + (0b100 << 3)
            self.instruction_info["SETCUR"] = (0b1101 << 12) + (0b101 << 3)
            self.instruction_info["POKE"]   = (0b1101 << 12) + (0b001 << 3)
            self.instruction_info["PEEK"]   = (0b1101 << 12) + (0b000 << 3)
            self.immediate["SCREEN"] = 0
            self.immediate["CLEAR"] = 0
            self.immediate["GETCUR"] = 0
            self.immediate["SETCUR"] = 0
            self.immediate["POKE"] = 0
            self.immediate["PEEK"] = 0
            # interpreter:
            self.cycles[0b1101] = 5  + 1
            self.apply[0b1101] = self.SCREEN
            self.format[0b1101] = self.SCREEN_format
        else:
            raise ValueError("Invalid .SET MODE, '%s'. Use 'GRAPHICS', 'SHIFT', or 'TERMINAL'" % mode)
        self.instructions = self.instruction_info.keys()
        self.immediate_mask = {}
        for im in self.immediate:
            self.immediate_mask[im] = (1 << self.immediate[im]) - 1

    def process_instruction(self, words, line_count, line):
        """
        Process ready split words from line and parse the line use
        put to show the instruction line without label values
        """
        self.source[self.get_pc()] = line_count
        found = ''
        alltogether = "".join(words)
        alltogether1 = "".join(words[1:])
        if not words or words[0].startswith(';'):
            return
        elif is_bin(alltogether):
            ## Allow:
            ##  0001 000 000 0 00000
            ##  0001000000000000
            inst = eval("0b" + alltogether)
            self.set_instruction(self.get_pc(), inst, line_count)
            self.increment_pc()
            self.dump_mode = "dump"
            return
        elif len(words) > 1 and is_bin(alltogether1) and not self.is_keyword(words[0]):
            ## Allow:
            ##  LABEL 0001000000000000
            self.labels[self.make_label(words[0])] = self.get_pc()
            inst = eval("0b" + alltogether1)
            self.set_instruction(self.get_pc(), inst, line_count)
            self.increment_pc()
            self.dump_mode = "dump"
            return
        elif len(words) == 1 and is_hex(words[0]): 
            ## Allow:
            ##  x10F4
            inst = eval("0" + words[0])
            self.set_instruction(self.get_pc(), inst, line_count)
            self.increment_pc()
            self.dump_mode = "dump"
            return
        elif len(words) == 2 and is_hex(words[1]) and not self.is_keyword(words[0]):
            ## Allow:
            ##  LABEL x2045
            self.labels[self.make_label(words[0])] = self.get_pc()
            inst = eval("0" + words[1])
            self.set_instruction(self.get_pc(), inst, line_count)
            self.increment_pc()
            self.dump_mode = "dump"
            return
        elif '.FILL' in words:
            word = words[words.index('.FILL') + 1]
            try:
                self.set_instruction(self.get_pc(), int(word), line_count)
            except ValueError:
                value = self.get_immediate(word)
                if value is None:
                    label = self.make_label(word)
                    if label in self.label_location:
                        self.label_location[label].append([self.get_pc(), 0xFFFF, -1])
                    else:
                        self.label_location[label] = [[self.get_pc(), 0xFFFF, -1]]
                else:
                    self.set_memory(self.get_pc(), lc_bin(value))
            if words[0] != '.FILL':
                self.labels[self.make_label(words[0])] = self.get_pc()
            self.increment_pc()
            return    
        elif '.ORIG' in [word.upper() for word in words]:
            self.set_pc(int('0' + words[1]
                            if words[1].startswith('x')
                            else words[1], 0))
            self.orig = self.get_pc()
            self.breakpoints = {}
            self.line_count = 0
            self.dump_mode = "dis"
            self.reset_registers()
            return
        elif '.STRINGZ' in words:
            if self.valid_label(words[0]):
                self.labels[self.make_label(words[0])] = self.get_pc()
            #else:
                # no label... could be a block of .STRINGZ
                # raise ValueError('No label for .STRINGZ in line for PC = %s: %s, line #%s' % (lc_hex(self.get_pc()), line, line_count))
            s = line.split('"')
            string1 = string = s[1]
            # rejoin if "  inside quotes
            for st in s[2:]:
                if string.endswith('\\'):
                    string += '"' + st
    
            # encode backslash to get special characters
            backslash = False
            for c in string:
                if not backslash:
                    if c == '\\':
                        if not backslash:
                            backslash = True
                            continue
                    m = ord(c)
                else:
                    if c in 'nblr':
                        m = ord(c) - 100
                    else:
                        # easiest to implement:
                        # anything else escaped is itself (unlike Python)
                        m = ord(c)
    
                    backslash = False
                self.set_instruction(self.get_pc(), m, line_count)
                self.increment_pc()
            self.set_instruction(self.get_pc(), 0, line_count)
            self.increment_pc()
            return
        elif '.STRINGC' in words:
            if self.valid_label(words[0]):
                self.labels[self.make_label(words[0])] = self.get_pc()
            #else:
                # no label... could be a block of .STRINGZ
                # raise ValueError('No label for .STRINGZ in line for PC = %s: %s, line #%s' % (lc_hex(self.get_pc()), line, line_count))
            s = line.split('"')
            string1 = string = s[1]
            # rejoin if "  inside quotes
            for st in s[2:]:
                if string.endswith('\\'):
                    string += '"' + st
    
            # encode backslash to get special characters
            backslash = False
            count = 1
            last_m = None
            for c in string:
                if not backslash:
                    if c == '\\':
                        if not backslash:
                            backslash = True
                            continue
                    m = ord(c)
                else:
                    if c in 'nblr':
                        m = ord(c) - 100
                    else:
                        # easiest to implement:
                        # anything else escaped is itself (unlike Python)
                        m = ord(c)
    
                    backslash = False
                if count % 2 == 0:
                    self.set_instruction(self.get_pc(), m << 8 | last_m, line_count)
                    self.increment_pc()
                else:
                    last_m = m
                count += 1
            if count % 2 == 0:
                self.set_instruction(self.get_pc(), last_m, line_count)
                self.increment_pc()
            self.set_instruction(self.get_pc(), 0, line_count)
            self.increment_pc()
            return
        elif '.BLKW' in words:
            self.labels[self.make_label(words[0])] = self.get_pc()
            value = self.get_immediate(words[-1])
            if value is None or value <= 0:
                raise ValueError('Bad .BLKW immediate: "%s", %r' % (words[-1], value))
            self.increment_pc(value)
            return
        elif '.SET' == words[0]:
            if words[1] == "MODE":
                self.set_assembly_mode(words[2])
            return
        # -------------------------------------------------------------
        self.dump_mode = "dis"
        ind = -1
        if words[0].startswith('BR'):
            ind = 0
        elif words[1:] and words[1].startswith('BR'):
            ind = 1
        if ind >= 0 and len(words[ind]) <= 5:
            if all(c in self.flags for c in words[ind][2:].lower()):
                fl = 0
                # BR means BRnzp
                if words[ind] == 'BR':
                    words[ind] = 'BRnzp'
                for f in words[ind][2:].lower():
                    fl |= self.flags[f]
                words[ind] = 'BR'
        if words[0].upper() in self.instructions:
            found = words[0].upper()
        else:
            if self.valid_label(words[0]):
                self.labels[self.make_label(words[0])] = self.get_pc()
            else:
                raise ValueError('Invalid label "%s" in source line "%s", line #: %s' % (words[0], line, line_count))
            if len(words) < 2:
                return
            found = words[1] if words[1] in self.instructions else ''
        if not found:
            word = words[0]
            if len(words) > 1:
                raise ValueError('Not an instruction: "%s"' % line)
            else:
                if self.valid_label(word):
                    if self.make_label(word) in self.label_location:
                        # FIXME: ? is this same as .FILL?
                        self.label_location[self.make_label(word)].append([self.get_pc(), 0xFFFF, 16])
                    else:
                        self.label_location[self.make_label(word)] = [[self.get_pc(), 0xFFFF, 16]]
                else:
                    raise ValueError('Invalid label: "%r", line: %s' % (word, line))
            return
    
        try:
            instruction = self.instruction_info[found]
        except KeyError:
            raise ValueError('Unknown: instruction "%s"' % found)
        else:
            if found == 'BR':
                instruction |= fl
            r = rc = 0
            rc += found == 'JMPT'
        
            if found in self.special_reg_pos:
                reg_pos = self.special_reg_pos[found]
            else:
                reg_pos = self.reg_pos

            for word in words[1:]:
                word = word.rstrip(',')
                
                if word in self.regs:
                    if found == "JMP":
                        t = self.regs[word] << 6
                    else:
                        t = self.regs[word] << reg_pos[rc]
                    r |= t
                    rc += 1
                else:
                    value = self.get_immediate(word, self.immediate_mask[found])
                    if value is not None:
                        instruction |= value
                        # set the immediate bit in ADD and AND instruction:
                        if found in ('ADD', 'AND'): 
                            instruction |= 1 << 5
                    elif word != found:
                        if self.valid_label(word):
                            if self.make_label(word) in self.label_location:
                                self.label_location[self.make_label(word)].append([self.get_pc(), self.immediate_mask[found], self.immediate[found]])
                            else:
                                self.label_location[self.make_label(word)] = [[self.get_pc(), self.immediate_mask[found], self.immediate[found]]]
                        else:
                            raise ValueError('Invalid label: "%r", line: %s' % (word, line))
    
                instruction |= r
                if found == 'JMPT':
                    break
            self.set_instruction(self.get_pc(), instruction, line_count)
            self.increment_pc()
    
    def is_keyword(self, s):
        return (s in self.instruction_info.keys() or 
                s.startswith(".") or
                s in ["GETC", "OUT", "PUTS", "IN", "PUTSP", "HALT"])

    def assemble(self, code):
        self.source = {}
        self.labels = {}
        self.label_location = {}
        # processing the lines
        # first pass:
        for line in code.splitlines():
            # remove comments
            ## FIXME: can't do like this! Need a real parser:
            orig_line, line = line, line.split(';')[0] 
            # add space after comma to make sure registers are space separated also (not with strings)
            if '"' not in line:
                line = line.replace(',', ', ')
            # drop comments
            words = (line.split()) if ';' in line else line.split()
            if '.END' in words:
                break
            self.process_instruction(words, self.line_count, line)
            self.line_count += 1
        # second pass:
        for label, value in self.label_location.items():
            if label not in self.labels:
                raise ValueError('Bad label: "%s"' % label)
            else:
                for ref, mask, bits in value:
                    current = self.labels[label] - ref - 1
                    # kludge for absolute addresses,
                    # but seems correct for some code (lc3os.asm)
                    if self.get_memory(ref) == 0: # not instruction -> absolute
                        self.set_memory(ref, self.labels[label])
                    elif bits != -1 and not self.in_range(current, bits) :
                        raise ValueError(("Not an instruction: \"%s\", mask %s, offset %s,  %s, ref %s" %
                                (label,
                                bin(mask),
                                self.labels[label] - ref,
                                bin(self.labels[label]),
                                lc_hex(ref))))
                    else:
                        # FIXME: 
                        # Sets memory to value of label
                        # ref, mask, bits: [x4000, 511, 9], [x4000, FFFF, -1]
                        # where label was used in instruction
                        # requires init memory first
                        if bits == -1:
                            self.set_memory(ref, self.labels[label])
                        else:
                            self.set_memory(ref, 
                                            plus(self.get_memory(ref), 
                                                 lc_bin(mask & current)))

    def handleDebug(self, lineno):
        pass

    def Print(self, *args, end="\n"):
        print(*args, end=end)

    def Error(self, string):
        if self.kernel:
            self.kernel.Error(string)
        else:
            sys.stderr.write(string)

    def run(self, reset=True):
        if reset:
            self.cycle = 0
            self.instruction_count = 0
            self.set_memory(0xFE04, 0xFFFF) ## OS_DSR Display Ready
            self.set_memory(0xFE00, 0xFFFF) ## OS_KBSR Keyboard Ready
        self.cont = True
        self.suspended = False
        if self.debug:
            self.Print("Tracing Script! PC* is incremented Program Counter")
            self.Print("(Instr/Cycles Count) INSTR [source line] (PC*: xHEX)")
            self.Print("----------------------------------------------------")
        while self.cont:
            self.step()

    def step(self):
        if self.debug:
            self.Print("=" * 60)
            self.Print("Stepping...  => read, <= write, (Instructions/Cycles):")
            self.Print("=" * 60)
        pc = self.get_pc()
        self.handleDebug(self.source.get(pc, -1))
        instruction = self.get_memory(pc)
        instr = (instruction >> 12) & 0xF
        self.instruction_count += 1
        self.cycle += self.cycles[instr]
        self.increment_pc()
        if self.debug:
            line = self.source.get(pc, -1)
            line_str = (" [%s]" % line) if (line != -1) else ""
            self.Print("(%s/%s) %s%s (%s*: %s)" % (
                self.instruction_count, 
                self.cycle, 
                self.format[instr](instruction, pc), 
                line_str,
                lc_hex(self.get_pc()), 
                lc_hex(instruction)))
        #if (instr in self.apply):
        self.apply[instr](instruction)
        if self.pc in self.breakpoints:
            self.cont = False
            self.suspended = True
            self.Print("...breakpoint hit at", lc_hex(self.pc))

    def dump_registers(self):
        self.Print()
        self.Print("=" * 60)
        self.Print("Registers:")
        self.Print("=" * 60)
        self.Print("PC:", lc_hex(self.get_pc()))
        for r,v in zip("NZP", self.get_nzp()):
            self.Print("%s: %s" % (r,v), end=" ")
        self.Print()
        count = 1
        for key in range(8):
            self.Print("R%d: %s" % (key, lc_hex(self.get_register(key))), end=" ")
            if count % 4 == 0:
                self.Print()
            count += 1
    
    def dump(self, orig_start=None, orig_stop=None, raw=False, header=True):
        if orig_start is None:
            start = self.orig
        else:
            start = orig_start
        if orig_stop is None:
            stop = max(self.source.keys()) + 1
        else:
            stop = orig_stop + 1

        if stop <= start:
            stop = start + 10
        if stop - start > 100:
            stop = start + 100
        if raw or self.dump_mode == "dump":
            if header:
                self.Print("=" * 60)
                self.Print("Memory dump:")
                self.Print("=" * 60)
            for x in range(start, stop):
                self.Print("%-10s %s: %s" % ("", lc_hex(x), lc_hex(self.get_memory(x))))
        else:
            if header:
                self.Print("=" * 60)
                self.Print("Memory disassembled:")
                self.Print("=" * 60)
            for memory in range(start, stop):
                instruction = self.get_memory(memory)
                instr = (instruction >> 12) & 0xF
                label = self.lookup(memory, "")
                if label:
                    label = label + ":"
                instr_str = self.source.get(memory, "")
                if instr_str:
                    self.Print("%-10s %s: %s  %-41s [line: %s]" % (
                        label, lc_hex(memory), lc_hex(instruction), 
                        self.format[instr](instruction, memory), instr_str))
                else:
                    if instruction == 0:
                        ascii = "\\0"
                    else:
                        ascii = "%s %s" % (instruction, ascii_str(instruction))
                    self.Print("%-10s %s: %s - %s" % (
                        label, lc_hex(memory), lc_hex(instruction), ascii))

    def disassemble(self):
        start = min(self.source.keys())
        stop = max(self.source.keys()) + 1
        self.Print(".ORIG %s " % lc_hex(start))
        for memory in range(start, stop):
            instruction = self.get_memory(memory)
            instr = (instruction >> 12) & 0xF
            label = self.lookup(memory, "")
            if label:
                label = label + ":"
            self.Print("%-10s %s" % (label, self.format[instr](instruction, memory)))
        self.Print(".END")

    def lookup(self, location, default=None):
        for label in self.labels:
            if self.labels[label] == location:
                return label
        if default is None:
            return location
        else:
            return default

    def STR(self, instruction):
        src = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        offset6 = instruction & 0b0000000000111111
        self.set_memory(plus(self.get_register(base), sext(offset6, 6)),
                        self.get_register(src))

    def STR_format(self, instruction, location):
        src = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        offset6 = instruction & 0b0000000000111111
        return "STR R%d, R%d, %s" % (src, base, offset6)

    def RTI(self, instruction):
        if (self.psr & 0b1000000000000000):
            raise ValueError("priviledge mode exception")
        else:
            self.set_pc(self.get_memory(self.get_register(6))) # R6 is the SSP
            self.set_register(6, lc_bin(plus(self.get_register(6), 1)))
            temp = self.get_memory(self.get_register(6))
            self.set_register(6, lc_bin(plus(self.get_register(6), 1)))
            self.psr = temp

    def RTI_format(self, instruction, location):
        return "RTI"

    def NOT(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        src = (instruction & 0b0000000111000000) >> 6
        self.set_register(dst, lc_bin(~self.get_register(src)))
        self.set_nzp(self.get_register(dst))

    def NOT_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        src = (instruction & 0b0000000111000000) >> 6
        return "NOT R%d, R%d" % (dst, src)

    def LDI(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        location = plus(self.get_pc(), sext(pc_offset9, 9))
        memory1 = self.get_memory(location)
        memory2 = self.get_memory(memory1)
        if self.debug:
            self.Print("  Reading memory[x%04x] (x%04x) =>" % (location, memory1))
            self.Print("  Reading memory[x%04x] (x%04x) =>" % (memory1, memory2))
        self.set_register(dst, memory2)
        self.set_nzp(self.get_register(dst))        

    def LDI_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "LDI R%d, %s" % (dst, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def STI(self, instruction):
        src = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        memory = self.get_memory(plus(self.get_pc(), sext(pc_offset9,9)))
        self.set_memory(memory, self.get_register(src))
        ## Hook up, side effect display:
        if memory == 0xFE06: ## OS_DDR
            try:
                self.Print(chr(self.get_register(src)), end="")
            except:
                raise ValueError("value in R%d (%s) is not in range 0-255 (x00-xFF)" % (src, lc_hex(self.get_register(src))))
        
    def STI_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "STI R%d, %s" % (dst, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def RESERVED(self, instruction):
        raise ValueError("attempt to execute reserved instruction")

    def RESERVED_format(self, instruction, location):
        return ";; RESERVED %s %s" % (lc_hex((instruction >> 12) & 0xF), 
                                      lc_hex(instruction & 0b0000111111111111))

    def LEA(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        self.set_register(dst, lc_bin(plus(self.get_pc(), sext(pc_offset9,9))))
        self.set_nzp(self.get_register(dst))

    def LEA_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "LEA R%d, %s" % (dst, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def getc(self):
        ### No prompt for input:
        if len(self.char_buffer) == 0:
            data = self.kernel.raw_input()
            data = data.replace("\\n", "\n")
            if len(data) == 0:
                self.char_buffer = [0] # end of string
            elif len(data) == 1:
                self.char_buffer = [ord(char) for char in data] # single char mode
            else:
                self.char_buffer = [ord(char) for char in data] + [0]
        return self.char_buffer.pop(0)

    def TRAP(self, instruction):
        vector = instruction & 0b0000000011111111
        self.set_register(7, self.get_pc())
        self.set_pc(self.get_memory(vector))
        if vector == 0x20:
            self.set_memory(0xFE02, self.getc())
        elif vector == 0x21:
            pass
        elif vector == 0x22: # PUTS
            pass
        elif vector == 0x23:
            pass
        elif vector == 0x24: # PUTSP
            pass
        elif vector == 0x25:
            self.cont = False
        else:
            raise ValueError("invalid TRAP vector: %s" % lc_hex(vector))

    def TRAP_format(self, instruction, location):
        vector = instruction & 0b0000000011111111
        if vector == 0x20:
            return "GETC"
        elif vector == 0x21:
            return "OUT"
        elif vector == 0x22:
            return "PUTS"
        elif vector == 0x23:
            return "IN"
        elif vector == 0x24:
            return "PUTSP"
        elif vector == 0x25:
            return "HALT"
        else:
            return ";; Invalid TRAP vector: %s" % lc_hex(vector)

    def BR(self, instruction):
        n = instruction & 0b0000100000000000
        z = instruction & 0b0000010000000000
        p = instruction & 0b0000001000000000
        pc_offset9 = instruction & 0b0000000111111111
        if (not any([n, z, p])):
            if self.noop_error:
                raise Exception("Attempting to execute NOOP at %s\n" % lc_hex(self.get_pc() - 1))
            elif self.warn:
                self.Error("Attempting to execute NOOP at %s\n" % lc_hex(self.get_pc() - 1))
        if (n and self.get_nzp(0) or 
            z and self.get_nzp(1) or 
            p and self.get_nzp(2)):
            self.set_pc(plus(self.get_pc(), sext(pc_offset9,9)))
            if self.debug:
                self.Print("    True - branching to", lc_hex(self.get_pc()))
        else:
            if self.debug:
                self.Print("    False - continuing...")

    def BR_format(self, instruction, location):
        n = instruction & 0b0000100000000000
        z = instruction & 0b0000010000000000
        p = instruction & 0b0000001000000000
        pc_offset9 = instruction & 0b0000000111111111
        instr = "BR"
        if n:
            instr += "n"
        if z:
            instr += "z"
        if p:
            instr += "p"
        val = self.lookup(plus(sext(pc_offset9,9), location) + 1)
        ascii = ascii_str(pc_offset9)
        if not (n or z or p):
            return "NOOP - (no BR to %s) %s" % (lc_hex(val), ascii)
        else:
            return "%s %s %s" % (instr, lc_hex(val), ascii)

    def LD(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        location = plus(self.get_pc(), sext(pc_offset9,9))
        memory = self.get_memory(location)
        if self.debug:
            self.Print("  Reading memory[x%04x] (x%04x) =>" % (location, memory))
        self.set_register(dst, memory)
        self.set_nzp(self.get_register(dst))

    def LD_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "LD R%d, %s" % (dst, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def LDR(self, instruction):
        dst =  (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        offset6 = instruction & 0b0000000000111111
        location = plus(self.get_register(base), sext(offset6,6))
        memory = self.get_memory(location)
        if self.debug:
            self.Print("  Reading memory[x%04x] (x%04x) =>" % (location, memory))
        self.set_register(dst, memory)
        self.set_nzp(self.get_register(dst))

    def LDR_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        offset6 = instruction & 0b0000000000111111
        return "LDR R%d, R%d, %s" % (dst, base, offset6)

    def ST(self, instruction):
        src = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        self.set_memory(plus(self.get_pc(), sext(pc_offset9,9)), self.get_register(src))

    def ST_format(self, instruction, location):
        src = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "ST R%d, %s" % (src, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def JMP(self, instruction):
        base = (instruction & 0b0000000111000000) >> 6
        self.set_pc(self.get_register(base))

    def JMP_format(self, instruction, location):
        base = (instruction & 0b0000000111000000) >> 6
        if base == 7:
            return "RET"
        else:
            return "JMP R%d" % base

    def JSR(self, instruction):
        temp = self.get_pc()
        if (instruction & 0b0000100000000000): # JSR
            pc_offset11 = instruction & 0b0000011111111111
            self.set_pc(plus(self.get_pc(), sext(pc_offset11,11)))
        else:                                  # JSRR
            base = (instruction & 0b0000000111000000) >> 6
            self.set_pc(self.get_register(base))
        self.set_register(7, temp)

    def JSR_format(self, instruction, location):
        if (instruction & 0b0000100000000000): # JSR
            pc_offset11 = instruction & 0b0000011111111111
            return "JSR %s" % lc_hex(self.lookup(plus(sext(pc_offset11,11), location) + 1))
        else:                                  # JSRR
            base = (instruction & 0b0000000111000000) >> 6
            return "JSRR R%d" % base

    def ADD(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        sr1 = (instruction & 0b0000000111000000) >> 6
        if (instruction & 0b0000000000100000) == 0:
            sr2 = instruction & 0b0000000000000111
            self.set_register(dst, lc_bin(plus(self.get_register(sr1), 
                                               self.get_register(sr2))))
        else:
            imm5 = instruction & 0b0000000000011111
            self.set_register(dst, lc_bin(plus(self.get_register(sr1), sext(imm5, 5))))
        self.set_nzp(self.get_register(dst))

    def ADD_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        sr1 = (instruction & 0b0000000111000000) >> 6
        if (instruction & 0b0000000000100000):
            imm5 = instruction & 0b0000000000011111
            return "ADD R%d, R%d, #%s" % (dst, sr1, lc_int(sext(imm5, 5)))
        else:
            sr2 = instruction & 0b0000000000000111
            return "ADD R%d, R%d, R%d" % (dst, sr1, sr2)

    def AND(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        sr1 = (instruction & 0b0000000111000000) >> 6
        if (instruction & 0b0000000000100000) == 0:
            sr2 = instruction & 0b0000000000000111
            self.set_register(dst, self.get_register(sr1) & self.get_register(sr2))
        else:
            imm5 = instruction & 0b0000000000011111
            self.set_register(dst, self.get_register(sr1) & sext(imm5, 5))
        self.set_nzp(self.get_register(dst))

    def AND_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        sr1 = (instruction & 0b0000000111000000) >> 6
        if (instruction & 0b0000000000100000):
            imm5 = instruction & 0b0000000000011111
            return "AND R%d, R%d, #%s" % (dst, sr1, lc_int(sext(imm5, 5)))
        else:
            sr2 = instruction & 0b0000000000000111
            return "AND R%d, R%d, R%d" % (dst, sr1, sr2)

    def SHIFT(self, instruction):
        ## SHIFT DST, SRC, immed6
        dst = (instruction & 0b0000111000000000) >> 9
        src = (instruction & 0b0000000111000000) >> 6
        imm6 = lc_int(sext(instruction & 0b0000000000111111,6))
        if imm6 < 0: # arithmetic shift right preserves sign
            value = sext(self.get_register(src) >> -imm6, 16 + imm6)
            self.set_register(dst, value)
        else:
            self.set_register(dst, self.get_register(src) << imm6)
        self.set_nzp(self.get_register(dst))

    def TERMINAL(self, instruction):
        ## TERMINAL SRC, 1
        src = (instruction & 0b0000111000000000) >> 9
        clear = (instruction & 0b0000000000000001)
        string = ""
        location = self.get_register(src)
        memory = self.get_memory(location)
        while memory != 0:
            string += chr(memory & 0b0000000011111111)
            if memory & 0b1111111100000000:
                string += chr((memory & 0b1111111100000000) >> 8)
            location += 1
            memory = self.get_memory(location)
        self.kernel.Display(HTML("<pre>" + string + "</pre>"), clear_output=clear)

    def TERMINAL_format(self, instruction):
        ## TERMINAL SRC, 1
        src = (instruction & 0b0000111000000000) >> 9
        clear = (instruction & 0b0000000100000000)
        return "TERMINAL R%d, %d" % (src, clear)

    def SHIFT_format(self, instruction, location):
        ## SHIFT DST, SRC, DIR, immed4
        dst = (instruction & 0b0000111000000000) >> 9
        src = (instruction & 0b0000000111000000) >> 6
        imm6 = instruction & 0b0000000000111111
        return "SHIFT R%d, R%d, #%s" % (dst, src, lc_int(sext(imm6, 6)))

    def screen_set_cursor(self, x, y):
        pass

    def screen_get_cursor(self):
        return 0,0

    def screen_clear(self):
        pass

    def screen_poke(self, x, y, value):
        pass

    def screen_peek(self, x, y):
        return 0

    def SCREEN(self, instruction):
        ## SCREEN 
        if (instruction & 0b010 << 3): # CLEAR
            #CLEAR:  SCREEN ...,...,010,...
            self.screen_clear()
        elif (instruction & 0b100 << 3): # cursor
            #GETCUR: SCREEN Rx , Ry,100,...
            #SETCUR: SCREEN Rx , Ry,101,...
            if (instruction & 0b001 << 3): # setcur
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                self.screen_set_cursor(self.get_register(rx), self.get_register(ry))
            else:
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                x, y = self.screen_get_cursor()
                self.set_register(rx, x)
                self.set_register(ry, y)
        else: # peek/poke
            #POKE:   SCREEN Rx , Ry,001, RSRC
            #PEEK:   SCREEN Rx , Ry,000, RDST
            if (instruction & 0b001 << 3): # poke
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                src = (instruction & 0b0000000000000111) 
                self.screen_poke(self.get_register(rx), self.get_register(ry), self.get_register(src))
            else:
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                dst = (instruction & 0b0000000000000111) 
                self.set_register(dst, self.screen_peek(self.get_register(rx), self.get_register(ry)))

    def SCREEN_format(self, instruction, location):
        ## SCREEN 
        if (instruction & 0b010 << 3): # CLEAR
            #CLEAR:  SCREEN ...,...,010,...
            return "CLEAR"
        elif (instruction & 0b100 << 3): # cursor
            #GETCUR: SCREEN Rx , Ry,100,...
            #SETCUR: SCREEN Rx , Ry,101,...
            if (instruction & 0b001 << 3): # setcur
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                return "SETCUR R%d, R%d" % (rx, ry)
            else:
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                return "GETCUR R%d, R%d" % (rx, ry)
        else: # peek/poke
            #POKE:   SCREEN Rx , Ry,001, RSRC
            #PEEK:   SCREEN Rx , Ry,000, RDST
            if (instruction & 0b001 << 3): # poke
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                src = (instruction & 0b0000000000000111) 
                return "POKE R%d, R%d, R%d" % (rx, ry, src)
            else:
                rx = (instruction & 0b0000111000000000) >> 9
                ry = (instruction & 0b0000000111000000) >> 6
                dst = (instruction & 0b0000000000000111) 
                return "PEEK R%d, R%d, R%d" % (rx, ry, dst)

    def load(self, filename):
        self.filename = filename
        fp = open(filename)
        text = "".join(fp.readlines())
        fp.close()
        return text

    def execute_file(self, filename):
        text = self.load(filename)
        self.assemble(text)
        self.set_pc(self.orig)
        self.cycle = 0
        self.instruction_count = 0
        self.run()
        if self.suspended:
            self.Print("=" * 60)
            self.Print("Computation SUSPENDED")
            self.Print("=" * 60)
        else:
            self.Print("=" * 60)
            self.Print("Computation completed")
            self.Print("=" * 60)
        self.Print("Instructions:", self.instruction_count)
        self.Print("Cycles: %s (%f milliseconds)" % 
                   (self.cycle, self.cycle * 1./2000000))
        self.dump_registers()

    def save(self, base):
        # producing output
        # symbol list for Simulators
        with open(base + '.sym', 'w') as f:
            self.Print('''//Symbol Name		Page Address
//----------------	------------
//''', end='\t', file=f)
        
            self.Print('\n//\t'.join('\t%-20s%4x' % (name, value)
                            for name, value in self.labels.items()), file=f)
        
        with open(base + '.bin', 'w') as f:
            self.Print('{0:016b}'.format(self.orig), file=f)  # orig address
            self.Print('\n'.join('{0:016b}'.format(self.get_memory(m)) for m in range(self.orig, self.get_pc())),
                    file=f)
    
        # object file for running in Simulator
        with open(base + '.obj', 'wb') as f:
            #do slice from right after code and write
            #(byteorder of 0 does not matter)
            self.set_memory(self.get_pc(), self.orig)
            self.memory_byteswap()
            self.memory_tofile(self.get_pc(), self.get_pc() + 1, f)
            self.memory_tofile(self.orig,self.get_pc(), f)
            self.memory_byteswap()

    def execute(self, text):
        words = [word.strip() for word in text.split()]
        if words[0].startswith("%"):
            if words[0] == "%dump":
                try:
                    self.dump(*[int("0" + word, 16) for word in words[1:]], raw=True)
                except:
                    self.Error("Error; did you load code first?")
                return True
            elif words[0] == "%regs":
                try:
                    self.dump_registers()
                except:
                    self.Error("Error; did you load code first?")
                return True
            elif words[0] == "%dis":
                try:
                    self.dump(*[int("0" + word, 16) for word in words[1:]])
                except:
                    self.Error("Error; did you run load first?")
                return True
            elif words[0] == "%d":
                self.debug = not self.debug
                self.Print("Debug is now %s" % ["off", "on"][int(self.debug)])
                return True
            elif words[0] == "%noop":
                self.noop_error = not self.noop_error
                self.Print("NOOP is now %s" % ["a warning", "an error"][int(self.noop_error)])
                return True
            elif words[0] == "%pc":
                self.cycle = 0
                self.instruction_count = 0
                self.set_pc(int("0" + words[1], 16))
                self.dump_registers()
                return True
            elif words[0] == "%labels":
                print("Label", "Location")
                for key in self.labels:
                    print(key + ":", hex(self.labels[key]))
                print(self.label_location)
                return True
            elif words[0] == "%mem":
                location = int("0" + words[1], 16)
                self.set_memory(location, int("0" + words[2], 16))
                self.dump(location, location)
                return True
            elif words[0] == "%reg":
                self.set_register(int(words[1]), int("0" + words[2], 16))
                self.dump_registers()
                return True
            elif words[0] == "%warn":
                self.warn = bool(int(words[1]))
                return True
            elif words[0] == "%reset":
                self.initialize(runit=True)
                self.dump_registers()
                return True
            elif words[0] == "%step":
                orig_debug = self.debug
                self.debug = True
                if self.get_pc() in self.source:
                    lineno = self.source[self.get_pc()]
                    ## show trace
                self.step()
                self.debug = orig_debug
                self.dump_registers()
                return True
            elif words[0] == "%bp":
                if len(words) > 1:
                    if words[1] == "clear":
                        self.breakpoints = {}
                        self.Print("All breakpoints cleared")
                        return
                    location = int("0" + words[1], 16)
                    self.breakpoints[location] = True
                if self.breakpoints:
                    count = 1
                    self.Print("=" * 60)
                    self.Print("Breakpoints")
                    self.Print("=" * 60)
                    for memory in sorted(self.breakpoints.keys()):
                        self.Print("    %d) " % count, end="")
                        self.dump(memory, memory, header=False)
                        count += 1
                else:
                    self.Print("    No breakpoints set")
                return True
            elif words[0] == "%exe" or words[0] == "%cont":
                ok = False
                try:
                    # if .orig in code, then run, otherwise just assemble:
                    self.debug = False
                    if words[0] == "%exe":
                        self.char_buffer = []
                        self.cycle = 0
                        self.instruction_count = 0
                        self.set_pc(self.orig)
                        self.reset_registers()
                        self.run()
                    else:
                        self.run(reset=False)
                    if self.suspended:
                        self.Print("=" * 60)
                        self.Print("Computation SUSPENDED")
                        self.Print("=" * 60)
                    else:
                        self.Print("=" * 60)
                        self.Print("Computation completed")
                        self.Print("=" * 60)
                    self.Print("Instructions:", self.instruction_count)
                    self.Print("Cycles: %s (%f milliseconds)" % 
                          (self.cycle, self.cycle * 1./2000000))
                    self.dump_registers()
                    ok = True
                except Exception as exc:
                    if self.get_pc() - 1 in self.source:
                        self.Error("\nRuntime error:\n    line %s:\n%s" % 
                                   (self.source[self.get_pc() - 1], str(exc)))
                    else:
                        self.Error("\nRuntime error:\n    memory %s\n%s" % 
                                   (lc_hex(self.get_pc() - 1), str(exc)))
                    ok = False
                return ok
            else:
                self.Error("Invalid Interactive Magic Directive\nHint: %help")
                return False
        else:
            ### Else, must be code to assemble:
            self.labels = {}
            self.label_location = {}
            ok = False
            try:
                self.assemble(text)
                self.Print("Assembled! Use %dis or %dump to examine; use %exe to run.")
                #self.dump()
                #self.dump_registers()
                ok = True
            except Exception as exc:
                if self.get_pc() - 1 in self.source:
                    self.Error("\nAssemble error\n    line %s\n" % 
                               self.source[self.get_pc()])
                else:
                    self.Error("\nAssemble error\n    memory %s\n" % 
                               lc_hex(self.get_pc() - 1))
                self.Error(str(exc) + "\n")
                ok = False
        return ok

def get_os():
    return """
;##############################################################################
;#
;# lc3os.asm -- the LC-3 operating system
;#
;#  "Copyright (c) 2003 by Steven S. Lumetta."
;# 
;#  Permission to use, copy, modify, and distribute this software and its
;#  documentation for any purpose, without fee, and without written 
;#  agreement is hereby granted, provided that the above copyright notice
;#  and the following two paragraphs appear in all copies of this software,
;#  that the files COPYING and NO_WARRANTY are included verbatim with
;#  any distribution, and that the contents of the file README are included
;#  verbatim as part of a file named README with any distribution.
;#  
;#  IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, 
;#  INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT 
;#  OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE AUTHOR 
;#  HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;#  
;#  THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT 
;#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
;#  A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" 
;#  BASIS, AND THE AUTHOR NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, 
;#  UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
;#
;#  Author:		Steve Lumetta
;#  Version:		1
;#  Creation Date:	18 October 2003
;#  Filename:		lc3os.asm
;#  History:		
;# 	SSL	1	18 October 2003
;# 		Copyright notices and Gnu Public License marker added.
;#
;##############################################################################

	.ORIG x0000

; the TRAP vector table
	.FILL BAD_TRAP	; x00
	.FILL BAD_TRAP	; x01
	.FILL BAD_TRAP	; x02
	.FILL BAD_TRAP	; x03
	.FILL BAD_TRAP	; x04
	.FILL BAD_TRAP	; x05
	.FILL BAD_TRAP	; x06
	.FILL BAD_TRAP	; x07
	.FILL BAD_TRAP	; x08
	.FILL BAD_TRAP	; x09
	.FILL BAD_TRAP	; x0A
	.FILL BAD_TRAP	; x0B
	.FILL BAD_TRAP	; x0C
	.FILL BAD_TRAP	; x0D
	.FILL BAD_TRAP	; x0E
	.FILL BAD_TRAP	; x0F
	.FILL BAD_TRAP	; x10
	.FILL BAD_TRAP	; x11
	.FILL BAD_TRAP	; x12
	.FILL BAD_TRAP	; x13
	.FILL BAD_TRAP	; x14
	.FILL BAD_TRAP	; x15
	.FILL BAD_TRAP	; x16
	.FILL BAD_TRAP	; x17
	.FILL BAD_TRAP	; x18
	.FILL BAD_TRAP	; x19
	.FILL BAD_TRAP	; x1A
	.FILL BAD_TRAP	; x1B
	.FILL BAD_TRAP	; x1C
	.FILL BAD_TRAP	; x1D
	.FILL BAD_TRAP	; x1E
	.FILL BAD_TRAP	; x1F
	.FILL TRAP_GETC	; x20
	.FILL TRAP_OUT	; x21
	.FILL TRAP_PUTS	; x22
	.FILL TRAP_IN	; x23
	.FILL TRAP_PUTSP ; x24
	.FILL TRAP_HALT	; x25
	.FILL BAD_TRAP	; x26
	.FILL BAD_TRAP	; x27
	.FILL BAD_TRAP	; x28
	.FILL BAD_TRAP	; x29
	.FILL BAD_TRAP	; x2A
	.FILL BAD_TRAP	; x2B
	.FILL BAD_TRAP	; x2C
	.FILL BAD_TRAP	; x2D
	.FILL BAD_TRAP	; x2E
	.FILL BAD_TRAP	; x2F
	.FILL BAD_TRAP	; x30
	.FILL BAD_TRAP	; x31
	.FILL BAD_TRAP	; x32
	.FILL BAD_TRAP	; x33
	.FILL BAD_TRAP	; x34
	.FILL BAD_TRAP	; x35
	.FILL BAD_TRAP	; x36
	.FILL BAD_TRAP	; x37
	.FILL BAD_TRAP	; x38
	.FILL BAD_TRAP	; x39
	.FILL BAD_TRAP	; x3A
	.FILL BAD_TRAP	; x3B
	.FILL BAD_TRAP	; x3C
	.FILL BAD_TRAP	; x3D
	.FILL BAD_TRAP	; x3E
	.FILL BAD_TRAP	; x3F
	.FILL BAD_TRAP	; x40
	.FILL BAD_TRAP	; x41
	.FILL BAD_TRAP	; x42
	.FILL BAD_TRAP	; x43
	.FILL BAD_TRAP	; x44
	.FILL BAD_TRAP	; x45
	.FILL BAD_TRAP	; x46
	.FILL BAD_TRAP	; x47
	.FILL BAD_TRAP	; x48
	.FILL BAD_TRAP	; x49
	.FILL BAD_TRAP	; x4A
	.FILL BAD_TRAP	; x4B
	.FILL BAD_TRAP	; x4C
	.FILL BAD_TRAP	; x4D
	.FILL BAD_TRAP	; x4E
	.FILL BAD_TRAP	; x4F
	.FILL BAD_TRAP	; x50
	.FILL BAD_TRAP	; x51
	.FILL BAD_TRAP	; x52
	.FILL BAD_TRAP	; x53
	.FILL BAD_TRAP	; x54
	.FILL BAD_TRAP	; x55
	.FILL BAD_TRAP	; x56
	.FILL BAD_TRAP	; x57
	.FILL BAD_TRAP	; x58
	.FILL BAD_TRAP	; x59
	.FILL BAD_TRAP	; x5A
	.FILL BAD_TRAP	; x5B
	.FILL BAD_TRAP	; x5C
	.FILL BAD_TRAP	; x5D
	.FILL BAD_TRAP	; x5E
	.FILL BAD_TRAP	; x5F
	.FILL BAD_TRAP	; x60
	.FILL BAD_TRAP	; x61
	.FILL BAD_TRAP	; x62
	.FILL BAD_TRAP	; x63
	.FILL BAD_TRAP	; x64
	.FILL BAD_TRAP	; x65
	.FILL BAD_TRAP	; x66
	.FILL BAD_TRAP	; x67
	.FILL BAD_TRAP	; x68
	.FILL BAD_TRAP	; x69
	.FILL BAD_TRAP	; x6A
	.FILL BAD_TRAP	; x6B
	.FILL BAD_TRAP	; x6C
	.FILL BAD_TRAP	; x6D
	.FILL BAD_TRAP	; x6E
	.FILL BAD_TRAP	; x6F
	.FILL BAD_TRAP	; x70
	.FILL BAD_TRAP	; x71
	.FILL BAD_TRAP	; x72
	.FILL BAD_TRAP	; x73
	.FILL BAD_TRAP	; x74
	.FILL BAD_TRAP	; x75
	.FILL BAD_TRAP	; x76
	.FILL BAD_TRAP	; x77
	.FILL BAD_TRAP	; x78
	.FILL BAD_TRAP	; x79
	.FILL BAD_TRAP	; x7A
	.FILL BAD_TRAP	; x7B
	.FILL BAD_TRAP	; x7C
	.FILL BAD_TRAP	; x7D
	.FILL BAD_TRAP	; x7E
	.FILL BAD_TRAP	; x7F
	.FILL BAD_TRAP	; x80
	.FILL BAD_TRAP	; x81
	.FILL BAD_TRAP	; x82
	.FILL BAD_TRAP	; x83
	.FILL BAD_TRAP	; x84
	.FILL BAD_TRAP	; x85
	.FILL BAD_TRAP	; x86
	.FILL BAD_TRAP	; x87
	.FILL BAD_TRAP	; x88
	.FILL BAD_TRAP	; x89
	.FILL BAD_TRAP	; x8A
	.FILL BAD_TRAP	; x8B
	.FILL BAD_TRAP	; x8C
	.FILL BAD_TRAP	; x8D
	.FILL BAD_TRAP	; x8E
	.FILL BAD_TRAP	; x8F
	.FILL BAD_TRAP	; x90
	.FILL BAD_TRAP	; x91
	.FILL BAD_TRAP	; x92
	.FILL BAD_TRAP	; x93
	.FILL BAD_TRAP	; x94
	.FILL BAD_TRAP	; x95
	.FILL BAD_TRAP	; x96
	.FILL BAD_TRAP	; x97
	.FILL BAD_TRAP	; x98
	.FILL BAD_TRAP	; x99
	.FILL BAD_TRAP	; x9A
	.FILL BAD_TRAP	; x9B
	.FILL BAD_TRAP	; x9C
	.FILL BAD_TRAP	; x9D
	.FILL BAD_TRAP	; x9E
	.FILL BAD_TRAP	; x9F
	.FILL BAD_TRAP	; xA0
	.FILL BAD_TRAP	; xA1
	.FILL BAD_TRAP	; xA2
	.FILL BAD_TRAP	; xA3
	.FILL BAD_TRAP	; xA4
	.FILL BAD_TRAP	; xA5
	.FILL BAD_TRAP	; xA6
	.FILL BAD_TRAP	; xA7
	.FILL BAD_TRAP	; xA8
	.FILL BAD_TRAP	; xA9
	.FILL BAD_TRAP	; xAA
	.FILL BAD_TRAP	; xAB
	.FILL BAD_TRAP	; xAC
	.FILL BAD_TRAP	; xAD
	.FILL BAD_TRAP	; xAE
	.FILL BAD_TRAP	; xAF
	.FILL BAD_TRAP	; xB0
	.FILL BAD_TRAP	; xB1
	.FILL BAD_TRAP	; xB2
	.FILL BAD_TRAP	; xB3
	.FILL BAD_TRAP	; xB4
	.FILL BAD_TRAP	; xB5
	.FILL BAD_TRAP	; xB6
	.FILL BAD_TRAP	; xB7
	.FILL BAD_TRAP	; xB8
	.FILL BAD_TRAP	; xB9
	.FILL BAD_TRAP	; xBA
	.FILL BAD_TRAP	; xBB
	.FILL BAD_TRAP	; xBC
	.FILL BAD_TRAP	; xBD
	.FILL BAD_TRAP	; xBE
	.FILL BAD_TRAP	; xBF
	.FILL BAD_TRAP	; xC0
	.FILL BAD_TRAP	; xC1
	.FILL BAD_TRAP	; xC2
	.FILL BAD_TRAP	; xC3
	.FILL BAD_TRAP	; xC4
	.FILL BAD_TRAP	; xC5
	.FILL BAD_TRAP	; xC6
	.FILL BAD_TRAP	; xC7
	.FILL BAD_TRAP	; xC8
	.FILL BAD_TRAP	; xC9
	.FILL BAD_TRAP	; xCA
	.FILL BAD_TRAP	; xCB
	.FILL BAD_TRAP	; xCC
	.FILL BAD_TRAP	; xCD
	.FILL BAD_TRAP	; xCE
	.FILL BAD_TRAP	; xCF
	.FILL BAD_TRAP	; xD0
	.FILL BAD_TRAP	; xD1
	.FILL BAD_TRAP	; xD2
	.FILL BAD_TRAP	; xD3
	.FILL BAD_TRAP	; xD4
	.FILL BAD_TRAP	; xD5
	.FILL BAD_TRAP	; xD6
	.FILL BAD_TRAP	; xD7
	.FILL BAD_TRAP	; xD8
	.FILL BAD_TRAP	; xD9
	.FILL BAD_TRAP	; xDA
	.FILL BAD_TRAP	; xDB
	.FILL BAD_TRAP	; xDC
	.FILL BAD_TRAP	; xDD
	.FILL BAD_TRAP	; xDE
	.FILL BAD_TRAP	; xDF
	.FILL BAD_TRAP	; xE0
	.FILL BAD_TRAP	; xE1
	.FILL BAD_TRAP	; xE2
	.FILL BAD_TRAP	; xE3
	.FILL BAD_TRAP	; xE4
	.FILL BAD_TRAP	; xE5
	.FILL BAD_TRAP	; xE6
	.FILL BAD_TRAP	; xE7
	.FILL BAD_TRAP	; xE8
	.FILL BAD_TRAP	; xE9
	.FILL BAD_TRAP	; xEA
	.FILL BAD_TRAP	; xEB
	.FILL BAD_TRAP	; xEC
	.FILL BAD_TRAP	; xED
	.FILL BAD_TRAP	; xEE
	.FILL BAD_TRAP	; xEF
	.FILL BAD_TRAP	; xF0
	.FILL BAD_TRAP	; xF1
	.FILL BAD_TRAP	; xF2
	.FILL BAD_TRAP	; xF3
	.FILL BAD_TRAP	; xF4
	.FILL BAD_TRAP	; xF5
	.FILL BAD_TRAP	; xF6
	.FILL BAD_TRAP	; xF7
	.FILL BAD_TRAP	; xF8
	.FILL BAD_TRAP	; xF9
	.FILL BAD_TRAP	; xFA
	.FILL BAD_TRAP	; xFB
	.FILL BAD_TRAP	; xFC
	.FILL BAD_TRAP	; xFD
	.FILL BAD_TRAP	; xFE
	.FILL BAD_TRAP	; xFF

; the interrupt vector table
	.FILL INT_PRIV	; x00
	.FILL INT_ILL	; x01
	.FILL BAD_INT	; x02
	.FILL BAD_INT	; x03
	.FILL BAD_INT	; x04
	.FILL BAD_INT	; x05
	.FILL BAD_INT	; x06
	.FILL BAD_INT	; x07
	.FILL BAD_INT	; x08
	.FILL BAD_INT	; x09
	.FILL BAD_INT	; x0A
	.FILL BAD_INT	; x0B
	.FILL BAD_INT	; x0C
	.FILL BAD_INT	; x0D
	.FILL BAD_INT	; x0E
	.FILL BAD_INT	; x0F
	.FILL BAD_INT	; x10
	.FILL BAD_INT	; x11
	.FILL BAD_INT	; x12
	.FILL BAD_INT	; x13
	.FILL BAD_INT	; x14
	.FILL BAD_INT	; x15
	.FILL BAD_INT	; x16
	.FILL BAD_INT	; x17
	.FILL BAD_INT	; x18
	.FILL BAD_INT	; x19
	.FILL BAD_INT	; x1A
	.FILL BAD_INT	; x1B
	.FILL BAD_INT	; x1C
	.FILL BAD_INT	; x1D
	.FILL BAD_INT	; x1E
	.FILL BAD_INT	; x1F
	.FILL BAD_INT	; x20
	.FILL BAD_INT	; x21
	.FILL BAD_INT	; x22
	.FILL BAD_INT	; x23
	.FILL BAD_INT   ; x24
	.FILL BAD_INT	; x25
	.FILL BAD_INT	; x26
	.FILL BAD_INT	; x27
	.FILL BAD_INT	; x28
	.FILL BAD_INT	; x29
	.FILL BAD_INT	; x2A
	.FILL BAD_INT	; x2B
	.FILL BAD_INT	; x2C
	.FILL BAD_INT	; x2D
	.FILL BAD_INT	; x2E
	.FILL BAD_INT	; x2F
	.FILL BAD_INT	; x30
	.FILL BAD_INT	; x31
	.FILL BAD_INT	; x32
	.FILL BAD_INT	; x33
	.FILL BAD_INT	; x34
	.FILL BAD_INT	; x35
	.FILL BAD_INT	; x36
	.FILL BAD_INT	; x37
	.FILL BAD_INT	; x38
	.FILL BAD_INT	; x39
	.FILL BAD_INT	; x3A
	.FILL BAD_INT	; x3B
	.FILL BAD_INT	; x3C
	.FILL BAD_INT	; x3D
	.FILL BAD_INT	; x3E
	.FILL BAD_INT	; x3F
	.FILL BAD_INT	; x40
	.FILL BAD_INT	; x41
	.FILL BAD_INT	; x42
	.FILL BAD_INT	; x43
	.FILL BAD_INT	; x44
	.FILL BAD_INT	; x45
	.FILL BAD_INT	; x46
	.FILL BAD_INT	; x47
	.FILL BAD_INT	; x48
	.FILL BAD_INT	; x49
	.FILL BAD_INT	; x4A
	.FILL BAD_INT	; x4B
	.FILL BAD_INT	; x4C
	.FILL BAD_INT	; x4D
	.FILL BAD_INT	; x4E
	.FILL BAD_INT	; x4F
	.FILL BAD_INT	; x50
	.FILL BAD_INT	; x51
	.FILL BAD_INT	; x52
	.FILL BAD_INT	; x53
	.FILL BAD_INT	; x54
	.FILL BAD_INT	; x55
	.FILL BAD_INT	; x56
	.FILL BAD_INT	; x57
	.FILL BAD_INT	; x58
	.FILL BAD_INT	; x59
	.FILL BAD_INT	; x5A
	.FILL BAD_INT	; x5B
	.FILL BAD_INT	; x5C
	.FILL BAD_INT	; x5D
	.FILL BAD_INT	; x5E
	.FILL BAD_INT	; x5F
	.FILL BAD_INT	; x60
	.FILL BAD_INT	; x61
	.FILL BAD_INT	; x62
	.FILL BAD_INT	; x63
	.FILL BAD_INT	; x64
	.FILL BAD_INT	; x65
	.FILL BAD_INT	; x66
	.FILL BAD_INT	; x67
	.FILL BAD_INT	; x68
	.FILL BAD_INT	; x69
	.FILL BAD_INT	; x6A
	.FILL BAD_INT	; x6B
	.FILL BAD_INT	; x6C
	.FILL BAD_INT	; x6D
	.FILL BAD_INT	; x6E
	.FILL BAD_INT	; x6F
	.FILL BAD_INT	; x70
	.FILL BAD_INT	; x71
	.FILL BAD_INT	; x72
	.FILL BAD_INT	; x73
	.FILL BAD_INT	; x74
	.FILL BAD_INT	; x75
	.FILL BAD_INT	; x76
	.FILL BAD_INT	; x77
	.FILL BAD_INT	; x78
	.FILL BAD_INT	; x79
	.FILL BAD_INT	; x7A
	.FILL BAD_INT	; x7B
	.FILL BAD_INT	; x7C
	.FILL BAD_INT	; x7D
	.FILL BAD_INT	; x7E
	.FILL BAD_INT	; x7F
	.FILL BAD_INT	; x80
	.FILL BAD_INT	; x81
	.FILL BAD_INT	; x82
	.FILL BAD_INT	; x83
	.FILL BAD_INT	; x84
	.FILL BAD_INT	; x85
	.FILL BAD_INT	; x86
	.FILL BAD_INT	; x87
	.FILL BAD_INT	; x88
	.FILL BAD_INT	; x89
	.FILL BAD_INT	; x8A
	.FILL BAD_INT	; x8B
	.FILL BAD_INT	; x8C
	.FILL BAD_INT	; x8D
	.FILL BAD_INT	; x8E
	.FILL BAD_INT	; x8F
	.FILL BAD_INT	; x90
	.FILL BAD_INT	; x91
	.FILL BAD_INT	; x92
	.FILL BAD_INT	; x93
	.FILL BAD_INT	; x94
	.FILL BAD_INT	; x95
	.FILL BAD_INT	; x96
	.FILL BAD_INT	; x97
	.FILL BAD_INT	; x98
	.FILL BAD_INT	; x99
	.FILL BAD_INT	; x9A
	.FILL BAD_INT	; x9B
	.FILL BAD_INT	; x9C
	.FILL BAD_INT	; x9D
	.FILL BAD_INT	; x9E
	.FILL BAD_INT	; x9F
	.FILL BAD_INT	; xA0
	.FILL BAD_INT	; xA1
	.FILL BAD_INT	; xA2
	.FILL BAD_INT	; xA3
	.FILL BAD_INT	; xA4
	.FILL BAD_INT	; xA5
	.FILL BAD_INT	; xA6
	.FILL BAD_INT	; xA7
	.FILL BAD_INT	; xA8
	.FILL BAD_INT	; xA9
	.FILL BAD_INT	; xAA
	.FILL BAD_INT	; xAB
	.FILL BAD_INT	; xAC
	.FILL BAD_INT	; xAD
	.FILL BAD_INT	; xAE
	.FILL BAD_INT	; xAF
	.FILL BAD_INT	; xB0
	.FILL BAD_INT	; xB1
	.FILL BAD_INT	; xB2
	.FILL BAD_INT	; xB3
	.FILL BAD_INT	; xB4
	.FILL BAD_INT	; xB5
	.FILL BAD_INT	; xB6
	.FILL BAD_INT	; xB7
	.FILL BAD_INT	; xB8
	.FILL BAD_INT	; xB9
	.FILL BAD_INT	; xBA
	.FILL BAD_INT	; xBB
	.FILL BAD_INT	; xBC
	.FILL BAD_INT	; xBD
	.FILL BAD_INT	; xBE
	.FILL BAD_INT	; xBF
	.FILL BAD_INT	; xC0
	.FILL BAD_INT	; xC1
	.FILL BAD_INT	; xC2
	.FILL BAD_INT	; xC3
	.FILL BAD_INT	; xC4
	.FILL BAD_INT	; xC5
	.FILL BAD_INT	; xC6
	.FILL BAD_INT	; xC7
	.FILL BAD_INT	; xC8
	.FILL BAD_INT	; xC9
	.FILL BAD_INT	; xCA
	.FILL BAD_INT	; xCB
	.FILL BAD_INT	; xCC
	.FILL BAD_INT	; xCD
	.FILL BAD_INT	; xCE
	.FILL BAD_INT	; xCF
	.FILL BAD_INT	; xD0
	.FILL BAD_INT	; xD1
	.FILL BAD_INT	; xD2
	.FILL BAD_INT	; xD3
	.FILL BAD_INT	; xD4
	.FILL BAD_INT	; xD5
	.FILL BAD_INT	; xD6
	.FILL BAD_INT	; xD7
	.FILL BAD_INT	; xD8
	.FILL BAD_INT	; xD9
	.FILL BAD_INT	; xDA
	.FILL BAD_INT	; xDB
	.FILL BAD_INT	; xDC
	.FILL BAD_INT	; xDD
	.FILL BAD_INT	; xDE
	.FILL BAD_INT	; xDF
	.FILL BAD_INT	; xE0
	.FILL BAD_INT	; xE1
	.FILL BAD_INT	; xE2
	.FILL BAD_INT	; xE3
	.FILL BAD_INT	; xE4
	.FILL BAD_INT	; xE5
	.FILL BAD_INT	; xE6
	.FILL BAD_INT	; xE7
	.FILL BAD_INT	; xE8
	.FILL BAD_INT	; xE9
	.FILL BAD_INT	; xEA
	.FILL BAD_INT	; xEB
	.FILL BAD_INT	; xEC
	.FILL BAD_INT	; xED
	.FILL BAD_INT	; xEE
	.FILL BAD_INT	; xEF
	.FILL BAD_INT	; xF0
	.FILL BAD_INT	; xF1
	.FILL BAD_INT	; xF2
	.FILL BAD_INT	; xF3
	.FILL BAD_INT	; xF4
	.FILL BAD_INT	; xF5
	.FILL BAD_INT	; xF6
	.FILL BAD_INT	; xF7
	.FILL BAD_INT	; xF8
	.FILL BAD_INT	; xF9
	.FILL BAD_INT	; xFA
	.FILL BAD_INT	; xFB
	.FILL BAD_INT	; xFC
	.FILL BAD_INT	; xFD
	.FILL BAD_INT	; xFE
	.FILL BAD_INT	; xFF


OS_START	; machine starts executing at x0200
	LEA R0,OS_START_MSG	; print a welcome message
	PUTS
	HALT

OS_START_MSG	.STRINGZ "\\nWelcome to the LC-3 simulator.\\n\\nThe contents of the LC-3 tools distribution, including sources, management\\ntools, and data, are Copyright (c) 2003 Steven S. Lumetta.\\n\\nThe LC-3 tools distribution is free software covered by the GNU General\\nPublic License, and you are welcome to modify it and/or distribute copies\\nof it under certain conditions.  The file COPYING (distributed with the\\ntools) specifies those conditions.  There is absolutely no warranty for\\nthe LC-3 tools distribution, as described in the file NO_WARRANTY (also\\ndistributed with the tools).\\n\\nHave fun.\\n"

OS_KBSR	.FILL xFE00
OS_KBDR	.FILL xFE02
OS_DSR	.FILL xFE04
OS_DDR	.FILL xFE06
OS_MCR	.FILL xFFFE
MASK_HI .FILL x7FFF
LOW_8_BITS .FILL x00FF
TOUT_R1 .BLKW 1
TIN_R7  .BLKW 1
OS_R0   .BLKW 1
OS_R1   .BLKW 1
OS_R2   .BLKW 1
OS_R3   .BLKW 1
OS_R7   .BLKW 1


TRAP_GETC
	LDI R0,OS_KBSR		; wait for a keystroke
	BRzp TRAP_GETC
	LDI R0,OS_KBDR		; read it and return
	RET

TRAP_OUT
	ST R1,TOUT_R1		; save R1
TRAP_OUT_WAIT
	LDI R1,OS_DSR		; wait for the display to be ready
	BRzp TRAP_OUT_WAIT
	STI R0,OS_DDR		; write the character and return
	LD R1,TOUT_R1		; restore R1
	RET

TRAP_PUTS
	ST R0,OS_R0		; save R0, R1, and R7
	ST R1,OS_R1
	ST R7,OS_R7
	ADD R1,R0,#0		; move string pointer (R0) into R1

TRAP_PUTS_LOOP
	LDR R0,R1,#0		; write characters in string using OUT
	BRz TRAP_PUTS_DONE
	OUT
	ADD R1,R1,#1
	BRnzp TRAP_PUTS_LOOP

TRAP_PUTS_DONE
	LD R0,OS_R0		; restore R0, R1, and R7
	LD R1,OS_R1
	LD R7,OS_R7
	RET

TRAP_IN
	ST R7,TIN_R7		; save R7 (no need to save R0, since we 
				;    overwrite later
	LEA R0,TRAP_IN_MSG	; prompt for input
	PUTS
	GETC			; read a character
	OUT			; echo back to monitor
	ST R0,OS_R0		; save the character
	AND R0,R0,#0		; write a linefeed, too
	ADD R0,R0,#10
	OUT
	LD R0,OS_R0		; restore the character
	LD R7,TIN_R7		; restore R7
	RET

TRAP_PUTSP
	; NOTE: This trap will end when it sees any NUL, even in
	; packed form, despite the P&P second edition's requirement
	; of a double NUL.

	ST R0,OS_R0		; save R0, R1, R2, R3, and R7
	ST R1,OS_R1
	ST R2,OS_R2
	ST R3,OS_R3
	ST R7,OS_R7
	ADD R1,R0,#0		; move string pointer (R0) into R1

TRAP_PUTSP_LOOP
	LDR R2,R1,#0		; read the next two characters
	LD R0,LOW_8_BITS	; use mask to get low byte
	AND R0,R0,R2		; if low byte is NUL, quit printing
	BRz TRAP_PUTSP_DONE
	OUT			; otherwise print the low byte

	AND R0,R0,#0		; shift high byte into R0
	ADD R3,R0,#8
TRAP_PUTSP_S_LOOP
	ADD R0,R0,R0		; shift R0 left
	ADD R2,R2,#0		; move MSB from R2 into R0
	BRzp TRAP_PUTSP_MSB_0
	ADD R0,R0,#1
TRAP_PUTSP_MSB_0
	ADD R2,R2,R2		; shift R2 left
	ADD R3,R3,#-1
	BRp TRAP_PUTSP_S_LOOP

	ADD R0,R0,#0		; if high byte is NUL, quit printing
	BRz TRAP_PUTSP_DONE
	OUT			; otherwise print the low byte

	ADD R1,R1,#1		; and keep going
	BRnzp TRAP_PUTSP_LOOP

TRAP_PUTSP_DONE
	LD R0,OS_R0		; restore R0, R1, R2, R3, and R7
	LD R1,OS_R1
	LD R2,OS_R2
	LD R3,OS_R3
	LD R7,OS_R7
	RET

TRAP_HALT	
	; an infinite loop of lowering OS_MCR's MSB
	LEA R0,TRAP_HALT_MSG	; give a warning
	PUTS
	LDI R0,OS_MCR		; halt the machine
	LD R1,MASK_HI
	AND R0,R0,R1
	STI R0,OS_MCR
	HALT ;; BRnzp TRAP_HALT		; HALT again...

BAD_TRAP
	; print an error message, then HALT
	LEA R0,BAD_TRAP_MSG	; give an error message
	PUTS
	BRnzp TRAP_HALT		; execute HALT

	; interrupts aren't really defined, since privilege doesn't
	; quite work
INT_PRIV	RTI
INT_ILL		RTI
BAD_INT		RTI

TRAP_IN_MSG	.STRINGZ "\\nInput a character> "
TRAP_HALT_MSG	.STRINGZ "\\n\\n--- halting the LC-3 ---\\n\\n"
BAD_TRAP_MSG	.STRINGZ "\\n\\n--- undefined trap executed ---\\n\\n"

	.END
"""
