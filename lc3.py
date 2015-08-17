"""
This code based on:
http://www.daniweb.com/software-development/python/code/367871/
assembler-for-little-computer-3-lc-3-in-python

Order of BRanch flags relaxed, BR without flags interpreted as BRnzp
(always).
"""

from array import array
import traceback
import os
import sys

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
        'JSR': 0b01001 << 11,
        'JSRR': 0b010000 << 9,
        'LD': 0b0010 << 12,
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
        'SHIFT': 6,
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

    def __init__(self):
        # Functions for interpreting instructions:
        self.char_buffer = []
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
    def initialize(self):
        self.filename = ""
        self.debug = False
        self.meta = False
        self.warn = True
        self.noop_error = True
        self.orig = 0x3000
        self.source = {}
        self.cycle = 0
        self.pc = HEX(0x3000)
        self.cont = False
        self.instruction_count = 0
        self.immediate_mask = {}
        for im in self.immediate:
            self.immediate_mask[im] = (1 << self.immediate[im]) - 1
        self.instructions = self.instruction_info.keys()
        self.regs = dict(('R%1i' % r, r) for r in range(8))
        self.labels = {}
        self.label_location = {}
        self.register = {0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0}
        self.reset_memory() # assembles OS
        self.reset_registers()
        self.set_pc(0x3000)

    def reset_memory(self, filename=None):
        if filename is None:
            filename = os.path.join(os.path.dirname(__file__), "lc3os.asm")
        text = "".join(open(filename).readlines())
        debug = self.debug 
        self.debug = self.meta
        self.memory = array('i', [0] * (1 << 16))
        # We reset these items here and below because of 
        # bug (related to hack in interpreter?)
        self.source = {}
        self.labels = {}
        self.label_location = {}
        self.assemble(text)
        self.debug = debug
        #self.set_pc(0x0200)
        #self.run()
        self.source = {}
        self.labels = {}
        self.label_location = {}

    def reset_registers(self):
        debug = self.debug
        self.debug = self.meta
        for i in range(8):
            self.set_register(i, 0)
        self.set_nzp(0)
        self.debug = debug
        
    def _set_nzp(self, value):
        self.nzp = (int(value & (1 << 15) > 0), 
                    int(value == 0), 
                    int((value & (1 << 15) == 0) and value != 0))

    def set_nzp(self, value):
        self._set_nzp(value)
        if self.debug:
            print("    NZP <=", self.get_nzp())

    def get_nzp(self, register=None):
        if register is not None:
            return self.nzp[register]
        else:
            return self.nzp

    def get_pc(self):
        return self.pc

    def set_pc(self, value):
        self._set_pc(value)
        if self.debug:
            print("    PC <= %s" % lc_hex(value))

    def _set_pc(self, value):
        self.pc = HEX(value)

    def increment_pc(self, value=1):
        self.set_pc(self.get_pc() + value)

    def get_register(self, position):
        return self.register[position]

    def _set_register(self, position, value):
        self.register[position] = value

    def set_register(self, position, value):
        self._set_register(position, value)
        if self.debug:
            print("    R%d <= %s" % (position, lc_hex(value)))

    def set_instruction(self, location, n, line):
        """
        Put n into memory[location]; also checks to to make sure represented 
        correctly.
        """
        self.set_memory(location, lc_bin(n))

    def get_memory(self, location):
        return self.memory[location]

    def _set_memory(self, location, value):
        self.memory[location] = value

    def set_memory(self, location, value):
        self._set_memory(location, value)
        if self.debug:
            print("    memory[%s] <= %s" % (lc_hex(location), lc_hex(value)))

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

    def reg(self, s, n=1):
        return self.registers[s.rstrip(', ')] << self.reg_pos[n]

    def undefined(self, data):
        raise ValueError('Undefined Instruction')

    def valid_label(self, word):
        if word[0] == 'x' and word[1].isdigit():
            return False
        return (word[0].isalpha() and
                all(c.isalpha() or c.isdigit() or c in ['_', ':'] for c in word))

    def bitwise_and(self, value, mask):
        if value >= 0:
            if (value & ~mask) and self.warn:
                self.Error("Overflow immediate: %s at line %s\n" % (value, self.source.get(self.get_pc(), "unknown")))
        else:
            if (-value & ~(mask >> 1)) and self.warn:
                self.Error("Overflow immediate: %s at line %s\n" % (value, self.source.get(self.get_pc(), "unknown")))
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
        for key in self.instruction_info.keys():
            if (self.instruction_info[key] >> 12) == 0b1101:
                del self.instruction_info[key]
        for key in self.immediate.keys():
            if (self.immediate[key] >> 12) == 0b1101:
                del self.immediate[key]
        # Add new instructions
        if mode == "SHIFT":
            # assembler:
            self.instruction_info["SHIFT"] = 0b1101 << 12
            self.immediate["SHIFT"] = 6
            # interpreter:
            self.cycles[0b1101] = 5  + 1
            self.apply[0b1101] = self.SHIFT
            self.format[0b1101] = self.SHIFT_format
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
            raise ValueError("Invalid .SET MODE, '%s'. Use 'GRAPHICS' or 'SHIFT'" % mode)
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
        if not words or words[0].startswith(';'):
            return
        elif '.FILL' in words:
            word = words[words.index('.FILL') + 1]
            try:
                self.set_instruction(self.get_pc(), int(word), line_count)
            except ValueError:
                value = self.get_immediate(word)
                if value is None:
                    if self.make_label(word) in self.label_location:
                        self.label_location[self.make_label(word)].append([self.get_pc(), 0xFFFF, 16])
                    else:
                        self.label_location[self.make_label(word)] = [[self.get_pc(), 0xFFFF, 16]]
                else:
                    self.set_memory(self.get_pc(), lc_bin(value))
            if words[0] != '.FILL':
                self.labels[self.make_label(words[0])] = self.get_pc()
            self.increment_pc()
            return    
        elif '.ORIG' in words:
            self.set_pc(int('0' + words[1]
                            if words[1].startswith('x')
                            else words[1], 0))
            self.orig = self.get_pc()
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
        elif '.BLKW' in words:
            self.labels[self.make_label(words[0])] = self.get_pc()
            value = self.get_immediate(words[-1])
            if value is None or value <= 0:
                raise ValueError('Bad .BLKW immediate: %s, %r' % (words[-1], value))
            self.increment_pc(value)
            return
        elif '.SET' == words[0]:
            if words[1] == "MODE":
                self.set_assembly_mode(words[2])
            return
        # -------------------------------------------------------------
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
        if words[0] in self.instructions:
            found = words[0]
        else:
            if self.valid_label(words[0]):
                self.labels[self.make_label(words[0])] = self.get_pc()
            else:
                raise ValueError('Invalid label %s in line %s, line #: %s' % (words[0], line, line_count))
            if len(words) < 2:
                return
            found = words[1] if words[1] in self.instructions else ''
        if not found:
            word = words[0]
            if len(words) > 1:
                raise ValueError('Not an instruction: %s' % line)
            else:
                if self.valid_label(word):
                    if self.make_label(word) in self.label_location:
                        self.label_location[self.make_label(word)].append([self.get_pc(), 0xFFFF, 16])
                    else:
                        self.label_location[self.make_label(word)] = [[self.get_pc(), 0xFFFF, 16]]
                else:
                    raise ValueError('Invalid label: %r, line: %s' % (word, line))
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
        
            for word in words[1:]:
                word = word.rstrip(',')
                if word in self.regs:
                    t = self.regs[word] << self.reg_pos[rc]
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
                            raise ValueError('Invalid label: %r, line: %s' % (word, line))
    
                instruction |= r
                if found == 'JMPT':
                    break
            self.set_instruction(self.get_pc(), instruction, line_count)
            self.increment_pc()
    
    def assemble(self, code):
        # processing the lines
        debug = self.debug
        self.debug = self.meta
        line_count = 1
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
            self.process_instruction(words, line_count, line)
            line_count += 1
         # second pass:
        for label, value in self.label_location.items():
            if label not in self.labels:
                self.debug = debug
                raise ValueError('Bad label: "%s"' % label)
            else:
                for ref, mask, bits in value:
                    current = self.labels[label] - ref - 1
                    # kludge for absolute addresses,
                    # but seems correct for some code (lc3os.asm)
                    if self.get_memory(ref) == 0: # not instruction -> absolute
                        self.set_memory(ref, self.labels[label])
                    elif not self.in_range(current, bits) :
                        self.debug = debug
                        raise ValueError(("Not an instruction: %s, mask %s, offset %s,  %s, ref %s" %
                                (label,
                                bin(mask),
                                self.labels[label] - ref,
                                bin(self.labels[label]),
                                lc_hex(ref))))
                    else:
                        # FIXME: not sure what this is, but if we init
                        # memory first, it works ok
                        self.set_memory(ref, 
                                        plus(self.get_memory(ref), 
                                             lc_bin(mask & current)))
        self.set_pc(self.orig)
        self.debug = debug

    def handleDebug(self, lineno):
        pass

    def Info(self, string):
        print(string, end="")

    def Error(self, string):
        print(string, end="")

    def run(self, reset=True):
        if reset:
            self.cycle = 0
            self.instruction_count = 0
            self.set_memory(0xFE04, 0xFFFF) ## OS_DSR Display Ready
            self.set_memory(0xFE00, 0xFFFF) ## OS_KBSR Keyboard Ready
        self.cont = True
        if self.debug:
            print("Tracing Script! PC* is incremented Program Counter")
            print("(Instr/Cycles Count) INSTR [source line] (PC*: xHEX)")
            print("----------------------------------------------------")
        while self.cont:
            self.step()

    def step(self):
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
            print("(%s/%s) %s%s (%s*: %s)" % (
                self.instruction_count, 
                self.cycle, 
                self.format[instr](instruction, pc), 
                line_str,
                lc_hex(self.get_pc()), 
                lc_hex(instruction)))
        #if (instr in self.apply):
        self.apply[instr](instruction)

    def dump_registers(self):
        print()
        print("=" * 50)
        print("Registers:")
        print("=" * 50)
        print("PC:", lc_hex(self.get_pc()))
        for r,v in zip("NZP", self.get_nzp()):
            print("%s: %s" % (r,v), end=" ")
        print()
        count = 1
        for key in range(8):
            print("R%d: %s" % (key, lc_hex(self.get_register(key))), end=" ")
            if count % 4 == 0:
                print()
            count += 1
    
    def dump(self, orig_start=None, orig_stop=None):
        if orig_start is None:
            start = self.orig
        else:
            start = orig_start
        if orig_stop is None:
            stop = max(self.source.keys()) + 1
        else:
            stop = orig_stop
        print("=" * 50)
        print("Memory, disassembled:")
        print("=" * 50)
        for memory in range(start, stop):
            instruction = self.get_memory(memory)
            instr = (instruction >> 12) & 0xF
            label = self.lookup(memory, "")
            if label:
                label = label + ":"
            instr_str = self.source.get(memory, "")
            if instr_str:
                print("%-10s %s: %s  %-41s [line: %s]" % (
                    label, lc_hex(memory), lc_hex(instruction), 
                    self.format[instr](instruction, memory), instr_str))
            else:
                if orig_stop is None:
                    break
                else:
                    if instruction == 0:
                        ascii = "\\0"
                    else:
                        try:
                            ascii = repr(chr(instruction))
                        except:
                            ascii = instruction
                    print("%-10s %s: %s - %s" % (
                        label, lc_hex(memory), lc_hex(instruction), ascii))

    def disassemble(self):
        start = min(self.source.keys())
        stop = max(self.source.keys()) + 1
        print("           .ORIG %s " % lc_hex(start))
        for memory in range(start, stop):
            instruction = self.get_memory(memory)
            instr = (instruction >> 12) & 0xF
            label = self.lookup(memory, "")
            if label:
                label = label + ":"
            print("%-10s %s" % (label, self.format[instr](instruction, memory)))
        print("           .END")

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
        pc_offset6 = instruction & 0b0000000000111111
        self.set_memory(plus(self.get_register(base), sext(pc_offset6, 6)),
                        self.get_register(src))

    def STR_format(self, instruction, location):
        src = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        pc_offset6 = instruction & 0b0000000000111111
        return "STR R%d, R%d, %s" % (src, base, lc_hex(self.lookup(plus(location, sext(pc_offset6,6)) + 1)))

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
            print("  Reading memory[x%04x] (x%04x) =>" % (location, memory1))
            print("  Reading memory[x%04x] (x%04x) =>" % (memory1, memory2))
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
                self.Info(chr(self.get_register(src)))
            except:
                raise ValueError("Value in R%d (%s) is not in range 0-255 (x00-xFF)" % (src, lc_hex(self.get_register(src))))
        
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
        data = input("GETC: ")
        if data:
            if len(data) > 1:
                self.char_buffer += [ord(char) for char in data[1:]]
            return ord(data[0])
        else:
            return 10 # Carriage Return

    def TRAP(self, instruction):
        vector = instruction & 0b0000000011111111
        self.set_register(7, self.get_pc())
        self.set_pc(self.get_memory(vector))
        if vector == 0x20:
            if self.char_buffer:
                self.set_memory(0xFE02, self.char_buffer.pop(0))
            else:
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
            raise ValueError("invalid TRAP vector: %s" % lc_hex(vector))

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
                print("    True - branching to", lc_hex(self.get_pc()))
        else:
            if self.debug:
                print("    False - continuing...")

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
        if pc_offset9 < 256:
            if pc_offset9 < 32: # integers
                return "%s %s (or %s)" % (instr, lc_hex(val), pc_offset9)
            elif pc_offset9 <= 127: # int, or ASCII
                return "%s %s (or %s, %s)" % (instr, lc_hex(val), pc_offset9, repr(chr(pc_offset9)))
            else: # integer
                return "%s %s (or %s)" % (instr, lc_hex(val), pc_offset9)
        else:
            return "%s %s" % (instr, lc_hex(val))

    def LD(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        location = plus(self.get_pc(), sext(pc_offset9,9))
        memory = self.get_memory(location)
        if self.debug:
            print("  Reading memory[x%04x] (x%04x) =>" % (location, memory))
        self.set_register(dst, memory)
        self.set_nzp(self.get_register(dst))

    def LD_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        pc_offset9 = instruction & 0b0000000111111111
        return "LD R%d, %s" % (dst, lc_hex(self.lookup(plus(sext(pc_offset9,9), location) + 1)))

    def LDR(self, instruction):
        dst = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        pc_offset6 = instruction & 0b0000000000111111
        location = plus(self.get_register(base), sext(pc_offset6,6))
        memory = self.get_memory(location)
        if self.debug:
            print("  Reading memory[x%04x] (x%04x) =>" % (location, memory))
        self.set_register(dst, memory)
        self.set_nzp(self.get_register(dst))

    def LDR_format(self, instruction, location):
        dst = (instruction & 0b0000111000000000) >> 9
        base = (instruction & 0b0000000111000000) >> 6
        pc_offset6 = instruction & 0b0000000000111111
        return "LDR R%d, R%d, %s" % (dst, base, lc_hex(self.lookup(plus(sext(pc_offset6,6), location) + 1)))

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
        self.run()
        self.dump_registers()
        print("Instructions:", self.instruction_count)
        print("Cycles: %s (%f milliseconds)" % 
              (self.cycle, self.cycle * 1./2000000))

    def save(self, base):
        # producing output
        # symbol list for Simulators
        with open(base + '.sym', 'w') as f:
            print('''//Symbol Name		Page Address
//----------------	------------
//''', end='\t', file=f)
        
            print('\n//\t'.join('\t%-20s%4x' % (name, value)
                            for name, value in self.labels.items()), file=f)
        
        with open(base + '.bin', 'w') as f:
            print('{0:016b}'.format(self.orig), file=f)  # orig address
            print('\n'.join('{0:016b}'.format(self.get_memory(m)) for m in range(self.orig, self.get_pc())),
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
        if words[0] == "%help":
            print("Interactive Directives: ")
            print(" %debug                          - toggle debug")
            print(" %cont                           - continue running")
            print(" %step                           - execute the next instruction, increment PC")
            print(" %reset                          - reset LC3 to start state")
            print(" %raw [start [stop]]             - list meory in hex")
            print(" %list                           - list program from memory")
            print(" %dump [start [stop]]            - dump memory as program")
            print(" %regs                           - show registers")
            print(" %set pc HEXVALUE                - set PC")
            print(" %set memory HEXLOCATION HEXVALUE- set memory")
            print(" %set reg VALUE HEXVALUE         - set register")
            print(" %set warn BOOL                  - set warnings on/off")
            print(" %get pc                         - get PC")
            print(" %get memory HEXLOCATION         - get memory")
            print(" %get reg VALUE                  - get register")
            return True
        elif words[0] == "%debug":
            self.debug = not self.debug
            return True
        elif words[0] == "%raw":
            if len(words) > 0:
                start = int("0" + words[1], 16)
                if len(words) > 1:
                    stop = int("0" + words[2], 16)
                else:
                    stop = start + 25
            else:
                start = 0x3000
                stop = 0x3000 + 25
            try:
                for x in range(start, stop):
                    print(lc_hex(x), lc_hex(self.get_memory(x)))
            except:
                print("Help: %raw [start [stop]]")
            return True
        elif words[0] == "%list":
            try:
                self.dump()
            except:
                print("Error; did you run code first?")
            return True
        elif words[0] == "%regs":
            try:
                self.dump_registers()
            except:
                print("Error; did you run code first?")
            return True
        elif words[0] == "%dump":
            try:
                self.dump(*[int("0" + word, 16) for word in words[1:]])
            except:
                print("Error; did you run code first?")
            return True
        elif words[0] == "%set":
            try:
                if words[1] == "pc":
                    self.set_pc(int("0" + words[2], 16))
                elif words[1] == "memory":
                    self.set_memory(int("0" + words[2], 16), int("0" + words[3], 16))
                elif words[1] == "reg":
                    self.set_register(int(words[2]), int("0" + words[3], 16))
                elif words[1] == "warn":
                    self.warn = bool(int(words[2]))
                    self.warn = bool(int(words[2]))
                else:
                    print("Use %set [pc|memory|reg|warn] ...")                
            except:
                print("Hint: %set pc x3000")
                print("      %set reg 1 xFFFF")
                print("      %set memory x300A x1")
                print("      %set warn 0")
            return True
        elif words[0] == "%get":
            try:
                if words[1] == "pc":
                    print(lc_hex(self.get_pc()))
                elif words[1] == "memory":
                    print(lc_hex(self.get_memory(int("0" + words[2], 16))))
                elif words[1] == "reg":
                    print(self.get_register(int(words[2])))
                elif words[1] == "warn":
                    print(int(self.warn))
                else:
                    print("Use %get [pc|memory|reg|warn] ...")                
            except:
                print("Hint: %get pc")
                print("      %get reg 1")
                print("      %get memory x300A")
                print("      %get warn")
            return True
        elif words[0] == "%reset":
            self.initialize()
            return True
        elif words[0] == "%cont":
            try:
                self.step()
                self.dump_registers()
            except:
                #traceback.print_exc()
                print("Error")
            return True
        elif words[0] == "%step":
            orig_debug = self.debug
            self.debug = True
            if self.get_pc() in self.source:
                lineno = self.source[self.get_pc()]
                ## show trace
            self.step()
            self.debug = orig_debug
            return True
        elif words[0] == "%run":
            ok = False
            try:
                # if .orig in code, then run, otherwise just assemble:
                self.pc = self.orig
                self.run()
                self.dump_registers()
                print("Instructions:", self.instruction_count)
                print("Cycles: %s (%f milliseconds)" % 
                      (self.cycle, self.cycle * 1./2000000))
                ok = True
            except Exception as exc:
                if self.debug:
                    traceback.print_exc()
                if self.get_pc() in self.source:
                    sys.stderr.write("\nRuntime error!\nFile \"%s\", line %s\n" % 
                                     (self.filename, 
                                      self.source[self.get_pc()]))
                else:
                    sys.stderr.write("\nRuntime error!\nFile \"%s\", memory %s\n" % 
                                     (self.filename, 
                                      lc_hex(self.get_pc())))
                sys.stderr.write(str(exc) + "\n")
                ok = False
            return ok

        ### Else, must be code to assemble:
        self.reset_memory()
        ok = False
        try:
            self.assemble(text)
            self.dump()
            self.dump_registers()
            ok = True
        except Exception as exc:
            if self.debug:
                traceback.print_exc()
            if self.get_pc() in self.source:
                sys.stderr.write("\nAssemble error!\nFile \"%s\", line %s\n" % 
                                 (self.filename, 
                                  self.source[self.get_pc()]))
            else:
                sys.stderr.write("\nAssemble error!\nFile \"%s\", memory %s\n" % 
                                 (self.filename, 
                                  lc_hex(self.get_pc())))
            sys.stderr.write(str(exc) + "\n")
            ok = False

        return ok


"""
Macro ideas, from:
http://www.cs.georgetown.edu/~squier/Teaching/HardwareFundamentals/LC3-trunk/src/lc3pre_Language_Extensions.txt

example code         translation
----------           -----------

mov__(r3, r5)        add r3, r5, 0        ;;-- r3 <== r5

zero__(r2)           and r2, r2, 0        ;;-- r2 <== 0

inc__(r7)            add r7, r7, 1        ;;-- r7 <== r7 + 1

dec__(r7)            add r7, r7, -1       ;;-- r7 <== r7 - 1

push__(r5)           add sp__, sp__, -1
                     str r5, sp__, 0

pop__(r5)            ldr r5, sp__, 0
                     add sp__, sp__, 1
                     mov__(r1, r1)        ;;-- sets NZP CCs per r5

sub__(r1, r2, r3)    not r3, r3           ;;-- r1 <== (r2 - r3)
                     add r3, r3, 1
                     add r1, r2, r3
                     add r3, r3, -1
                     not r3, r3           ;;-- r2 and r3 unchanged,
                     mov__(r1, r1)        ;;-- sets NZP CCs per r1

or__(r1, r2, r3)    not r2, r2            ;;-- r1 <== (r2 OR r3)
                    not r3, r3
                    and r1, r2, r3
                    not r1, r1
                    not r2, r2
                    not r3, r3            ;;-- r2 and r3 unchanged,
                    mov__(r1, r1)         ;;-- sets NZP CCs per r1

jsr__(mySub_BEGIN)  push__( R7 )          ;;-- uses stack discpline,
                    jsr mySub_BEGIN       ;;-- allows nested calls
                    pop__( R7 )

trap__(x13)         push__( R7 )          ;;-- uses stack discpline,
                    trap x13              ;;-- allows nested calls
                    pop__( R7 )
"""
