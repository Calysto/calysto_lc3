from __future__ import print_function

from metakernel import MetaKernel

from .lc3 import LC3

class CalystoLC3(MetaKernel):
    implementation = 'LC3'
    implementation_version = '1.0'
    language = 'Calysto LC3'
    language_version = '0.1'
    banner = "Calysto Little Computer 3 - assembly language of the LC3"
    language_info = {
        'name': 'gas',
        'mimetype': 'text/x-gas',
        'file_extension': '.asm',
    }

    def __init__(self, *args, **kwargs):
        super(CalystoLC3, self).__init__(*args, **kwargs)
        self.lc3 = LC3(self)

    def get_usage(self):
        return """This is the Calysto LC3 Jupyter kernel.

LC3 Interactive Magic Directives: 

 %bp [clear | SUSPENDHEX]           - show, clear, or set breakpoints
 %cont                              - continue running
 %dis [STARTHEX [STOPHEX]]          - dump memory as program
 %dump [STARTHEX [STOPHEX]]         - list memory in hex
 %exe                               - execute the program
 %mem HEXLOCATION HEXVALUE          - set memory
 %pc HEXVALUE                       - set PC
 %reg REG HEXVALUE                  - set register REG to HEXVALUE
 %regs                              - show registers
 %reset                             - reset LC3 to start state
 %step                              - execute the next instruction, increment PC

HEX values begin with an 'x' and are composed of 4 0-F digits or letters.

To get additional help on these items, use '%help %item'.

To see additional magics, use %lsmagic, and put a question mark after a magic 
name.
"""

    def get_completions(self, info):
        token = info["help_obj"]
        matches = []
        for item in (list(self.lc3.mnemonic.values()) + 
                     [".ORIG", ".END", "GETC", "OUT", "PUTS", "IN", "PUTSP", 
                      "HALT"] + 
                     list(self.lc3.labels.keys()) + 
                     ["%bp", "%cont", "%dis",  "%dump",  "%exe",  "%mem",  
                      "%pc", "%reg",  "%regs",  "%reset",  "%step"]):
            if item.startswith(token) and item not in matches:
                matches.append(item)
        return matches

    def get_kernel_help_on(self, info, level=0, none_on_fail=False):
        expr = info["code"]
        if expr == "%bp":
            return """%bp - See, clear, or set a breakpoint.
See all of the breakpoints:
    %bp

Clear all of the breakpoints:
    %bp clear

Create a breakpoint at location x3005:
    %bp x3005
"""
        elif expr == "%cont":
            return """%cont - Continue executing the program
"""
        elif expr == "%dis":
            return """%dis - Disassemble memory
"""
        elif expr == "%dump":
            return """%dump - Dump memory
"""
        elif expr == "%exe":
            return """%exe - Execute the program
"""
        elif expr == "%mem":
            return """%mem - Set a memory location
"""                      
        elif expr == "%pc":
            return """%pc - Set the Program Counter
"""
        elif expr == "%reg":
            return """%reg - Set a register
"""
        elif expr == "%regs":
            return """%regs - See the registers
"""
        elif expr == "%reset":
            return """%reset - Reset the LC3
"""
        elif expr == "%step":
            return """%step - Execute the next instruction
"""
        elif none_on_fail:
            return None
        else:
            return "No available help on '%s'" % expr

    def do_execute_file(self, filename):
        self.lc.execute_file(filename)

    def do_execute_direct(self, code):
        try:
            self.lc3.execute(code.rstrip())
        except Exception as exc:
            self.Error(str(exc))
        except KeyboardInterrupt:
            self.Error("Keyboard Interrupt!")

    def do_is_complete(self, code):
        if code:
            if code.split()[-1].strip() != "":
                return {'status' : 'incomplete',
                        'indent': '    '}
            else:
                return {'status' : 'complete'}
        else:
            return {'status' : 'incomplete'}

    def repr(self, data):
        return repr(data)

