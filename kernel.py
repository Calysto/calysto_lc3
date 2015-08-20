from __future__ import print_function

from metakernel import MetaKernel

from lc3 import LC3

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

Interactive Magic Directives: 

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
"""

    def do_execute_direct(self, code):
        try:
            self.lc3.execute(code.rstrip())
        except Exception as exc:
            self.Error(str(exc))

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

if __name__ == '__main__':
    from IPython.kernel.zmq.kernelapp import IPKernelApp
    IPKernelApp.launch_instance(kernel_class=CalystoLC3)
