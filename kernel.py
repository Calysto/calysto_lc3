from __future__ import print_function

from metakernel import MetaKernel

from lc3 import LC3

class CalystoLC3(MetaKernel):
    implementation = 'LC3'
    implementation_version = '1.0'
    language = 'Calysto LC3'
    language_version = '0.1'
    banner = "Calysto Little Computer 3 - assembling language of the LC3"
    language_info = {
        'name': 'asm',
        'mimetype': 'text/x-asm',
        'file_extension': '.asm',
    }

    def __init__(self, *args, **kwargs):
        super(CalystoLC3, self).__init__(*args, **kwargs)
        self.lc3 = LC3()

    def get_usage(self):
        return "This is the Calysto LC3 kernel."

    def do_execute_direct(self, code):
        self.lc3.execute(code.rstrip())

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
