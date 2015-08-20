from IPython.kernel.zmq.kernelapp import IPKernelApp
from .kernel import CalystoLC3
IPKernelApp.launch_instance(kernel_class=CalystoLC3)
