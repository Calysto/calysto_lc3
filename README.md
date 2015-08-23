# calysto_lc3

Calysto Little Computer - LC3 Assembly Language for Jupyter 

An Jupyter kernel for LC3

This requires IPython 3.

To install::

    pip install calysto_lc3
    python -m calysto_lc3.install

To use it, run one of:

* ipython notebook
  * In the notebook interface, select 'Calysto LC3' from the 'New' menu
* ipython qtconsole --kernel calysto_lc3
* ipython console --kernel calysto_lc3

Typing `?` to the kernel gives:
```
This is the Calysto LC3 Jupyter kernel.

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
```
Additional help is available with `%help ITEM` such as `%help pc`.
