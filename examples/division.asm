.ORIG x3000
    AND R6,R6,#0 ; remainder
    AND R7,R7,#0 ; quotient
    LD R1, DIVIDEND
    LD R2, DIVISOR
    NOT R3,R2
    ADD R3, R3,#1

LOOP1 ADD R7,R7,#1 ; subtraction until dividend value
                   ; becomes either zero or negative
    ADD R1,R1,R3
    BRN NEG
    BRZ ZERO
    BRP LOOP1

NEG ADD R7,R7,#-1
    ADD R6,R1,R2
ZERO ST R6, REMAINDER
     ST R7, QUOTIENT
    HALT
DIVIDEND  .FILL #25
DIVISOR   .FILL #4
QUOTIENT  .FILL #0
REMAINDER .FILL #0
.END
