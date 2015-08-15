.SET MODE GRAPHICS
.ORIG x3000
        CLEAR
        AND R0,R0,#0 ;; x
        AND R1,R1,#0 ;; y
        AND R3,R3,#0 ;; char to poke
        LD R4,ROWS
        LD R6,COLS
LOOP:   POKE R0,R1,R3
        ADD R3,R3,#1
        ADD R0,R0,#1
        ADD R5,R0,R4
        BRz NEXT
        BR LOOP
        HALT
NEXT    AND R0,R0,#0
        ADD R1,R1,#1
        ADD R5,R1,R6
        BRz DONE
        BR LOOP
DONE    HALT
ROWS .FILL #-32
COLS .FILL #-8
.END
