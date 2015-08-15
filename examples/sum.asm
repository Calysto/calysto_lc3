; Example 1 -- Compute the sum of 12 integers
; This file contains the instructions (in assembly format)

    .ORIG x3000   ; Start program at x3000
    LEA R1 DATA   ; R1 <- (PC + offset)
    AND R3 R3 x0  ; R3 <- 0
    AND R2 R2 x0  ; R2 <- 0
    ADD R2 R2 xC  ; R2 <- 12
LOOP BRz DONE      ; If Z, goto x300A (PC+5)
    LDR R4 R1 x0  ; Load next value to R4
    ADD R3 R3 R4  ; Add to R4
    ADD R1 R1 x1  ; Increment R1
    ADD R2 R2 x-1 ; Decrement R2
    BRnzp LOOP    ; Goto x3004
DONE HALT          ; HALT
DATA  .FILL 1
      .FILL 2
      .FILL 3
      .FILL 4
      .FILL 5
      .FILL 6
      .FILL 7
      .FILL 8
      .FILL 9
      .FILL 10
      .FILL 11
      .FILL 12
 .END
