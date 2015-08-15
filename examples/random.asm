;;; Algorithm for the iteration x ← a x mod m
;;; using Schrage’s method

    .ORIG x3000
    JSR Random
    HALT

;;; -----------------------------------------------------
;;; Memory X has next random number
Random: ST R7,BACK         ; save return location
    LD R0, M
    LD R1, A
    JSR Divide         ; R0 / R1
    ;; q = m / a
    LD R0, QUOTIENT     ; R0 / R1
    ST R0, Q     
    ;; r = m mod a
    LD R0, REMAINDER     ; R0 mod R1
    ST R0, R
        ;; x / q
    LD R0, X
    LD R1, Q
    JSR Divide         ; R0 / R1
    LD R1, QUOTIENT
    ST R1, TEMP2
    LD R1, REMAINDER     ; x mod q
    ST R1, TEMP1
    ;; x ←  a ∗  (x mod q) − r ∗  (x / q)
    ;;      a * TEMP1 - r * TEMP2
    LD R0, A
    JSR Multiply         ; R2 <- R0 * R1
    ST R2, TEMP1
    ;;      a * TEMP1 - r * TEMP2
    LD R0, R
    LD R1, TEMP2
    JSR Multiply         ; R2 <- r * TEMP2
    NOT R2,R2         ; -R2
    ADD R2,R2,#1
    ST R2, TEMP2 
    LD R1, TEMP1
    ADD R2, R2, R1         ; TEMP1 - TEMP2
TEST:    BRzp DONE         ; if x < 0 then
    LD R1, M
    ADD R2, R2, R1         ; x ←  x + m
DONE:    ST R2, X
    LD R7, BACK         ; Restore return address
    RET
A:    .FILL #7           ;; a , the multiplicative constant is given
M:    .FILL #32767    ;; m = 2 ˆ 15 − 1, the modulus is given
X:    .FILL #10    ;; x, the seed is given
R:    .FILL #0
Q:    .FILL #0
TEMP1:    .FILL #0
TEMP2:    .FILL #0
BACK:    .FILL #0

;;; -----------------------------------------------------
;;; R2 <- R0 * R1
;;; Also uses R3 to store SIGN
Multiply: AND R2,R2,#0
      AND R3,R3,#0
      ADD R0,R0,#0         ; compare R0
      BRn MultNEG1
      BR  MultCont
MultNEG1: NOT R3,R3         ; flip SIGN
      NOT R0,R0
      ADD R0,R0,#1
MultCONT: ADD R1,R1,#0         ; compare R1
      BRn MultNEG2
      BR MultInit
MultNEG2: NOT R3,R3         ; flip SIGN
      NOT R1,R1
      ADD R1,R1,#1
MultInit: ADD R0,R0,#0      ; have R0 set the condition codes
MultLoop: BRz MultDone
      ADD R2,R2,R1
      ADD R0,R0,#-1
      BR MultLoop
MultDone: ADD R0,R3,#0
      BRzp MultRet
      NOT R2,R2
      ADD R2,R2,#1
MultRet:  RET            ; R2 has the sum

;;; -----------------------------------------------------
;;; R0 / R1
;;; Also uses R3 to store SIGN
;;;           R4 to store -R1
;;;           R5 is QUOTIENT
;;;           R6 is REMAINDER
;;;           R2 temp
Divide:   AND R3,R3,#0
      ST R3, QUOTIENT
      ST R3, REMAINDER
      ADD R0,R0,#0         ; compare R0
      BRn DivNEG1
      BR  DivCont
DivNEG1:  NOT R3,R3         ; flip SIGN
      NOT R0,R0
      ADD R0,R0,#1
DivCONT:  ADD R1,R1,#0         ; compare R1
      BRn DivNEG2
      BR DivInit
DivNEG2:  NOT R3,R3         ; flip SIGN
      NOT R1,R1
      ADD R1,R1,#1
DivInit:  ADD R4,R1,#0
      NOT R4,R4
      ADD R4,R4,#1
DivLoop:  ADD R2,R0,R4      ; have R2 set the condition codes
      BRn DivDone
      ADD R0,R0,R4
      LD R2,QUOTIENT
      ADD R2,R2,#1
      ST R2,QUOTIENT
      BR DivLoop
DivDone:  ADD R3,R3,#0         ; Negative?
      BRzp DivRet
      LD R2,QUOTIENT     ; Yes, then negate R2
      NOT R2,R2
      ADD R2,R2,#1
      ST R2,QUOTIENT
DivRet:      ST R0,REMAINDER
      RET            ; R2 has the sum
QUOTIENT:    .FILL #0
REMAINDER:    .FILL #0
    .END
