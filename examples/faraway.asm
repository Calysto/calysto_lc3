;; The LC3 has PC-relative memory access, which
;; limits the memory you can access based on how
;; much space you have in the instruction, and
;; how far away the LABEL is.

;; Here is an example of storing the value 1 into
;; a location very far away. You can use the same
;; trick for .STRINGZ and .BLKW

;; In this example, DATA must be within 256
;; words in memory from the STI command, but
;; MEMORY can be very far away.

.ORIG x3000
        AND R0,R0,#0
        ADD R0,R0,#1
        STI R0, DATA
        HALT
DATA:   .FILL MEMORY
FILLER: .BLKW 1000
MEMORY: .BLKW 1000
.END
