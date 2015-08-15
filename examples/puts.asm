 .ORIG x3000            ; print out an abreviation of the i-th month
       LD  R0, I        ; get the index;
       ADD R0, R0, #-1  ; convert to 0 based index
       ADD R0, R0, R0
       ADD R0, R0, R0   ; R0 = 4*I (sizeof each entry is 4)
       LEA R1, MONTHS   ; R1 is the address of the beginning of the array
       ADD R0, R0, R1   ; R0 cntains address of the I-th element
       PUTS             ; print out the abreviation
       HALT
I      .FILL #1          ; the variable I (1-12)
                        ; an array of strings each 4 characters long
                        ; 3 char plus terrminating null
MONTHS .STRINGZ "Jan"
       .STRINGZ "Feb"
       .STRINGZ "Mar"
       .STRINGZ "Apr"
       .STRINGZ "May"
       .STRINGZ "Jun"
       .STRINGZ "Jul"
       .STRINGZ "Aug"
       .STRINGZ "Sep"
       .STRINGZ "Oct"
       .STRINGZ "Nov"
       .STRINGZ "Dec"
.END
