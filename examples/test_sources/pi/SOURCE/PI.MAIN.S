********************************
*                              *
*          APPLE PI            *
*                              *
*    Glen Bredon    6/13/82    *
*                              *
********************************

          REL
SAVOBJ    KBD
          DO SAVOBJ
          DSK /MERLIN/PI/MAIN
          FIN

ZSTRNG    EXT
MOVSTR    EXT
DIVSTR    EXT
DIVSTR0   EXT
DIVSTR1   EXT
ADDORSUB  EXT
PRINT     EXT
HOOKS     EXT
START     EXT

          TR
          EXP OFF

          USE /MERLIN/SOURCE/PI.MACS

STARTSER  STADR 1        ;ODD ;Init odd divisors
          STADR PWRSTR   ;PL
          JSR ZSTRNG     ;Zero power string
          LDA #1         ;Dividend 1
          BIT WHICHSER   ; for first series
          BPL SETBEG
          LDA #4         ;4 for second
SETBEG    STA PWRSTR     ;Set up series start
          JSR DIVSTR0    ;Divide by 5 or 239
          BIT WHICHSER
          BMI SERLOOP
          LDA #3         ;Correct for using 1
          STA PWRSTR     ; instead of 16 in 1st series

********************************
*     Main series loop:
********************************
SERLOOP   JSR MOVSTR     ;Move power string to temp
          STADR TEMPSTR  ;PL
          MOVD ODD       ;DIVR
          JSR DIVSTR     ;Divide by odd numbers
          JSR ADDORSUB   ;Add/subtract result & sum
          CLC
          LDA ODD        ;Next odd number
          ADC #2
          STA ODD
          BCC CNGSIGN
          INC ODD+1
          BNE CNGSIGN
RNGERR    ENT
          JSR PRINT
          HEX 8D8D878787
          ASC "Overflow!"
          HEX 8D00
          JMP EXIT?
CNGSIGN   LDA SIGN       ;Alternate signs
          EOR #$FF
          STA SIGN
          JSR DIVSTR1    ;Divide by 25 or 239^2
          BIT FLAG       ;Series stable?
          BMI SERLOOP    ;Loop until it is
          BIT WHICHSER   ;Both series done?
          BMI PRINTRES   ;Branch if so
          LDA #-1        ;Set for second if not
          STA WHICHSER   ;Flag second series
          STA SIGN       ;Start with minus sign
          JMP STARTSER   ;Go do second series

PRINTRES  LDX #3         ;Save current I/O hooks
SAVHK     LDA CSWL,X
          STA HOOKS,X
          DEX
          BPL SAVHK
          LDA CURSLOT
          AND #7
          CMP SLOT       ;Using video screen?
          BEQ PR         ;Ignore outport if so
          LDA SLOT       ;Get output slot
          JSR OUTPORT    ;Do PR#
          JSR CROUT      ;CR to init card
          LDX #0
SI        LDA INITSTR,X  ;Send init string
          JSR COUT
          INX
          CMP #$8D       ;Loop till CR
          BNE SI
PR        LDA DEFLEN     ;Correct the length
          SEC
          SBC #2         ;Down by two
          STA COUNT
          LDA DEFLEN+1
          SBC #0
          STA COUNT+1
          STADR SUMSTR   ;PL
          JSR CROUT
          LDY #0
          LDA SUMSTR
          ORA #"0"
          JSR COUT       ;Print first digit (3)
          LDA #"."       ; and decimal point
          JSR COUT
          LDX #10        ;Count for 10 digits
          LDA DEFNUMC    ;Count for # columns
          STA NUMCOL
PRLOOP    INCD PL        ;Point to next digit
          LDA COUNT      ;Finished
          BNE GETDIG     ;Branch if not
          DEC COUNT+1
          BPL GETDIG     ; "
          LDX #3         ;Replace original hooks
RPL       LDA HOOKS,X
          STA CSWL,X
          DEX
          BPL RPL
EXIT?     JSR PRINT
          HEX 8D8D
          ASC "Repeat (Y/N)?"
          HEX 8700
GETKEY    JSR RDKEY
          AND #%11011111
          CMP #"Y"
          BEQ GOSTART
          CMP #"N"
          BNE GETKEY
          JSR COUT
          JMP BASCLD     ;Merlin will fix its z-page
                         ; with this reentry.
GOSTART   JMP START
GETDIG    DEC COUNT
          LDA (PL),Y     ;Get next digit
          ORA #"0"
          JSR COUT       ;Print it
          DEX            ;Count them
          BNE PRLOOP     ;Branch till 10 done
          LDA #" "       ; then send space
          JSR COUT
          LDX #10        ;Reset chr count
          DEC NUMCOL     ;Count # columns
          BNE PRLOOP     ;Loop if line not done
          JSR CROUT      ;Do CR
          LDA #" "       ; and 2 spaces
          JSR COUT
          JSR COUT
          LDA DEFNUMC    ;Reset column count
          STA NUMCOL
          BNE PRLOOP     ;Back for more

