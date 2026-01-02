********************************
*                              *
*          APPLE PI            *
*                              *
*    Glen Bredon    6/13/82    *
*------------------------------*
* This is just a test source   *
* for the linker.  After       *
* linking and saving the       *
* object code, you should BRUN *
* it from the EXEC mode Disk   *
* command provision.           *
*------------------------------*
* This MUST be linked to an    *
* address between $800 and     *
* $81C since the program       *
* expects free space at $E00   *
* and above.                   *
********************************

          REL
SAVOBJ    KBD
          DO SAVOBJ
          DSK /MERLIN/PI/START
          FIN

PRINT     EXT
RNGERR    EXT
ZSTRNG    EXT

          TR
          EXP OFF

          USE /MERLIN/SOURCE/PI.MACS

          LDA #0
          STA CURSLOT    ;To see if 80 col there
START     ENT
          LDA #$8C
          JSR COUT
          JSR HOME
          LDA #":"
          STA PROMPT
          LDA #16
          BIT CURSLOT
          BPL SETHOR
          ASL
SETHOR    STA CH
          JSR PRINT
          INV "APPLE PI"
          HEX 8D8D
          ASC "       This program computes pi to many "
          ASC "decimal places (max 11516)."
          HEX 8D8D00
LINE      LDX #40
          LDA #"="
SNDEQU    JSR COUT
          DEX
          BNE SNDEQU
          LDA CV
          CMP #4
          BEQ LINE
          JSR PRINT
          HEX 8D
          ASC "Number of 11-char. columns for printout "
          ASC "(1-10) "
          BRK
          JSR GETLN
          TXA
          BEQ DEFLT
          LDA IN
          EOR #"0"
          CMP #10
          BLT OK
RESTART   JMP START
DEFLT     LDA #7         ;Use if CURSLOT <> 0
          BIT CURSLOT    ;Peripheral in use?
          BMI PRDP       ;Use 7 if so
          LSR            ;7 -> 3
PRDP      ORA #"0"
          JSR COUT       ;Show it
          AND #7         ;Get it back
          BPL PASS       ;Always taken
OK        LDY IN+1
          CPY #$8D
          BEQ PASS
          ASL
          STA DEFNUMC
          ASL
          ASL
          ADC DEFNUMC
          STA DEFNUMC
          TYA
          EOR #"0"
          CMP #10
          BGE RESTART
          ADC DEFNUMC
          BEQ RESTART
PASS      CMP #11
          BGE RESTART
          STA DEFNUMC
          JSR PRINT
          HEX 8D
          ASC "Output slot (RTN for video screen):"
          BRK
          JSR RDKEY
          CMP #$8D       ;CR only?
          BNE MASK       ;Branch if not
          LDA CURSLOT    ;Get current output slot
MASK      AND #7         ; and use that
          STA SLOT
          ORA #"0"
          JSR COUT
          JSR PRINT
          HEX 8D8D
          ASC "Initialization string (if any) "
          BRK
          JSR GETLN
MVINIT    LDA IN,X
          STA INITSTR,X
          DEX
          BPL MVINIT
          JSR CROUT
VERIFY    INX
          LDA INITSTR,X
          CMP #$8D
          BEQ CORR?
          CMP #$A0
          BGE NOTCNTR
          ORA #"@"
          LDY #$3F
          STY INVFLG
NOTCNTR   JSR COUT
          LDY #$FF
          STY INVFLG
          BNE VERIFY
CORR?     JSR PRINT
          HEX 8D
          ASC "Correct? (Y/N):"
          BRK
CANS      JSR RDKEY
          CMP #$8D
          BEQ SETY
          AND #%11011111
          CMP #"N"
          BNE ISY?
          JMP START
ISY?      CMP #"Y"
          BNE CANS
SETY      LDA #"Y"
          JSR COUT
          JSR PRINT
          HEX 8D8D
          ASC "Number of decimal places "
          BRK
          JSR GETLN
          LDY #0
          STY DEFLEN
          STY DEFLEN+1
GETNUM    LDA IN,Y
          CMP #$8D
          BEQ NUMGOT
          INY
          EOR #"0"
          CMP #10
          BGE BADNUM
          STA NUMCOL     ;Temp
          ASL DEFLEN
          ROL DEFLEN+1
          BCS BADNUM
          LDA DEFLEN+1
          STA TEMP
          LDA DEFLEN
          ASL
          ROL TEMP
          BCS BADNUM
          ASL
          ROL TEMP
          BCS BADNUM
          ADC DEFLEN
          STA DEFLEN
          LDA TEMP
          ADC DEFLEN+1
          STA DEFLEN+1
          BCS BADNUM
          LDA NUMCOL
          ADC DEFLEN
          STA DEFLEN
          LDA DEFLEN+1
          ADC #0
          STA DEFLEN+1
          BCC GETNUM
BADNUM    JMP RNGERR

NUMGOT    TYA
          BEQ BADNUM     ;Null input not accepted
          LDA DEFLEN     ;Add 2 to length for rounding
          CLC
          ADC #2
          STA DEFLEN
          LDX DEFLEN+1
          BCC RNGOK?
          INC DEFLEN+1
          INX
RNGOK?    CPX #>STRLEN-$100
          BLT LENOK
          BNE BADNUM
          CMP #$FF
          BEQ BADNUM
LENOK     LDA #0
          STA SIGN       ;Init sign to +
          STA WHICHSER   ; and first series
          STADR SUMSTR   ;PL
          JSR ZSTRNG     ;Zero sum string
