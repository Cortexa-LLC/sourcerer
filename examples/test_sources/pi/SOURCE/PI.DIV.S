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
          DSK /MERLIN/PI/DIV
          FIN

LOOK      EXT

          TR
          EXP OFF

          USE /MERLIN/SOURCE/PI.MACS

*************************************
* String division entry which uses the
* appropriate routine to divide power
* string by 5 or 239:
***************************************
DIVSTR0   ENT
          STADR PWRSTR   ;PL
          STADR 5        ;DIVR
          STA ZLEN       ;A=0 here
          STA ZLEN+1
          BIT WHICHSER   ;First series?
          BPL DIVSTR     ;Divide by 5 if so
                         ;Divide by 239 if not
          LDA #239
          STA DIVR
          BNE DIVSTR

*************************************
* String division entry which uses the
* appropriate routine to divide power
* string by 5*5 or 239*239:
***************************************
DIVSTR1   ENT
          STADR PWRSTR   ;PL
          STADR 25       ;DIVR
          BIT WHICHSER
          BPL DIVSTR
          STADR 239*239  ;DIVR

*************************************
* Routine to divide string at (PL)
* by # in DIVR leaving result in (PL)
*************************************
DIVSTR    ENT
          LDA DIVR+1     ;Check max remainder (x10+9)
          BEQ ONEORTWO   ;Branch if can't be 3 digits
          CMP #$100/10
          BGE THREEBYT   ;Branch if may have 3 digits
GOTWO     JMP TWOBYTE    ;Two digit remainder
ONEORTWO  LDA DIVR       ;Can remainder have 2 digits?
          CMP #$100/10+1
          BGE GOTWO      ;Branch if so

************************************
* String division expecting partial
* dividends to have only one digit:
************************************
          JSR LOOK
          LDA REMR
          JMP :DS
:IPL      INCD PL        ;Point to next digit
          ADC (PL),Y     ;Rem x 10 + next digit
:DS       LDX #-1
          SEC
:SR       STA REMR       ;Set up dividend
          INX
          SBC DIVR       ;Divide by repeated
          BCS :SR        ; subtraction
          TXA            ;Has quotient (0-9)
          STA (PL),Y     ;Build string quotient
          ASL REMR       ;Remainder times 10
          LDA REMR
          ASL
          ASL
          ADC REMR
          STA REMR
          INC COUNT      ;Check if done
          BNE :IPL
          INC COUNT+1
          BNE :IPL
          RTS

************************************
* String division expecting partial
* dividends to have only 3 digits:
* (Worst case for this program.)
************************************
THREEBYT  JSR LOOK
          STY REMR+1     ;Zero 1st remainder
          STY REMR+2     ; high bytes
:DS       LDX #0
:DIV      LDA REMR
          CMP DIVR
          LDA REMR+1
          SBC DIVR+1
          TAY
          LDA REMR+2
          SBC #0
          BCC :DIVED
          STA REMR+2
          LDA REMR
          SBC DIVR
          STA REMR
          STY REMR+1
          INX
          JMP :DIV
:DIVED    TXA
          LDY #0
          STA (PL),Y
          ASL REMR
          ROL REMR+1
          ROL REMR+2
          MOVD REMR+1    ;TEMP
          LDA REMR
          ASL
          ROL TEMP
          ROL TEMP+1
          ASL
          ROL TEMP
          ROL TEMP+1
          ADC REMR
          STA REMR
          LDA TEMP
          ADC REMR+1
          STA REMR+1
          LDA TEMP+1
          ADC REMR+2
          STA REMR+2
          INC COUNT
          BNE :IPL
          INC COUNT+1
          BEQ :BACK
:IPL      INCD PL
          LDA REMR
          ADC (PL),Y     ;Carry is clear
          STA REMR
          BCC :DS
          INC REMR+1
          BNE :DS
          INC REMR+2
          JMP :DS
:BACK     RTS

************************************
* String division expecting partial
* dividends to have only 2 digits:
************************************
TWOBYTE   JSR LOOK
          STY REMR+1
:DS       LDX #0
          SEC
:DIV      LDA REMR
          SBC DIVR
          TAY
          LDA REMR+1
          SBC DIVR+1
          BCC :DIVED
          STA REMR+1
          STY REMR
          INX
          JMP :DIV
:DIVED    TXA
          LDY #0
          STA (PL),Y
          ASL REMR
          ROL REMR+1
          MOV REMR+1     ;TEMP
          LDA REMR
          ASL
          ROL TEMP
          ASL
          ROL TEMP
          ADC REMR
          STA REMR
          LDA TEMP
          ADC REMR+1
          STA REMR+1
          INC COUNT
          BNE :IPL
          INC COUNT+1
          BEQ :BACK
:IPL      INCD PL
          LDA REMR
          ADC (PL),Y     ;Carry is clear
          STA REMR
          BCC :DS
          INC REMR+1
          JMP :DS
:BACK     RTS
