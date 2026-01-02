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
          DSK /MERLIN/PI/ADD
          FIN

          TR
          EXP OFF

          USE /MERLIN/SOURCE/PI.MACS

ADDORSUB  ENT
          ADD SUMSTR     ;DEFLEN;PL
          ADD TEMPSTR    ;DEFLEN;QL
          SEC
          LDA DEFLEN+1
          SBC ZLEN+1
          BMI BACK
          TAX
          SEC
          LDY #0
          BIT SIGN
          BMI SUBSTR
********************************
* Routine to add string at (PL)
* to that at (QL) sum in (PL)
********************************
ADDSTR    ENT
          CLC
          BCC ADS
SKIP      DEC PL
          DEC QL
ADS       LDA (PL),Y
          ADC (QL),Y
          CMP #10
          BLT ADOK
          SBC #10
ADOK      STA (PL),Y
          LDA PL
          BNE SKIP
          DEC PL+1
          DEC QL+1
          DEX
          BPL SKIP
          BCS SKIP       ;Do another page if nec
BACK      RTS

************************************
* Routine to subtract string at (QL)
* from that at (PL) diff in (PL)
************************************
SKP       DEC PL
          DEC QL
SUBSTR    LDA (PL),Y     ;Entry point
          SBC (QL),Y
          BPL SOK
          ADC #10        ;Carry is clear
          CLC
SOK       STA (PL),Y
          LDA PL
          BNE SKP
          DEC PL+1
          DEC QL+1
          DEX
          BPL SKP
          BCC SKP        ;Another page if nec
          RTS

***********************************
* Routine to move PWRSTR to TEMPSTR
* (Only moves full pages)
***********************************
MOVSTR    ENT
          LDA ZLEN+1
          LDY #0
          STY PL
          STY QL
          CLC
          ADC #>PWRSTR
          STA PL+1
          LDA ZLEN+1
          ADC #>TEMPSTR
          STA QL+1
          SEC
          LDA DEFLEN+1
          SBC ZLEN+1
          TAX
MV        LDA (PL),Y
          STA (QL),Y
          INY
          BNE MV
          INC PL+1
          INC QL+1
          DEX
          BPL MV
          RTS

********************************
* Routine to zero string at (PL)
* Number of pages in DEFLEN+1
********************************
ZSTRNG    ENT
          LDY #0
          TYA
          LDX DEFLEN+1
ZS        STA (PL),Y
          INY
          BNE ZS
          INC PL+1
          DEX
          BPL ZS
          RTS

PRINT     ENT
          VAR MSGPNT     ;OUTPUT
          PUT /MERLIN/LIB/SENDMSG

OUTPUT    BMI NOINV
          LDY #%00111111
          STY INVFLG
          CLC
          AND #%00111111
          ADC #%00100000
          EOR #%11100000
NOINV     JSR COUT
          LDY #$FF
          STY INVFLG
          INY
          RTS

HOOKS     ENT
          DA $FDF0
          DA $FD1B

* Make sure this program, when linked, does
* not conflict with the first string buffer
* SUMSTR (now at $E00):

          ERR \SUMSTR
