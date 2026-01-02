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
          DSK /MERLIN/PI/LOOK
          FIN

          TR
          EXP OFF

          USE /MERLIN/SOURCE/PI.MACS

********************************
* Routine to find first nonzero
* digit of string at (PL):
********************************
LOOK      ENT
          LDY #0
          STY FLAG
          CLC
          LDA PL
          ADC ZLEN
          STA PL
          LDA PL+1
          ADC ZLEN+1
          STA PL+1
LUK       LDA (PL),Y     ;Get first digit
          BNE FIX        ; non 0
          INY
          BNE LUK
ABORT     PLA            ;Pop return adrs
          PLA
          RTS            ;Number was zero
FIX       STA REMR       ;Wanted on return
          TYA
          ADC PL
          STA PL
          BCC DOZ
          INC PL+1
          CLC
DOZ       TYA
          ADC ZLEN
          STA ZLEN
          BCC SETCOUNT
          INC ZLEN+1
SETCOUNT  LDA DEFLEN
          SEC
          SBC ZLEN
          EOR #-1
          STA COUNT
          LDA DEFLEN+1
          SBC ZLEN+1
          EOR #-1
          STA COUNT+1
          BPL ABORT
          LDY #0
          DEC FLAG
          RTS
