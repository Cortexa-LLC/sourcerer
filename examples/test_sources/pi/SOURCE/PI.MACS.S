*-------------------------------------
* Equates & macros for PI test for REL
*-------------------------------------

PL        = 0            ;General pointer
QL        = 2            ; "
COUNT     = 4            ;Countdown of string length
ODD       = 6            ;Holds "odd" divisors
SIGN      = 8            ;Sign of series term
WHICHSER  = 9            ;Flags series 1 or 2
DIVR      = 10           ;Divisor
REMR      = 12           ;Remainder (1-3 bytes)
TEMP      = 15           ;Scratch
FLAG      = 17           ;Flags 0 number string
MSGPNT    = 18           ;Message pointer
DEFLEN    = 20           ;Specified string length
NUMCOL    = 22           ;Countdown printout columns
DEFNUMC   = 23           ;Specified # of columns
SLOT      = 24           ;Holds slot # for printout
ZLEN      = 25
CH        = $24
CV        = $25
INVFLG    = $32
PROMPT    = $33
CSWL      = $36
IN        = $200
INITSTR   = IN+$80
CURSLOT   = $7F8
BASCLD    = $E000
HOME      = $FC58
RDKEY     = $FD0C
CROUT     = $FD8E
COUT      = $FDED
GETLN     = $FD6A
OUTPORT   = $FE95

STRLEN    = $2D00
SUMSTR    = $E00
PWRSTR    = SUMSTR+STRLEN
TEMPSTR   = PWRSTR+STRLEN

MOV       MAC
          LDA ]1
          STA ]2
          <<<

MOVD      MAC
          MOV ]1         ;]2
          MOV ]1+1       ;]2+1
          <<<

INCD      MAC
          INC ]1
          BNE NC
          INC ]1+1
NC
          <<<

ADD       MAC
          CLC
          LDA ]2
          STA ]3
          LDA #>]1
          ADC ]2+1
          STA ]3+1
          <<<

STADR     MAC
          LDA #]1
          STA ]2
          LDA #>]1
          STA ]2+1
          <<<
