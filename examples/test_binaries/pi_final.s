*---------------------------------------
* Disassembly of: examples/test_binaries/pi.bin
* Load address: $0803
* Size: 1508 bytes
* File type: RAW
*---------------------------------------
         ORG   $0803

         LDA   #$00           ; $0803
         STA   DATA_07F8          ; $0805
SUB_0808 LDA   #$8C           ; Referenced from: $08C4, $08C4, $09A4, $09A4, $0B5B, $0B5B
         JSR   DATA_FDED          ; $080A
         JSR   DATA_FC58          ; $080D
         LDA   #$BA           ; $0810
         STA   $33            ; $0812
         LDA   #$10           ; $0814
         BIT   DATA_07F8          ; $0816
         BPL   SUB_081C          ; $0819
         ASL                  ; $081B
SUB_081C STA   $24            ; Referenced from: $0819, $0819
         JSR   SUB_0DAF          ; $081E
         HEX   0110100C05201009     ; $0821-$0828
         ASC   "
         HEX   8D
         ASC   ""
         HEX   8D
         ASC   "      "     ; $0829-$0830
         HEX   A0D4E8E9F3A0F0F2
         HEX   EFE7F2E1EDA0E3EF
         HEX   EDF0F5F4E5F3A0F0
         HEX   E9A0F4EFA0EDE1EE
         HEX   F9A0E4E5E3E9EDE1
         HEX   ECA0F0ECE1E3E5F3
         HEX   A0A8EDE1F8A0B1B1
         HEX   B5B1B6A9AE8D8D00     ; $0831-$0870
SUB_0871 LDX   #$28           ; Referenced from: $087F, $087F
         LDA   #$BD           ; $0873
SUB_0875 JSR   DATA_FDED          ; Referenced from: $0879, $0879
         DEX                  ; $0878
         BNE   SUB_0875          ; $0879
         LDA   $25            ; $087B
         CMP   #$04           ; $087D
         BEQ   SUB_0871          ; $087F
         JSR   SUB_0DAF          ; $0881
         HEX   8DCEF5EDE2E5F2A0
         HEX   EFE6A0B1B1ADE3E8
         HEX   E1F2AEA0E3EFECF5
         HEX   EDEEF3A0E6EFF2A0
         HEX   F0F2E9EEF4EFF5F4
         HEX   A0A8B1ADB1B0A9A0
         HEX   00     ; $0884-$08B4
         JSR   DATA_FD6A          ; $08B5
         TXA                  ; $08B8
         BEQ   SUB_08C7          ; $08B9
         LDA   DATA_0200          ; $08BB
         EOR   #$B0           ; $08BE
         CMP   #$0A           ; $08C0
         BCC   SUB_08D8          ; $08C2
SUB_08C4 JMP   SUB_0808          ; Referenced from: $08ED, $08ED, $08F1, $08F1, $08F5, $08F5
SUB_08C7 LDA   #$07           ; Referenced from: $08B9, $08B9
         BIT   DATA_07F8          ; $08C9
         BMI   SUB_08CF          ; $08CC
         LSR                  ; $08CE
SUB_08CF ORA   #$B0           ; Referenced from: $08CC, $08CC
         JSR   DATA_FDED          ; $08D1
         AND   #$07           ; $08D4
         BPL   SUB_08F3          ; $08D6
SUB_08D8 LDY   DATA_0201          ; Referenced from: $08C2, $08C2
         CPY   #$8D           ; $08DB
         BEQ   SUB_08F3          ; $08DD
         ASL                  ; $08DF
         STA   $17            ; $08E0
         ASL                  ; $08E2
         ASL                  ; $08E3
         ADC   $17            ; $08E4
         STA   $17            ; $08E6
         TYA                  ; $08E8
         EOR   #$B0           ; $08E9
         CMP   #$0A           ; $08EB
         BCS   SUB_08C4          ; $08ED
         ADC   $17            ; $08EF
         BEQ   SUB_08C4          ; $08F1
SUB_08F3 CMP   #$0B           ; Referenced from: $08D6, $08D6, $08DD, $08DD
         BCS   SUB_08C4          ; $08F5
         STA   $17            ; $08F7
         JSR   SUB_0DAF          ; $08F9
         HEX   8DCFF5F4F0F5F4A0
         HEX   F3ECEFF4A0A8D2D4
         HEX   CEA0E6EFF2A0F6E9
         HEX   E4E5EFA0F3E3F2E5
         HEX   E5EEA9BA00     ; $08FC-$0920
         JSR   DATA_FD0C          ; $0921
         CMP   #$8D           ; $0924
         BNE   SUB_092B          ; $0926
         LDA   DATA_07F8          ; $0928
SUB_092B AND   #$07           ; Referenced from: $0926, $0926
         STA   $18            ; $092D
         ORA   #$B0           ; $092F
         JSR   DATA_FDED          ; $0931
         JSR   SUB_0DAF          ; $0934
         ASC   "
         HEX   8D
         ASC   ""
         HEX   8D
         ASC   "Initia"     ; $0937-$093E
         HEX   ECE9FAE1F4E9EFEE
         HEX   A0F3F4F2E9EEE7A0
         HEX   A8E9E6A0E1EEF9A9
         HEX   A000     ; $093F-$0958
         JSR   DATA_FD6A          ; $0959
SUB_095C LDA   $0200,X        ; Referenced from: $0963, $0963
         STA   $0280,X        ; $095F
         DEX                  ; $0962
         BPL   SUB_095C          ; $0963
         JSR   DATA_FD8E          ; $0965
SUB_0968 INX                  ; Referenced from: $0981, $0981
         LDA   $0280,X        ; $0969
         CMP   #$8D           ; $096C
         BEQ   SUB_0983          ; $096E
         CMP   #$A0           ; $0970
         BCS   SUB_097A          ; $0972
         ORA   #$C0           ; $0974
         LDY   #$3F           ; $0976
         STY   $32            ; $0978
SUB_097A JSR   DATA_FDED          ; Referenced from: $0972, $0972
         LDY   #$FF           ; $097D
         STY   $32            ; $097F
         BNE   SUB_0968          ; $0981
SUB_0983 JSR   SUB_0DAF          ; Referenced from: $096E, $096E
         HEX   8DC3EFF2F2E5E3F4
         HEX   BFA0A8D9AFCEA9BA
         HEX   00     ; $0986-$0996
SUB_0997 JSR   DATA_FD0C          ; Referenced from: $09A9, $09A9
         CMP   #$8D           ; $099A
         BEQ   SUB_09AB          ; $099C
         AND   #$DF           ; $099E
         CMP   #$CE           ; $09A0
         BNE   SUB_09A7          ; $09A2
         JMP   SUB_0808          ; $09A4
SUB_09A7 CMP   #$D9           ; Referenced from: $09A2, $09A2
         BNE   SUB_0997          ; $09A9
SUB_09AB LDA   #$D9           ; Referenced from: $099C, $099C
         JSR   DATA_FDED          ; $09AD
         JSR   SUB_0DAF          ; $09B0
         ASC   "
         HEX   8D
         ASC   ""
         HEX   8D
         ASC   "Number"     ; $09B3-$09BA
         HEX   A0EFE6A0E4E5E3E9
         HEX   EDE1ECA0F0ECE1E3
         HEX   E5F3A000     ; $09BB-$09CE
         JSR   DATA_FD6A          ; $09CF
         LDY   #$00           ; $09D2
         STY   $14            ; $09D4
         STY   $15            ; $09D6
SUB_09D8 LDA   $0200,Y        ; Referenced from: $0A16, $0A16
         CMP   #$8D           ; $09DB
         BEQ   SUB_0A1B          ; $09DD
         INY                  ; $09DF
         EOR   #$B0           ; $09E0
         CMP   #$0A           ; $09E2
         BCS   SUB_0A18          ; $09E4
         STA   $16            ; $09E6
         ASL   $14            ; $09E8
         ROL   $15            ; $09EA
         BCS   SUB_0A18          ; $09EC
         LDA   $15            ; $09EE
         STA   $0F            ; $09F0
         LDA   $14            ; $09F2
         ASL                  ; $09F4
         ROL   $0F            ; $09F5
         BCS   SUB_0A18          ; $09F7
         ASL                  ; $09F9
         ROL   $0F            ; $09FA
         BCS   SUB_0A18          ; $09FC
         ADC   $14            ; $09FE
         STA   $14            ; $0A00
         LDA   $0F            ; $0A02
         ADC   $15            ; $0A04
         STA   $15            ; $0A06
         BCS   SUB_0A18          ; $0A08
         LDA   $16            ; $0A0A
         ADC   $14            ; $0A0C
         STA   $14            ; $0A0E
         LDA   $15            ; $0A10
         ADC   #$00           ; $0A12
         STA   $15            ; $0A14
         BCC   SUB_09D8          ; $0A16
SUB_0A18 JMP   SUB_0A97          ; Referenced from: $09E4, $09E4, $09EC, $09EC, $09F7, $09F7, $09FC, $09FC, $0A08, $0A08... (6 more)
SUB_0A1B TYA                  ; Referenced from: $09DD, $09DD
         BEQ   SUB_0A18          ; $0A1C
         LDA   $14            ; $0A1E
         CLC                  ; $0A20
         ADC   #$02           ; $0A21
         STA   $14            ; $0A23
         LDX   $15            ; $0A25
         BCC   SUB_0A2C          ; $0A27
         INC   $15            ; $0A29
         INX                  ; $0A2B
SUB_0A2C CPX   #$2C           ; Referenced from: $0A27, $0A27
         BCC   SUB_0A36          ; $0A2E
         BNE   SUB_0A18          ; $0A30
         CMP   #$FF           ; $0A32
         BEQ   SUB_0A18          ; $0A34
SUB_0A36 LDA   #$00           ; Referenced from: $0A2E, $0A2E
         STA   $08            ; $0A38
         STA   $09            ; $0A3A
         LDA   #$00           ; $0A3C
         STA   $00            ; $0A3E
         LDA   #$0E           ; $0A40
         STA   $01            ; $0A42
         JSR   SUB_0D9F          ; $0A44
SUB_0A47 LDA   #$01           ; Referenced from: $0AC4, $0AC4
         STA   $06            ; $0A49
         LDA   #$00           ; $0A4B
         STA   $07            ; $0A4D
         LDA   #$00           ; $0A4F
         STA   $00            ; $0A51
         LDA   #$3B           ; $0A53
         STA   $01            ; $0A55
         JSR   SUB_0D9F          ; $0A57
         LDA   #$01           ; $0A5A
         BIT   $09            ; $0A5C
         BPL   SUB_0A62          ; $0A5E
         LDA   #$04           ; $0A60
SUB_0A62 STA   DATA_3B00          ; Referenced from: $0A5E, $0A5E
         JSR   SUB_0BCE          ; $0A65
         BIT   $09            ; $0A68
         BMI   SUB_0A71          ; $0A6A
         LDA   #$03           ; $0A6C
         STA   DATA_3B00          ; $0A6E
SUB_0A71 JSR   SUB_0D77          ; Referenced from: $0A6A, $0A6A, $0AB8, $0AB8
         LDA   #$00           ; $0A74
         STA   $00            ; $0A76
         LDA   #$68           ; $0A78
         STA   $01            ; $0A7A
         LDA   $06            ; $0A7C
         STA   $0A            ; $0A7E
         LDA   $07            ; $0A80
         STA   $0B            ; $0A82
         JSR   SUB_0C08          ; $0A84
         JSR   SUB_0D14          ; $0A87
         CLC                  ; $0A8A
         LDA   $06            ; $0A8B
         ADC   #$02           ; $0A8D
         STA   $06            ; $0A8F
         BCC   SUB_0AAD          ; $0A91
         INC   $07            ; $0A93
         BNE   SUB_0AAD          ; $0A95
SUB_0A97 JSR   SUB_0DAF          ; Referenced from: $0A18, $0A18
         HEX   8D8D878787CFF6E5     ; $0A9A-$0AA1
         HEX   F2E6ECEFF7A18D00     ; $0AA2-$0AA9
         JMP   SUB_0B34          ; $0AAA
SUB_0AAD LDA   $08            ; Referenced from: $0A91, $0A91, $0A95, $0A95
         EOR   #$FF           ; $0AAF
         STA   $08            ; $0AB1
         JSR   SUB_0BEC          ; $0AB3
         BIT   $11            ; $0AB6
         BMI   SUB_0A71          ; $0AB8
         BIT   $09            ; $0ABA
         BMI   SUB_0AC7          ; $0ABC
         LDA   #$FF           ; $0ABE
         STA   $09            ; $0AC0
         STA   $08            ; $0AC2
         JMP   SUB_0A47          ; $0AC4
SUB_0AC7 LDX   #$03           ; Referenced from: $0ABC, $0ABC
SUB_0AC9 LDA   $36,X          ; Referenced from: $0ACF, $0ACF
         STA   $0DE3,X        ; $0ACB
         DEX                  ; $0ACE
         BPL   SUB_0AC9          ; $0ACF
         LDA   DATA_07F8          ; $0AD1
         AND   #$07           ; $0AD4
         CMP   $18            ; $0AD6
         BEQ   SUB_0AEF          ; $0AD8
         LDA   $18            ; $0ADA
         JSR   DATA_FE95          ; $0ADC
         JSR   DATA_FD8E          ; $0ADF
         LDX   #$00           ; $0AE2
SUB_0AE4 LDA   $0280,X        ; Referenced from: $0AED, $0AED
         JSR   DATA_FDED          ; $0AE7
         INX                  ; $0AEA
         CMP   #$8D           ; $0AEB
         BNE   SUB_0AE4          ; $0AED
SUB_0AEF LDA   $14            ; Referenced from: $0AD8, $0AD8
         SEC                  ; $0AF1
         SBC   #$02           ; $0AF2
         STA   $04            ; $0AF4
         LDA   $15            ; $0AF6
         SBC   #$00           ; $0AF8
         STA   $05            ; $0AFA
         LDA   #$00           ; $0AFC
         STA   $00            ; $0AFE
         LDA   #$0E           ; $0B00
         STA   $01            ; $0B02
         JSR   DATA_FD8E          ; $0B04
         LDY   #$00           ; $0B07
         LDA   DATA_0E00          ; $0B09
         ORA   #$B0           ; $0B0C
         JSR   DATA_FDED          ; $0B0E
         LDA   #$AE           ; $0B11
         JSR   DATA_FDED          ; $0B13
         LDX   #$0A           ; $0B16
         LDA   $17            ; $0B18
         STA   $16            ; $0B1A
SUB_0B1C INC   $00            ; Referenced from: $0B68, $0B68, $0B73, $0B73, $0B84, $0B84
         BNE   SUB_0B22          ; $0B1E
         INC   $01            ; $0B20
SUB_0B22 LDA   $04            ; Referenced from: $0B1E, $0B1E
         BNE   SUB_0B5E          ; $0B24
         DEC   $05            ; $0B26
         BPL   SUB_0B5E          ; $0B28
         LDX   #$03           ; $0B2A
SUB_0B2C LDA   $0DE3,X        ; Referenced from: $0B32, $0B32
         STA   $36,X          ; $0B2F
         DEX                  ; $0B31
         BPL   SUB_0B2C          ; $0B32
SUB_0B34 JSR   SUB_0DAF          ; Referenced from: $0AAA, $0AAA
         ASC   "
         HEX   8D
         ASC   ""
         HEX   8D
         ASC   "Repeat"     ; $0B37-$0B3E
         ASC   " (Y/N)?"     ; $0B3F-$0B45
         HEX   8700     ; $0B46-$0B47
SUB_0B48 JSR   DATA_FD0C          ; Referenced from: $0B53, $0B53
         AND   #$DF           ; $0B4B
         CMP   #$D9           ; $0B4D
         BEQ   SUB_0B5B          ; $0B4F
         CMP   #$CE           ; $0B51
         BNE   SUB_0B48          ; $0B53
         JSR   DATA_FDED          ; $0B55
         JMP   DATA_E000          ; $0B58
SUB_0B5B JMP   SUB_0808          ; Referenced from: $0B4F, $0B4F
SUB_0B5E DEC   $04            ; Referenced from: $0B24, $0B24, $0B28, $0B28
         LDA   ($00),Y        ; $0B60
         ORA   #$B0           ; $0B62
         JSR   DATA_FDED          ; $0B64
         DEX                  ; $0B67
         BNE   SUB_0B1C          ; $0B68
         LDA   #$A0           ; $0B6A
         JSR   DATA_FDED          ; $0B6C
         LDX   #$0A           ; $0B6F
         DEC   $16            ; $0B71
         BNE   SUB_0B1C          ; $0B73
         JSR   DATA_FD8E          ; $0B75
         LDA   #$A0           ; $0B78
         JSR   DATA_FDED          ; $0B7A
         JSR   DATA_FDED          ; $0B7D
         LDA   $17            ; $0B80
         STA   $16            ; $0B82
         BNE   SUB_0B1C          ; $0B84
SUB_0B86 LDY   #$00           ; Referenced from: $0C19, $0C19, $0C49, $0C49, $0CBE, $0CBE
         STY   $11            ; $0B88
         CLC                  ; $0B8A
         LDA   $00            ; $0B8B
         ADC   $19            ; $0B8D
         STA   $00            ; $0B8F
         LDA   $01            ; $0B91
         ADC   $1A            ; $0B93
         STA   $01            ; $0B95
SUB_0B97 LDA   ($00),Y        ; Referenced from: $0B9C, $0B9C
         BNE   SUB_0BA1          ; $0B99
         INY                  ; $0B9B
         BNE   SUB_0B97          ; $0B9C
SUB_0B9E PLA                  ; Referenced from: $0BC7, $0BC7
         PLA                  ; $0B9F
         RTS                  ; $0BA0
SUB_0BA1 STA   $0C            ; Referenced from: $0B99, $0B99
         TYA                  ; $0BA3
         ADC   $00            ; $0BA4
         STA   $00            ; $0BA6
         BCC   SUB_0BAD          ; $0BA8
         INC   $01            ; $0BAA
         CLC                  ; $0BAC
SUB_0BAD TYA                  ; Referenced from: $0BA8, $0BA8
         ADC   $19            ; $0BAE
         STA   $19            ; $0BB0
         BCC   SUB_0BB6          ; $0BB2
         INC   $1A            ; $0BB4
SUB_0BB6 LDA   $14            ; Referenced from: $0BB2, $0BB2
         SEC                  ; $0BB8
         SBC   $19            ; $0BB9
         EOR   #$FF           ; $0BBB
         STA   $04            ; $0BBD
         LDA   $15            ; $0BBF
         SBC   $1A            ; $0BC1
         EOR   #$FF           ; $0BC3
         STA   $05            ; $0BC5
         BPL   SUB_0B9E          ; $0BC7
         LDY   #$00           ; $0BC9
         DEC   $11            ; $0BCB
         RTS                  ; $0BCD
SUB_0BCE LDA   #$00           ; Referenced from: $0A65, $0A65
         STA   $00            ; $0BD0
         LDA   #$3B           ; $0BD2
         STA   $01            ; $0BD4
         LDA   #$05           ; $0BD6
         STA   $0A            ; $0BD8
         LDA   #$00           ; $0BDA
         STA   $0B            ; $0BDC
         STA   $19            ; $0BDE
         STA   $1A            ; $0BE0
         BIT   $09            ; $0BE2
         BPL   SUB_0C08          ; $0BE4
         LDA   #$EF           ; $0BE6
         STA   $0A            ; $0BE8
         BNE   SUB_0C08          ; $0BEA
SUB_0BEC LDA   #$00           ; Referenced from: $0AB3, $0AB3
         STA   $00            ; $0BEE
         LDA   #$3B           ; $0BF0
         STA   $01            ; $0BF2
         LDA   #$19           ; $0BF4
         STA   $0A            ; $0BF6
         LDA   #$00           ; $0BF8
         STA   $0B            ; $0BFA
         BIT   $09            ; $0BFC
         BPL   SUB_0C08          ; $0BFE
         LDA   #$21           ; $0C00
         STA   $0A            ; $0C02
         LDA   #$DF           ; $0C04
         STA   $0B            ; $0C06
SUB_0C08 LDA   $0B            ; Referenced from: $0A84, $0A84, $0BE4, $0BE4, $0BEA, $0BEA, $0BFE, $0BFE
         BEQ   SUB_0C13          ; $0C0A
         CMP   #$19           ; $0C0C
         BCS   SUB_0C49          ; $0C0E
SUB_0C10 JMP   SUB_0CBE          ; Referenced from: $0C17, $0C17
SUB_0C13 LDA   $0A            ; Referenced from: $0C0A, $0C0A
         CMP   #$1A           ; $0C15
         BCS   SUB_0C10          ; $0C17
         JSR   SUB_0B86          ; $0C19
         LDA   $0C            ; $0C1C
         JMP   SUB_0C29          ; $0C1E
SUB_0C21 INC   $00            ; Referenced from: $0C42, $0C42, $0C46, $0C46
         BNE   SUB_0C27          ; $0C23
         INC   $01            ; $0C25
SUB_0C27 ADC   ($00),Y        ; Referenced from: $0C23, $0C23
SUB_0C29 LDX   #$FF           ; Referenced from: $0C1E, $0C1E
         SEC                  ; $0C2B
SUB_0C2C STA   $0C            ; Referenced from: $0C31, $0C31
         INX                  ; $0C2E
         SBC   $0A            ; $0C2F
         BCS   SUB_0C2C          ; $0C31
         TXA                  ; $0C33
         STA   ($00),Y        ; $0C34
         ASL   $0C            ; $0C36
         LDA   $0C            ; $0C38
         ASL                  ; $0C3A
         ASL                  ; $0C3B
         ADC   $0C            ; $0C3C
         STA   $0C            ; $0C3E
         INC   $04            ; $0C40
         BNE   SUB_0C21          ; $0C42
         INC   $05            ; $0C44
         BNE   SUB_0C21          ; $0C46
         RTS                  ; $0C48
SUB_0C49 JSR   SUB_0B86          ; Referenced from: $0C0E, $0C0E
         STY   $0D            ; $0C4C
         STY   $0E            ; $0C4E
SUB_0C50 LDX   #$00           ; Referenced from: $0CB2, $0CB2, $0CB6, $0CB6, $0CBA, $0CBA
SUB_0C52 LDA   $0C            ; Referenced from: $0C6C, $0C6C
         CMP   $0A            ; $0C54
         LDA   $0D            ; $0C56
         SBC   $0B            ; $0C58
         TAY                  ; $0C5A
         LDA   $0E            ; $0C5B
         SBC   #$00           ; $0C5D
         BCC   SUB_0C6F          ; $0C5F
         STA   $0E            ; $0C61
         LDA   $0C            ; $0C63
         SBC   $0A            ; $0C65
         STA   $0C            ; $0C67
         STY   $0D            ; $0C69
         INX                  ; $0C6B
         JMP   SUB_0C52          ; $0C6C
SUB_0C6F TXA                  ; Referenced from: $0C5F, $0C5F
         LDY   #$00           ; $0C70
         STA   ($00),Y        ; $0C72
         ASL   $0C            ; $0C74
         ROL   $0D            ; $0C76
         ROL   $0E            ; $0C78
         LDA   $0D            ; $0C7A
         STA   $0F            ; $0C7C
         LDA   $0E            ; $0C7E
         STA   $10            ; $0C80
         LDA   $0C            ; $0C82
         ASL                  ; $0C84
         ROL   $0F            ; $0C85
         ROL   $10            ; $0C87
         ASL                  ; $0C89
         ROL   $0F            ; $0C8A
         ROL   $10            ; $0C8C
         ADC   $0C            ; $0C8E
         STA   $0C            ; $0C90
         LDA   $0F            ; $0C92
         ADC   $0D            ; $0C94
         STA   $0D            ; $0C96
         LDA   $10            ; $0C98
         ADC   $0E            ; $0C9A
         STA   $0E            ; $0C9C
         INC   $04            ; $0C9E
         BNE   SUB_0CA6          ; $0CA0
         INC   $05            ; $0CA2
         BEQ   SUB_0CBD          ; $0CA4
SUB_0CA6 INC   $00            ; Referenced from: $0CA0, $0CA0
         BNE   SUB_0CAC          ; $0CA8
         INC   $01            ; $0CAA
SUB_0CAC LDA   $0C            ; Referenced from: $0CA8, $0CA8
         ADC   ($00),Y        ; $0CAE
         STA   $0C            ; $0CB0
         BCC   SUB_0C50          ; $0CB2
         INC   $0D            ; $0CB4
         BNE   SUB_0C50          ; $0CB6
         INC   $0E            ; $0CB8
         JMP   SUB_0C50          ; $0CBA
SUB_0CBD RTS                  ; Referenced from: $0CA4, $0CA4
SUB_0CBE JSR   SUB_0B86          ; Referenced from: $0C10, $0C10
         STY   $0D            ; $0CC1
SUB_0CC3 LDX   #$00           ; Referenced from: $0D0C, $0D0C, $0D10, $0D10
         SEC                  ; $0CC5
SUB_0CC6 LDA   $0C            ; Referenced from: $0CD6, $0CD6
         SBC   $0A            ; $0CC8
         TAY                  ; $0CCA
         LDA   $0D            ; $0CCB
         SBC   $0B            ; $0CCD
         BCC   SUB_0CD9          ; $0CCF
         STA   $0D            ; $0CD1
         STY   $0C            ; $0CD3
         INX                  ; $0CD5
         JMP   SUB_0CC6          ; $0CD6
SUB_0CD9 TXA                  ; Referenced from: $0CCF, $0CCF
         LDY   #$00           ; $0CDA
         STA   ($00),Y        ; $0CDC
         ASL   $0C            ; $0CDE
         ROL   $0D            ; $0CE0
         LDA   $0D            ; $0CE2
         STA   $0F            ; $0CE4
         LDA   $0C            ; $0CE6
         ASL                  ; $0CE8
         ROL   $0F            ; $0CE9
         ASL                  ; $0CEB
         ROL   $0F            ; $0CEC
         ADC   $0C            ; $0CEE
         STA   $0C            ; $0CF0
         LDA   $0F            ; $0CF2
         ADC   $0D            ; $0CF4
         STA   $0D            ; $0CF6
         INC   $04            ; $0CF8
         BNE   SUB_0D00          ; $0CFA
         INC   $05            ; $0CFC
         BEQ   SUB_0D13          ; $0CFE
SUB_0D00 INC   $00            ; Referenced from: $0CFA, $0CFA
         BNE   SUB_0D06          ; $0D02
         INC   $01            ; $0D04
SUB_0D06 LDA   $0C            ; Referenced from: $0D02, $0D02
         ADC   ($00),Y        ; $0D08
         STA   $0C            ; $0D0A
         BCC   SUB_0CC3          ; $0D0C
         INC   $0D            ; $0D0E
         JMP   SUB_0CC3          ; $0D10
SUB_0D13 RTS                  ; Referenced from: $0CFE, $0CFE
SUB_0D14 CLC                  ; Referenced from: $0A87, $0A87
         LDA   $14            ; $0D15
         STA   $00            ; $0D17
         LDA   #$0E           ; $0D19
         ADC   $15            ; $0D1B
         STA   $01            ; $0D1D
         CLC                  ; $0D1F
         LDA   $14            ; $0D20
         STA   $02            ; $0D22
         LDA   #$68           ; $0D24
         ADC   $15            ; $0D26
         STA   $03            ; $0D28
         SEC                  ; $0D2A
         LDA   $15            ; $0D2B
         SBC   $1A            ; $0D2D
         BMI   SUB_0D59          ; $0D2F
         TAX                  ; $0D31
         SEC                  ; $0D32
         LDY   #$00           ; $0D33
         BIT   $08            ; $0D35
         BMI   SUB_0D5E          ; $0D37
         CLC                  ; $0D39
         BCC   SUB_0D40          ; $0D3A
SUB_0D3C DEC   $00            ; Referenced from: $0D4E, $0D4E, $0D55, $0D55, $0D57, $0D57
         DEC   $02            ; $0D3E
SUB_0D40 LDA   ($00),Y        ; Referenced from: $0D3A, $0D3A
         ADC   ($02),Y        ; $0D42
         CMP   #$0A           ; $0D44
         BCC   SUB_0D4A          ; $0D46
         SBC   #$0A           ; $0D48
SUB_0D4A STA   ($00),Y        ; Referenced from: $0D46, $0D46
         LDA   $00            ; $0D4C
         BNE   SUB_0D3C          ; $0D4E
         DEC   $01            ; $0D50
         DEC   $03            ; $0D52
         DEX                  ; $0D54
         BPL   SUB_0D3C          ; $0D55
         BCS   SUB_0D3C          ; $0D57
SUB_0D59 RTS                  ; Referenced from: $0D2F, $0D2F
SUB_0D5A DEC   $00            ; Referenced from: $0D6B, $0D6B, $0D72, $0D72, $0D74, $0D74
         DEC   $02            ; $0D5C
SUB_0D5E LDA   ($00),Y        ; Referenced from: $0D37, $0D37
         SBC   ($02),Y        ; $0D60
         BPL   SUB_0D67          ; $0D62
         ADC   #$0A           ; $0D64
         CLC                  ; $0D66
SUB_0D67 STA   ($00),Y        ; Referenced from: $0D62, $0D62
         LDA   $00            ; $0D69
         BNE   SUB_0D5A          ; $0D6B
         DEC   $01            ; $0D6D
         DEC   $03            ; $0D6F
         DEX                  ; $0D71
         BPL   SUB_0D5A          ; $0D72
         BCC   SUB_0D5A          ; $0D74
         RTS                  ; $0D76
SUB_0D77 LDA   $1A            ; Referenced from: $0A71, $0A71
         LDY   #$00           ; $0D79
         STY   $00            ; $0D7B
         STY   $02            ; $0D7D
         CLC                  ; $0D7F
         ADC   #$3B           ; $0D80
         STA   $01            ; $0D82
         LDA   $1A            ; $0D84
         ADC   #$68           ; $0D86
         STA   $03            ; $0D88
         SEC                  ; $0D8A
         LDA   $15            ; $0D8B
         SBC   $1A            ; $0D8D
         TAX                  ; $0D8F
SUB_0D90 LDA   ($00),Y        ; Referenced from: $0D95, $0D95, $0D9C, $0D9C
         STA   ($02),Y        ; $0D92
         INY                  ; $0D94
         BNE   SUB_0D90          ; $0D95
         INC   $01            ; $0D97
         INC   $03            ; $0D99
         DEX                  ; $0D9B
         BPL   SUB_0D90          ; $0D9C
         RTS                  ; $0D9E
SUB_0D9F LDY   #$00           ; Referenced from: $0A44, $0A44, $0A57, $0A57
         TYA                  ; $0DA1
         LDX   $15            ; $0DA2
SUB_0DA4 STA   ($00),Y        ; Referenced from: $0DA7, $0DA7, $0DAC, $0DAC
         INY                  ; $0DA6
         BNE   SUB_0DA4          ; $0DA7
         INC   $01            ; $0DA9
         DEX                  ; $0DAB
         BPL   SUB_0DA4          ; $0DAC
         RTS                  ; $0DAE
SUB_0DAF PLA                  ; Referenced from: $081E, $081E, $0881, $0881, $08F9, $08F9, $0934, $0934, $0983, $0983... (6 more)
         STA   $12            ; $0DB0
         PLA                  ; $0DB2
         STA   $13            ; $0DB3
         BNE   SUB_0DBA          ; $0DB5
SUB_0DB7 JSR   SUB_0DCD          ; Referenced from: $0DC4, $0DC4
SUB_0DBA LDY   #$00           ; Referenced from: $0DB5, $0DB5
         INC   $12            ; $0DBC
         BNE   SUB_0DC2          ; $0DBE
         INC   $13            ; $0DC0
SUB_0DC2 LDA   ($12),Y        ; Referenced from: $0DBE, $0DBE
         BNE   SUB_0DB7          ; $0DC4
         LDA   $13            ; $0DC6
         PHA                  ; $0DC8
         LDA   $12            ; $0DC9
         PHA                  ; $0DCB
         RTS                  ; $0DCC
SUB_0DCD BMI   SUB_0DDA          ; Referenced from: $0DB7, $0DB7
         LDY   #$3F           ; $0DCF
         STY   $32            ; $0DD1
         CLC                  ; $0DD3
         AND   #$3F           ; $0DD4
         ADC   #$20           ; $0DD6
         EOR   #$E0           ; $0DD8
SUB_0DDA JSR   DATA_FDED          ; Referenced from: $0DCD, $0DCD
         LDY   #$FF           ; $0DDD
         STY   $32            ; $0DDF
         INY                  ; $0DE1
         RTS                  ; $0DE2
         HEX   F0FD     ; $0DE3-$0DE4
         HEX   1BFD     ; $0DE5-$0DE6

         CHK