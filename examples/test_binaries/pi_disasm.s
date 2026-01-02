*---------------------------------------
* Disassembly of: examples/test_binaries/pi.bin
* Load address: $0803
* Size: 1508 bytes
* File type: RAW
*---------------------------------------
         ORG   $0803

         LDA   #$00           ; $0803
         STA   DATA_07F8          ; $0805
         LDA   #$8C           ; $0808
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
         ORA   ($10,X)        ; $0821
         BPL   SUB_0831          ; $0823
         ORA   $20            ; $0825
         BPL   SUB_0832          ; $0827
         STA   DATA_A08D          ; $0829
         LDY   #$A0           ; $082C
         LDY   #$A0           ; $082E
         LDY   #$A0           ; $0830
SUB_0832 ???                  ; Referenced from: $0827, $0827
         INX                  ; $0833
         SBC   #$F3           ; $0834
         LDY   #$F0           ; $0836
         ???                  ; $0838
         ???                  ; $0839
         ???                  ; $083A
         ???                  ; $083B
         SBC   ($ED,X)        ; $083C
         LDY   #$E3           ; $083E
         ???                  ; $0840
         SBC   DATA_F5F0          ; $0841
         ???                  ; $0844
         SBC   $F3            ; $0845
         LDY   #$F0           ; $0847
         SBC   #$A0           ; $0849
         ???                  ; $084B
         ???                  ; $084C
         LDY   #$ED           ; $084D
         SBC   ($EE,X)        ; $084F
         SBC   $E4A0,Y        ; $0851
         SBC   $E3            ; $0854
         SBC   #$ED           ; $0856
         SBC   ($EC,X)        ; $0858
         LDY   #$F0           ; $085A
         CPX   DATA_E3E1          ; $085C
         SBC   $F3            ; $085F
         LDY   #$A8           ; $0861
         SBC   DATA_F8E1          ; $0863
         LDY   #$B1           ; $0866
         LDA   ($B5),Y        ; $0868
         LDA   ($B6),Y        ; $086A
         LDA   #$AE           ; $086C
         STA   ZP_8D          ; $086E
SUB_0871 LDX   #$28           ; Referenced from: $087F, $087F
         LDA   #$BD           ; $0873
SUB_0875 JSR   DATA_FDED          ; Referenced from: $0879, $0879
         DEX                  ; $0878
         BNE   SUB_0875          ; $0879
         LDA   $25            ; $087B
         CMP   #$04           ; $087D
         BEQ   SUB_0871          ; $087F
         JSR   SUB_0DAF          ; $0881
         STA   DATA_F5CE          ; $0884
         SBC   DATA_E5E2          ; $0887
         ???                  ; $088A
         LDY   #$EF           ; $088B
         INC   $A0            ; $088D
         LDA   ($B1),Y        ; $088F
         LDA   DATA_E8E3          ; $0891
         SBC   ($F2,X)        ; $0894
         LDX   DATA_E3A0          ; $0896
         ???                  ; $0899
         CPX   DATA_EDF5          ; $089A
         INC   DATA_A0F3          ; $089D
         INC   $EF            ; $08A0
         ???                  ; $08A2
         LDY   #$F0           ; $08A3
         ???                  ; $08A5
         SBC   #$EE           ; $08A6
         ???                  ; $08A8
         ???                  ; $08A9
         SBC   $F4,X          ; $08AA
         LDY   #$A8           ; $08AC
         LDA   ($AD),Y        ; $08AE
         LDA   ($B0),Y        ; $08B0
         LDA   #$A0           ; $08B2
         BRK                  ; $08B4
SUB_0DAF PLA                  ; Referenced from: $081E, $081E, $0881, $0881
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

         CHK