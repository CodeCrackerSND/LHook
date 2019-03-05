; #########################################################################

      .386
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\MasmBasic\MasmBasic.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

; #########################################################################

Dissasm     PROTO   :DWORD,:DWORD

.data
IndexBakup dd 0
RegRepeat  dd 0
AddrRepeat dd 0
LockRepeat dd 0
RepRepeat  dd 0
SegRepeat  dd 0
Bit_D db 0
Bit_W db 0
modrmb db 0
sib db 0

DisplOffset dd 0
DisplOffset2 dd 0
FourBytesSub dd 0

Op db 0
NextOp db 0
NextOp2 db 0
opcode2 db 0
IsWord db 0

InstructionSize dd 0
SubstractFromPos dd 0

.code

Dissasm  proc uses esi ecx edi ebx edx addrs:DWORD, index:DWORD
.if (addrs==0||index<0)
xor eax,eax
ret
.endif

mov RegRepeat,0
mov AddrRepeat,0
mov LockRepeat,0
mov RepRepeat,0
mov SegRepeat,0
mov InstructionSize,0
mov DisplOffset,0
mov DisplOffset2,0
mov FourBytesSub,0
mov SubstractFromPos,0
mov IsWord,0

mov eax,index
mov IndexBakup,eax

mov ebx,addrs ; ebx = address
mov ecx,index ; ecx = index

mov al, byte ptr [ebx+ecx]
mov Op, al ; current opcode

; check only RegPreifix/LockProfix/SegPrefixes/RepPrefix/AddrPerfix
.while (Op==066h||Op==0F0h||Op==02Eh||Op==36h||Op==03Eh||Op==026h||Op==064h||Op==065h||Op==0F2h||Op==0F3h||Op==067h)

		Switch_ Op
		Case_ 066h  ; reg prefix, change default size, dword->word
		      mov IsWord,1
			inc ecx ; increment index
                  mov al, byte ptr [ebx+ecx]
			mov Op, al ; current opcode
                  inc RegRepeat
                  inc InstructionSize

			.if (RegRepeat>1)
                  ret			
                  .endif

                  
		Case_ 067h	; Addr prefix, change default Reg size, (EDI->DI) and more!
			inc ecx ; increment index
                  mov al, byte ptr [ebx+ecx]
			mov Op, al ; current opcode
                  inc AddrRepeat
                  inc InstructionSize

			.if (AddrRepeat>1)
                  ret			
                  .endif

		Case_ 0F0h	; LockPrefix, Add bus lock menemonic opcode in front of every menemonic
			inc ecx ; increment index
                  mov al, byte ptr [ebx+ecx]
			mov Op, al ; current opcode
                  inc LockRepeat
                  inc InstructionSize

			.if (LockRepeat>1)
                  ret			
                  .endif

            Case_ 0F2h, 0F3h ; RepPrefix (only string instruction!!)
                  inc InstructionSize ; increment instruction size
                  inc ecx  ; increment instruction index

                  inc RepRepeat
                  mov al, byte ptr [ebx+ecx]
			mov Op, al ; next opcode
                  
; REPE/REPNE Prefixes affect only string operations:
; MOVS/LODS/SCAS/CMPS/STOS/CMPSS.CMPPS..etc (NewSet Instructions)

.if !((Op>=0A4h&&Op<=0A7h)||(Op>=0AAh&&Op<=0AFh)||(NextOp==00Fh&&(NextOp2==02Ah||NextOp2==010h||NextOp2==011h||NextOp2==02Ch||NextOp2==02Dh||NextOp2==051h||NextOp2==052h||NextOp2==053h||NextOp2==058h||NextOp2==059h||NextOp2==05Ch||NextOp2==05Dh||NextOp2==05Eh||NextOp2==05Fh||NextOp2==0C2h)))
; Prefix REP:
; Do nothing here! These are just bogus instruction which actually don't accept prefixes!
; Non-working instructions with prefixes:
; 004012CA      F2:           PREFIX REPNE:                            ;  Superfluous prefix
; 004012CB      A8 CC         TEST AL,0CC

; 004012B5      F2            DB F2
; 004012B6      0FA9          POP GS                                   ;  Modification of segment register
; ret
.endif

Case_ 02Eh, 036h, 03Eh, 026h, 064h, 065h  ; Segment Prefixes
			inc ecx ; increment index
                  mov al, byte ptr [ebx+ecx]
			mov Op, al ; current opcode
                  inc SegRepeat
                  inc InstructionSize

			.if (SegRepeat>1)
                  ret			
                  .endif
                  
       
		Default_
			nop
		Endsw_

.endw
; \ - contiune on next line character
; Main Decoding starts here! 
    Switch_ Op ;' Find & Decode Big Set Opcodes
    Case_ 00h, 01h, 02h, 03h,\ ; ADD  XX/XXX, XX/XXX
    08h, 09h, 0Ah, 0Bh,\ ; OR   XX/XXX, XX/XXX
    010h, 011h, 012h, 013h,\ ; ADC  XX/XXX, XX/XXX 
    018h, 019h, 01Ah, 01Bh,\ ; SBB  XX/XXX, XX/XXX 
    020h, 021h, 022h, 023h,\ ; AND  XX/XXX, XX/XXX 
    028h, 029h, 02Ah, 02Bh,\ ; SUB  XX/XXX, XX/XXX 
    030h, 031h, 032h, 033h,\ ; XOR  XX/XXX, XX/XXX 
    038h, 039h, 03Ah, 03Bh,\ ; CMP  XX/XXX, XX/XXX 
    088h, 089h, 08Ah, 08Bh  ; MOV  XX/XXX, XX/XXX
    jmp MainProcessIns
    
    Case_ 08Ch, 08Eh,\ ; MOV  XX/XXX, XX/XXX
    062h, 063h,\ ; BOUND / ARPL XX/XXX, XX/XXX
    069h,\ ; IMUL RM,IIM32 (DWORD)
    06Bh,\ ; IMUL <reg>,<RM>
    084h, 085h,\ ; TEST
    086h, 087h ; XCHG
    jmp MainProcessIns

    ; 81 has to be treated alone!
    Case_ 080h, 082h, 083h ; MIXED Instructions
    inc InstructionSize ; count 1 last byte of direct value
    inc SubstractFromPos ; last bytes doesn't count as position
    jmp MainProcessIns

    Case_ 081h
    add InstructionSize,4 ; count last 4 byte of direct value
    jmp MainProcessIns
        
    Case_ 08Dh,\          ; LEA 
    08Fh,\                 ; POP
    0C4h, 0C5h,\           ; LES / LDS REG,MEM
    0D0h, 0D1h, 0D2h, 0D3h,\ ; MIXED Bitwise Instructions
    0D8h, 0D9h, 0DAh, 0DBh,\ ; FPU Instructions
    0DCh, 0DDh, 0DEh, 0DFh,\ ; FPU Instructions
    0FEh, 0FFh ; MIX Instructions
    jmp MainProcessIns
    ; 0F6h, 0F7h, - threated elsewhere

    Case_ 0C0h, 0C1h, 0C6h  ; MIXED Instructions / Mov + byte offset
    inc InstructionSize ; one byte (imediate) at the end
    inc SubstractFromPos ; last bytes doesn't count as position
    jmp MainProcessIns

    Case_ 0C7h
    .if (IsWord==0)
    add InstructionSize,04 ; one dword (imediate) at the end
    add SubstractFromPos,04 ; one dword (imediate) at the end
    mov FourBytesSub,4
    jmp MainProcessIns
    .else
    add InstructionSize,02 ; one word (imediate) at the end
    .endif

    Case_ 0F6h ; funny subblock of opcodes
    mov al,byte ptr [ebx+ecx+1]

    .if (al==05)  ; just a creapy exception
    inc SubstractFromPos
    .endif

    .if ((al>=80h)&&(al<=087h))
    mov eax,InstructionSize
    add eax,2
    mov DisplOffset,eax
    add InstructionSize,7
    ret
    .endif

    .if (((al>=010h)&&(al<=03Fh))||((al>=048h)&&(al<=07Fh))||\
    ((al>=090h)&&(al<=0BFh))||((al>=0C8h)&&(al<=0FFh)))

    jmp MainProcessIns
    .else
    inc InstructionSize
    jmp MainProcessIns
    .endif
  
    Case_ 0F7h ; funny subblock of opcodes
    mov al,byte ptr [ebx+ecx+1]

    .if ((al>=0)&&(al<=07))
    mov eax,InstructionSize
    add eax,2
    mov DisplOffset,eax
    add InstructionSize,6
    ret
    .endif

    .if ((al>=40h)&&(al<=047h))
    mov eax,InstructionSize
    add eax,3
    mov DisplOffset,eax
    add InstructionSize,7
    ret
    .endif

    .if ((al>=80h)&&(al<=087h))
    mov eax,InstructionSize
    add eax,2
    mov DisplOffset,eax
    add InstructionSize,10
    ret
    .endif

    .if ((al>=0C0h)&&(al<=0C7h))
    mov eax,InstructionSize
    add eax,2
    mov DisplOffset,eax
    add InstructionSize,6
    ret
    .endif

    .if (((al>=010h)&&(al<=03Fh))||((al>=048h)&&(al<=07Fh))||\
    ((al>=090h)&&(al<=0BFh))||((al>=0C8h)&&(al<=0FFh)))

    jmp MainProcessIns
    .else
    inc InstructionSize
    jmp MainProcessIns
    .endif
    


  ; ONE BYTE OPCODE, move to next opcode without remark
  Case_ 006h, 007h,\ ; PUSH ES and POP ES
  00Eh,\       ; PUSH CS
  016h, 017h,\ ; PUSH SS and POP SS
  01Eh, 01Fh,\ ; PUSH DS and POP DS
  027h, 02Fh,\ ; DAA and DAS
  037h, 03Fh  ; AAA and AAS
  inc InstructionSize
  ret

  Case_ 040h, 041h, 042h, 043h, 044h, 045h, 046h, 047h,\  ; inc eax - inc edi
  048h, 049h, 04Ah, 04Bh, 04Ch, 04Dh, 04Eh, 04Fh,\  ; dec eax - dec edi
  050h, 051h, 052h, 053h, 054h, 055h, 056h, 057h,\  ; push eax - push edi
  058h, 059h, 05Ah, 05Bh, 05Ch, 05Dh, 05Eh, 05Fh,\  ; pop eax - pop edi
  060h, 061h, ; PUSHAD and POPAD
  inc InstructionSize
  ret

  Case_ 06Ch, 06Dh, 06Eh, 06Fh,\ ; 2 INS / 2 OUTS
  090h,\ ; nop
  091h, 092h, 093h, 094h, 095h, 096h, 097h,\ ; xchg
  098h, 099h,\  ; CWDE and CDQ
  09Bh,\  ; WAIT
  09Ch, 09Dh, 09Eh, 09Fh,\  ; PUSHFD, POPFD, SAHF, LAHF
  0A4h, 0A5h, 0A6h, 0A7h, 0AAh, 0ABh,\ ; string operators
  0ACh, 0ADh, 0AEh, 0AFh
  ; ->LODS BYTE PTR DS:[ESI], LODS DWORD PTR DS:[ESI], SCAS BYTE PTR ES:[EDI], SCAS DWORD PTR ES:[EDI]
  inc InstructionSize
  ret

  Case_ 0D6h, 0D7h,\ ; SALC / XLAT  
  0C3h,\ ; RET handled HERE!
  0C9h,\ ; LEAVE
  0CBh,\ ; RETF
  0CCh,\ ; int3
  0CEh,\ ; INTO
  0CFh,\ ; IRETD
  0F1h,\ ; INT1
  0F4h,\ ; HLT
  0F5h, 0F8h, 0F9h,\ ; CMC, CLC, STC,
  0FAh, 0FBh,\  ; CLI / STI
  0FCh, 0FDh  ;  CLD, STD
  inc InstructionSize
  ret

    ; 0xC2, C2 0000 RETN 0 - WTF? this is 3 bytes instruction!
    
    ; TWO BYTE INSTRUCTION
  Case_ 004h, 00Ch, 014h, 01Ch, 024h, 02Ch, 034h, 03Ch,\ ; ADD/OR/ADC/SBB/AND/SUB/XOR/CMP AL,bvalue
    06Ah,\  ; push byte_value
    0A8h,\  ; TEST AL,bvalue
    0B0h, 0B1h, 0B2h, 0B3h, 0B4h, 0B5h, 0B6h, 0B7h,\ ; MOV AL-..BH,bvalue
    0CDh,\ ; CD 12              INT 0x12
    0D4h, 0D5h ; AAM, AAD
  add InstructionSize,2
  ret
  
    ; TWO BYTE RELATIVE BRANCH
 Case_ 070h, 071h, 072h, 073h, 074h, 075h, 076h, 077h,\
    078h, 079h, 07Ah, 07Bh, 07Ch, 07Dh, 07Eh, 07Fh,\
    0E0h, 0E1h, 0E2h, 0E3h,\	; LOOPDNE / LOOPDE / LOOPD / JECXZ
    0E4h, 0E5h,\ ; IN AL, / IN EAX,
    0E6h, 0E7h,\ ; OUT 0x11,AL / OUT 0x11,EAX
    0EBh,\  ; JMP SHORT
    0ECh, 0EDh,\  ; IN AL,DX / IN EAX,DX
    0EEh, 0EFh  ; OUT DX,AL / OUT DX,EAX
  add InstructionSize,2
  ret

 Case_ 0C2h, 0CAh
  add InstructionSize,3  ; C2 0000 RETN 0 / CA 1234  RETF 0x3412
  ret

 Case_ 0C8h
  add InstructionSize,4 ; C8 123456  ENTER 0x3412,0x56
  ret

   ; FIVE BYTE INSTRUCTION:
 Case_ 05h, 0Dh, 015h, 01Dh,\ ; ADD/OR/ADC/SBB eax,value
   025h, 02Dh, 035h, 03Dh,\ ; AND/SUB/XOR/CMP eax,value 
   068h,\  ; PUSH DWORD_VALUE
   0A9h,\  ; TEST EAX,value
   0B8h, 0B9h, 0BAh, 0BBh, 0BCh, 0BDh, 0BEh, 0BFh,\  ; MOV EAX-EDI,value
   0E8h,\ ; FIVE BYTE RELATIVE CALL
   0E9h,\ ; FIVE BYTE RELATIVE BRANCH
   0A0h, 0A1h, 0A2h, 0A3h ; MOV AL,AX,EAX moffset...

 .if (Op!=0E8h&&Op!=0E9h) ; no jump or call
  mov eax,InstructionSize
  sub eax,SubstractFromPos
  inc eax
  mov DisplOffset,eax
 .endif

  add InstructionSize,5
  ret
  
 Case_ 09Ah, 0EAh
  add InstructionSize,7
  ret

 Case_ 0Fh ; Intel's special prefix opcode
 jmp ProcessIntelInstructions

    MainProcessIns:
    inc InstructionSize ; account for first opcode
    mov al, byte ptr [ebx+ecx+1] ; get next byte
    and al,0C0h

    inc ecx ; skipp first opcode

    MainProcessInsFeeted:

    .if (al==0C0h)  ; Check Opcode Range
    mov al,byte ptr [ebx+ecx+1]
    and al,002h
    shr al,1
    mov Bit_D,al ; Get bit d (direction)
    
    mov al,byte ptr [ebx+ecx]
    and al,01h
    mov Bit_W,al ; Get bit w (full/partial reg size)



    ; Check Special Cases for alone Opcodes
    Switch_ Op
       Case_ 063h
       mov Bit_D,0
       mov Bit_W,1
       Case_ 062h
       mov Bit_D,1
       mov Bit_W,1
       Case_ 086h
       mov Bit_D,0
       mov Bit_W,0
       Case_ 087h
       mov Bit_D,0
       mov Bit_W,1
       Case_ 080h, 082h
       mov Bit_D,0
       mov Bit_W,0
       Case_ 081h, 083h
       mov Bit_D,0
       mov Bit_W,1
       Case_ 08Ch
       mov Bit_D,0
       mov Bit_W,0
       Case_ 08Eh
       mov Bit_D,1
       mov Bit_W,0
       Case_ 0C4h, 0C5h
       mov Bit_D,1
       mov Bit_W,1
       ; some addresses pushed on stack and return from them!
       Endsw_
    
    .endif

    Endsw_

    ; // HERE SHOULD PROCESS mod!
ModProcess:
mov al, byte ptr [ebx+ecx] ; get next byte - +1
mov modrmb,al
.if (al>=0C0h)  ; Second byte - Check Opcode Range
; two bytes instructions
inc InstructionSize ; account for next byte
call FixDisplOffset2
ret
.else  ; memory access
and al,07h
.if (al==04)  ; instruction with SIB byte
inc InstructionSize ; account for SIB byte
add ecx,01
mov al, byte ptr [ebx+ecx] ; fetch the sib byte
mov sib,al
and al,07h
.if (al==05)
mov al,modrmb
and al,0C0h
.if (bl==040h)
add InstructionSize,2 ; account for MOD + 1 byte displacement
call FixDisplOffset2
ret
.else
mov eax,InstructionSize
sub eax,SubstractFromPos
inc eax ; MOD
mov DisplOffset,eax
add InstructionSize,5 ; account for MOD + dword displacement 4 byte displacement
call FixDisplOffset2
ret
.endif  ; .if bl==0x40

.endif ; .if (al==05)

.endif ; .if (al==04)

mov al,modrmb
and al,0C0h

        Switch_ al 
	  Case_ 00
        mov al,modrmb
        and al,07
        
             .if (al==005)
             mov eax,InstructionSize
             sub eax,SubstractFromPos
             inc eax ; MOD
             mov DisplOffset,eax
             add InstructionSize,5 ; account for MOD + dword displacement 4 byte displacement
             call FixDisplOffset2
             ret
             .else
		 inc InstructionSize   ; return length+1; // zero length offset
             call FixDisplOffset2
             ret
             .endif
                
        Case_ 080h
             mov eax,InstructionSize
             sub eax,SubstractFromPos
             inc eax ; MOD
             mov DisplOffset,eax
             add InstructionSize,5 ; account for MOD + dword displacement 4 byte displacement
             call FixDisplOffset2
             ret
             
         Default_
             add InstructionSize,2 ; one byte offset
             call FixDisplOffset2
             ret
         Endsw_
        
.endif ; .if (al>=0C0h) else

mov eax,InstructionSize
ret

ProcessIntelInstructions:
      inc InstructionSize ; add one for special prefix
      mov ecx,InstructionSize
      mov al, byte ptr [ebx+ecx]
      mov opcode2,al
      inc InstructionSize ; and one for following opcode

      mov al, byte ptr [ebx+ecx+1] ; get next byte
      and al,0C0h ; feed next opcode


        Switch_ opcode2
        
        ; Protection Model Instructions:
          Case_ 00, 01, 02, 03
          jmp MainProcessInsFeeted
          ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 05, 06, 07, 08,\  ; 0F05 SYSCALL, 0F06 CLTS, 0F07 SYSRET, 0F08 INVD
                09, 0Bh,\ ; 0F09 WBINVD, 0F0B UD2
                0Eh ; 0F0E FEMMS
             ret

          Case_ 00Dh, 010h, 011h, 012h, 013h,\ ; PREFETCH,  2 MOVUPS, 2 MOVLPS
          014h, 015h, 016h, 017h, 018h,\ ; 2 UNPCKLPS, 2 MOVHPS, PREFETCHNTA
          028h, 029h, 02Ah, 02Ch, 02Dh,\ ; 2 MOVAPS, CVTPI2PS, 2 CVTTPS2PI
          02Eh, 02Fh ; UCOMISS, COMISS
          jmp MainProcessInsFeeted
          ; return length+GetIntelInstructionSize(bytes,position+length);
		  
          Case_ 030h,\ ; WRMSR
                031h,\ ; RDTSC
                032h,\ ; RDMSR
                033h,\ ; RDPMC
                034h,\ ; SYSENTER
                035h   ; SYSEXIT
             ret

          ; CMOVxx
          Case_ 040h, 041h, 042h, 043h, 044h, 045h, 046h, 047h,\ 
                048h, 049h, 04Ah, 04Bh, 04Ch, 04Dh, 04Eh, 04Fh
                jmp MainProcessInsFeeted
                ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 051h, 052h, 053h, 054h, 055h,\ ; SQRTPS, RSQRTPS, RCPPS, ANDPS, ANDNPS
                056h, 057h, 058h, 059h,\ ; ORPS, XORPS, ADDPS, MULPS
                05Ch, 05Dh, 05Eh, 05Fh,\ ; SUBPS, MINPS, DIVPS, MAXPS
                060h, 061h, 062h, 063h ; PUNPCKLBW, PUNPCKLWD, PUNPCKLDQ, PACKSSWB
                jmp MainProcessInsFeeted
              ;return length+GetIntelInstructionSize(bytes,position+length);
              
          Case_ 064h, 065h, 066h, 067h,\ ; PCMPGTB, PCMPGTW, PCMPGTD, PACKUSWB
                068h, 069h, 06Ah, 06Bh,\ ; PUNPCKHBW, PUNPCKHWD, PUNPCKHDQ, PACKSSDW
                06Eh, 06Fh, 070h,\ ; MOVD, MOVQ, PSHUFW
                074h, 075h, 076h  ; PCMPEQB, PCMPEQW, PCMPEQD,
                jmp MainProcessInsFeeted
              ;return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 077h ; EMMS
             ret

          Case_ 07Eh, 07Fh ; MOVD, MOVQ
              jmp MainProcessInsFeeted
              ; return length+GetIntelInstructionSize(bytes,position+length);

              ; JC relative 32 bits
          Case_ 080h, 081h, 082h, 083h, 084h, 085h, 086h, 087h,\
                088h, 089h, 08Ah, 08Bh, 08Ch, 08Dh, 08Eh, 08Fh
          add InstructionSize,04 ; account for displacement
          ret

              ; SETxx rm32
          Case_ 090h, 091h, 092h, 093h, 094h, 095h, 096h, 097h,\ 
                098h, 099h, 09Ah, 09Bh, 09Ch, 09Dh, 09Eh, 09Fh
              jmp MainProcessInsFeeted
	    ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0A0h,\ ; PUSH FS
          0A1h,\ ; POP FS
          0A2h ; CPUID
          ret

          Case_ 0A3h,\  ; BT
                0A4h, 0A5h  ; 2 SHLD
                jmp MainProcessInsFeeted
          ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0A8h,\ ; PUSH GS
                0A9h,\ ; POP GS
                0AAh   ; RSM
           ret

          Case_ 0ABh,\  ; BTS
                0ACh, 0ADh,\  ; 2 SHRD
                0AEh,\  ; LFENCE, SFENCE, MFENCE and more others!
                0AFh,\  ; imul
                0B0h,\  ; cmpxchg 8 bits
                0B1h,\  ; cmpxchg 32 bits
                0B2h,\  ; LSS
                0B3h,\  ; BTR
                0B4h,\   ; LFS
                0B5h    ; LGS
                jmp MainProcessInsFeeted
	          ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0B6h, 0B7h,\  ; movzx
			    0BBh,\  ; BTC
			    0BCh,\  ; bsf
                      0BDh,\  ; bsr
                0BEh, 0BFh,\  ; movsx
                0C0h, 0C1h,\  ; xadd
			    0C2h,\  ; CMPPS
			    0C4h,\  ; PINSRW
			    0C5h,\  ; PEXTRW
			    0C6h   ; SHUFPS
                   jmp MainProcessInsFeeted
			 ; return length+GetIntelInstructionSize(bytes,position+length);

			 ; case 0xC7 cmpxchg8b missing ???

          Case_ 0C8h,\ ; BSWAP EAX
                0C9h,\ ; BSWAP ECX
                0CAh,\ ; BSWAP EDX
                0CBh,\ ; BSWAP EBX
                0CCh,\ ; BSWAP ESP
                0CDh,\ ; BSWAP EBP
                0CEh,\ ; BSWAP ESI
                0CFh   ; BSWAP EDI
                ret

          Case_ 0D1h,\ ; PSRLW
                0D2h,\ ; PSRLD
                0D3h,\ ; PSRLQ
                0D5h,\ ; PMULLW
                0D7h,\ ; PMOVMSKB
                0D8h,\ ; PSUBUSB
                0D9h,\ ; PSUBUSW
                0DAh   ; PMINUB
                jmp MainProcessInsFeeted
		    ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0DBh,\ ; PAND
                0DCh,\ ; PADDUSB
                0DDh,\ ; PADDUSW
                0DEh,\ ; PMAXUB
                0DFh,\ ; PANDN
                0E0h,\ ; PAVGB
                0E1h,\ ; PSRAW
                0E2h   ; PSRAD
                jmp MainProcessInsFeeted
		    ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0E3h,\ ; PAVGW
                0E4h,\ ; PMULHUW
                0E5h,\ ; PMULHW
                0E7h,\ ; MOVNTQ
                0E8h,\ ; PSUBSB
                0E9h,\ ; PSUBSW
                0EAh,\ ; PMINSW
                0EBh,\ ; POR
                0ECh,\ ; PADDSB
                0EDh,\ ; PADDSW
                0EEh,\ ; PMAXSW
                0EFh   ; PXOR
                jmp MainProcessInsFeeted
		    ; return length+GetIntelInstructionSize(bytes,position+length);

          Case_ 0F1h,\ ; PSLLW
                0F2h,\ ; PSLLD
                0F3h,\ ; PSLLQ
                0F5h,\ ; PMADDWD
                0F6h,\ ; PSADBW
                0F7h,\ ; MASKMOVQ
                0F8h,\ ; PSUBB
                0F9h,\ ; PSUBW
                0FAh,\ ; PSUBD
                0FCh,\ ; PADDB
                0FDh,\ ; PADDW
                0FEh   ; PADDD
                jmp MainProcessInsFeeted
		    ; return length+GetIntelInstructionSize(bytes,position+length);

              Default_
		  ret  ; not a valid instruction

              Endsw_
; you should take care because it will return to this after switch! 
inc ecx
returnBre db 0C3h ; mega fix, you can't enter ret here since will be interpreted in other way!

Dissasm  endp

FixDisplOffset2  proc

.if (FourBytesSub!=0)
mov eax,InstructionSize
sub eax,FourBytesSub
mov DisplOffset2,eax
.endif

ret
FixDisplOffset2  endp

TestOne:
MOV DWORD PTR DS:[ESI+1Ch],04A8768h
repne scasb
mov eax,01
; repne POP GS

start2:

lea ebx,TestOne
mov ecx,0FFFh

LoopBegin:
pushad ; save all registers - recommanded
invoke Dissasm, ebx, 0
popad ; restore all registers - recommanded

mov eax,InstructionSize
add ebx,eax
mov edx, DisplOffset
mov esi, DisplOffset2
cmp ebx,00407F27h
jl LoopBegin

invoke ExitProcess,0

; end start