; #########################################################################

      .486
      .model flat, stdcall
      option casemap :none   ; case sensitive

; #########################################################################

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

      include dissasm.asm

; #########################################################################

Hook     PROTO   :DWORD,:DWORD,:DWORD
UnHook   PROTO   :DWORD,:DWORD
EmitJumpOrCall PROTO   :DWORD,:DWORD,:DWORD
EmitJumpOrCall2 PROTO  :DWORD,:DWORD,:DWORD,:DWORD
EmitShortJump PROTO   :DWORD,:DWORD,:DWORD
GetJumpDestination PROTO   :DWORD
GetJumpDestination2 PROTO   :DWORD, :DWORD
IsAlreadyHooked PROTO   :DWORD
MakeRoom     PROTO   :DWORD,:DWORD,:DWORD,:DWORD
KillRoom     PROTO   :DWORD,:DWORD,:DWORD,:DWORD

.data
;ModuleName db "ntdll",0
;ApiName db "NtOpenProcess",0

UserModuleName db "User32.dll",0
MsgBoxApiName db "MessageBoxA",0

MsgBoxCaption  db "LHook Tutorial No.1",0
MsgBoxText     db "MessageBoxA should have a question icon!",0

MsgBoxCaption2  db "LHook Tutorial No.2",0
MsgBoxText2     db "CreateFileA just returned -1 (file doesn't exist)!",0

FileName db "LHook.exe", 0

KernelModuleName db "Kernel32.dll",0
CreateFileApiName db "CreateFileA",0

ReturnBackup dd 0
AdditionalSource dd 00

MakeRoomTest db "DIE",0
user	db 50 dup (0)

CodeBackup db 250 dup (0)
CodeRestore db 250 dup(0)


.code

MakeRoom PROC place:DWORD, position:DWORD, room_size:DWORD, code_size:DWORD

mov esi, place
add esi, position
mov edi, offset CodeBackup
mov ecx, code_size
sub ecx, position
rep movsb ; we first backup old code

mov al,00
mov ecx, room_size
mov edi, place
add edi, position
rep stosb ; we write some zeros

mov ecx, code_size
sub ecx, position
mov edi, place
add edi, position
add edi, room_size
mov esi, offset CodeBackup
rep movsb ; we write code

ret
MakeRoom ENDP

KillRoom PROC place:DWORD, position:DWORD, room_size:DWORD, code_size:DWORD

mov esi, place
add esi, position
add esi, room_size
mov edi, offset CodeBackup
mov ecx, code_size ; this is old code size len
sub ecx, position
rep movsb ; we first backup old code

mov esi, offset CodeBackup
mov edi, place
add edi, position
mov ecx, code_size ; this is old code size len
sub ecx, position
rep movsb ; we overwrite

ret
KillRoom ENDP


Hook PROC DllName:DWORD, ApiNameOrOrdinal:DWORD, pUserHandler:DWORD
LOCAL ApiAddress:DWORD, ShouldFixIt:DWORD, IsCallD:DWORD, OrigInsSize:DWORD, CAddedSize:DWORD, AddedSize:DWORD, NewInsSize:DWORD, OldProt:DWORD, HookMem:DWORD

invoke GetModuleHandle, DllName
invoke GetProcAddress, eax, ApiNameOrOrdinal
.if (eax==0)
ret  ; the return value in eax will be 0 since it fails
.endif

mov ApiAddress, eax
mov OrigInsSize, 0

SearchEnoughBytes:

invoke Dissasm, ApiAddress, OrigInsSize

mov eax,InstructionSize
add OrigInsSize,eax
cmp OrigInsSize, 5  ; at last 5 bytes for our jump
jl SearchEnoughBytes

; set the flags of memory so we can change the memory:
invoke VirtualProtect, ApiAddress, 5, PAGE_EXECUTE_READWRITE, addr OldProt	

mov eax,OrigInsSize
add eax, 5 ; 5 bytes for calling the hook
add eax, 5 ; 5 bytes for jumping back to Api Address
invoke VirtualAlloc,0,eax,MEM_COMMIT,PAGE_EXECUTE_READWRITE
mov HookMem, eax

invoke EmitJumpOrCall, HookMem, pUserHandler, 1 ; 1 since it is a call
; so this call user code hook

; copy original Api instructions:
mov edi, HookMem
add edi, 5
mov esi, ApiAddress
mov ecx, OrigInsSize
rep movsb

pusha
; search for Jump (E9) or Call (E8)

mov NewInsSize, 0
mov AddedSize, 0
mov CAddedSize, 0
SearchJumpOrCall:

mov CAddedSize, 0

mov eax, ApiAddress
add eax, NewInsSize

mov ShouldFixIt, 0

.if (byte ptr [eax]==0E9h)
mov ShouldFixIt, 1
mov IsCallD, 0
.endif

.if (byte ptr [eax]==0E8h)
mov ShouldFixIt, 1
mov IsCallD, 1
.endif

.if (byte ptr [eax]==0EBh) ; short jump
mov ShouldFixIt, 1
mov IsCallD, 0
mov edi, 5
add edi, HookMem ; where to make room
add edi, AddedSize ; add previously added sheets

mov ebx, NewInsSize
add ebx, 2 ; index where to make place

invoke MakeRoom, edi, ebx, 5-2, OrigInsSize
add CAddedSize, 5-2
.endif


.if (ShouldFixIt==1)
mov eax, ApiAddress
add eax, NewInsSize
invoke GetJumpDestination, eax
mov edx, HookMem
add edx, 5
add edx, NewInsSize
add edx, AddedSize

invoke EmitJumpOrCall, edx, eax, IsCallD
; edx = from where to jump; eax = where to jump

mov eax, CAddedSize
add AddedSize, eax

.endif

invoke Dissasm, ApiAddress, NewInsSize

mov eax, InstructionSize
add NewInsSize,eax

mov eax, NewInsSize
cmp eax, OrigInsSize  ; at last 5 bytes for our jump
jl SearchJumpOrCall

popa

mov esi, ApiAddress ; calculate jump back to original Api
add esi, OrigInsSize

add edi, AddedSize

invoke EmitJumpOrCall, edi, esi, 0
; edi = from where to jump; esi = where to jump

; FINNALY we jump from Api to HookMem
invoke EmitJumpOrCall, ApiAddress, HookMem, 0 ; 0 since it is a jump

; set the access back to original state:
invoke VirtualProtect, ApiAddress, 5, OldProt, addr OldProt	

ret
Hook ENDP

UnHook PROC DllName:DWORD, ApiNameOrOrdinal:DWORD
LOCAL RealJumpDest:DWORD, ApiAddress:DWORD, JumpDestination:DWORD, NewInsSize:DWORD, OrigInsSize:DWORD, InsSize:DWORD, OldProt:DWORD, ShouldFixIt:DWORD, IsCallD:DWORD, CSubSize:DWORD,SubstrSize:DWORD, pCodeFrom:DWORD
invoke GetModuleHandle, DllName
invoke GetProcAddress, eax, ApiNameOrOrdinal
.if (eax==0)
ret ; the return value in eax will be 0 since it fails
.endif

mov ApiAddress, eax

invoke IsAlreadyHooked, ApiAddress
.if (eax==0)
ret ; the return value in eax will be 0 since it fails
.endif
mov InsSize, eax ; EAX holds instruction size

invoke GetJumpDestination, ApiAddress
add eax, 5  ; add 5 to instruction to skipp first call
mov JumpDestination, eax

mov edi, offset CodeRestore
mov esi, JumpDestination
mov ecx, InsSize
rep movsb ; backup Api code

pusha
; search for Jump (E9) or Call (E8)

mov NewInsSize, 0
mov SubstrSize, 0

SearchJumpOrCall:
mov CSubSize, 0

mov eax, JumpDestination
add eax, NewInsSize

mov ShouldFixIt, 0

.if (byte ptr [eax]==0E9h)  ; long jump
mov ShouldFixIt, 1
mov IsCallD, 0
.endif

.if (byte ptr [eax]==0E8h)  ; long call
mov ShouldFixIt, 1
mov IsCallD, 1
.endif

.if (ShouldFixIt==1)
mov eax, JumpDestination ; eax = where to jump
add eax, NewInsSize


mov edx, ApiAddress
add edx, NewInsSize ; edx = from where to jump

invoke GetJumpDestination, eax
mov RealJumpDest, eax

mov edx, ApiAddress  ; original Address
add edx, NewInsSize
sub edx, SubstrSize
mov pCodeFrom, edx

mov edi, offset CodeRestore ; destination
add edi, NewInsSize
sub edi, SubstrSize

.if (IsCallD==0)  ; if is a jump
invoke EmitShortJump, edi, pCodeFrom, RealJumpDest
.if (eax==1) ; if eax = 1 - just emited short jump!
invoke KillRoom, edi, 2, 5-2, InsSize
; place, position, room_size, code_size

add CSubSize, 3
.else

invoke EmitJumpOrCall2, edi, pCodeFrom, RealJumpDest, IsCallD
; edx = from where to jump; eax = where to jump
.endif

.else  ; if ISN'T a jump

invoke EmitJumpOrCall2, edi, pCodeFrom, RealJumpDest, IsCallD
; edi = destination edx = from where to jump; eax = where to jump

.endif

mov eax, CSubSize
add SubstrSize, eax

.endif

invoke Dissasm, JumpDestination, NewInsSize

mov eax, InstructionSize
add NewInsSize,eax

mov eax, NewInsSize
cmp eax, InsSize  ; at last 5 bytes for our jump
jl SearchJumpOrCall

popa

mov eax, InsSize
sub eax, SubstrSize
mov InsSize, eax

sub JumpDestination, 5

; We're done, release the memory
invoke VirtualFree, JumpDestination, 0, MEM_RELEASE

; set the flags of memory so we can change the memory:
invoke VirtualProtect, ApiAddress, InsSize, PAGE_EXECUTE_READWRITE, addr OldProt

; finnaly restore Api code:
mov edi, ApiAddress
mov esi, offset CodeRestore
mov ecx, InsSize
rep movsb ; restore Api code

; set the access back to original state:
invoke VirtualProtect, ApiAddress, InsSize, OldProt, addr OldProt

mov eax,01
ret

UnHook ENDP

EmitJumpOrCall PROC pCodeFrom:DWORD, pJumpTo:DWORD, IsCall:DWORD
LOCAL pJumpFrom:DWORD, InsSize:DWORD

mov eax, pCodeFrom
add eax, 5  ; add 5 to offset jump from
mov pJumpFrom, eax

mov eax, pCodeFrom
.if (IsCall==0)
mov byte ptr [eax], 0E9h  ; jump
.else
mov byte ptr [eax], 0E8h  ; call
.endif

inc eax
mov edx, pJumpTo
sub edx, pJumpFrom

mov [eax], edx  ; fill jump to that location

ret

EmitJumpOrCall ENDP

EmitJumpOrCall2 PROC destination:DWORD, pCodeFrom:DWORD, pJumpTo:DWORD, IsCall:DWORD
LOCAL pJumpFrom:DWORD, InsSize:DWORD

mov edi, destination
mov eax, pCodeFrom
add eax, 5  ; add 5 to offset jump from
mov pJumpFrom, eax

mov eax, pCodeFrom
.if (IsCall==0)
mov byte ptr [edi], 0E9h  ; jump
.else
mov byte ptr [edi], 0E8h  ; call
.endif

mov edx, pJumpTo
sub edx, pJumpFrom

mov [edi+1], edx  ; fill jump to that location

ret

EmitJumpOrCall2 ENDP


EmitShortJump PROC destination:DWORD, pCodeFrom:DWORD, pJumpTo:DWORD
LOCAL difference:DWORD, InsSize:DWORD

mov eax, pCodeFrom
mov edx, pJumpTo

.if (eax>edx)
mov eax, pCodeFrom
sub eax, pJumpTo
mov difference, eax
.else
mov eax, pJumpTo
sub eax, pCodeFrom
mov difference, eax
.endif

.if (difference<128)
mov edi, destination
mov byte ptr [edi], 0EBh

mov eax, pJumpTo
sub eax, 2
sub eax, pCodeFrom

mov byte ptr [edi+1], al

mov eax,01
.else
mov eax,0
.endif

ret

EmitShortJump ENDP


IsAlreadyHooked PROC ApiAddress:DWORD
LOCAL JumpDestination:DWORD, InsSize:DWORD, memory_basic_information:MEMORY_BASIC_INFORMATION
mov eax, ApiAddress
mov AdditionalSource, 0
.if (byte ptr [eax]!=0E9h)  ; if is not a jump means is not hooked
xor eax, eax
ret
.endif

invoke GetJumpDestination, ApiAddress
mov JumpDestination, eax

invoke VirtualQuery, JumpDestination, addr memory_basic_information, sizeof memory_basic_information
.if (eax==0)
ret
.else

mov eax, memory_basic_information.BaseAddress
.if (eax!=JumpDestination)  ; the memory block has to be the base address
xor eax, eax
ret
.endif

.endif

mov eax, JumpDestination
.if (byte ptr [eax]!=0E8h)  ; if is not a call means is not hooked
xor eax, eax
ret
.endif

add JumpDestination, 5
mov InsSize,0

LoopSearchSize:
inc InsSize

.if (InsSize>15)  ; if we have more then 15 bytes we have error
xor eax, eax
ret
.endif

mov eax, JumpDestination
add eax, InsSize
cmp byte ptr [eax], 0E9h
jnz LoopSearchSize

cmp dword ptr [eax+5], 0 ; the dword after has to be 0
jnz LoopSearchSize

cmp byte ptr [eax-5], 0E9h ; the previous instruction is a jump
jnz PreviousIsNotJump

mov edx,eax
sub edx, 5
invoke GetJumpDestination, edx
mov JumpDestination, eax

invoke VirtualQuery, JumpDestination, addr memory_basic_information, sizeof memory_basic_information
.if (eax==0)
jmp PreviousIsNotJump
.else

mov eax, memory_basic_information.BaseAddress
.if (JumpDestination==eax)  ; the memory block has to be the base address
mov eax, InsSize
; sub eax, 5  substract a jump size
ret
.endif

.endif

PreviousIsNotJump:
mov eax, InsSize
ret

IsAlreadyHooked ENDP


GetJumpDestination PROC pCodeFrom:DWORD
LOCAL IsCallOrJump:DWORD
mov IsCallOrJump, 0


mov eax, pCodeFrom
.if (byte ptr [eax]==0E9h) ; long jump
mov IsCallOrJump, 1
.endif
.if (byte ptr [eax]==0E8h) ; long call
mov IsCallOrJump, 2
.endif

.if (byte ptr [eax]==0EBh) ; short jump 
mov IsCallOrJump, 3
.endif

;.if (byte ptr [eax]==0EBh) ; short jump 
;mov IsCallOrJump, 4
;.endif

.if (IsCallOrJump==0)
xor eax,eax
ret
.endif


.if (IsCallOrJump==3||IsCallOrJump==4)  ; short jump
mov eax, pCodeFrom
add eax, 1
movsx edx, byte ptr [eax]
add eax, edx
add eax, 1
ret

.else
mov eax, pCodeFrom
add eax, 1
add eax, dword ptr [eax]
add eax, 4

ret
.endif

GetJumpDestination ENDP

GetJumpDestination2 PROC pCodeFrom:DWORD, RealFrom:DWORD
LOCAL IsCallOrJump:DWORD
mov IsCallOrJump, 0


mov eax, pCodeFrom
.if (byte ptr [eax]==0E9h) ; long jump
mov IsCallOrJump, 1
.endif
.if (byte ptr [eax]==0E8h) ; long call
mov IsCallOrJump, 2
.endif

.if (byte ptr [eax]==0EBh) ; short jump 
mov IsCallOrJump, 3
.endif

;.if (byte ptr [eax]==0EBh) ; short jump 
;mov IsCallOrJump, 4
;.endif

.if (IsCallOrJump==0)
xor eax,eax
ret
.endif


.if (IsCallOrJump==3||IsCallOrJump==4)  ; short jump
mov eax, RealFrom
add eax, 1
movsx edx, byte ptr [eax]
add eax, edx
add eax, 1
ret

.else
mov eax, RealFrom
add eax, 1
add eax, dword ptr [eax]
add eax, 4

ret
.endif

GetJumpDestination2 ENDP


MessageBoxTypeChange:
; Current ESP = 0012FFAC
; 0012FFAC   00AE0005  RETURN to 00AE0005 from LHook.004031FF
; 0012FFB0   00403243  RETURN to LHook.<ModuleEntryPoint>+3A from <JMP.&user32.MessageBoxA>
; 0012FFB4   00000000
; 0012FFB8   0040A063  ASCII "MessageBoxA should have a question icon!"
; 0012FFBC   0040A04C  ASCII "LHook Tutorial No.1"
; 0012FFC0   00000000
; 0012FFC4   7C817077  RETURN to kernel32.7C817077
; The hook will add a LHook hook call so it will sub from esp 4 value comparing with original Api
; 0012FFC0 - 0012FFAC = 14h
; MessageBoxA has 4 parameters; last parameter is message box type
MOV DWORD PTR DS:[ESP+4*5], MB_ICONQUESTION
ret

PermanentReturnChanger:
add esp, 04 ; change the return address
mov eax,-1  ; EAX holds the return value
RETN 01Ch   ; CreateFileA stack fixer



ChangeReturnAddress:
mov eax, dword ptr [esp+4] ; get return address
mov ReturnBackup, eax

mov eax, offset NewReturnAddress
mov dword ptr [esp+4], eax ; set return address

ret

NewReturnAddress:
mov eax,-1  ; EAX holds the return value
jmp dword ptr [ReturnBackup] ; jump to orginal return address

OPCODE_TEST:
IN AL, DX

start:
invoke Dissasm, ADDR OPCODE_TEST, 0
mov eax, InstructionSize

; first sample: change MessageBoxA calls to MB_ICONQUESTION
invoke Hook, ADDR UserModuleName, ADDR MsgBoxApiName, ADDR MessageBoxTypeChange

invoke MessageBox, NULL, addr MsgBoxText, addr MsgBoxCaption, MB_OK
invoke UnHook, ADDR UserModuleName, ADDR MsgBoxApiName


; second sample: change permanently the return value of CreateFileA Api and don't call original Api
invoke Hook, ADDR KernelModuleName, ADDR CreateFileApiName, ADDR PermanentReturnChanger

invoke CreateFile,addr FileName,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
cmp eax, -1  ; INVALID_HANDLE_VALUE = -1
jnz FileExists
invoke MessageBox, NULL, addr MsgBoxText2, addr MsgBoxCaption2, MB_OK

FileExists:
invoke UnHook, ADDR KernelModuleName, ADDR CreateFileApiName



; final example: change return address:
invoke Hook, ADDR KernelModuleName, ADDR CreateFileApiName, ADDR ChangeReturnAddress

invoke CreateFile,addr FileName,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
invoke ExitProcess,0

end start

