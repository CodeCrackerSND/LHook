LHook:
Local Api Hooker coded in MASM!

LHook.asm start contains all examples you will need on the wild:

start:
invoke Hook, ADDR UserModuleName, ADDR MsgBoxApiName, ADDR MessageBoxTypeChange
; hook MessageBoxA api, ADDR MessageBoxTypeChange is the address called

invoke UnHook, ADDR UserModuleName, ADDR MsgBoxApiName
; unhook MessageBoxA api

