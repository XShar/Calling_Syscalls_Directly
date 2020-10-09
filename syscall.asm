_DATA SEGMENT
call_number DQ 0
_DATA ENDS

.code

ZwCreateFile proc
		mov r10, rcx
		mov eax, dword ptr[call_number]
		syscall
		ret
ZwCreateFile endp

SetCallNumber proc
        mov call_number, rcx
        ret
SetCallNumber endp

end 