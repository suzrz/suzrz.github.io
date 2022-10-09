---
layout: post
title: "Debugme CTF Writeup"
date: 2022-10-09 15:24:00 +0200
---
# Debugme

Debugme is a reversing challenge on [Hackthebox](https://www.hackthebox.com), 
created by user Malfurion. 
At the time of solving it was for 40pts and rated as medium difficulty.

For solving this CTF I'll take my regular approach, which consists of 
initial assesment of the executable, static analysis and dynamic analysis.

## Initial Assesment

The first bits of the executable are:
```4D 5A```
Which is the `MZ` constant present in PE files.

By simply parsing the PE header it is possible to obtain interesting information 
about the program.
![](/assets/debugme/basicInfo.png)

The program to analyse is a 32bit Windows executable. Important properties to 
look for are security features possibly enabled in this program. Two of these 
features are in the `Optional Header`. The first is `ASLR` ([address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization))
second is indicator of `NX bit` ([NX bit](https://ctf101.org/binary-exploitation/no-execute/)) support. This program doesn't use any of these as shown on the following figure.

![](/assets/debugme/optionalHeader.png)

The next step I took is to run the program to see what it does. This time however, 
nothing interesting is shown or revealed by running the program and nor is by 
performing analysis using `procmon`.

## Static analysis

Usually I am performing the static analysis using disassembler (in this case 
[IDA Free 8.0](https://hex-rays.com/ida-free/) from Hex Rays).

The first easy step is to analyze the strings available without running the program. 
This surely does reveal some interesting information. The strings looks like messages 
to someone, who is using a debugger to debug this program. There are though no 
cross-references to these strings. This could mean that they are a trap or 
that the code that references to them is yet to be created (e. g. decrypted).

![](/assets/debugme/visibleStrings.png)

### Main Function

By looking at the procedure that IDA has identified as the `main` function of the program, 
one can tell that this is probably not real code of the main function. The procedure is 
missing prologue (which is not mandatory though) and the disassembled bytes seem random.
Another suspicious thing is usage of uncommon instructions.

![](/assets/debugme/main.png)

IDA has identified most of the functions/subroutines present in this executable. 
This is not a signal for the analyst to be off guard. As with every software, IDA is 
not perfect and could be fooled.

### Startup Functions

There are some functions that have caught my untrained eye.

![](/assets/debugme/initCRTFuncs.png)

These functions are probably executed even before the `main` function and because the `main` 
function is currently a little chaotic, there may be some 
additional functionality implemented that alters the code during runtime.

After quickly looking at the first three mentioned functions, `_pre_c_init`, `_pre_cpp_init` and
`_WinMainCRTStartup`, I've come to a finding that these are not relevant for the analysis. 

#### Why do I not consider these functions interesting?

These initializing functions are created by the compiler, and they look like 
functions with valid behavior. 

The `_pre_c_init` function does some checks and setups. This 
behavior is specific to the `MinGW` compiler ("`GCC` on Windows"). That means this 
program was compiled using `MinGW`.

The `_pre_cpp_init` function obtains `startinfo`, `envp` and `argv` for `main` 
function.

The `WinMainCRTStartup` just checks the security cookie and calls 
`__tmainCRTStartup` which is a `#define` macro to `WinMain`.

```c
#ifdef  _UNICODE
#define _tWinMain  wWinMain
#else
#define _tWinMain  WinMain
#endif
```

These functions are setting up the runtime environment.

### mainCRTStartup

The first interesting function is `_mainCRTStartup`. This function is the entry 
point for this program. `mainCRTStartup` is used for 
Windows console applications 
([mainCRTStartup](https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol?view=msvc-170)).

![](/assets/debugme/mainCRTStartup.png)

Going down the rabbit hole.

![](/assets/debugme/mainCRTStartup_0.png)

At the beginning of the `mainCRTStartup_0`, there is a procedure to check 
`BeingDebugged` byte from ([PEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)).
```asm
mov     eax, large fs:30h       ; move PEB to EAX
mov     al, [eax+2]             ; move second byte of PEB to AL
mov     dl, al
cmp     al, 0                   ; compare if BeingDebugged is equal to zero
```

Because I know which branch I want the program to go, I've patched the conditional 
jump bytes to `nop` (no operation). The patched function is shown on the following 
figure. The graph clearly shows the new flow of the program.

![Patched Bytes](/assets/debugme/patched0MainCRTStartup_0.png)

The next block has a similar pattern. Again the PEB is loaded and 
a byte value is read from it. This time it is value on offset 0x68.
On this offset is the `NtGlobalFlag`. The value of this flag is not changed at the time of 
the debugger attachment event. However, using this flag is possible to access these 
three flags: `FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_ENABLE_FREE_CHECK` and 
`FLG_HEAP_VALIDATE_PARAMETERS`. If the combination of these three flags equals 
`0x70`, is a sign that a debugger is being used to analyze the process. 
The `NtGlobalFlag` has by default value of 0. So if this flag is not zero, 
the program will again jump to the function end and terminate itself. 
Checking the `NtGlobalFlag` is another common anti-debugging technique. 
The analyst can apply the same trick by patching the bytes as shown on the 
following figure.

![](/assets/debugme/patched1MainCRTStartup_0.png)

After that, some magic is done and another check is performed. It is not really 
necessary to precisely analyze this chunk of code because it is obvious which 
branch the program goes when it is running correctly. Terminating this 
function would terminate the program.

![](/assets/debugme/ad3MainCRTStartup_0.png)

This branching was also solved by patching the executable.

![](/assets/debugme/patched2MainCRTStartup_0.png)

After overcoming these branching obstacles, a loop, which is xoring and searching 
for something, is executed.

```asm
loc_408973:                             
    xor     byte ptr [eax], 5Ch             ; xor byte with 0x5c
    inc     eax                             ; move to next byte
    cmp     eax, offset loc_401791          ; check if at end
    jle     short loc_408973                ; if not, repeat
```

The location at `loc_401791` is a part of code close to the `main` function, after 
the funny labels. This indicates that the code of the `main` function, the 
funny labels, until the `loc_401791`, is encrypted using XOR 0x5C. The 
encrypted code is depicted on the following figure.

![](/assets/debugme/encrypted_main.png)

I won't be analysing this further in the static analysis phase since the code 
will be decoded at runtime during dynamic analysis.

Code encrypting is common disassembling technique.

Finally, `__tMainCRTStartup` is called.

![](/assets/debugme/mainCRTStartup_0_tMainCRTStartup_call.png)

The `__tMainCRTStartup` is pretty complex, but not really worth analyzing 
as it probably was generated by the compiler. It is 
doing common setup procedures and is probably generated by the compiler without 
any user changes. Finally, it calls, the `main` function. I've set a software 
breakpoint to this call.

## Dynamic Analysis

Executing the program with debugger attached to it has been successfull and now 
the program is suspended right before executing the call of the `main` function.
Now I have the possibility to step into decrypted `main`.

![](/assets/debugme/EIP_main_call.png)

Stepping into the `main` shows the function in its real form as shown.

![](/assets/debugme/main_decrypted.png)

In the `main` function, the program uses the same anti-debugging techniques 
as in the `_mainCRTStartup_0` function. First `BeingDebugged` byte from PEB is 
checked, then `NtGlobalFlag` is checked and finally the "magic" procedure. 

I've overcome these techniques by setting the `ZF` (zero flag) to 1 at relevant 
times. This caused that the program executed the conditional jumps the way that 
I wanted it to be (ignoring debugger checks).

During analyzing this part, the program tried to tell me something :)

![](/assets/debugme/poor_program.png)

Finally, the execution got to the funny named labels.

![](/assets/debugme/funny_lables.png)

The code under the funny named labels looks like some decrypting procedure 
that should result in values that could be read as ASCII chars. 

The processed values are stored on the stack. However it is still not in 
human-readable format.

![](/assets/debugme/stack_with_chars.png)

Finally, a small trick with `LODSB` and `STOSB` 
(load string/store string byte length; these instructions are usually used 
when some processing of elements in an array is necessary + the xor used 
as decoding) is done and voilà,

```asm
loc_401776:                             
    mov     edi, esi
    mov     edx, edi
    mov     ecx, 24h ; '$'                  
    mov     ebx, 4Bh ; 'K'
    xor     eax, eax
    push    eax
    
    _l:                                     
    ; decryption loop
    ; go through the data on stack byte by byte, decrypt them and store decrypted
        lodsb                   ; load string byte
        xor     eax, ebx        ; decrypt using xor
        stosb                   ; store string byte
        loop    _l
        
    mov     esp, ebp
    pop     ebp
    
    locret_401791:                          
    retn
```

here is the flag :)

![](/assets/debugme/flag.png)
