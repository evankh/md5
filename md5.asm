; Final Project
; Computes the MD5 checksum of a file (https://en.wikipedia.org/wiki/MD5)
; By Evan Hoffman

.386
.MODEL flat,stdcall
.STACK 4096

; Command line argument API calls: Since ToArgvW only comes in a W version, the others have to be W too
GetCommandLineW PROTO
CommandLineToArgvW PROTO, lpCmdLine:PTR, pNumArgs:PTR
LocalFree PROTO, hMem:DWORD
; File handling API functions
CreateFileW PROTO, lpFileName:PTR, dwDesiredAccess:DWORD, dwShareMode:DWORD, lpSecurityAttributes:PTR, dwCreationDisposition:DWORD, dwFlagsAndAttributes:DWORD, hTemplateFile:PTR
CloseHandle PROTO, dwFileDescriptor:DWORD
ReadFile PROTO, hFile:DWORD, lpBuffer:PTR, nNumberOfBytesToRead:DWORD, lpNumberOfBytesRead:PTR, lpOverlapped:PTR
; Other API functions
MessageBoxW PROTO, hWnd:DWORD, lpText:PTR, lpCaption:PTR, uType:DWORD
ExitProcess PROTO, dwExitCode:DWORD
GetLastError PROTO

.data
; Data used for reading file
argv_raw DWORD ?
argc DWORD ?
argv DWORD ?
error DWORD ?
filename DWORD ?
fileHandle DWORD ?
bytesToRead DWORD 64
bytesRead DWORD ?
totalBytes DWORD 0	; This being a DWORD means file size is limited to 4GB, but allows for much simpler code
edgeCase BYTE 0
lastIteration BYTE 0
; The text of the output message to be displayed
errorTitle WORD 0045h, 0072h, 0072h, 006Fh, 0072h, 0000h	; Wide characters for "Error"
badArgMessage WORD 0045h, 0072h, 0072h, 006Fh, 0072h, 0020h, 0070h, 0061h, 0072h, 0073h, 0069h, 006Eh, 0067h, 0020h, 0063h, 006Fh
	WORD 006Dh, 006Dh, 0061h, 006Eh, 0064h, 0020h, 006Ch, 0069h, 006Eh, 0065h, 0020h, 0061h, 0072h, 0067h, 0075h, 006Dh
	WORD 0065h, 006Eh, 0074h, 0073h, 002Eh, 0020h, 0055h, 0073h, 0061h, 0067h, 0065h, 003Ah, 0020h, 006Dh, 0064h, 0035h
	WORD 0020h, 003Ch, 0066h, 0069h, 006Ch, 0065h, 006Eh, 0061h, 006Dh, 0065h, 003Eh, 0000h	; Wide characters for "Error parsing command line arguments. Usage: md5 <filename>"
badFileMessage WORD 0055h, 006Eh, 0061h, 0062h, 006Ch, 0065h, 0020h, 0074h, 006Fh, 0020h, 006Fh, 0070h, 0065h, 006Eh, 0020h, 0066h
	WORD 0069h, 006Ch, 0065h, 002Eh, 0000h	; Wide characters for "Unable to open file."
message WORD 004Dh, 0044h, 0035h, 0020h, 0048h, 0061h, 0073h, 0068h, 003Ah, 0020h	; Wide characters for "MD5 Hash: "
digest WORD 33 DUP(0)
; Data used for the algorithm
; Constants
A_0 DWORD 067452301h
B_0 DWORD 0efcdab89h
C_0 DWORD 098badcfeh
D_0 DWORD 010325476h
; Painstakingly copied from the Wikipedia article
s BYTE 7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22
	BYTE 5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20
	BYTE 4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23
	BYTE 6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
; More constants, carefully copy-pasted and reformatted
K DWORD 0d76aa478h,0e8c7b756h,0242070dbh,0c1bdceeeh, 0f57c0fafh,04787c62ah,0a8304613h,0fd469501h, 0698098d8h,08b44f7afh,0ffff5bb1h,0895cd7beh, 06b901122h,0fd987193h,0a679438eh,049b40821h
	DWORD 0f61e2562h,0c040b340h,0265e5a51h,0e9b6c7aah, 0d62f105dh,002441453h,0d8a1e681h,0e7d3fbc8h, 021e1cde6h,0c33707d6h,0f4d50d87h,0455a14edh, 0a9e3e905h,0fcefa3f8h,0676f02d9h,08d2a4c8ah
	DWORD 0fffa3942h,08771f681h,06d9d6122h,0fde5380ch, 0a4beea44h,04bdecfa9h,0f6bb4b60h,0bebfbc70h, 0289b7ec6h,0eaa127fah,0d4ef3085h,004881d05h, 0d9d4d039h,0e6db99e5h,01fa27cf8h,0c4ac5665h
	DWORD 0f4292244h,0432aff97h,0ab9423a7h,0fc93a039h, 0655b59c3h,08f0ccc92h,0ffeff47dh,085845dd1h, 06fa87e4fh,0fe2ce6e0h,0a3014314h,04e0811a1h, 0f7537e82h,0bd3af235h,02ad7d2bbh,0eb86d391h
; Variables
A_ DWORD ?
B_ DWORD ?
C_ DWORD ?
D_ DWORD ?
i_ DWORD 0
M DWORD 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0	; Buffer containing the current block

.code

; A helper function to perform a certain bitshifting operation.
; Function does not conform to any standard protocol; because I know when and how I'm using it, it takes its arguments in the eax and cl registers, and returns in eax, for performance.
_leftrotate PROC
	push eax
	shl eax, cl
	mov bl, 32
	sub bl, cl
	mov cl, bl
	pop ebx
	shr ebx, cl
	or eax, ebx
	ret
_leftrotate ENDP

; A helper function that turns a single nibble in eax into its ASCII character code
_nibbletoascii PROC
	add eax, 30h
	cmp eax, 3ah
	jl done
	add eax, 7h
	done:
	ret
_nibbletoascii ENDP

_main PROC
	; Parse the command-line arguments
	call GetCommandLineW
	mov argv_raw, eax
	lea ebx, argc
	push ebx
	push argv_raw
	call CommandLineToArgvW
	mov argv, eax
	cmp argv, 0
	je invalid_args
	cmp argc, 2
	je args_correct

	invalid_args:
	call GetLastError
	mov error, eax
	push argv
	call LocalFree
	; Incorrect command line arguments message
	push 10h	; "OK" with an error exclamation point
	lea eax, errorTitle
	push eax
	lea eax, badArgMessage
	push eax
	push 0	; No owner
	call MessageBoxW
	INVOKE ExitProcess, error

	args_correct:
	; eax points to an array of 2 pointers to strings: the running program, and the path to the input file
	add eax, 4
	mov eax, DWORD PTR [eax]
	mov filename, eax
	; Open the file
	push 0			; No template file
	push 0			; No special attributes
	push 3			; Open existing file (TODO: error handling)
	push 0			; No special security
	push 1			; Only share for reading
	push 80000000h	; Open for read-only
	push filename
	call CreateFileW
	mov fileHandle, eax
	cmp eax, 0FFFFFFFFh
	jne valid_file
	call GetLastError
	mov error, eax
	; Failed to open file message
	push 10h	; "OK" with an error exclamation point
	push filename
	lea eax, badFileMessage
	push eax
	push 0	; No owner
	call MessageBoxW
	push argv
	call LocalFree	; No memory leaks allowed
	INVOKE ExitProcess, error

	valid_file:
	; Run the algorithm
	start_chunk:
		; Read the chunk, check the length and pad as appropriate
		push 0		; lpOverlapped = NULL
		lea eax, bytesRead
		push eax
		push bytesToRead
		lea eax, M
		push eax
		push fileHandle
		call ReadFile

		; Although MD5 can handle messages of any bit length, we know that files will end on a byte boundary, and we know where in the buffer that byte falls

		; C++ Pseudocode for the amount of padding to do:
		; if (bytesRead != bytesToRead) {
		;	if (bytesRead < 56) {	// Normal case, plenty of room for padding
		;		if (!cornerCase)
		;			pad(0x80);
		;		bytesRead++;
		;		while (bytesRead < 56)
		;			pad(0x00);
		;		pad(length);
		;	}
		;	else {	// Buffer too full
		;		pad(0x80);
		;		pad(0x00 until buffer full);
		;		cornerCase = true;
		;	}
		;}
		mov edx, bytesRead
		add totalBytes, edx
		cmp edx, bytesToRead
		je buffer_full	; Filled the buffer completely (e.g. file isn't empty yet), go ahead with the algorithm
		cmp edx, 56
		jl room_enough	; Didn't fill the buffer, but there's enough room left in it for the necessary padding

		; Edge case: buffer too full for padding, need to do another iteration
		mov BYTE PTR [M + edx], 80h
		inc edx
		; Fill the rest of the buffer with 0x00
		mov ecx, bytesToRead
		sub ecx, edx
		lea ebx, M
		add ebx, edx
		mov edi, ebx	; Adding edx to edi directly would actually add 4 * edx
		xor eax, eax
		cld
		rep stosb
		mov edgeCase, 1	; Mark that we need another iteration, and that it should be filled with all 0x00
		jmp buffer_full

		room_enough:	; Normal case: buffer has enough room for the padding
			cmp edgeCase, 0
			jne no_1_pad	; If this is an edge case, then the 0x80 was already appended last iteration, don't add it again
				mov BYTE PTR [M + edx], 80h
				inc edx
			no_1_pad:
			; Fill to 56 bytes with 0x00
			mov ecx, 56
			sub ecx, edx
			lea ebx, M
			add ebx, edx
			mov edi, ebx
			xor eax, eax
			cld
			rep stosb
			; Append the length
			mov eax, totalBytes
			shl eax, 3
			mov DWORD PTR [M + 56], eax
			mov DWORD PTR [M + 60], 0
			mov lastIteration, 1

		buffer_full:
		; Begin processing the chunk
		mov eax, A_0
		mov A_, eax
		mov eax, B_0
		mov B_, eax
		mov eax, C_0
		mov C_, eax
		mov eax, D_0
		mov D_, eax
		mov i_, 0
		mov ecx, 16
		func_F:
			mov eax, B_
			and eax, C_
			mov ebx, B_
			not ebx
			and ebx, D_
			or eax, ebx

			mov ebx, i_
		
			add eax, A_
			add eax, DWORD PTR [M + ebx * 4]
			add eax, DWORD PTR [K + ebx * 4]
			push ecx
			mov cl, BYTE PTR [s + ebx]
			call _leftrotate
			pop ecx
			add eax, B_

			xchg B_, edx
			xchg C_, edx
			xchg D_, edx
			xchg A_, edx
			mov B_, eax

			inc i_
			loop func_F
		mov ecx, 16
		func_G:
			mov eax, D_
			mov ebx, eax
			and eax, B_
			not ebx
			and ebx, C_
			or eax, ebx

			mov ebx, i_
			shl ebx, 2
			add ebx, i_
			inc ebx
			and ebx, 15

			add eax, A_
			add eax, DWORD PTR [M + ebx * 4]
			mov edx, i_
			add eax, DWORD PTR [K + edx * 4]
			push ecx
			mov cl, BYTE PTR [s + edx]
			call _leftrotate
			pop ecx
			add eax, B_

			xchg B_, edx
			xchg C_, edx
			xchg D_, edx
			xchg A_, edx
			mov B_, eax

			inc i_
			loop func_G
		mov ecx, 16
		func_H:
			mov eax, B_
			xor eax, C_
			xor eax, D_

			mov ebx, i_
			shl ebx, 1
			add ebx, i_
			add ebx, 5
			and ebx, 15

			add eax, A_
			add eax, DWORD PTR [M + ebx * 4]
			mov edx, i_
			add eax, DWORD PTR [K + edx * 4]
			push ecx
			mov cl, BYTE PTR [s + edx]
			call _leftrotate
			pop ecx
			add eax, B_

			xchg B_, edx
			xchg C_, edx
			xchg D_, edx
			xchg A_, edx
			mov B_, eax

			inc i_
			loop func_H
		mov ecx, 16
		func_I:
			mov eax, D_
			not eax
			or eax, B_
			xor eax, C_

			mov edx, i_
			mov ebx, edx
			shl ebx, 1
			add ebx, edx
			shl ebx, 1
			add ebx, edx
			and ebx, 15

			add eax, A_
			add eax, DWORD PTR [M + ebx * 4]
			add eax, DWORD PTR [K + edx * 4]
			push ecx
			mov cl, BYTE PTR [s + edx]
			call _leftrotate
			pop ecx
			add eax, B_

			xchg B_, edx
			xchg C_, edx
			xchg D_, edx
			xchg A_, edx
			mov B_, eax

			inc i_
			loop func_I
		mov eax, A_
		add A_0, eax
		mov eax, B_
		add B_0, eax
		mov eax, C_
		add C_0, eax
		mov eax, D_
		add D_0, eax
	cmp lastIteration, 0
	je start_chunk

	; Now that we're done reading from the file, close it
	push fileHandle
	call CloseHandle

	; Format output
	; md5 hash is in binary in A_0, but it needs to be converted to characters to be displayed, and they need to be wide characters to work with MessageBoxW
	xor ecx, ecx
	start:
		mov ebx, ecx
		mov al, BYTE PTR [A_0 + ecx]
		and eax, 0f0h
		shr eax, 4
		call _nibbletoascii
		mov WORD PTR [digest + ebx * 4], ax
		mov al, BYTE PTR [A_0 + ecx]
		and eax, 0fh
		call _nibbletoascii
		mov WORD PTR [digest + ebx * 4 + 2], ax
		inc ecx
		cmp ecx, 16
	jl start

	push 0	; Default "OK"
	push filename
	lea eax, message	; Digest is directly after message with no separation, so they will both be printed
	push eax
	push 0	; No owner
	call MessageBoxW

	push argv
	call LocalFree
	INVOKE ExitProcess, 0
_main ENDP
END