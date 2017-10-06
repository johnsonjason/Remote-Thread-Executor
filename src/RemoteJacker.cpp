#include "RemoteJacker.h"

ULong GetDispatcher(ULong ProcessId)
{
	NTPtr Dispatcher = (NTPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserExceptionDispatcher");
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!Process)
		return NULL;
	else
		CloseHandle(Process);
	
	ULong Difference = ((ULong)Dispatcher - (ULong)GetModuleHandleA("ntdll.dll"));
	return (GetModuleBase(ProcessId, L"ntdll.dll") + Difference + 1);
}

ULong MarkShellCode(ULong ProcessId, ULong Shellcode)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Shellcode, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);

	CloseHandle(Process);
	return FormerProtection;
}

void WriteHook(HANDLE Process, ULong BaseAddress, ULong ShellCode)
{
	UByte Patch[5];

	ULong Address = (ShellCode - BaseAddress) - 5;
	Patch[0] = 0xE9;
	*(ULong *)(Patch + 1) = Address;

	WriteProcessMemory(Process, (LPVOID)BaseAddress, &Patch, sizeof(Patch), 0);
}

void SetDispatcher(ULong ProcessId, ULong Address, ULong ShellCode)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Address, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);
	WriteHook(Process, GetDispatcher(ProcessId), ShellCode);
	VirtualProtectEx(Process, (LPVOID)Address, 1, FormerProtection, &FormerProtection);

	CloseHandle(Process);
}

void RemoteJack(ULong ProcessId, ULong Target)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Target, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);
	WriteProcessMemory(Process, (LPVOID)Target, "\xF4", 1, 0);
	VirtualProtectEx(Process, (LPVOID)Target, 1, FormerProtection, &FormerProtection);

	CloseHandle(Process);
}
