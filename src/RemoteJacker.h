#ifndef REMOTEJACKER
#define REMOTEJACKER
#include "ptinfo.h"

ULong GetDispatcher(ULong ProcessId);
ULong MarkShellCode(ULong ProcessId, ULong Shellcode);
void WriteHook(HANDLE Process, ULong BaseAddress, ULong ShellCode);
void SetDispatcher(ULong ProcessId, ULong Address, ULong ShellCode);
void RemoteJack(ULong ProcessId, ULong Target);

#endif
