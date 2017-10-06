#ifndef PTINFO
#define PTINFO
#include <windows.h>
#include <TlHelp32.h>
#include <string>

typedef unsigned long ULong;
typedef void* NTPtr;
typedef unsigned char UByte;

ULong FindProcessIdFromProcessName(const std::wstring processName);
ULong GetModuleBase(const ULong dwProcessId, LPCWSTR szModuleName);

#endif
