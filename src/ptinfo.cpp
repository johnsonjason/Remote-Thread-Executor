#include "ptinfo.h"

ULong FindProcessIdFromProcessName(const std::wstring processName) 
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}


ULong GetModuleBase(const ULong dwProcessId, LPCWSTR szModuleName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (!hSnap)
		return 0;

	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	ULong dwReturn = 0;
	if (Module32First(hSnap, &me))
	{
		do
		{
			if (lstrcmpi(me.szModule, szModuleName) == 0)
			{
				dwReturn = (ULong)me.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnap, &me));
	}
	CloseHandle(hSnap);
	return dwReturn;
}
