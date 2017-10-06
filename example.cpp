#include "RemoteJacker.h"

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

