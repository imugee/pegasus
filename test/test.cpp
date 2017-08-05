#include <Windows.h>
#include <stdio.h>

void load()
{
	HMODULE module = GetModuleHandle(L"ntdll.dll");

	module = LoadLibrary(L"kernel32.dll");
	if (module)
		FreeLibrary(module);
}

void alloc()
{
	void *address = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READ);

	if (address)
		VirtualFree(address, 1024, MEM_FREE);
}

void fs_test()
{
	__asm
	{
		mov eax, fs:[0]
		mov eax, fs:[0x18]
	}
}

void main()
{
	__asm call fs_test
	load();
	printf("test\n");
	Sleep(1000);
	alloc();
}
