#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <strsafe.h>
#include <tlhelp32.h>

#include "util.h"

typedef struct _DLL_ARGS_
{
	WCHAR dll_path[MAX_PATH];
	ULONG64 break_point;
}DLL_ARGS, *PDLL_ARGS;

unsigned char g_backup[1024];

void patch_32(unsigned long long ip)
{
	memset(g_backup, 0, 1024);

	SuspendProcess();
	///
	unsigned long old = 0;
	if (VirtualProtect((void *)ip, 1024, PAGE_EXECUTE_READWRITE, &old))
	{
		memcpy(g_backup, (void *)ip, 1024);
		((unsigned char *)ip)[0] = 0x90;
		((unsigned char *)ip)[1] = 0xEB;
		((unsigned char *)ip)[2] = 0xFD;

		VirtualProtect((void *)ip, 1024, old, &old);
	}
	///
	ResumeProcess();
}

void restore_32(unsigned long tid, unsigned long long ip)
{
	unsigned long old = 0;
	if (VirtualProtect((void *)ip, 1024, PAGE_EXECUTE_READWRITE, &old))
	{
		((unsigned char *)ip)[0] = g_backup[0];
		((unsigned char *)ip)[1] = g_backup[1];
		((unsigned char *)ip)[2] = g_backup[2];

		VirtualProtect((void *)ip, 1024, old, &old);
	}

	HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;

	GetThreadContext(h_thread, &context);
#ifndef _WIN64
	context.Eip = ip;
#else
	context.Rip = ip;
#endif
	SetThreadContext(h_thread, &context);
}

unsigned long check_32(unsigned long long ip)
{
	THREADENTRY32 thread_block32 = { 0, };
	HANDLE h_snapshot = NULL;
	HANDLE h_thread = NULL;

	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!h_snapshot)
		return 0;

	thread_block32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(h_snapshot, &thread_block32))
		return 0;

	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;

	do
	{
		if (thread_block32.th32OwnerProcessID == GetCurrentProcessId()
			&& thread_block32.th32ThreadID != GetCurrentThreadId())
		{
			h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_block32.th32ThreadID);

			SuspendThread(h_thread);

			if (GetThreadContext(h_thread, &context))
			{
#ifndef _WIN64
				if (context.Eip == (unsigned long)ip || context.Eip == (unsigned long)ip + 1)
#else
				if (context.Rip == ip || context.Rip == ip + 1)
#endif
				{
					CloseHandle(h_thread);
					return thread_block32.th32ThreadID;
				}
			}

			ResumeThread(h_thread);

			CloseHandle(h_thread);
		}
	} while (Thread32Next(h_snapshot, &thread_block32));

	return 0;
}
///
///
///
DWORD WINAPI reopen(LPVOID args)
{
	PDLL_ARGS dll_args = (PDLL_ARGS)args;
	wchar_t cmd[MAX_PATH];
	wchar_t process_id[MAX_PATH];

	_itow(GetCurrentProcessId(), process_id, 10);

	StringCbCopy(cmd, MAX_PATH, dll_args->dll_path);
	StringCbCat(cmd, MAX_PATH, L"\\windbg.exe -pv -p ");
	StringCbCat(cmd, MAX_PATH, process_id);
	
	STARTUPINFOW startup_info = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info))
	{

	}

	return 0;
}

void __stdcall reopen(PDLL_ARGS dll_args)
{
	wchar_t cmd[MAX_PATH];
	wchar_t process_id[MAX_PATH];

	_itow(GetCurrentProcessId(), process_id, 10);

	StringCbCopy(cmd, MAX_PATH, dll_args->dll_path);
	StringCbCat(cmd, MAX_PATH, L"\\windbg.exe -pv -p ");
	StringCbCat(cmd, MAX_PATH, process_id);

	STARTUPINFOW startup_info = { 0 };
	PROCESS_INFORMATION proc_info = { 0 };
	if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &proc_info))
	{
		StringCbCopy(cmd, MAX_PATH, dll_args->dll_path);
		StringCbCat(cmd, MAX_PATH, L"\\test.bat");

		_wsystem(cmd);
	}
}
///
///
///
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);

		PDLL_ARGS args = (PDLL_ARGS)lpvReserved;
		patch_32(args->break_point);

		unsigned long tid = 0;
		do
		{
			tid = check_32(args->break_point);
		} while (tid == 0);

		restore_32(tid, args->break_point);

		if (args->dll_path)
		{
			unsigned long oepn_tid = 0;
			//HANDLE h_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)reopen, args, 0, &oepn_tid);
			//WaitForSingleObject(h_thread, INFINITE);
			reopen(args);
		}
	}
}
