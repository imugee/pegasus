#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include "util.h"

VOID WINAPI OpenConsoleLogViewer()
{
	if (AllocConsole())
	{
		freopen("CONOUT$", "w", stdout);
		SetConsoleTitle(L"logv");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
}

BOOL WINAPI SuspendProcess()
{
	THREADENTRY32 thread_block32 = { 0, };
	HANDLE h_snapshot = NULL;
	HANDLE h_thread = NULL;
	DWORD s = 0;

	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!h_snapshot)
		return FALSE;

	thread_block32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(h_snapshot, &thread_block32))
		return FALSE;

	do
	{
		if (thread_block32.th32OwnerProcessID == GetCurrentProcessId()
			&& thread_block32.th32ThreadID != GetCurrentThreadId())
		{
			h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_block32.th32ThreadID);

			s = SuspendThread(h_thread);

			CloseHandle(h_thread);
		}
	} while (Thread32Next(h_snapshot, &thread_block32));

	return TRUE;
}

BOOL WINAPI ResumeProcess()
{
	THREADENTRY32 thread_block32 = { 0, };
	HANDLE h_snapshot = NULL;
	HANDLE h_thread = NULL;
	DWORD s = 0;

	h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!h_snapshot)
		return FALSE;

	thread_block32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(h_snapshot, &thread_block32))
		return FALSE;

	do
	{
		if (thread_block32.th32OwnerProcessID == GetCurrentProcessId()
			&& thread_block32.th32ThreadID != GetCurrentThreadId())
		{
			h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_block32.th32ThreadID);

			do
			{
				s = ResumeThread(h_thread);
			} while (s);

			CloseHandle(h_thread);
		}
	} while (Thread32Next(h_snapshot, &thread_block32));

	return TRUE;
}
