#include "xdv_sdk.h"
#include <windows.h>

#ifdef _WIN64
#pragma comment(lib, "xdvlib_x64.lib")
#else
#pragma comment(lib, "xdvlib.lib")
#endif

void * FindPattern(void * base, size_t base_size, unsigned char * pattern, size_t pattern_size);
void * XdvFindPattern(void * base, size_t base_size, unsigned char * pattern, size_t pattern_size)
{
	return FindPattern(base, base_size, pattern, pattern_size);
}

//
void * _debug_event = nullptr;
bool XdvInstallDebugEvent(unsigned long pid)
{
	wchar_t debug_event_name[100];
	wsprintf(debug_event_name, L"%ls-%08x", DBG_ATTACH_POINT_EVENT, pid);

	_debug_event = CreateEvent(0, FALSE, FALSE, debug_event_name);
	if (!_debug_event)
	{
		_debug_event = OpenEvent(EVENT_ALL_ACCESS, FALSE, debug_event_name);
		if (!_debug_event)
		{
			return false;
		}
	}

	return true;
}

void XdvSetDebugEvent()
{
	SetEvent(_debug_event);
}

void XdvWaitForDebugEvent()
{
	WaitForSingleObject(_debug_event, INFINITE);
}

unsigned long _process_id = 0;
void * _exception_event_handle = nullptr;
void * _return_event_handle = nullptr;
void * _share_memory_handle = nullptr;
void * _share_memory = nullptr;
int XdvInstallRemoteEvent(unsigned long pid)
{
	if (pid == 0 || pid == 4)
	{
		return 1;
	}

	int status = 0;
	wchar_t exception_event_name[100];
	wsprintf(exception_event_name, L"%ls-%08x", DBG_EXCEPTION_EVENT_NAME, pid);
	_exception_event_handle = CreateEvent(0, FALSE, FALSE, exception_event_name);
	if (!_exception_event_handle)
	{
		_exception_event_handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, exception_event_name);
		status = -1;
	}

	wchar_t return_evnet_name[100];
	wsprintf(return_evnet_name, L"%ls-%08x", DBG_RETURN_EVENT_NAME, pid);
	_return_event_handle = CreateEvent(0, FALSE, FALSE, return_evnet_name);
	if (!_return_event_handle)
	{
		_return_event_handle = OpenEvent(EVENT_ALL_ACCESS, FALSE, return_evnet_name);
		status = -1;
	}

	wchar_t share_map_name[100];
	wsprintf(share_map_name, L"%ls-%08x", DBG_INFO_SHARE_MEMORY_NAME, pid);
	_share_memory_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x2000, share_map_name);
	if (!_share_memory_handle)
	{
		_share_memory_handle = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, share_map_name);
		status = -1;
	}
	_share_memory = MapViewOfFile(_share_memory_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0x2000);

	if (_exception_event_handle == nullptr
		|| _return_event_handle == nullptr
		|| _share_memory_handle == nullptr
		|| _share_memory == nullptr)
	{
		status = 1;
	}
	else
	{
		_process_id = pid;
	}

	return status;
}

void XdvCloseRemoteEvent()
{
	CloseHandle(_exception_event_handle);
	CloseHandle(_return_event_handle);

	UnmapViewOfFile(_share_memory);
	CloseHandle(_share_memory_handle);
}

void XdvExceptionEvent()
{
	SetEvent(_exception_event_handle);
}

void XdvReturnEvent()
{
	SetEvent(_return_event_handle);
}

void XdvWaitForExceptionEvent()
{
	WaitForSingleObject(_exception_event_handle, INFINITE);
}

void XdvWaitForReturnEvent()
{
	WaitForSingleObject(_return_event_handle, INFINITE);
}

void * XdvDebugSharedMemory()
{
	return _share_memory;
}

bool XdvCheckRemoteEvent()
{
	if (_process_id)
	{
		return true;
	}

	return false;
}