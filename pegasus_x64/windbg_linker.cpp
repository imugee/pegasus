#include <windows.h>
#include <dbgeng.h>
#include <strsafe.h>
#include <memory>

#include "interface.h"
#include "windbg_linker.h"

#pragma comment(lib, "dbgeng.lib")

WindbgSafeLinker::WindbgSafeLinker()
{
	if (DebugCreate(__uuidof(IDebugClient), (void **)&debug_client_) == S_OK
		&& ((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&debug_data_space_2_) == S_OK
		&& ((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&debug_data_space_) == S_OK
		&& ((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugAdvanced), (void **)&debug_advanced_) == S_OK
		&& ((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugSystemObjects), (void **)&debug_system_objects_) == S_OK)
		init_flag_ = true;
	else
		init_flag_ = false;
}

WindbgSafeLinker::~WindbgSafeLinker()
{
}

void __stdcall WindbgSafeLinker::setting(const char *argument_str, int *argument_count, char(*args)[MAX_ARGUMENT_LENGTH])
{
	int count = 0;
	int index = 0;
	int backup_index = 0;

	while (INFINITE)
	{
		if ((argument_str[index] == ' ' && argument_str[index + 1] != ' '))
		{
			StringCbCopyA(args[count], index - backup_index + 1, &argument_str[backup_index]);

			backup_index = index + 1;
			++count;
		}

		if (argument_str[index] == NULL)
		{
			if (argument_str[index - 1] != ' ')
			{
				StringCbCopyA(args[count], index - backup_index + 1, &argument_str[backup_index]);

				++count;
			}
			break;
		}

		++index;
	}

	*argument_count = count;
}

bool __stdcall WindbgSafeLinker::virtual_query(uint64_t address, void *context, size_t context_size)
{
	try
	{
		if (!init_flag_)
			return false;

		MEMORY_BASIC_INFORMATION64 mbi_64 = { 0, };
		memset(&mbi_64, 0, sizeof(mbi_64));

		if (((IDebugDataSpaces2 *)debug_data_space_2_)->QueryVirtual(address, &mbi_64) != S_OK)
			return false;

		if (context && context_size != sizeof(mbi_64))
			return false;

		if (memcpy_s(context, context_size, &mbi_64, context_size) != 0)
			return false;
	}
	catch (...)
	{
		return false;
	}

	return true;
}

bool __stdcall WindbgSafeLinker::virtual_query(uint64_t address, MEMORY_BASIC_INFORMATION64 *mbi)
{
	if (!init_flag_)
		return false;

	if (((IDebugDataSpaces2 *)debug_data_space_2_)->QueryVirtual(address, mbi) != S_OK)
	{
		//if (mbi->BaseAddress > address)
			return false;
	}

	return true;
}

unsigned long __stdcall WindbgSafeLinker::read_memory(uint64_t address, void *buffer, size_t buffer_size)
{
	unsigned long readn = 0;

	try
	{
		if (!init_flag_)
			return 0;

		if (((IDebugDataSpaces *)debug_data_space_)->ReadVirtual(address, buffer, (unsigned long)buffer_size, &readn) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return readn;
}

bool __stdcall WindbgSafeLinker::get_context(void *context, size_t context_size)
{
	try
	{
		if (!init_flag_)
			return false;

		if (((IDebugAdvanced *)debug_advanced_)->GetThreadContext(context, (unsigned long)context_size) != S_OK)
			return false;
	}
	catch (...)
	{
		return false;
	}

	return true;
}

unsigned long long __stdcall WindbgSafeLinker::get_teb_address()
{
	unsigned long long teb_address = 0;

	try
	{
		if (!init_flag_)
			return 0;

		if (((IDebugSystemObjects *)debug_system_objects_)->GetCurrentThreadTeb(&teb_address) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return teb_address;
}

unsigned long long __stdcall WindbgSafeLinker::get_peb_address()
{
	unsigned long long peb_address = 0;

	try
	{
		if (!init_flag_)
			return 0;

		if (((IDebugSystemObjects *)debug_system_objects_)->GetCurrentProcessPeb(&peb_address) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return peb_address;
}