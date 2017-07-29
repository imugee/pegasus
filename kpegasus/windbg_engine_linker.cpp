#define _CRT_SECURE_NO_WARNINGS

#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>

#pragma comment(lib, "dbgeng.lib")
///
///
///
windbg_process::windbg_process(unsigned long long eprocess, ExtRemoteTyped eprocess_node) : eprocess_(eprocess), eprocess_node_(eprocess_node)
{
	if(eprocess_node_.Field("VadRoot").HasField("Root"))
	{
		vad_root_node_ = eprocess_node_.Field("VadRoot").Field("Root");
		set_vad_list(vad_root_node_);
	}
}

bool __stdcall windbg_process::set_vad_list(ExtRemoteTyped node)
{
	if (!node.GetPtr())
		return false;

	ULONG64 val = node.GetPtr();
	ExtRemoteTyped current = ExtRemoteTyped("(nt!_MMVAD *)@$extin", val);
	ExtRemoteTyped left = current.Field("Core").Field("VadNode").Field("Left");
	ExtRemoteTyped right = current.Field("Core").Field("VadNode").Field("Right");

	set_vad_list(left);
	///
	///
	///
	ULONG64 start = current.Field("Core").Field("StartingVpn").GetUlong();
	ULONG64 end = current.Field("Core").Field("EndingVpn").GetUlong();
	if (current.Field("Core").HasField("StartingVpnHigh") && current.Field("Core").HasField("EndingVpnHigh"))
	{
		ULONG64 start_high = current.Field("Core").Field("StartingVpnHigh").GetUchar();
		ULONG64 end_high = current.Field("Core").Field("EndingVpnHigh").GetUchar();

		start = start | (start_high << 32);
		end = end | (end_high << 32);
	}
	start <<= 12;
	end <<= 12;

	ULONG64 size = end - start;
	ULONG type = current.Field("Core").Field("u.VadFlags.VadType").GetUlong();
	ULONG protect = current.Field("Core").Field("u.VadFlags.Protection").GetUlong();
	ULONG private_mem = current.Field("Core").Field("u.VadFlags.PrivateMemory").GetUlong();
	ULONG commit = current.Field("Core").Field("u1.VadFlags1.MemCommit").GetUlong();

	dprintf("%0*I64x-%0*I64x\n", 16, start, 16, end);
	///
	///
	///
	set_vad_list(right);

	return true;
}
///
///
///
windbg_engine_linker::windbg_engine_linker() : pid_(0), process_(nullptr)
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
windbg_engine_linker::~windbg_engine_linker() {}

void __stdcall windbg_engine_linker::setting(const char *argument_str, int *argument_count, char(*args)[MAX_ARGUMENT_LENGTH])
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

bool __stdcall windbg_engine_linker::virtual_query(uint64_t address, void *context, size_t context_size)
{
	return true;
}

bool __stdcall windbg_engine_linker::virtual_query(uint64_t address, MEMORY_BASIC_INFORMATION64 *mbi)
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

unsigned long __stdcall windbg_engine_linker::read_memory(uint64_t address, void *buffer, size_t buffer_size)
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

bool __stdcall windbg_engine_linker::get_context(void *context, size_t context_size)
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

unsigned long long __stdcall windbg_engine_linker::get_teb_address()
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

unsigned long long __stdcall windbg_engine_linker::get_peb_address()
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

bool __stdcall windbg_engine_linker::write_file_log(wchar_t *log_dir, wchar_t *log_file_name, wchar_t *format, ...)
{
	FILE *log = NULL;
	wchar_t path[MAX_PATH];

	memset(path, 0, MAX_PATH);
	StringCbCopy(path, MAX_PATH, log_dir);
	StringCbCat(path, MAX_PATH, L"\\");
	StringCbCat(path, MAX_PATH, log_file_name);

	log = _wfopen(path, L"a+");

	va_list ap;
	va_start(ap, format);

	vfwprintf(log, format, ap);

	va_end(ap);
	fclose(log);

	return true;
}

bool __stdcall windbg_engine_linker::write_binary(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned char *dump, size_t size)
{
	WCHAR path[MAX_PATH] = { 0, };

	StringCbCopy(path, MAX_PATH, bin_dir);
	StringCbCat(path, MAX_PATH, L"\\");
	StringCbCat(path, MAX_PATH, bin_file_name);

	HANDLE h_file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	std::shared_ptr<void> handle_closer(h_file, CloseHandle);
	if (!WriteFile(h_file, (PVOID)dump, (DWORD)size, &written, NULL))
		return false;

	return true;
}

bool __stdcall windbg_engine_linker::read_binary(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned char *dump, size_t size)
{
	WCHAR path[MAX_PATH] = { 0, };

	StringCbCopy(path, MAX_PATH, bin_dir);
	StringCbCat(path, MAX_PATH, L"\\");
	StringCbCat(path, MAX_PATH, bin_file_name);

	HANDLE h_file = CreateFile(path, GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD readn = 0;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	std::shared_ptr<void> handle_closer(h_file, CloseHandle);
	if (!ReadFile(h_file, (PVOID)dump, (DWORD)size, &readn, NULL))
		return false;

	return true;
}

void __stdcall windbg_engine_linker::select_process(unsigned long long pid)
{
	ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessList(); // eprocess list

	//if (process_)
	//	delete process_;

	for (list.StartHead(); list.HasNode(); list.Next())
	{
		ExtRemoteTyped n = list.GetTypedNode();
		ULONG64 current_pid = n.Field("UniqueProcessId").GetPtr();

		if (current_pid == pid)
		{
			dprintf("%x\n", pid);
			std::shared_ptr<windbg_process> process(new windbg_process(list.GetNodeOffset(), n));
			//process_ = new windbg_process(list.GetNodeOffset(), n);
			break;
		}
	}
}