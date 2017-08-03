// https://www.reactos.org/wiki/Techwiki:Ntoskrnl/MMVAD
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
/// threads
///
windbg_thread::windbg_thread()
{
}

windbg_thread::windbg_thread(unsigned long long ethread, unsigned long long tid, ExtRemoteTyped ethread_node) : ethread_(ethread), tid_(tid)//, ethread_node_(ethread_node)
{
}

windbg_thread::~windbg_thread()
{
}
///
/// process
///
windbg_process::windbg_process()
{
}

void __stdcall windbg_process::set_process_information(unsigned long long eprocess, unsigned long long pid, ExtRemoteTyped eprocess_node)
{
	if (eprocess_node.Field("VadRoot").HasField("Root"))
	{
		ExtRemoteTyped vad_root_node = eprocess_node.Field("VadRoot").Field("Root");
		set_vad_list(vad_root_node);
	}
	
	ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessThreadList(eprocess); // ethread list
	for (list.StartHead(); list.HasNode(); list.Next())
	{
		ExtRemoteTyped n = list.GetTypedNode();
		if (n.HasField("Cid"))
		{
			windbg_thread thread(list.GetNodeOffset(), n.Field("Cid.UniqueThread").GetPtr(), n);
			thread_list_.push_back(thread);
		}
	}
}

windbg_process::windbg_process(unsigned long long eprocess, unsigned long long pid, ExtRemoteTyped eprocess_node) : eprocess_(eprocess), pid_(pid)//, eprocess_node_(eprocess_node)
{
	if(eprocess_node.Field("VadRoot").HasField("Root"))
	{
		ExtRemoteTyped vad_root_node = eprocess_node.Field("VadRoot").Field("Root");
		set_vad_list(vad_root_node);
	}
	
	ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessThreadList(eprocess); // ethread list
	for (list.StartHead(); list.HasNode(); list.Next())
	{
		ExtRemoteTyped n = list.GetTypedNode();
		if (n.HasField("Cid"))
		{
			windbg_thread thread(list.GetNodeOffset(), n.Field("Cid.UniqueThread").GetPtr(), n);
			thread_list_.push_back(thread);
		}
	}
}

windbg_process::~windbg_process()
{
	thread_list_.clear();

}

bool __stdcall windbg_process::set_vad_list(ExtRemoteTyped node)
{
	if (!node.GetPtr())
		return false;

	ULONG64 val = node.GetPtr();
	ExtRemoteTyped current = ExtRemoteTyped("(nt!_MMVAD *)@$extin", val);

	if (!current.HasField("Core"))
		return false;

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

	vad_node vad;
	memset(&vad, 0, sizeof(vad));

	vad.start = start;
	vad.end = end;
	vad.type = current.Field("Core").Field("u.VadFlags.VadType").GetUlong();
	vad.protect = current.Field("Core").Field("u.VadFlags.Protection").GetUlong();
	vad.is_private = current.Field("Core").Field("u.VadFlags.PrivateMemory").GetUlong();
	vad.commit = current.Field("Core").Field("u1.VadFlags1.MemCommit").GetUlong();

	//if (current.HasField("Subsection"))
	//{
	//	unsigned long long sub_section_ptr = current.Field("Subsection").GetPtr();
	//	ExtRemoteTyped sub_section("(nt!_SUBSECTION *)@$extin", sub_section_ptr);
	//	vad.object = sub_section.Field("ControlArea").Field("FilePointer").Field("Object").GetPtr();
	//}

	vad_list_.push_back(vad);
	///
	///
	///
	set_vad_list(right);

	return true;
}

std::list<windbg_process::vad_node> __stdcall windbg_process::get_vad_list()
{
	return vad_list_;
}

std::list<windbg_thread> __stdcall windbg_process::get_thread_list()
{
	return thread_list_;
}
///
///
///
windbg_engine_linker::windbg_engine_linker()
{
	if (g_Ext->IsKernelMode())
	{
		ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessList(); // eprocess list

		for (list.StartHead(); list.HasNode(); list.Next())
		{
			ExtRemoteTyped n = list.GetTypedNode();
			ULONG64 current_pid = n.Field("UniqueProcessId").GetPtr();
			windbg_process process(list.GetNodeOffset(), current_pid, n);

			process_list_.push_back(process);
		}
	}
}

windbg_engine_linker::~windbg_engine_linker() 
{
	process_list_.clear();
}

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
	if (g_Ext->m_Data2->QueryVirtual(address, mbi) != S_OK)
		return false;

	return true;
}

unsigned long __stdcall windbg_engine_linker::read_memory(uint64_t address, void *buffer, size_t buffer_size)
{
	unsigned long readn = 0;

	try
	{
		if (g_Ext->m_Data->ReadVirtual(address, buffer, (unsigned long)buffer_size, &readn) != S_OK)
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
		if (g_Ext->m_Advanced->GetThreadContext(context, (unsigned long)context_size) != S_OK)
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
		if (g_Ext->m_System->GetCurrentThreadTeb(&teb_address) != S_OK)
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
		if (g_Ext->m_System->GetCurrentProcessPeb(&peb_address) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return peb_address;
}

bool __stdcall windbg_engine_linker::set_debuggee_process(unsigned long pid)
{
	if (g_Ext->m_System->SetCurrentProcessId(pid) == S_OK)
		return true;
	return false;
}

bool __stdcall windbg_engine_linker::set_debuggee_thread(unsigned long tid)
{
	if (g_Ext->m_System->SetCurrentThreadId(tid) == S_OK)
		return true;
	return false;
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

bool __stdcall windbg_engine_linker::file_query(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned long long value, wchar_t *file_name, size_t *size)
{
	WIN32_FIND_DATA wfd;
	WCHAR path[MAX_PATH] = { 0, };
	StringCbCopy(path, MAX_PATH, bin_dir);
	StringCbCat(path, MAX_PATH, L"\\");
	StringCbCat(path, MAX_PATH, bin_file_name);

	HANDLE h_file = FindFirstFile(path, &wfd);

	if (h_file == INVALID_HANDLE_VALUE)
		return false;
	std::shared_ptr<void> file_closer(h_file, CloseHandle);

	do
	{
		wchar_t *end = nullptr;
		unsigned long long base_address = wcstoll(wfd.cFileName, &end, 16);
		size_t region_size = (wfd.nFileSizeHigh * (MAXDWORD + 1)) + wfd.nFileSizeLow;
		unsigned long long end_address = base_address + region_size;

		if(base_address <= value && value <= end_address)
			;//dprintf("%llx %llx\n", base_address, region_size);

	} while (FindNextFile(h_file, &wfd));

	return true;
}

bool __stdcall windbg_engine_linker::get_process_table(void *table, size_t table_size, size_t *read_size)
{
	if (!table)
		return false;

	if (sizeof((windbg_process *)table)[0] != sizeof(windbg_process))
		return false;

	if (process_list_.size() < table_size)
		table_size = process_list_.size();

	unsigned int index = 0;
	std::list<windbg_process>::iterator p = process_list_.begin();
	for (p; p != process_list_.end(); ++p)
	{
		if(table_size == index)
			break;
		
		((windbg_process *)table)[index++] = *p;
	}
	*read_size = (size_t)index;

	return true;
}
