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

	HANDLE h_file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD readn = 0;

	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	std::shared_ptr<void> handle_closer(h_file, CloseHandle);
	if (!ReadFile(h_file, (PVOID)dump, (DWORD)size, &readn, NULL))
		return false;

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
		if (table_size == index)
			break;

		((windbg_process *)table)[index++] = *p;
	}
	*read_size = (size_t)index;

	return true;
}

 void __stdcall windbg_engine_linker::clear_screen()
{
	for(int i = 0; i<15000; ++i)
		dprintf("%c", 0x8);
}

bool __stdcall windbg_engine_linker::get_thread_context(cpu_context_type *context)
{
	if (context == nullptr)
		return false;

	unsigned long count = 0;
	
	if (g_Ext->m_Registers->GetNumberRegisters(&count) != S_OK)
		return false;

	DEBUG_VALUE debug_value_array[1000];
	memset(debug_value_array, 0, sizeof(debug_value_array));

	if (g_Ext->m_Registers->GetValues(count, nullptr, 0, debug_value_array) != S_OK)
		return false;

	if (g_Ext->IsCurMachine64())
	{
		context->rax = debug_value_array[DBG_X64_REG_IDX_RAX].I64;
		context->rbx = debug_value_array[DBG_X64_REG_IDX_RBX].I64;
		context->rcx = debug_value_array[DBG_X64_REG_IDX_RCX].I64;
		context->rdx = debug_value_array[DBG_X64_REG_IDX_RDX].I64;

		context->rbp = debug_value_array[DBG_X64_REG_IDX_RBP].I64;
		context->rsp = debug_value_array[DBG_X64_REG_IDX_RSP].I64;

		context->rdi = debug_value_array[DBG_X64_REG_IDX_RDI].I64;
		context->rdi = debug_value_array[DBG_X64_REG_IDX_RSI].I64;

		context->r8 = debug_value_array[DBG_X64_REG_IDX_R8].I64;
		context->r9 = debug_value_array[DBG_X64_REG_IDX_R9].I64;
		context->r10 = debug_value_array[DBG_X64_REG_IDX_R10].I64;
		context->r11 = debug_value_array[DBG_X64_REG_IDX_R11].I64;
		context->r12 = debug_value_array[DBG_X64_REG_IDX_R12].I64;
		context->r13 = debug_value_array[DBG_X64_REG_IDX_R13].I64;
		context->r14 = debug_value_array[DBG_X64_REG_IDX_R14].I64;
		context->r15 = debug_value_array[DBG_X64_REG_IDX_R15].I64;

		context->rip = debug_value_array[DBG_X64_REG_IDX_RIP].I64;

		context->efl = (unsigned long)debug_value_array[DBG_X64_REG_IDX_EFL].I64;

		context->cs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_CS].I64;
		context->ds = (unsigned long)debug_value_array[DBG_X64_REG_IDX_DS].I64;
		context->es = (unsigned long)debug_value_array[DBG_X64_REG_IDX_ES].I64;
		context->fs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_FS].I64;
		context->gs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_GS].I64;
		context->ss = (unsigned long)debug_value_array[DBG_X64_REG_IDX_SS].I64;

		context->dr0 = debug_value_array[DBG_X64_REG_IDX_DR0].I64;
		context->dr1 = debug_value_array[DBG_X64_REG_IDX_DR1].I64;
		context->dr2 = debug_value_array[DBG_X64_REG_IDX_DR2].I64;
		context->dr3 = debug_value_array[DBG_X64_REG_IDX_DR3].I64;
		context->dr6 = debug_value_array[DBG_X64_REG_IDX_DR6].I64;
		context->dr7 = debug_value_array[DBG_X64_REG_IDX_DR7].I64;

		context->fpcw = debug_value_array[DBG_X64_REG_IDX_FPCW].I64;
		context->fpsw = debug_value_array[DBG_X64_REG_IDX_FPSW].I64;
		context->fptw = debug_value_array[DBG_X64_REG_IDX_FPTW].I64;

		context->st0 = debug_value_array[DBG_X64_REG_IDX_ST0].I64;
		context->st1 = debug_value_array[DBG_X64_REG_IDX_ST1].I64;
		context->st2 = debug_value_array[DBG_X64_REG_IDX_ST2].I64;
		context->st3 = debug_value_array[DBG_X64_REG_IDX_ST3].I64;
		context->st4 = debug_value_array[DBG_X64_REG_IDX_ST4].I64;
		context->st5 = debug_value_array[DBG_X64_REG_IDX_ST5].I64;
		context->st6 = debug_value_array[DBG_X64_REG_IDX_ST6].I64;
		context->st7 = debug_value_array[DBG_X64_REG_IDX_ST7].I64;

		context->mm0 = debug_value_array[DBG_X64_REG_IDX_MM0].I64;
		context->mm1 = debug_value_array[DBG_X64_REG_IDX_MM1].I64;
		context->mm2 = debug_value_array[DBG_X64_REG_IDX_MM2].I64;
		context->mm3 = debug_value_array[DBG_X64_REG_IDX_MM3].I64;
		context->mm4 = debug_value_array[DBG_X64_REG_IDX_MM4].I64;
		context->mm5 = debug_value_array[DBG_X64_REG_IDX_MM5].I64;
		context->mm6 = debug_value_array[DBG_X64_REG_IDX_MM6].I64;
		context->mm7 = debug_value_array[DBG_X64_REG_IDX_MM7].I64;

		context->mxcsr = debug_value_array[DBG_X64_REG_IDX_MXCSR].I64;

		context->xmm0 = debug_value_array[DBG_X64_REG_IDX_XMM0].I64;
		context->xmm1 = debug_value_array[DBG_X64_REG_IDX_XMM1].I64;
		context->xmm2 = debug_value_array[DBG_X64_REG_IDX_XMM2].I64;
		context->xmm3 = debug_value_array[DBG_X64_REG_IDX_XMM3].I64;
		context->xmm4 = debug_value_array[DBG_X64_REG_IDX_XMM4].I64;
		context->xmm5 = debug_value_array[DBG_X64_REG_IDX_XMM5].I64;
		context->xmm6 = debug_value_array[DBG_X64_REG_IDX_XMM6].I64;
		context->xmm7 = debug_value_array[DBG_X64_REG_IDX_XMM7].I64;
		context->xmm8 = debug_value_array[DBG_X64_REG_IDX_XMM8].I64;
		context->xmm9 = debug_value_array[DBG_X64_REG_IDX_XMM9].I64;
		context->xmm10 = debug_value_array[DBG_X64_REG_IDX_XMM10].I64;
		context->xmm11 = debug_value_array[DBG_X64_REG_IDX_XMM11].I64;
		context->xmm12 = debug_value_array[DBG_X64_REG_IDX_XMM12].I64;
		context->xmm13 = debug_value_array[DBG_X64_REG_IDX_XMM13].I64;
		context->xmm14 = debug_value_array[DBG_X64_REG_IDX_XMM14].I64;
		context->xmm15 = debug_value_array[DBG_X64_REG_IDX_XMM15].I64;

		context->ymm0 = debug_value_array[DBG_X64_REG_IDX_YMM0].I64;
		context->ymm1 = debug_value_array[DBG_X64_REG_IDX_YMM1].I64;
		context->ymm2 = debug_value_array[DBG_X64_REG_IDX_YMM2].I64;
		context->ymm3 = debug_value_array[DBG_X64_REG_IDX_YMM3].I64;
		context->ymm4 = debug_value_array[DBG_X64_REG_IDX_YMM4].I64;
		context->ymm5 = debug_value_array[DBG_X64_REG_IDX_YMM5].I64;
		context->ymm6 = debug_value_array[DBG_X64_REG_IDX_YMM6].I64;
		context->ymm7 = debug_value_array[DBG_X64_REG_IDX_YMM7].I64;
		context->ymm8 = debug_value_array[DBG_X64_REG_IDX_YMM8].I64;
		context->ymm9 = debug_value_array[DBG_X64_REG_IDX_YMM9].I64;
		context->ymm10 = debug_value_array[DBG_X64_REG_IDX_YMM10].I64;
		context->ymm11 = debug_value_array[DBG_X64_REG_IDX_YMM11].I64;
		context->ymm12 = debug_value_array[DBG_X64_REG_IDX_YMM12].I64;
		context->ymm13 = debug_value_array[DBG_X64_REG_IDX_YMM13].I64;
		context->ymm14 = debug_value_array[DBG_X64_REG_IDX_YMM14].I64;
		context->ymm15 = debug_value_array[DBG_X64_REG_IDX_YMM15].I64;

		context->iopl = debug_value_array[DBG_X64_REG_IDX_IOPL].I64;
		context->vip = debug_value_array[DBG_X64_REG_IDX_VIP].I64;
		context->vif = debug_value_array[DBG_X64_REG_IDX_VIF].I64;
	}
	else
	{
		context->rax = debug_value_array[DBG_X86_REG_IDX_EAX].I32;
		context->rbx = debug_value_array[DBG_X86_REG_IDX_EBX].I32;
		context->rcx = debug_value_array[DBG_X86_REG_IDX_ECX].I32;
		context->rdx = debug_value_array[DBG_X86_REG_IDX_EDX].I32;

		context->rbp = debug_value_array[DBG_X86_REG_IDX_EBP].I32;
		context->rsp = debug_value_array[DBG_X86_REG_IDX_ESP].I32;

		context->rdi = debug_value_array[DBG_X86_REG_IDX_EDI].I32;
		context->rdi = debug_value_array[DBG_X86_REG_IDX_ESI].I32;

		context->rip = debug_value_array[DBG_X86_REG_IDX_EIP].I32;

		context->efl = (unsigned long)debug_value_array[DBG_X86_REG_IDX_EFL].I32;

		context->cs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_CS].I32;
		context->ds = (unsigned long)debug_value_array[DBG_X86_REG_IDX_DS].I32;
		context->es = (unsigned long)debug_value_array[DBG_X86_REG_IDX_ES].I32;
		context->fs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_FS].I32;
		context->gs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_GS].I32;
		context->ss = (unsigned long)debug_value_array[DBG_X86_REG_IDX_SS].I32;

		context->dr0 = debug_value_array[DBG_X86_REG_IDX_DR0].I32;
		context->dr1 = debug_value_array[DBG_X86_REG_IDX_DR1].I32;
		context->dr2 = debug_value_array[DBG_X86_REG_IDX_DR2].I32;
		context->dr3 = debug_value_array[DBG_X86_REG_IDX_DR3].I32;
		context->dr6 = debug_value_array[DBG_X86_REG_IDX_DR6].I32;
		context->dr7 = debug_value_array[DBG_X86_REG_IDX_DR7].I32;

		context->fpcw = debug_value_array[DBG_X86_REG_IDX_FPCW].I32;
		context->fpsw = debug_value_array[DBG_X86_REG_IDX_FPSW].I32;
		context->fptw = debug_value_array[DBG_X86_REG_IDX_FPTW].I32;

		context->st0 = debug_value_array[DBG_X86_REG_IDX_ST0].I32;
		context->st1 = debug_value_array[DBG_X86_REG_IDX_ST1].I32;
		context->st2 = debug_value_array[DBG_X86_REG_IDX_ST2].I32;
		context->st3 = debug_value_array[DBG_X86_REG_IDX_ST3].I32;
		context->st4 = debug_value_array[DBG_X86_REG_IDX_ST4].I32;
		context->st5 = debug_value_array[DBG_X86_REG_IDX_ST5].I32;
		context->st6 = debug_value_array[DBG_X86_REG_IDX_ST6].I32;
		context->st7 = debug_value_array[DBG_X86_REG_IDX_ST7].I32;

		context->mm0 = debug_value_array[DBG_X86_REG_IDX_MM0].I32;
		context->mm1 = debug_value_array[DBG_X86_REG_IDX_MM1].I32;
		context->mm2 = debug_value_array[DBG_X86_REG_IDX_MM2].I32;
		context->mm3 = debug_value_array[DBG_X86_REG_IDX_MM3].I32;
		context->mm4 = debug_value_array[DBG_X86_REG_IDX_MM4].I32;
		context->mm5 = debug_value_array[DBG_X86_REG_IDX_MM5].I32;
		context->mm6 = debug_value_array[DBG_X86_REG_IDX_MM6].I32;
		context->mm7 = debug_value_array[DBG_X86_REG_IDX_MM7].I32;

		context->mxcsr = debug_value_array[DBG_X86_REG_IDX_MXCSR].I32;

		context->xmm0 = debug_value_array[DBG_X86_REG_IDX_XMM0].I32;
		context->xmm1 = debug_value_array[DBG_X86_REG_IDX_XMM1].I32;
		context->xmm2 = debug_value_array[DBG_X86_REG_IDX_XMM2].I32;
		context->xmm3 = debug_value_array[DBG_X86_REG_IDX_XMM3].I32;
		context->xmm4 = debug_value_array[DBG_X86_REG_IDX_XMM4].I32;
		context->xmm5 = debug_value_array[DBG_X86_REG_IDX_XMM5].I32;
		context->xmm6 = debug_value_array[DBG_X86_REG_IDX_XMM6].I32;
		context->xmm7 = debug_value_array[DBG_X86_REG_IDX_XMM7].I32;

		context->ymm0 = debug_value_array[DBG_X86_REG_IDX_YMM0].I32;
		context->ymm1 = debug_value_array[DBG_X86_REG_IDX_YMM1].I32;
		context->ymm2 = debug_value_array[DBG_X86_REG_IDX_YMM2].I32;
		context->ymm3 = debug_value_array[DBG_X86_REG_IDX_YMM3].I32;
		context->ymm4 = debug_value_array[DBG_X86_REG_IDX_YMM4].I32;
		context->ymm5 = debug_value_array[DBG_X86_REG_IDX_YMM5].I32;
		context->ymm6 = debug_value_array[DBG_X86_REG_IDX_YMM6].I32;
		context->ymm7 = debug_value_array[DBG_X86_REG_IDX_YMM7].I32;

		context->iopl = debug_value_array[DBG_X86_REG_IDX_IOPL].I32;
		context->vip = debug_value_array[DBG_X86_REG_IDX_VIP].I32;
		context->vif = debug_value_array[DBG_X86_REG_IDX_VIF].I32;
	}

	return true;
}
