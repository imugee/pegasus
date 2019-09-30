#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <dbgeng.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#include "dbgeng_exts.h"

#pragma comment(lib, "dbgeng.lib")
#pragma comment(lib, "corexts.lib")

DbgEngSystem::DbgEngSystem()
	: attach_id_(0), winapi_(nullptr)
{
	if (DebugCreate(__uuidof(IDebugClient5), (void **)&client_) != S_OK)
	{
		client_ = nullptr;
	}
}

DbgEngSystem::~DbgEngSystem()
{
}

xdv::object::id DbgEngSystem::ObjectType()
{
	return xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT;
}

std::string DbgEngSystem::ObjectString()
{
	return " Windows Debugger, [DEBUGGER][MDMP][USERDUMP][USERDU64]";
}

void DbgEngSystem::SetModuleName(std::string module)
{
}

std::string DbgEngSystem::ModuleName()
{
	return "";
}

std::map<unsigned long, std::string> DbgEngSystem::ProcessList()
{
	std::map<unsigned long, std::string> process_map;
	PROCESSENTRY32 process_block32 = { 0, };
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!snapshot_handle)
	{
		return process_map;
	}
	std::shared_ptr<void> handle_closer(snapshot_handle, CloseHandle);

	process_block32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snapshot_handle, &process_block32))
	{
		return process_map;
	}

	do
	{
		unsigned long pid = process_block32.th32ProcessID;
		std::wstring wpn = process_block32.szExeFile;
		std::string pn(wpn.begin(), wpn.end());

		process_map[pid] = pn;
	} while (Process32Next(snapshot_handle, &process_block32));

	return process_map;
}

bool nametoid(wchar_t *process_name, unsigned long *pid)
{
	PROCESSENTRY32 process_block32 = { 0, };
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!snapshot_handle)
		return false;
	std::shared_ptr<void> handle_closer(snapshot_handle, CloseHandle);

	process_block32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot_handle, &process_block32))
	{
		return false;
	}

	do
	{
		if (wcsstr(process_block32.szExeFile, process_name))
		{
			*pid = process_block32.th32ProcessID;

			return true;
		}
	} while (Process32Next(snapshot_handle, &process_block32));

	return false;
}

unsigned long DbgEngSystem::WaitForProcess(std::string process_name)
{
	std::wstring wprocess_name(process_name.begin(), process_name.end());
	unsigned long pid = 0;
	while (1)
	{
		if (nametoid((wchar_t *)wprocess_name.c_str(), &pid))
		{
			break;
		}
	}

	return pid;
}

void DebugMonitor(void * ctx);
bool DbgEngSystem::Attach(unsigned long pid)
{
	if (!client_)
	{
		return false;
	}

	if (attach_id_)
	{
		return true;
	}

	if (ProcessId())
	{
		client_->DetachProcesses();
	}

	if (winapi_)
	{
		return winapi_->Attach(pid);
	}

	IDebugControl5 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl5), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	unsigned long eng_option = 0;
	if (debug_control->GetEngineOptions(&eng_option) != S_OK)
	{
		return false;
	}

	eng_option |= DEBUG_ENGOPT_INITIAL_BREAK;
	eng_option |= DEBUG_ENGOPT_ALLOW_READ_ONLY_BREAKPOINTS;
	if (debug_control->SetEngineOptions(eng_option) != S_OK)
	{
		return false;
	}

	if (((IDebugClient5 *)client_)->AttachProcess(0, pid, DEBUG_ATTACH_DEFAULT) != S_OK)
	{
		return false;
	}

	if (debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)
	{
		return false;
	}

	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return false;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
		break;

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64);
		break;

	default:
		return false;
	}

	attach_id_ = 1;
	if (XdvInstallRemoteEvent(pid) != 1)
	{
		std::thread * dmt = new std::thread(DebugMonitor, this);
	}

	return true;
}

bool DbgEngSystem::Open(unsigned long pid)
{
	if (!client_)
	{
		return false;
	}

	if (((IDebugClient5 *)client_)->AttachProcess(0, pid, DEBUG_ATTACH_NONINVASIVE) != S_OK)
	{
		return false;
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	if (debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)
	{
		return false;
	}

	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return false;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
		break;

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64);
		break;

	default:
		return false;
	}

	winapi_ = (IDebugger *)XdvGetObjectByString("[Windows API]");
	if (winapi_)
	{
		winapi_->Open(pid);
		winapi_->Select(0);
	}

	return true;
}

bool DbgEngSystem::Open(char *path)
{
	if (!client_)
	{
		return false;
	}

	if (((IDebugClient5 *)client_)->OpenDumpFile(path) != S_OK)
	{
		return false;
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	if (debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)
	{
		return false;
	}

	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return false;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386);
		break;

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
		debug_control->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_AMD64);
		break;

	default:
		return false;
	}

	return true;
}

bool DbgEngSystem::Update()
{
	//if (attach_id_)
	//{
	//	return true;
	//}

	//if (!client_)
	//{
	//	return false;
	//}

	//IDebugSystemObjects4 *system_object;
	//if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	//{
	//	return false;
	//}

	//unsigned long process_id = 0;
	//if (system_object->GetCurrentProcessSystemId(&process_id) != S_OK)
	//{
	//	return false;
	//}

	//std::map<unsigned long, unsigned long long> thread_map;
	//this->Threads(thread_map);
	//for (auto it : thread_map)
	//{
	//	SuspendThread(it.first);
	//}

	//if (client_->DetachProcesses() != S_OK)
	//{
	//	return false;
	//}

	//if (!Open(process_id))
	//{
	//	return false;
	//}

	//thread_map.clear();
	//this->Threads(thread_map);
	//for (auto it : thread_map)
	//{
	//	ResumeThread(it.first);
	//}

	return true;
}

unsigned long DbgEngSystem::ProcessId()
{
	if (!client_)
	{
		return 0;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return 0;
	}

	unsigned long process_id = 0;
	if (system_object->GetCurrentProcessSystemId(&process_id) == S_OK)
	{
		return process_id;
	}

	return 0;
}

//
//
unsigned long long DbgEngSystem::Read(unsigned long long ptr, unsigned char *out_memory, unsigned long read_size)
{
	if (winapi_)
	{
		return winapi_->Read(ptr, out_memory, read_size);
	}

	if (!client_)
	{
		return 0;
	}

	unsigned long readn = 0;
	IDebugDataSpaces2 *debug_data_space;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&debug_data_space) != S_OK)
	{
		return 0;
	}

	unsigned long long virtual_address = (unsigned long long)ptr;
	if (debug_data_space->ReadVirtual(virtual_address, out_memory, read_size, &readn) != S_OK)
	{
		return 0;
	}

	return readn;
}

unsigned long long DbgEngSystem::Write(void * ptr, unsigned char *input_memory, unsigned long write_size)
{
	if (winapi_)
	{
		return winapi_->Write(ptr, input_memory, write_size);
	}

	if (!client_)
	{
		return false;
	}

	unsigned long written = 0;
	IDebugDataSpaces2 *debug_data_space;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&debug_data_space) != S_OK)
	{
		return false;
	}

	unsigned long long virtual_address = (unsigned long long)ptr;
	if (debug_data_space->WriteVirtual(virtual_address, input_memory, write_size, &written) != S_OK)
	{
		return 0;
	}

	return written;
}

bool DbgEngSystem::Query(unsigned long long ptr, xdv::memory::type *memory_type)
{
	if (winapi_)
	{
		return winapi_->Query(ptr, memory_type);
	}

	if (!client_)
	{
		return false;
	}

	MEMORY_BASIC_INFORMATION64 mbi;
	IDebugDataSpaces2 *debug_data_space;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&debug_data_space) != S_OK)
	{
		return false;
	}

	unsigned long long virtual_address = ptr;
	if (debug_data_space->QueryVirtual(virtual_address, &mbi) == S_OK)
	{
		memory_type->AllocationBase = (unsigned long long)mbi.AllocationBase;
		memory_type->AllocationProtect = mbi.AllocationProtect;
		memory_type->BaseAddress = (unsigned long long)mbi.BaseAddress;
		memory_type->Protect = mbi.Protect;
		memory_type->RegionSize = (unsigned long long)mbi.RegionSize;
		memory_type->State = mbi.State;
		memory_type->Type = mbi.Type;

		return true;
	}

	return false;
}

void * DbgEngSystem::Alloc(void *ptr, unsigned long size, unsigned long allocation_type, unsigned long protect_type)
{
	if (winapi_)
	{
		return winapi_->Alloc(ptr, size, allocation_type, protect_type);
	}

	return nullptr;
}

//
//
bool DbgEngSystem::Select(unsigned long tid)
{
	if (winapi_)
	{
		return winapi_->Select(tid);
	}

	if (!client_)
	{
		return 0;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return 0;
	}

	unsigned long id = 0;
	if (system_object->GetThreadIdBySystemId(tid, &id) != S_OK)
	{
		return 0;
	}

	if (system_object->SetCurrentThreadId(id) != S_OK)
	{
		return 0;
	}

	return 1;
}

void DbgEngSystem::Threads(std::map<unsigned long, unsigned long long> &thread_info_map)
{
	if (winapi_)
	{
		winapi_->Threads(thread_info_map);
		return;
	}

	unsigned long thread_count = 0;
	if (!client_)
	{
		return;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return;
	}

	IDebugAdvanced3 *debug_advanced;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugAdvanced3), (void **)&debug_advanced) != S_OK)
	{
		return;
	}

	if (system_object->GetNumberThreads(&thread_count) != S_OK)
	{
		return;
	}

	unsigned long *tids = (unsigned long *)malloc(sizeof(unsigned long) * thread_count);
	if (!tids)
	{
		return;
	}
	memset(tids, 0, sizeof(unsigned long) * thread_count);

	if (system_object->GetThreadIdsByIndex(0, thread_count, nullptr, tids) != S_OK)
	{
		free(tids);
		return;
	}

	for (unsigned long i = 0; i < thread_count; ++i)
	{
		unsigned long long entry = 0;
		DEBUG_THREAD_BASIC_INFORMATION dtbi;
		unsigned long buffer_size = 0;

		unsigned long id = 0;
		if (system_object->GetThreadIdBySystemId(tids[i], &id) == S_OK)
		{
			if (debug_advanced->GetSystemObjectInformation(DEBUG_SYSOBJINFO_THREAD_BASIC_INFORMATION, 0, id, &dtbi, sizeof(dtbi), &buffer_size) == S_OK)
			{
				entry = dtbi.StartOffset;
			}
		}

		thread_info_map[tids[i]] = entry;
	}
}

unsigned long DbgEngSystem::ThreadId()
{
	if (!client_)
	{
		return 0;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return 0;
	}

	unsigned long tid = 0;
	if (system_object->GetCurrentThreadSystemId(&tid) == S_OK)
	{
		return tid;
	}

	return 0;
}

bool DbgEngSystem::GetThreadContext(xdv::architecture::x86::context::type *context)
{
	if (winapi_)
	{
		return winapi_->GetThreadContext(context);
	}

	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return false;
	}

	IDebugRegisters * debug_register;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugRegisters), (void **)&debug_register) != S_OK)
	{
		return false;
	}

	if (context == nullptr)
	{
		return false;
	}

	unsigned long count = 0;
	if (((IDebugRegisters *)debug_register)->GetNumberRegisters(&count) != S_OK)
	{
		return false;
	}

	DEBUG_VALUE debug_value_array[1000];
	memset(debug_value_array, 0, sizeof(debug_value_array));
	if (((IDebugRegisters *)debug_register)->GetValues(count, nullptr, 0, debug_value_array) != S_OK)
	{
		return false;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
	{
		context->rax = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EAX].I32;
		context->rbx = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EBX].I32;
		context->rcx = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ECX].I32;
		context->rdx = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EDX].I32;

		context->rbp = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EBP].I32;
		context->rsp = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ESP].I32;

		context->rdi = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EDI].I32;
		context->rsi = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ESI].I32;

		context->rip = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EIP].I32;

		context->efl = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EFL].I32;

		context->cs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_CS].I32;
		context->ds = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DS].I32;
		context->es = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ES].I32;
		context->fs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FS].I32;
		context->gs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_GS].I32;
		context->ss = (unsigned long)debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_SS].I32;

		context->dr0 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR0].I32;
		context->dr1 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR1].I32;
		context->dr2 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR2].I32;
		context->dr3 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR3].I32;
		context->dr6 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR6].I32;
		context->dr7 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR7].I32;

		context->fpcw = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPCW].I32;
		context->fpsw = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPSW].I32;
		context->fptw = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPTW].I32;

		context->st0 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST0].I32;
		context->st1 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST1].I32;
		context->st2 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST2].I32;
		context->st3 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST3].I32;
		context->st4 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST4].I32;
		context->st5 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST5].I32;
		context->st6 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST6].I32;
		context->st7 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST7].I32;

		context->mm0 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM0].I32;
		context->mm1 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM1].I32;
		context->mm2 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM2].I32;
		context->mm3 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM3].I32;
		context->mm4 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM4].I32;
		context->mm5 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM5].I32;
		context->mm6 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM6].I32;
		context->mm7 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM7].I32;

		context->mxcsr = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MXCSR].I32;

		context->xmm0 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM0].I32;
		context->xmm1 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM1].I32;
		context->xmm2 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM2].I32;
		context->xmm3 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM3].I32;
		context->xmm4 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM4].I32;
		context->xmm5 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM5].I32;
		context->xmm6 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM6].I32;
		context->xmm7 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM7].I32;

		context->ymm0 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM0].I32;
		context->ymm1 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM1].I32;
		context->ymm2 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM2].I32;
		context->ymm3 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM3].I32;
		context->ymm4 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM4].I32;
		context->ymm5 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM5].I32;
		context->ymm6 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM6].I32;
		context->ymm7 = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM7].I32;

		context->iopl = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_IOPL].I32;
		context->vip = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_VIP].I32;
		context->vif = debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_VIF].I32;
		break;
	}

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
	{
		context->rax = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RAX].I64;
		context->rbx = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RBX].I64;
		context->rcx = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RCX].I64;
		context->rdx = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RDX].I64;

		context->rbp = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RBP].I64;
		context->rsp = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RSP].I64;

		context->rdi = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RDI].I64;
		context->rsi = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RSI].I64;

		context->r8 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R8].I64;
		context->r9 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R9].I64;
		context->r10 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R10].I64;
		context->r11 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R11].I64;
		context->r12 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R12].I64;
		context->r13 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R13].I64;
		context->r14 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R14].I64;
		context->r15 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R15].I64;

		context->rip = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RIP].I64;

		context->efl = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_EFL].I64;

		context->cs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_CS].I64;
		context->ds = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DS].I64;
		context->es = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ES].I64;
		context->fs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FS].I64;
		context->gs = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_GS].I64;
		context->ss = (unsigned long)debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_SS].I64;

		context->dr0 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR0].I64;
		context->dr1 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR1].I64;
		context->dr2 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR2].I64;
		context->dr3 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR3].I64;
		context->dr6 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR6].I64;
		context->dr7 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR7].I64;

		context->fpcw = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPCW].I64;
		context->fpsw = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPSW].I64;
		context->fptw = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPTW].I64;

		context->st0 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST0].I64;
		context->st1 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST1].I64;
		context->st2 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST2].I64;
		context->st3 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST3].I64;
		context->st4 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST4].I64;
		context->st5 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST5].I64;
		context->st6 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST6].I64;
		context->st7 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST7].I64;

		context->mm0 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM0].I64;
		context->mm1 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM1].I64;
		context->mm2 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM2].I64;
		context->mm3 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM3].I64;
		context->mm4 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM4].I64;
		context->mm5 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM5].I64;
		context->mm6 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM6].I64;
		context->mm7 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM7].I64;

		context->mxcsr = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MXCSR].I64;

		context->xmm0 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM0].I64;
		context->xmm1 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM1].I64;
		context->xmm2 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM2].I64;
		context->xmm3 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM3].I64;
		context->xmm4 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM4].I64;
		context->xmm5 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM5].I64;
		context->xmm6 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM6].I64;
		context->xmm7 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM7].I64;
		context->xmm8 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM8].I64;
		context->xmm9 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM9].I64;
		context->xmm10 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM10].I64;
		context->xmm11 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM11].I64;
		context->xmm12 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM12].I64;
		context->xmm13 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM13].I64;
		context->xmm14 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM14].I64;
		context->xmm15 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM15].I64;

		context->ymm0 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM0].I64;
		context->ymm1 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM1].I64;
		context->ymm2 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM2].I64;
		context->ymm3 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM3].I64;
		context->ymm4 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM4].I64;
		context->ymm5 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM5].I64;
		context->ymm6 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM6].I64;
		context->ymm7 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM7].I64;
		context->ymm8 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM8].I64;
		context->ymm9 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM9].I64;
		context->ymm10 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM10].I64;
		context->ymm11 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM11].I64;
		context->ymm12 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM12].I64;
		context->ymm13 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM13].I64;
		context->ymm14 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM14].I64;
		context->ymm15 = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM15].I64;

		context->iopl = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_IOPL].I64;
		context->vip = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_VIP].I64;
		context->vif = debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_VIF].I64;
		break;
	}

	default:
		return false;
	}

	return true;
}

bool DbgEngSystem::SetThreadContext(xdv::architecture::x86::context::type *context)
{
	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return false;
	}

	IDebugRegisters * debug_register;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugRegisters), (void **)&debug_register) != S_OK)
	{
		return false;
	}

	if (context == nullptr)
	{
		return false;
	}

	unsigned long count = 0;
	if (((IDebugRegisters *)debug_register)->GetNumberRegisters(&count) != S_OK)
	{
		return false;
	}

	DEBUG_VALUE debug_value_array[1000];
	memset(debug_value_array, 0, sizeof(debug_value_array));
	if (((IDebugRegisters *)debug_register)->GetValues(count, nullptr, 0, debug_value_array) != S_OK)
	{
		return false;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
	{
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EAX].I64 = context->rax;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EBX].I64 = context->rbx;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ECX].I64 = context->rcx;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EDX].I64 = context->rdx;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EBP].I64 = context->rbp;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ESP].I64 = context->rsp;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EDI].I64 = context->rdi;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ESI].I64 = context->rsi;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EIP].I64 = context->rip;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_EFL].I32 = context->efl;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_CS].I32 = context->cs;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DS].I32 = context->ds;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ES].I32 = context->es;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FS].I32 = context->fs;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_GS].I32 = context->gs;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_SS].I32 = context->ss;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR0].I64 = context->dr0;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR1].I64 = context->dr1;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR2].I64 = context->dr2;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR3].I64 = context->dr3;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR6].I64 = context->dr6;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_DR7].I64 = context->dr7;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPCW].I64 = context->fpcw;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPSW].I64 = context->fpsw;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_FPTW].I64 = context->fptw;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST0].I64 = context->st0;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST1].I64 = context->st1;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST2].I64 = context->st2;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST3].I64 = context->st3;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST4].I64 = context->st4;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST5].I64 = context->st5;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST6].I64 = context->st6;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_ST7].I64 = context->st7;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM0].I64 = context->mm0;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM1].I64 = context->mm1;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM2].I64 = context->mm2;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM3].I64 = context->mm3;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM4].I64 = context->mm4;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM5].I64 = context->mm5;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM6].I64 = context->mm6;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MM7].I64 = context->mm7;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_MXCSR].I64 = context->mxcsr;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM0].I64 = context->xmm0;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM1].I64 = context->xmm1;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM2].I64 = context->xmm2;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM3].I64 = context->xmm3;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM4].I64 = context->xmm4;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM5].I64 = context->xmm5;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM6].I64 = context->xmm6;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_XMM7].I64 = context->xmm7;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM0].I64 = context->ymm0;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM1].I64 = context->ymm1;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM2].I64 = context->ymm2;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM3].I64 = context->ymm3;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM4].I64 = context->ymm4;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM5].I64 = context->ymm5;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM6].I64 = context->ymm6;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_YMM7].I64 = context->ymm7;

		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_IOPL].I64 = context->iopl;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_VIP].I64 = context->vip;
		debug_value_array[xdv::architecture::x86::context::x86idx::DBG_X86_REG_IDX_VIF].I64 = context->vif;
		break;
	}

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
	{
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RAX].I64 = context->rax;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RBX].I64 = context->rbx;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RCX].I64 = context->rcx;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RDX].I64 = context->rdx;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RBP].I64 = context->rbp;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RSP].I64 = context->rsp;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RDI].I64 = context->rdi;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RSI].I64 = context->rsi;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R8].I64 = context->r8;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R9].I64 = context->r9;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R10].I64 = context->r10;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R11].I64 = context->r11;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R12].I64 = context->r12;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R13].I64 = context->r13;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R14].I64 = context->r14;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_R15].I64 = context->r15;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_RIP].I64 = context->rip;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_EFL].I64 = context->efl;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_CS].I64 = context->cs;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DS].I64 = context->ds;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ES].I64 = context->es;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FS].I64 = context->fs;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_GS].I64 = context->gs;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_SS].I64 = context->ss;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR0].I64 = context->dr0;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR1].I64 = context->dr1;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR2].I64 = context->dr2;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR3].I64 = context->dr3;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR6].I64 = context->dr6;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_DR7].I64 = context->dr7;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPCW].I64 = context->fpcw;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPSW].I64 = context->fpsw;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_FPTW].I64 = context->fptw;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST0].I64 = context->st0;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST1].I64 = context->st1;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST2].I64 = context->st2;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST3].I64 = context->st3;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST4].I64 = context->st4;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST5].I64 = context->st5;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST6].I64 = context->st6;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_ST7].I64 = context->st7;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM0].I64 = context->mm0;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM1].I64 = context->mm1;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM2].I64 = context->mm2;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM3].I64 = context->mm3;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM4].I64 = context->mm4;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM5].I64 = context->mm5;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM6].I64 = context->mm6;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MM7].I64 = context->mm7;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_MXCSR].I64 = context->mxcsr;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM0].I64 = context->xmm0;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM1].I64 = context->xmm1;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM2].I64 = context->xmm2;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM3].I64 = context->xmm3;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM4].I64 = context->xmm4;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM5].I64 = context->xmm5;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM6].I64 = context->xmm6;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM7].I64 = context->xmm7;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM8].I64 = context->xmm8;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM9].I64 = context->xmm9;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM10].I64 = context->xmm10;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM11].I64 = context->xmm11;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM12].I64 = context->xmm12;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM13].I64 = context->xmm13;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM14].I64 = context->xmm14;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_XMM15].I64 = context->xmm15;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM0].I64 = context->ymm0;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM1].I64 = context->ymm1;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM2].I64 = context->ymm2;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM3].I64 = context->ymm3;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM4].I64 = context->ymm4;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM5].I64 = context->ymm5;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM6].I64 = context->ymm6;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM7].I64 = context->ymm7;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM8].I64 = context->ymm8;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM9].I64 = context->ymm9;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM10].I64 = context->ymm10;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM11].I64 = context->ymm11;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM12].I64 = context->ymm12;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM13].I64 = context->ymm13;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM14].I64 = context->ymm14;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_YMM15].I64 = context->ymm15;

		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_IOPL].I64 = context->iopl;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_VIP].I64 = context->vip;
		debug_value_array[xdv::architecture::x86::context::x64idx::DBG_X64_REG_IDX_VIF].I64 = context->vif;
		break;
	}

	default:
		return false;
	}

	if (debug_register->SetValues(count, nullptr, 0, debug_value_array) != S_OK)
	{
		return false;
	}

	return true;
}

bool DbgEngSystem::SuspendThread(unsigned long tid)
{
	if (winapi_)
	{
		return winapi_->SuspendThread(tid);
	}

	return false;
}

bool DbgEngSystem::ResumeThread(unsigned long tid)
{
	if (winapi_)
	{
		return winapi_->ResumeThread(tid);
	}

	return false;
}

bool DbgEngSystem::StackTraceEx(unsigned long long bp, unsigned long long sp, unsigned long long ip, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	if (winapi_)
	{
		return winapi_->StackTraceEx(bp, sp, ip, stack_frame, size_of_stack_frame, stack_count);
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	size_t cnt = size_of_stack_frame / sizeof(xdv::architecture::x86::frame::type);
	PDEBUG_STACK_FRAME debug_stack_frame = (PDEBUG_STACK_FRAME)malloc(sizeof(DEBUG_STACK_FRAME) * cnt);
	if (!debug_stack_frame)
	{
		return false;
	}
	memset(debug_stack_frame, 0, sizeof(DEBUG_STACK_FRAME) * cnt);

	if (debug_control->GetStackTrace(bp, sp, ip, debug_stack_frame, (unsigned long)(sizeof(DEBUG_STACK_FRAME) * cnt), stack_count) != S_OK)
	{
		return false;
	}

	for (unsigned long i = 0; i < *stack_count; ++i)
	{
		stack_frame[i].frame_number = debug_stack_frame[i].FrameNumber;
		stack_frame[i].frame_offset = debug_stack_frame[i].FrameOffset;
		stack_frame[i].func_table_entry = debug_stack_frame[i].FuncTableEntry;
		stack_frame[i].instruction_offset = debug_stack_frame[i].InstructionOffset;
		stack_frame[i].return_offset = debug_stack_frame[i].ReturnOffset;
		stack_frame[i].stack_offset = debug_stack_frame[i].StackOffset;
		stack_frame[i].bool_virtual = debug_stack_frame[i].Virtual;

		for (int j = 0; j < 4; ++j)
		{
			stack_frame[i].params[j] = debug_stack_frame[i].Params[j];
		}

		for (int j = 0; j < 6; ++j)
		{
			stack_frame[i].reserved[j] = debug_stack_frame[i].Reserved[j];
		}
	}

	free(debug_stack_frame);

	return true;
}

bool DbgEngSystem::StackTrace(xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	if (winapi_)
	{
		return winapi_->StackTrace(stack_frame, size_of_stack_frame, stack_count);
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	size_t cnt = size_of_stack_frame / sizeof(xdv::architecture::x86::frame::type);
	PDEBUG_STACK_FRAME debug_stack_frame = (PDEBUG_STACK_FRAME)malloc(sizeof(DEBUG_STACK_FRAME) * cnt);
	if (!debug_stack_frame)
	{
		return false;
	}
	memset(debug_stack_frame, 0, sizeof(DEBUG_STACK_FRAME) * cnt);

	if (debug_control->GetStackTrace(0, 0, 0, debug_stack_frame, (unsigned long)(sizeof(DEBUG_STACK_FRAME) * cnt), stack_count) != S_OK)
	{
		return false;
	}

	for (unsigned long i = 0; i < *stack_count; ++i)
	{
		stack_frame[i].frame_number = debug_stack_frame[i].FrameNumber;
		stack_frame[i].frame_offset = debug_stack_frame[i].FrameOffset;
		stack_frame[i].func_table_entry = debug_stack_frame[i].FuncTableEntry;
		stack_frame[i].instruction_offset = debug_stack_frame[i].InstructionOffset;
		stack_frame[i].return_offset = debug_stack_frame[i].ReturnOffset;
		stack_frame[i].stack_offset = debug_stack_frame[i].StackOffset;
		stack_frame[i].bool_virtual = debug_stack_frame[i].Virtual;

		for (int j = 0; j < 4; ++j)
		{
			stack_frame[i].params[j] = debug_stack_frame[i].Params[j];
		}

		for (int j = 0; j < 6; ++j)
		{
			stack_frame[i].reserved[j] = debug_stack_frame[i].Reserved[j];
		}
	}

	free(debug_stack_frame);

	return true;
}

std::string DbgEngSystem::Module(unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->Module(ptr);
	}

	IDebugAdvanced2 *debug_advanced2;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugAdvanced2), (void **)&debug_advanced2) != S_OK)
	{
		return "";
	}

	IMAGEHLP_MODULEW64 module_info = { 0, };
	if (debug_advanced2->GetSymbolInformation(DEBUG_SYMINFO_IMAGEHLP_MODULEW64, (unsigned long long)ptr, 0, &module_info, sizeof(module_info), nullptr, nullptr, 0, nullptr) != S_OK)
	{
		return "";
	}
	
	std::wstring ws = module_info.ImageName;
	return std::string(ws.begin(), ws.end());
}

unsigned long DbgEngSystem::Symbol(unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size)
{
	if (winapi_)
	{
		return winapi_->Symbol(ptr, disp, symbol_str, symbol_size);
	}

	if (!client_)
	{
		return false;
	}

	IDebugSymbols *debug_symbol;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSymbols), (void **)&debug_symbol) != S_OK)
	{
		return false;
	}

	unsigned long long offset = (unsigned long long)ptr;
	unsigned long size_of_name;
	if (debug_symbol->GetNameByOffset(offset, symbol_str, symbol_size, &size_of_name, disp) != S_OK)
	{
		return false;
	}

	return true;
}

unsigned long DbgEngSystem::Symbol(unsigned long long ptr, char *symbol_str, unsigned long symbol_size)
{
	if (winapi_)
	{
		return winapi_->Symbol(ptr, symbol_str, symbol_size);
	}

	if (!client_)
	{
		return false;
	}

	IDebugSymbols *debug_symbol;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSymbols), (void **)&debug_symbol) != S_OK)
	{
		return false;
	}

	char symbol_string[1024] = { 0, };
	unsigned long long disp = 0;
	unsigned long long offset = (unsigned long long)ptr;
	unsigned long size_of_name;
	if (debug_symbol->GetNameByOffset(offset, symbol_string, sizeof(symbol_string), &size_of_name, &disp) != S_OK)
	{
		return false;
	}

	if (disp)
	{
		sprintf_s(symbol_str, symbol_size, "%s+0x%I64x", symbol_string, disp);
	}
	else
	{
		sprintf_s(symbol_str, symbol_size, "%s", symbol_string);
	}

	return true;
}

unsigned long long DbgEngSystem::SymbolToPtr(char *symbol_str)
{
	if (winapi_)
	{
		return winapi_->SymbolToPtr(symbol_str);
	}

	if (!client_)
	{
		return 0;
	}

	IDebugSymbols *debug_symbol;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSymbols), (void **)&debug_symbol) != S_OK)
	{
		return 0;
	}
	
	unsigned long long ptr = 0;
	if (debug_symbol->GetOffsetByName(symbol_str, &ptr) != S_OK)
	{
		return 0;
	}

	return ptr;
}

unsigned long long DbgEngSystem::GetPebAddress()
{
	if (!client_)
	{
		return 0;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return 0;
	}

	unsigned long long peb = 0;
	if (system_object->GetCurrentProcessPeb(&peb) != S_OK)
	{
		return 0;
	}

	return peb;
}

unsigned long long DbgEngSystem::GetTebAddress()
{
	if (!client_)
	{
		return 0;
	}

	IDebugSystemObjects4 *system_object;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugSystemObjects4), (void **)&system_object) != S_OK)
	{
		return 0;
	}

	unsigned long long teb = 0;
	if (system_object->GetCurrentThreadTeb(&teb) != S_OK)
	{
		return 0;
	}

	return teb;
}

bool DbgEngSystem::StepInto(DebugCallbackT callback, void * cb_ctx)
{
	if (winapi_)
	{
		return winapi_->StepInto(callback, cb_ctx);
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	if (callback)
	{
		callback(DebugCallbackStatus::DBG_PRE_CALLBACK, cb_ctx);
	}

	RestoreAllBreakPoint();

	if (debug_control->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK)
	{
		return false;
	}

	XdvExceptionEvent();
	XdvWaitForReturnEvent();

	if (callback)
	{
		callback(DebugCallbackStatus::DBG_POST_CALLBACK, cb_ctx);
	}

	return true;
}

bool DbgEngSystem::StepOver(DebugCallbackT callback, void * cb_ctx)
{
	if (winapi_)
	{
		return winapi_->StepOver(callback, cb_ctx);
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	RestoreAllBreakPoint();

	if (callback)
	{
		callback(DebugCallbackStatus::DBG_PRE_CALLBACK, cb_ctx);
	}

	if (debug_control->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK)
	{
		return false;
	}

	if (debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)
	{
		return false;
	}

	if (callback)
	{
		callback(DebugCallbackStatus::DBG_POST_CALLBACK, cb_ctx);
	}

	return true;
}

bool DbgEngSystem::RunningProcess()
{
	if (winapi_)
	{
		return winapi_->RunningProcess();
	}

	if (attach_id_ == 0)
	{
		XdvResumeProcess(XdvGetParserHandle());
		return true;
	}

	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client_)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return false;
	}

	if (StepInto(nullptr, nullptr)) // hang, bug..
	{
		ReInstallAllBreakPoint();
	}

	if (debug_control->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK)
	{
		return false;
	}

	XdvExceptionEvent();

	return true;
}

std::vector<unsigned long long> DbgEngSystem::GetBreakPointList()
{
	std::vector<unsigned long long> v;
	if (winapi_)
	{
		v = winapi_->GetBreakPointList();
	}

	return v;
}

unsigned char * DbgEngSystem::GetBpBackupDump(unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->GetBpBackupDump(ptr);
	}

	std::map<unsigned long long, break_point_ptr>::iterator it = break_point_map_.find(ptr);
	if (it != break_point_map_.end())
	{
		return it->second->bytes;
	}

	return nullptr;
}

bool DbgEngSystem::SetBreakPoint(DebugBreakPointId id, unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->SetBreakPoint(id, ptr);
	}

	switch (id)
	{
	case DebugBreakPointId::SUSPEND_BREAK_POINT_ID:
		return this->InstallSuspendBreakPoint(ptr);

	case DebugBreakPointId::SOFTWARE_BREAK_POINT_ID:
		return this->InstallSoftwareBreakPoint(ptr);

	case DebugBreakPointId::HARDWARE_BREAK_POINT_ID:
		return this->InstallHardwareBreakPoint(ptr);
	}

	return false;
}

DebugBreakPointId DbgEngSystem::GetBreakPointId(unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->GetBreakPointId(ptr);
	}

	auto it = break_point_map_.find(ptr);
	if (it != break_point_map_.end())
	{
		return it->second->id;
	}

	return DebugBreakPointId::NO_BREAK_POINT_ID;
}

void DbgEngSystem::ReInstallBreakPoint(unsigned long long ptr)
{
	if (winapi_)
	{
		winapi_->ReInstallBreakPoint(ptr);
		return;
	}

	auto it = break_point_map_.find(ptr);
	if (it != break_point_map_.end())
	{
		DebugBreakPointId id = it->second->id;
		DeleteBreakPoint(ptr);
		SetBreakPoint(id, ptr);
	}
}

bool DbgEngSystem::RestoreBreakPoint(unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->RestoreBreakPoint(ptr);
		
	}

	auto it = break_point_map_.find(ptr);
	if (it != break_point_map_.end())
	{
		if (XdvWriteMemory(XdvGetParserHandle(), (void *)ptr, it->second->bytes, 16))
		{
			return true;
		}
	}

	return false;
}

bool DbgEngSystem::DeleteBreakPoint(unsigned long long ptr)
{
	if (winapi_)
	{
		return winapi_->DeleteBreakPoint(ptr);

	}

	if (RestoreBreakPoint(ptr))
	{		
		break_point_map_.erase(ptr);
		return true;
	}

	return false;
}

void DbgEngSystem::RestoreAllBreakPoint()
{
	if (winapi_)
	{
		winapi_->RestoreAllBreakPoint();
		return;
	}

	for (auto it : break_point_map_)
	{
		RestoreBreakPoint(it.first);
	}
}

void DbgEngSystem::ReInstallAllBreakPoint()
{
	if (winapi_)
	{
		winapi_->ReInstallAllBreakPoint();
		return;
	}

	for (auto it : break_point_map_)
	{
		SetBreakPoint(it.second->id, it.first);
	}
}

IDebugClient5 * DbgEngSystem::GetDebugClient()
{
	return client_;
}

std::map<unsigned long long, unsigned char *> DbgEngSystem::GetBreakPointMap()
{
	std::map<unsigned long long, unsigned char *> bpm;
	for (auto it : break_point_map_)
	{
		bpm.insert(std::pair<unsigned long long, unsigned char *>(it.first, it.second->bytes));
	}

	return bpm;
}

//
//
#ifdef DLL_VERSION
XENOM_ADD_INTERFACE()
{
	IObject * obj = __add_object(DbgEngSystem);
	if (obj)
	{
		return XdvGetHandleByObject(obj);
	}

	return 0;
}
#endif