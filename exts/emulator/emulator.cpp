#include "emulator.h"

//
Emulator::Emulator()
	: uc_(nullptr), syscall_rip_(0)
{
	debugger_ = (IDebugger *)XdvGetObjectByString("Windows Debugger");
	if (debugger_)
	{
		if (debugger_->ObjectType() != xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT)
		{
			debugger_ = nullptr;
		}
	}
}

Emulator::~Emulator()
{
}

xdv::object::id Emulator::ObjectType()
{
	return xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT;
}

std::string Emulator::ObjectString()
{
	return " Emulator, [DEBUGGER][EMULATOR][MDMP][USERDUMP][USERDU64]";
}

void Emulator::SetModuleName(std::string module)
{
}

std::string Emulator::ModuleName()
{
	return "";
}

//
//
std::map<unsigned long, std::string> Emulator::ProcessList()
{
	std::map<unsigned long, std::string> pl;
	if (debugger_)
	{
		pl = debugger_->ProcessList();
	}
	return pl;
}

unsigned long Emulator::WaitForProcess(std::string process_name)
{
	unsigned long pid = 0;
	if (debugger_)
	{
		pid = debugger_->WaitForProcess(process_name);
	}

	return pid;
}

bool Emulator::Attach(unsigned long pid)
{
	if (!AttachEmulator())
	{
		return false;
	}

	return true;
}

bool Emulator::Open(unsigned long pid)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->Open(pid);
		if (result)
		{
			if (!AttachEmulator())
			{
				return false;
			}
		}
	}

	return result;
}

bool Emulator::Open(char * path)
{
	bool result = false;
	if (debugger_)
	{
		IParser * parser = (IParser *)debugger_;
		result = parser->Open(path);
		if (result)
		{
			if (!AttachEmulator())
			{
				return false;
			}
		}
	}

	return result;
}

bool Emulator::Update()
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->Update();
		if (result)
		{
			if (uc_)
			{
				DetachEmulator();
			}

			result = AttachEmulator();
		}
	}

	return result;
}

unsigned long Emulator::ProcessId()
{
	unsigned long pid = 0;
	if (debugger_)
	{
		pid = debugger_->ProcessId();
	}

	return pid;
}

unsigned long long Emulator::Read(unsigned long long ptr, unsigned char *out_memory, unsigned long read_size)
{
	unsigned long long result = 0;
	if (debugger_)
	{
		result = debugger_->Read(ptr, out_memory, read_size);
	}

	return result;
}

unsigned long long Emulator::Write(void * ptr, unsigned char *input_memory, unsigned long write_size)
{
	unsigned long long result = 0;
	if (debugger_)
	{
		result = debugger_->Write(ptr, input_memory, write_size);
	}

	return result;
}

bool Emulator::Query(unsigned long long ptr, xdv::memory::type *memory_type)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->Query(ptr, memory_type);
	}

	return result;
}

void * Emulator::Alloc(void *ptr, unsigned long size, unsigned long allocation_type, unsigned long protect_type)
{
	return nullptr;
}

bool Emulator::Select(unsigned long tid)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->Select(tid);
	}

	return result;
}

void Emulator::Threads(std::map<unsigned long, unsigned long long> &thread_info_map)
{
	if (debugger_)
	{
		debugger_->Threads(thread_info_map);
	}
}

bool Emulator::GetThreadContext(xdv::architecture::x86::context::type *context)
{
	*context = context_;

	return true;
}

bool Emulator::SetThreadContext(xdv::architecture::x86::context::type *context)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->SetThreadContext(context);
	}

	return result;
}

bool Emulator::SuspendThread(unsigned long tid)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->SuspendThread(tid);
	}

	return result;
}

bool Emulator::ResumeThread(unsigned long tid)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->ResumeThread(tid);
	}

	return result;
}

bool Emulator::StackTrace(xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->StackTrace(stack_frame, size_of_stack_frame, stack_count);
	}

	return result;
}

bool Emulator::StackTraceEx(unsigned long long bp, unsigned long long ip, unsigned long long sp, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->StackTraceEx(bp, ip, sp, stack_frame, size_of_stack_frame, stack_count);
	}

	return result;
}

std::string Emulator::Module(unsigned long long ptr)
{
	if (debugger_)
	{
		return debugger_->Module(ptr);
	}

	return "";
}

unsigned long Emulator::Symbol(unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size)
{
	unsigned long result = 0;
	if (debugger_)
	{
		result = debugger_->Symbol(ptr, disp, symbol_str, symbol_size);
	}

	return result;
}

unsigned long Emulator::Symbol(unsigned long long ptr, char *symbol_str, unsigned long symbol_size)
{
	unsigned long result = 0;
	if (debugger_)
	{
		result = debugger_->Symbol(ptr, symbol_str, symbol_size);
	}

	return result;
}

unsigned long long Emulator::SymbolToPtr(char *symbol_str)
{
	unsigned long long result = 0;
	if (debugger_)
	{
		result = debugger_->SymbolToPtr(symbol_str);
	}

	return result;
}

unsigned long long Emulator::GetPebAddress()
{
	unsigned long long result = 0;
	if (debugger_)
	{
		result = debugger_->GetPebAddress();
	}

	return result;
}

unsigned long long Emulator::GetTebAddress()
{
	unsigned long long result = 0;
	if (debugger_)
	{
		result = debugger_->GetTebAddress();
	}

	return result;
}

unsigned char * Emulator::GetBpBackupDump(unsigned long long ptr)
{
	unsigned char * result = nullptr;
	if (debugger_)
	{
		result = debugger_->GetBpBackupDump(ptr);
	}

	return result;
}

bool Emulator::SetBreakPoint(DebugBreakPointId id, unsigned long long ptr)
{
	bool result = false;
	//if (debugger_)
	//{
	//	result = debugger_->SetBreakPoint(id, ptr);
	//}

	return result;
}

DebugBreakPointId Emulator::GetBreakPointId(unsigned long long ptr)
{
	return DebugBreakPointId::NO_BREAK_POINT_ID;
}

bool Emulator::RestoreBreakPoint(unsigned long long ptr)
{
	bool result = false;
	if (debugger_)
	{
		result = debugger_->RestoreBreakPoint(ptr);
	}

	return result;
}

bool Emulator::StepInto(DebugCallbackT callback, void * cb_ctx)
{
	if (!Trace(TraceId::EMULATOR_TRACE_STEP_INTO))
	{
		return false;
	}

	return true;
}

bool Emulator::StepOver(DebugCallbackT callback, void * cb_ctx)
{
	if (!Trace(TraceId::EMULATOR_TRACE_STEP_OVER))
	{
		return false;
	}

	return true;
}

bool Emulator::RunningProcess()
{
	return false;
}

bool Emulator::DeleteBreakPoint(unsigned long long ptr)
{
	return false;
}

void Emulator::RestoreAllBreakPoint()
{
}

void Emulator::ReInstallBreakPoint(unsigned long long ptr)
{
}

void Emulator::ReInstallAllBreakPoint()
{
}

std::vector<unsigned long long> Emulator::GetBreakPointList()
{
	std::vector<unsigned long long> v;
	if (debugger_)
	{
		v = debugger_->GetBreakPointList();
	}

	return v;
}

#if 0
XENOM_ADD_INTERFACE()
{
	IObject * obj = __add_object(Emulator);
	if (obj)
	{
		return XdvGetHandleByObject(obj);
	}

	return 0;
}
#endif
