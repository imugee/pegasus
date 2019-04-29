#include "xdv_sdk.h"

std::map<unsigned long, std::string> XdvProcessList(xdv_handle ih)
{
	std::map<unsigned long, std::string> ret_map;
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return ret_map;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return ret_map;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->ProcessList();
}

unsigned long XdvWaitForProcess(xdv_handle ih, std::string process_name)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return 0;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->WaitForProcess(process_name);
}

bool XdvAttachProcess(xdv_handle ih, unsigned long pid)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return 0;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->Attach(pid);
}

bool XdvOpenProcess(xdv_handle ih, unsigned long pid)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return 0;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->Open(pid);
}

bool XdvOpenFile(xdv_handle ih, char *path)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IParser *parser = (IParser*)object;
	return parser->Open(path);
}

bool XdvUpdateDebuggee(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->Update();
}

unsigned long XdvProcessId(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return 0;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger*)object;
	return debugger->ProcessId();
}

unsigned long long XdvReadMemory(xdv_handle ih, unsigned long long ptr, unsigned char *out_memory, unsigned long read_size)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IParser *parser = (IParser*)object;
	return parser->Read(ptr, out_memory, read_size);
}

unsigned long long XdvWriteMemory(xdv_handle ih, void * ptr, unsigned char *input_memory, unsigned long write_size)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IParser *parser = (IParser*)object;
	return parser->Write(ptr, input_memory, write_size);
}

bool XdvQueryMemory(xdv_handle ih, unsigned long long ptr, xdv::memory::type *memory_type)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT
		|| object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IParser *parser = (IParser*)object;
	return parser->Query(ptr, memory_type);
}

std::string XdvGetModuleName(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->Module(ptr);
}

bool XdvGetSymbolString(xdv_handle ih, unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	unsigned long r = debugger->Symbol(ptr, disp, symbol_str, symbol_size);
	if (r)
	{
		return true;
	}

	return false;
}

bool XdvGetSymbolString(xdv_handle ih, unsigned long long ptr, char *symbol_str, unsigned long symbol_size)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	unsigned long r = debugger->Symbol(ptr, symbol_str, symbol_size);
	if (r)
	{
		return true;
	}

	return false;
}

unsigned long long XdvGetSymbolPointer(xdv_handle ih, char *symbol_str)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->SymbolToPtr(symbol_str);
}

bool XdvIsAscii(unsigned char *data, size_t max_len)
{
	size_t len = 0;
	for (char *p = (char *)data; *p; ++len, ++p)
	{
		if (len >= max_len)
			break;
	}
	if (len < 2 || len + 1 >= max_len)
	{
		return false;
	}
	for (size_t i = 0; i < len; ++i)
	{
		if (!isprint(data[i]) && !isspace(data[i]))
		{
			return false;
		}
	}
	return true;
}

bool XdvIsUnicode(unsigned char *data, size_t max_len)
{
	size_t len = 0;
	for (wchar_t *p = (wchar_t *)data; *p; ++len, ++p)
	{
		if (len >= max_len)
			break;
	}
	if (len < 2 || len + 1 >= max_len)
	{
		return false;
	}
	for (size_t i = 0; i < len * 2; i += 2)
	{
		if (data[i + 1])
		{
			return false;
		}
		if (!isprint(data[i]) && !isspace(data[i]))
		{
			return false;
		}
	}

	return true;
}

bool XdvIsAscii(unsigned char *p, size_t l, std::string &ascii)
{
	if (!XdvIsAscii(p, l))
	{
		return false;
	}

	for (size_t i = 0; i < strlen((char *)p); ++i)
	{
		if (isprint(p[i]))
		{
			ascii += p[i];
		}
	}

	return true;
}

bool XdvIsUnicode(unsigned char *p, size_t l, std::string &ascii)
{
	if (!XdvIsUnicode(p, l))
	{
		return false;
	}

	for (size_t i = 0; i < wcslen((wchar_t *)p) * 2; ++i)
	{
		if (isprint(p[i]))
		{
			ascii += p[i];
		}
	}

	return true;
}

bool XdvIsJumpCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump, bool *jxx)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->IsJumpCode(ptr, dump, jxx);
}

bool XdvIsCallCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->IsCallCode(ptr, dump);
}

bool XdvIsRetCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->IsRetCode(ptr, dump);
}

bool XdvIsReadableCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->IsReadableCode(ptr, dump);
}

bool XdvIsInterruptCode(xdv_handle ah, unsigned long long ptr, unsigned char *dump)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->IsInterruptCode(ptr, dump);
}

bool XdvGetThreadContext(xdv_handle ih, xdv::architecture::x86::context::type *context)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->GetThreadContext(context);
}

bool XdvSetThreadContext(xdv_handle ih, xdv::architecture::x86::context::type *context)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->SetThreadContext(context);
}

bool XdvStackTrace(xdv_handle ih, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->StackTrace(stack_frame, size_of_stack_frame, stack_count);
}

bool XdvStackTraceEx(xdv_handle ih, unsigned long long bp, unsigned long long sp, unsigned long long ip, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->StackTraceEx(bp, sp, ip, stack_frame, size_of_stack_frame, stack_count);
}

bool XdvSelectThread(xdv_handle ih, unsigned long tid)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->Select(tid);
}

void XdvThreads(xdv_handle ih, std::map<unsigned long, unsigned long long> &thread_info_map)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->Threads(thread_info_map);
}

bool XdvSuspendThread(xdv_handle ih, unsigned long tid)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->SuspendThread(tid);
}

void XdvSuspendProcess(xdv_handle ih)
{
	std::map<unsigned long, unsigned long long> thread_map;
	XdvThreads(ih, thread_map);

	for (auto it : thread_map)
	{
		XdvSuspendThread(ih, it.first);
	}
}

bool XdvResumeThread(xdv_handle ih, unsigned long tid)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	debugger->ResumeThread(tid);
	return debugger->ResumeThread(tid);
}

void XdvResumeProcess(xdv_handle ih)
{
	std::map<unsigned long, unsigned long long> thread_map;
	XdvThreads(ih, thread_map);

	for (auto it : thread_map)
	{
		XdvResumeThread(ih, it.first);
	}
}

unsigned long long XdvGetPebAddress(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->GetPebAddress();
}

unsigned long long XdvGetTebAddress(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->GetTebAddress();
}

bool XdvStepInto(xdv_handle ih, DebugCallbackT callback, void * cb_ctx)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->StepInto(callback, cb_ctx);
}

bool XdvStepOver(xdv_handle ih, DebugCallbackT callback, void * cb_ctx)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->StepOver(callback, cb_ctx);
}

bool XdvRunningProcess(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return false;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return 0;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->RunningProcess();
}

unsigned char * XdvGetBpBackupDump(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return nullptr;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return nullptr;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->GetBpBackupDump(ptr);
}

bool XdvSetBreakPoint(xdv_handle ih, DebugBreakPointId id, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return nullptr;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return nullptr;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->SetBreakPoint(id, ptr);
}

DebugBreakPointId XdvGetBreakPointId(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return DebugBreakPointId::NO_BREAK_POINT_ID;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return DebugBreakPointId::NO_BREAK_POINT_ID;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->GetBreakPointId(ptr);
}

bool XdvRestoreBreakPoint(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return nullptr;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return nullptr;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->RestoreBreakPoint(ptr);
}

void XdvReInstallBreakPoint(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return;
	}

	IDebugger *debugger = (IDebugger *)object;
	debugger->ReInstallBreakPoint(ptr);
}

bool XdvDeleteBreakPoint(xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return nullptr;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return nullptr;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->DeleteBreakPoint(ptr);
}

void XdvRestoreAllBreakPoint(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->RestoreAllBreakPoint();
}

void XdvReInstallAllBreakPoint(xdv_handle ih)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ih];
	if (!object)
	{
		return;
	}

	if (!(object->ObjectType() == xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT))
	{
		return;
	}

	IDebugger *debugger = (IDebugger *)object;
	return debugger->ReInstallAllBreakPoint();
}
