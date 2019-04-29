#include <dbgeng.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#include "dbgeng_exts.h"

//
bool InstallSuspendPoint(unsigned long long ptr)
{
	unsigned char lp[3] = { 0x90, 0xEB, 0xFD };
	if (XdvWriteMemory(XdvGetParserHandle(), (void *)ptr, lp, 3))
	{
		return true;
	}

	return false;
}

bool DbgEngSystem::InstallSuspendBreakPoint(unsigned long long ptr)
{
	break_point_ptr bp_ptr = new break_point;
	bp_ptr->id = DebugBreakPointId::SUSPEND_BREAK_POINT_ID;
	if (XdvReadMemory(XdvGetParserHandle(), ptr, bp_ptr->bytes, 16) == 0)
	{
		return false;
	}

	if (InstallSuspendPoint(ptr))
	{
		break_point_map_.insert(std::pair<unsigned long long, break_point_ptr>(ptr, bp_ptr));
		return true;
	}

	return false;
}

//
bool InstallSoftwarePoint(unsigned long long ptr)
{
	unsigned char lp[1] = { 0xcc };
	if (XdvWriteMemory(XdvGetParserHandle(), (void *)ptr, lp, 1))
	{
		return true;
	}

	return false;
}

bool DbgEngSystem::InstallSoftwareBreakPoint(unsigned long long ptr)
{
	break_point_ptr bp_ptr = new break_point;
	bp_ptr->id = DebugBreakPointId::SOFTWARE_BREAK_POINT_ID;
	if (XdvReadMemory(XdvGetParserHandle(), ptr, bp_ptr->bytes, 16) == 0)
	{
		return false;
	}

	if (InstallSoftwarePoint(ptr))
	{
		break_point_map_.insert(std::pair<unsigned long long, break_point_ptr>(ptr, bp_ptr));
		return true;
	}

	return false;
}

//
bool DbgEngSystem::InstallHardwareBreakPoint(unsigned long long ptr)
{
	break_point_ptr bp_ptr = new break_point;
	bp_ptr->id = DebugBreakPointId::HARDWARE_BREAK_POINT_ID;
	if (XdvReadMemory(XdvGetParserHandle(), ptr, bp_ptr->bytes, 16) == 0)
	{
		return false;
	}

	HANDLE thread_handle = OpenThread(MAXIMUM_ALLOWED, FALSE, this->ThreadId());
	if (!thread_handle)
	{
		return false;
	}
	std::shared_ptr<void> handle_closer(thread_handle, CloseHandle);

	CONTEXT ctx = { 0, };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	ctx.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
	if (::SetThreadContext(thread_handle, &ctx))
	{
		break_point_map_.insert(std::pair<unsigned long long, break_point_ptr>(ptr, bp_ptr));
		return true;
	}

	return false;
}
