#include <windows.h>
#include <dbgeng.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#include "dbgeng_exts.h"

#pragma comment(lib, "dbgeng.lib")
#pragma comment(lib, "corexts.lib")

void DebugMonitor(void * ctx)
{
	DbgEngSystem * des = (DbgEngSystem *)ctx;
	if (!des)
	{
		return;
	}

	IDebugClient5 * client = des->GetDebugClient();
	IDebugControl3 *debug_control;
	if (((IDebugClient5 *)client)->QueryInterface(__uuidof(IDebugControl3), (void **)&debug_control) != S_OK)
	{
		return;
	}

	do
	{
		XdvWaitForExceptionEvent();

		unsigned long status = 0;
		if (debug_control->GetExecutionStatus(&status) != S_OK)
		{
			continue;
		}

		if (status == DEBUG_STATUS_GO)
		{
		//	des->RestoreAllBreakPoint();
			debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
			XdvSetDebugEvent();

		//	des->ReInstallAllBreakPoint();
		}
		else if (status == DEBUG_STATUS_STEP_INTO)
		{
			debug_control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
			XdvSetDebugEvent();
			XdvReturnEvent();
		}
	} while (1);
}