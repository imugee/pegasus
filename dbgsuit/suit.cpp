#include <engextcpp.hpp>
#include <windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <engine.h>

#include <windbg_engine_linker.h>
#include <helper.h>

EXT_CLASS_COMMAND(WindbgEngine, suspend, "", "{p;ed,o;p;;}" )
{
	if(!g_Ext->IsLiveLocalUser())
		return;

	DLL_ARGS dll_args;
	unsigned long pid; 

	if (g_Ext->m_System->GetCurrentProcessSystemId(&pid) != S_OK)
		return;
	if (!g_Ext->HasArg("p"))
		return;

	GetCurrentDirectoryW(MAX_PATH, dll_args.dll_path);
	StringCbCat(dll_args.dll_path, MAX_PATH, L"\\test.bat");

	dll_args.break_point = GetArgU64("p", FALSE);

	module_load_information_type module_load_info;
	if (install(L"suspend.dll", pid, &module_load_info, dll_args))
	{
		dprintf("loader base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.loader_address, (unsigned long)module_load_info.size_of_loader);
		dprintf("module image base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.module_load_address, (unsigned long)module_load_info.size_of_module_image);

		ResumeThread(module_load_info.main_thread_handle);

		DWORD exit_code = 0;
		WaitForSingleObject(module_load_info.main_thread_handle, INFINITE);
		GetExitCodeThread(module_load_info.main_thread_handle, &exit_code);

		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.loader_address, module_load_info.size_of_loader, MEM_RELEASE);
		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.module_load_address, module_load_info.size_of_module_image, MEM_RELEASE);

		CloseHandle(module_load_info.main_thread_handle);
		CloseHandle(module_load_info.target_process_handle);

		g_Ext->ExecuteSilent("qd");
	}
	else
		dprintf("install fail\n");
}