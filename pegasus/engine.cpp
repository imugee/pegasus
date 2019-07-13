#define _CRT_SECURE_NO_WARNINGS

#include <xdv_sdk.h>
#include <x86_arch_exts.h>
#include <x64_arch_exts.h>
#include <emulator.h>
#include <dbgeng_exts.h>

#pragma comment(lib, "corexts.lib")
#pragma comment(lib, "x64_arch_exts.lib")
#pragma comment(lib, "x86_arch_exts.lib")
#pragma comment(lib, "dbgeng_exts.lib")
#pragma comment(lib, "emulator.lib")

#include <engextcpp.hpp>
#include <engine.h>

#pragma comment(lib, "dbgeng.lib")

WindbgEngine g_windbg_engine;
ExtExtension* g_ExtInstancePtr = &g_windbg_engine;

WindbgEngine::WindbgEngine() {}

HRESULT WindbgEngine::Initialize()
{
	PDEBUG_CLIENT debug_client;
	PDEBUG_CONTROL debug_control;

	DebugCreate(__uuidof(IDebugClient), (void **)&debug_client);
	debug_client->QueryInterface(__uuidof(IDebugControl), (void **)&debug_control);
	ExtensionApis.nSize = sizeof(ExtensionApis);
	debug_control->GetWindbgExtensionApis64(&ExtensionApis);

	dprintf(" *****************************************************************************\n");
	dprintf(" *                                                                           *\n");
	dprintf(" *         PEGASUS - reverse engineering extension plugin for windbg         *\n");
	dprintf(" *                                                                           *\n");
	dprintf(" *****************************************************************************\n");

	IObject * arch = __add_object(x86Architecture);
	if (arch)
	{
		XdvSetArchitectureHandle(arch);
	}
	__add_object(x64Architecture);
	__add_object(DbgEngSystem);

	IObject * emulator = __add_object(Emulator);
	if (emulator)
	{
		XdvSetParserHandle(emulator);
	}
	return S_OK;
}

