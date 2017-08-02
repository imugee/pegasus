#include <engextcpp.hpp>
#include <engine.h>
///
///
///
WindbgEngine g_windbg_engine;
ExtExtension* g_ExtInstancePtr = &g_windbg_engine;

WindbgEngine::WindbgEngine()
{}

HRESULT WindbgEngine::Initialize()
{
	PDEBUG_CLIENT debug_client;
	PDEBUG_CONTROL debug_control;

	DebugCreate(__uuidof(IDebugClient), (void **)&debug_client);
	debug_client->QueryInterface(__uuidof(IDebugControl), (void **)&debug_control);
	ExtensionApis.nSize = sizeof(ExtensionApis);
	debug_control->GetWindbgExtensionApis64(&ExtensionApis);

	dprintf("test...\n");

	return S_OK;
}
