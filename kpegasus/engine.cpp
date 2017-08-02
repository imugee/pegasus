#include <engextcpp.hpp>
#include <engine.h>

EXT_DECLARE_GLOBALS();

Extension::Extension()
{
}

HRESULT	Extension::Initialize(void)
{
	PDEBUG_CLIENT debug_client;
	PDEBUG_CONTROL debug_control;

	DebugCreate(__uuidof(IDebugClient), (void **)&debug_client);
	debug_client->QueryInterface(__uuidof(IDebugControl), (void **)&debug_control);
	ExtensionApis.nSize = sizeof(ExtensionApis);
	debug_control->GetWindbgExtensionApis64(&ExtensionApis);

	dprintf("..\n");

	return S_OK;
}
