#include <windows.h>
#include <ntverp.h>
#include <WDBGEXTS.H>
#include <dbgeng.h>

EXT_API_VERSION			ApiVersion = { (VER_PRODUCTVERSION_W >> 8), (VER_PRODUCTVERSION_W & 0xff), EXT_API_VERSION_NUMBER64, 0 };
WINDBG_EXTENSION_APIS	ExtensionApis;
ULONG					SavedMajorVersion;
ULONG					SavedMinorVersion;

extern "C"
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_PROCESS_ATTACH:
		break;
	}
	return TRUE;
}

extern "C"
VOID WINAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT MajorVersion, USHORT MinorVersion)
{
	ExtensionApis = *lpExtensionApis;
	SavedMajorVersion = MajorVersion;
	SavedMinorVersion = MinorVersion;
}

extern "C"
LPEXT_API_VERSION WINAPI ExtensionApiVersion()
{
	return &ApiVersion;
}

extern "C"
VOID WINAPI CheckVersion() {}
