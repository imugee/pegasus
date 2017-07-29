#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>

class EXT_CLASS : public ExtExtension
{
public:
	EXT_COMMAND_METHOD(kaddress);
};

// EXT_DECLARE_GLOBALS must be used to instantiate
// the framework's assumed globals.
EXT_DECLARE_GLOBALS();

EXT_COMMAND(kaddress,
	"",
	"{pid;ed,o;pid;;}")
{
	std::shared_ptr<engine::linker> windbg_linker;
	if (!engine::create<windbg_engine_linker>(windbg_linker))
		return;

	if (g_Ext->IsKernelMode())
	{
		unsigned long long pid = GetArgU64("pid", FALSE);
		windbg_linker->select_process(pid);
	}

	//if (windbg_linker->virtual_query(0, nullptr, 0))
	//	;
}