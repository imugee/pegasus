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
EXT_DECLARE_GLOBALS();

EXT_COMMAND(kaddress,
	"",
	"{pid;ed,o;pid;;}")
{
	unsigned long long pid = GetArgU64("pid", FALSE);
	std::shared_ptr<engine::linker> windbg_linker;
	if (!engine::create<windbg_engine_linker>(windbg_linker))
		return;

	windbg_process process_table[1024];
	size_t process_count = 0;
	windbg_linker->get_process_table(process_table, 1024, &process_count);

	if (pid)
	{
		size_t i = 0;
		for (i; i < process_count; ++i)
		{
			if (process_table[i].get_pid() == pid)
				break;
		}

		print_vad(process_table[i]);
	}
	else
	{
		for (size_t i = 0; i < process_count; ++i)
			print_vad(process_table[i]);
	}
}
