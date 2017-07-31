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
	// unsigned long long pid = GetArgU64("pid", FALSE);
	std::shared_ptr<engine::linker> windbg_linker;
	if (!engine::create<windbg_engine_linker>(windbg_linker))
		return;

	windbg_process process_table[1024];
	size_t process_count = 0;
	windbg_linker->get_process_table(process_table, 1024, &process_count);

	for (size_t i = 0; i < process_count; ++i)
	{
		std::list<windbg_process::vad_node> vad_list = process_table[i].get_vad_list();
		std::list<windbg_process::vad_node>::iterator vad_node = vad_list.begin();

		dprintf("eprocess=%0*I64x pid=%d(0x%x)\n", 16, process_table[i].get_eprocess(), process_table[i].get_pid(), process_table[i].get_pid());
		for (vad_node; vad_node != vad_list.end(); ++vad_node)
		{
			dprintf("	%0*I64x - %0*I64x\n", 16, vad_node->start, 16, vad_node->end);
		}
	}
}
