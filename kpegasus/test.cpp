#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <engine.h>

#include <windbg_engine_linker.h>
#include <emulator.h>

void __stdcall print_vad(windbg_process process)
{
	std::list<windbg_process::vad_node> vad_list = process.get_vad_list();
	std::list<windbg_process::vad_node>::iterator vad_node = vad_list.begin();

	for (vad_node; vad_node != vad_list.end(); ++vad_node)
	{
		dprintf("	%0*I64x - %0*I64x\n", 16, vad_node->start, 16, vad_node->end);
	}
}

void __stdcall print_thread(windbg_process process)
{
	std::list<windbg_thread> thread_list = process.get_thread_list();
	std::list<windbg_thread>::iterator thread_node = thread_list.begin();

	for (thread_node; thread_node != thread_list.end(); ++thread_node)
	{
		dprintf("	nt!_ETHREAD=%0*I64x tid=%d(0x%x)\n", 16, thread_node->get_ethread(), thread_node->get_tid(), thread_node->get_tid());
	}
}
///
///
///
EXT_CLASS_COMMAND(WindbgEngine, test, "", "{pid;ed,o;pid;;}")
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

		dprintf("nt!_EPROCESS=%0*I64x pid=%d(0x%x)\n", 16, process_table[i].get_eprocess(), process_table[i].get_pid(), process_table[i].get_pid());
		print_thread(process_table[i]);
		print_vad(process_table[i]);
	}
	else
	{
		for (size_t i = 0; i < process_count; ++i)
		{
			dprintf("nt!_EPROCESS=%0*I64x pid=%d(0x%x)\n", 16, process_table[i].get_eprocess(), process_table[i].get_pid(), process_table[i].get_pid());

			print_thread(process_table[i]);
			print_vad(process_table[i]);
			dprintf("\n");
		}
	}
	WindbgEngine::test2();
}
///
///
///
std::shared_ptr<engine::debugger> g_emulator;

EXT_CLASS_COMMAND(WindbgEngine, test2, "", "{pid;ed,o;pid;;}")
{
	engine::create<emulation_debugger>(g_emulator);
	dprintf("test2!!\n");
}

//EXTERN_C HRESULT CALLBACK test2(PDEBUG_CLIENT Client, PCSTR Args);
//ExtCommandDesc g_test2_desc("test2", (ExtCommandMethod)&WindbgEngine::test2, "", "{pid;ed,o;pid;;}");
//HRESULT CALLBACK test2(PDEBUG_CLIENT Client, PCSTR Args)
//{
//	if (!g_Ext.IsSet())
//		return E_UNEXPECTED;
//
//	return g_Ext->CallCommand(&g_test2_desc, Client, Args);
//}
//
//void WindbgEngine::test2()
//{
//	dprintf("test..\n");
//}
