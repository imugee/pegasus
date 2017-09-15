#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>

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

std::list<unsigned long long> g_trace_step_list;
std::shared_ptr<engine::debugger> g_emulator;
wchar_t g_log_path[MAX_PATH];

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	g_trace_step_list.push_back(address);

	g_emulator->mnemonic_mov_ss(uc, address);
	g_emulator->mnemonic_mov_gs(uc, address);
}

static void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_READ_UNMAPPED)
	{
		windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();
		emulation_debugger::page unknown_page;
		
		if (g_emulator->load_page(address))
		{
			windbg_linker->write_file_log(g_log_path, L"emul.log", L"data:: load existing memory %08x=>%08x-%08x\n", address, unknown_page.base, unknown_page.size);

			return;
		}
		else
		{
			MEMORY_BASIC_INFORMATION64 mbi;
			memset(&mbi, 0, sizeof(mbi));
			unsigned char *unknown_dump = nullptr;

			if (windbg_linker->virtual_query(address, &mbi) && address >= mbi.BaseAddress)
			{

				unknown_dump = (unsigned char *)malloc(mbi.RegionSize);
				if (unknown_dump && windbg_linker->read_memory(mbi.BaseAddress, unknown_dump, mbi.RegionSize))
				{
					if (uc_mem_map(uc, mbi.BaseAddress, mbi.RegionSize, UC_PROT_ALL) == 0)
					{
						uc_mem_write(uc, mbi.BaseAddress, unknown_dump, mbi.RegionSize);
						windbg_linker->write_file_log(g_log_path, L"emul.log", L"data:: load new memory %08x=>%08x-%08x\n", address, mbi.BaseAddress, mbi.RegionSize);
					}
					std::shared_ptr<void> dump_closer(unknown_dump, free);

					return;
				}
			}
		}

		unsigned char dump[16] = { 0, };

		uc_err err;
		if ((err = uc_mem_read(uc, address, dump, 16)) == 0)
			return;

		address += 0x1;
		size_t resize = g_emulator->alignment((size_t)address, 0x1000);
		uc_mem_region *um = nullptr;
		uint32_t count = 0;

		if (uc_mem_regions(uc, &um, &count) != 0)
			return;

		uc_mem_region b;
		bool find = false;
		unsigned int i = 0;
		for (i = 0; i < count; ++i)
		{
			if (um[i].end < resize && um[i + 1].begin >= resize)
			{
				b.begin = um[i].begin;
				b.end = um[i].end;
				find = true;
				break;
			}
		}

		if (!find)
			b.end = um[i].end;

		unsigned long long base = b.end + 1;
		size_t size = resize - base;

		err = uc_mem_map(uc, base, size, UC_PROT_ALL);
		if (err)
		{
			base = address - 0x500;
			base = g_emulator->alignment(base, 0x1000);
			unsigned long long end = g_emulator->alignment(address, 0x1000);
			size = end - base;

			err = uc_mem_map(uc, base, size, UC_PROT_ALL);

			if (err)
			{
				windbg_linker->write_file_log(g_log_path, L"emul.log", L"data::fail %d, %08x = >%08x %08x, %08x\n", err, address, base, size, resize);
			}
			else
			{
				windbg_linker->write_file_log(g_log_path, L"emul.log", L"data:: alloc memory %08x-%08x\n", base, end);
			}
		}
		else
		{
			windbg_linker->write_file_log(g_log_path, L"emul.log", L"data:: alloc memory %08x-%08x\n", base, base + size);
		}
	}
}

static void hook_fetch_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_FETCH_UNMAPPED)
	{
		emulation_debugger::page unknown_page;
		unsigned char *unknown_dump = nullptr;
		windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();

		if (g_emulator->load_page(address))
		{
			windbg_linker->write_file_log(g_log_path, L"emul.log", L"code:: load existing memory %08x=>%08x-%08x\n", address, unknown_page.base, unknown_page.size);
		}
		else
		{
			windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();
			MEMORY_BASIC_INFORMATION64 mbi;
			memset(&mbi, 0, sizeof(mbi));

			if (windbg_linker->virtual_query(address, &mbi) && address >= mbi.BaseAddress)
			{
				unknown_dump = (unsigned char *)malloc(mbi.RegionSize);
				if (unknown_dump && windbg_linker->read_memory(mbi.BaseAddress, unknown_dump, mbi.RegionSize))
				{
					uc_mem_map(uc, mbi.BaseAddress, mbi.RegionSize, UC_PROT_ALL);
					uc_mem_write(uc, mbi.BaseAddress, unknown_dump, mbi.RegionSize);

					std::shared_ptr<void> dump_closer(unknown_dump, free);
					windbg_linker->write_file_log(g_log_path, L"emul.log", L"code:: load new memory %08x=>%08x-%08x\n", address, mbi.BaseAddress, mbi.RegionSize);
				}
			}
		}
	}
}
///
///
///
EXT_CLASS_COMMAND(EmulationEngine, attach, "", "{p;s;p;.}")
{
	if (g_emulator)
	{
		g_trace_step_list.clear();
		g_emulator.reset();
	}

	if (!engine::create<emulation_debugger>(g_emulator))
		return;

	trace_item item;

	if (HasArg("p"))
	{
		StringCbCopyA(item.path, MAX_PATH, GetArgStr("p", FALSE));
	}
	else
		memset(item.path, 0, sizeof(item.path));

	if (!g_emulator->is_64_cpu())
	{
		item.mode = UC_MODE_32;
		item.code_callback = hook_code;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;
	}
	else
	{
		item.mode = UC_MODE_64;
		item.code_callback = hook_code;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;
	}

	if (g_emulator->attach(&item))
	{
		GetCurrentDirectory(MAX_PATH, g_log_path);
		windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();
		windbg_linker->write_file_log(g_log_path, L"emul.log", L"::::::: attach debuggee :::::::\n");

		g_emulator->log_print();

		g_Ext->DmlCmdExec("step into", "!trace");
		dprintf("   ");
		//g_Ext->DmlCmdExec("step over\n", "!trace -so");
		dprintf("\n");
	}
}

EXT_CLASS_COMMAND(EmulationEngine, detach, "; 0:000> !detach command detached the current target application to the emulator.", "{;e,o;;no arguments.}")
{
	if (g_emulator)
	{
		g_trace_step_list.clear();
		g_emulator.reset();
	}
}
///
///
///
#define PEGASUS_STEP_MODE

EXT_CLASS_COMMAND(EmulationEngine, trace, "; 0:000> !trace command executes a single instruction.", "{bp;ed,o;bp;break point.}")
{
	if (!g_emulator)
		return;

	bool strange = false;
	unsigned long long bp = GetArgU64("bp", FALSE);
	unsigned long long step = GetArgU64("step", FALSE);
	trace_item item;

	if (!g_emulator->is_64_cpu())
	{
		item.mode = UC_MODE_32;
		item.code_callback = hook_code;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;

		item.break_point = 0;
	}
	else
	{
		item.mode = UC_MODE_64;
		item.code_callback = hook_code;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;

		item.break_point = 0;
	}

	do
	{
		if (!g_emulator->trace_ex(&item))
		{
			if (item.mode == UC_MODE_32 && g_emulator->is_64_cpu())
			{
				item.mode = UC_MODE_64;
				g_emulator->switch_cpu(&item);
				g_Ext->ExecuteSilent("!wow64exts.sw");
			}
			else if (item.mode == UC_MODE_64 && !g_emulator->is_64_cpu())
			{
				item.mode = UC_MODE_32;
				g_emulator->switch_cpu(&item);
				g_Ext->ExecuteSilent("!wow64exts.sw");
			}
			else
				break;
		}
	} while (bp && g_emulator->get_current_thread_context().rip != bp);

	g_emulator->log_print();
	g_Ext->DmlCmdExec("step into", "!trace");
	dprintf("   ");
	//g_Ext->DmlCmdExec("step over\n", "!trace -so");
	dprintf("\n");
}
//
//
//
EXT_CLASS_COMMAND(EmulationEngine, steps, "; 0:000> !steps command displays the trace step.", "{;e,o;;no arguments.}")
{
	std::list<unsigned long long>::iterator it = g_trace_step_list.begin();
	int i = 0;

	for (it; it != g_trace_step_list.end(); ++it)
	{
		if (i == 12)
		{
			dprintf("\n");
			i = 0;
		}

		if (it == g_trace_step_list.begin())
			dprintf("  ");
		else
			dprintf("=>");

		dprintf("%08x ", *it);
		++i;
	}
	dprintf("\n");
}
//
//
//
bool __stdcall is_ascii(char c)
{
	if (c >= 0x41 && c <= 0x7e)
		return TRUE;

	return FALSE;
}

EXT_CLASS_COMMAND(EmulationEngine, dbvm, "; 0:000> !dbvm commands display the contents of memory in the given range.", "{a;ed,o;a;address}" "{l;ed,o;l;length}")
{
	if (!g_emulator)
		return;

	unsigned long long address = GetArgU64("a", FALSE);
	size_t size = GetArgU64("l", FALSE);
	unsigned char *dump = (unsigned char *)malloc(size);
	if (!dump)
		return;
	std::shared_ptr<void> dump_closer(dump, free);
	memset(dump, 0, size);

	if(!g_emulator->read(address, dump, &size))
		return;

	unsigned int i = 0, j = 0;
	for (i; i < size; ++i)
	{
		if (i == 0)
		{
			dprintf("%08x  ", address);
		}
		else if (i % 16 == 0)
		{
			/*-- ascii --*/
			for (j; j < i; ++j)
			{
				if (is_ascii(dump[j]))
					dprintf("%c", dump[j]);
				else
					dprintf(".");
			}

			/*-- next line --*/
			dprintf("\n");
			address += 16;
			dprintf("%08x  ", address);
		}

		dprintf("%02x ", dump[i]);
	}

	if (i % 16)
	{
		for (unsigned k = 0; k < i % 16; ++i)
			dprintf("   ");
	}

	for (j; j < i; ++j)
	{
		if (is_ascii(dump[j]))
			dprintf("%c", dump[j]);
		else
			dprintf(".");
	}
	dprintf("\n");
}

EXT_CLASS_COMMAND(EmulationEngine, ddvm, "", "{a;ed,o;a;;}" "{l;ed,o;l;;}")
{
	if (!g_emulator)
		return;

	unsigned long long address = GetArgU64("a", FALSE);
	size_t size = GetArgU64("l", FALSE);

	size *= 4;
	unsigned char *dump = (unsigned char *)malloc(size);
	if (!dump)
		return;
	std::shared_ptr<void> dump_closer(dump, free);
	memset(dump, 0, size);

	char buffer[256];
	unsigned long long displacement;

	if (!g_emulator->read(address, dump, &size))
		return;
	
	unsigned long *dd = (unsigned long *)dump;
	for (unsigned int i = 0; i < size / 4; ++i)
	{
		memset(buffer, 0, 256);
		buffer[0] = '!';
		GetSymbol(dd[i], buffer, &displacement);

		if(strlen(buffer))
			dprintf("%08x   %08x %s+0x%x\n", address, dd[i], buffer, displacement);
		else
			dprintf("%08x   %08x\n", address, dd[i]);

		address += 4;
	}
}

EXT_CLASS_COMMAND(EmulationEngine, reg, "; 0:000> !reg command displays current registers.", "{;e,o;;no arguments.}")
{
	if (!g_emulator)
		return;

	g_emulator->log_print();
}