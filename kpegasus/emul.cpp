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

#pragma comment(lib, "unicorn_static_x64.lib")

std::shared_ptr<engine::debugger> g_emulator;

static void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_READ_UNMAPPED)
	{
		emulation_debugger::page unknown_page;
		unsigned char *unknown_dump = g_emulator->load_page(address, &unknown_page.base, &unknown_page.size);
		std::shared_ptr<void> dump_closer(unknown_dump, free);

		if (unknown_dump)
		{
			uc_mem_map(uc, unknown_page.base, unknown_page.size, UC_PROT_ALL);
			uc_mem_write(uc, unknown_page.base, unknown_dump, unknown_page.size);
			return;
		}

		unsigned char dump[16] = { 0, };
		address += 0x1;

		uc_err err;
		if ((err = uc_mem_read(uc, address, dump, 16)) == 0)
			return;

		size_t resize = g_emulator->alignment((size_t)address, 0x1000);
		uc_mem_region *um = nullptr;
		uint32_t count = 0;

		if (uc_mem_regions(uc, &um, &count) != 0)
			return;

		uc_mem_region b;
		for (unsigned int i = 0; i < count; ++i)
		{
			if (um[i].end < resize && um[i + 1].begin >= resize)
			{
				b.begin = um[i].begin;
				b.end = um[i].end;
				break;
			}
		}

		unsigned long long base = b.end + 1;
		size_t size = resize - base;

		err = uc_mem_map(uc, base, size, UC_PROT_ALL);
	}
}

static void hook_fetch_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_FETCH_UNMAPPED)
	{
		emulation_debugger::page unknown_page;
		unsigned char *unknown_dump = g_emulator->load_page(address, &unknown_page.base, &unknown_page.size);
		std::shared_ptr<void> dump_closer(unknown_dump, free);

		if (unknown_dump)
		{
			uc_err err;
			if((err = uc_mem_map(uc, unknown_page.base, unknown_page.size, UC_PROT_ALL)) == 0)
			{
				uc_mem_write(uc, unknown_page.base, unknown_dump, unknown_page.size);
			}
		}
	}
}
///
///
///
EXT_CLASS_COMMAND(EmulationEngine, attach, "", "{;e,o;;;}")
{
	if (g_emulator)
	{
		detach();
		g_emulator.reset();
	}

	if (!engine::create<emulation_debugger>(g_emulator))
		return;

	if (g_emulator->attach())
		dprintf("attach process\n");
}

EXT_CLASS_COMMAND(EmulationEngine, detach, "", "{;e,o;;;}")
{
	if (!g_emulator)
		return;

	if (g_emulator->clear_ring3())
		dprintf("clear ring3 partition\n");
	else
		dprintf("clear fail..\n");

	g_emulator.reset();
}

EXT_CLASS_COMMAND(EmulationEngine, trace, "", "{bp;ed,o;bp;;}")
{
	bool strange = false;
	unsigned long long bp = GetArgU64("bp", FALSE);

	if(!g_emulator->is_64_cpu())
	{
		if (g_Ext->IsCurMachine64())
			g_Ext->ExecuteSilent("!wow64exts.sw");

		if (g_emulator->trace32(nullptr, bp, hook_unmap_memory, hook_fetch_memory, nullptr, nullptr))
		{
			if (g_emulator->is_64_cpu())
				dprintf("switch wow64cpu=>64bit\n");
		}
		else
			dprintf("break\n");
	}
	else
	{
		if (g_Ext->IsCurMachine32())
			g_Ext->ExecuteSilent("!wow64exts.sw");

		if (g_emulator->trace64(nullptr, bp, hook_unmap_memory, hook_fetch_memory, nullptr, nullptr))
		{
			if (g_emulator->is_64_cpu())
				dprintf("switch wow64cpu=>64bit\n");
		}
		else
			dprintf("break\n");
	}
}

EXT_CLASS_COMMAND(EmulationEngine, regs, "", "{;e,o;;;}")
{
	if (!g_emulator)
		return;
	
	g_emulator->current_regs();
}
