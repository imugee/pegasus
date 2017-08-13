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

std::shared_ptr<engine::debugger> g_emulator;

static void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_READ_UNMAPPED)
	{
		emulation_debugger::page unknown_page;
		unsigned char *unknown_dump = g_emulator->load_page(address, &unknown_page.base, &unknown_page.size);

		if (unknown_dump)
		{
			if (uc_mem_map(uc, unknown_page.base, unknown_page.size, UC_PROT_ALL) == 0)
			{
				uc_mem_write(uc, unknown_page.base, unknown_dump, unknown_page.size);
				dprintf("data:: load existing memory\n");
			}

			std::shared_ptr<void> dump_closer(unknown_dump, free);
			return;
		}
		else
		{
			windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();
			MEMORY_BASIC_INFORMATION64 mbi;

			if (windbg_linker->virtual_query(address, &mbi) && address >= mbi.BaseAddress)
			{
				unknown_dump = (unsigned char *)malloc(mbi.RegionSize);
				if (unknown_dump && windbg_linker->read_memory(mbi.BaseAddress, unknown_dump, mbi.RegionSize))
				{
					if (uc_mem_map(uc, mbi.BaseAddress, mbi.RegionSize, UC_PROT_ALL) == 0)
					{
						uc_mem_write(uc, mbi.BaseAddress, unknown_dump, mbi.RegionSize);
						dprintf("data:: load new memory\n");
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

			if(err)
				dprintf("data:: fail %d, %08x=>%08x %08x, %08x\n", err, address, base, size, resize);
			else
				dprintf("data:: alloc memory %08x-%08x\n", base, end);
		}
		else
			dprintf("data:: alloc memory %08x-%08x\n", base, base + size);
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
				dprintf("code:: load existing memory\n");
			}
		}
		else
		{
			windbg_engine_linker *windbg_linker = (windbg_engine_linker *)g_emulator->get_windbg_linker();
			MEMORY_BASIC_INFORMATION64 mbi;

			if (windbg_linker->virtual_query(address, &mbi) && address >= mbi.BaseAddress)
			{
				unknown_dump = (unsigned char *)malloc(mbi.RegionSize);
				if (unknown_dump && windbg_linker->read_memory(mbi.BaseAddress, unknown_dump, mbi.RegionSize))
				{
					uc_mem_map(uc, mbi.BaseAddress, mbi.RegionSize, UC_PROT_ALL);
					uc_mem_write(uc, mbi.BaseAddress, unknown_dump, mbi.RegionSize);

					std::shared_ptr<void> dump_closer(unknown_dump, free);
					dprintf("code:: load new memory\n");
				}
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
		g_emulator.reset();
	}

	if (!engine::create<emulation_debugger>(g_emulator))
		return;

	if (g_emulator->attach())
		dprintf("attach process\n");
}

EXT_CLASS_COMMAND(EmulationEngine, trace, "", "{bp;ed,o;bp;;}")
{
	bool strange = false;
	unsigned long long bp = GetArgU64("bp", FALSE);

	if (!g_emulator->is_64_cpu())
	{
		trace_item item;
		item.mode = UC_MODE_32;
		item.code_callback = nullptr;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;
		item.break_point = bp;

		g_emulator->trace(&item);
	}
	else
	{
		trace_item item;
		item.mode = UC_MODE_64;
		item.code_callback = nullptr;
		item.unmap_callback = hook_unmap_memory;
		item.fetch_callback = hook_fetch_memory;
		item.break_point = bp;

		g_emulator->trace(&item);
	}
}
