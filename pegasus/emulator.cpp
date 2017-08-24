#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>

#include <engextcpp.hpp>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

#include <distorm/include/distorm.h>
#include <distorm/include/mnemonics.h>

#ifdef _WIN64
#pragma comment(lib, "unicorn_static_x64.lib")
#else
#pragma comment(lib, "unicorn_static.lib")
#endif

void __stdcall emulation_debugger::install()
{
	wmemset(ring0_path_, 0, MAX_PATH);
	wmemset(ring3_path_, 0, MAX_PATH);
	wmemset(log_path_, 0, MAX_PATH);

	GetCurrentDirectory(MAX_PATH, ring0_path_);
	StringCbCat(ring0_path_, MAX_PATH, L"\\ring0");
	CreateDirectory(ring0_path_, FALSE);

	StringCbCopy(log_path_, MAX_PATH, ring0_path_);

	StringCbCopy(ring3_path_, MAX_PATH, ring0_path_);
	StringCbCat(ring3_path_, MAX_PATH, L"\\ring3");
	CreateDirectory(ring3_path_, FALSE);
}

bool __stdcall emulation_debugger::setup()
{
	if (!windbg_linker_.get_context(&context_, sizeof(context_)))
		return false;
#ifdef _WIN64
	if(!write_binary(context_.Rip)) // code
		return false;

	if (!write_binary(context_.Rsp)) // stack
		return false;
#else
	if (!write_binary(context_.Eip)) // code
		return false;

	if (!write_binary(context_.Esp)) // stack
		return false;
#endif

	if (!write_binary(teb_address_))
		return false;

	gdt_base_ = 0xc0000000;
	if (!create_global_descriptor_table())
		return false;

	return true;
}

bool __stdcall emulation_debugger::load_gdt(void *engine)
{
	emulation_debugger::page gdt_page;
	unsigned char * gdt_dump = nullptr;

	gdt_dump = load_page(gdt_base_, &gdt_page.base, &gdt_page.size);
	if (!gdt_dump) return false;
	std::shared_ptr<void> gdt_dump_closer(gdt_dump, free);

	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write((uc_engine *)engine, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load(engine, gdt_page.base, 0x10000, gdt_dump, gdt_page.size))
		return false;

	return true;
}

bool __stdcall emulation_debugger::load_context(void *engine, unsigned long mode)
{
	uc_engine *uc = (uc_engine *)engine;

	if ((uc_mode)mode == UC_MODE_64)
	{
		if (!write_x64_cpu_context(uc))
			return false;
	}
	else
	{
		if (!write_x86_cpu_context(uc))
			return false;
	}

	return true;
}

bool __stdcall emulation_debugger::attach()
{
	bool is_32 = false;

	if (g_Ext->IsCurMachine32())
	{
		is_32 = true;
		g_Ext->ExecuteSilent("!wow64exts.sw");
	}
	else
		is_64_ = true;

	peb_address_ = windbg_linker_.get_peb_address();
	teb_address_ = windbg_linker_.get_teb_address();

	if (!peb_address_ || !teb_address_)
		return false;

	if (is_wow64cpu())
	{
		teb_64_address_ = teb_address_;
		NT_TIB64 tib_64;
		if (!windbg_linker_.read_memory(teb_64_address_, &tib_64, sizeof(tib_64)))
			return false;
		teb_address_ = tib_64.ExceptionList;

		peb_64_address_ = peb_address_;
		unsigned char teb32[1024];
		if (!windbg_linker_.read_memory(teb_address_, &teb32, sizeof(teb32)))
			return false;

		peb_address_ = *((unsigned long long *)&teb32[0x30]);
	}

	install();
	if(!setup())
		return false;

	if (is_32)
		g_Ext->ExecuteSilent("!wow64exts.sw");

	clear_and_print();

	return true;
}

bool __stdcall emulation_debugger::trace(void *engine, trace_item item)
{
	uc_engine *uc = (uc_engine *)engine;
	BYTE dump[1024];
	_DInst di;
	unsigned long long end_point = context_.Rip + 0x1000;
	unsigned long step = 1;

	if (!windbg_linker_.read_memory(context_.Rip, dump, 1024))
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (item.break_point)
	{
		end_point = item.break_point;
		step = 0;
	}

	//if (item.step_over)
	//{
	//	end_point = context_.Rip + di.size;
	//	step = 0;
	//}

	uc_err err = uc_emu_start(uc, context_.Rip, end_point, 0, step);
	if (err)
	{
		if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED)
		{
			err = uc_emu_start(uc, context_.Rip, end_point, 0, step);// dprintf("break::e::%d\n", err);
		}
	}

	backup_context_ = context_;

	if (is_64_)
	{
		if (!read_x64_cpu_context(uc))
			return false;
	}
	else
	{
		if (!read_x86_cpu_context(uc))
			return false;
	}

	if (err)
		return false;
	
	return true;
}

bool __stdcall emulation_debugger::trace(void *mem)
{
	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;
	uc_engine *uc = nullptr;
	trace_item *item = (trace_item *)mem;
	bool s = true;

	if (uc_open(UC_ARCH_X86, (uc_mode)item->mode, &uc) != 0)
		return false;
	std::shared_ptr<void> uc_closer(uc, uc_close);

	uc_hook_add(uc, &code_hook, UC_HOOK_CODE, item->code_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	if (!load_gdt(uc) || !load_context(uc, item->mode))
		return false;

	if (!trace(uc, *item))
	{
		mnemonic_switch_wow64cpu(uc);
		mnemonic_wow_ret(uc);
		s = false;
	}

	if (!backup(uc))
		return false;

	//log_print();
	clear_and_print();

	return s;
}
