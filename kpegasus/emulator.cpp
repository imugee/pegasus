#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>

#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

#pragma comment(lib, "unicorn_static_x64.lib")

emulation_debugger::emulation_debugger()
{
}

void __stdcall emulation_debugger::install()
{
	wmemset(ring0_path_, 0, MAX_PATH);
	wmemset(ring3_path_, 0, MAX_PATH);

	GetCurrentDirectory(MAX_PATH, ring0_path_);
	StringCbCat(ring0_path_, MAX_PATH, L"\\ring0");
	CreateDirectory(ring0_path_, FALSE);

	StringCbCopy(ring3_path_, MAX_PATH, ring0_path_);
	StringCbCat(ring3_path_, MAX_PATH, L"\\ring3");
	CreateDirectory(ring3_path_, FALSE);
}

bool __stdcall emulation_debugger::capture()
{
	uint64_t address = 0;
	MEMORY_BASIC_INFORMATION64 mbi = { 0, };

	install();

	wchar_t name[MAX_PATH];

	while (windbg_linker_.virtual_query(address, &mbi))
	{
		if (mbi.BaseAddress > address)
		{
			address = mbi.BaseAddress;
			continue;
		}

		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS))
		{
			unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);

			if (!dump)
				return false;

			memset(dump, 0, (size_t)mbi.RegionSize);
			std::shared_ptr<void> dump_closer(dump, free);

			if (!windbg_linker_.read_memory(mbi.BaseAddress, dump, (size_t)mbi.RegionSize))
				return false;

			wmemset(name, 0, MAX_PATH);
			if (!_ui64tow(mbi.BaseAddress, name, 16))
				return false;

			if (!windbg_linker_.write_binary(ring3_path_, name, dump, (size_t)mbi.RegionSize))
				return false;
		}

		address += mbi.RegionSize;
		memset(&mbi, 0, sizeof(mbi));
	}

	CONTEXT context;
	memset(&context, 0, sizeof(context));

	if (!windbg_linker_.get_context(&context, sizeof(context)))
		return false;

	if (!windbg_linker_.write_binary(ring3_path_, L"context", (unsigned char *)&context, sizeof(context)))
		return false;

	return true;
}

bool __stdcall emulation_debugger::load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	if (!engine)
		return false;

	uc_err err;
	if ((err = uc_mem_map((uc_engine *)engine, load_address, load_size, UC_PROT_ALL)) != 0 || (err = uc_mem_write((uc_engine *)engine, load_address, dump, write_size)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	return true;
}

void __stdcall emulation_debugger::set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
	desc->descriptor = 0;
	desc->base_low = base & 0xffff;
	desc->base_mid = (base >> 16) & 0xff;
	desc->base_hi = base >> 24;

	if (limit > 0xfffff)
	{
		limit >>= 12;
		desc->granularity = 1;
	}
	desc->limit_low = limit & 0xffff;
	desc->limit_hi = limit >> 16;

	desc->dpl = 3;
	desc->present = 1;
	desc->db = 1;
	desc->type = is_code ? 0xb : 3;
	desc->system = 1;
}

bool __stdcall emulation_debugger::create_global_descriptor_table(void *engine, void *context, size_t context_size)
{
	NT_TIB64 tib;
	uc_engine *uc = (uc_engine *)engine;
	SegmentDescriptor global_descriptor[31];
	CONTEXT *ctx = (CONTEXT *)context;
	uc_x86_mmr gdtr;
	wchar_t name[MAX_PATH];
	memset(&tib, 0, sizeof(tib));
	wmemset(name, 0, MAX_PATH);

	if (context_size != sizeof(CONTEXT))
		return false;

	if (!_ui64tow(teb_address_, name, 16))
		return false;

	if (!windbg_linker_.read_binary(ring0_path_, name, (unsigned char *)&tib, sizeof(tib)))
		return false;
	//if (!read(teb_address_, &tib, sizeof(tib)))
	//	return false;

	//memset(&gdtr, 0, sizeof(gdtr));
	//memset(global_descriptor, 0, sizeof(global_descriptor));

	//gdtr.base = gdt_base_;
	//gdtr.limit = sizeof(global_descriptor) - 1;

	//uc_err err;
	//if ((err = uc_mem_map(uc, gdt_base_, 0x10000, UC_PROT_WRITE | UC_PROT_READ)) != 0)
	//{
	//	if (err != UC_ERR_MAP)
	//		return false;
	//}

	//if (uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) != 0)
	//	return false;

	//if (ctx->SegDs == ctx->SegSs)
	//	ctx->SegSs = 0x88; // rpl = 0

	//ctx->SegGs = 0x63;

	//set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	//set_global_descriptor(&global_descriptor[ctx->SegCs >> 3], 0, 0xfffff000, 1);
	//set_global_descriptor(&global_descriptor[ctx->SegDs >> 3], 0, 0xfffff000, 0);
	//set_global_descriptor(&global_descriptor[ctx->SegFs >> 3], (uint32_t)tib.ExceptionList, 0xfff, 0);
	//set_global_descriptor(&global_descriptor[ctx->SegGs >> 3], (uint32_t)tib.Self, 0xfffff000, 0);
	//set_global_descriptor(&global_descriptor[ctx->SegSs >> 3], 0, 0xfffff000, 0);
	//global_descriptor[ctx->SegSs >> 3].dpl = 0; // dpl = 0, cpl = 0

	//if (uc_mem_write(uc, gdt_base_, &global_descriptor, sizeof(global_descriptor)) != 0)
	//	return false;

	return true;
}
///
///
///
bool __stdcall emulation_debugger::attach()
{
	bool is_32 = false;

	if (g_Ext->IsCurMachine32())
	{
		is_32 = true;
		g_Ext->ExecuteSilent("!wow64exts.sw");
	}

	if (!capture())
		return false;

	peb_address_ = windbg_linker_.get_peb_address();
	teb_address_ = windbg_linker_.get_teb_address();
	gdt_base_ = 0xc0000000;

	if (!peb_address_ || !teb_address_)
		return false;

	if (is_32)
		g_Ext->ExecuteSilent("!wow64exts.sw");

	return true;
}

bool __stdcall emulation_debugger::trace32()
{
	uc_engine *uc = nullptr;
	if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != 0)
		return false;
	std::shared_ptr<void> uc_closer(uc, uc_close);
	CONTEXT context = { 0, };

	if (!windbg_linker_.read_binary(ring3_path_, L"context", (unsigned char *)&context, sizeof(context)))
		return false;

	wchar_t teb_region[MAX_PATH];
	size_t region_size = 0;
	wmemset(teb_region, 0, MAX_PATH);
	if (!windbg_linker_.file_query(ring3_path_, L"*.*", teb_address_, teb_region, &region_size))
		return false;

	unsigned char *dump = (unsigned char *)malloc(region_size);
	memset(dump, 0, region_size);
	std::shared_ptr<void> dump_closer(dump, free);
	if (!windbg_linker_.read_binary(ring3_path_, teb_region, dump, region_size))
		return false;

	return true;
}