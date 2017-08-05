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

#pragma comment(lib, "unicorn_static_x64.lib")

emulation_debugger::emulation_debugger()
{
}
///
///
///
size_t __stdcall emulation_debugger::alignment(size_t region_size, unsigned long image_aligin)
{
	size_t alignment = region_size;

	while (1)
	{
		if (alignment > image_aligin)
			alignment -= image_aligin;
		else
			break;
	}

	alignment = image_aligin - alignment;

	return 	alignment += region_size;
}
///
///
///
bool __stdcall emulation_debugger::file_query_ring3(unsigned long long value, wchar_t *file_name, size_t *size)
{
	WIN32_FIND_DATA wfd;
	wchar_t path[MAX_PATH] = { 0, };

	StringCbCopy(path, MAX_PATH, ring3_path_);
	StringCbCat(path, MAX_PATH, L"\\*.*");

	HANDLE h_file = FindFirstFile(path, &wfd);

	if (h_file == INVALID_HANDLE_VALUE)
		return false;
	std::shared_ptr<void> file_closer(h_file, CloseHandle);

	do
	{
		wchar_t *end = nullptr;
		unsigned long long base_address = wcstoll(wfd.cFileName, &end, 16);
		size_t region_size = (wfd.nFileSizeHigh * ((unsigned)0x100000000) + wfd.nFileSizeLow);
		unsigned long long end_address = base_address + region_size;

		if (base_address <= value && value <= end_address)
		{
			if (file_name && size)
			{
				*size = region_size;
				StringCbCopy(file_name, MAX_PATH, wfd.cFileName);
				return true;
			}
		}
	} while (FindNextFile(h_file, &wfd));

	return false;
}

unsigned char * __stdcall emulation_debugger::load_page(unsigned long long value, unsigned long long *base, size_t *size)
{
	wchar_t *end = nullptr;
	wchar_t name[MAX_PATH];
	size_t region_size = 0;
	wmemset(name, 0, MAX_PATH);

	if (!file_query_ring3(value, name, &region_size))
		return nullptr;

	unsigned char *dump = (unsigned char *)malloc(region_size);

	if (!dump)
		return nullptr;

	memset(dump, 0, region_size);

	if (!windbg_linker_.read_binary(ring3_path_, name, dump, region_size))
		return nullptr;

	*base = wcstoull(name, &end, 16);
	*size = region_size;

	return dump;
}
///
///
///
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

bool __stdcall emulation_debugger::is_wow64cpu()
{
	unsigned long long teb_address = windbg_linker_.get_teb_address();
	NT_TIB64 tib_64;

	if (!windbg_linker_.read_memory(teb_address, &tib_64, sizeof(tib_64)))
		return false;

	if (teb_address == tib_64.Self)
		return true;

	return false;
}
///
///
///
bool __stdcall emulation_debugger::capture()
{
	uint64_t address = 0;
	MEMORY_BASIC_INFORMATION64 mbi = { 0, };
	wchar_t name[MAX_PATH];

	install();

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

	if (!windbg_linker_.get_context(&context_, sizeof(context_)))
		return false;

	//if (!windbg_linker_.write_binary(ring3_path_, L"context", (unsigned char *)&context_, sizeof(context_)))
	//	return false;

	return true;
}

bool __stdcall emulation_debugger::load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	if (!engine)
		return false;

	uc_err err;
	if ((err = uc_mem_map((uc_engine *)engine, load_address, load_size, UC_PROT_ALL)) != 0)
	{
		//dprintf("map err = %d\n", err);
		if (err != UC_ERR_MAP)
			return false;
	}

	if ((err = uc_mem_write((uc_engine *)engine, load_address, dump, write_size)) != 0)
	{
		//dprintf("write err = %d\n", err);
		if (err != UC_ERR_MAP)
			return false;
	}
	return true;
}

bool __stdcall emulation_debugger::load_ex(void *engine)
{
	emulation_debugger::page teb32_page;
	emulation_debugger::page peb32_page;
	emulation_debugger::page teb64_page;
	emulation_debugger::page peb64_page;
	unsigned char * teb32_dump = nullptr;
	unsigned char * teb64_dump = nullptr;
	unsigned char * peb32_dump = nullptr;
	unsigned char * peb64_dump = nullptr;

	emulation_debugger::page stack;
	emulation_debugger::page code;
	unsigned char * stack_dump = nullptr;
	unsigned char * code_dump = nullptr;

	emulation_debugger::page gdt_page;
	unsigned char * gdt_dump = nullptr;

	stack_dump = load_page(context_.Rsp, &stack.base, &stack.size);
	if (!stack_dump) return false;
	std::shared_ptr<void> stack_dump_closer(stack_dump, free);

	code_dump = load_page(context_.Rip, &code.base, &code.size);
	if (!code_dump) return false;
	std::shared_ptr<void> code_dump_closer(code_dump, free);

	teb32_dump = load_page(teb_address_, &teb32_page.base, &teb32_page.size);
	if (!teb32_dump) return false;
	std::shared_ptr<void> teb_dump_closer(teb32_dump, free);

	peb32_dump = load_page(peb_address_, &peb32_page.base, &peb32_page.size);
	if (!peb32_dump) return false;
	std::shared_ptr<void> peb_dump_closer(peb32_dump, free);

	if(is_wow64cpu())
	{
		teb64_dump = load_page(teb_64_address_, &teb64_page.base, &teb64_page.size);
		if (!teb64_dump) return false;
		std::shared_ptr<void> teb64_dump_closer(teb64_dump, free);

		peb64_dump = load_page(peb_64_address_, &peb64_page.base, &peb64_page.size);
		if (!peb64_dump) return false;
		std::shared_ptr<void> peb64_dump_closer(peb64_dump, free);
	}

	gdt_dump = load_page(gdt_base_, &gdt_page.base, &gdt_page.size);
	if (!gdt_dump) return false;
	std::shared_ptr<void> gdt_dump_closer(gdt_dump, free);
	///
	///
	///
	if (!load(engine, teb32_page.base, teb32_page.size, teb32_dump, teb32_page.size))
		return false;

	if (!load(engine, peb32_page.base, peb32_page.size, peb32_dump, peb32_page.size))
		return false;

	if (is_wow64cpu())
	{
		if (!load(engine, teb64_page.base, teb64_page.size, teb64_dump, teb64_page.size))
			return false;
		if (!load(engine, peb64_page.base, peb64_page.size, peb64_dump, peb64_page.size))
			return false;
	}

	if (!load(engine, code.base, code.size, code_dump, code.size))
		return false;

	if (!load(engine, stack.base, stack.size, stack_dump, stack.size))
		return false;

	SegmentDescriptor global_descriptor[31];
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = sizeof(global_descriptor) - 1;

	if (uc_reg_write((uc_engine *)engine, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load(engine, gdt_page.base, 0x10000, gdt_dump, gdt_page.size))
		return false;

	return true;
}
///
///
///
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

bool __stdcall emulation_debugger::create_global_descriptor_table()
{
	SegmentDescriptor global_descriptor[31];
	memset(global_descriptor, 0, sizeof(global_descriptor));

	if (context_.SegDs == context_.SegSs)
		context_.SegSs = 0x88; // rpl = 0

	context_.SegGs = 0x63;

	set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	set_global_descriptor(&global_descriptor[context_.SegCs >> 3], 0, 0xfffff000, 1);
	set_global_descriptor(&global_descriptor[context_.SegDs >> 3], 0, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context_.SegFs >> 3], teb_address_, 0xfff, 0);
	set_global_descriptor(&global_descriptor[context_.SegGs >> 3], teb_64_address_, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context_.SegSs >> 3], 0, 0xfffff000, 0);
	global_descriptor[context_.SegSs >> 3].dpl = 0; // dpl = 0, cpl = 0

	wchar_t name[MAX_PATH];
	wmemset(name, 0, MAX_PATH);
	if (!_ui64tow(gdt_base_, name, 16))
		return false;

	if (!windbg_linker_.write_binary(ring3_path_, name, (unsigned char *)global_descriptor, sizeof(global_descriptor)))
		return false;

	return true;
}

bool __stdcall emulation_debugger::read_x86_cpu_context(void *engine)
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!read_register)
		return false;
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
		return false;
	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		read_ptr[i] = &read_register[i];

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_read_batch(uc, x86_register, read_ptr, size) != 0)
		return false;

	context_.Rax = read_register[PR_RAX];
	context_.Rbx = read_register[PR_RBX];
	context_.Rcx = read_register[PR_RCX];
	context_.Rdx = read_register[PR_RDX];
	context_.Rsi = read_register[PR_RSI];
	context_.Rdi = read_register[PR_RDI];
	context_.Rsp = read_register[PR_RSP];
	context_.Rbp = read_register[PR_RBP];
	context_.Rip = read_register[PR_RIP];
	context_.EFlags = read_register[PR_EFLAGS];
	context_.SegCs = (unsigned short)read_register[PR_REG_CS];
	context_.SegDs = (unsigned short)read_register[PR_REG_DS];
	context_.SegEs = (unsigned short)read_register[PR_REG_ES];
	context_.SegFs = (unsigned short)read_register[PR_REG_FS];
	context_.SegGs = (unsigned short)read_register[PR_REG_GS];
	context_.SegSs = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool __stdcall emulation_debugger::write_x86_cpu_context(void *engine)
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!write_register)
		return false;
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
		return false;
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		write_ptr[i] = &write_register[i];

	write_register[PR_RAX] = (unsigned long)context_.Rax;
	write_register[PR_RBX] = (unsigned long)context_.Rbx;
	write_register[PR_RCX] = (unsigned long)context_.Rcx;
	write_register[PR_RDX] = (unsigned long)context_.Rdx;
	write_register[PR_RSI] = (unsigned long)context_.Rsi;
	write_register[PR_RDI] = (unsigned long)context_.Rdi;
	write_register[PR_RSP] = (unsigned long)context_.Rsp;
	write_register[PR_RBP] = (unsigned long)context_.Rbp;
	write_register[PR_RIP] = (unsigned long)context_.Rip;
	write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
	write_register[PR_REG_CS] = context_.SegCs;
	write_register[PR_REG_DS] = context_.SegDs;
	write_register[PR_REG_ES] = context_.SegEs;
	write_register[PR_REG_FS] = context_.SegFs;
	write_register[PR_REG_GS] = context_.SegGs;
	write_register[PR_REG_SS] = context_.SegSs;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::read_x64_cpu_context(void *engine)
{
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!read_register)
		return false;
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
		return false;
	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		read_ptr[i] = &read_register[i];

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_read_batch(uc, x86_register, read_ptr, size) != 0)
		return false;

	context_.Rax = read_register[PR_RAX];
	context_.Rbx = read_register[PR_RBX];
	context_.Rcx = read_register[PR_RCX];
	context_.Rdx = read_register[PR_RDX];
	context_.Rsi = read_register[PR_RSI];
	context_.Rdi = read_register[PR_RDI];
	context_.Rsp = read_register[PR_RSP];
	context_.Rbp = read_register[PR_RBP];
	context_.Rip = read_register[PR_RIP];
	context_.R8 = read_register[PR_R8];
	context_.R9 = read_register[PR_R9];
	context_.R10 = read_register[PR_R10];
	context_.R11 = read_register[PR_R11];
	context_.R12 = read_register[PR_R12];
	context_.R13 = read_register[PR_R13];
	context_.R14 = read_register[PR_R14];
	context_.R15 = read_register[PR_R15];
	context_.EFlags = (unsigned long)read_register[PR_EFLAGS];
	context_.SegCs = (unsigned short)read_register[PR_REG_CS];
	context_.SegDs = (unsigned short)read_register[PR_REG_DS];
	context_.SegEs = (unsigned short)read_register[PR_REG_ES];
	context_.SegFs = (unsigned short)read_register[PR_REG_FS];
	context_.SegGs = (unsigned short)read_register[PR_REG_GS];
	context_.SegSs = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool __stdcall emulation_debugger::write_x64_cpu_context(void *engine)
{
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!write_register)
		return false;
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
		return false;
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		write_ptr[i] = &write_register[i];

	write_register[PR_RAX] = context_.Rax;
	write_register[PR_RBX] = context_.Rbx;
	write_register[PR_RCX] = context_.Rcx;
	write_register[PR_RDX] = context_.Rdx;
	write_register[PR_RSI] = context_.Rsi;
	write_register[PR_RDI] = context_.Rdi;
	write_register[PR_RSP] = context_.Rsp;
	write_register[PR_RBP] = context_.Rbp;
	write_register[PR_R8] = context_.R8;
	write_register[PR_R9] = context_.R9;
	write_register[PR_R10] = context_.R10;
	write_register[PR_R11] = context_.R11;
	write_register[PR_R12] = context_.R12;
	write_register[PR_R13] = context_.R13;
	write_register[PR_R14] = context_.R14;
	write_register[PR_R15] = context_.R15;
	write_register[PR_EFLAGS] = (unsigned long)context_.EFlags;
	write_register[PR_REG_CS] = context_.SegCs;
	write_register[PR_REG_DS] = context_.SegDs;
	write_register[PR_REG_ES] = context_.SegEs;
	write_register[PR_REG_FS] = context_.SegFs;
	write_register[PR_REG_GS] = context_.SegGs;
	write_register[PR_REG_SS] = context_.SegSs;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::backup(void *engine)
{
	uc_engine *uc = (uc_engine *)engine;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;

	for (unsigned int i = 0; i < count; ++i)
	{
		size_t size = um[i].end - um[i].begin;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
			return false;

		memset(dump, 0, size);
		std::shared_ptr<void> dump_closer(dump, free);

		if (uc_mem_read(uc, um[i].begin, dump, size))
			return false;

		wchar_t name[MAX_PATH];
		wmemset(name, 0, MAX_PATH);
		if (!_ui64tow(um[i].begin, name, 16))
			return false;

		if (!windbg_linker_.write_binary(ring3_path_, name, dump, size + 1))
			return false;
	}

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

	if (!capture())
		return false;

	gdt_base_ = 0xc0000000;
	if (!create_global_descriptor_table())
		return false;

	if (is_32)
		g_Ext->ExecuteSilent("!wow64exts.sw");

	return true;
}
///
///
///
bool __stdcall emulation_debugger::trace32(void *code_callback, void *unmap_callback, void *fetch_callback, void *read_callback, void *write_callback)
{
	uc_engine *uc = nullptr;
	if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != 0)
		return false;
	std::shared_ptr<void> uc_closer(uc, uc_close);

	if (!load_ex(uc))
		return false;

	if (!write_x86_cpu_context(uc))
		return false;

	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;

	uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	dprintf("%08x\n", context_.Rip);

	uc_err err;
	if ((err = uc_emu_start(uc, context_.Rip, context_.Rip + 0x1000, 0, 1)) != 0)
	{
		if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED)
		{
			if ((err = uc_emu_start(uc, context_.Rip, context_.Rip + 0x1000, 0, 1)) == 0)
				return true;
		}
		dprintf("err=%d\n", err);

		return false;
	}

	if (!backup(uc))
		return false;

	if (!read_x86_cpu_context(uc))
		return false;

	dprintf("ax=%08x\n", context_.Rax);

	return true;
}