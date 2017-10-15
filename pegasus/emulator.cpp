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

emulation_debugger::~emulation_debugger()
{
	if (engine_)
	{
		uc_engine *uc = (uc_engine *)engine_;
		uc_close(uc);
	}
}
//
//
//
bool __stdcall emulation_debugger::load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	if (!engine)
		return false;

	uc_err err;
	if ((err = uc_mem_map((uc_engine *)engine, load_address, load_size, UC_PROT_ALL)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	if ((err = uc_mem_write((uc_engine *)engine, load_address, dump, write_size)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}
	return true;
}

bool __stdcall emulation_debugger::load(void *address)
{
	if (!engine_)
		return false;

	uc_engine *uc = (uc_engine *)engine_;
	MEMORY_BASIC_INFORMATION64 mbi;
	memset(&mbi, 0, sizeof(mbi));
	if (!windbg_linker_.virtual_query((unsigned long long)address, &mbi))
		return false;

	unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);
	if (!dump)
		return false;
	std::shared_ptr<void> dump_closer(dump, free);

	if (!windbg_linker_.read_memory(mbi.BaseAddress, dump, (size_t)mbi.RegionSize))
		return false;

	uc_err err;
	if ((err = uc_mem_map(uc, mbi.BaseAddress, (size_t)mbi.RegionSize, UC_PROT_ALL)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	if ((err = uc_mem_write(uc, mbi.BaseAddress, dump, (size_t)mbi.RegionSize)) != 0)
		return false;

	//dprintf("load::%08x-%08x\n", mbi.BaseAddress, mbi.RegionSize);

	return true;
}
//
//
//
bool __stdcall emulation_debugger::query(unsigned long long address, unsigned long long *base, size_t *size)
{
	if (!engine_)
		return false;

	uc_engine *uc = (uc_engine *)engine_;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

	for (unsigned int i = 0; i < count; ++i)
	{
		if (address >= um[i].begin && address <= um[i].end)
		{
			*base = um[i].begin;
			*size = um[i].end - um[i].begin;
			
			return true;
		}
	}

	return false;
}

bool __stdcall emulation_debugger::read(unsigned long long address, unsigned char *dump, size_t *size)
{
	if (!engine_)
		return false;

	unsigned long long base = 0;
	size_t region_size = 0;

	if (!query(address, &base, &region_size))
		return nullptr;

	unsigned char *d = (unsigned char *)malloc(region_size);
	if (!d)
		return nullptr;
	std::shared_ptr<void> dump_closer(d, free);
	memset(d, 0, region_size);

	uc_engine * uc = (uc_engine *)engine_;
	if(uc_mem_read(uc, base, d, region_size) != 0)
		return nullptr;

	unsigned long long offset = address - base;
	if (region_size - offset < *size)
		*size = region_size - offset;

	memcpy(dump, &d[offset], *size);

	return true;
}
//
//
//
bool __stdcall emulation_debugger::set_msr()
{
	uc_engine * uc = (uc_engine *)engine_;
	uc_x86_msr fs_msr = { 0xC0000100, teb_address_ };
	uc_x86_msr gs_msr = { 0xC0000101, teb_64_address_ };

	if (uc_reg_write(uc, UC_X86_REG_MSR, &fs_msr) != 0)
		return false;

	if (uc_reg_write(uc, UC_X86_REG_MSR, &gs_msr) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::set_environment_block()
{
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

bool __stdcall emulation_debugger::create_global_descriptor_table_ex()
{
	uc_engine *uc = (uc_engine *)engine_;
	SegmentDescriptor global_descriptor[31];
	memset(global_descriptor, 0, sizeof(global_descriptor));

	if (context_.ds == context_.ss)
		context_.ss = 0x88; // rpl = 0

	context_.gs = 0x63;

	set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	set_global_descriptor(&global_descriptor[context_.cs >> 3], 0, 0xfffff000, 1);
	set_global_descriptor(&global_descriptor[context_.ds >> 3], 0, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context_.fs >> 3], (unsigned long)teb_address_, 0xfff, 0);
	set_global_descriptor(&global_descriptor[context_.gs >> 3], (unsigned long)teb_64_address_, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context_.ss >> 3], 0, 0xfffff000, 0);
	global_descriptor[context_.ss >> 3].dpl = 0; // dpl = 0, cpl = 0

	gdt_base_ = 0xc0000000;
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load(uc, gdt_base_, 0x10000, global_descriptor, sizeof(global_descriptor)))
		return false;

	return true;
}
//
//
//
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

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];

	context_.efl = read_register[PR_EFLAGS];
	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];

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

	write_register[PR_RAX] = (unsigned long)context_.rax;
	write_register[PR_RBX] = (unsigned long)context_.rbx;
	write_register[PR_RCX] = (unsigned long)context_.rcx;
	write_register[PR_RDX] = (unsigned long)context_.rdx;
	write_register[PR_RSI] = (unsigned long)context_.rsi;
	write_register[PR_RDI] = (unsigned long)context_.rdi;
	write_register[PR_RSP] = (unsigned long)context_.rsp;
	write_register[PR_RBP] = (unsigned long)context_.rbp;
	write_register[PR_RIP] = (unsigned long)context_.rip;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = (unsigned long)context_.xmm0;
	write_register[PR_XMM1] = (unsigned long)context_.xmm1;
	write_register[PR_XMM2] = (unsigned long)context_.xmm2;
	write_register[PR_XMM3] = (unsigned long)context_.xmm3;
	write_register[PR_XMM4] = (unsigned long)context_.xmm4;
	write_register[PR_XMM5] = (unsigned long)context_.xmm5;
	write_register[PR_XMM6] = (unsigned long)context_.xmm6;
	write_register[PR_XMM7] = (unsigned long)context_.xmm7;

	write_register[PR_YMM0] = (unsigned long)context_.ymm0;
	write_register[PR_YMM1] = (unsigned long)context_.ymm1;
	write_register[PR_YMM2] = (unsigned long)context_.ymm2;
	write_register[PR_YMM3] = (unsigned long)context_.ymm3;
	write_register[PR_YMM4] = (unsigned long)context_.ymm4;
	write_register[PR_YMM5] = (unsigned long)context_.ymm5;
	write_register[PR_YMM6] = (unsigned long)context_.ymm6;
	write_register[PR_YMM7] = (unsigned long)context_.ymm7;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::read_x64_cpu_context(void *engine)
{
#ifdef _WIN64
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

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];
	context_.r8 = read_register[PR_R8];
	context_.r9 = read_register[PR_R9];
	context_.r10 = read_register[PR_R10];
	context_.r11 = read_register[PR_R11];
	context_.r12 = read_register[PR_R12];
	context_.r13 = read_register[PR_R13];
	context_.r14 = read_register[PR_R14];
	context_.r15 = read_register[PR_R15];
	context_.efl = (unsigned long)read_register[PR_EFLAGS];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];
	context_.xmm8 = read_register[PR_XMM8];
	context_.xmm9 = read_register[PR_XMM9];
	context_.xmm10 = read_register[PR_XMM10];
	context_.xmm11 = read_register[PR_XMM11];
	context_.xmm12 = read_register[PR_XMM12];
	context_.xmm13 = read_register[PR_XMM13];
	context_.xmm14 = read_register[PR_XMM14];
	context_.xmm15 = read_register[PR_XMM15];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];
	context_.ymm8 = read_register[PR_YMM8];
	context_.ymm9 = read_register[PR_YMM9];
	context_.ymm10 = read_register[PR_YMM10];
	context_.ymm11 = read_register[PR_YMM11];
	context_.ymm12 = read_register[PR_YMM12];
	context_.ymm13 = read_register[PR_YMM13];
	context_.ymm14 = read_register[PR_YMM14];
	context_.ymm15 = read_register[PR_YMM15];

	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];
#endif
	return true;
}

bool __stdcall emulation_debugger::write_x64_cpu_context(void *engine)
{
#ifdef _WIN64
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

	write_register[PR_RAX] = context_.rax;
	write_register[PR_RBX] = context_.rbx;
	write_register[PR_RCX] = context_.rcx;
	write_register[PR_RDX] = context_.rdx;
	write_register[PR_RSI] = context_.rsi;
	write_register[PR_RDI] = context_.rdi;
	write_register[PR_RSP] = context_.rsp;
	write_register[PR_RBP] = context_.rbp;
	write_register[PR_R8] = context_.r8;
	write_register[PR_R9] = context_.r9;
	write_register[PR_R10] = context_.r10;
	write_register[PR_R11] = context_.r11;
	write_register[PR_R12] = context_.r12;
	write_register[PR_R13] = context_.r13;
	write_register[PR_R14] = context_.r14;
	write_register[PR_R15] = context_.r15;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = context_.xmm0;
	write_register[PR_XMM1] = context_.xmm1;
	write_register[PR_XMM2] = context_.xmm2;
	write_register[PR_XMM3] = context_.xmm3;
	write_register[PR_XMM4] = context_.xmm4;
	write_register[PR_XMM5] = context_.xmm5;
	write_register[PR_XMM6] = context_.xmm6;
	write_register[PR_XMM7] = context_.xmm7;
	write_register[PR_XMM8] = context_.xmm8;
	write_register[PR_XMM9] = context_.xmm9;
	write_register[PR_XMM10] = context_.xmm10;
	write_register[PR_XMM11] = context_.xmm11;
	write_register[PR_XMM12] = context_.xmm12;
	write_register[PR_XMM13] = context_.xmm13;
	write_register[PR_XMM14] = context_.xmm14;
	write_register[PR_XMM15] = context_.xmm15;

	write_register[PR_YMM0] = context_.ymm0;
	write_register[PR_YMM1] = context_.ymm1;
	write_register[PR_YMM2] = context_.ymm2;
	write_register[PR_YMM3] = context_.ymm3;
	write_register[PR_YMM4] = context_.ymm4;
	write_register[PR_YMM5] = context_.ymm5;
	write_register[PR_YMM6] = context_.ymm6;
	write_register[PR_YMM7] = context_.ymm7;
	write_register[PR_YMM8] = context_.ymm8;
	write_register[PR_YMM9] = context_.ymm9;
	write_register[PR_YMM10] = context_.ymm10;
	write_register[PR_YMM11] = context_.ymm11;
	write_register[PR_YMM12] = context_.ymm12;
	write_register[PR_YMM13] = context_.ymm13;
	write_register[PR_YMM14] = context_.ymm14;
	write_register[PR_YMM15] = context_.ymm15;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
		return false;
#endif
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
//
//
//
bool __stdcall emulation_debugger::disasm(void *code, size_t size, uint32_t dt, void *out)
{
	unsigned int dc;
	_CodeInfo ci;
	_DInst *di = (_DInst *)out;

	ci.code = (unsigned char *)code;
	ci.codeLen = (int)size;
	ci.codeOffset = (_OffsetType)(unsigned long long *)code;
	ci.dt = (_DecodeType)dt;
	ci.features = DF_NONE;

	if (distorm_decompose(&ci, di, 1, &dc) == DECRES_INPUTERR)
		return false;

	if (dc < 1)
		return false;

	return true;
}

bool __stdcall emulation_debugger::mnemonic_mov_gs(void *engine, unsigned long long ip)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

	if (uc_mem_read(uc, ip, dump, 1024) != 0)
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[1].type != O_DISP || di.size != 9 || di.disp != 0x30)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };
	if (uc_reg_write(uc, distorm_to_uc[di.ops[0].index], &teb_64_address_) != 0)
		return false;

	context_.rip = ip + di.size;
	if (uc_reg_write(uc, UC_X86_REG_RIP, &context_.rip) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::mnemonic_mov_ss(void *engine, unsigned long long ip)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

	if (uc_mem_read(uc, ip, dump, 1024) != 0)
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[0].index != R_SS || di.size != 3)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	DWORD ss = 0x88;
	if (uc_reg_write(uc, distorm_to_uc[di.ops[1].index], &ss) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::mnemonic_wow_ret(void *engine)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

	if (uc_mem_read(uc, context_.rip, dump, 1024) != 0)
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_JMP_FAR || di.ops[0].type != O_SMEM || di.size != 3)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	unsigned long long return_register = 0;
	if (uc_reg_read(uc, distorm_to_uc[di.ops[0].index], &return_register) != 0)
		return false;

	unsigned long value = 0;
	if (uc_mem_read(uc, return_register, &value, sizeof(value)) != 0)
		return false;

	context_.rip = value;
	is_64_ = false;

	return true;
}

bool __stdcall emulation_debugger::mnemonic_switch_wow64cpu(void *engine)
{
	uc_err err;
	uc_engine *uc = (uc_engine *)engine;
	unsigned char dump[16] = { 0, };

	if ((err = uc_mem_read(uc, context_.rip, dump, 16)) == 0)
	{
		if ((dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0))
		{
			unsigned long *syscall_ptr = (unsigned long *)(&dump[1]);
			unsigned long syscall = *syscall_ptr;

			is_64_ = true;
			context_.rip = syscall;

			return true;
		}
	}
	//else
	//	dprintf("wow64fail::%d::%08x\n", err, context_.rip);

	return false;
}
//
// storage memory
//
bool __stdcall emulation_debugger::setting(char *path)
{
	int l = MultiByteToWideChar(CP_ACP, 0, path, (int)strlen(path), NULL, NULL);

	if (l == 0)
		return false;

	ZeroMemory(storage_path_, MAX_PATH);
	l = MultiByteToWideChar(CP_ACP, 0, path, (int)strlen(path), storage_path_, l);

	if (l == 0)
		return false;

	wchar_t max_path[MAX_PATH];
	wchar_t storage[MAX_PATH];

	_itow(storage_count_, storage, 10);
	StringCbCopy(max_path, MAX_PATH, storage_path_);
	StringCbCat(max_path, MAX_PATH, L"\\");
	StringCbCat(max_path, MAX_PATH, storage);

	if (!CreateDirectory(max_path, FALSE) && GetLastError() != ERROR_ALREADY_EXISTS)
		return false;

	return true;
}

bool __stdcall emulation_debugger::store()
{
	uc_engine *uc = (uc_engine *)engine_;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

	wchar_t max_path[MAX_PATH];
	wchar_t storage[MAX_PATH];

	_itow(storage_count_, storage, 10);
	StringCbCopy(max_path, MAX_PATH, storage_path_);
	StringCbCat(max_path, MAX_PATH, L"\\");
	StringCbCat(max_path, MAX_PATH, storage);

	for (unsigned int i = 0; i < count; ++i)
	{
		size_t size = um[i].end - um[i].begin + 1;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
			return false;

		memset(dump, 0, size);
		std::shared_ptr<void> dump_closer(dump, free);

		if (uc_mem_read(uc, um[i].begin, dump, size) != 0)
			return false;

		wchar_t name[MAX_PATH];
		wmemset(name, 0, MAX_PATH);
		if (!_ui64tow(um[i].begin, name, 16))
			return false;

		if (!windbg_linker_.write_binary(max_path, name, dump, size))
			return false;
	}

	wchar_t name[MAX_PATH];
	wmemset(name, 0, MAX_PATH);
	if (!_ui64tow(0xCCCCCCCC, name, 16))
		return false;

	if (!windbg_linker_.write_binary(max_path, name, (unsigned char *)&context_, sizeof(context_)))
		return false;

	++storage_count_;
	return true;
}

bool __stdcall emulation_debugger::query_storage_memory(unsigned long long value, wchar_t *file_name, size_t *size)
{
	WIN32_FIND_DATA wfd;
	wchar_t path[MAX_PATH] = { 0, };
	wchar_t storage[MAX_PATH];

	_itow(storage_count_, storage, 10);
	StringCbCopy(path, MAX_PATH, storage_path_);
	StringCbCat(path, MAX_PATH, L"\\");
	StringCbCat(path, MAX_PATH, storage);
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

		if (base_address <= value && value < end_address)
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

unsigned char * __stdcall emulation_debugger::load_storage_memory(unsigned long long value, unsigned long long *base, size_t *size)
{
	wchar_t *end = nullptr;
	wchar_t name[MAX_PATH];
	size_t region_size = 0;
	wmemset(name, 0, MAX_PATH);

	if (!query_storage_memory(value, name, &region_size))
		return nullptr;

	unsigned char *dump = (unsigned char *)malloc(region_size);

	if (!dump)
		return nullptr;

	memset(dump, 0, region_size);

	wchar_t max_path[MAX_PATH];
	wchar_t storage[MAX_PATH];

	_itow(storage_count_, storage, 10);
	StringCbCopy(max_path, MAX_PATH, storage_path_);
	StringCbCat(max_path, MAX_PATH, L"\\");
	StringCbCat(max_path, MAX_PATH, storage);

	if (!windbg_linker_.read_binary(max_path, name, dump, region_size))
		return nullptr;

	*base = wcstoull(name, &end, 16);
	*size = region_size;

	return dump;
}

bool __stdcall emulation_debugger::load_page(unsigned long long value)
{
	emulation_debugger::page p;
	unsigned char *dump = load_storage_memory(value, &p.base, &p.size);

	if (!dump) 
		return false;

	std::shared_ptr<void> dump_closer(dump, free);

	if (!load(engine_, p.base, p.size, dump, p.size))
		return false;

	return true;
}

bool __stdcall emulation_debugger::load_context(void *mem)
{
	emulation_debugger::page p;
	trace_item *item = (trace_item *)mem;
	unsigned char *dump = load_storage_memory(0xCCCCCCCC, &p.base, &p.size);

	if (!dump)
		return false;
	std::shared_ptr<void> dump_closer(dump, free);

	memcpy(&context_, dump, p.size);

	if (!load_context(engine_, item->mode))
		return false;

	return true;
}

bool __stdcall emulation_debugger::reboot(void *mem)
{
	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;
	uc_engine *uc = nullptr;
	trace_item *item = (trace_item *)mem;

	if (uc_open(UC_ARCH_X86, (uc_mode)item->mode, &uc) != 0)
		return false;

	engine_ = uc;
	uc_hook_add(uc, &code_hook, UC_HOOK_CODE, item->code_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	if (!load_page(teb_address_))
		return false;

	if (!load_page(peb_64_address_))
		return false;

	if (teb_64_address_ || peb_64_address_)
	{
		if (!load_page(teb_64_address_))
			return false;

		if (!load_page(peb_64_address_))
			return false;
	}

	gdt_base_ = 0xc0000000;
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load_page(gdt_base_))
		return false;

	if (!load_context(item))
		return false;

	if (!load_page(context_.rip))
		return false;

	if (!load_page(context_.rsp))
		return false;

	return true;
}
//
//
//
bool __stdcall emulation_debugger::attach(void *mem)
{
	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;
	uc_engine *uc = nullptr;
	trace_item *item = (trace_item *)mem;

	if (uc_open(UC_ARCH_X86, (uc_mode)item->mode, &uc) != 0)
		return false;

	engine_ = uc;
	uc_hook_add(uc, &code_hook, UC_HOOK_CODE, item->code_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	if (!set_environment_block())
		return false;

	if (!load((void *)teb_address_))
	{
		if (!load((void *)teb_64_address_))
			return false;
	}

	if (!load((void *)peb_address_))
	{
		if (!load((void *)peb_64_address_))
			return false;
	}

	//if (teb_64_address_ || peb_64_address_)
	//{
	//	if (!load((void *)teb_64_address_))
	//		return false;

	//	if (!load((void *)peb_64_address_))
	//		return false;
	//}

	memset(&context_, 0, sizeof(context_));
	if (!windbg_linker_.get_thread_context(&context_))
		return false;

	if (!create_global_descriptor_table_ex())
		return false;

	if (set_msr())
		return false;

	if (!load_context(uc, item->mode))
		return false;

	if (!load((void *)context_.rip))
		return false;

	if (!load((void *)context_.rsp))
		return false;

	if (strlen(item->path) != 0)
	{
		if (!setting(item->path))
			return false;
	}
	else
		memset(storage_path_, 0, sizeof(storage_path_));

	return true;
}

bool __stdcall emulation_debugger::trace(void *engine, trace_item item)
{
	uc_err err = (uc_err)0;
	uc_engine *uc = (uc_engine *)engine;
	BYTE dump[1024];
	_DInst di;

	unsigned long long end_point = context_.rip + 0x1000;
	unsigned long step = 1;

	if (windbg_linker_.read_memory(context_.rip, dump, 1024) && disasm((PVOID)dump, 64, Decode64Bits, &di))
	{
		if (item.break_point)
		{
			end_point = item.break_point;
			step = 0;
		}

		err = uc_emu_start(uc, context_.rip, end_point, 0, step);
		if (err)
		{
			if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED)
			{
				unsigned restart_count = 0;

				do
				{
					err = uc_emu_start(uc, context_.rip, end_point, 0, step);
					++restart_count;
				} while ((err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED) && restart_count < 3);
			}
		}
	}
	else
	{
		err = UC_ERR_EXCEPTION;
	}

	backup_context_ = context_;

	if (is_64_)
	{
		if (!read_x64_cpu_context(uc))
		{
			return false;
		}
	}
	else
	{
		if (!read_x86_cpu_context(uc))
		{
			return false;
		}
	}

	if (err)
	{
		dprintf("break::e::%d\n", err);

		return false;
	}

	return true;
}

bool __stdcall emulation_debugger::trace_ex(void *mem)
{
	uc_engine *	uc = (uc_engine *)engine_;
	trace_item *item = (trace_item *)mem;
	bool s = true;

	if (!trace(uc, *item))
	{
		mnemonic_switch_wow64cpu(uc);
		mnemonic_wow_ret(uc);
		s = false;
	}

	return s;
}
//
//
//
bool __stdcall emulation_debugger::switch_cpu(void *mem)
{
	uc_engine *current_engine = (uc_engine *)engine_;
	uc_engine *switch_engine = nullptr;

	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;
	trace_item *item = (trace_item *)mem;

	if (uc_open(UC_ARCH_X86, (uc_mode)item->mode, &switch_engine) != 0)
		return false;

	uc_hook_add(switch_engine, &code_hook, UC_HOOK_CODE, item->code_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(switch_engine, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(switch_engine, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(switch_engine, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(current_engine, &um, &count) != 0)
		return false;
	std::shared_ptr<void> um_closer(um, free);

	bool s = true;
	for (unsigned int i = 0; i < count; ++i)
	{
		size_t size = (um[i].end + 1) - um[i].begin;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
		{
			s = false;
			break;
		}

		if (uc_mem_read(current_engine, um[i].begin, dump, size) != 0)
		{
			s = false;
			break;
		}

		if (!load(switch_engine, um[i].begin, size, dump, size))
		{
			s = false;
			break;
		}
	}

	if (!s)
	{
		uc_close(switch_engine);
		return false;
	}

	gdt_base_ = 0xc0000000;
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(switch_engine, UC_X86_REG_GDTR, &gdtr) != 0)
	{
		uc_close(switch_engine);
		return false;
	}

	if (!load_context(switch_engine, item->mode))
	{
		uc_close(switch_engine);
		return false;
	}

	if (set_msr())
		return false;

	uc_close(current_engine);
	engine_ = switch_engine;

	return true;
}
//
//
//
size_t __stdcall emulation_debugger::alignment(size_t region_size, unsigned long image_aligin)
{
	unsigned long mod = region_size % image_aligin;
	region_size -= mod;

	return region_size + image_aligin;
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

bool __stdcall emulation_debugger::is_64_cpu()
{
	return is_64_;
}

void __stdcall emulation_debugger::current_regs()
{
	log_print();
}

void * __stdcall emulation_debugger::get_windbg_linker()
{
	return &windbg_linker_;
}

cpu_context_type __stdcall emulation_debugger::get_current_thread_context()
{
	return context_;
}
//
//
//
void __stdcall emulation_debugger::print_code(unsigned long long ip, unsigned long line)
{
	unsigned long long index = ip;

	_DInst di;
	unsigned char dump[32] = { 0, };

	di.size = 0;
	for (unsigned int i = 0; i < line; ++i)
		index = before(index);

	char mnemonic[1024] = { 0, };
	unsigned long size = 0;
	unsigned long long next = 0;

	dprintf("\n");
	for (unsigned int i = 0; i<(line * 2 + 1); ++i)
	{
		unsigned long long next = index;
		if (Disasm(&next, mnemonic, 0))
		{
			if (index == ip)
				g_Ext->Dml("<b><col fg=\"emphfg\">	%s</col></b>", mnemonic);
			else
				dprintf("	%s", mnemonic);
		}

		index = next;
	}
	dprintf("\n");
}

void __stdcall emulation_debugger::print64(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%0*I64x</col></b>", 16, c);
	else
		dprintf("%0*I64x", 16, c);
}

void __stdcall emulation_debugger::print32(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%08x</col></b>", c);
	else
		dprintf("%08x", c);
}

unsigned long long emulation_debugger::before(unsigned long long offset)
{
	_DInst di;
	unsigned char dump[32] = { 0, };
	unsigned long long b = offset - 32;

	do
	{
		if (!windbg_linker_.read_memory(b, dump, 32))
			return 0;

		if (disasm(dump, 32, Decode64Bits, &di))
			b += di.size;
		else
			++b;

	} while (b < offset && b != offset);

	return b - di.size;
}

void __stdcall emulation_debugger::log_print()
{
	if (is_64_cpu())
	{
#ifdef _WIN64
		dprintf("	rax="), print64(context_.rax, backup_context_.rax), dprintf(" ");
		dprintf("rbx="), print64(context_.rbx, backup_context_.rbx), dprintf(" ");
		dprintf("rcx="), print64(context_.rcx, backup_context_.rcx), dprintf("\n");

		dprintf("	rdx="), print64(context_.rdx, backup_context_.rdx), dprintf(" ");
		dprintf("rsi="), print64(context_.rsi, backup_context_.rsi), dprintf(" ");
		dprintf("rdi="), print64(context_.rdi, backup_context_.rdi), dprintf("\n");

		dprintf("	rip="), print64(context_.rip, backup_context_.rip), dprintf(" ");
		dprintf("rsp="), print64(context_.rsp, backup_context_.rsp), dprintf(" ");
		dprintf("rbp="), print64(context_.rbp, backup_context_.rbp), dprintf("\n");

		dprintf("	r8="), print64(context_.r8, backup_context_.r8), dprintf(" ");
		dprintf("r9="), print64(context_.r9, backup_context_.r9), dprintf(" ");
		dprintf("r10="), print64(context_.r10, backup_context_.r10), dprintf("\n");

		dprintf("	r11="), print64(context_.r11, backup_context_.r11), dprintf(" ");
		dprintf("r12="), print64(context_.r12, backup_context_.r12), dprintf(" ");
		dprintf("r13="), print64(context_.r13, backup_context_.r13), dprintf("\n");

		dprintf("	r14="), print64(context_.r14, backup_context_.r14), dprintf(" ");
		dprintf("r15="), print64(context_.r15, backup_context_.r15), dprintf(" ");
		dprintf("efl="), print32(context_.efl, backup_context_.efl), dprintf("\n");
#endif
	}
	else
	{
		dprintf("	eax="), print32(context_.rax, backup_context_.rax), dprintf(" ");
		dprintf("ebx="), print32(context_.rbx, backup_context_.rbx), dprintf(" ");
		dprintf("ecx="), print32(context_.rcx, backup_context_.rcx), dprintf(" ");
		dprintf("edx="), print32(context_.rdx, backup_context_.rdx), dprintf(" ");
		dprintf("esi="), print32(context_.rsi, backup_context_.rsi), dprintf(" ");
		dprintf("edi="), print32(context_.rdi, backup_context_.rdi), dprintf("\n");

		dprintf("	eip="), print32(context_.rip, backup_context_.rip), dprintf(" ");
		dprintf("esp="), print32(context_.rsp, backup_context_.rsp), dprintf(" ");
		dprintf("ebp="), print32(context_.rbp, backup_context_.rbp), dprintf(" ");
		dprintf("efl="), print32(context_.efl, backup_context_.efl), dprintf("\n");
	}

	print_code(context_.rip, 0);
}