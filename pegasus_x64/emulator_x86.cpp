#define _CRT_SECURE_NO_WARNINGS

#include <unicorn/unicorn.h>
#include <distorm/include/distorm.h>
#include <distorm/include/mnemonics.h>

#include <list>
#include <memory>

#include <winternl.h>
#include <Psapi.h>
#include <WDBGEXTS.H>

#include "interface.h"
#include "windbg_linker.h"
#include "emulator.h"

#pragma comment(lib, "unicorn_static_x64.lib")
///
/// hook code
///
size_t __stdcall x86alignment(size_t region_size, unsigned long image_aligin)
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

static void hook_unmap_memory_x86(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_READ_UNMAPPED)
	{
		unsigned char dump[16] = { 0, };
		address += 0x1;

		uc_err err;
		if ((err = uc_mem_read(uc, address, dump, 16)) == 0)
			return;

		size_t resize = x86alignment((size_t)address, 0x1000);
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

		uc_mem_map(uc, base, size, UC_PROT_ALL);
	}
}
///
///
///
bool __stdcall Wow64EmulationDebugger::attach_x86()
{
	CONTEXT context;
	std::shared_ptr<binary::linker> windbg_linker;
	gdt_base_ = 0xc0000000;

	if(!binary::create<WindbgSafeLinker>(windbg_linker))
		return false;

	if (uc_open(UC_ARCH_X86, UC_MODE_32, (uc_engine **)&emulator_x86_) != 0)
		return false;

	if (!load_ex(windbg_linker))
		return false;

	teb_address_ = windbg_linker->get_teb_address();
	peb_address_ = windbg_linker->get_peb_address();

	if (teb_address_ == 0 || peb_address_ == 0)
		return false;

	if (!check(teb_address_) || !check(peb_address_))
		return false;

	if (!windbg_linker->get_context(&context, sizeof(context)))
		return false;

	if (!create_global_descriptor_table(emulator_x86_, &context, sizeof(context)))
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EAX, &context.Rax) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EBX, &context.Rbx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_ECX, &context.Rcx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EDX, &context.Rdx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_ESI, &context.Rsi) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EDI, &context.Rdi) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_ESP, &context.Rsp) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EBP, &context.Rbp) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EIP, &context.Rip) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_EFLAGS, &context.EFlags) != 0)
		return false;
	///
	/// x64
	///
	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R8, &context.R8) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R9, &context.R9) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R10, &context.R10) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R11, &context.R11) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R12, &context.R12) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R13, &context.R13) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R14, &context.R14) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_R15, &context.R15) != 0)
		return false;
	///
	/// segment
	///
	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_CS, &context.SegCs) != 0)
		return false;

	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_SS, &context.SegSs) != 0)
		return false;

	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_DS, &context.SegDs) != 0)
		return false;

	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_ES, &context.SegEs) != 0)
		return false;

	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_FS, &context.SegFs) != 0)
		return false;

	if(uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_GS, &context.SegGs) != 0)
		return false;

	uc_hook hw;
	uc_hook hr;
	uc_hook_add((uc_engine *)emulator_x86_, &hw, UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmap_memory_x86, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add((uc_engine *)emulator_x86_, &hr, UC_HOOK_MEM_READ_UNMAPPED, hook_unmap_memory_x86, NULL, (uint64_t)1, (uint64_t)0);

	return true;
}

bool __stdcall Wow64EmulationDebugger::trace_x86()
{
	if (!emulator_x86_)
		return false;

	uc_engine *uc = (uc_engine *)emulator_x86_;
	unsigned long eip = 0L;

	memset(&eip, 0, sizeof(eip));

	if (uc_reg_read(uc, UC_X86_REG_EIP, &eip) != 0)
		return false;

	unsigned char dump[16] = { 0, };

	uc_err err;
	if ((err = uc_emu_start(uc, eip, eip + 0x1000, 0, 1)) != 0)
	{
		if (uc_mem_read(uc, eip, dump, 16) == 0 && dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0)
		{
			unsigned long *syscall_ptr = (unsigned long *)(&dump[1]);
			unsigned long syscall = *syscall_ptr;

			if (!switch_x64())
				return false;

			if (!write_register("rip", syscall))
				return false;

			return true;
		}

		if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED)
		{
			if ((err = uc_emu_start(uc, eip, eip + 0x1000, 0, 1)) == 0)
				return true;
		}

		//dprintf("err:: %d\n", err);
		return false;
	}

	return true;
}

bool __stdcall Wow64EmulationDebugger::read_context_x86(CONTEXT *context)
{
	if (!emulator_x86_)
		return false;

	uc_engine *uc = (uc_engine *)emulator_x86_;

	if (uc_reg_read(uc, UC_X86_REG_EAX, &context->Rax) != 0 || uc_reg_read(uc, UC_X86_REG_EBX, &context->Rbx) != 0 || uc_reg_read(uc, UC_X86_REG_ECX, &context->Rcx) != 0
		|| uc_reg_read(uc, UC_X86_REG_EDX, &context->Rdx) != 0 || uc_reg_read(uc, UC_X86_REG_EDI, &context->Rdi) != 0 || uc_reg_read(uc, UC_X86_REG_ESI, &context->Rsi) != 0
		|| uc_reg_read(uc, UC_X86_REG_ESP, &context->Rsp) != 0 || uc_reg_read(uc, UC_X86_REG_EBP, &context->Rbp) != 0 || uc_reg_read(uc, UC_X86_REG_EIP, &context->Rip) != 0)
		return false;

	if (uc_reg_read(uc, UC_X86_REG_R8, &context->R8) != 0 || uc_reg_read(uc, UC_X86_REG_R9, &context->R9) != 0 || uc_reg_read(uc, UC_X86_REG_R10, &context->R10) != 0
		|| uc_reg_read(uc, UC_X86_REG_R11, &context->R11) != 0 || uc_reg_read(uc, UC_X86_REG_R12, &context->R12) != 0 || uc_reg_read(uc, UC_X86_REG_R13, &context->R13) != 0
		|| uc_reg_read(uc, UC_X86_REG_R14, &context->R14) != 0 || uc_reg_read(uc, UC_X86_REG_R15, &context->R15) != 0)
		return false;

	if (uc_reg_read(uc, UC_X86_REG_CS, &context->SegCs) != 0 || uc_reg_read(uc, UC_X86_REG_DS, &context->SegDs) != 0 || uc_reg_read(uc, UC_X86_REG_ES, &context->SegEs) != 0
		|| uc_reg_read(uc, UC_X86_REG_FS, &context->SegFs) != 0 || uc_reg_read(uc, UC_X86_REG_GS, &context->SegGs) != 0 || uc_reg_read(uc, UC_X86_REG_SS, &context->SegSs) != 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::switch_x86()
{
	x64_flag_ = false;

	if (!emulator_x64_)
		return false;

	if (emulator_x86_)
		uc_close((uc_engine *)emulator_x64_);

	if (uc_open(UC_ARCH_X86, UC_MODE_32, (uc_engine **)&emulator_x86_) != 0)
		return false;

	uc_engine *uc_x86 = (uc_engine *)emulator_x86_;
	uc_engine *uc_x64 = (uc_engine *)emulator_x64_;
	uc_mem_region *x64_um = nullptr;
	uint32_t x64_count = 0;
	uint32_t count = 0;

	if (uc_mem_regions(uc_x64, &x64_um, &x64_count) != 0)
		return false;

	for (unsigned int i = 0; i < x64_count; ++i)
	{
		size_t size = (x64_um[i].end + 1) - x64_um[i].begin;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
			break;

		if (uc_mem_read(uc_x64, x64_um[i].begin, dump, size) != 0)
			break;

		if (!load(x64_um[i].begin, size, dump, size))
			break;

		free(dump);
		++count;
	}
	free(x64_um);

	if (x64_count != count)
		return false;

	CONTEXT context;
	memset(&context, 0, sizeof(context));

	if (!read_context_x64(&context))
		return false;

	if (!create_global_descriptor_table(uc_x86, &context, sizeof(context)))
		return false;
	///
	///
	///
	if (uc_reg_write(uc_x86, UC_X86_REG_EAX, &context.Rax) != 0 || uc_reg_write(uc_x86, UC_X86_REG_EBX, &context.Rbx) != 0 || uc_reg_write(uc_x86, UC_X86_REG_ECX, &context.Rcx) != 0
		|| uc_reg_write(uc_x86, UC_X86_REG_EDX, &context.Rdx) != 0 || uc_reg_write(uc_x86, UC_X86_REG_EDI, &context.Rdi) != 0 || uc_reg_write(uc_x86, UC_X86_REG_ESI, &context.Rsi) != 0
		|| uc_reg_write(uc_x86, UC_X86_REG_ESP, &context.Rsp) != 0 || uc_reg_write(uc_x86, UC_X86_REG_EBP, &context.Rbp) != 0 || uc_reg_write(uc_x86, UC_X86_REG_EIP, &context.Rip) != 0)
		return false;

	if (uc_reg_write(uc_x86, UC_X86_REG_R8, &context.R8) != 0 || uc_reg_write(uc_x86, UC_X86_REG_R9, &context.R9) != 0 || uc_reg_write(uc_x86, UC_X86_REG_R10, &context.R10) != 0
		|| uc_reg_write(uc_x86, UC_X86_REG_R11, &context.R11) != 0 || uc_reg_write(uc_x86, UC_X86_REG_R12, &context.R12) != 0 || uc_reg_write(uc_x86, UC_X86_REG_R13, &context.R13) != 0
		|| uc_reg_write(uc_x86, UC_X86_REG_R14, &context.R14) != 0 || uc_reg_write(uc_x86, UC_X86_REG_R15, &context.R15) != 0)
		return false;

	unsigned long cs_86 = 0x33;
	if (uc_reg_write(uc_x86, UC_X86_REG_CS, &context.SegCs) != 0 || uc_reg_write(uc_x86, UC_X86_REG_DS, &context.SegDs) != 0 || uc_reg_write(uc_x86, UC_X86_REG_ES, &context.SegEs) != 0
		|| uc_reg_write(uc_x86, UC_X86_REG_FS, &context.SegFs) != 0 || uc_reg_write(uc_x86, UC_X86_REG_GS, &context.SegGs) != 0 || uc_reg_write(uc_x86, UC_X86_REG_SS, &context.SegSs) != 0)
		return false;

	uc_close(uc_x64);
	emulator_x64_ = nullptr;

	uc_hook hw;
	uc_hook hr;
	uc_hook_add((uc_engine *)emulator_x86_, &hw, UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmap_memory_x86, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add((uc_engine *)emulator_x86_, &hr, UC_HOOK_MEM_READ_UNMAPPED, hook_unmap_memory_x86, NULL, (uint64_t)1, (uint64_t)0);

	return true;
}