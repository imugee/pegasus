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
///
///
bool __stdcall Wow64EmulationDebugger::attach_x64()
{
	CONTEXT context;
	std::shared_ptr<binary::linker> windbg_linker;
	gdt_base_ = 0xc0000000;

	if(!binary::create<WindbgSafeLinker>(windbg_linker))
		return false;

	if (uc_open(UC_ARCH_X86, UC_MODE_64, (uc_engine **)&emulator_x64_) != 0)
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

	if (!create_global_descriptor_table(emulator_x64_, &context, sizeof(context)))
		return false;

	if (!write_x64_cpu_context(context))
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::mnemonic_mov_gs(unsigned long long ip)
{
	BYTE dump[1024];
	_DInst di;

	if (!read(ip, dump, 1024))
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[1].type != O_DISP || di.size != 9 || di.disp != 0x30)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	if (!write_register(distorm_to_uc[di.ops[0].index], teb_address_))
		return false;

	if (!write_register(UC_X86_REG_EIP, ip + di.size))
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::mnemonic_mov_ss(unsigned long long ip)
{
	BYTE dump[1024];
	_DInst di;

	if (!read(ip, dump, 1024))
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[0].index != R_SS || di.size != 3)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	if (!write_register(distorm_to_uc[di.ops[1].index], 0x88))
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::mnemonic_wow_ret(unsigned long long ip)
{
	BYTE dump[1024];
	_DInst di;

	if (!read(ip, dump, 1024))
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_JMP_FAR || di.ops[0].type != O_SMEM || di.size != 3)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	unsigned long long return_register = 0;
	if (!read_register(distorm_to_uc[di.ops[0].index], &return_register))
		return false;

	unsigned long value = 0;
	if (!read(return_register, &value, sizeof(value)))
		return false;

	if (!switch_x86())
		return false;

	if(!write_register(UC_X86_REG_EIP, value))
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::trace_x64()
{
	if (!emulator_x64_)
		return false;

	uc_engine *uc = (uc_engine *)emulator_x64_;
	unsigned long long eip = 0L;
	memset(&eip, 0, sizeof(eip));

	if (uc_reg_read(uc, UC_X86_REG_RIP, &eip) != 0)
		return false;

	uc_err err;
	if ((err = uc_emu_start(uc, eip, eip + 0x1000, 0, 1)) != 0)
	{
		if (mnemonic_mov_gs(eip))
			return true;

		if(mnemonic_mov_ss(eip))
			return true;

		if(mnemonic_wow_ret(eip))
			return true;
		//dprintf("err:: %d\n", err);
		return false;
	}

	return true;
}

bool __stdcall Wow64EmulationDebugger::read_x64_cpu_context(CONTEXT *context)
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

	uc_engine *uc = (uc_engine *)emulator_x64_;
	if (uc_reg_read_batch(uc, x86_register, read_ptr, size) != 0)
		return false;

	context->Rax = read_register[PR_RAX];
	context->Rbx = read_register[PR_RBX];
	context->Rcx = read_register[PR_RCX];
	context->Rdx = read_register[PR_RDX];
	context->Rsi = read_register[PR_RSI];
	context->Rdi = read_register[PR_RDI];
	context->Rsp = read_register[PR_RSP];
	context->Rbp = read_register[PR_RBP];
	context->Rip = read_register[PR_RIP];
	context->R8 = read_register[PR_R8];
	context->R9 = read_register[PR_R9];
	context->R10 = read_register[PR_R10];
	context->R11 = read_register[PR_R11];
	context->R12 = read_register[PR_R12];
	context->R13 = read_register[PR_R13];
	context->R14 = read_register[PR_R14];
	context->R15 = read_register[PR_R15];
	context->EFlags = (unsigned long)read_register[PR_EFLAGS];
	context->SegCs = (unsigned short)read_register[PR_REG_CS];
	context->SegDs = (unsigned short)read_register[PR_REG_DS];
	context->SegEs = (unsigned short)read_register[PR_REG_ES];
	context->SegFs = (unsigned short)read_register[PR_REG_FS];
	context->SegGs = (unsigned short)read_register[PR_REG_GS];
	context->SegSs = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool __stdcall Wow64EmulationDebugger::write_x64_cpu_context(CONTEXT context)
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

	write_register[PR_RAX] = context.Rax;
	write_register[PR_RBX] = context.Rbx;
	write_register[PR_RCX] = context.Rcx;
	write_register[PR_RDX] = context.Rdx;
	write_register[PR_RSI] = context.Rsi;
	write_register[PR_RDI] = context.Rdi;
	write_register[PR_RSP] = context.Rsp;
	write_register[PR_RBP] = context.Rbp;
	write_register[PR_R8] = context.R8;
	write_register[PR_R9] = context.R9;
	write_register[PR_R10] = context.R10;
	write_register[PR_R11] = context.R11;
	write_register[PR_R12] = context.R12;
	write_register[PR_R13] = context.R13;
	write_register[PR_R14] = context.R14;
	write_register[PR_R15] = context.R15;
	write_register[PR_EFLAGS] = (unsigned long)context.EFlags;
	write_register[PR_REG_CS] = context.SegCs;
	write_register[PR_REG_DS] = context.SegDs;
	write_register[PR_REG_ES] = context.SegEs;
	write_register[PR_REG_FS] = context.SegFs;
	write_register[PR_REG_GS] = context.SegGs;
	write_register[PR_REG_SS] = context.SegSs;

	uc_engine *uc = (uc_engine *)emulator_x64_;
	if (uc_reg_write_batch(uc, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::switch_x64()
{
	x64_flag_ = true;

	if (!emulator_x86_)
		return false;

	if (emulator_x64_)
		uc_close((uc_engine *)emulator_x64_);

	if (uc_open(UC_ARCH_X86, UC_MODE_64, (uc_engine **)&emulator_x64_) != 0)
		return false;

	uc_engine *uc_x86 = (uc_engine *)emulator_x86_;
	uc_engine *uc_x64 = (uc_engine *)emulator_x64_;
	uc_mem_region *x86_um = nullptr;
	uint32_t x86_count = 0;
	uint32_t count = 0;

	if (uc_mem_regions(uc_x86, &x86_um, &x86_count) != 0)
		return false;

	for (unsigned int i = 0; i < x86_count; ++i)
	{
		size_t size = (x86_um[i].end + 1) - x86_um[i].begin;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
			break;

		if (uc_mem_read(uc_x86, x86_um[i].begin, dump, size) != 0)
			break;

		if (!load(x86_um[i].begin, size, dump, size))
			break;

		free(dump);
		++count;
	}
	free(x86_um);

	if (x86_count != count)
		return false;

	CONTEXT context;
	memset(&context, 0, sizeof(context));

	if (!read_x86_cpu_context(&context))
		return false;

	context.SegCs = 0x33;
	if (!create_global_descriptor_table(uc_x64, &context, sizeof(context)))
		return false;

	std::shared_ptr<binary::linker> windbg_linker;
	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return false;

	CONTEXT x64_context;
	memset(&x64_context, 0, sizeof(x64_context));

	if(!windbg_linker->get_context(&x64_context, sizeof(x64_context)))
		return false;

	context.R8 = x64_context.R8;
	context.R9 = x64_context.R9;
	context.R10 = x64_context.R10;
	context.R11 = x64_context.R11;
	context.R12 = x64_context.R12;
	context.R13 = x64_context.R13;
	context.R14 = x64_context.R14;
	context.R15 = x64_context.R15;

	if (!write_x64_cpu_context(context))
		return false;

	uc_close(uc_x86);
	emulator_x86_ = nullptr;

	return true;
}
