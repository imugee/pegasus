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

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RAX, &context.Rax) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RBX, &context.Rbx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RCX, &context.Rcx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RDX, &context.Rdx) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RSI, &context.Rsi) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RDI, &context.Rdi) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RSP, &context.Rsp) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RBP, &context.Rbp) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_RIP, &context.Rip) != 0)
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
	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_CS, &context.SegCs) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_SS, &context.SegSs) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_DS, &context.SegDs) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_ES, &context.SegEs) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_FS, &context.SegFs) != 0)
		return false;

	if (uc_reg_write((uc_engine *)emulator_x86_, UC_X86_REG_GS, &context.SegGs) != 0)
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

	char *reg[16] = { "rax", "rcx" , "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
	if(!write_register(reg[di.ops[0].index], teb_address_))
		return false;

	if (!write_register("rip", ip + di.size))
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

	char *reg[48] = { "rax", "rcx" , "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
		, "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
		, "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
	if (!write_register(reg[di.ops[1].index], 0x88))
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

	char *reg[48] = { "rax", "rcx" , "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
		, "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
		, "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

	unsigned long long return_register = 0;
	if (!read_register(reg[di.ops[0].index], &return_register))
		return false;

	unsigned long value = 0;
	if (!read(return_register, &value, sizeof(value)))
		return false;

	if (!switch_x86())
		return false;

	if(!write_register("eip", value))
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

bool __stdcall Wow64EmulationDebugger::read_context_x64(CONTEXT *context)
{
	if (!emulator_x64_)
		return false;

	uc_engine *uc = (uc_engine *)emulator_x64_;

	if (uc_reg_read(uc, UC_X86_REG_RAX, &context->Rax) != 0 || uc_reg_read(uc, UC_X86_REG_RBX, &context->Rbx) != 0 || uc_reg_read(uc, UC_X86_REG_RCX, &context->Rcx) != 0
		|| uc_reg_read(uc, UC_X86_REG_RDX, &context->Rdx) != 0 || uc_reg_read(uc, UC_X86_REG_RDI, &context->Rdi) != 0 || uc_reg_read(uc, UC_X86_REG_RSI, &context->Rsi) != 0
		|| uc_reg_read(uc, UC_X86_REG_RSP, &context->Rsp) != 0 || uc_reg_read(uc, UC_X86_REG_RBP, &context->Rbp) != 0 || uc_reg_read(uc, UC_X86_REG_RIP, &context->Rip) != 0)
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

	if (!read_context_x86(&context))
		return false;

	if (!create_global_descriptor_table(uc_x64, &context, sizeof(context)))
		return false;
	///
	///
	///
	unsigned long cs_64 = 0x33;
	if (uc_reg_write(uc_x64, UC_X86_REG_RAX, &context.Rax) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RBX, &context.Rbx) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RCX, &context.Rcx) != 0
		|| uc_reg_write(uc_x64, UC_X86_REG_RDX, &context.Rdx) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RDI, &context.Rdi) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RSI, &context.Rsi) != 0
		|| uc_reg_write(uc_x64, UC_X86_REG_RSP, &context.Rsp) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RBP, &context.Rbp) != 0 || uc_reg_write(uc_x64, UC_X86_REG_RIP, &context.Rip) != 0)
		return false;

	if (uc_reg_write(uc_x64, UC_X86_REG_CS, &cs_64) != 0 || uc_reg_write(uc_x64, UC_X86_REG_DS, &context.SegDs) != 0 || uc_reg_write(uc_x64, UC_X86_REG_ES, &context.SegEs) != 0
		|| uc_reg_write(uc_x64, UC_X86_REG_FS, &context.SegFs) != 0 || uc_reg_write(uc_x64, UC_X86_REG_GS, &context.SegGs) != 0 || uc_reg_write(uc_x64, UC_X86_REG_SS, &context.SegSs) != 0)
		return false;
	///
	///
	///
	std::shared_ptr<binary::linker> windbg_linker;
	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return false;

	if(!windbg_linker->get_context(&context, sizeof(context)))
		return false;

	if (uc_reg_write(uc_x64, UC_X86_REG_R8, &context.R8) != 0 || uc_reg_write(uc_x64, UC_X86_REG_R9, &context.R9) != 0 || uc_reg_write(uc_x64, UC_X86_REG_R10, &context.R10) != 0
		|| uc_reg_write(uc_x64, UC_X86_REG_R11, &context.R11) != 0 || uc_reg_write(uc_x64, UC_X86_REG_R12, &context.R12) != 0 || uc_reg_write(uc_x64, UC_X86_REG_R13, &context.R13) != 0
		|| uc_reg_write(uc_x64, UC_X86_REG_R14, &context.R14) != 0 || uc_reg_write(uc_x64, UC_X86_REG_R15, &context.R15) != 0)
		return false;

	uc_close(uc_x86);
	emulator_x86_ = nullptr;

	return true;
}