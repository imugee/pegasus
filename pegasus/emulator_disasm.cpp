#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>
#include <engextcpp.hpp>
#include <memory>
#include <list>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

#include <distorm/include/distorm.h>
#include <distorm/include/mnemonics.h>

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

bool __stdcall emulation_debugger::mnemonic_mov_gs(void *engine)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

#ifdef _WIN64
	if (uc_mem_read(uc, context_.Rip, dump, 1024) != 0)
#else
	if (uc_mem_read(uc, context_.Eip, dump, 1024) != 0)
#endif
		return false;

	if (!disasm((PVOID)dump, 64, Decode64Bits, &di))
		return false;

	if (di.opcode != I_MOV || di.ops[0].type != O_REG || di.ops[1].type != O_DISP || di.size != 9 || di.disp != 0x30)
		return false;

	unsigned int distorm_to_uc[] = { DISTORM_TO_UC_REGS };

	if (uc_reg_write(uc, distorm_to_uc[di.ops[0].index], &teb_64_address_) != 0)
		return false;

#ifdef _WIN64
	context_.Rip = context_.Rip + di.size;
#else
	context_.Eip = context_.Eip + di.size;
#endif

	return true;
}

bool __stdcall emulation_debugger::mnemonic_mov_ss(void *engine)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

#ifdef _WIN64
	if (uc_mem_read(uc, context_.Rip, dump, 1024) != 0)
#else
	if (uc_mem_read(uc, context_.Eip, dump, 1024) != 0)
#endif
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

bool __stdcall emulation_debugger::mnemonic_wow_ret(void *engine, trace_item item, void *new_engine)
{
	BYTE dump[1024];
	_DInst di;
	uc_engine *uc = (uc_engine *)engine;

#ifdef _WIN64
	if (uc_mem_read(uc, context_.Rip, dump, 1024) != 0)
#else
	if (uc_mem_read(uc, context_.Eip, dump, 1024) != 0)
#endif
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

#ifdef _WIN64
	context_.Rip = value;
#else
	context_.Eip = value;
#endif
	is_64_ = false;
	//
	//
	//
	if (!backup(uc))
		return false;

	uc_close(uc);
	if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != 0)
		return false;

	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;

	uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item.unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item.unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item.fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	if (!load_gdt(uc))
		return false;

	if (!load_context(uc, UC_MODE_32))
		return false;

	g_Ext->ExecuteSilent("!wow64exts.sw");
	*(uc_engine **)new_engine = uc;
	//
	//
	//
	return true;
}

bool __stdcall emulation_debugger::mnemonic_switch_wow64cpu(void *engine, trace_item item, void *new_engine)
{
	uc_engine *uc = (uc_engine *)engine;
	unsigned char dump[16] = { 0, };

#ifdef _WIN64
	if (uc_mem_read(uc, context_.Rip, dump, 16) == 0 && dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0)
#else
	if (uc_mem_read(uc, context_.Eip, dump, 16) == 0 && dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0)
#endif
	{
		unsigned long *syscall_ptr = (unsigned long *)(&dump[1]);
		unsigned long syscall = *syscall_ptr;

		is_64_ = true;
#ifdef _WIN64
		context_.Rip = syscall;
#else
		context_.Eip = syscall;
#endif
		//
		//
		//
		if (!backup(uc))
			return false;

		uc_close(uc);
		if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != 0)
			return false;

		uc_hook write_unmap_hook;
		uc_hook read_unmap_hook;
		uc_hook fetch_hook;

		uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item.unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
		uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item.unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
		uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item.fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

		if (!load_gdt(uc))
			return false;

		if (!load_context(uc, UC_MODE_64))
			return false;

		g_Ext->ExecuteSilent("!wow64exts.sw");
		*(uc_engine **)new_engine = uc;
		//
		//
		//
		return true;
	}

	return false;
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
//
//	https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/customizing-debugger-output-using-dml
//
void __stdcall emulation_debugger::print_code(unsigned long long ip, unsigned long line)
{
#ifdef _WIN64
	unsigned long long index = ip;
#else
	unsigned long index = context_.Eip;
#endif
	_DInst di;
	unsigned char dump[32] = { 0, };

	windbg_linker_.clear_screen();

	di.size = 0;
	for (unsigned int i = 0; i < line; ++i)
		index = before(index);

	char mnemonic[1024] = { 0, };
	unsigned long size = 0;
	unsigned long long next = 0;

	dprintf("\n");
	for(unsigned int i = 0; i<(line * 2 + 1); ++i)
	{
		if (g_Ext->m_Control->Disassemble(index, DEBUG_DISASM_EFFECTIVE_ADDRESS, mnemonic, 1024, &size, &next) == S_OK)
		{
			if(index == context_.Rip)
				g_Ext->Dml("<b><col fg=\"emphfg\">	%s</col></b>", mnemonic);
			else
				dprintf("	%s", mnemonic);
		}

		index = next;
	}
	dprintf("\n");
	//print_register();
}