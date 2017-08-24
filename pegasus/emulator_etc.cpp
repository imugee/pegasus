#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>
#include <engextcpp.hpp>
#include <memory>
#include <list>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

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

CONTEXT __stdcall emulation_debugger::current_thread_context()
{
	return context_;
}

bool __stdcall emulation_debugger::is_64_cpu()
{
	return is_64_;
}

void __stdcall emulation_debugger::current_regs()
{
	//print_register();
}

void __stdcall emulation_debugger::log_print()
{
	CONTEXT context = context_;

	if (is_64_cpu())
	{
#ifdef _WIN64
		dprintf("	rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x\n", 16, context.Rax, 16, context.Rbx, 16, context.Rcx, 16, context.Rdx);
	dprintf("	rsi=%0*I64x rdi=%0*I64x\n", 16, context.Rsi, 16, context.Rdi);
	dprintf("	rsp=%0*I64x rbp=%0*I64x\n", 16, context.Rsp, 16, context.Rbp);
	dprintf("	rip=%0*I64x\n", 16, context.Rip);
	dprintf("\n");
	dprintf("	r8=%0*I64x r9=%0*I64x r10=%0*I64x\n", 16, context.R8, 16, context.R9, 16, context.R10);
	dprintf("	r11=%0*I64x r12=%0*I64x r13=%0*I64x\n", 16, context.R11, 16, context.R12, 16, context.R13);
	dprintf("	r14=%0*I64x r15=%0*I64x\n", 16, context.R14, 16, context.R15);
	dprintf("	efl=%0*I64x\n", 16, context.EFlags);
	dprintf("	CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d%d NT=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
		, GetFlagBit(context.EFlags, CF_INDEX), GetFlagBit(context.EFlags, PF_INDEX)
		, GetFlagBit(context.EFlags, AF_INDEX), GetFlagBit(context.EFlags, ZF_INDEX)
		, GetFlagBit(context.EFlags, SF_INDEX), GetFlagBit(context.EFlags, TF_INDEX)
		, GetFlagBit(context.EFlags, IF_INDEX), GetFlagBit(context.EFlags, DF_INDEX)
		, GetFlagBit(context.EFlags, OF_INDEX), GetFlagBit(context.EFlags, IOPL_INDEX_1), GetFlagBit(context.EFlags, IOPL_INDEX_2)
		, GetFlagBit(context.EFlags, NT_INDEX), GetFlagBit(context.EFlags, RF_INDEX), GetFlagBit(context.EFlags, VM_INDEX)
		, GetFlagBit(context.EFlags, AC_INDEX), GetFlagBit(context.EFlags, VIF_INDEX), GetFlagBit(context.EFlags, VIP_INDEX), GetFlagBit(context.EFlags, ID_INDEX));
	dprintf("	cs=%02x ds=%02x es=%02x fs=%02x gs=%02x ss=%02x\n", context.SegCs, context.SegDs, context.SegEs, context.SegFs, context.SegGs, context.SegSs);
#endif
	}
	else
	{
#ifdef _WIN64
		dprintf("	eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Rax, context.Rbx, context.Rcx, context.Rdx, context.Rsi, context.Rdi);
		dprintf("	eip=%08x esp=%08x ebp=%08x efl=%08x\n", context.Rip, context.Rsp, context.Rbp, context.EFlags);
#else
		dprintf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esi, context.Edi);
		dprintf("eip=%08x esp=%08x ebp=%08x efl=%08x\n", context.Eip, context.Esp, context.Ebp, context.EFlags);
#endif
		dprintf("	CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d%d NT=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
			, GetFlagBit(context.EFlags, CF_INDEX), GetFlagBit(context.EFlags, PF_INDEX)
			, GetFlagBit(context.EFlags, AF_INDEX), GetFlagBit(context.EFlags, ZF_INDEX)
			, GetFlagBit(context.EFlags, SF_INDEX), GetFlagBit(context.EFlags, TF_INDEX)
			, GetFlagBit(context.EFlags, IF_INDEX), GetFlagBit(context.EFlags, DF_INDEX)
			, GetFlagBit(context.EFlags, OF_INDEX), GetFlagBit(context.EFlags, IOPL_INDEX_1), GetFlagBit(context.EFlags, IOPL_INDEX_2)
			, GetFlagBit(context.EFlags, NT_INDEX), GetFlagBit(context.EFlags, RF_INDEX), GetFlagBit(context.EFlags, VM_INDEX)
			, GetFlagBit(context.EFlags, AC_INDEX), GetFlagBit(context.EFlags, VIF_INDEX), GetFlagBit(context.EFlags, VIP_INDEX), GetFlagBit(context.EFlags, ID_INDEX));
		dprintf("	cs=%02x ss=%02x ds=%02x es=%02x fs=%02x gs=%02x\n", context.SegCs, context.SegSs, context.SegDs, context.SegEs, context.SegFs, context.SegGs);
	}

	char mnemonic[1024] = { 0, };
	void *eip = (void *)context.Rip;

	Disasm(&context.Rip, mnemonic, 0);
	dprintf("	%s\n", mnemonic);
}

void __stdcall emulation_debugger::print64(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"emphfg\">%0*I64x</col></b>", 16, c);
	else
		dprintf("%0*I64x", 16, c);
}

void __stdcall emulation_debugger::print32(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"emphfg\">%08x</col></b>", c);
	else
		dprintf("%08x", c);
}

#ifdef _WIN64
void __stdcall emulation_debugger::clear_and_print()
{
	print_code(context_.Rip, 10);

	if (is_64_cpu())
	{
		dprintf("	rax="), print64(context_.Rax, backup_context_.Rax), dprintf(" ");
		dprintf("rbx="), print64(context_.Rbx, backup_context_.Rbx), dprintf(" ");
		dprintf("rcx="), print64(context_.Rcx, backup_context_.Rcx), dprintf("\n");

		dprintf("	rdx="), print64(context_.Rdx, backup_context_.Rdx), dprintf(" ");
		dprintf("rsi="), print64(context_.Rsi, backup_context_.Rsi), dprintf(" ");
		dprintf("rdi="), print64(context_.Rdi, backup_context_.Rdi), dprintf("\n");

		dprintf("	rip="), print64(context_.Rip, backup_context_.Rip), dprintf(" ");
		dprintf("rsp="), print64(context_.Rsp, backup_context_.Rsp), dprintf(" ");
		dprintf("rbp="), print64(context_.Rbp, backup_context_.Rbp), dprintf("\n");

		dprintf("	r8="), print64(context_.R8, backup_context_.R8), dprintf(" ");
		dprintf("r9="), print64(context_.R9, backup_context_.R9), dprintf(" ");
		dprintf("r10="), print64(context_.R10, backup_context_.R10), dprintf("\n");

		dprintf("	r11="), print64(context_.R11, backup_context_.R11), dprintf(" ");
		dprintf("r12="), print64(context_.R12, backup_context_.R12), dprintf(" ");
		dprintf("r13="), print64(context_.R13, backup_context_.R13), dprintf("\n");

		dprintf("	r14="), print64(context_.R14, backup_context_.R14), dprintf(" ");
		dprintf("r15="), print64(context_.R15, backup_context_.R15), dprintf(" ");
		dprintf("efl="), print32(context_.EFlags, backup_context_.EFlags), dprintf("\n");
	}
	else
	{
		dprintf("	eax="), print32(context_.Rax, backup_context_.Rax), dprintf(" ");
		dprintf("ebx="), print32(context_.Rbx, backup_context_.Rbx), dprintf(" ");
		dprintf("ecx="), print32(context_.Rcx, backup_context_.Rcx), dprintf(" ");
		dprintf("edx="), print32(context_.Rdx, backup_context_.Rdx), dprintf(" ");
		dprintf("esi="), print32(context_.Rsi, backup_context_.Rsi), dprintf(" ");
		dprintf("edi="), print32(context_.Rdi, backup_context_.Rdi), dprintf("\n");

		dprintf("	eip="), print32(context_.Rip, backup_context_.Rip), dprintf(" ");
		dprintf("esp="), print32(context_.Rsp, backup_context_.Rsp), dprintf(" ");
		dprintf("ebp="), print32(context_.Rbp, backup_context_.Rbp), dprintf(" ");
		dprintf("efl="), print32(context_.EFlags, backup_context_.EFlags), dprintf("\n");
	}
}
#endif

void * __stdcall emulation_debugger::get_windbg_linker()
{
	return &windbg_linker_;
}