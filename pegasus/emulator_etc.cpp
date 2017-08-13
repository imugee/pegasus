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
	print_register();
}

void __stdcall emulation_debugger::print_register()
{
	CONTEXT context = context_;

	if (is_64_cpu())
	{
#ifdef _WIN64
		dprintf("rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x\n", 16, context.Rax, 16, context.Rbx, 16, context.Rcx, 16, context.Rdx);
		dprintf("rsi=%0*I64x rdi=%0*I64x\n", 16, context.Rsi, 16, context.Rdi);
		dprintf("rsp=%0*I64x rbp=%0*I64x\n", 16, context.Rsp, 16, context.Rbp);
		dprintf("rip=%0*I64x\n", 16, context.Rip);
		dprintf("\n");
		dprintf("r8=%0*I64x r9=%0*I64x r10=%0*I64x\n", 16, context.R8, 16, context.R9, 16, context.R10);
		dprintf("r11=%0*I64x r12=%0*I64x r13=%0*I64x\n", 16, context.R11, 16, context.R12, 16, context.R13);
		dprintf("r14=%0*I64x r15=%0*I64x\n", 16, context.R14, 16, context.R15);
		dprintf("efl=%0*I64x\n", 16, context.EFlags);
		dprintf("CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d%d NT=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
			, GetFlagBit(context.EFlags, CF_INDEX), GetFlagBit(context.EFlags, PF_INDEX)
			, GetFlagBit(context.EFlags, AF_INDEX), GetFlagBit(context.EFlags, ZF_INDEX)
			, GetFlagBit(context.EFlags, SF_INDEX), GetFlagBit(context.EFlags, TF_INDEX)
			, GetFlagBit(context.EFlags, IF_INDEX), GetFlagBit(context.EFlags, DF_INDEX)
			, GetFlagBit(context.EFlags, OF_INDEX), GetFlagBit(context.EFlags, IOPL_INDEX_1), GetFlagBit(context.EFlags, IOPL_INDEX_2)
			, GetFlagBit(context.EFlags, NT_INDEX), GetFlagBit(context.EFlags, RF_INDEX), GetFlagBit(context.EFlags, VM_INDEX)
			, GetFlagBit(context.EFlags, AC_INDEX), GetFlagBit(context.EFlags, VIF_INDEX), GetFlagBit(context.EFlags, VIP_INDEX), GetFlagBit(context.EFlags, ID_INDEX));
		dprintf("cs=%02x ds=%02x es=%02x fs=%02x gs=%02x ss=%02x\n", context.SegCs, context.SegDs, context.SegEs, context.SegFs, context.SegGs, context.SegSs);

		char mnemonic[1024] = { 0, };
		void *eip = (void *)context.Rip;

		Disasm(&context.Rip, mnemonic, 0);
		dprintf("%s\n", mnemonic);
#endif
	}
	else
	{
#ifdef _WIN64
		dprintf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Rax, context.Rbx, context.Rcx, context.Rdx, context.Rsi, context.Rdi);
		dprintf("eip=%08x esp=%08x ebp=%08x\n", context.Rip, context.Rsp, context.Rbp);
#else
		dprintf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Eax, context.Ebx, context.Ecx, context.Edx, context.Esi, context.Edi);
		dprintf("eip=%08x esp=%08x ebp=%08x\n", context.Eip, context.Esp, context.Ebp);
#endif
		dprintf("efl=%08x ", context.EFlags);
		dprintf("CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d%d NT=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d\n"
			, GetFlagBit(context.EFlags, CF_INDEX), GetFlagBit(context.EFlags, PF_INDEX)
			, GetFlagBit(context.EFlags, AF_INDEX), GetFlagBit(context.EFlags, ZF_INDEX)
			, GetFlagBit(context.EFlags, SF_INDEX), GetFlagBit(context.EFlags, TF_INDEX)
			, GetFlagBit(context.EFlags, IF_INDEX), GetFlagBit(context.EFlags, DF_INDEX)
			, GetFlagBit(context.EFlags, OF_INDEX), GetFlagBit(context.EFlags, IOPL_INDEX_1), GetFlagBit(context.EFlags, IOPL_INDEX_2)
			, GetFlagBit(context.EFlags, NT_INDEX), GetFlagBit(context.EFlags, RF_INDEX), GetFlagBit(context.EFlags, VM_INDEX)
			, GetFlagBit(context.EFlags, AC_INDEX), GetFlagBit(context.EFlags, VIF_INDEX), GetFlagBit(context.EFlags, VIP_INDEX), GetFlagBit(context.EFlags, ID_INDEX));
		dprintf("cs=%02x ss=%02x ds=%02x es=%02x fs=%02x gs=%02x\n", context.SegCs, context.SegSs, context.SegDs, context.SegEs, context.SegFs, context.SegGs);

		char mnemonic[1024] = { 0, };

#ifdef _WIN64
		Disasm(&context.Rip, mnemonic, 0);
#else
		Disasm((unsigned long long *)&context.Eip, mnemonic, 0);
#endif
		dprintf("%s\n", mnemonic);
	}
}

void * __stdcall emulation_debugger::get_windbg_linker()
{
	return &windbg_linker_;
}