#define _CRT_SECURE_NO_WARNINGS

#include <uc\unicorn\unicorn.h>
#include <Windows.h>
#include <memory>
#include <WDBGEXTS.H>

#include "interface.h"
#include "windbg_linker.h"
#include "emulator.h"
///
/// global
///
std::shared_ptr<binary::debugger> emulator;
///
/// share
///
bool __stdcall print_register()
{
	CONTEXT context;
	memset(&context, 0, sizeof(context));

	if (!emulator->read_context(&context, sizeof(context)))
		return false;

	if (emulator->is_64())
	{
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
	}
	else
	{
		dprintf("eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", context.Rax, context.Rbx, context.Rcx, context.Rdx, context.Rsi, context.Rdi);
		dprintf("eip=%08x esp=%08x ebp=%08x\n", context.Rip, context.Rsp, context.Rbp);
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
		void *eip = (void *)context.Rip;

		Disasm(&context.Rip, mnemonic, 0);
		dprintf("%s\n", mnemonic);
	}

	return true;
}
///
/// exts
///
bool __stdcall attach_main(std::shared_ptr<binary::linker> windbg_linker, int argc, char(*argv)[MAX_ARGUMENT_LENGTH])
{
	char *end = nullptr;

	if (!binary::create<Wow64EmulationDebugger>(emulator))
		return false;

	if (!emulator->attach())
		return false;

	print_register();

	return true;
}

extern "C"
void __stdcall attach(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	std::shared_ptr<binary::linker> windbg_linker;
	char args[100][MAX_ARGUMENT_LENGTH];
	int argc = 0;

	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return;

	windbg_linker->setting(argument_string, &argc, args);
	attach_main(windbg_linker, argc, args);
}
///
///
///
extern "C"
void __stdcall trace(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	std::shared_ptr<binary::linker> windbg_linker;
	char args[100][MAX_ARGUMENT_LENGTH];
	int argc = 0;

	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return;

	windbg_linker->setting(argument_string, &argc, args);

	if (argc < 2)
	{
		if (emulator->trace())
			print_register();
	}
	else if (argc == 2)
	{
		char *end = nullptr;
		unsigned long break_point = strtol(args[1], &end, 16);
		unsigned long long eip = 0L;

		if (!strstr(args[0], "-r"))
			return;

		while (true)
		{
			if (!emulator->read_register(UC_X86_REG_EIP, &eip))
				break;
			if (eip == break_point)
				break;
			else
			{
				if (emulator->trace())
					print_register();
				else
				{
					dprintf("run fail..\n");
					break;
				}
			}
		}
	}
}
///
///
///
extern "C"
void __stdcall swch(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	if (!emulator->cpu_switch())
	{
		dprintf("fail\n");
	}
	else
	{
		if (emulator->is_64())
			dprintf("64bit\n");
		else
			dprintf("32bit\n");
	}
}
///
///
///
extern "C"
void __stdcall mov(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	std::shared_ptr<binary::linker> windbg_linker;
	char args[100][MAX_ARGUMENT_LENGTH];
	int argc = 0;
	char *end = nullptr;

	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return;

	windbg_linker->setting(argument_string, &argc, args);

	if (argc < 2)
		return;

	if (strstr(args[0], "eax") || strstr(args[0], "ebx") || strstr(args[0], "ecx") || strstr(args[0], "edx") || strstr(args[0], "esi") || strstr(args[0], "edi") || strstr(args[0], "ebp") || strstr(args[0], "esp" ) || strstr(args[0], "eip")
		// 64
		|| strstr(args[0], "rax") || strstr(args[0], "rbx") || strstr(args[0], "rcx") || strstr(args[0], "rdx") || strstr(args[0], "rsi") || strstr(args[0], "rdi") || strstr(args[0], "rsp") || strstr(args[0], "rbp") || strstr(args[0], "rip")
		|| strstr(args[0], "r8") || strstr(args[0], "r9") || strstr(args[0], "r10") || strstr(args[0], "r11") || strstr(args[0], "r12") || strstr(args[0], "r13") || strstr(args[0], "r14") || strstr(args[0], "r15"))
	{
		unsigned long long value = strtoll(args[1], &end, 16);
		dprintf("mov   %s,%llx\n", args[0], value);
		//emulator->write_register(args[0], value);
	}
}
///
///
///
extern "C"
void __stdcall regs(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	print_register();
}
///
///
///
extern "C"
void __stdcall link(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	std::shared_ptr<binary::linker> windbg_linker;
	char args[100][MAX_ARGUMENT_LENGTH];
	int argc = 0;
	char *end = nullptr;

	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return;

	windbg_linker->setting(argument_string, &argc, args);

	unsigned long long address = strtoll(args[0], &end, 16);
	dprintf("m=%llx\n", address);

	if(emulator->link(address))
		dprintf("link success\n");
}
///
///
///
extern "C"
void __stdcall check(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG64 dwCurrentPc, ULONG dwProcessor, PCSTR argument_string)
{
	std::shared_ptr<binary::linker> windbg_linker;
	char args[100][MAX_ARGUMENT_LENGTH];
	int argc = 0;
	char *end = nullptr;

	if (!binary::create<WindbgSafeLinker>(windbg_linker))
		return;

	windbg_linker->setting(argument_string, &argc, args);

	unsigned long long address = strtoll(args[0], &end, 16);

	if (!emulator->check(address))
		dprintf("read fail..\n");
	else
		dprintf("ok!\n");
}
