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
//
//
//
emulation_debugger::~emulation_debugger()
{
	if (engine_)
	{
		uc_engine *uc = (uc_engine *)engine_;
		uc_close(uc);
	}
}

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
	set_global_descriptor(&global_descriptor[context_.SegFs >> 3], (unsigned long)teb_address_, 0xfff, 0);
	set_global_descriptor(&global_descriptor[context_.SegGs >> 3], (unsigned long)teb_64_address_, 0xfffff000, 0);
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
///
///
///
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

#ifdef _WIN64
	context_.Rax = read_register[PR_RAX];
	context_.Rbx = read_register[PR_RBX];
	context_.Rcx = read_register[PR_RCX];
	context_.Rdx = read_register[PR_RDX];
	context_.Rsi = read_register[PR_RSI];
	context_.Rdi = read_register[PR_RDI];
	context_.Rsp = read_register[PR_RSP];
	context_.Rbp = read_register[PR_RBP];
	context_.Rip = read_register[PR_RIP];
#else
	context_.Eax = read_register[PR_RAX];
	context_.Ebx = read_register[PR_RBX];
	context_.Ecx = read_register[PR_RCX];
	context_.Edx = read_register[PR_RDX];
	context_.Esi = read_register[PR_RSI];
	context_.Edi = read_register[PR_RDI];
	context_.Esp = read_register[PR_RSP];
	context_.Ebp = read_register[PR_RBP];
	context_.Eip = read_register[PR_RIP];
#endif
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

#ifdef _WIN64
	write_register[PR_RAX] = (unsigned long)context_.Rax;
	write_register[PR_RBX] = (unsigned long)context_.Rbx;
	write_register[PR_RCX] = (unsigned long)context_.Rcx;
	write_register[PR_RDX] = (unsigned long)context_.Rdx;
	write_register[PR_RSI] = (unsigned long)context_.Rsi;
	write_register[PR_RDI] = (unsigned long)context_.Rdi;
	write_register[PR_RSP] = (unsigned long)context_.Rsp;
	write_register[PR_RBP] = (unsigned long)context_.Rbp;
	write_register[PR_RIP] = (unsigned long)context_.Rip;
#else
	write_register[PR_RAX] = (unsigned long)context_.Eax;
	write_register[PR_RBX] = (unsigned long)context_.Ebx;
	write_register[PR_RCX] = (unsigned long)context_.Ecx;
	write_register[PR_RDX] = (unsigned long)context_.Edx;
	write_register[PR_RSI] = (unsigned long)context_.Esi;
	write_register[PR_RDI] = (unsigned long)context_.Edi;
	write_register[PR_RSP] = (unsigned long)context_.Esp;
	write_register[PR_RBP] = (unsigned long)context_.Ebp;
	write_register[PR_RIP] = (unsigned long)context_.Eip;
#endif
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
#endif
	return true;
}
//
//
//
void __stdcall emulation_debugger::install()
{
	wmemset(ring0_path_, 0, MAX_PATH);
	wmemset(ring3_path_, 0, MAX_PATH);
	wmemset(log_path_, 0, MAX_PATH);

	GetCurrentDirectory(MAX_PATH, ring0_path_);
	StringCbCat(ring0_path_, MAX_PATH, L"\\ring0");
	CreateDirectory(ring0_path_, FALSE);

	StringCbCopy(log_path_, MAX_PATH, ring0_path_);

	StringCbCopy(ring3_path_, MAX_PATH, ring0_path_);
	StringCbCat(ring3_path_, MAX_PATH, L"\\ring3");
	CreateDirectory(ring3_path_, FALSE);
}

bool __stdcall emulation_debugger::setup()
{
	if (!windbg_linker_.get_context(&context_, sizeof(context_)))
		return false;
#ifdef _WIN64
	if(!write_binary(context_.Rip)) // code
		return false;

	if (!write_binary(context_.Rsp)) // stack
		return false;
#else
	if (!write_binary(context_.Eip)) // code
		return false;

	if (!write_binary(context_.Esp)) // stack
		return false;
#endif

	if (!write_binary(teb_address_))
		return false;

	gdt_base_ = 0xc0000000;
	if (!create_global_descriptor_table())
		return false;

	return true;
}

bool __stdcall emulation_debugger::load_gdt(void *engine)
{
	emulation_debugger::page gdt_page;
	unsigned char * gdt_dump = nullptr;

	gdt_dump = load_page(gdt_base_, &gdt_page.base, &gdt_page.size);
	if (!gdt_dump) return false;
	std::shared_ptr<void> gdt_dump_closer(gdt_dump, free);

	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write((uc_engine *)engine, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load(engine, gdt_page.base, 0x10000, gdt_dump, gdt_page.size))
		return false;

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

bool __stdcall emulation_debugger::attach()
{
	bool is_32 = false;

	if (is_wow64cpu() && g_Ext->IsCurMachine64())
		g_Ext->ExecuteSilent("!wow64exts.sw");

	if (g_Ext->IsCurMachine32())
	{
		is_32 = true;
		g_Ext->ExecuteSilent("!wow64exts.sw");
	}
	else
		is_64_ = true;

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

	install();
	if(!setup())
		return false;

	if (is_32)
		g_Ext->ExecuteSilent("!wow64exts.sw");

	return true;
}

bool __stdcall emulation_debugger::trace(void *engine, trace_item item)
{
	uc_err err = (uc_err)0;
	uc_engine *uc = (uc_engine *)engine;
	BYTE dump[1024];
	_DInst di;
#ifdef _WIN64
	unsigned long long end_point = context_.Rip + 0x1000;
#else
	unsigned long long end_point = context_.Eip + 0x1000;
#endif
	unsigned long step = 1;

#ifdef _WIN64
	if (windbg_linker_.read_memory(context_.Rip, dump, 1024) && disasm((PVOID)dump, 64, Decode64Bits, &di))
#else
	if (windbg_linker_.read_memory(context_.Eip, dump, 1024) && disasm((PVOID)dump, 64, Decode64Bits, &di))
#endif
	{
		if (item.break_point)
		{
			end_point = item.break_point;
			step = 0;
		}
#ifdef _WIN64
		err = uc_emu_start(uc, context_.Rip, end_point, 0, step);
#else
		err = uc_emu_start(uc, context_.Eip, end_point, 0, step);
#endif
		if (err)
		{
			if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED)
			{
				unsigned restart_count = 0;

				do
				{
#ifdef _WIN64
					err = uc_emu_start(uc, context_.Rip, end_point, 0, step);
#else
					err = uc_emu_start(uc, context_.Eip, end_point, 0, step);
#endif
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
		//dprintf("break::e::%d\n", err);

		return false;
	}

	return true;
}

bool __stdcall emulation_debugger::trace(void *mem)
{
	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;
	uc_engine *uc = nullptr;
	trace_item *item = (trace_item *)mem;
	bool s = true;

	if (!engine_)
	{
		if (uc_open(UC_ARCH_X86, (uc_mode)item->mode, &uc) != 0)
			return false;
		//std::shared_ptr<void> uc_closer(uc, uc_close);

		uc_hook_add(uc, &code_hook, UC_HOOK_CODE, item->code_callback, NULL, (uint64_t)1, (uint64_t)0);
		uc_hook_add(uc, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
		uc_hook_add(uc, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, item->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
		uc_hook_add(uc, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, item->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

		if (!load_gdt(uc) || !load_context(uc, item->mode))
			return false;

		engine_ = uc;
	}
	else
	{
		uc = (uc_engine *)engine_;
	}
	
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
//
// exception mnemonic
//
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
#ifdef _WIN64
	context_.Rip = ip + di.size;
	if (uc_reg_write(uc, UC_X86_REG_RIP, &context_.Rip) != 0)
#else
	context_.Eip = ip + di.size;
	if (uc_reg_write(uc, UC_X86_REG_RIP, &context_.Eip) != 0)
#endif
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

	return true;
}

bool __stdcall emulation_debugger::mnemonic_switch_wow64cpu(void *engine)
{
	uc_engine *uc = (uc_engine *)engine;
	unsigned char dump[16] = { 0, };

#ifdef _WIN64
	if ((uc_mem_read(uc, context_.Rip, dump, 16) == 0) && (dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0))
#else
	if ((uc_mem_read(uc, context_.Eip, dump, 16) == 0) && (dump[0] == 0xea && dump[5] == 0x33 && dump[6] == 0))
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
		return true;
	}

	return false;
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
		if(Disasm(&next, mnemonic, 0))
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
//
// segment manager
//
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

bool __stdcall emulation_debugger::clear_ring3()
{
	WIN32_FIND_DATA wfd;
	wchar_t path[MAX_PATH] = { 0, };
	unsigned int fail_count = 0;

	StringCbCopy(path, MAX_PATH, ring3_path_);
	StringCbCat(path, MAX_PATH, L"\\*.*");

	HANDLE h_file = FindFirstFile(path, &wfd);

	if (h_file == INVALID_HANDLE_VALUE)
		return false;
	std::shared_ptr<void> file_closer(h_file, CloseHandle);

	do
	{
		if (!wcsstr(wfd.cFileName, L".") && !wcsstr(wfd.cFileName, L".."))
		{
			wchar_t target[MAX_PATH];

			StringCbCopy(target, MAX_PATH, ring3_path_);
			StringCbCat(target, MAX_PATH, L"\\");
			StringCbCat(target, MAX_PATH, wfd.cFileName);

			if (!DeleteFile(target))
			{
				dprintf("%ls, %08x\n", target, GetLastError());
				++fail_count;
			}
		}
	} while (FindNextFile(h_file, &wfd));

	if (fail_count > 3)
		return false;

	return true;
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

bool __stdcall emulation_debugger::backup(void *engine)
{
	uc_engine *uc = (uc_engine *)engine;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

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

		if (!windbg_linker_.write_binary(ring3_path_, name, dump, size))
			return false;
	}

	return true;
}

bool __stdcall emulation_debugger::backup()
{
	uc_engine *uc = (uc_engine *)engine_;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

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

		if (!windbg_linker_.write_binary(ring3_path_, name, dump, size))
			return false;
	}

	return true;
}

bool __stdcall emulation_debugger::write_binary(unsigned long long address)
{
	MEMORY_BASIC_INFORMATION64 mbi;
	if (!windbg_linker_.virtual_query(address, &mbi))
		return false;

	unsigned char *dump = (unsigned char *)malloc(mbi.RegionSize);
	if (!dump)
		return false;
	std::shared_ptr<void> teb_dump_closer(dump, free);

	if (!windbg_linker_.read_memory(mbi.BaseAddress, dump, mbi.RegionSize))
		return false;

	wchar_t name[MAX_PATH];
	wmemset(name, 0, MAX_PATH);
	if (!_ui64tow(mbi.BaseAddress, name, 16))
		return false;
	if (!windbg_linker_.write_binary(ring3_path_, name, dump, mbi.RegionSize))
		return false;

	return true;
}
//
//
//
bool __stdcall emulation_debugger::read_page(unsigned long long address, unsigned char *dump, size_t *size)
{
	wchar_t *end = nullptr;
	wchar_t name[MAX_PATH];
	size_t region_size = 0;

	wmemset(name, 0, MAX_PATH);
	if (!file_query_ring3(address, name, &region_size))
		return nullptr;

	unsigned char *d = (unsigned char *)malloc(region_size);
	if (!d)
		return nullptr;
	std::shared_ptr<void> dump_closer(d, free);
	memset(d, 0, region_size);

	if (!windbg_linker_.read_binary(ring3_path_, name, d, region_size))
		return nullptr;

	unsigned long long base = wcstoll(name, &end, 16);
	unsigned long long offset = address - base;

	if (region_size - offset < *size)
		*size = region_size - offset;

	memcpy(dump, &d[offset], *size);

	return true;
}
//
// public
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
	log_print();
}

void * __stdcall emulation_debugger::get_windbg_linker()
{
	return &windbg_linker_;
}

void __stdcall emulation_debugger::log_print()
{
	if (is_64_cpu())
	{
#ifdef _WIN64
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
#endif
	}
	else
	{
#ifdef _WIN64
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
#else
		dprintf("	eax="), print32(context_.Eax, backup_context_.Eax), dprintf(" ");
		dprintf("ebx="), print32(context_.Ebx, backup_context_.Ebx), dprintf(" ");
		dprintf("ecx="), print32(context_.Ecx, backup_context_.Ecx), dprintf(" ");
		dprintf("edx="), print32(context_.Edx, backup_context_.Edx), dprintf(" ");
		dprintf("esi="), print32(context_.Esi, backup_context_.Esi), dprintf(" ");
		dprintf("edi="), print32(context_.Edi, backup_context_.Edi), dprintf("\n");

		dprintf("	eip="), print32(context_.Eip, backup_context_.Eip), dprintf(" ");
		dprintf("esp="), print32(context_.Esp, backup_context_.Esp), dprintf(" ");
		dprintf("ebp="), print32(context_.Ebp, backup_context_.Ebp), dprintf(" ");
		dprintf("efl="), print32(context_.EFlags, backup_context_.EFlags), dprintf("\n");
#endif
	}

#ifdef _WIN64
	print_code(context_.Rip, 3);
#else
	print_code(context_.Eip, 3);
#endif
}

void __stdcall emulation_debugger::clear_and_print()
{
#ifdef _WIN64
	windbg_linker_.clear_screen();
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
#endif
}

CONTEXT __stdcall emulation_debugger::get_current_thread_context()
{
	return context_;
}

void __stdcall emulation_debugger::close()
{
	uc_engine *uc = (uc_engine *)engine_;

	backup(uc);
	uc_close(uc);
	engine_ = nullptr;
}