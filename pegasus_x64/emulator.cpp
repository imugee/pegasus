#define _CRT_SECURE_NO_WARNINGS

#include <unicorn/unicorn.h>
#include <distorm/include/distorm.h>
#include <distorm/include/mnemonics.h>

#include <list>
#include <memory>

#include <winternl.h>
#include <Psapi.h>

#include "interface.h"
#include "windbg_linker.h"
#include "emulator.h"

#pragma comment(lib, "unicorn_static_x64.lib")

Wow64EmulationDebugger::Wow64EmulationDebugger() : emulator_x86_(nullptr), emulator_x64_(nullptr), teb_address_(0), peb_address_(0), gdt_base_(0), x64_flag_(0)
{
}

Wow64EmulationDebugger::~Wow64EmulationDebugger()
{
}
///
///
///
size_t __stdcall Wow64EmulationDebugger::alignment(size_t region_size, unsigned long image_aligin)
{
	size_t alignment = region_size;

	while (true)
	{
		if (alignment > image_aligin)
			alignment -= image_aligin;
		else
			break;
	}

	alignment = image_aligin - alignment;

	return 	alignment += region_size;
}

bool __stdcall Wow64EmulationDebugger::load(unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	uc_err err;

	if ((err = uc_mem_map((uc_engine *)engine, load_address, load_size, UC_PROT_ALL)) != 0 || (err = uc_mem_write((uc_engine *)engine, load_address, dump, write_size)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	return true;
}

bool __stdcall Wow64EmulationDebugger::load_ex(std::shared_ptr<binary::linker> windbg_linker)
{
	std::list<MEMORY_BASIC_INFORMATION64> memory_list;
	uint64_t address = 0;
	MEMORY_BASIC_INFORMATION64 mbi = { 0, };
	unsigned int count = 0;

	while (windbg_linker->virtual_query(address, &mbi))
	{
		if (mbi.BaseAddress > address)
		{
			address = mbi.BaseAddress;
			continue;
		}

		if (mbi.State == MEM_COMMIT)
		{
			unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);

			if (!dump)
				continue;

			memset(dump, 0, (size_t)mbi.RegionSize);
			std::shared_ptr<void> dump_closer(dump, free);

			if (!windbg_linker->read_memory(mbi.BaseAddress, dump, (size_t)mbi.RegionSize))
				continue;

			if (!load((uint64_t)mbi.BaseAddress, (size_t)mbi.RegionSize, dump, (size_t)mbi.RegionSize))
				continue;

			++count;
		}
		
		address += mbi.RegionSize;
		memset(&mbi, 0, sizeof(mbi));
	}

	if (count == 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::link(unsigned long long address)
{
	address += 0x10;
	size_t resize = alignment((size_t)address, 0x1000);
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	uc_engine *uc = (uc_engine *)engine;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;

	uc_mem_region b = { 0, };
	for (unsigned int i = 0; i < count; ++i)
	{
		if (um[i].end < resize && um[i+1].begin >= resize)
		{
			b.begin = um[i].begin;
			b.end = um[i].end;
		}
	}

	unsigned long long base = b.end + 1;
	size_t size = resize - base;
	uc_err err;

	if((err = uc_mem_map(uc, base, size, UC_PROT_ALL)) != 0)
		return false;

	return true;
}
///
/// segmentation
///
void __stdcall Wow64EmulationDebugger::set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
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

bool __stdcall Wow64EmulationDebugger::create_global_descriptor_table(void *engine, void *context, size_t context_size)
{
	NT_TIB64 tib;
	uc_engine *uc = (uc_engine *)engine;
	SegmentDescriptor global_descriptor[31];
	CONTEXT *ctx = (CONTEXT *)context;
	uc_x86_mmr gdtr;
	memset(&tib, 0, sizeof(tib));

	if (context_size != sizeof(CONTEXT))
		return false;

	if (!read(teb_address_, &tib, sizeof(tib)))
		return false;

	memset(&gdtr, 0, sizeof(gdtr));
	memset(global_descriptor, 0, sizeof(global_descriptor));

	gdtr.base = gdt_base_;
	gdtr.limit = sizeof(global_descriptor) - 1;

	uc_err err;
	if ((err = uc_mem_map(uc, gdt_base_, 0x10000, UC_PROT_WRITE | UC_PROT_READ)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	if (uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (ctx->SegDs == ctx->SegSs)
		ctx->SegSs = 0x88; // rpl = 0

	ctx->SegGs = 0x63;

	set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	set_global_descriptor(&global_descriptor[ctx->SegCs >> 3], 0, 0xfffff000, 1);
	set_global_descriptor(&global_descriptor[ctx->SegDs >> 3], 0, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[ctx->SegFs >> 3], (uint32_t)tib.ExceptionList, 0xfff, 0);
	set_global_descriptor(&global_descriptor[ctx->SegGs >> 3], (uint32_t)tib.Self, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[ctx->SegSs >> 3], 0, 0xfffff000, 0);
	global_descriptor[ctx->SegSs >> 3].dpl = 0; // dpl = 0, cpl = 0

	if (uc_mem_write(uc, gdt_base_, &global_descriptor, sizeof(global_descriptor)) != 0)
		return false;

	return true;
}
///
///
///
bool __stdcall Wow64EmulationDebugger::disasm(void *code, size_t size, uint32_t dt, void *out)
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
///
///
///
bool __stdcall Wow64EmulationDebugger::check(unsigned long long address)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	unsigned char dump[16];

	if (!engine)
		return false;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_mem_read(uc, address, dump, sizeof(dump) != 0))
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::read(unsigned long long address, void *dump, size_t dump_size)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_mem_read(uc, address, dump, dump_size) != 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::write(unsigned long long address, void *dump, size_t dump_size)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_mem_write(uc, address, dump, dump_size) != 0)
		return false;

	return true;
}


bool __stdcall Wow64EmulationDebugger::read_register(char *mask, unsigned long long *value)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	unsigned long register_id = 0;

	if (strstr(mask, "eax"))
		register_id = UC_X86_REG_EAX;
	else if (strstr(mask, "ebx"))
		register_id = UC_X86_REG_EBX;
	else if (strstr(mask, "ecx"))
		register_id = UC_X86_REG_ECX;
	else if (strstr(mask, "edx"))
		register_id = UC_X86_REG_EDX;
	else if (strstr(mask, "esi"))
		register_id = UC_X86_REG_ESI;
	else if (strstr(mask, "edi"))
		register_id = UC_X86_REG_EDI;
	else if (strstr(mask, "esp"))
		register_id = UC_X86_REG_ESP;
	else if (strstr(mask, "ebp"))
		register_id = UC_X86_REG_EBP;
	else if (strstr(mask, "eip"))
		register_id = UC_X86_REG_EIP;
	///
	else if (strstr(mask, "rax"))
		register_id = UC_X86_REG_RAX;
	else if (strstr(mask, "rbx"))
		register_id = UC_X86_REG_RBX;
	else if (strstr(mask, "rcx"))
		register_id = UC_X86_REG_RCX;
	else if (strstr(mask, "rdx"))
		register_id = UC_X86_REG_RDX;
	else if (strstr(mask, "rsi"))
		register_id = UC_X86_REG_RSI;
	else if (strstr(mask, "rdi"))
		register_id = UC_X86_REG_RDI;
	else if (strstr(mask, "rsp"))
		register_id = UC_X86_REG_RSP;
	else if (strstr(mask, "rbp"))
		register_id = UC_X86_REG_RBP;
	else if (strstr(mask, "rip"))
		register_id = UC_X86_REG_RIP;
	///
	else if (strstr(mask, "r8"))
		register_id = UC_X86_REG_R8;
	else if (strstr(mask, "r9"))
		register_id = UC_X86_REG_R9;
	else if (strstr(mask, "r10"))
		register_id = UC_X86_REG_R10;
	else if (strstr(mask, "r11"))
		register_id = UC_X86_REG_R11;
	else if (strstr(mask, "r12"))
		register_id = UC_X86_REG_R12;
	else if (strstr(mask, "r13"))
		register_id = UC_X86_REG_R13;
	else if (strstr(mask, "r14"))
		register_id = UC_X86_REG_R14;
	else if (strstr(mask, "r15"))
		register_id = UC_X86_REG_R15;
	///
	else if (strstr(mask, "cs"))
		register_id = UC_X86_REG_CS;
	else if (strstr(mask, "ds"))
		register_id = UC_X86_REG_DS;
	else if (strstr(mask, "es"))
		register_id = UC_X86_REG_ES;
	else if (strstr(mask, "fs"))
		register_id = UC_X86_REG_FS;
	else if (strstr(mask, "gs"))
		register_id = UC_X86_REG_GS;
	else if (strstr(mask, "ss"))
		register_id = UC_X86_REG_SS;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_read(uc, register_id, value) != 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::write_register(char *mask, unsigned long long value)
{
	void *engine = nullptr;

	if (x64_flag_)
		engine = emulator_x64_;
	else
		engine = emulator_x86_;

	if (!engine)
		return false;

	unsigned long register_id = 0;

	if (strstr(mask, "eax"))
		register_id = UC_X86_REG_EAX;
	else if (strstr(mask, "ebx"))
		register_id = UC_X86_REG_EBX;
	else if (strstr(mask, "ecx"))
		register_id = UC_X86_REG_ECX;
	else if (strstr(mask, "edx"))
		register_id = UC_X86_REG_EDX;
	else if (strstr(mask, "esi"))
		register_id = UC_X86_REG_ESI;
	else if (strstr(mask, "edi"))
		register_id = UC_X86_REG_EDI;
	else if (strstr(mask, "esp"))
		register_id = UC_X86_REG_ESP;
	else if (strstr(mask, "ebp"))
		register_id = UC_X86_REG_EBP;
	else if (strstr(mask, "eip"))
		register_id = UC_X86_REG_EIP;
	///
	else if (strstr(mask, "rax"))
		register_id = UC_X86_REG_RAX;
	else if (strstr(mask, "rbx"))
		register_id = UC_X86_REG_RBX;
	else if (strstr(mask, "rcx"))
		register_id = UC_X86_REG_RCX;
	else if (strstr(mask, "rdx"))
		register_id = UC_X86_REG_RDX;
	else if (strstr(mask, "rsi"))
		register_id = UC_X86_REG_RSI;
	else if (strstr(mask, "rdi"))
		register_id = UC_X86_REG_RDI;
	else if (strstr(mask, "rsp"))
		register_id = UC_X86_REG_RSP;
	else if (strstr(mask, "rbp"))
		register_id = UC_X86_REG_RBP;
	else if (strstr(mask, "rip"))
		register_id = UC_X86_REG_RIP;
	///
	else if (strstr(mask, "r8"))
		register_id = UC_X86_REG_R8;
	else if (strstr(mask, "r9"))
		register_id = UC_X86_REG_R9;
	else if (strstr(mask, "r10"))
		register_id = UC_X86_REG_R10;
	else if (strstr(mask, "r11"))
		register_id = UC_X86_REG_R11;
	else if (strstr(mask, "r12"))
		register_id = UC_X86_REG_R12;
	else if (strstr(mask, "r13"))
		register_id = UC_X86_REG_R13;
	else if (strstr(mask, "r14"))
		register_id = UC_X86_REG_R14;
	else if (strstr(mask, "r15"))
		register_id = UC_X86_REG_R15;
	///
	else if (strstr(mask, "cs"))
		register_id = UC_X86_REG_CS;
	else if (strstr(mask, "ds"))
		register_id = UC_X86_REG_DS;
	else if (strstr(mask, "es"))
		register_id = UC_X86_REG_ES;
	else if (strstr(mask, "fs"))
		register_id = UC_X86_REG_FS;
	else if (strstr(mask, "gs"))
		register_id = UC_X86_REG_GS;
	else if (strstr(mask, "ss"))
		register_id = UC_X86_REG_SS;

	uc_engine *uc = (uc_engine *)engine;
	if (uc_reg_write(uc, register_id, &value) != 0)
		return false;

	return true;
}

bool __stdcall Wow64EmulationDebugger::read_context(void *context, size_t context_size)
{
	if (x64_flag_)
		return read_context_x64((CONTEXT *)context);
	
	return read_context_x86((CONTEXT *)context);
}
///
///
///
bool __stdcall Wow64EmulationDebugger::is_64()
{
	if (x64_flag_)
		return true;
	return false;
}
///
///
///
bool __stdcall Wow64EmulationDebugger::attach()
{
	return attach_x86();
}

bool __stdcall Wow64EmulationDebugger::trace()
{
	if (x64_flag_)
		return trace_x64();

	return trace_x86();
}

bool __stdcall Wow64EmulationDebugger::cpu_switch()
{
	if (x64_flag_)
		return switch_x86();

	return switch_x64();
}
