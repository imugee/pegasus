#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>
#include <engextcpp.hpp>
#include <memory>
#include <list>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

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
