#include "emulator.h"
#include <Windows.h>
#include <WDBGEXTS.H>

void Emulator::SetSyscallRip(unsigned long long rip)
{
	syscall_rip_ = rip;
}

unsigned long long Emulator::GetSyscallRip()
{
	return syscall_rip_;
}

static void HookUnmapMemory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	Emulator * emulator = (Emulator *)user_data;
	if (uc_mem_type::UC_MEM_READ)
	{
		dprintf(" [+] unmap::read = >%I64x\n", address);
	}
	else if (uc_mem_type::UC_MEM_WRITE)
	{
		dprintf(" [+] unmap:: write=>%I64x, val=>%I64x\n", address, value);
	}

	if (!emulator->LoadEmulatorMemory(address))
	{
		dprintf(" [-] loadf..\n");
	}
}

static void HookFetchMemory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	Emulator * emulator = (Emulator *)user_data;
	dprintf(" [+] fetch:: code=>%I64x\n", address);

	if (!emulator->LoadEmulatorMemory(address))
	{
		dprintf(" [-] loadf..\n");
	}
}

static void HookCurrentCode(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	Emulator * emulator = (Emulator *)user_data;
	dprintf(" [+] code:: exe=>%I64x\n", address);

	unsigned char dump[16] = { 0, };
	emulator->Read(address, dump, sizeof(dump));
	if (dump[0] == 0xb8 && dump[5] == 0xba && dump[10] == 0xff)
	{
		dprintf(" [-] syscall:: %I64x\n", address);
		emulator->SetSyscallRip(address);
		uc_emu_stop(uc);
	}
}

static void HookReadWriteMemory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	Emulator * emulator = (Emulator *)user_data;
	if (uc_mem_type::UC_MEM_READ)
	{
		dprintf(" [+] read memory=>%I64x\n", address);
	}
	else if (uc_mem_type::UC_MEM_WRITE)
	{
		dprintf(" [+] write memory=>%I64x, val=>%I64x\n", address, value);
	}
}

// ------------------------------------------
//
uc_mode Emulator::GetCurrentArch()
{
	uc_mode mode = UC_MODE_32;
	xdv_handle h = XdvGetArchitectureHandle();
	IObject *obj = XdvGetObjectByHandle(h);
	if (!obj)
	{
		return mode;
	}

	switch (obj->ObjectType())
	{
	case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
		mode = UC_MODE_32;
		break;

	case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
	case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
		mode = UC_MODE_64;
		break;
	}

	return mode;
}

bool Emulator::AttachEmulator()
{
	uc_mode mode = GetCurrentArch();
	if (uc_open(UC_ARCH_X86, mode, &uc_) != 0)
	{
		return false;
	}

	uc_hook write_unmap_hook = 0;
	uc_hook read_unmap_hook = 0;
	uc_hook fetch_hook = 0;

	uc_hook code_hook = 0;
	uc_hook read_hook = 0;
	uc_hook write_hook = 0;

	if (uc_hook_add(uc_, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, HookUnmapMemory, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (uc_hook_add(uc_, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, HookUnmapMemory, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (uc_hook_add(uc_, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, HookFetchMemory, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (uc_hook_add(uc_, &code_hook, UC_HOOK_CODE, HookCurrentCode, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (uc_hook_add(uc_, &read_hook, UC_HOOK_MEM_READ, HookReadWriteMemory, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (uc_hook_add(uc_, &write_hook, UC_HOOK_MEM_WRITE, HookReadWriteMemory, this, (uint64_t)1, (uint64_t)0) != 0)
	{
		return false;
	}

	if (!debugger_->GetThreadContext(&context_))
	{
		return false;
	}

	if (!LoadMsr(mode))
	{
		return false;
	}

	if (!CreateGlobalDescriptorTable(mode))
	{
		return false;
	}

	if (!LoadContext(mode))
	{
		return false;
	}

	//if (!LoadEmulatorMemory(context_.rip))
	//{
	//	return false;
	//}

	//if (!LoadEmulatorMemory(context_.rsp))
	//{
	//	return false;
	//}

	//if (!LoadEmulatorMemory(debugger_->GetTebAddress()))
	//{
	//	return false;
	//}

	return true;
}

bool Emulator::DetachEmulator()
{
	if (uc_close(uc_) != 0)
	{
		return false;
	}
	uc_ = nullptr;

	return true;
}

void Emulator::SetSegmentDescriptor(SegmentDescriptor *desc, unsigned long long base, unsigned long long limit, uint8_t is_code)
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

// https://github.com/williballenthin/unicorn/blob/5ae7516238bd936550817a4e79465bc42ee1186b/tests/regress/x86_64_msr.py#L23
// https://github.com/hzqst/unicorn_pe/blob/5e95aad73989d56ced979101b21899f37f42f150/unicorn_pe/unicorn_pe.cpp#L801
bool Emulator::CreateGlobalDescriptorTable(uc_mode mode)
{
	SegmentDescriptor global_descriptor[31];
	memset(global_descriptor, 0, sizeof(global_descriptor));

	context_.ss = 0x88; // rpl = 0
	context_.gs = 0x63;

	SetSegmentDescriptor(&global_descriptor[context_.cs >> 3], 0, 0xfffff000, 1);
	SetSegmentDescriptor(&global_descriptor[context_.ds >> 3], 0, 0xfffff000, 0);
	SetSegmentDescriptor(&global_descriptor[context_.es >> 3], 0, 0xfffff000, 0);
	SetSegmentDescriptor(&global_descriptor[context_.ss >> 3], 0, 0xfffff000, 0);
	global_descriptor[context_.ss >> 3].dpl = 0; // rpl = 0, dpl = 0, cpl = 0

	if (mode == uc_mode::UC_MODE_32)
	{
		gdt_base_ = 0xc0000000;
		SetSegmentDescriptor(&global_descriptor[context_.fs >> 3], debugger_->GetTebAddress(), 0xfffff000, 0);
		SetSegmentDescriptor(&global_descriptor[context_.gs >> 3], 0, 0xfffff000, 0);
	}
	else if (mode == uc_mode::UC_MODE_64)
	{
		gdt_base_ = 0xc000000000000000;
		SetSegmentDescriptor(&global_descriptor[context_.fs >> 3], 0, 0xfffff000, 0);
		SetSegmentDescriptor(&global_descriptor[context_.gs >> 3], debugger_->GetTebAddress(), 0xfffff000, 0);
	}

	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(uc_, UC_X86_REG_GDTR, &gdtr) != 0)
	{
		return false;
	}

	if (!LoadEmulatorMemory(gdt_base_, 0x10000, global_descriptor, sizeof(global_descriptor)))
	{
		return false;
	}

	return true;
}

bool Emulator::LoadMsr(uc_mode mode)
{
	unsigned long long teb = debugger_->GetTebAddress();
	if (teb == 0)
	{
		return false;
	}

	unsigned long rid = 0xC0000100;
	switch (mode)
	{
	case uc_mode::UC_MODE_64:
		rid += 1;
		break;
	}

	uc_x86_msr msr;
	msr.rid = rid;
	msr.value = teb;
	if (uc_reg_write(uc_, UC_X86_REG_MSR, &msr) != 0)
	{
		return false;
	}

	return true;
}

//
//
bool Emulator::LoadEmulatorMemory(unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	uc_err err;
	if ((err = uc_mem_map(uc_, load_address, load_size, UC_PROT_ALL)) != 0)
	{
		if (err != UC_ERR_MAP)
		{
			return false;
		}
	}

	if ((err = uc_mem_write(uc_, load_address, dump, write_size)) != 0)
	{
		if (err != UC_ERR_MAP)
		{
			return false;
		}
	}

	return true;
}

bool Emulator::QueryEmulatorMemory(unsigned long long ptr, unsigned long long *base, unsigned long long *end)
{
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc_, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

	for (unsigned int i = 0; i < count; ++i)
	{
		printf("%I64x-%I64x\n", um[i].begin, um[i].end);

		if (ptr >= um[i].begin && ptr <= um[i].end)
		{
			*base = um[i].begin;
			*end = um[i].end;

			return true;
		}
	}

	return false;
}

bool Emulator::LoadEmulatorMemory(unsigned long long address)
{
	xdv::memory::type mbi;
	if (!debugger_->Query(address, &mbi))
	{
		return false;
	}

	unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);
	if (!dump)
	{
		return false;
	}
	std::shared_ptr<void> dump_closer(dump, free);

	if (!debugger_->Read(mbi.BaseAddress, dump, (unsigned long)mbi.RegionSize))
	{
		return false;
	}

	uc_err err;
	if ((err = uc_mem_map(uc_, mbi.BaseAddress, (size_t)mbi.RegionSize, UC_PROT_ALL)) != 0)
	{
		mbi.RegionSize = 0x1000;
		err = uc_mem_map(uc_, mbi.BaseAddress, (size_t)mbi.RegionSize, UC_PROT_ALL);
		//printf("map err %d\n", err);
		//unsigned long long base = 0;
		//unsigned long long end = 0;
		//QueryEmulatorMemory(address, &base, &end);
		//printf("%I64x-%I64x\n", base, end);
		if (err != UC_ERR_MAP)
		{
			return false;
		}
	}

	if ((err = uc_mem_write(uc_, mbi.BaseAddress, dump, (size_t)mbi.RegionSize)) != 0)
	{
		return false;
	}

	return true;
}

bool Emulator::Read32bitContext()
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!read_register)
	{
		return false;
	}
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
	{
		return false;
	}
	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
	{
		read_ptr[i] = &read_register[i];
	}

	if (uc_reg_read_batch(uc_, x86_register, read_ptr, size) != 0)
	{
		return false;
	}

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];

	context_.efl = read_register[PR_EFLAGS];
	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool Emulator::Write32bitContext()
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!write_register)
	{
		return false;
	}
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
	{
		return false;
	}
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
	{
		write_ptr[i] = &write_register[i];
	}

	write_register[PR_RAX] = (unsigned long)context_.rax;
	write_register[PR_RBX] = (unsigned long)context_.rbx;
	write_register[PR_RCX] = (unsigned long)context_.rcx;
	write_register[PR_RDX] = (unsigned long)context_.rdx;
	write_register[PR_RSI] = (unsigned long)context_.rsi;
	write_register[PR_RDI] = (unsigned long)context_.rdi;
	write_register[PR_RSP] = (unsigned long)context_.rsp;
	write_register[PR_RBP] = (unsigned long)context_.rbp;
	write_register[PR_RIP] = (unsigned long)context_.rip;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = (unsigned long)context_.xmm0;
	write_register[PR_XMM1] = (unsigned long)context_.xmm1;
	write_register[PR_XMM2] = (unsigned long)context_.xmm2;
	write_register[PR_XMM3] = (unsigned long)context_.xmm3;
	write_register[PR_XMM4] = (unsigned long)context_.xmm4;
	write_register[PR_XMM5] = (unsigned long)context_.xmm5;
	write_register[PR_XMM6] = (unsigned long)context_.xmm6;
	write_register[PR_XMM7] = (unsigned long)context_.xmm7;

	write_register[PR_YMM0] = (unsigned long)context_.ymm0;
	write_register[PR_YMM1] = (unsigned long)context_.ymm1;
	write_register[PR_YMM2] = (unsigned long)context_.ymm2;
	write_register[PR_YMM3] = (unsigned long)context_.ymm3;
	write_register[PR_YMM4] = (unsigned long)context_.ymm4;
	write_register[PR_YMM5] = (unsigned long)context_.ymm5;
	write_register[PR_YMM6] = (unsigned long)context_.ymm6;
	write_register[PR_YMM7] = (unsigned long)context_.ymm7;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	if (uc_reg_write_batch(uc_, x86_register, write_ptr, size) != 0)
	{
		return false;
	}

	return true;
}

bool Emulator::Read64bitContext()
{
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!read_register)
	{
		return false;
	}
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
	{
		return false;
	}
	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
	{
		read_ptr[i] = &read_register[i];
	}

	if (uc_reg_read_batch(uc_, x86_register, read_ptr, size) != 0)
	{
		return false;
	}

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];
	context_.r8 = read_register[PR_R8];
	context_.r9 = read_register[PR_R9];
	context_.r10 = read_register[PR_R10];
	context_.r11 = read_register[PR_R11];
	context_.r12 = read_register[PR_R12];
	context_.r13 = read_register[PR_R13];
	context_.r14 = read_register[PR_R14];
	context_.r15 = read_register[PR_R15];
	context_.efl = (unsigned long)read_register[PR_EFLAGS];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];
	context_.xmm8 = read_register[PR_XMM8];
	context_.xmm9 = read_register[PR_XMM9];
	context_.xmm10 = read_register[PR_XMM10];
	context_.xmm11 = read_register[PR_XMM11];
	context_.xmm12 = read_register[PR_XMM12];
	context_.xmm13 = read_register[PR_XMM13];
	context_.xmm14 = read_register[PR_XMM14];
	context_.xmm15 = read_register[PR_XMM15];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];
	context_.ymm8 = read_register[PR_YMM8];
	context_.ymm9 = read_register[PR_YMM9];
	context_.ymm10 = read_register[PR_YMM10];
	context_.ymm11 = read_register[PR_YMM11];
	context_.ymm12 = read_register[PR_YMM12];
	context_.ymm13 = read_register[PR_YMM13];
	context_.ymm14 = read_register[PR_YMM14];
	context_.ymm15 = read_register[PR_YMM15];

	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool Emulator::Write64bitContext()
{
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!write_register)
	{
		return false;
	}
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
	{
		return false;
	}
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
	{
		write_ptr[i] = &write_register[i];
	}
	write_register[PR_RAX] = context_.rax;
	write_register[PR_RBX] = context_.rbx;
	write_register[PR_RCX] = context_.rcx;
	write_register[PR_RDX] = context_.rdx;
	write_register[PR_RSI] = context_.rsi;
	write_register[PR_RDI] = context_.rdi;
	write_register[PR_RSP] = context_.rsp;
	write_register[PR_RBP] = context_.rbp;
	write_register[PR_R8] = context_.r8;
	write_register[PR_R9] = context_.r9;
	write_register[PR_R10] = context_.r10;
	write_register[PR_R11] = context_.r11;
	write_register[PR_R12] = context_.r12;
	write_register[PR_R13] = context_.r13;
	write_register[PR_R14] = context_.r14;
	write_register[PR_R15] = context_.r15;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = context_.xmm0;
	write_register[PR_XMM1] = context_.xmm1;
	write_register[PR_XMM2] = context_.xmm2;
	write_register[PR_XMM3] = context_.xmm3;
	write_register[PR_XMM4] = context_.xmm4;
	write_register[PR_XMM5] = context_.xmm5;
	write_register[PR_XMM6] = context_.xmm6;
	write_register[PR_XMM7] = context_.xmm7;
	write_register[PR_XMM8] = context_.xmm8;
	write_register[PR_XMM9] = context_.xmm9;
	write_register[PR_XMM10] = context_.xmm10;
	write_register[PR_XMM11] = context_.xmm11;
	write_register[PR_XMM12] = context_.xmm12;
	write_register[PR_XMM13] = context_.xmm13;
	write_register[PR_XMM14] = context_.xmm14;
	write_register[PR_XMM15] = context_.xmm15;

	write_register[PR_YMM0] = context_.ymm0;
	write_register[PR_YMM1] = context_.ymm1;
	write_register[PR_YMM2] = context_.ymm2;
	write_register[PR_YMM3] = context_.ymm3;
	write_register[PR_YMM4] = context_.ymm4;
	write_register[PR_YMM5] = context_.ymm5;
	write_register[PR_YMM6] = context_.ymm6;
	write_register[PR_YMM7] = context_.ymm7;
	write_register[PR_YMM8] = context_.ymm8;
	write_register[PR_YMM9] = context_.ymm9;
	write_register[PR_YMM10] = context_.ymm10;
	write_register[PR_YMM11] = context_.ymm11;
	write_register[PR_YMM12] = context_.ymm12;
	write_register[PR_YMM13] = context_.ymm13;
	write_register[PR_YMM14] = context_.ymm14;
	write_register[PR_YMM15] = context_.ymm15;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	if (uc_reg_write_batch(uc_, x86_register, write_ptr, size) != 0)
	{
		return false;
	}

	return true;
}

bool Emulator::LoadContext(uc_mode mode)
{
	if (mode == UC_MODE_64)
	{
		if (!Write64bitContext())
		{
			return false;
		}
	}
	else
	{
		if (!Write32bitContext())
		{
			return false;
		}
	}

	return true;
}

bool Emulator::Trace(TraceId id)
{
	uc_err err = (uc_err)0;
	unsigned long long end_point = XdvGetNextPtr(XdvGetArchitectureHandle(), XdvGetParserHandle(), context_.rip);
	unsigned long step = 0;
	switch (id)
	{
	case TraceId::EMULATOR_TRACE_STEP_INTO:
		step = 1;
		break;
	}

	err = uc_emu_start(uc_, context_.rip, end_point, 0, step);
	if (err)
	{
		return false;
	}
	else if (this->GetSyscallRip())
	{
#if 0
		unsigned long long ptr = this->GetSyscallRip() + 0xc;
		debugger_->SetBreakPoint(xdv::breakpoint::SUSPEND_BREAK_POINT_ID, ptr);
		XdvResumeProcess(XdvGetParserHandle());

		do
		{
			//XdvSuspendProcess(XdvGetParserHandle());
			if (debugger_->Update())
			{
				bool result = false;
				std::map<unsigned long, unsigned long long> thread_map;
				debugger_->Threads(thread_map);
				for (auto it : thread_map)
				{
					if (debugger_->Select(it.first))
					{
						xdv::architecture::x86::context::type ctx;
						if (debugger_->GetThreadContext(&ctx))
						{
							if (ctx.rip == ptr || ctx.rip == ptr + 1)
							{
								result = true;
								break;
							}
						}
					}
				}

				if (result)
				{
					break;
				}

				std::chrono::seconds dura_sec(1);
				std::this_thread::sleep_for(dura_sec);
			}
			else
			{
				break;
			}
		} while (true);

		XdvSuspendProcess(XdvGetParserHandle());
		xdv::architecture::x86::context::type ctx;
		if (debugger_->GetThreadContext(&ctx))
		{
			ctx.rip = ptr;
			debugger_->SetThreadContext(&ctx);
		}
		debugger_->RestoreBreakPoint(ptr);

		if (debugger_->Update())
		{
			if (DetachEmulator())
			{
				AttachEmulator();
			}
		}
#endif
	}

	bool result = true;
	uc_mode mode = GetCurrentArch();
	switch (mode)
	{
	case uc_mode::UC_MODE_32:
		result = Read32bitContext();
		break;

	case uc_mode::UC_MODE_64:
		result = Read64bitContext();
	}

	return result;
}