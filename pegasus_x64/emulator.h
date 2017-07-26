#ifndef __DEFINE_PEGASUS_EMULATOR_HEADER__
#define __DEFINE_PEGASUS_EMULATOR_HEADER__

class Wow64EmulationDebugger : public binary::debugger
{
private:
	void *emulator_x86_;
	void *emulator_x64_;

	unsigned long long teb_address_;
	unsigned long long peb_address_;

	unsigned long long gdt_base_;
	unsigned long long ldt_base_;
	unsigned long long idt_base_;
	unsigned long long tss_base_;

	unsigned int x64_flag_;

private: // local&share
	virtual void * __stdcall get_engine();
	virtual void __stdcall set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);
	virtual bool __stdcall create_global_descriptor_table(void *engine, void *context, size_t context_size);
	virtual bool __stdcall load_ex(std::shared_ptr<binary::linker> windbg_linker);
	virtual size_t __stdcall alignment(size_t region_size, unsigned long image_aligin);

	virtual bool __stdcall mnemonic_mov_gs(unsigned long long ip);
	virtual bool __stdcall mnemonic_mov_ss(unsigned long long ip);
	virtual bool __stdcall mnemonic_wow_ret(unsigned long long ip);
	virtual bool __stdcall disasm(void *code, size_t size, uint32_t dt, void *out);

private: // x86 cpu
	virtual bool __stdcall read_context_x86(CONTEXT *context);
	virtual bool __stdcall attach_x86();
	virtual bool __stdcall trace_x86();
	virtual bool __stdcall switch_x86();

private: // x64 cpu
	virtual bool __stdcall read_context_x64(CONTEXT *context);
	virtual bool __stdcall attach_x64();
	virtual bool __stdcall trace_x64();
	virtual bool __stdcall switch_x64();

public:
	Wow64EmulationDebugger();
	~Wow64EmulationDebugger();

	virtual bool __stdcall is_64();
	
	virtual bool __stdcall check(unsigned long long address);
	virtual bool __stdcall link(unsigned long long address);
	virtual bool __stdcall load(unsigned long long load_address, size_t load_size, void *dump, size_t write_size);

	virtual bool __stdcall read(unsigned long long address, void *dump, size_t dump_size);
	virtual bool __stdcall write(unsigned long long address, void *dump, size_t dump_size);
	
	virtual bool __stdcall read_register(unsigned int id, unsigned long long *value);
	virtual bool __stdcall write_register(unsigned int id, unsigned long long value);
	
	virtual bool __stdcall read_context(void *context, size_t context_size);

	virtual bool __stdcall attach();
	virtual bool __stdcall trace();
	virtual bool __stdcall cpu_switch();
};

#define DISTORM_TO_UC_REGS \
UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,\
UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_R8D, UC_X86_REG_R9D, UC_X86_REG_R10D, UC_X86_REG_R11D, UC_X86_REG_R12D, UC_X86_REG_R13D, UC_X86_REG_R14D, UC_X86_REG_R15D,\
UC_X86_REG_AX, UC_X86_REG_CX, UC_X86_REG_DX, UC_X86_REG_BX, UC_X86_REG_SP, UC_X86_REG_BP, UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_R8W, UC_X86_REG_R9W, UC_X86_REG_R10W, UC_X86_REG_R11W, UC_X86_REG_R12W, UC_X86_REG_R13W, UC_X86_REG_R14W, UC_X86_REG_R15W,\
UC_X86_REG_AL, UC_X86_REG_CL, UC_X86_REG_DL, UC_X86_REG_BL, UC_X86_REG_AH, UC_X86_REG_CH, UC_X86_REG_DH, UC_X86_REG_BH, UC_X86_REG_R8B, UC_X86_REG_R9B, UC_X86_REG_R10B, UC_X86_REG_R11B, UC_X86_REG_R12B, UC_X86_REG_R13B, UC_X86_REG_R14B, UC_X86_REG_R15B,\
UC_X86_REG_SPL, UC_X86_REG_BPL, UC_X86_REG_SIL, UC_X86_REG_DIL,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS,\
UC_X86_REG_RIP,\
UC_X86_REG_ST0, UC_X86_REG_ST1, UC_X86_REG_ST2, UC_X86_REG_ST3, UC_X86_REG_ST4, UC_X86_REG_ST5, UC_X86_REG_ST6, UC_X86_REG_ST7,\
UC_X86_REG_MM0, UC_X86_REG_MM1, UC_X86_REG_MM2, UC_X86_REG_MM3, UC_X86_REG_MM4, UC_X86_REG_MM5, UC_X86_REG_MM6, UC_X86_REG_MM7,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_CR0, UC_X86_REG_CR2, UC_X86_REG_CR3, UC_X86_REG_CR4, UC_X86_REG_CR8,\
UC_X86_REG_DR0, UC_X86_REG_DR1, UC_X86_REG_DR2, UC_X86_REG_DR3, UC_X86_REG_DR6, UC_X86_REG_DR7

#endif
