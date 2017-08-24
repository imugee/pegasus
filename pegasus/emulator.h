#ifndef __DEFINE_PEGASUS_EMULATOR_HEADER
#define __DEFINE_PEGASUS_EMULATOR_HEADER

typedef struct _EMULATOR_TRACE_
{
	unsigned long long break_point;
	unsigned long mode;
	unsigned long long step;
	bool step_over;

	void *code_callback;
	void *unmap_callback;
	void *fetch_callback;
	void *read_callback;
	void *write_callback;
}trace_item;

class emulation_debugger : public engine::debugger
{
public:
	typedef struct emul_page
	{
		unsigned long long base = 0;
		size_t size = 0;
	}page;

private:
	windbg_engine_linker windbg_linker_;
	std::list<MEMORY_BASIC_INFORMATION64> memory_list_;

	CONTEXT context_;
	CONTEXT backup_context_;
	unsigned long long teb_address_;
	unsigned long long teb_64_address_;
	unsigned long long peb_address_;
	unsigned long long peb_64_address_;

	unsigned long long gdt_base_;

	bool is_64_;

	wchar_t ring0_path_[MAX_PATH];
	wchar_t ring3_path_[MAX_PATH];
	wchar_t log_path_[MAX_PATH];

private:
	virtual bool __stdcall write_binary(unsigned long long address);
	virtual bool __stdcall file_query_ring3(unsigned long long value, wchar_t *file_name, size_t *size);

	virtual bool __stdcall is_wow64cpu();

	virtual void __stdcall install();
	virtual bool __stdcall setup();

	virtual bool __stdcall load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size);
	virtual bool __stdcall load_gdt(void *engine);
	virtual bool __stdcall load_context(void *engine, unsigned long mode);

	virtual void __stdcall set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);
	virtual bool __stdcall create_global_descriptor_table();

	virtual bool __stdcall write_x86_cpu_context(void *engine);
	virtual bool __stdcall read_x86_cpu_context(void *engine);

	virtual bool __stdcall write_x64_cpu_context(void *engine);
	virtual bool __stdcall read_x64_cpu_context(void *engine);

	virtual bool __stdcall backup(void *engine);

	bool __stdcall disasm(void *code, size_t size, uint32_t dt, void *out);

	bool __stdcall mnemonic_switch_wow64cpu(void *engine);
	bool __stdcall mnemonic_wow_ret(void *engine);

	unsigned long long before(unsigned long long offset);

	void __stdcall clear_and_print();
	void __stdcall log_print();

	void __stdcall print64(unsigned long long, unsigned long long);
	void __stdcall print32(unsigned long long, unsigned long long);

	virtual bool __stdcall trace(void *engine, trace_item item);

public:
	virtual unsigned char * __stdcall load_page(unsigned long long value, unsigned long long *base, size_t *size);
	virtual size_t __stdcall alignment(size_t region_size, unsigned long image_aligin);
	virtual bool __stdcall clear_ring3();
	virtual void __stdcall current_regs();

public:
	emulation_debugger() : is_64_(false) {}

	virtual bool __stdcall is_64_cpu();

	virtual bool __stdcall attach();
	virtual bool __stdcall trace(void *mem);

	virtual CONTEXT __stdcall current_thread_context();

	void __stdcall print_code(unsigned long long ip, unsigned long line);
	virtual void * __stdcall get_windbg_linker();

	virtual bool __stdcall mnemonic_mov_gs(void *engine, unsigned long long ip);
	virtual bool __stdcall mnemonic_mov_ss(void *engine, unsigned long long ip);
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

typedef enum _pegasus_regs
{
	PR_RAX, PR_RCX, PR_RDX, PR_RBX, PR_RSP, PR_RBP, PR_RSI, PR_RDI, PR_RIP, PR_R8, PR_R9, PR_R10, PR_R11, PR_R12, PR_R13, PR_R14, PR_R15, PR_EFLAGS,
	PR_XMM0, PR_XMM1, PR_XMM2, PR_XMM3, PR_XMM4, PR_XMM5, PR_XMM6, PR_XMM7, PR_XMM8, PR_XMM9, PR_XMM10, PR_XMM11, PR_XMM12, PR_XMM13, PR_XMM14, PR_XMM15,
	PR_YMM0, PR_YMM1, PR_YMM2, PR_YMM3, PR_YMM4, PR_YMM5, PR_YMM6, PR_YMM7, PR_YMM8, PR_YMM9, PR_YMM10, PR_YMM11, PR_YMM12, PR_YMM13, PR_YMM14, PR_YMM15,
	PR_REG_ES, PR_REG_CS, PR_REG_SS, PR_REG_DS, PR_REG_FS, PR_REG_GS
}pegasus_regs;

#define UC_X86_REGISTER_SET \
UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS

#define UC_X64_REGISTER_SET \
UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_EFLAGS,\
UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7, UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11, UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,\
UC_X86_REG_YMM0, UC_X86_REG_YMM1, UC_X86_REG_YMM2, UC_X86_REG_YMM3, UC_X86_REG_YMM4, UC_X86_REG_YMM5, UC_X86_REG_YMM6, UC_X86_REG_YMM7, UC_X86_REG_YMM8, UC_X86_REG_YMM9, UC_X86_REG_YMM10, UC_X86_REG_YMM11, UC_X86_REG_YMM12, UC_X86_REG_YMM13, UC_X86_REG_YMM14, UC_X86_REG_YMM15,\
UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS

#endif // !__DEFINE_PEGASUS_EMULATOR_HEADER


