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
	virtual bool __stdcall read_register(char *mask, unsigned long long *value);
	virtual bool __stdcall write_register(char *mask, unsigned long long value);
	virtual bool __stdcall read_context(void *context, size_t context_size);

	virtual bool __stdcall attach();
	virtual bool __stdcall trace();
	virtual bool __stdcall cpu_switch();
};

#endif