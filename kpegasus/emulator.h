#ifndef __DEFINE_PEGASUS_EMULATOR_HEADER
#define __DEFINE_PEGASUS_EMULATOR_HEADER

class emulation_debugger : public engine::debugger
{
private:
	windbg_engine_linker windbg_linker_;
	std::list<MEMORY_BASIC_INFORMATION64> memory_list_;

	unsigned long long teb_address_;
	unsigned long long peb_address_;
	unsigned long long gdt_base_;

	wchar_t ring0_path_[MAX_PATH];
	wchar_t ring3_path_[MAX_PATH];

private:
	virtual void __stdcall install();
	virtual bool __stdcall capture();
	virtual bool __stdcall load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size);
	//virtual bool __stdcall load_page(unsigned long long address, unsigned char *dump);

	virtual void __stdcall set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);
	virtual bool __stdcall create_global_descriptor_table(void *engine, void *context, size_t context_size);

public:
	emulation_debugger();

	virtual bool __stdcall attach();
	virtual bool __stdcall trace32();
};

#endif // !__DEFINE_PEGASUS_EMULATOR_HEADER


