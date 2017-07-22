#ifndef __DEFINE_PEGASUS_EXTERNAL_INTERFACE__
#define __DEFINE_PEGASUS_EXTERNAL_INTERFACE__
///
// interface
///
#define get_bit_flag(t, i)		(t >> i) & 1
#define GetFlagBit(eflags, i)	get_bit_flag(eflags, i)

#define CF_INDEX	0
#define PF_INDEX	2
#define AF_INDEX	4
#define ZF_INDEX	6
#define SF_INDEX	7
#define TF_INDEX	8
#define IF_INDEX	9
#define DF_INDEX	10
#define OF_INDEX	11
#define IOPL_INDEX_1	12
#define IOPL_INDEX_2	13
#define NT_INDEX		14
#define RF_INDEX		16
#define VM_INDEX		17
#define AC_INDEX		18
#define VIF_INDEX		19
#define VIP_INDEX		20
#define ID_INDEX		21

#pragma pack(push, 1)
typedef struct _SegmentDescriptor {
	union {
		struct {
			unsigned short limit_low;
			unsigned short base_low;
			unsigned char base_mid;
			unsigned char type : 4;
			unsigned char system : 1;
			unsigned char dpl : 2;
			unsigned char present : 1;
			unsigned char limit_hi : 4;
			unsigned char available : 1;
			unsigned char is_64_code : 1;
			unsigned char db : 1;
			unsigned char granularity : 1;
			unsigned char base_hi;
		};
		unsigned long long descriptor; // resize 8byte.
	};
}SegmentDescriptor, *PSegmentDescriptor;
#pragma pack(pop)

namespace binary
{
	class debugger
	{
	public:
		virtual ~debugger() {}

		virtual bool __stdcall is_64() = 0;
		virtual bool __stdcall check(unsigned long long address) = 0;
		virtual bool __stdcall link(unsigned long long address) = 0;
		virtual bool __stdcall load(unsigned long long load_address, size_t load_size, void *dump, size_t write_size) = 0;

		virtual bool __stdcall read(unsigned long long address, void *dump, size_t dump_size) = 0;
		virtual bool __stdcall write(unsigned long long address, void *dump, size_t dump_size) = 0;
		virtual bool __stdcall read_register(char *mask, unsigned long long *value) = 0;
		virtual bool __stdcall write_register(char *mask, unsigned long long value) = 0;
		virtual bool __stdcall read_context(void *context, size_t context_size) = 0;

		//virtual bool __stdcall push(int value) = 0;
		//virtual int __stdcall pop() = 0;

		virtual bool __stdcall attach() = 0;
		virtual bool __stdcall trace() = 0;

		virtual bool __stdcall cpu_switch() = 0;
	};

	class linker
	{
	public:
		virtual ~linker() {}
		virtual void __stdcall setting(const char *argument_str, int *argument_count, char(*args)[1024]) = 0;

		virtual unsigned long long __stdcall get_teb_address() = 0;
		virtual unsigned long long __stdcall get_peb_address() = 0;

		virtual bool __stdcall virtual_query(uint64_t address, void *context, size_t context_size) = 0;
		virtual bool __stdcall virtual_query(uint64_t address, MEMORY_BASIC_INFORMATION64 *mbi) = 0;
		virtual unsigned long __stdcall read_memory(uint64_t address, void *buffer, size_t buffer_size) = 0;
		virtual bool __stdcall get_context(void *context, size_t context_size) = 0;
	};

	template <class T> bool __stdcall create(void **u);
	template <typename T1, class T2> bool __stdcall create(std::shared_ptr<T2> &u);
}
///
/// class
///
#define MAX_ARGUMENT_LENGTH		1024

class WindbgSafeLinker : public binary::linker
{
private: 
	/// 속도를 위해 미리 생성
	void *debug_client_;
	void *debug_data_space_;
	void *debug_data_space_2_;
	void *debug_advanced_;
	void *debug_system_objects_;

	bool init_flag_;

public:
	WindbgSafeLinker();
	~WindbgSafeLinker();

	virtual void __stdcall setting(const char *argument_str, int *argument_count, char(*args)[MAX_ARGUMENT_LENGTH]);

	virtual unsigned long long __stdcall get_teb_address();
	virtual unsigned long long __stdcall get_peb_address();

	virtual bool __stdcall virtual_query(uint64_t address, void *context, size_t context_size);
	virtual bool __stdcall virtual_query(uint64_t address, MEMORY_BASIC_INFORMATION64 *mbi);
	virtual unsigned long __stdcall read_memory(uint64_t address, void *buffer, size_t buffer_size);
	virtual bool __stdcall get_context(void *context, size_t context_size);
};

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
///
///
///
template <class T> 
bool __stdcall binary::create(void **u)
{
	try
	{
		T *obj = new T;
		*u = obj;
	}
	catch (...)
	{
		return false;
	}

	return true;
}

template <typename T1, class T2> 
bool __stdcall binary::create(std::shared_ptr<T2> &u)
{
	void *o = nullptr;

	if (!create<T1>(&o))
		return false;

	u.reset(static_cast<T2 *>(o));

	return true;
}

#endif