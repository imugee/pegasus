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
		virtual bool __stdcall read_register(unsigned int id, unsigned long long *value) = 0;
		virtual bool __stdcall write_register(unsigned int id, unsigned long long value) = 0;
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
		
		virtual bool __stdcall write_file_log(wchar_t *log_dir, wchar_t *log_file_name, wchar_t *format, ...) = 0;
		virtual bool __stdcall write_binary(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned char *dump, size_t size) = 0;
	};

	template <typename T1, class T2> bool __stdcall create(std::shared_ptr<T2> &u);
}
///
///
///
template <typename T1, class T2>
bool __stdcall binary::create(std::shared_ptr<T2> &u)
{
	try
	{
		void *o = nullptr;
		T1 *t = new T1;

		o = t;
		u.reset(static_cast<T2 *>(o));
	}
	catch (...)
	{
		return false;
	}

	return true;
}

#endif
