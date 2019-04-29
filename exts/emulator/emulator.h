#ifndef __DEFINE_PEGASUS__
#define __DEFINE_PEGASUS__

#define _CRT_SECURE_NO_WARNINGS
#include "unicorn/unicorn.h"

#pragma comment(lib, "corexts.lib")

#ifdef _WIN64
#pragma comment(lib, "dbgcore_static_x64.lib")
#else
#pragma comment(lib, "dbgcore_static.lib")
#endif

#include "xdv_sdk.h"

#pragma pack(push, 1)
typedef struct _SegmentDescriptor 
{
	union {
		struct {
			unsigned long long limit_low : 16;
			unsigned long long base_low : 16;
			unsigned long long base_mid : 8;
			unsigned long long type : 4;
			unsigned long long system : 1;
			unsigned long long dpl : 2;
			unsigned long long present : 1;
			unsigned long long limit_hi : 4;
			unsigned long long avl : 1;
			unsigned long long l : 1;  //!< 64-bit code segment (IA-32e mode only)
			unsigned long long db : 1;
			unsigned long long granularity : 1;
			unsigned long long base_hi : 8;
		};
		unsigned long long descriptor; // resize 8byte.
	};
}SegmentDescriptor, *PSegmentDescriptor;
#pragma pack(pop)

typedef enum _tag_trace_type
{
	EMULATOR_TRACE_STEP_INTO,
	EMULATOR_TRACE_STEP_OVER,
	EMULATOR_TRACE_STEP_RUN
}TraceId;

class Emulator : public IDebugger
{
private:
	IDebugger * debugger_;
	uc_engine * uc_;

	unsigned long long gdt_base_;
	xdv::architecture::x86::context::type context_;

	unsigned long long syscall_rip_;

public:
	Emulator();
	~Emulator();

public:
	virtual xdv::object::id ObjectType();
	virtual std::string ObjectString();
	virtual void SetModuleName(std::string module);
	virtual std::string ModuleName();

public:
	virtual std::map<unsigned long, std::string> ProcessList();
	virtual unsigned long WaitForProcess(std::string process_name);

	//
	virtual bool Attach(unsigned long pid);
	virtual bool Open(char *path);
	virtual bool Open(unsigned long pid);
	virtual bool Update();

	virtual unsigned long ProcessId();

	//
	virtual unsigned long long Read(unsigned long long ptr, unsigned char *out_memory, unsigned long read_size);
	virtual unsigned long long Write(void * ptr, unsigned char *input_memory, unsigned long write_size);
	virtual bool Query(unsigned long long ptr, xdv::memory::type *memory_type);
	virtual void * Alloc(void *ptr, unsigned long size, unsigned long allocation_type, unsigned long protect_type);

	//
	virtual bool Select(unsigned long tid);
	virtual void Threads(std::map<unsigned long, unsigned long long> &thread_info_map);

	virtual bool GetThreadContext(xdv::architecture::x86::context::type *context);
	virtual bool SetThreadContext(xdv::architecture::x86::context::type *context);

	virtual bool SuspendThread(unsigned long tid);
	virtual bool ResumeThread(unsigned long tid);

	//
	virtual std::string Module(unsigned long long ptr);
	virtual unsigned long Symbol(unsigned long long ptr, unsigned long long *disp, char *symbol_str, unsigned long symbol_size);
	virtual unsigned long Symbol(unsigned long long ptr, char *symbol_str, unsigned long symbol_size);
	virtual unsigned long long SymbolToPtr(char *symbol_str);

	//
	virtual bool StackTrace(xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count);
	virtual bool StackTraceEx(unsigned long long bp, unsigned long long ip, unsigned long long sp, xdv::architecture::x86::frame::type *stack_frame, size_t size_of_stack_frame, unsigned long *stack_count);

	virtual unsigned long long GetPebAddress();
	virtual unsigned long long GetTebAddress();

	virtual bool StepInto(DebugCallbackT callback, void * cb_ctx);
	virtual bool StepOver(DebugCallbackT callback, void * cb_ctx);
	virtual bool RunningProcess();

	virtual unsigned char * GetBpBackupDump(unsigned long long ptr);
	virtual bool SetBreakPoint(DebugBreakPointId id, unsigned long long ptr);
	virtual DebugBreakPointId GetBreakPointId(unsigned long long ptr);
	virtual std::vector<unsigned long long> GetBreakPointList();

	virtual bool RestoreBreakPoint(unsigned long long ptr);
	virtual void ReInstallBreakPoint(unsigned long long ptr);
	virtual bool DeleteBreakPoint(unsigned long long ptr);

	virtual void RestoreAllBreakPoint();
	virtual void ReInstallAllBreakPoint();

public: // unicorn engine
	void SetSyscallRip(unsigned long long rip);
	unsigned long long GetSyscallRip();

	uc_mode GetCurrentArch();

	bool AttachEmulator();
	bool DetachEmulator();
	void SetSegmentDescriptor(SegmentDescriptor *desc, unsigned long long base, unsigned long long limit, uint8_t is_code);
	bool CreateGlobalDescriptorTable(uc_mode mode);
	bool LoadContext(uc_mode mode);
	bool LoadMsr(uc_mode mode);
	
	bool QueryEmulatorMemory(unsigned long long ptr, unsigned long long *base, unsigned long long *end);
	bool LoadEmulatorMemory(unsigned long long load_address, size_t load_size, void *dump, size_t write_size);
	bool LoadEmulatorMemory(unsigned long long address);

	bool Read32bitContext();
	bool Write32bitContext();

	bool Read64bitContext();
	bool Write64bitContext();

	bool Trace(TraceId id);
};

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

#endif