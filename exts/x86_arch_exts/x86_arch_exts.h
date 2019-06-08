#ifndef __DEFINE_DBGHLPR_EXTS_X86_ARCH_HEADER__
#define __DEFINE_DBGHLPR_EXTS_X86_ARCH_HEADER__

#include <capstone.h>
#include <keystone.h>

// #define DLL_VERSION

#ifdef DLL_VERSION
#include "xdv_sdk.h"
#else
#include "xdv_interface.h"
#endif
#include <windows.h>

class x86Architecture : public ICodeAnalyzer
{
private:
	csh cs_handle_;
	cs_insn *insn_;

	csh cs_x86_handle_;
	cs_insn *x86_insn_;

	csh cs_x64_handle_;
	cs_insn *x64_insn_;

#define X86_ARCH_MUTEX_NAME		L"AD7F399E-BA01-4299-8C4F-EF0D8067DDA7"
	HANDLE mutex_;

private:
	ks_engine *ks_handle_;
	ks_engine *ks_x86_handle_;
	ks_engine *ks_x64_handle_;

	xdv::object::id arch_type_;

public:
	x86Architecture();
	~x86Architecture();

public:
	virtual xdv::object::id ObjectType();
	virtual std::string ObjectString();
	virtual void SetModuleName(std::string module);
	virtual std::string ModuleName();

public: // IArchitecture
	virtual unsigned long long Disassemble(unsigned long long ptr, unsigned char *dump, void *context);
	virtual unsigned long long Disassemble(unsigned long long ptr, unsigned char *dump, char *mnemonic, size_t output_size);

	virtual unsigned long long Assemble(unsigned char *dump, size_t *insn_size, char *mnemonic);

public: // IAnalyzer
	unsigned long long GetBeforePtr(xdv_handle ih, unsigned long long ptr, int back_offset);

	virtual unsigned long long GetBeforePtr(xdv_handle ih, unsigned long long ptr);
	virtual unsigned long long GetNextPtr(xdv_handle ih, unsigned long long ptr);

	virtual void FindReferenceValue(xdv_handle ih, unsigned long long base, size_t size, ref_callback_type cb, void *cb_ctx);

	virtual xdv::architecture::x86::block::id Analyze(unsigned long long base, unsigned long long end, unsigned long long ptr, unsigned char *dump, std::set<unsigned long long> &ptr_set);
	virtual xdv::architecture::x86::block::id Analyze(xdv_handle ih, unsigned long long ptr, std::set<unsigned long long> &ptr_set);
	virtual xdv::architecture::x86::block::id Analyze(xdv_handle ih, unsigned long long ptr, std::vector<unsigned long long> &ptr_vector);

	virtual unsigned long long Analyze(xdv_handle ih, unsigned long long base, size_t size, analyze_callback_type cb, void *cb_context);

	virtual bool GetOperandValues(xdv_handle ih, unsigned long long ptr, unsigned char *dump, std::vector<unsigned long long> &v);
	virtual bool IsJumpCode(unsigned long long ptr, unsigned char *dump, bool *jxx);
	virtual bool IsCallCode(unsigned long long ptr, unsigned char *dump);
	virtual bool IsRetCode(unsigned long long ptr, unsigned char *dump);
	virtual bool IsReadableCode(unsigned long long ptr, unsigned char *dump);
	virtual bool IsInterruptCode(unsigned long long ptr, unsigned char *dump);

private:
	bool check_ptr(xdv_handle ih, unsigned long long ptr);
	bool check(unsigned long long ptr, unsigned long long base, unsigned long long end);
};

#endif