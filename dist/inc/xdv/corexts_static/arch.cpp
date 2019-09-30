#include "xdv_sdk.h"

unsigned long long XdvGetBeforePtr(xdv_handle ah, xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return 0;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->GetBeforePtr(ih, ptr);
}

unsigned long long XdvGetNextPtr(xdv_handle ah, xdv_handle ih, unsigned long long ptr)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return 0;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->GetNextPtr(ih, ptr);
}

bool XdvGetOperandValues(xdv_handle ah, xdv_handle ih, unsigned long long ptr, unsigned char *dump, std::vector<unsigned long long> &v)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return false;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->GetOperandValues(ih, ptr, dump, v);
}

typedef struct _tag_entry_point
{
	unsigned long long base;
	unsigned long long end;

	unsigned long long ptr;
	unsigned long long entry;

	unsigned char *dump;
}entry_ctx;

bool FindEntryPointCallback(unsigned long long ptr, void *cb_ctx, xdv::architecture::x86::block::id id)
{
	if (!cb_ctx)
	{
		return false;
	}

	entry_ctx *ctx = (entry_ctx *)cb_ctx;
	std::set<unsigned long long> trace_set;
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();

	XdvAnalyze(ah, ctx->base, ctx->end, ptr, ctx->dump, trace_set);
	std::set<unsigned long long>::iterator it = trace_set.find(ctx->ptr);
	if (it != trace_set.end())
	{
		ctx->entry = ptr;
		return false;
	}

	return true;
}

void XdvFineReferenceValues(xdv_handle ah, xdv_handle ih, unsigned long long base, size_t size, ref_callback_type cb, void *cb_ctx)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->FindReferenceValue(ih, base, size, cb, cb_ctx);
}

unsigned long long XdvFindEntryPoint(xdv_handle ah, xdv_handle ih, unsigned long long ptr)
{
	xdv::memory::type mbi;
	if (!XdvQueryMemory(ih, ptr, &mbi))
	{
		return 0;
	}

	unsigned long long begine = ptr - 0x5000;
	unsigned long long end = ptr + 0x1000;
	if (begine <= mbi.BaseAddress)
	{
		begine = mbi.BaseAddress;
	}

	if (end >= mbi.BaseAddress + mbi.RegionSize)
	{
		end = mbi.BaseAddress + mbi.RegionSize;
	}

	unsigned char *dump = (unsigned char *)malloc(size_t(end - begine));
	if (!dump)
	{
		return 0;
	}
	std::shared_ptr<void> dump_closer(dump, free);

	unsigned long long read = XdvReadMemory(ih, begine, dump, unsigned long(end - begine));
	if (read == 0)
	{
		return 0;
	}

	entry_ctx ctx;
	ctx.ptr = ptr;
	ctx.base = begine;
	ctx.end = begine + read;
	ctx.dump = dump;
	ctx.entry = 0;
	XdvAnalyze(ah, ih, begine, (size_t)read, FindEntryPointCallback, &ctx);

	return ctx.entry;
}

unsigned long long XdvDisassemble(xdv_handle ah, unsigned long long ptr, unsigned char *dump, void *context)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	IArchitecture *arch = (IArchitecture *)object;
	return arch->Disassemble(ptr, dump, context);
}

unsigned long long XdvDisassemble(xdv_handle ah, unsigned long long ptr, unsigned char *dump, char *mnemonic, size_t output_size)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	IArchitecture *arch = (IArchitecture *)object;
	return arch->Disassemble(ptr, dump, mnemonic, output_size);
}

unsigned long long XdvAssemble(xdv_handle ah, unsigned char *dump, size_t *insn_size, char *mnemonic)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return false;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT
		|| type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	IArchitecture *arch = (IArchitecture *)object;
	return arch->Assemble(dump, insn_size, mnemonic);
}

xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long ptr, std::set<unsigned long long> &ptr_set)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->Analyze(ih, ptr, ptr_set);
}

xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, unsigned long long base, unsigned long long end, unsigned long long ptr, unsigned char *dump, std::set<unsigned long long> &ptr_set)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->Analyze(base, end, ptr, dump, ptr_set);
}

xdv::architecture::x86::block::id XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long ptr, std::vector<unsigned long long> &ptr_vector)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return xdv::architecture::x86::block::id::X86_ANALYZE_FAIL;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->Analyze(ih, ptr, ptr_vector);
}

unsigned long long XdvAnalyze(xdv_handle ah, xdv_handle ih, unsigned long long base, size_t size, analyze_callback_type cb, void *cb_context)
{
	std::vector<IObject *> obj_table = XdvGetObjectTable();
	IObject *object = obj_table[ah];
	if (!object)
	{
		return 0;
	}

	xdv::object::id type = object->ObjectType();
	if (!(type == xdv::object::id::XENOM_X86_ANALYZER_OBJECT
		|| type == xdv::object::id::XENOM_X64_ANALYZER_OBJECT))
	{
		return 0;
	}

	ICodeAnalyzer *analyzer = (ICodeAnalyzer *)object;
	return analyzer->Analyze(ih, base, size, cb, cb_context);
}
