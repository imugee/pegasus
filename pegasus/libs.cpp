#include <xdv_sdk.h>

#include <engextcpp.hpp>
#include <engine.h>

std::set<unsigned long long> _visit_set;
std::map<unsigned long long, unsigned long long> _visit_map;

std::mutex _ref_map_mutex;
std::mutex _analyze_map_mutex;
std::multimap<unsigned long long, unsigned long long> _ref_map;
std::map<unsigned long long, xdv::architecture::x86::block::id> _proc_map;
std::set<unsigned long long> _break_point_set;

unsigned long long getEntryPoint(unsigned long long ptr)
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();
	unsigned long long entry = 0;
	while (entry == 0)
	{
		unsigned char dump[16] = { 0, };
		unsigned long long read = XdvReadMemory(ih, ptr, dump, sizeof(dump));
		if (read == 0)
		{
			break;
		}

		xdv::architecture::x86::type type;
		unsigned long long size = XdvDisassemble(ah, ptr, dump, &type);
		if (size < 4)
		{
			--ptr;
			continue;
		}

		//ptr += size;
		entry = XdvFindEntryPoint(ah, ih, ptr--);
	}

	return entry;
}

void findReferenceValueCallback(unsigned long long callee, unsigned long long caller, void *cb_ctx)
{
	_ref_map_mutex.lock();
	_ref_map.insert(std::multimap<unsigned long long, unsigned long long>::value_type(callee, caller));
	_ref_map_mutex.unlock();
}

bool analyzeCodeBlockCallback(unsigned long long ptr, void *cb_ctx, xdv::architecture::x86::block::id id)
{
	_analyze_map_mutex.lock();
	_proc_map.insert(std::map<unsigned long long, xdv::architecture::x86::block::id>::value_type(ptr, id));
	_analyze_map_mutex.unlock();

	return true;
}

void AnalyzeCallback(void *ctx)
{
	dprintf(" [+] analyzer:: start\n");

	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();

	unsigned long long * ptr = (unsigned long long *)ctx;
	xdv::memory::type mbi;
	if (!XdvQueryMemory(ih, *ptr, &mbi))
	{
		free(ctx);
		return;
	}

	unsigned long long begine = *ptr;
	unsigned long long end = *ptr + 0x5000;
	if (begine <= mbi.BaseAddress)
	{
		begine = mbi.BaseAddress;
	}
	else
	{
		begine = getEntryPoint(begine);
	}

	if (end >= mbi.BaseAddress + mbi.RegionSize)
	{
		end = mbi.BaseAddress + mbi.RegionSize;
	}
	else
	{
		end = getEntryPoint(end);
	}

	if (begine == 0 || end == 0)
	{
		_visit_set.erase(mbi.BaseAddress); // remove lock
		free(ctx);
		return;
	}

	//
	// collect xref values
	{
		XdvFineReferenceValues(ah, ih, begine, (size_t)(end - begine), findReferenceValueCallback, nullptr);
	}

	//
	// analyze block
	{
		XdvAnalyze(ah, ih, begine, (size_t)(end - begine), analyzeCodeBlockCallback, nullptr);
	}

	_visit_set.erase(mbi.BaseAddress); // remove lock
	_visit_map[begine] = end; // add visit map

	free(ctx);

	dprintf(" [+] analyzer:: end\n");
}

void Analyze(unsigned long long ptr)
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();
	xdv::memory::type mbi;
	if (!XdvQueryMemory(ih, ptr, &mbi))
	{
		return;
	}

	std::set<unsigned long long>::iterator vsit = _visit_set.find(mbi.BaseAddress);
	if (vsit == _visit_set.end())
	{
		std::map<unsigned long long, unsigned long long>::iterator vmit = _visit_map.begin();
		for (vmit; vmit != _visit_map.end(); ++vmit)
		{
			if (vmit->first <= ptr && ptr <= vmit->second)
			{
				return;
			}
		}

		_visit_set.insert((unsigned long long)mbi.BaseAddress);
		unsigned long long * pptr = (unsigned long long *)malloc(sizeof(unsigned long long));
		*pptr = ptr;
#if 0
		//std::thread * analyze_thread = new std::thread(AnalyzeCallback, pptr);
#else
		AnalyzeCallback(pptr);
#endif
	}
}

void NavigationString(unsigned long long ptr, std::string &str)
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();

	std::set<unsigned long long>::iterator bi = _break_point_set.find(ptr);
	std::multimap<unsigned long long, unsigned long long>::iterator ri = _ref_map.find(ptr);
	std::map<unsigned long long, xdv::architecture::x86::block::id>::iterator pi = _proc_map.find(ptr);
	if (ri != _ref_map.end())
	{
		char symbol[256] = { 0, };
		if (XdvGetSymbolString(ih, ptr, symbol, sizeof(symbol)))
		{
			if (pi != _proc_map.end())
			{
				switch (pi->second)
				{
				case xdv::architecture::x86::block::id::X86_CODE_BLOCK:
					str += "\n ; =========================== subroutine ===========================";
					break;

				default:
					break;
				}
			}

			str += "\n ; .sym : ";
			str += symbol;
		}

		unsigned char dump[16] = { 0, };
		unsigned long long readn = XdvReadMemory(ih, ri->second, dump, sizeof(dump));
		if (readn == 0)
		{
			return;
		}

		str += "\n ; .xref ";

		std::pair<std::multimap<unsigned long long, unsigned long long>::iterator
			, std::multimap<unsigned long long, unsigned long long>::iterator> proc_table = _ref_map.equal_range(ptr);
		std::multimap<unsigned long long, unsigned long long>::iterator range_it = proc_table.first;
		if (proc_table.first != proc_table.second)
		{
			str += "\n ; ";
		}
		else
		{
			str += "\n";
		}

		int i = 0;
		for (range_it; range_it != proc_table.second; ++range_it, ++i)
		{
			if (i == 16)
			{
				str += "\n ; ";
				i = 0;
			}

			char xref_str[500] = { 0, };
			sprintf_s(xref_str, sizeof(xref_str), "0x%I64x ", range_it->second);
			str += xref_str;
		}

		str += "\n";
	}
	else if (pi != _proc_map.end())
	{
		char symbol[256] = { 0, };
		if (!XdvGetSymbolString(ih, ptr, symbol, sizeof(symbol)))
		{
			sprintf_s(symbol, sizeof(symbol), "unknown");
		}

		switch (pi->second)
		{
		case xdv::architecture::x86::block::id::X86_CODE_BLOCK:
			str += "\n ; =========================== subroutine ===========================";
			break;

		default:
			break;
		}

		str += "\n ; .sym : ";
		str += symbol;
		str += "\n";
	}

	xdv::architecture::x86::context::type *pctx = (xdv::architecture::x86::context::type *)ptrvar(XdvExe("!cpuv.getctx"));
	if (ptr && pctx && pctx->rip == ptr)
	{
		str += " ; ======= current point\n";
	}
	else if (bi != _break_point_set.end())
	{
		str += " ; ======= break point\n";
	}
}

// ------------------------------------------------------
//
unsigned long long CodeAndRemarkString(unsigned long long ptr, std::string &str)
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();

	unsigned char * dump = nullptr;
	unsigned char cdump[16] = { 0, };
	unsigned long long readn = XdvReadMemory(ih, ptr, cdump, sizeof(cdump));
	if (readn == 0)
	{
		return 0;
	}

	std::set<unsigned long long>::iterator bi = _break_point_set.find(ptr);
	if (bi != _break_point_set.end())
	{
		dump = XdvGetBpBackupDump(ih, ptr);
		if (!dump)
		{
			dump = cdump;
			_break_point_set.erase(bi);
		}
	}
	else
	{
		dump = cdump;
	}

	//
	// assemble mn & symbol & string
	char mn[200] = { 0, };
	unsigned long long r = XdvDisassemble(ah, ptr, dump, mn, sizeof(mn));
	if (r == 0)
	{
		return 0;
	}

	//
	//
	char asm_mn[3072] = { 0, };
	sprintf_s(asm_mn, sizeof(asm_mn), " %s", mn);

	//
	// remark
	unsigned long align = (unsigned long)(100 - strlen(mn));
	std::vector<unsigned long long> ov;
	bool ovr = XdvGetOperandValues(ah, ih, ptr, dump, ov);

	if (ov.size())
	{
		for (size_t i = 0; i < ov.size(); ++i)
		{
			unsigned char str[1024] = { 0, };
			readn = XdvReadMemory(ih, ov[i], str, sizeof(str));
			if (readn == 0)
			{
				continue;
			}

			char symbol[1000] = { 0, };
			memset(asm_mn, 0, sizeof(asm_mn));
			if (XdvGetSymbolString(ih, ov[i], symbol, sizeof(symbol)))
			{
				sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; 0x%I64x, %s", mn, align, ' ', ov[0], symbol);
			}
			else
			{
				sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; 0x%I64x, %s", mn, align, ' ', ov[0], "<unknown>");
			}

			if (!ovr)
			{
				std::string ascii;
				if (XdvIsAscii(str, sizeof(str), ascii))
				{
					memset(asm_mn, 0, sizeof(asm_mn));
					sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; \"%s\"", mn, align, ' ', ascii.c_str());
				}

				std::string unicode;
				if (XdvIsUnicode(str, sizeof(str), unicode))
				{
					memset(asm_mn, 0, sizeof(asm_mn));
					sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; L\"%s\"", mn, align, ' ', unicode.c_str());
				}
			}
		}
	}

	//
	// add str
	str += asm_mn;

	//
	//
	bool is_jxx = false;
	if (XdvIsJumpCode(ah, ptr, dump, &is_jxx) || XdvIsRetCode(ah, ptr, dump))
	{
		unsigned long long next = ptr + r;
		std::multimap<unsigned long long, unsigned long long>::iterator ri = _ref_map.find(next);
		std::map<unsigned long long, xdv::architecture::x86::block::id>::iterator pi = _proc_map.find(next);

		if (ri == _ref_map.end() && pi == _proc_map.end())
		{
			str += "\n";
		}
	}

	return r;
}

unsigned long long Disassemble(unsigned long long ptr, std::string &str)
{
	//
	// print code navigation
	Analyze(ptr);
	NavigationString(ptr, str);
	return CodeAndRemarkString(ptr, str);
}

void print_reg_64(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%0*I64x</col></b>", 16, c);
	else
		dprintf("%0*I64x", 16, c);
}

void print_reg_32(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%08x</col></b>", c);
	else
		dprintf("%08x", c);
}

void PrintCurrentContext()
{
	xdv::architecture::x86::context::type context;
	if (XdvGetThreadContext(XdvGetParserHandle(), &context))
	{
		std::string str;
		Disassemble(context.rip, str);

		xdv_handle h = XdvGetArchitectureHandle();
		IObject *obj = XdvGetObjectByHandle(h);
		if (!obj)
		{
			return;
		}

		switch (obj->ObjectType())
		{
		case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
		case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
			dprintf(" eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", (unsigned long)context.rax, (unsigned long)context.rbx, (unsigned long)context.rcx, (unsigned long)context.rdx, (unsigned long)context.rsi, (unsigned long)context.rdi);
			dprintf(" eip=%08x esp=%08x ebp=%08x efl=%08x\n", (unsigned long)context.rip, (unsigned long)context.rsp, (unsigned long)context.rbp, (unsigned long)context.efl);
			break;

		case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
		case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
			dprintf(" rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x rsi=%0*I64x rdi=%0*I64x\n", 16, context.rax, 16, context.rbx, 16, context.rcx, 16, context.rdx, 16, context.rsi, 16, context.rdi);
			dprintf(" rip=%0*I64x rsp=%0*I64x rbp=%0*I64x efl=%0*I64x\n", 16, context.rip, 16, context.rsp, 16, context.rbp, context.efl);
			dprintf(" r8=%0*I64x r9=%0*I64x r10=%0*I64x r11=%0*I64x r12=%0*I64x r13=%0*I64x r14=%0*I64x r15=%0*I64x\n", 16, context.r8, 16, context.r9, 16, context.r10, 16, context.r11, 16, context.r12, 16, context.r13, 16, context.r14, 16, context.r15);
			break;
		}

		dprintf(" cs=%x ds=%x es=%x fs=%x gs=%x ss=%x\n", context.cs, context.ds, context.es, context.fs, context.gs, context.ss);
		dprintf("%s\n\n", str.c_str());
	}
}
