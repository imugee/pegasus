#include <xdv_sdk.h>

#include <engextcpp.hpp>
#include <engine.h>

//
unsigned long long getEntryPoint(unsigned long long ptr);
void Analyze(unsigned long long ptr);
void NavigationString(unsigned long long ptr, std::string &str);
unsigned long long CodeAndRemarkString(unsigned long long ptr, std::string &str);
unsigned long long Disassemble(unsigned long long ptr, std::string &str);

void PrintCurrentContext();

//
void FindEntryPoint(unsigned long long ptr)
{
	dprintf(" [+] find entry point\n");
	unsigned long long entry = getEntryPoint(ptr);
	if (entry)
	{
		dprintf(" [-] %I64x\n", entry);
	}
	else
	{
		dprintf(" [-] not found\n");
	}
}

EXT_CLASS_COMMAND(WindbgEngine, find, "", "{;ed,o;ptr;;}" "{entry;b,o;entry;;}")
{
	if (HasArg("entry"))
	{
		unsigned long n = GetNumUnnamedArgs();
		if (n == 0)
		{
			return;
		}
		unsigned long long ptr = GetUnnamedArgU64(0);
		FindEntryPoint(ptr);
	}
}

//
unsigned long long GetJumpDest(unsigned long long ptr)
{
	unsigned char dump[16] = { 0, };
	unsigned long long readn = XdvReadMemory(XdvGetParserHandle(), ptr, dump, sizeof(dump));
	if (readn == 0)
	{
		return 0;
	}

	bool is_jxx = false;
	if (XdvIsJumpCode(XdvGetArchitectureHandle(), ptr, dump, &is_jxx) || XdvIsCallCode(XdvGetArchitectureHandle(), ptr, dump))
	{
		std::vector<unsigned long long> ov;
		XdvGetOperandValues(XdvGetArchitectureHandle(), XdvGetParserHandle(), ptr, dump, ov);
		if (ov.size() == 1)
		{
			return ov[0];
		}
	}

	return 0;
}

unsigned long long CodeAndRemarkString(unsigned long long ptr, std::multimap<unsigned long long, unsigned long long> ref_map, unsigned long long debug_ptr)
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

	dump = cdump;

	// assemble mn & symbol & string
	char mn[200] = { 0, };
	unsigned long long r = XdvDisassemble(ah, ptr, dump, mn, sizeof(mn));
	if (r == 0)
	{
		return 0;
	}

	//
	char asm_mn[3072] = { 0, };
	sprintf_s(asm_mn, sizeof(asm_mn), " %s", mn);

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
				sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; %s", mn, align, ' ', symbol);
			}
			else
			{
				sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; %s", mn, align, ' ', "<unknown>");
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

	if (debug_ptr == ptr)
	{
		g_Ext->Dml("<link name=\"%I64x\"></link>", ptr);
		g_Ext->Dml("<b><col fg=\"changed\"> %s</col></b>", asm_mn);
	}
	else
	{
		g_Ext->Dml("<link name=\"%I64x\"> %s</link>", ptr, asm_mn);
	}

	//
	bool is_jxx = false;
	if (XdvIsJumpCode(ah, ptr, dump, &is_jxx) || XdvIsRetCode(ah, ptr, dump))
	{
		unsigned long long jump_dest = GetJumpDest(ptr);
		if (jump_dest)
		{
			dprintf(", ");
			g_Ext->Dml("<link section=\"%I64x\">jump branch</link>", jump_dest);
			dprintf("\n");
		}
		else
		{
			dprintf("\n");
		}
	}
	else if (XdvIsCallCode(ah, ptr, dump))
	{
		unsigned long long jump_dest = GetJumpDest(ptr);
		if (jump_dest)
		{
			char cmd[500] = { 0, };
			sprintf_s(cmd, sizeof(cmd), "!ut %I64x", jump_dest);

			dprintf(", ");
			g_Ext->DmlCmdLink("call branch", cmd),
			dprintf("\n");
		}
		else
		{
			dprintf("\n");
		}
	}
	else
	{
		unsigned long long next = ptr + r;
		std::multimap<unsigned long long, unsigned long long>::iterator ri = ref_map.find(next);

		if (ri != ref_map.end())
		{
			dprintf("\n");
		}
	}

	return r;
}

void FindReferenceValueCallback(unsigned long long callee, unsigned long long caller, void *cb_ctx)
{
	std::multimap<unsigned long long, unsigned long long> * ref_map = (std::multimap<unsigned long long, unsigned long long> *)cb_ctx;
	ref_map->insert(std::multimap<unsigned long long, unsigned long long>::value_type(callee, caller));
}

// -------------------------------------------------
//
EXT_CLASS_COMMAND(WindbgEngine, ut, "", "{;ed,o;ptr;;}" "{entry;b,o;entry;;}" "{debug;b,o;entry;;}")
{
	unsigned long n = GetNumUnnamedArgs();
	if (n == 0)
	{
		return;
	}

	unsigned long long debug_ptr = 0;
	unsigned long long ptr = GetUnnamedArgU64(0);
	unsigned long long entry = 0;
	if (HasArg("entry")){ entry = getEntryPoint(ptr); }
	if (HasArg("debug")){ debug_ptr = ptr; }

	std::set<unsigned long long> ptr_set;
	if (entry)
	{
		XdvAnalyze(XdvGetArchitectureHandle(), XdvGetParserHandle(), entry, ptr_set);
	}
	else
	{
		XdvAnalyze(XdvGetArchitectureHandle(), XdvGetParserHandle(), ptr, ptr_set);
	}

	unsigned long long start = *(ptr_set.begin());
	auto eit = ptr_set.end();
	unsigned long long end = *(--eit);

	std::multimap<unsigned long long, unsigned long long> ref_map;
	XdvFineReferenceValues(XdvGetArchitectureHandle(), XdvGetParserHandle(), start, (size_t)(end - start), FindReferenceValueCallback, &ref_map);

	dprintf("\n");
	Dml("<link name=\"TOP\">  ; goto </link>");
	Dml("<link section=\"%I64x\">%I64x\n</link>", ptr, ptr);

	for (auto it = ptr_set.begin(); it != ptr_set.end(); ++it)
	{
		auto fi = ref_map.find(*it);
		if (fi != ref_map.end())
		{
			auto pair = ref_map.equal_range(*it);

			dprintf("  > ");
			for (auto range = pair.first; range != pair.second; ++range)
			{
				Dml("<link section=\"%I64x\">%I64x</link>", range->second, range->second), dprintf(" ");
			}
			dprintf("\n");
		}

		CodeAndRemarkString(*it, ref_map, debug_ptr);
		dprintf("\n");
	}

	dprintf("  "), Dml("<link section=\"TOP\">[top]\n</link>", ptr, ptr);
}

//
EXT_CLASS_COMMAND(WindbgEngine, refstr, "", "{;ed,o;ptr;;}")
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();
	unsigned long long ptr = GetUnnamedArgU64(0);
	xdv::memory::type mbi;
	if (!XdvQueryMemory(ih, ptr, &mbi))
	{
		return;
	}

	std::multimap<unsigned long long, unsigned long long> ref_map;
	XdvFineReferenceValues(ah, XdvGetParserHandle(), mbi.BaseAddress, (size_t)mbi.RegionSize, FindReferenceValueCallback, &ref_map);

	int i = 0;
	std::string out;
	std::multimap<unsigned long long, unsigned long long>::iterator it = ref_map.begin();
	for (it; it != ref_map.end(); ++it)
	{
		if (mbi.BaseAddress <= it->second && it->second <= mbi.BaseAddress + mbi.RegionSize)
		{
			unsigned char dump[16] = { 0, };
			unsigned long long readn = XdvReadMemory(ih, it->second, dump, sizeof(dump));
			if (readn == 0)
			{
				continue;
			}

			if (!XdvIsReadableCode(ah, it->second, dump))
			{
				continue;
			}

			std::vector<unsigned long long> ov;
			bool ovr = XdvGetOperandValues(ah, ih, it->second, dump, ov);
			if (!ovr && ov.size() >= 1)
			{
				for (size_t i = 0; i < ov.size(); ++i)
				{
					unsigned char str[1024] = { 0, };
					readn = XdvReadMemory(ih, ov[i], str, sizeof(str));
					if (readn == 0)
					{
						continue;
					}

					//std::string asm_str;
					char mn[512] = { 0, };
					XdvDisassemble(ah, it->second, dump, mn, sizeof(mn));

					std::string ascii;
					if (XdvIsAscii(str, sizeof(str), ascii))
					{
						unsigned long align = (unsigned long)(100 - strlen(mn));
						char asm_mn[512] = { 0, };
						memset(asm_mn, 0, sizeof(asm_mn));
						sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; \"%s\"\n", mn, align, ' ', ascii.c_str());
						dprintf(" %s", asm_mn);
					}

					std::string unicode;
					if (XdvIsUnicode(str, sizeof(str), unicode))
					{
						unsigned long align = (unsigned long)(100 - strlen(mn));
						char asm_mn[512] = { 0, };
						memset(asm_mn, 0, sizeof(asm_mn));
						sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; L\"%s\"\n", mn, align, ' ', unicode.c_str());
						dprintf(" %s", asm_mn);
					}
				}
			}
		}
	}
}

EXT_CLASS_COMMAND(WindbgEngine, refexe, "", "{;ed,o;ptr;;}")
{
	xdv_handle ah = XdvGetArchitectureHandle();
	xdv_handle ih = XdvGetParserHandle();
	unsigned long long ptr = GetUnnamedArgU64(0);
	xdv::memory::type mbi;
	if (!XdvQueryMemory(ih, ptr, &mbi))
	{
		return;
	}

	std::multimap<unsigned long long, unsigned long long> ref_map;
	XdvFineReferenceValues(ah, XdvGetParserHandle(), mbi.BaseAddress, (size_t)mbi.RegionSize, FindReferenceValueCallback, &ref_map);

	int i = 0;
	std::string str;
	std::multimap<unsigned long long, unsigned long long>::iterator it = ref_map.begin();
	for (it; it != ref_map.end(); ++it)
	{
		if (!(mbi.BaseAddress <= it->first && it->first <= mbi.BaseAddress + mbi.RegionSize))
		{
			unsigned char dump[16] = { 0, };
			unsigned long long readn = XdvReadMemory(ih, it->second, dump, sizeof(dump));
			if (readn == 0)
			{
				continue;
			}

			bool jxx = false;
			if (!(XdvIsJumpCode(ah, it->second, dump, &jxx) || XdvIsCallCode(ah, it->second, dump)))
			{
				continue;
			}

			char mn[200] = { 0, };
			unsigned long long r = XdvDisassemble(ah, it->second, dump, mn, sizeof(mn));
			if (r == 0)
			{
				continue;
			}

			unsigned long align = (unsigned long)(100 - strlen(mn));
			char asm_mn[3072] = { 0, };
			sprintf_s(asm_mn, sizeof(asm_mn), " %s", mn);

			//
			std::vector<unsigned long long> ov;
			bool ovr = XdvGetOperandValues(ah, ih, it->second, dump, ov);
			if (ovr && ov.size() >= 1) // is call code
			{
				char symbol[1000] = { 0, };
				memset(asm_mn, 0, sizeof(asm_mn));
				if (XdvGetSymbolString(ih, ov[0], symbol, sizeof(symbol)))
				{
					sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; 0x%I64x, %s", mn, align, ' ', ov[0], symbol);
				}
				else
				{
					xdv::memory::type mbi;
					if (XdvQueryMemory(ih, ov[0], &mbi))
					{
						unsigned long long end = mbi.BaseAddress + mbi.RegionSize;
						sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; 0x%I64x, %s %I64x::%I64x-%I64x", mn, align, ' ', ov[0], "<unknown>", mbi.AllocationBase, mbi.BaseAddress, end);
					}
					else
					{
						sprintf_s(asm_mn, sizeof(asm_mn), " %s%*c; 0x%I64x, %s", mn, align, ' ', ov[0], "<unknown>");
					}
				}
			}
			else
			{
				continue;
			}

			dprintf("%s\n", asm_mn);
		}
	}
}