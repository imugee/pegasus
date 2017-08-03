#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>

#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

#pragma comment(lib, "unicorn_static_x64.lib")

r3_emulation_debugger::r3_emulation_debugger()
{
}

bool __stdcall r3_emulation_debugger::attach()
{
	uint64_t address = 0;
	MEMORY_BASIC_INFORMATION64 mbi = { 0, };
	wchar_t bin_dir[MAX_PATH];
	wchar_t name[MAX_PATH];
	wmemset(bin_dir, 0, MAX_PATH);
	wmemset(name, 0, MAX_PATH);
	GetCurrentDirectory(MAX_PATH, bin_dir);
	StringCbCat(bin_dir, MAX_PATH, L"\\pegasus");

	CreateDirectory(bin_dir, FALSE);

	while (windbg_linker_.virtual_query(address, &mbi))
	{
		if (mbi.BaseAddress > address)
		{
			address = mbi.BaseAddress;
			continue;
		}

		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS))
		{
			unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);

			if (!dump)
				return false;

			memset(dump, 0, (size_t)mbi.RegionSize);
			std::shared_ptr<void> dump_closer(dump, free);

			if (!windbg_linker_.read_memory(mbi.BaseAddress, dump, (size_t)mbi.RegionSize))
				return false;

			if (!_ui64tow(mbi.BaseAddress, name, 16))
				return false;

			if (!windbg_linker_.write_binary(bin_dir, name, dump, (size_t)mbi.RegionSize))
				return false;

			memory_list_.push_back(mbi);
		}

		address += mbi.RegionSize;
		memset(&mbi, 0, sizeof(mbi));
	}

	CONTEXT context;
	memset(&context, 0, sizeof(context));

	if(!windbg_linker_.get_context(&context, sizeof(context)))
		return false;

	if (!windbg_linker_.write_binary(bin_dir, L"context", (unsigned char *)&context, sizeof(context)))
		return false;

	if (memory_list_.size() == 0)
		return false;

	windbg_linker_.file_query(bin_dir, L"*.*", 0x00403000, nullptr, nullptr);

	return true;
}
