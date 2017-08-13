#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>
#include <engextcpp.hpp>
#include <memory>
#include <list>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

bool __stdcall emulation_debugger::file_query_ring3(unsigned long long value, wchar_t *file_name, size_t *size)
{
	WIN32_FIND_DATA wfd;
	wchar_t path[MAX_PATH] = { 0, };

	StringCbCopy(path, MAX_PATH, ring3_path_);
	StringCbCat(path, MAX_PATH, L"\\*.*");

	HANDLE h_file = FindFirstFile(path, &wfd);

	if (h_file == INVALID_HANDLE_VALUE)
		return false;
	std::shared_ptr<void> file_closer(h_file, CloseHandle);

	do
	{
		wchar_t *end = nullptr;
		unsigned long long base_address = wcstoll(wfd.cFileName, &end, 16);
		size_t region_size = (wfd.nFileSizeHigh * ((unsigned)0x100000000) + wfd.nFileSizeLow);
		unsigned long long end_address = base_address + region_size;

		if (base_address <= value && value < end_address)
		{
			if (file_name && size)
			{
				*size = region_size;
				StringCbCopy(file_name, MAX_PATH, wfd.cFileName);
				return true;
			}
		}
	} while (FindNextFile(h_file, &wfd));

	return false;
}

bool __stdcall emulation_debugger::clear_ring3()
{
	WIN32_FIND_DATA wfd;
	wchar_t path[MAX_PATH] = { 0, };
	unsigned int fail_count = 0;

	StringCbCopy(path, MAX_PATH, ring3_path_);
	StringCbCat(path, MAX_PATH, L"\\*.*");

	HANDLE h_file = FindFirstFile(path, &wfd);

	if (h_file == INVALID_HANDLE_VALUE)
		return false;
	std::shared_ptr<void> file_closer(h_file, CloseHandle);

	do
	{
		if (!wcsstr(wfd.cFileName, L".") && !wcsstr(wfd.cFileName, L".."))
		{
			wchar_t target[MAX_PATH];

			StringCbCopy(target, MAX_PATH, ring3_path_);
			StringCbCat(target, MAX_PATH, L"\\");
			StringCbCat(target, MAX_PATH, wfd.cFileName);

			if (!DeleteFile(target))
			{
				dprintf("%ls, %08x\n", target, GetLastError());
				++fail_count;
			}
		}
	} while (FindNextFile(h_file, &wfd));

	if (fail_count > 3)
		return false;

	return true;
}

unsigned char * __stdcall emulation_debugger::load_page(unsigned long long value, unsigned long long *base, size_t *size)
{
	wchar_t *end = nullptr;
	wchar_t name[MAX_PATH];
	size_t region_size = 0;
	wmemset(name, 0, MAX_PATH);

	if (!file_query_ring3(value, name, &region_size))
		return nullptr;

	unsigned char *dump = (unsigned char *)malloc(region_size);

	if (!dump)
		return nullptr;

	memset(dump, 0, region_size);

	if (!windbg_linker_.read_binary(ring3_path_, name, dump, region_size))
		return nullptr;

	*base = wcstoull(name, &end, 16);
	*size = region_size;

	return dump;
}

bool __stdcall emulation_debugger::backup(void *engine)
{
	uc_engine *uc = (uc_engine *)engine;
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

	for (unsigned int i = 0; i < count; ++i)
	{
		size_t size = um[i].end - um[i].begin + 1;
		unsigned char *dump = (unsigned char *)malloc(size);

		if (!dump)
			return false;

		memset(dump, 0, size);
		std::shared_ptr<void> dump_closer(dump, free);

		if (uc_mem_read(uc, um[i].begin, dump, size) != 0)
			return false;

		wchar_t name[MAX_PATH];
		wmemset(name, 0, MAX_PATH);
		if (!_ui64tow(um[i].begin, name, 16))
			return false;

		if (!windbg_linker_.write_binary(ring3_path_, name, dump, size))
			return false;
	}

	return true;
}

bool __stdcall emulation_debugger::write_binary(unsigned long long address)
{
	MEMORY_BASIC_INFORMATION64 mbi;
	if (!windbg_linker_.virtual_query(address, &mbi))
		return false;

	unsigned char *dump = (unsigned char *)malloc(mbi.RegionSize);
	if (!dump) 
		return false;
	std::shared_ptr<void> teb_dump_closer(dump, free);

	if (!windbg_linker_.read_memory(mbi.BaseAddress, dump, mbi.RegionSize))
		return false;

	wchar_t name[MAX_PATH];
	wmemset(name, 0, MAX_PATH);
	if (!_ui64tow(mbi.BaseAddress, name, 16))
		return false;
	if (!windbg_linker_.write_binary(ring3_path_, name, dump, mbi.RegionSize))
		return false;

	return true;
}