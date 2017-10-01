#include <Windows.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include <stdio.h>
#include <helper.h>

unsigned long long __stdcall setup(void *args)
{
	ldr_package_ptr ldr = (ldr_package_ptr)args;
	unsigned long long delta = (unsigned long long)ldr->image_base - ldr->nt_header->OptionalHeader.ImageBase;
	///
	/// set reloc
	///
	PIMAGE_BASE_RELOCATION base_reloc = ldr->base_reloc;
	while (base_reloc->VirtualAddress)
	{
		if (base_reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			unsigned long long count = (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);
			unsigned short *list = (unsigned short *)(base_reloc + 1);
			unsigned long long *ptr = nullptr;

			for (unsigned int i = 0; i < count; ++i)
			{
				if (list[i])
				{
					ptr = (unsigned long long *)((unsigned long long)ldr->image_base + (base_reloc->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		base_reloc = (PIMAGE_BASE_RELOCATION)((unsigned long long)base_reloc + base_reloc->SizeOfBlock);
	}
	///
	/// set import descriptor
	///
	PIMAGE_IMPORT_DESCRIPTOR import_desc = ldr->import_dir;
	while (import_desc->Characteristics)
	{
		PIMAGE_THUNK_DATA origin_first_dunk = (PIMAGE_THUNK_DATA)((unsigned long long)ldr->image_base + import_desc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA first_dunk = (PIMAGE_THUNK_DATA)((unsigned long long)ldr->image_base + import_desc->FirstThunk);
		HMODULE module_handle = ldr->load_library((LPCSTR)ldr->image_base + import_desc->Name);

		if (!module_handle)
		{
			return 0;
		}

		while (origin_first_dunk->u1.AddressOfData)
		{
#ifdef _WIN64
			unsigned long long func = (unsigned long long)ldr->get_proc_address(module_handle, (LPCSTR)(origin_first_dunk->u1.Ordinal & 0xFFFF));
#else
			unsigned long func = (unsigned long)ldr->get_proc_address(module_handle, (LPCSTR)(origin_first_dunk->u1.Ordinal & 0xFFFF));
#endif
			if (origin_first_dunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				func = (unsigned long long)ldr->get_proc_address(module_handle, (LPCSTR)(origin_first_dunk->u1.Ordinal & 0xFFFF));
				if (!func)
				{
					return 0;
				}

				first_dunk->u1.Function = func;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((unsigned long long)ldr->image_base + origin_first_dunk->u1.AddressOfData);
				func = (unsigned long long)ldr->get_proc_address(module_handle, (LPCSTR)import_by_name->Name);
				if (!func)
				{
					return 0;
				}

				first_dunk->u1.Function = func;
			}

			++origin_first_dunk;
			++first_dunk;
		}

		++import_desc;
	}
	///
	/// call main
	///
	if (ldr->nt_header->OptionalHeader.AddressOfEntryPoint)
	{
		DllMainT entry_point = (DllMainT)((unsigned long long)ldr->image_base + ldr->nt_header->OptionalHeader.AddressOfEntryPoint);

		return entry_point((HMODULE)ldr->image_base, DLL_PROCESS_ATTACH, &ldr->args);
	}

	return 0;
}
unsigned long long __stdcall setup_end_point(void *args) { return 0; }

bool __stdcall install(wchar_t *module_name, unsigned long pid, module_load_information_type_ptr out_module_info, DLL_ARGS dll_args)
{
	if (!module_name)
	{
		return false;
	}

	HANDLE token_handle = nullptr;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
	{
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid.LowPart = 20;
		tp.Privileges[0].Luid.HighPart = 0;

		AdjustTokenPrivileges(token_handle, FALSE, &tp, 0, NULL, NULL);
		CloseHandle(token_handle);
	}

	HANDLE module_file_handle = CreateFile(module_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (module_file_handle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	unsigned long module_file_size = GetFileSize(module_file_handle, NULL);
	void *buffer = VirtualAlloc(NULL, module_file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
	{
		CloseHandle(module_file_handle);
		return false;
	}

	unsigned long readn = 0;
	if (!ReadFile(module_file_handle, buffer, module_file_size, &readn, NULL))
	{
		CloseHandle(module_file_handle);
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		return false;
	}
	CloseHandle(module_file_handle);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		return false;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + dos_header->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		return false;
	}

	HANDLE process_handle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	if (!process_handle)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		return false;
	}

	void *module_image = VirtualAllocEx(process_handle, NULL, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!module_image)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	if (!WriteProcessMemory(process_handle, module_image, buffer, nt_header->OptionalHeader.SizeOfHeaders, NULL))
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(nt_header + 1);
	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
	{
		if (!WriteProcessMemory(process_handle, (PVOID)((LPBYTE)module_image + section_header[i].VirtualAddress), (PVOID)((LPBYTE)buffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, NULL))
		{
			VirtualFree(buffer, module_file_size, MEM_RELEASE);
			VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
			CloseHandle(process_handle);

			return false;
		}
	}

	void *loader_image = VirtualAllocEx(process_handle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!loader_image)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	ldr_package ldr;
	memset(&ldr, 0, sizeof(ldr));

	ldr.image_base = module_image;
	ldr.nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module_image + dos_header->e_lfanew);
	ldr.base_reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)module_image + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ldr.import_dir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)module_image + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ldr.load_library = LoadLibraryA;
	ldr.get_proc_address = GetProcAddress;
	memcpy(&ldr.args, &dll_args, sizeof(dll_args));

	if (!WriteProcessMemory(process_handle, loader_image, &ldr, sizeof(ldr_package), NULL))
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
		VirtualFreeEx(process_handle, loader_image, 4096, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	if (!WriteProcessMemory(process_handle, (PVOID)((ldr_package_ptr)loader_image + 1), setup, (unsigned long long)setup_end_point - (unsigned long long)setup, NULL))
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
		VirtualFreeEx(process_handle, loader_image, 4096, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, (LPTHREAD_START_ROUTINE)((ldr_package_ptr)loader_image + 1), loader_image, 0, NULL);
	if (!thread_handle)
	{
		VirtualFree(buffer, module_file_size, MEM_RELEASE);
		VirtualFreeEx(process_handle, module_image, nt_header->OptionalHeader.SizeOfImage, MEM_RELEASE);
		VirtualFreeEx(process_handle, loader_image, 4096, MEM_RELEASE);
		CloseHandle(process_handle);

		return false;
	}

	out_module_info->target_process_handle = process_handle;
	out_module_info->main_thread_handle = thread_handle;

	out_module_info->loader_address = loader_image;
	out_module_info->size_of_loader = 4096;

	out_module_info->module_load_address = module_image;
	out_module_info->size_of_module_image = nt_header->OptionalHeader.SizeOfImage;

	VirtualFree(buffer, module_file_size, MEM_RELEASE);

	return true;
}
//
//
//
bool __stdcall process_name_to_pid(wchar_t *process_name, unsigned long *pid)
{
	PROCESSENTRY32 process_block32 = { 0, };
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!snapshot_handle)
		return false;

	process_block32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshot_handle, &process_block32))
	{
		CloseHandle(snapshot_handle);
		return false;
	}

	do
	{
		if (wcsstr(process_block32.szExeFile, process_name))
		{
			*pid = process_block32.th32ProcessID;
			CloseHandle(snapshot_handle);

			return true;
		}
	} while (Process32Next(snapshot_handle, &process_block32));

	CloseHandle(snapshot_handle);
	return false;
}

unsigned long wait(wchar_t *process_name)
{
	unsigned long pid = 0;

	while (INFINITE)
	{
		if (process_name_to_pid(process_name, &pid))
		{
			break;
		}
	}

	return pid;
}
