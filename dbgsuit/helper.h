#ifndef __DEFINE_DBGSUIT_HELPER__
#define __DEFINE_DBGSUIT_HELPER__

typedef HMODULE(WINAPI *LoadLibraryT)(LPCSTR);	// LoadLibraryA
typedef FARPROC(WINAPI *GetProcAddressT)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *DllMainT)(HMODULE, DWORD, PVOID);

typedef struct _DLL_ARGS_
{
	WCHAR dll_path[MAX_PATH];
	ULONG64 break_point;
}DLL_ARGS, *PDLL_ARGS;

typedef struct _TAG_LOADER_TYPE
{
	void *image_base;
	PIMAGE_NT_HEADERS nt_header;
	PIMAGE_BASE_RELOCATION base_reloc;
	PIMAGE_IMPORT_DESCRIPTOR import_dir;
	LoadLibraryT load_library;
	GetProcAddressT get_proc_address;
	DLL_ARGS args;
}ldr_package, *ldr_package_ptr;

typedef struct _TAG_MODULE_LOAD_INFO
{
	HANDLE target_process_handle;
	HANDLE main_thread_handle;

	void *module_load_address;
	size_t size_of_module_image;

	void *loader_address;
	size_t size_of_loader;
}module_load_information_type, *module_load_information_type_ptr;
//
//
//
unsigned long long __stdcall setup(void *args);
unsigned long long __stdcall setup_end_point(void *args);
bool __stdcall install(wchar_t *module_name, unsigned long pid, module_load_information_type_ptr out_module_info, DLL_ARGS dll_args);
bool __stdcall process_name_to_pid(wchar_t *process_name, unsigned long *pid);
unsigned long wait(wchar_t *process_name);

#endif