#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE_LINKER
#define __DEFINE_PEGASUS_WINDBG_ENGINE_LINKER

typedef enum
{
	VAD_PAGE_READONLY = 1, VAD_PAGE_EXECUTE, VAD_PAGE_EXECUTE_READ, VAD_PAGE_READWRITE, VAD_PAGE_WRITECOPY, VAD_PAGE_EXECUTE_READWRITE, VAD_PAGE_EXECUTE_WRITECOPY
}VAD_PROTECTION;

#define MAX_ARGUMENT_LENGTH		1024

class windbg_process
{
private:
	unsigned long long eprocess_;
	ExtRemoteTyped eprocess_node_;
	ExtRemoteTyped vad_root_node_;
	//std::list<MEMORY_BASIC_INFORMATION64> vad_list_;

private:
	bool __stdcall set_vad_list(ExtRemoteTyped node);

public:
	windbg_process(unsigned long long eprocess, ExtRemoteTyped eprocess_node);
};

class windbg_engine_linker : public engine::linker
{
private:
	void *debug_client_;
	void *debug_data_space_;
	void *debug_data_space_2_;
	void *debug_advanced_;
	void *debug_system_objects_;

	bool init_flag_;

	//std::list<windbg_process> process_list_;
	unsigned long long pid_;
	windbg_process *process_;

public:
	windbg_engine_linker();
	~windbg_engine_linker();

	virtual void __stdcall setting(const char *argument_str, int *argument_count, char(*args)[MAX_ARGUMENT_LENGTH]);

	virtual unsigned long long __stdcall get_teb_address();
	virtual unsigned long long __stdcall get_peb_address();

	virtual bool __stdcall virtual_query(uint64_t address, void *context, size_t context_size);
	virtual bool __stdcall virtual_query(uint64_t address, MEMORY_BASIC_INFORMATION64 *mbi);
	virtual unsigned long __stdcall read_memory(uint64_t address, void *buffer, size_t buffer_size);
	virtual bool __stdcall get_context(void *context, size_t context_size);

	virtual bool __stdcall write_file_log(wchar_t *log_dir, wchar_t *log_file_name, wchar_t *format, ...);
	virtual bool __stdcall write_binary(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned char *address, size_t size);
	virtual bool __stdcall read_binary(wchar_t *bin_dir, wchar_t *bin_file_name, unsigned char *address, size_t size);

	virtual void __stdcall select_process(unsigned long long pid);
};

#endif // !__DEFINE_PEGASUS_WINDBG_ENGINE_LINKER
