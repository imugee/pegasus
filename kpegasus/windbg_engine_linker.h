#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE_LINKER
#define __DEFINE_PEGASUS_WINDBG_ENGINE_LINKER

typedef enum
{
	VAD_MM_ZERO_ACCESS, VAD_MM_READONLY, VAD_MM_EXECUTE, VAD_MM_EXECUTE_READ, VAD_MM_READWRITE, VAD_MM_WRITECOPY, VAD_MM_EXECUTE_READWRITE, VAD_MM_EXECUTE_WRITECOPY
}VAD_PROTECTION;

#define MAX_ARGUMENT_LENGTH		1024

class windbg_process
{
public: // type
	typedef struct _vad_node
	{
		unsigned long long start;
		unsigned long long end;
		unsigned long type;
		unsigned long protect;
		unsigned long is_private;
		unsigned long commit;
		unsigned long long object;
	}vad_node, *vad_node_ptr;

private:
	unsigned long long pid_;
	unsigned long long eprocess_;
	ExtRemoteTyped eprocess_node_;
	ExtRemoteTyped vad_root_node_;
	std::list<vad_node> vad_list_;

private:
	bool __stdcall set_vad_list(ExtRemoteTyped node);

public:
	windbg_process(unsigned long long eprocess, unsigned long long pid, ExtRemoteTyped eprocess_node);
	std::list<vad_node> get_vad_list();
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

	std::shared_ptr<windbg_process> process_;
	windbg_process::vad_node_ptr vad_table_;

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
	virtual void * __stdcall get_vad_node(unsigned long long *size);
};

#endif // !__DEFINE_PEGASUS_WINDBG_ENGINE_LINKER
