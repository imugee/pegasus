#ifndef __DEFINE_PEGASUS_WINDBG_HEADER__
#define __DEFINE_PEGASUS_WINDBG_HEADER__

#define MAX_ARGUMENT_LENGTH		1024

class WindbgSafeLinker : public binary::linker
{
private:
	/// ¼Óµµ¸¦ À§ÇØ ¹Ì¸® »ý¼º
	void *debug_client_;
	void *debug_data_space_;
	void *debug_data_space_2_;
	void *debug_advanced_;
	void *debug_system_objects_;

	bool init_flag_;

public:
	WindbgSafeLinker();
	~WindbgSafeLinker();

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
};

#endif
