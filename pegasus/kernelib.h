#ifndef __DEFINE_KERNEL_LIB__
#define __DEFINE_KERNEL_LIB__

typedef enum
{
	VAD_MM_ZERO_ACCESS, VAD_MM_READONLY, VAD_MM_EXECUTE, VAD_MM_EXECUTE_READ, VAD_MM_READWRITE, VAD_MM_WRITECOPY, VAD_MM_EXECUTE_READWRITE, VAD_MM_EXECUTE_WRITECOPY
}VAD_PROTECTION;

#define MAX_ARGUMENT_LENGTH		1024

class WindbgThread
{
private:
	unsigned long long ethread_;
	unsigned long long tid_;

public:
	WindbgThread();
	WindbgThread(unsigned long long ethread, unsigned long long tid, ExtRemoteTyped ethread_node);
	~WindbgThread();

	unsigned long long __stdcall Tid() { return tid_; }
	unsigned long long __stdcall Ethread() { return ethread_; }
};

class WindbgProcess
{
public: // type
	typedef struct _tag_vad_node
	{
		unsigned long long start;
		unsigned long long end;
		unsigned long type;
		unsigned long protect;
		unsigned long is_private;
		unsigned long commit;
		unsigned long long object;
	}VadNode, *VadNodePtr;

private:
	unsigned long long pid_;
	unsigned long long eprocess_;

	std::vector<VadNode> vad_list_;
};

#endif