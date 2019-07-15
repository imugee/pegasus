#ifndef __DEFINE_KERNEL_LIB__
#define __DEFINE_KERNEL_LIB__

#include <vector>

typedef enum
{
	VAD_MM_ZERO_ACCESS, VAD_MM_READONLY, VAD_MM_EXECUTE, VAD_MM_EXECUTE_READ, VAD_MM_READWRITE, VAD_MM_WRITECOPY, VAD_MM_EXECUTE_READWRITE, VAD_MM_EXECUTE_WRITECOPY
}VAD_PROTECTION;

#define MAX_ARGUMENT_LENGTH		1024

//
class WindbgThread
{
private:
	unsigned long long ethread_;
	unsigned long tid_;
	ExtRemoteTyped ethread_node_;

public:
	WindbgThread(unsigned long long ethread, unsigned long tid, ExtRemoteTyped ethread_node);
	~WindbgThread();

	unsigned long Tid();
	unsigned long long Ethread();
};

//
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
	unsigned long pid_;
	unsigned long long eprocess_;
	char name_[16];

	ExtRemoteTyped eprocess_node_;

	std::vector<WindbgThread *> threads_;
	std::vector<VadNodePtr> vads_;

private:
	bool SetVadList_(ExtRemoteTyped node);

public:
	WindbgProcess(unsigned long long eprocess, unsigned long pid, ExtRemoteTyped eprocess_node);
	~WindbgProcess();

	static std::vector<WindbgProcess *> Processes();
	static void Cleanup(std::vector<WindbgProcess *> processes);
	static WindbgProcess * Find(std::vector<WindbgProcess *> processes, unsigned long long eprocess);

	//
	std::vector<WindbgThread *> Threads();
	std::vector<VadNodePtr> Vads();

	char * Name();
	unsigned long Pid();
	unsigned long long EProcess();

	bool QueryVirtual(unsigned long long base, MEMORY_BASIC_INFORMATION *mbi);
};

#endif