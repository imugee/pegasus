#include <engextcpp.hpp>
#include <engine.h>

#include <kernelib.h>

std::vector<WindbgProcess *> _processes;
EXT_CLASS_COMMAND(KernelMode, lp, "", "{;ed,o;ptr;;}")
{
	if (_processes.size())
	{
		WindbgProcess::Cleanup(_processes);
		_processes.clear();
	}

	dprintf(" Process list>\n");
	_processes = WindbgProcess::Processes();
	for (auto it : _processes)
	{
		Dml(" [%08x] <link cmd=\"!kd_process %p\">%s</link>\n", it->Pid(), it->EProcess(), it->Name());
	}
}

unsigned long long _eprocess = 0;
EXT_CLASS_COMMAND(KernelMode, kd_process, "", "{;ed,o;eprocess;;}")
{
	unsigned long n = GetNumUnnamedArgs();
	if (n == 0)
	{
		return;
	}

	unsigned long long eprocess = GetUnnamedArgU64(0);
	WindbgProcess * process = WindbgProcess::Find(_processes, eprocess);
	if (!process)
	{
		return;
	}

	std::vector<WindbgThread *> threads = process->Threads();
	ExecuteSilent(".process /r /p %I64x", eprocess);
	ExecuteSilent(".thread /r /p %I64x", threads[0]->Ethread());

	dprintf(" > process context=>%s, %I64x\n", process->Name(), eprocess);
	dprintf(" > thread context=>%d(%x), %I64x\n", threads[0]->Tid(), threads[0]->Tid(), threads[0]->Ethread());

	_eprocess = eprocess;
}

EXT_CLASS_COMMAND(KernelMode, lvm, "", "{;ed,o;eprocess;;}")
{
	if (_eprocess == 0)
	{
		return;
	}

	WindbgProcess * process = WindbgProcess::Find(_processes, _eprocess);
	if (!process)
	{
		return;
	}

	std::vector<WindbgProcess::VadNodePtr> vads = process->Vads();
	for (auto it : vads)
	{
		dprintf("   %0*I64x-%0*I64x, %d %d %d\n", 16, it->start, 16, it->end, it->commit, it->protect, it->type);
	}
}