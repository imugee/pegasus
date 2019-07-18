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

	dprintf(" Process list:\n");
	_processes = WindbgProcess::Processes();
	for (auto it : _processes)
	{
		Dml(" [%08x] <link cmd=\"!kd_process %p\">%s</link>\n", it->Pid(), it->EProcess(), it->Name());
	}
	dprintf("\n");
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

	dprintf("\n");
	dprintf(" Switch Process context..\n");
	dprintf("\n");

	dprintf(" EProcess context: %s, %I64x\n", process->Name(), eprocess);
	dprintf(" EThread context: %I64x, Tid: %d(0x%x)\n", threads[0]->Ethread(), threads[0]->Tid(), threads[0]->Tid());
	dprintf("\n");

	for (auto it : threads)
	{
		dprintf(" Thread: %d(0x%x), EThread: ", it->Tid(), it->Tid());
		Dml("<link cmd=\"!kd_thread %I64x\">%I64x</link>\n", it->Ethread(), it->Ethread());
	}
	dprintf("\n");

	_eprocess = eprocess;
}

EXT_CLASS_COMMAND(KernelMode, kd_thread, "", "{;ed,o;ethread;;}")
{
	unsigned long n = GetNumUnnamedArgs();
	if (n == 0)
	{
		return;
	}

	if (_eprocess == 0)
	{
		return;
	}

	WindbgProcess * process = WindbgProcess::Find(_processes, _eprocess);
	if (!process)
	{
		return;
	}

	dprintf("\n");
	dprintf(" Switch Thread context..\n");
	dprintf("\n");

	unsigned long long ethread = GetUnnamedArgU64(0);
	std::vector<WindbgThread *> threads = process->Threads();
	for (auto it : threads)
	{
		dprintf(" Thread: %d(0x%x), EThread: ", it->Tid(), it->Tid());
		Dml("<link cmd=\"!kd_thread %I64x\">%I64x</link>   ", it->Ethread(), it->Ethread());

		if (it->Ethread() == ethread)
		{
			dprintf("***");
			ExecuteSilent(".thread /r /p %I64x", it->Ethread());
		}
		dprintf("\n");
	}
	dprintf("\n");
}

EXT_CLASS_COMMAND(KernelMode, queryvm, "", "{;ed,o;ptr;;}")
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
	unsigned long n = GetNumUnnamedArgs();
	if (n == 0)
	{
		for (auto it : vads)
		{
			dprintf("   %0*I64x %0*I64x, %d %d %d\n", 16, it->start, 16, it->end, it->commit, it->protect, it->type);
		}
	}
	else
	{
		unsigned long long ptr = GetUnnamedArgU64(0);
		MEMORY_BASIC_INFORMATION mbi;
		if (process->QueryVirtual(ptr, &mbi))
		{
			dprintf("\n");
			dprintf("Mapping VAD list..\n");
			dprintf("Mapping PEB regions..\n");
			dprintf("\n");

			dprintf("Base Address: %0*I64x\n", 16, mbi.BaseAddress);
			dprintf("End Address: %0*I64x\n", 16, (unsigned long long)mbi.BaseAddress + mbi.RegionSize);
			dprintf("Region Size: %0*I64x\n", 16, mbi.RegionSize);
			dprintf("State: <Unknown>\n");
			dprintf("Protect: <Unknown>\n");
			dprintf("Type: ");
			switch (mbi.Type)
			{
			case MEM_IMAGE:
				dprintf("MEM_IMAGE\n");
				break;

			case MEM_PRIVATE:
				dprintf("MEM_PRIVATE\n");
				break;

			case MEM_MAPPED:
				dprintf("MEM_MAPPED\n");
				break;
			}

			dprintf("Allocation Base: %0*I64x\n", 16, mbi.AllocationBase);
			dprintf("Allocation Protect: ");
			switch (mbi.AllocationProtect)
			{
			case PAGE_NOACCESS:
				dprintf("PAGE_NOACCESS\n");
				break;
			case PAGE_READONLY:
				dprintf("PAGE_READONLY\n");
				break;
			case PAGE_EXECUTE:
				dprintf("PAGE_EXECUTE\n");
				break;
			case PAGE_EXECUTE_READ:
				dprintf("PAGE_EXECUTE_READ\n");
				break;
			case PAGE_READWRITE:
				dprintf("PAGE_READWRITE\n");
				break;
			case PAGE_WRITECOPY:
				dprintf("PAGE_WRITECOPY\n");
				break;
			case PAGE_EXECUTE_READWRITE:
				dprintf("PAGE_EXECUTE_READWRITE\n");
				break;
			case PAGE_EXECUTE_WRITECOPY:
				dprintf("PAGE_EXECUTE_WRITECOPY\n");
				break;

			default:
				dprintf("UNKNOWN(%08x)\n", mbi.AllocationProtect);
				break;
			}

			std::wstring module_name = process->GetModuleName((unsigned long long)mbi.AllocationBase, false);
			if (module_name.size())
			{
				dprintf("Module Name: %ls\n", module_name.c_str());
			}
			else
			{
				dprintf("Module Name: Unknown\n");
			}

			std::wstring path = process->GetModuleName((unsigned long long)mbi.AllocationBase, true);
			if (path.size())
			{
				dprintf("Module Path: %ls\n", path.c_str());
			}
			else
			{
				dprintf("Module Path: Unknown\n");
			}
			dprintf("\n");
		}
	}
}

EXT_CLASS_COMMAND(KernelMode, current, "", "{;ed,o;ptr;;}")
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

	dprintf("\n");
	dprintf(" EProcess context=>%I64x\n", _eprocess);
	dprintf("\n");

	std::vector<WindbgThread *> threads = process->Threads();
	dprintf(" EProcess context: %s, %I64x\n", process->Name(), _eprocess);
	dprintf(" EThread context: %I64x, Tid: %d(0x%x)\n", threads[0]->Ethread(), threads[0]->Tid(), threads[0]->Tid());
	dprintf("\n");

	for (auto it : threads)
	{
		dprintf(" Thread: %d(0x%x), EThread: ", it->Tid(), it->Tid());
		Dml("<link cmd=\"!kd_thread %I64x\">%I64x</link>\n", it->Ethread(), it->Ethread());
	}
	dprintf("\n");
}
