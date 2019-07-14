#include <engextcpp.hpp>
#include <kernelib.h>

WindbgThread::WindbgThread(unsigned long long ethread, unsigned long tid, ExtRemoteTyped ethread_node)
	: ethread_(ethread), tid_(tid), ethread_node_(ethread_node)
{
}

WindbgThread::~WindbgThread()
{
}

unsigned long WindbgThread::Tid()
{
	return tid_;
}

unsigned long long WindbgThread::Ethread()
{
	return ethread_;
}

//
WindbgProcess::WindbgProcess(unsigned long long eprocess, unsigned long pid, ExtRemoteTyped eprocess_node)
	: eprocess_(eprocess), pid_(pid), eprocess_node_(eprocess_node)
{
	eprocess_node.Field("ImageFileName").GetString((PTSTR)&name_, sizeof(name_));
}

WindbgProcess::~WindbgProcess()
{
	if (vads_.size())
	{
		for (auto it : vads_)
		{
			delete it;
		}
	}

	if (threads_.size())
	{
		for (auto it : threads_)
		{
			delete it;
		}
	}
}

std::vector<WindbgProcess *> WindbgProcess::Processes()
{
	std::vector<WindbgProcess *> processes;
	if (g_Ext->IsKernelMode())
	{
		ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessList(); // eprocess list
		for (list.StartHead(); list.HasNode(); list.Next())
		{
			ExtRemoteTyped n = list.GetTypedNode();
			ULONG64 current_pid = n.Field("UniqueProcessId").GetPtr();
			WindbgProcess * process = new WindbgProcess(list.GetNodeOffset(), (unsigned long)current_pid, n);
			processes.push_back(process);
		}
	}
	return processes;
}

void WindbgProcess::Cleanup(std::vector<WindbgProcess *> processes)
{
	for (auto it : processes)
	{
		delete it;
	}
}

WindbgProcess * WindbgProcess::Find(std::vector<WindbgProcess *> processes, unsigned long long eprocess)
{
	for (auto it : processes)
	{
		if (it->EProcess() == eprocess)
		{
			return it;
		}
	}
	return nullptr;
}

//
std::vector<WindbgThread *> WindbgProcess::Threads()
{
	if (threads_.size())
	{
		for (auto it : threads_)
		{
			delete it;
		}
		threads_.clear();
	}

	ExtRemoteTypedList list = ExtNtOsInformation::GetKernelProcessThreadList(eprocess_);
	for (list.StartHead(); list.HasNode(); list.Next())
	{
		ExtRemoteTyped n = list.GetTypedNode();
		if (n.HasField("Cid"))
		{
			WindbgThread * thread = new WindbgThread(list.GetNodeOffset(), (unsigned long)n.Field("Cid.UniqueThread").GetPtr(), n);
			threads_.push_back(thread);
		}
	}
	return threads_;
}

char * WindbgProcess::Name()
{
	return name_;
}

unsigned long WindbgProcess::Pid()
{
	return pid_;
}

unsigned long long WindbgProcess::EProcess()
{
	return eprocess_;
}

bool WindbgProcess::SetVadList_(ExtRemoteTyped node)
{
	if (!node.GetPtr())
	{
		return false;
	}

	ULONG64 val = node.GetPtr();
	ExtRemoteTyped current = ExtRemoteTyped("(nt!_MMVAD *)@$extin", val);
	if (!current.HasField("Core"))
	{
		return false;
	}

	ExtRemoteTyped left = current.Field("Core").Field("VadNode").Field("Left");
	ExtRemoteTyped right = current.Field("Core").Field("VadNode").Field("Right");

	SetVadList_(left);

	ULONG64 start = current.Field("Core").Field("StartingVpn").GetUlong();
	ULONG64 end = current.Field("Core").Field("EndingVpn").GetUlong();
	if (current.Field("Core").HasField("StartingVpnHigh") && current.Field("Core").HasField("EndingVpnHigh"))
	{
		ULONG64 start_high = current.Field("Core").Field("StartingVpnHigh").GetUchar();
		ULONG64 end_high = current.Field("Core").Field("EndingVpnHigh").GetUchar();

		start = start | (start_high << 32);
		end = end | (end_high << 32);
	}
	start <<= 12;
	end <<= 12;

	VadNodePtr vad = new VadNode;
	memset(vad, 0, sizeof(VadNode));

	vad->start = start;
	vad->end = end;
	vad->type = current.Field("Core").Field("u.VadFlags.VadType").GetUlong();
	vad->protect = current.Field("Core").Field("u.VadFlags.Protection").GetUlong();
	vad->is_private = current.Field("Core").Field("u.VadFlags.PrivateMemory").GetUlong();
	vad->commit = current.Field("Core").Field("u1.VadFlags1.MemCommit").GetUlong();

	//if (current.HasField("Subsection"))
	//{
	//	unsigned long long sub_section_ptr = current.Field("Subsection").GetPtr();
	//	ExtRemoteTyped sub_section("(nt!_SUBSECTION *)@$extin", sub_section_ptr);
	//	vad.object = sub_section.Field("ControlArea").Field("FilePointer").Field("Object").GetPtr();
	//}

	vads_.push_back(vad);

	SetVadList_(right);

	return true;
}

std::vector<WindbgProcess::VadNodePtr> WindbgProcess::Vads()
{
	if (vads_.size())
	{
		for (auto it : vads_)
		{
			delete it;
		}
		vads_.clear();
	}

	if (eprocess_node_.Field("VadRoot").HasField("Root"))
	{
		ExtRemoteTyped vad_root_node = eprocess_node_.Field("VadRoot").Field("Root");
		SetVadList_(vad_root_node);
	}

	return vads_;
}