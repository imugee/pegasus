#include <xdv_sdk.h>

#include <engextcpp.hpp>
#include <engine.h>

//
//
unsigned long long getEntryPoint(unsigned long long ptr);
void Analyze(unsigned long long ptr);
void NavigationString(unsigned long long ptr, std::string &str);
unsigned long long CodeAndRemarkString(unsigned long long ptr, std::string &str);
unsigned long long Disassemble(unsigned long long ptr, std::string &str);

void PrintCurrentContext();

//
//
EXT_CLASS_COMMAND(EmulatorEngine, arch, "", "{;ed,o;bit;;}")
{
	unsigned long n = GetNumUnnamedArgs();
	if (n == 0)
	{
		return;
	}

	IObject * arch = nullptr;
	unsigned long long bit = GetUnnamedArgU64(0);
	std::string name;
	if (bit == 0x32)
	{
		arch = XdvGetObjectByString("x86");
		name = "x86 arch";
	}
	else if (bit == 0x64)
	{
		arch = XdvGetObjectByString("x64");
		name = "x64 arch";
	}
	else
	{
		dprintf(" [+] unsupported arch..\n");
		return;
	}

	XdvSetArchitectureHandle(arch);
	dprintf(" [+] emulator arch=>%s\n\n", name.c_str());
}

EXT_CLASS_COMMAND(EmulatorEngine, attach, "", "{bit;ed,o;bit;;}")
{
	if (XdvAttachProcess(XdvGetParserHandle(), 0))
	{
		PrintCurrentContext();
	}
}

EXT_CLASS_COMMAND(EmulatorEngine, stepinto, "", "{;ed,o;ptr;;}")
{
	unsigned long long ptr = 0;
	unsigned long n = GetNumUnnamedArgs();
	if (n != 0)
	{
		ptr = GetUnnamedArgU64(0); // 
	}

	if (XdvStepInto(XdvGetParserHandle(), nullptr, nullptr))
	{
		PrintCurrentContext();
	}
	else
	{
		dprintf("emulator:: stepinto f\n");
	}
}

EXT_CLASS_COMMAND(EmulatorEngine, stepover, "", "{;ed,o;ptr;;}")
{
	unsigned long long ptr = 0;
	unsigned long n = GetNumUnnamedArgs();
	if (n != 0)
	{
		ptr = GetUnnamedArgU64(0); // 
	}

	if (XdvStepOver(XdvGetParserHandle(), nullptr, nullptr))
	{
		PrintCurrentContext();
	}
	else
	{
		dprintf("emulator:: stepover f\n");
	}
}


