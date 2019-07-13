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


