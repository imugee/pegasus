#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <engine.h>

#include <windbg_engine_linker.h>
#include <emulator.h>

std::shared_ptr<engine::debugger> g_emulator;

EXT_CLASS_COMMAND(EmulationEngine, attach, "", "{;e,o;;;}")
{
	if (g_emulator)
		g_emulator.reset();

	if (!engine::create<emulation_debugger>(g_emulator))
		return;

	if (g_emulator->attach())
		dprintf("attach process\n");
}

EXT_CLASS_COMMAND(EmulationEngine, trace, "", "{;e,o;;;}")
{
	if (!g_emulator)
		return;

	if (!g_emulator->trace32())
		dprintf("err..\n");
}