#define _CRT_SECURE_NO_WARNINGS
#include <unicorn/unicorn.h>

#include <engextcpp.hpp>
#include <Windows.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <windbg_engine_linker.h>
#include <emulator.h>

#pragma comment(lib, "unicorn_static_x64.lib")

emulation_debugger::emulation_debugger()
{
	//engine::create<windbg_engine_linker>(windbg_linker_);
}