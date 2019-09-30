#include "xdv_sdk.h"

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <mutex>
#include <thread>

size_t XxcnArgv(char *args, char * argv[])
{
	std::vector<std::string> arg_vector = XdvSplit(args, "(/)|(-)");
	for (size_t i = 0; i < arg_vector.size(); ++i)
	{
		char * str = (char *)malloc(arg_vector[i].size() + 10);
		memset(str, 0, arg_vector[i].size() + 10);

		size_t size = arg_vector[i].size();
		if (arg_vector[i].size() && arg_vector[i].c_str()[arg_vector[i].size() - 1] == ' ')
		{
			size -= 1;
		}
		memcpy(str, arg_vector[i].c_str(), size);
		argv[i] = str;
	}

	return arg_vector.size();
}

typedef enum { EXTS_TYPE_A, EXTS_TYPE_B } EXTS_TYPE;
std::vector<std::string> XXdvSplit(const std::string str, const std::string regex)
{
	std::regex split_with{ regex };
	std::sregex_token_iterator it{ str.begin(),str.end(),split_with, -1 };
	std::vector<std::string> tmp = { it,std::sregex_token_iterator{} };
	std::vector<std::string>::iterator b = tmp.begin();
	for (b; b != tmp.end(); ++b)
	{
		if (b->size() == 0)
		{
			tmp.erase(b);
		}
	}

	return tmp;
}

char * XxcnBlank(char *str)
{
	size_t size = strlen(str);
	size_t idx = 0;
	for (idx; idx < size; ++idx)
	{
		if (str[idx] == ' ')
		{
			break;
		}
		else if (str[idx] == '\n')
		{
			break;
		}
	}

	if (idx != size)
	{
		return &str[idx];
	}

	return nullptr;
}

char * XXdvValue(char * argv[], int argc, char *option, int *idx)
{
	for (int i = 0; i < argc; ++i)
	{
		if (strstr(argv[i], option))
		{
			if (idx)
			{
				*idx = i;
			}
			return strstr(argv[i], ":") + 1;
		}
	}

	return nullptr;
}

xvar XxcnCmd(char *module_name, char *func_name, char *args, EXTS_TYPE type)
{
	try
	{
		switch (type)
		{
		case EXTS_TYPE::EXTS_TYPE_A:
		{
			ExtensionFunctionT func = (ExtensionFunctionT)GetProcAddress(GetModuleHandleA(module_name), func_name);
			if (func)
			{
				char * argv[100] = { 0, };
				size_t argc = 0;
				if (strlen(args))
				{
					argc = XxcnArgv(args, argv);
				}

				xvar r = func((int)argc, argv);
				for (size_t i = 0; i < argc; ++i)
				{
					free(argv[i]);
				}

				return r;
			}
		}
		break;

		default:
			break;
		}
	}
	catch (...)
	{
	}

	return nullvar();
}

void * XxcnLoad(char * module_name)
{
	char dll[512] = { 0, };
	sprintf_s(dll, sizeof(dll), ".\\exts\\%s.dll", module_name);

	return LoadLibraryA(dll);
}

xvar exts(char *cmd)
{
	char module_name[MAX_COMMAND_LENGTH] = { 0, };
	char * func_split = strstr(cmd, ".");
	if (!func_split)
	{
		return nullvar();
	}
	memcpy(module_name, cmd, func_split - cmd);
	cmd = func_split + 1;

	char func_name[MAX_COMMAND_LENGTH] = { 0, };
	char args[MAX_COMMAND_LENGTH] = { 0, };
	char *blank = XxcnBlank(cmd);
	size_t size = 0;
	if (blank)
	{
		size = (int)(blank - cmd);
		memcpy(args, &cmd[size + 1], 1024);
	}
	else
	{
		size = strlen(cmd);
	}
	memcpy(func_name, &cmd[0], size);
	return XxcnCmd(module_name, func_name, args, EXTS_TYPE::EXTS_TYPE_A);
}

xvar exea(char *cmd)
{
	char func_name[MAX_COMMAND_LENGTH] = { 0, };
	char args[MAX_COMMAND_LENGTH] = { 0, };
	char *blank = XxcnBlank(cmd);
	size_t size = 0;
	if (blank)
	{
		size = (int)(blank - cmd);
		memcpy(args, &cmd[size + 1], 1024);
	}
	else
	{
		size = strlen(cmd);
	}
	memcpy(func_name, &cmd[0], size);
	return XxcnCmd(nullptr, func_name, args, EXTS_TYPE::EXTS_TYPE_A);
}

xvar exe(char *cmd)
{
	char mask = cmd[0];
	switch (mask)
	{
	case '!':
		return exts(cmd + 1);

	case '.':
		return exea(cmd + 1);

	default:
		//return exeb(cmd);
		break;
	}

	return nullvar();
}

// --------------------------------------------------------
// 
xvar XdvExe(char *format, ...)
{
	char cmd[MAX_COMMAND_LENGTH] = { 0, };
	va_list ap;
	va_start(ap, format);
	vsprintf_s(cmd, sizeof(cmd), format, ap);
	va_end(ap);

	return exe(cmd);
}

xvar XdvExeA(char *format, ...)
{
	char cmd[MAX_COMMAND_LENGTH] = { 0, };
	va_list ap;
	va_start(ap, format);
	vsprintf_s(cmd, sizeof(cmd), format, ap);
	va_end(ap);

	return exea(cmd);
}

xvar XdvExts(char *format, ...)
{
	char cmd[MAX_COMMAND_LENGTH] = { 0, };
	va_list ap;
	va_start(ap, format);
	vsprintf_s(cmd, sizeof(cmd), format, ap);
	va_end(ap);

	return exts(cmd);
}

std::vector<std::string> XdvSplit(const std::string str, const std::string regex)
{
	return XXdvSplit(str, regex);
}

char * XdvValue(char * argv[], int argc, char *option, int *idx)
{
	return XXdvValue(argv, argc, option, idx);
}

void * XdvLoadModule(char *module_name)
{
	return XxcnLoad(module_name);
}

unsigned long long XdvToUll(char * ull_str)
{
	char * end = nullptr;
	if (strstr(ull_str, "'"))
	{
		unsigned long long h_ull = strtoull(ull_str, &end, 16);
		unsigned long l_ull = strtoul(end + 1, &end, 16);
		unsigned long long ull = 0;

		ull |= (h_ull << 32);
		ull |= l_ull;

		return ull;
	}

	return strtoull(ull_str, &end, 16);
}
