#include "xdv_sdk.h"

xvar nullvar()
{
	xvar r = { 0, };
	return r;
}

xvar ullvar(unsigned long long var)
{
	xvar r = { 0, };
	sprintf_s(r.tag, sizeof(r.tag), "-ull:%I64x", var);
	return r;
}

xvar ptrvar(void * var)
{
	xvar r = { 0, };
	sprintf_s(r.tag, sizeof(r.tag), "-ptr:%p", var);
	return r;
}

xvar handlevar(xdv_handle var)
{
	xvar r = { 0, };
	sprintf_s(r.tag, sizeof(r.tag), "-handle:%x", var);

	return r;
}

// --------------------------------------------------------
// 
unsigned long long ullvar(xvar var)
{
	if (strstr(var.tag, "ull"))
	{
		const char * svar = strstr(var.tag, ":") + 1;
		if (svar)
		{
			char * end = nullptr;
			unsigned long long r = strtoull(svar, &end, 16);
			return r;
		}
	}

	return 0;
}

void * ptrvar(xvar var)
{
	if (strstr(var.tag, "ptr"))
	{
		const char * svar = strstr(var.tag, ":") + 1;
		if (svar)
		{
			char * end = nullptr;
			unsigned long long r = strtoull(svar, &end, 16);
			return (void *)r;
		}
	}

	return nullptr;
}

xdv_handle handlevar(xvar var)
{
	if (strstr(var.tag, "handle"))
	{
		const char * svar = strstr(var.tag, ":") + 1;
		if (svar)
		{
			char * end = nullptr;
			xdv_handle xh = strtoul(svar, &end, 16);
			return xh;
		}
	}

	return 0;
}

// --------------------------------------------------------
// 
unsigned long long ullarg(char * argv[], int argc, char * option)
{
	char * ull_str = XdvValue(argv, argc, option, nullptr);
	if (!ull_str)
	{
		return 0;
	}

	return XdvToUll(ull_str);
}

void * ptrarg(char * argv[], int argc, char * option)
{
	char * ull_str = XdvValue(argv, argc, option, nullptr);
	if (!ull_str)
	{
		return 0;
	}

	return (void *)XdvToUll(ull_str);
}

xdv_handle handlearg(char * argv[], int argc, char * option)
{
	char * ull_str = XdvValue(argv, argc, option, nullptr);
	if (!ull_str)
	{
		return 0;
	}

	return (xdv_handle)XdvToUll(ull_str);
}

bool checkarg(char * argv[], int argc, char * option, char * value)
{
	char * str = XdvValue(argv, argc, option, nullptr);
	if (!str)
	{
		return false;
	}

	if (!value)
	{
		return true;
	}

	if (strstr(str, value))
	{
		return true;
	}

	return false;
}