#include "xdv_sdk.h"

// pegasus
#include <Windows.h>
#include <WDBGEXTS.H>

#include <stdarg.h>

bool XdvPrintLog(char *format, ...)
{
	IObject *object = XdvGetObjectByString("Log");
	if (!object)
	{
		return false;
	}

	std::string log_str;
	time_t now = time(0);
	struct tm tstruct;
	char time_buf[80];
	errno_t e = localtime_s(&tstruct, &now);
	if (e == 0)
	{
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%d.%X", &tstruct);
	}
	log_str += time_buf;
	log_str += " ";

	char log_dump[1024] = { 0, };
	va_list ap;
	va_start(ap, format);
	vsprintf_s(log_dump, sizeof(log_dump), format, ap);
	va_end(ap);

	log_str += log_dump;
	log_str += "\n";

	//IViewer *viewer = (IViewer *)object;
	//viewer->Print(log_str);
	dprintf(" %s\n\n", log_str.c_str());

	return true;
}

bool XdvPrintViewer(xdv_handle vh, std::string str)
{
	IObject *object = XdvGetObjectByHandle(vh);
	if (!object || object->ObjectType() != xdv::object::id::XENOM_VIEWER_OBJECT)
	{
		return false;
	}

	IViewer *viewer = (IViewer *)object;
	viewer->Print(str);

	return true;
}

bool XdvPrintViewer(xdv_handle vh, std::string str, bool wait)
{
	IObject *object = XdvGetObjectByHandle(vh);
	if (!object || object->ObjectType() != xdv::object::id::XENOM_VIEWER_OBJECT)
	{
		return false;
	}

	IViewer *viewer = (IViewer *)object;
	viewer->Print(str, wait);

	return true;
}

bool XdvPrintAndClear(xdv_handle vh, std::string str, bool wait)
{
	IObject *object = XdvGetObjectByHandle(vh);
	if (!object || object->ObjectType() != xdv::object::id::XENOM_VIEWER_OBJECT)
	{
		return false;
	}
	IViewer *viewer = (IViewer *)object;
	viewer->PrintAndClear(str, wait);

	return true;
}
