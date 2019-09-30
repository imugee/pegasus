#include "xdv_sdk.h"
#include <stdarg.h>

std::vector<IObject *> _obj_table;

// --------------------------------------------------------
// 
bool XdvAddObject(void * object)
{
	try
	{
		IObject *obj = (IObject *)object;
		if (obj->ObjectType() == xdv::object::id::XENOM_NO_OBJECT)
		{
			return false;
		}

		_obj_table.push_back(obj);

		return true;
	}
	catch (...)
	{
	}

	return false;
}

// --------------------------------------------------------
// 
IObject * XdvGetObjectByHandle(xdv_handle h)
{
	return _obj_table[h];
}

IObject * XdvGetObjectByString(std::string object_str)
{
	for (size_t i = 0; i < _obj_table.size(); ++i)
	{
		std::string str = _obj_table[i]->ObjectString();
		if (strstr(str.c_str(), object_str.c_str()))
		{
			return _obj_table[i];
		}
	}

	return nullptr;
}

std::vector<IObject *> XdvGetObjectTable()
{
	return _obj_table;
}

// --------------------------------------------------------
// 
xdv_handle XdvGetHandleByObject(IObject *object)
{
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		if (obj_table[i] == object)
		{
			return (xdv_handle)i;
		}
	}

	return 0;
}

xdv_handle XdvGetHandleByString(std::string object_str)
{
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		std::string str = obj_table[i]->ObjectString();
		if (strstr(str.c_str(), object_str.c_str()))
		{
			return (xdv_handle)i;
		}
	}

	return 0;
}

// --------------------------------------------------------
// 
std::vector<IViewer *> XdvGetViewerTable()
{
	std::vector<IViewer *> table;
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		switch (obj_table[i]->ObjectType())
		{
		case xdv::object::id::XENOM_VIEWER_OBJECT:
			table.push_back((IViewer *)obj_table[i]);
			break;

		default:
			break;
		}
	}

	return table;
}

// --------------------------------------------------------
// 
xdv_handle _xenom_handle_table[xdv_handle_TABLE_MAX_IDX] = { 0, };
xdv_handle XdvGetArchitectureHandle()
{
	return _xenom_handle_table[xdv::handle::id::xdv_handle_ARCH_IDX];
}

std::vector<IArchitecture *> XdvGetArchitectureTable()
{
	std::vector<IArchitecture *> table;
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		switch (obj_table[i]->ObjectType())
		{
		case xdv::object::id::XENOM_X86_ARCHITECTURE_OBJECT:
		case xdv::object::id::XENOM_X64_ARCHITECTURE_OBJECT:
		case xdv::object::id::XENOM_X86_ANALYZER_OBJECT:
		case xdv::object::id::XENOM_X64_ANALYZER_OBJECT:
			table.push_back((IArchitecture *)obj_table[i]);
			break;

		default:
			break;
		}
	}

	return table;
}

// --------------------------------------------------------
// 
xdv_handle XdvGetParserHandle()
{
	return _xenom_handle_table[xdv::handle::id::xdv_handle_PARSER_IDX];
}

std::vector<IParser *> XdvGetParserTable()
{
	std::vector<IParser *> table;
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		switch (obj_table[i]->ObjectType())
		{
		case xdv::object::id::XENOM_PARSER_SYSTEM_OBJECT:
		case xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT:
			table.push_back((IParser *)obj_table[i]);
			break;

		default:
			break;
		}
	}

	return table;
}

// --------------------------------------------------------
// 
std::vector<IDebugger *> XdvGetDebuggerTable()
{
	std::vector<IDebugger *> table;
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		switch (obj_table[i]->ObjectType())
		{
		case xdv::object::id::XENOM_DEBUGGER_SYSTEM_OBJECT:
			table.push_back((IDebugger *)obj_table[i]);
			break;

		default:
			break;
		}
	}

	return table;
}

// --------------------------------------------------------
// 
void XdvSetArchitectureHandle(IObject *obj)
{
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		if (obj_table[i] == obj)
		{
			_xenom_handle_table[xdv::handle::id::xdv_handle_ARCH_IDX] = (xdv_handle)i;
		}
	}
}

void XdvSetParserHandle(IObject *obj)
{
	std::vector<IObject *> obj_table = _obj_table;
	for (size_t i = 0; i < obj_table.size(); ++i)
	{
		if (obj_table[i] == obj)
		{
			_xenom_handle_table[xdv::handle::id::xdv_handle_PARSER_IDX] = (xdv_handle)i;
		}
	}
}

