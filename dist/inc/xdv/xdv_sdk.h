#ifndef __DEFINE_XDV_SDK__
#define __DEFINE_XDV_SDK__

#include "xdv_interface.h"

template<class T>
XDV_WINDOWS_EXPORT
T * AddInterface()
{
	T *o = new T();
	IObject *object = (IObject *)o;
	if (XdvAddObject(o))
	{
		return o;
	}

	return nullptr;
}
#define __add_object(type_class) AddInterface<type_class>()
#define XENOM_ADD_INTERFACE()			extern "C" XDV_WINDOWS_EXPORT xdv_handle AddInterface()

#endif