#include "xdv_sdk.h"

bool XdvRun(xdv_handle vh, IWorker::ThreadRunCallbackType callback, void *callback_context)
{
	IObject *object = XdvGetObjectByHandle(vh);
	if (!object || object->ObjectType() != xdv::object::id::XENOM_VIEWER_OBJECT)
	{
		return false;
	}

	IViewer *viewer = (IViewer *)object;
	IWorker *worker = viewer->GetWorker();

	worker->Run(vh, callback, callback_context);
	return true;
}
