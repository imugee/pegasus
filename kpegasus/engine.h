#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE
#define __DEFINE_PEGASUS_WINDBG_ENGINE

class Extension : public ExtExtension
{
public:
	Extension();
	virtual HRESULT Initialize(void);

	void test();
	void test2();
};

#endif
