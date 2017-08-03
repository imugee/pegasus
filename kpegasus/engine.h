#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE
#define __DEFINE_PEGASUS_WINDBG_ENGINE

class WindbgEngine : public ExtExtension
{
public:
	WindbgEngine();
	virtual HRESULT Initialize(void);

	void test();
	void test2();
};
///
///
///
class EmulationEngine : public ExtExtension
{
public:
	EmulationEngine();

	void open();
	void close();
	void trace();
};

#endif
