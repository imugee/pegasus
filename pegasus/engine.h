#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE
#define __DEFINE_PEGASUS_WINDBG_ENGINE

class WindbgEngine : public ExtExtension
{
public:
	WindbgEngine();
	virtual HRESULT Initialize(void);
};

class EmulatorEngine : public ExtExtension
{
public:
	EmulatorEngine() {}

	void arch();
	void attach();

	void stepinto();
	void stepover();
};

#endif
