#ifndef __DEFINE_PEGASUS_EMULATOR_HEADER
#define __DEFINE_PEGASUS_EMULATOR_HEADER

class emulation_debugger : public engine::debugger
{
private:
	//std::shared_ptr<engine::linker> windbg_linker_;
	windbg_engine_linker windbg_linker_;

public:
	emulation_debugger();
};

#endif // !__DEFINE_PEGASUS_EMULATOR_HEADER
