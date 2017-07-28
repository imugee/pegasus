#include "engextcpp.hpp"

class EXT_CLASS : public ExtExtension
{
public:
	EXT_COMMAND_METHOD(test);
};
EXT_DECLARE_GLOBALS();

EXT_COMMAND(test,
	"Output the user-mode OS loaded module list",
	"{;e,o;;}")
{
	//...
}
