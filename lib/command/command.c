#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include "names.inc"

const char *
get_command_name(command_t cmd)
{
	static const char *names[] = CODE_NAMES;

	if ((cmd < CODE_MIN) || (CODE_MAX <= cmd))
		return ("invalid");
	return (names[cmd - CODE_MIN]);
}
