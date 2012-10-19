#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/command/name.h>

const char *
get_command_name(command_t cmd)
{
	const char *name_of_command[] = CALL_NAMES;
	const char *name_of_ret[] = RET_NAMES;

	return (((cmd & 1) == 0 ? name_of_command : name_of_ret)[cmd >> 1]);
}
