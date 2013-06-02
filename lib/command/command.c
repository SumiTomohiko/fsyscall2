#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/command/name.h>

const char *
get_command_name(command_t cmd)
{
	/*
	 * The following expression assumes that CALL_EXIT is the first command.
	 */
	int index = cmd - CALL_EXIT;
	const char *name_of_command[] = CALL_NAMES;
	const char *name_of_ret[] = RET_NAMES;

	return (((index & 1) == 0 ? name_of_command : name_of_ret)[index >> 1]);
}
