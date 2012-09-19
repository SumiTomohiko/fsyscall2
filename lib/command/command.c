#include <assert.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>

const char *
get_command_name(command_t cmd)
{
	const char *name_of_command[] = {
		"CALL_EXIT",
		"CALL_WRITE"
	};

	assert(cmd < array_sizeof(name_of_command));
	return (name_of_command[cmd]);
}
