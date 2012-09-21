#include <sys/stdint.h>
#include <assert.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>

const char *
get_command_name(command_t cmd)
{
	int ret;
	const char *name_of_command[] = {
		"CALL_EXIT",
		"CALL_OPEN",
		"CALL_WRITE"
	};
	const char *name_of_ret[] = {
		"INVALID",
		"RET_OPEN",
		"RET_WRITE"
	};

	if (cmd < UINT16_MAX)
		return (name_of_command[cmd]);
	ret = cmd >> 16;
	return (name_of_ret[ret]);
}
