#include <sys/param.h>
#include <sys/stat.h>
#include <assert.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	array_sizeof(a)	(sizeof(a) / sizeof(a[0]))

static const char *
register_of_size(size_t size)
{
	switch (size) {
	case 2:
		return "ax";
	case 4:
		return "eax";
	case 8:
		return "rax";
	default:
		abort();
		/* NOTREACHED */
	}
}

static void
usage()
{
	printf("%s [-v|--verbose]\n", getprogname());
}

int
main(int argc, char *argv[])
{
	FILE *name_fp, *print_fp;
	struct stat stat;
	struct option opts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	unsigned long offset;
	int opt;
	bool verbose = false;
	char name_path[MAXPATHLEN], print_path[MAXPATHLEN], prog[MAXPATHLEN];
	const char *dirpath, *fmt = "offsetof(struct stat, %s)=%lu\n", *reg, *s;
	const char *tmpl = "\
\t; %s\n\
\tmov\trdi, member\n\
\tmov\trsi, %s\n\
\tcall\tstreq\n\
\tcmp\trax, 0\n\
\tjne\t.%s_end\n\
\tmov\t%s, [sb + %lu]\n\
\tmov\trdi, rax\n\
\tcall\tprint_num\n\
.%s_end:\n\
\n";
	const char *vim = "; vim: filetype=nasm\n";

	while ((opt = getopt_long(argc, argv, "v", opts, NULL)) != -1)
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case '?':
		default:
			usage();
			exit(1);
		}

	strlcpy(prog, argv[0], array_sizeof(prog));
	dirpath = dirname(prog);
	snprintf(name_path, array_sizeof(name_path), "%s/name.inc", dirpath);
	snprintf(print_path, array_sizeof(print_path), "%s/print.inc", dirpath);
	name_fp = fopen(name_path, "w");
	assert(name_fp != NULL);
	print_fp = fopen(print_path, "w");
	assert(print_fp != NULL);

	if (verbose)
		printf("sizeof(struct stat)=%zu\n", sizeof(struct stat));

#define	PROCESS_MEMBER(name)	do {				\
	reg = register_of_size(sizeof(stat.name));		\
	offset = offsetof(struct stat, name);			\
	if (verbose)						\
		printf(fmt, #name, offset);			\
	fprintf(name_fp, "%s:\tdb\t\"%s\", 0\n", #name, #name);	\
	s = #name;						\
	fprintf(print_fp, tmpl, s, s, s, reg, offset, s);	\
} while (0)
	PROCESS_MEMBER(st_dev);
	PROCESS_MEMBER(st_ino);
	PROCESS_MEMBER(st_mode);
	PROCESS_MEMBER(st_nlink);
	PROCESS_MEMBER(st_uid);
	PROCESS_MEMBER(st_gid);
#if 0
	PROCESS_MEMBER(st_atim);
	PROCESS_MEMBER(st_mtim);
	PROCESS_MEMBER(st_ctim);
#endif
	PROCESS_MEMBER(st_size);
	PROCESS_MEMBER(st_blocks);
	PROCESS_MEMBER(st_blksize);
	PROCESS_MEMBER(st_flags);
	PROCESS_MEMBER(st_gen);
	PROCESS_MEMBER(st_lspare);
#if 0
	PROCESS_MEMBER(st_birthtim);
#endif
#undef	PROCESS_MEMBER

	fprintf(print_fp, "%s", vim);
	fprintf(name_fp, "%s", vim);

	fclose(print_fp);
	fclose(name_fp);

	return (0);
}
