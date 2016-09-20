#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

#define	UNKNOWN	"unknown"

static const char *
get_array_element(const char *a[], int len, int index)
{

	return ((0 <= index) && (index < len) ? a[index] : UNKNOWN);
}

static const char *
get_domain_str(int domain)
{
	static const char *domains[] = {
		"PF_UNSPEC",
		"PF_LOCAL",
		"PF_INET",
		"PF_IMPLINK",
		"PF_PUP",
		"PF_CHAOS",
		"PF_NETBIOS",
		"PF_ISO",
		"PF_ECMA",
		"PF_DATAKIT",
		"PF_CCITT",
		"PF_SNA",
		"PF_DECnet",
		"PF_DLI",
		"PF_LAT",
		"PF_HYLINK",
		"PF_APPLETALK",
		"PF_ROUTE",
		"PF_LINK",
		"pseudo_PF_XTP",
		"PF_COIP",
		"PF_CNT",
		"pseudo_PF_RTIP",
		"PF_IPX",
		"PF_SIP",
		"pseudo_PF_PIP",
		"PF_ISDN",
		"pseudo_PF_KEY",
		"PF_INET6",
		"PF_NATM",
		"PF_ATM",
		"pseudo_PF_HDRCMPLT",
		"PF_NETGRAPH",
		"PF_SLOW",
		"PF_SCLUSTER",
		"PF_ARP",
		"PF_BLUETOOTH",
		"PF_IEEE80211"
	};
	static int ndomains = array_sizeof(domains);

	return (get_array_element(domains, ndomains, domain));
}

static void
get_type_str(char *dst, size_t dstsize, int type)
{
	static struct flag_definition defs[] = {
		DEFINE_FLAG(SOCK_CLOEXEC),
		DEFINE_FLAG(SOCK_NONBLOCK)
	};
	static const char *types[] = {
		UNKNOWN,
		"SOCK_STREAM",
		"SOCK_DGRAM",
		"SOCK_RAW",
		"SOCK_RDM",
		"SOCK_SEQPACKET"
	};
	static int ntypes = array_sizeof(types);
	int flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
	const char *fmt, *s;
	char t[256];

	s = get_array_element(types, ntypes, ~flags & type);
	fmaster_chain_flags(t, sizeof(t), flags & type, defs,
			    array_sizeof(defs));
	fmt = t[0] == '\0' ? "%s" : "%s|%s";

	snprintf(dst, dstsize, fmt, s, t);
}

int
sys_fmaster_socket(struct thread *td, struct fmaster_socket_args *uap)
{
	struct timeval time_start;
	int domain, error, protocol, type;
	char typestr[256];
	const char *domainstr, *sysname = "socket";

	domain = uap->domain;
	domainstr = get_domain_str(domain);
	type = uap->type;
	get_type_str(typestr, sizeof(typestr), type);
	protocol = uap->protocol;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: domain=0x%x (%s), type=0x%x (%s), protocol=0x"
		    "%x",
		    sysname, domain, domainstr, type, typestr, protocol);
	microtime(&time_start);

	error = fmaster_register_pending_socket(td, domain, type, protocol);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}
