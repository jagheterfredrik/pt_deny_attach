/*
 * System call prototypes.
 *
 * Derived from FreeBSD's syscalls.master by Landon Fuller, original RCS IDs below:
 *
 * $FreeBSD: src/sys/sys/sysproto.h,v 1.216 2008/01/08 22:01:26 jhb Exp $
 * created from FreeBSD: src/sys/kern/syscalls.master,v 1.235 2008/01/08 21:58:15 jhb Exp
 */

#define PAD_(t) (sizeof(uint64_t) <= sizeof(t) ? \
0 : sizeof(uint64_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define PADL_(t)        0
#define PADR_(t)        PAD_(t)
#else
#define PADL_(t)        PAD_(t)
#define PADR_(t)        0
#endif

/** ptrace request */
#define PT_DENY_ATTACH 31

/* nosys syscall */
#define SYS_syscall 0

/* exit syscall */
#define SYS_exit 1

/* fork syscall */
#define SYS_fork 2

/* read syscall */
#define SYS_read 3

/* wait4 syscall */
#define SYS_wait4 7

/* ptrace() syscall */
#define SYS_ptrace 26

struct ptrace_args {
	char req_l_[PADL_(int)]; int req; char req_r_[PADR_(int)];
	char pid_l_[PADL_(pid_t)]; pid_t pid; char pid_r_[PADR_(pid_t)];
	char addr_l_[PADL_(caddr_t)]; caddr_t addr; char addr_r_[PADR_(caddr_t)];
	char data_l_[PADL_(int)]; int data; char data_r_[PADR_(int)];
};

typedef int32_t	sy_call_t (struct proc *, void *, int *);
typedef void	sy_munge_t (const void *, void *);

/* Must match apple's structure, which differs significantly from FreeBSD's */
/* Note: New Mavericks structure */
struct sysent {
	sy_call_t	*sy_call;		/* implementing function */
	sy_munge_t	*sy_arg_munge32;	/* munge system call arguments for 32-bit processes */
	sy_munge_t	*sy_arg_munge64;	/* munge system call arguments for 64-bit processes */
	int32_t		sy_return_type; /* return type */
    int16_t		sy_narg;		/* number of arguments */
	uint16_t	sy_arg_bytes;	/* The size of all arguments for 32-bit system calls, in bytes */
};

struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

/* Borrowed from kernel source. It doesn't exist in Kernel.framework. */
struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};

