/*
 * pt_deny_attach.c
 *
 * Author: Landon J. Fuller <landonf@opendarwin.org>
 *
 * Updated for Snow Leopard and Lion: Dan Walters <https://github.com/dwalters/pt_deny_attach>
 *
 * Updated for Mountain Lion: Matthew Robinson <matt@zensunni.org>
 *
 * This software is placed in the public domain
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <stdint.h>
#include "structures.h"


// The following header file can be generated
// for each OS X version using get_addresses.sh
#include "kernel_addresses.h"

// Allow the CPU to write to read-only pages by clearing the WP flag in the Control Register CR0
#define DISABLE_WRITE_PROTECTION()  asm volatile (                                  \
                                            "cli\n"                                 \
                                            "mov    %cr0,%rax\n"                    \
                                            "and    $0xfffffffffffeffff,%rax\n"     \
                                            "mov    %rax,%cr0"                      \
                                    )
// Re-enable the write protection by re-enabling the WP flag in the Control Register CR0
#define ENABLE_WRITE_PROTECTION()   asm volatile (                                  \
                                            "mov    %cr0,%rax\n"                    \
                                            "or     $0x10000,%rax\n"                \
                                            "mov    %rax,%cr0\n"                    \
                                            "sti"                                   \
                                    )


/*
 * The SYSENT_OFFSET was discovered by searching memory around 
 * _nsysent for an address that passes the sanity check.
 *
 * A for loop adding/subtracting from _nsysent will do the job.
 */
#define SYSENT_OFFSET         0x1C028

static struct sysent *_sysent;
static int *_nsysent;

static vm_offset_t slide;

typedef int	ptrace_func_t (struct proc *, struct ptrace_args *, int *);
static ptrace_func_t *real_ptrace;

static int our_ptrace (struct proc *p, struct ptrace_args *uap, int *retval)
{
	
	if (uap->req == PT_DENY_ATTACH) {
		printf("[ptrace] Blocking PT_DENY_ATTACH for pid %d.\n", uap->pid);
		return (0);
	} else {
        printf("[ptrace] Forwarding call to original ptrace for pid %d.\n", uap->pid);
		return real_ptrace(p, uap, retval);
	}
}

/*
 * nsysent is placed before the hidden sysent, so skip ahead
 * and sanity check that we've found the sysent array.
 *
 * Clearly, this is extremely fragile and not for general consumption.
 */
static struct sysent *find_sysent () {
	struct sysent *table;
    
	table = (struct sysent *) ( ((char *) _nsysent) + SYSENT_OFFSET);
    
    printf("[ptrace] Found nsysent at %p (count %d), calculated sysent location %p.\n", _nsysent, *_nsysent, table);
    
    /* Sanity check */
    printf("[ptrace] Sanity check %d %d %d %d %d %d %p: ",
           table[SYS_syscall].sy_narg,
           table[SYS_exit].sy_narg,
           table[SYS_fork].sy_narg,
           table[SYS_read].sy_narg,
           table[SYS_wait4].sy_narg,
           table[SYS_ptrace].sy_narg,
           table[SYS_ptrace].sy_call);
    
    if (table[SYS_syscall].sy_narg == 0 &&
        table[SYS_exit].sy_narg == 1  &&
        table[SYS_fork].sy_narg == 0 &&
        table[SYS_read].sy_narg == 3 &&
        table[SYS_wait4].sy_narg == 4 &&
        table[SYS_ptrace].sy_narg == 4 &&
        table[SYS_ptrace].sy_call == (void *)(_PTRACE_ADDR + slide))
    {
        printf("sysent sanity check succeeded.\n");
        return table;
    } else {
        printf("sanity check failed, could not find sysent table.\n");
        return NULL;
    }
}

/*
 * vm_kernel_slide doesn't appear to be available to kexts
 * but we can calculate it by getting the address of a known
 * function, e.g. printf, and then comparing that to the
 * address returned by nm -g /mach_kernel
 * 
 * We can then use the calculated slide to read the value of
 * the vm_kernel_slide variable to see if they match
 */
static vm_offset_t calculate_vm_kernel_slide(void) {
    vm_offset_t kernel_slide = (vm_offset_t)&printf - _PRINTF_ADDR;
    
    printf("[ptrace] Calculated KASLR kernel slide: 0x%lx\n", kernel_slide);
    
    vm_offset_t *actual_slide = (_VM_KERNEL_SLIDE_ADDR + kernel_slide);
    
    printf("[ptrace] Stored KASLR kernel slide (based on calculated slide): 0x%lx\n", *actual_slide);
    
    if (*actual_slide == kernel_slide) {
        printf("[ptrace] calculated KASLR slide matches stored slide\n");
        return kernel_slide;
    }
    
    return 0;
}


kern_return_t pt_deny_attach_start (kmod_info_t *ki, void *d) {
    
    printf("[ptrace] Using addresses from OS X %s\n", _OSX_VERSION);
    
    slide = calculate_vm_kernel_slide();
    printf("[ptrace] KASLR kernel slide is 0x%lx\n", slide);
    
    _nsysent = (int *)(_NSYSENT_ADDR + slide);
    
	_sysent = find_sysent();
	if (_sysent == NULL) {
		return KERN_FAILURE;
	}

	real_ptrace = (ptrace_func_t *) _sysent[SYS_ptrace].sy_call;
    
    
    printf("[ptrace] Patching ptrace(PT_DENY_ATTACH, ...).\n");
    
    
    DISABLE_WRITE_PROTECTION();
    
    _sysent[SYS_ptrace].sy_call = (sy_call_t *) our_ptrace;
    
    ENABLE_WRITE_PROTECTION();

        
    return KERN_SUCCESS;
}


kern_return_t pt_deny_attach_stop (kmod_info_t * ki, void * d) {
        
    printf("[ptrace] Unpatching ptrace(PT_DENY_ATTACH, ...)\n");
        
    
    DISABLE_WRITE_PROTECTION();
    
    _sysent[SYS_ptrace].sy_call = (sy_call_t *) real_ptrace;

    ENABLE_WRITE_PROTECTION();
    
    
    return KERN_SUCCESS;
}
