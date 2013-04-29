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
 * The SYSENT_OFFSET can be discovered by searching memory around 
 * _nsysent for an address that passes the sanity check.
 *
 * If SCAN_RANGE is defined this will happen automatically and 
 * the offset printed into the system log.
 */
#define SYSENT_OFFSET         0x1C028

static struct sysent *_sysent;

typedef int	ptrace_func_t (struct proc *, struct ptrace_args *, int *);
static ptrace_func_t *original_ptrace;

static int our_ptrace (struct proc *p, struct ptrace_args *uap, int *retval)
{
	
	if (uap->req == PT_DENY_ATTACH) {
		printf("[pt_deny_attach] Blocking PT_DENY_ATTACH for pid %d\n", uap->pid);
		return (0);
	} else {
        printf("[pt_deny_attach] Forwarding call to original ptrace for pid %d\n", uap->pid);
		return original_ptrace(p, uap, retval);
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
    
    printf("[pt_deny_attach] Calculated KASLR kernel slide: 0x%lx\n", kernel_slide);
    
    vm_offset_t *actual_slide = (_VM_KERNEL_SLIDE_ADDR + kernel_slide);
    
    printf("[pt_deny_attach] Kernel vm_kernel_slide == 0x%lx (based on calculated slide)\n", *actual_slide);
    
    if (*actual_slide == kernel_slide) {
        printf("[pt_deny_attach] Calculated KASLR slide matches kernel vm_kernel_slide\n");
        return kernel_slide;
    }
    
    return 0;
}


static int *locate_nsysent(vm_offset_t slide) {
    int *_nsysent = (int *)(_NSYSENT_ADDR + slide);

    printf("[pt_deny_attach] Found nsysent at %p, with value %d\n", _nsysent, *_nsysent);
    
    return _nsysent;
}


/*
 * nsysent is no longer placed near the hidden sysent, so skip to the
 * offset and sanity check that we've found the sysent array.
 *
 * Clearly, this is extremely fragile and not for general consumption.
 */
static struct sysent *locate_sysent(vm_offset_t slide, int *_nsysent, long offset) {
	struct sysent *table;
    
	table = (struct sysent *) ( ((char *) _nsysent) + offset);
    
    /* Sanity check */
    if (table[SYS_syscall].sy_narg  == 0 &&
        table[SYS_exit].sy_narg     == 1 &&
        table[SYS_fork].sy_narg     == 0 &&
        table[SYS_read].sy_narg     == 3 &&
        table[SYS_wait4].sy_narg    == 4 &&
        table[SYS_ptrace].sy_narg   == 4 &&
        table[SYS_ptrace].sy_call   == (void *)(_PTRACE_ADDR + slide))
    {
        return table;
    }
    
    return NULL;
}



kern_return_t pt_deny_attach_start (kmod_info_t *ki, void *d) {
    long offset = SYSENT_OFFSET;
    
    printf("[pt_deny_attach] Using addresses from OS X %s\n", _OSX_VERSION);
    
    vm_offset_t slide = calculate_vm_kernel_slide();
    
    int *_nsysent = locate_nsysent(slide);
    
	_sysent = locate_sysent(slide, _nsysent, offset);
	
    
#ifdef SCAN_RANGE
    // If we don't find _sysent at the hard-coded offset
    // search for it in memory around _nsysent
    if (_sysent == NULL) {
        printf("[pt_deny_attach] Attempting to locate _sysent in memory\n");
        
        for(offset = -SCAN_RANGE; offset < SCAN_RANGE && _sysent == NULL; offset++) {
            _sysent = locate_sysent(slide, _nsysent, offset);
        }
	}
#endif

    if (_sysent == NULL) {
        printf("[pt_deny_attach] Unable to locate _sysent in memory\n");
        
        return KERN_FAILURE;
    }
    
    printf("[pt_deny_attach] Found _sysent table at %p (offset 0x%lx from _nsysent)\n",
           _sysent, (void *)_sysent - (void *)_nsysent);

	original_ptrace = (ptrace_func_t *) _sysent[SYS_ptrace].sy_call;
    
    
    printf("[pt_deny_attach] Patching ptrace(PT_DENY_ATTACH, ...)\n");
    
    
    DISABLE_WRITE_PROTECTION();
    
    _sysent[SYS_ptrace].sy_call = (sy_call_t *) our_ptrace;
    
    ENABLE_WRITE_PROTECTION();

        
    return KERN_SUCCESS;
}


kern_return_t pt_deny_attach_stop (kmod_info_t * ki, void * d) {
        
    printf("[pt_deny_attach] Unpatching ptrace(PT_DENY_ATTACH, ...)\n");
        
    
    DISABLE_WRITE_PROTECTION();
    
    _sysent[SYS_ptrace].sy_call = (sy_call_t *) original_ptrace;

    ENABLE_WRITE_PROTECTION();
    
    
    return KERN_SUCCESS;
}
