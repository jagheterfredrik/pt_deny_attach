/*
 * Kernel Offsets for OS X 10.8.3
 */

#ifndef PT_DENY_ATTACH_KERNEL_ADDRESSES
#define PT_DENY_ATTACH_KERNEL_ADDRESSES

#define _OSX_VERSION          "10.8.3"

#define _VM_KERNEL_SLIDE_ADDR 0xffffff80008c0b58
#define _NSYSENT_ADDR         0xffffff8000839818
#define _PRINTF_ADDR          0xffffff8000229090
#define _PTRACE_ADDR          0xffffff8000570990

#define SCAN_RANGE 0x20000

#endif
