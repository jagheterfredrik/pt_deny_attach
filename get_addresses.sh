#!/bin/bash

OSX_VERSION=`sw_vers | grep 'ProductVersion:' | awk '{print $2}'`

VM_KERNEL_SLIDE=`nm -g /mach_kernel | grep ' _vm_kernel_slide$' | awk '{print $1}'`
NSYSENT=`nm -g /mach_kernel | grep ' _nsysent$' | awk '{print $1}'`
PRINTF=`nm -g /mach_kernel | grep ' _printf$' | awk '{print $1}'`
PTRACE=`nm -g /mach_kernel | grep ' _ptrace$' | awk '{print $1}'`

echo "/*" > kernel_addresses.h
echo " * Kernel Offsets for OS X $OSX_VERSION" >> kernel_addresses.h
echo " */" >> kernel_addresses.h

echo "" >> kernel_addresses.h

echo "#ifndef PT_DENY_ATTACH_KERNEL_ADDRESSES" >> kernel_addresses.h
echo "#define PT_DENY_ATTACH_KERNEL_ADDRESSES" >> kernel_addresses.h

echo "" >> kernel_addresses.h

echo "#define _OSX_VERSION          \"$OSX_VERSION\"" >> kernel_addresses.h

echo "" >> kernel_addresses.h

echo "#define _VM_KERNEL_SLIDE_ADDR 0x$VM_KERNEL_SLIDE" >> kernel_addresses.h
echo "#define _NSYSENT_ADDR         0x$NSYSENT" >> kernel_addresses.h
echo "#define _PRINTF_ADDR          0x$PRINTF" >> kernel_addresses.h
echo "#define _PTRACE_ADDR          0x$PTRACE" >> kernel_addresses.h

echo "" >> kernel_addresses.h

echo "//#define SCAN_RANGE 0x20000" >> kernel_addresses.h

echo "" >> kernel_addresses.h
echo "#endif" >> kernel_addresses.h

less kernel_addresses.h
