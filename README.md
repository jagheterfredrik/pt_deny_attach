pt_deny_attach Kernel Module for Mavericks 10.9.0
====

This is a successful attempt to update the `pt_deny_attach` kernel module (originally by Landon J. Fuller) to work with Mavericks.

The kext now founds the correct sysent offset using very high probability heuristic scanning of the mach_kernel binary. This will
hopefully make it rather generic.

Note! Only tested on Mavericks.
