pt_deny_attach Kernel Module for Mountain Lion 10.8.2
====

**THIS DOES NOT WORK!!!!**  It loads/unloads succesfully on 10.8.2 but it doesn't patch the `ptrace` call.

This is an attempt to update the `pt_deny_attach` kernel module (originally by Landon J. Fuller) to work with Mountain Lion.

The attempt was ultimately unsuccessful due to write protected memory.  However, the module does work around the issues presented by Kernel Address Space Layout Randomisation (KASLR).  

The code might provide interest and some useful techniques for dealing with KASLR in other projects.

See [Failing to update the `pt_deny_attach` kernel module for Mountain Lion](http://www.blendedcocoa.com/blog/2013/02/16/failing-to-update-the-pt_deny_attach-kernel-module-for-mountain-lion/)  for more details.
