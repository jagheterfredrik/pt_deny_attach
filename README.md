pt_deny_attach Kernel Module for Mountain Lion 10.8.3
====

**THIS NOW WORKS :-D !!!!**  It loads/unloads succesfully on 10.8.3 and successfully patches the `ptrace` call.

This is a successful attempt to update the `pt_deny_attach` kernel module (originally by Landon J. Fuller) to work with Mountain Lion.

In order to patch the `ptrace` call in Mountain Lion it is first necessary to work around the issues presented by Kernel Address Space Layout Randomisation (KASLR).  Once this is done it is then necessary to disable write protected memory to allow updating of the `sysent` table.

The code might provide interest and some useful techniques for dealing with KASLR in other projects.

See [Failing to update the `pt_deny_attach` kernel module for Mountain Lion](http://www.blendedcocoa.com/blog/2013/02/16/failing-to-update-the-pt_deny_attach-kernel-module-for-mountain-lion/)  for more details.
