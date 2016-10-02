# Resources

Here are the tools and resources I found most useful writing
SandboxMirror.  You'll also need them (or something like them) to
decide how to use SandboxMirror, and to interpret the results you get
from it.

* [Hopper Disassembler](https://www.hopperapp.com/)
  <p>
  I use this on Apple's `sandboxd` and `Sandbox.kext`, of course.  But
  I also need it to understand the stack traces logged by
  SandboxMirror.

* [Apple Open Source](http://opensource.apple.com/)
  <p>
  OS X isn't open source.  But this site has source code (sometimes
  incomplete) for a lot of its components, which can provide crucial
  information on the undocumented stuff that shows up in SandboxMirror
  stack traces.  It doesn't contain source code for any kernel
  extensions, but it does have source for the kernel itself (the xnu
  kernel).  I found this extremely useful writing
  `SandboxMirror.kext`.

* [Kernel Debug Kits](http://developer.apple.com/download/more/)
  <p>
  These in effect let you load a Mach kernel running on a remote
  machine (the target computer) into `lldb` running in a Terminal
  window on your local machine (the development computer).  Apple's
  documentation is poor, and there are technical restrictions that can
  make it cumbersome to use.  But there are times when there's no
  substitute for doing this.
  <p>
  It's probably best to start by reading [Debugging a Kernel Extension
  with GDB]
  (https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptDebugger/debug_tutorial.html).
  This is badly out of date, but it's reasonably well written and
  gives you a good overview.  Then read the ReadMe file that comes
  with the version of the Kernel Debug Kit that you'll be using.  The
  Kernel Debug Kit gets installed on the development computer (where
  you'll be running `lldb`), and must match the version of OS X or
  macOS on the target computer.  The development computer should also
  be running the same version of Apple's OS, but this isn't absolutely
  necessary.
  <p>
  Apple's instructions won't work with a target computer that's a
  virtual machine.  But with a slightly modified procedure, remote
  kernel debugging works with a VMware Fusion virtual machine.
  <p>
  1. Make sure the target virtual machine isn't running, then add the
     following two lines to the `.vmx` config file in its `.vmwarevm`
     package directory:
     <p>
     `debugStub.listen.guest64 = "TRUE"`
     <p>
     `debugStub.listen.guest64.remote = "TRUE"`
     <p>
  2. Download [x86_64_target_definition.py]
     (http://llvm.org/svn/llvm-project/lldb/trunk/examples/python/x86_64_target_definition.py)
     to some convenient location on your development computer.
     <p>
  3. On the development computer, run the following two commands:
     <p>
     `lldb /Library/Developer/KDKs/KDK_[version].kdk/System/Library/Kernels/kernel`
     <p>
     `settings set plugin.process.gdb-remote.target-definition-file /path/to/x86_64_target_definition.py`
     <p>
  4. Then enter one of the following commands instead of `kdp-remote
     {name_or_ip_address}`.  Use the first if your development
     computer is the VMware Fusion host.  Use the second if it's some
     other computer.
     <p>
     `gdb-remote 8864`
     <p>
     `gdb-remote [fusionhost]:8864`

  For more information see the following:
  <p>
  [Using the VMware Fusion GDB stub for kernel debugging with LLDB]
  (http://ddeville.me/2015/08/using-the-vmware-fusion-gdb-stub-for-kernel-debugging-with-lldb)
  <p>
  [VMware](http://wiki.osdev.org/VMware)
