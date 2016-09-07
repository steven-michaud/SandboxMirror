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
