# Building

SandboxMirror is incompatible with CHUD's kernel extensions.  The
problem is that it currently uses CHUD's "host port" (because no
others are available for use by non-Apple software).  So before
building or trying to install SandboxMirror, first run `kextstat` from
the commandline and look for any kernel extensions with "CHUD" in
their names.  You're very unlikely to find any:  CHUD has long been
obsolete, its functionality replaced by other tools that come with
XCode.  But if you do and still have your original CHUD distro, you
may be able to run the CHUD Remover tool from its `Utilities`
subdirectory.  Otherwise SandboxMirror may cause serious trouble on
your computer.

SandboxMirror requires a compatible version of OS X -- OS X 10.9
(Mavericks) through macOS 10.12 (Sierra).  Building it also requires a
relatively recent version of XCode.  I recommend building on the
version of OS X where you'll be using SandboxMirror, and using the
most recent version of XCode available for that version.

Once you've dealt with the above, building `SandboxMirror.kext` and
`sandboxmirrord` should be straightforward.  I ususally just run
`xcodebuild` from the command line.  This drops release builds into
the projects' `build/Release/` subdirectories.
