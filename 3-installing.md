# Installing

On OS X 10.10 (Yosemite) and up, to load `SandboxMirror.kext` you'll
need to turn off Apple's protection against loading kernel extensions
that aren't signed using a special kernel extension signing
certificate (in practice, almost exclusively Apple's own kernel
extensions).  On OS X 10.11 (El Capitan) and up, to do this you'll
need to turn off "rootless mode".  Rootless mode will also prevent you
from copying the SandboxMirror binaries, and other files, to their
final destinations.

## On OS X 10.10:

1. From the command line run `nvram boot-args` to see if you already
   have some boot-args.  Then run the following command:
   <p>
   `sudo nvram boot-args [existing-boot-args,]boot-args=kext-dev-mode=1`

2. Reboot your computer.

## On OS X 10.11 and up:

1. Boot into your Recovery partition by restarting your computer and
   pressing Command-R immediately after you hear the Mac startup
   sound.  Release these keys when you see the Apple logo.

2. Choose Utilties : Terminal, then run the following at the command
   line:
   <p>
   `csrutil disable`

3. Quit Terminal and reboot your computer.

Now copy the `SandboxMirror.kext` and `sandboxmirrord` binaries to the
`/usr/local/sbin/` directory.  Also copy
`org.smichaud.sandboxmirrord.plist` to `/Library/LaunchDaemons/` and
run the following command there:

`sudo launchctl load org.smichaud.sandboxmirrord.plist`

When loading `SandboxMirror.kext` for the first time, it's best not to
use a method that will cause it to reload every time your computer
boots (something provided in `org.smichaud.loadSandboxMirror.plist`).
To load `SandboxMirror.kext` by hand, do the following on the command
line:

`sudo kextutil /usr/local/sbin/SandboxMirror.kext`

Because it won't have been signed using a kernel extension signing
certificate, you'll see the following error (or something like it):

        Diagnostics for SandboxMirror.kext:
        Code Signing Failure: code signature is invalid
        kext-dev-mode allowing invalid signature -67050
          0xFFFFFFFFFFFEFA16 for kext "SandboxMirror.kext"
        kext signature failure override allowing invalid signature -67050
          0xFFFFFFFFFFFEFA16 for kext "/usr/local/sbin/SandboxMirror.kext"

Run `kextstat` to see that it did load.

Test it out by running something like the following command, which
logs a few lines in the Console.  (On macOS 10.12 (Sierra) you'll need
to run the Console before running Calculator, and filter on "sandbox"
or "sandboxmirror".)

`SM_TRACE=mach-lookup* SM_DOSTACK=1 /Applications/Calculator.app/Contents/MacOS/Calculator`

Run the following command to unload SandboxMirror.kext:

`sudo kextunload -b org.smichaud.SandboxMirror`

Once you feel comfortable using SandboxMirror, and if you think it's
convenient, you can make `SandboxMirror.kext` load at startup by coping
`org.smichaud.loadSandboxMirror.plist` to `/Library/LaunchDaemons/`.
