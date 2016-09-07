# What is Apple's "App Sandbox"?

In addition to the Scheme-like language mentioned above, Apple also
offers (and documents) a higher level way to turn on and configure
process-level sandboxing, using "entitlements" -- their "App Sandbox"
(see [About App Sandbox]
(https://developer.apple.com/library/mac/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
and [Enabling App Sandbox]
(https://developer.apple.com/library/mac/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html)).

Entitlements are somewhat easier to use, especially to configure
hardware access.  But the App Sandbox has a serious limitation: You
can't control when it starts up.  So you have no control over which
resources get initialized before the sandbox's constraints are
imposed.  Probably at least partly for this reason, large complex apps
(like Safari) don't use entitlements and the App Sandbox.  Instead
they use the Scheme-like language directly, via calls to
`sandbox_init()` or `sandbox_init_with_parameters()`:

        // Possible values for 'flags':
        #define SANDBOX_STRING  0x0000
        #define SANDBOX_NAMED   0x0001
        #define SANDBOX_BUILTIN 0x0002
        #define SANDBOX_FILE    0x0003

        int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
        int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                         const char **params, char **errorbuf);

When `flags == SANDBOX_STRING`, `profile` is a ruleset written in
Apple's Scheme-like language.  When `flags == SANDBOX_FILE`, `profile`
is the path to a file containing such a ruleset.  In both cases,
`sandbox_init...()` calls `compile()` (via `sandbox_compile_string()`
or `sandbox_compile_file()`), which compiles `profile` into Scheme
bytecode (via `sb_program_get_bytecode()`).

This also happens with entitlements, but indirectly, via a call to
`sandbox_compile_entitlements()`:

        void *sandbox_compile_entitlements(const char **entitlement_paths,
                                           sb_params *sandbox_params,
                                           CFDict entitlements,
                                           char **errorbuf);

`entitlement_paths` contains contains paths to a bunch of `*.sb`
files, each containing a sandbox ruleset.  They get compiled together
into a single blob of Scheme bytecode.  These files usually include
`/System/Library/Sandbox/Profiles/application.sb` and a bunch of
`framework.sb` files associated with frameworks used by the sandboxed
application.

Of most interest to us here is the `application.sb` file.  Unlike any
other system `*.sb` file, it contains a bunch of statements starting
`if (entitlement ...`.  Each of these associates one or more
entitlements with one or more low-level rules in the Scheme-like
language used by `sandbox_init...()`.  For example:

        (if (entitlement "com.apple.security.device.firewire")
          (begin
            (allow iokit-open (iokit-user-client-class "IOFireWireUserClient"))
            (allow iokit-open (iokit-user-client-class "IOFireWireAVCUserClient"))
            (allow iokit-open
                   (iokit-user-client-class "IOFireWireAVCProtocolUserClient"))
            (allow iokit-set-properties (iokit-property "SummonNub"))))

These in effect translate high-level entitlements (relatively easy to
understand) into low-level rules that, otherwise, would be very
difficult to understand.

Let's use SandboxMirror to show all this in action with an application
that uses App Sandbox -- Apple's Calculator.

The App Sandbox is initialized (and `sandbox_compile_entitlements()`
is called) as `dyld` initializes `libSystem.dylib` (to which
Calculator is dynamically linked) by calling `libSystem_initializer()`
[Libsystem-1226.10.1/init.c]
(http://opensource.apple.com/source/Libsystem/Libsystem-1226.10.1/init.c)).
(So the App Sandbox starts up even before the app that uses it starts
running.)  `libSystem_initializer()` in turn calls
`_libsecinit_initializer()`, which calls `__mac_syscall()` to start up
the sandbox.  But `_libsecinit_initializer()` gets the information it
needs by doing IPC with `secinitd` (spawned as an agent running in the
background as the currently logged on user).  It's `secinitd` that
calls `sandbox_compile_entitlements()`.

So we need to use SandboxMirror to trace two executables at once --
the Calculator app and `secinitd`.  The latter is launched via
`com.apple.secinitd.plist` in `/System/Library/LaunchAgents`.  So we
can set its environment variables by adding an `EnvironmentVariables`
key to this file.

1. Remove any files named `Calculator.log` or `secinitd.log` from
   `/var/log/sandboxmirrord/`.

2. Make a backup copy of `com.apple.secinitd.plist` from
   `/System/Library/LaunchAgents/`.

3. Add the following section to `com.apple.secinitd.plist`:

        <key>EnvironmentVariables</key>
        <dict>
          <key>SM_TRACE</key>
          <string>*</string>
          <key>SM_DOSTACK</key>
          <string>1</string>
          <key>SM_LOGFILE</key>
          <string>secinitd.log</string>
        </dict>

4. Run the following command to unload any existing instance of the
   `secinitd` agent:
   <p>
   `launchctl unload -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist`

5. Run the following command to load an instance of `secinitd` with the
   `SM_...` environment variables set:
   <p>
   `launchctl load -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist`

6. Delete the following directory, if it exists.  It caches the
   compiled Scheme bytecode (among other things) for the Calculator
   app.  So `sandbox_compile_entitlements()` won't get called if it
   exists.
   <p>
   `~/Library/Containers/com.apple.calculator/`

7. Run the following to load the Calculator app with the appropriate
   `SM_...` environment variables set, then quit the app:
   <p>
   `SM_TRACE=~* SM_DOSTACK=1 SM_LOGFILE=Calculator.log /Applications/Calculator.app/Contents/MacOS/Calculator`

8. Restore the original `com.apple.secinitd.plist` in
   `/System/Library/LaunchAgents` and run the following two commands:
   <p>
   `launchctl unload -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist`
   <p>
   `launchctl load -S Background /System/Library/LaunchAgents/com.apple.secinitd.plist`

Two new files should now have been created in
`/var/log/sandboxmirrord/`:  `Calculator.log` and `secinitd.log`.

`Calculator.log` contains a single entry, showing the call to
`__mac_syscall()` which initializes the sandbox.

`secinitd.log` contains many entries, most of which aren't relevant to
this particular use case.  Search on "`sandbox_compile_entitlements`"
to find all stacktraces that contain it.  Note that the first several
instances have the following on the stack above
`sandbox_compile_entitlements()`, and log calls to query the
"file-read-data" rule for files ending in `*.sb`:

        (libsystem_kernel.dylib) __open_nocancel + 0xa
        (libsandbox.1.dylib) sb_program_add_source_path + 0x3d
        (libsandbox.1.dylib) compile + 0x151

The first of these files is
`/System/Library/Sandbox/Profiles/application.sb`.  The others are
various `framework.sb` files.

These entries are followed by a couple of instances with the following
on the stack above `sandbox_compile_entitlements()`:

        (libsandbox.1.dylib) Eval_Cycle + 0x29e
        (libsandbox.1.dylib) scheme_load_file + 0x101
        (libsandbox.1.dylib) sb_program_get_bytecode + 0x23d
        (libsandbox.1.dylib) compile + 0x240

Both of these log calls to query "file-read-data" on
`/System/Library/Sandbox/Profiles/system.sb`, which is imported by
`/System/Library/Sandbox/Profiles/application.sb`.  Note the call to
`sb_program_get_bytecode()`.  This must be where the actual
compilation takes place.
