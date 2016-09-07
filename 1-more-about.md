# More About SandboxMirror

SandboxMirror has two parts:  A kernel extension called
`SandboxMirror.kext` and a service/daemon called `sandboxmirrord`.
`SandboxMirror.kext` keeps track of the sandbox's internal operations,
and can be configured (per process) to log them to the Console and to
separate files (in `/var/log/sandboxmirror/`).  `sandboxmirrord` is
what actually does the logging, in response to Mach messages it
receives from `SandboxMirror.kext`.  These two parts are modeled on
Apple's `Sandbox.kext` and `sandboxd`, and have somewhat similar
functionality.

Like Apple's `Sandbox.kext`, `SandboxMirror.kext` is both an OS X
kernel extension and a "MAC policy module".  MAC stands for "Mandatory
Access Control", and (since OS X 10.5 Leopard) is implemented on OS X
by a "MAC Framework" which is a port of the TrustedBSD MAC Framework.
"Mandatory access controls extend operating system access control
policy by allowing administrators to enforce additional constraints on
user and application behavior" ([http://www.trustedbsd.org/mac.html]
(http://www.trustedbsd.org/mac.html)).

A sandbox is a restricted environment, which constrains in various
ways the behavior of applications which run inside it.  As of OS X
10.11 (El Capitan), Apple has (at least) two different kinds of
sandboxing, both implemented in `Sandbox.kext`.  One is configurable
per-process, and is (mostly) implemented using the MAC framework.  The
other (aka "rootless mode") is also configurable (at least in
principle), but its settings are system-wide and it doesn't use the
MAC framework.  At least for now, SandboxMirror is only concerned with
per-process sandboxing.

Apple's per-process sandboxing can be turned on or left off
(per-process).  And its constraints (per-process) are configured using
[rulesets written in a Scheme-like language]
(http://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf).
Apple has no documentation whatsoever on this language, and the
third-party documentation that exists is incomplete.  But many
examples of such rulesets can be found inside system directories, with
file names ending in `*.sb`.

SandboxMirror's main purpose is to make it easier to understand the
practical implications of implementing a given rule in a sandbox
ruleset.  It logs every time a given process **might** violate a given
rule (if that rule were implemented), optionally accompanied by a
stack trace of the (potential) violation.  With sufficient knowledge
of operating system internals, you can see exactly what kinds of calls
would be effected, and when.

Note that Apple's `sandboxd` already logs sandbox rule **violations**,
complete with stack traces.  But failing a given call prevents others
from even being attempted.  You only get the full picture if you log
potential violations of a rule without actually enforcing it.

`SandboxMirror.kext` doesn't replace Apple's `Sandbox.kext`.  It runs
alongside it, and is added to the list of MAC frameworks that the
kernel consults every time a call takes place for which at least one
of the MAC frameworks implements a hook.  The hooks in Apple's
`Sandbox.kext` return '0' for "this call is allowed" or an error for
"this call is forbidden".  On an error return, the kernel fails the
call.  `SandboxMirror.kext` implements exactly the same hooks as
`Sandbox.kext`, but always returns '0'.  Instead it looks at the
current process's environment variables to determine what it should
log, if anything.

Some per-process sandbox rule checking takes place outside the MAC
framework model, directly via calls from user-space (for example to
`sandbox_check(pid_t pid, const char *rule, uint32_t flags, ...)` in
`/usr/lib/system/libsystem_sandbox.dylib`).  `SandboxMirror.kext`
hooks these calls, and can log them.

`SandboxMirror.kext` also hooks calls to initialize (and turn on) a
process's sandbox, and can log them.
