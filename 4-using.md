# Using

SandboxMirror is configured using environment variables.  In other
words, to make SandboxMirror log some or all sandbox activity for a
given process, set various environment variables appropriately for
that process.

Note that, for the moment at least, SandboxMirror only checks a
process's environment as it was before the process was started.  So if
a process changes its own environment, SandboxMirror won't see these
changes.

Note also that on OS X 10.9 and 10.10, SandboxMirror can't always keep
track of which processes are child processes.  This is because many
Apple applications, at least, use XPC to launch child processes, and
"XPC processes" (unlike "ordinary" child processes) don't inherit
their parent's environment.  SandboxMirror has a workaround for this,
but it's only available on OS X 10.11 and up.  For more information
see `get_xpc_parent()` in `SandboxMirror.cpp`.

Here are the environment variables that SandboxMirror pays attention
to:

* #### SM_TRACE - Which rules to log that a process might be constrained by
  <p>
  Set this to one or more rule names, separated by commas.  Add a
  wildcard (`*`) to the end of a (partial) rule specification to make
  it include every rule beginning with that string.  The specification
  "`*`" includes every rule.  Prepend a tilde character (`~`) to
  negate the rule specification -- to make it exclude every rule that
  it matches.  All "positive" specifications are ORed together, then
  ANDed with each "negative" specification.

* #### SM_LOGFILE - Name of the file (if any) to which to append logging
  <p>
  By default SandboxMirror only logs to the Console.  (On OS X 10.11
  and below these entries get written to `/var/log/system.log`.)  Set
  this to make it also append logging to a file in
  `/var/log/sandboxmirrord`.

* #### SM_DOSTACK - Also log stack traces
  <p>
  By default, SandboxMirror logs the name of the rule being checked,
  the path to the process's executable, and similar information to
  identify exactly when and where a particular constraint has
  (potentially) been applied to a particular process.  Set this (to
  any value) to make SandboxMirror also log a stack trace for each
  instance of potential "constraint".

* #### SM_KIDSONLY - Only log for child processes
  <p>
  By default SandboxMirror logs for a given process and all its
  children (though on OS X 10.9 and 10.10 only if they inherit their
  parent's environment, and aren't XPC processes).  But often a
  developer will only want to sandbox an app's child processes (each
  of whose functionality can be more narrowly defined than that of the
  parent process).  Set this (to any value) to make SandboxMirror not
  log anything for the parent process.  Because of the problem witn
  XPC child processes mentioned above, this environment variable is
  less useful on OS X 10.9 and 10.10.

Here's an example that uses all of these environment variables:

`SM_TRACE=iokit-* SM_DOSTACK=1 SM_LOGFILE=Safari.log SM_KIDSONLY=1 /Applications/Safari.app/Contents/MacOS/Safari`

This logs all instances where Safari's child processes (on OS X 10.11
and up) might be constrained by a sandbox rule starting with "iokit-"
(for example "iokit-open" or "iokit-get-properties").  It also logs
sandbox initialization for each child process where it occurs.  Each
log entry is accompanied by a stack trace.  And in addition to being
written to the Console, each log entry is also appended to a file
named `Safari.log` in `/var/log/sandboxmirrord/`.
