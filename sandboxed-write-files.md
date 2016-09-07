# What files should sandboxed processes be allowed to write?

You might think that a sandboxed process shouldn't be allowed to write
any files whatsoever.  But check what files get written by Safari's
(sandboxed) child processes, and you'll see that many do.  Note that
this use case will only work properly on OS X 10.11 and above, because
of the problem mentioned above with XPC child processes.

Try one or both of the following:

`SM_TRACE=file-write* SM_KIDSONLY=1 SM_LOGFILE=Safari-file-write.log /Applications/Safari.app/Contents/MacOS/Safari`

`SM_TRACE=file-write* SM_KIDSONLY=1 SM_DOSTACK=1 SM_LOGFILE=Safari-file-write-stack.log /Applications/Safari.app/Contents/MacOS/Safari`

You'll see writes to `/dev/dtracehelper` and `/dev/null`, plus many
more to files in `~/Library/Caches/com.apple.Safari/` and
`/private/var/folders/`.  You'll also see the sandbox being
initialized for several of these child processes.

The files in the two directories are presumably temporary caches of
one kind or another.  Those in `/private/var/folders/` appear to be
databases (their names end in `*.db`) containing SSL certificates (the
writes happen via `HTTPProtocolSSLSupport::getSSLCertsCached()`).
They're written by the `com.apple.NSURLConnectionLoader` thread of the
`com.apple.WebKit.Networking` process or the
`com.apple.Safari.SearchHelper` process.

The writes to standard files all happen after the sandbox has been
initialized (in those processes).  But the writes to
`/dev/dtracehelper` and `/dev/null` happen before the sandbox has been
initialized or the process has even been started (while it's still
being loaded by `/usr/libexec/xpcproxy`).

The files that get written after the sandbox has been initialized are
all located in standard, well-defined directories.  Caching files in
those directories seems legitimate even for a sandboxed process.  It
shouldn't be a problem for your sandbox ruleset to allow writes to
files in those directories.
