# How does Apple's sandbox control hardware access?

There are two rules that control hardware access at a fairly high
level -- "device-audio" and "device-camera".  And there's another
("hid-control") that controls whether or not methods in the
CoreGraphics framework can synthesize keyboard events, or set hot keys
(for other applications).  But the others all control access at a very
low level, via the IOKit framework and the kernel.

        iokit-open
        iokit-set-properties
        iokit-get-properties

These correspond exactly to documented calls in `IOKit.h` (in the IOKit
framework):

        iokit-open:           IOServiceOpen()
        iokit-set-properties: IORegistryEntrySetCFProperties(),
                              IOConnectSetCFProperties()
        iokit-get-properties: IORegistryEntrySearchCFProperty(),
                              IORegistryEntryCreateCFProperties(),
                              IORegistryEntryGetProperty()

Frankly, the "iokit-`*`" rules are too low level to be of much use on
their own.  The IOKit framework methods to which they correspond are
poorly documented, so it's hard to understand how they work.  You can
use SandboxMirror with various apps (like Safari, Firefox and Google
Chrome) to glean quite a lot of information about them.  But there's
also another way to control hardware access, using higher-level
"entitlements", which are easier to understand.  These can be
translated into "iokit-`*`" rules.  For more about this see the [next
section](app-sandbox.md).
