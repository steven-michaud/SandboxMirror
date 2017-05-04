// The MIT License (MIT)
//
// Copyright (c) 2016 Steven Michaud
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Like Apple's Sandbox.kext, SandboxMirror.kext is an OS X kernel extension
// and also a "MAC policy module".  MAC stands for "Mandatory Access Control",
// and (since OS X 10.5 Leopard) is implemented on OS X by a "MAC Framework"
// which is a port of the TrustedBSD MAC Framework.  "Mandatory access controls
// extend operating system access control policy by allowing administrators to
// enforce additional constraints on user and application behavior"[1].
// Sandbox.kext implements Apple's sandbox policy.  Other MAC policy modules
// on OS X are Quarantine.kext and TMSafetyNet.kext.  Quarantine.kext tracks
// information on downloaded files and constrains their execute permissions.
// TMSafetyNet.kext "protects the integrity of backup data managed by Apple's
// Time Machine backup system"[2].
//
// [1]http://www.trustedbsd.org/mac.html
// [2]http://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-818.html
//
// A sandbox is a restricted environment, which constrains in various ways the
// behavior of applications which run inside it.  Starting with OS X 10.5 but
// prior to OS X 10.11, the only kind of sandboxing available was optional and
// per-process.  For convenience I'll call this Apple's "sandbox".  It remains
// available in OS X 10.11.  But starting with that version, OS X also
// supports another kind of sandboxing which Apple calls "rootless mode".  It,
// too, can be turned off and on and is configurable (at least in principle).
// But its settings are system-wide, and not per-process.  Both kinds of
// sandboxing are implemented in Sandbox.kext.  But (at least for now)
// SandboxMirror.kext only tracks Apple's implementation of what I've called
// Apple's "sandbox", and not of its "rootless mode".
//
//[3]http://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really
//[4]https://developer.apple.com/library/mac/documentation/Security/Conceptual/System_Integrity_Protection_Guide/Introduction/Introduction.html
//
// In my narrower sense of the word "sandbox", individual (user-level)
// processes can be sandboxed or not.  Sandbox policies can be configured
// using rulesets written in a Scheme-like language[6].  Many examples of such
// rulesets can be found in files inside system directories whose names end in
// ".sb".  But Apple has no documentation whatsoever on this Scheme-like
// language, and the non-Apple documentation[6] is incomplete.  Furthermore,
// though sandbox violations are usually logged in the Console, there is no
// other way (aside from the rule's expression) to figure out what a rule
// actually means, in practical terms.  Hence the need for a debugging tool
// like SandboxMirror.
//
// [5]http://www.chromium.org/developers/design-documents/sandbox/osx-sandboxing-design
// [6]http://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
//
// SandboxMirror.kext "mirrors" Apple's implementation of what I've called its
// "sandbox" in Sandbox.kext:  Wherever and whenever Sandbox.kext's sandbox
// might constrain user and application behavior, SandboxMirror.kext can log
// which rule is (potentially) being applied to which process, and show a
// stack trace of exactly which operation in the process is being constrained.
// Note that we're not logging sandbox *violations*.  Instead we're
// (potentially) logging every operation that *might* violate a sandbox rule
// (if sandboxing were enabled and that rule were implemented in its policy).
// This gives a much fuller picture of what's going on than you get from just
// logging violations.
//
// What's logged is determined by one or more environment variables (see
// below).  The actual logging is done by the sandboxmirrord daemon.
// Offloading this work allows support for more complex logging options and
// helps keep SandboxMirror.kext performant.

// Apple's Sandbox.kext is closed source.  But their MAC framework is
// implemented in the xnu kernel, which is (largely) open source
// (http://opensource.apple.com/).  See particularly the xnu kernel source
// dump's security directory, and in that the mac_policy.h file -- which has
// definitions of the MAC framework's hooks, many of which are implemented in
// Sandbox.kext and SandboxMirror.kext.  Calls to these hooks can be found all
// over the xnu kernel source tree.

// Apple only supports a subset of C/C++ for kernel extensions.  Apple
// documents some of the features which are disallowed[7], but not all of
// them.  Apple's list of disallowed features includes exceptions, multiple
// inheritance, templates and RTTI.  But complex initialization of local
// variables is also disallowed -- for example structure initialization and
// variable initialization in a "for" statement (e.g. "for (int i = 1; ; )").
// You won't always get a compiler warning if you use one of these disallowed
// features.  And you may not always see problems using the resulting binary.
// But in at least some cases you will see mysterious kernel panics.
//
// [7]https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Features/Features.html#//apple_ref/doc/uid/TP0000012-TPXREF105

#include <libkern/libkern.h>

#include <AvailabilityMacros.h>

#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/fcntl.h>
#include <sys/ipc.h>
// Apple has changed how the MAC_OS_X_VERSION_... variables are defined in
// AvailabilityMacros.h on OS X 10.10 and up.  Now minor versions may also be
// defined, and the "base" is 100 times what it was on OS X 10.9 and below.
#if !defined(MAC_OS_X_VERSION_10_11) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_11
#include <sys/lctx.h> // Not in Kernel framework on 10.11 and up.
#endif
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/sem.h>
#define SYSCTL_DEF_ENABLED
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/vnode.h>
#include <sys/posix_sem.h>
#include <sys/posix_shm.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <bsm/audit.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/OSAtomic.h>
#include <i386/proc_reg.h>

#include <IOKit/IOLib.h>
#include <IOKit/IORegistryEntry.h>
extern "C" {
#include <security/mac.h>
#include <security/mac_policy.h>
}

extern "C" const char *vnode_getname(vnode_t vp);
extern "C" void vnode_putname(const char *name);

extern "C" int atoi(const char *str);
//extern "C" char *itoa(int value, char *string);

extern "C" uint64_t thread_tid(thread_t thread);

typedef struct pmap *pmap_t;
extern pmap_t kernel_pmap;
extern vm_map_t kernel_map;
extern "C" void vm_kernel_unslide_or_perm_external(vm_offset_t addr,
                                                   vm_offset_t *up_addr);
extern "C" ppnum_t pmap_find_phys(pmap_t map, addr64_t va);


/*------------------------------*/

// "kern.osrelease" is what's returned by 'uname -r', which uses a different
// numbering system than the "standard" one.  These defines translate from
// that (kernel) system to the "standard" one.

#define MAC_OS_X_VERSION_10_9_HEX  0x00000D00
#define MAC_OS_X_VERSION_10_10_HEX 0x00000E00
#define MAC_OS_X_VERSION_10_11_HEX 0x00000F00
#define MAC_OS_X_VERSION_10_12_HEX 0x00001000

char *gOSVersionString = NULL;
size_t gOSVersionStringLength = 0;

int32_t OSX_Version()
{
  static int32_t version = -1;
  if (version != -1) {
    return version;
  }

  version = 0;
  sysctlbyname("kern.osrelease", NULL, &gOSVersionStringLength, NULL, 0);
  gOSVersionString = (char *) IOMalloc(gOSVersionStringLength);
  char *version_string = (char *) IOMalloc(gOSVersionStringLength);
  if (!gOSVersionString || !version_string) {
    return version;
  }
  if (sysctlbyname("kern.osrelease", gOSVersionString,
                   &gOSVersionStringLength, NULL, 0) < 0)
  {
    IOFree(version_string, gOSVersionStringLength);
    return version;
  }
  strncpy(version_string, gOSVersionString, gOSVersionStringLength);

  const char *part; int i;
  for (i = 0; i < 3; ++i) {
    part = strsep(&version_string, ".");
    if (!part) {
      break;
    }
    version += (atoi(part) << ((2 - i) * 4));
  }

  IOFree(version_string, gOSVersionStringLength);
  return version;
}

bool OSX_Mavericks()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_9_HEX);
}

bool OSX_Yosemite()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_10_HEX);
}

bool OSX_ElCapitan()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_11_HEX);
}

bool macOS_Sierra()
{
  return ((OSX_Version() & 0xFF00) == MAC_OS_X_VERSION_10_12_HEX);
}

bool OSX_Version_Unsupported()
{
  return (((OSX_Version() & 0xFF00) < MAC_OS_X_VERSION_10_9_HEX) ||
          ((OSX_Version() & 0xFF00) > MAC_OS_X_VERSION_10_12_HEX));
}

// The system kernel (stored in /System/Library/Kernels on OS X 10.10 and up)
// is (in some senses) an ordinary Mach-O binary.  You can use 'otool -hv' to
// show its Mach header, and 'otool -lv' to display its "load commands" (all
// of its segments and sections).  From the output of 'otool -lv' it's
// apparent that the kernel (starting with its Mach header) is meant to be
// loaded at 0xFFFFFF8000200000.  But recent versions of OS X implement ASLR
// (Address Space Layout Randomization) for the kernel -- they "slide" all
// kernel addresses by a random value (determined at startup).  So in order
// to find the address of the kernel (and of its Mach header), we also need to
// know the value of this "kernel slide".

#define KERNEL_HEADER_ADDR 0xFFFFFF8000200000

vm_offset_t g_kernel_slide = 0;
struct mach_header_64 *g_kernel_header = NULL;

// Find the address of the kernel's Mach header.
bool find_kernel_header()
{
  if (g_kernel_header) {
    return true;
  }

#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  // vm_kernel_unslide_or_perm_external() is only available on OS X 10.11 and up.
  if (OSX_ElCapitan() || macOS_Sierra()) {
    vm_offset_t func_address = (vm_offset_t) vm_kernel_unslide_or_perm_external;
    vm_offset_t func_address_unslid = 0;
    vm_kernel_unslide_or_perm_external(func_address, &func_address_unslid);
    g_kernel_slide = func_address - func_address_unslid;
  } else {
#endif
    bool kernel_header_found = false;
    vm_offset_t slide;
    // The 0x10000 increment was determined by trial and error.
    for (slide = 0; slide < 0x100000000; slide += 0x10000) {
      addr64_t addr = KERNEL_HEADER_ADDR + slide;
      // pmap_find_phys() returns 0 if 'addr' isn't a valid address.
      if (!pmap_find_phys(kernel_pmap, addr)) {
        continue;
      }
      struct mach_header_64 *header = (struct mach_header_64 *) addr;
      if ((header->magic != MH_MAGIC_64) ||
          (header->cputype != CPU_TYPE_X86_64 ) ||
          (header->cpusubtype != CPU_SUBTYPE_I386_ALL) ||
          (header->filetype != MH_EXECUTE) ||
          (header->flags != (MH_NOUNDEFS | MH_PIE)))
      {
        continue;
      }
      g_kernel_slide = slide;
      kernel_header_found = true;
      break;
    }
    if (!kernel_header_found) {
      return false;
    }
#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
  }
#endif

  g_kernel_header = (struct mach_header_64 *)
    (KERNEL_HEADER_ADDR + g_kernel_slide);

  return true;
}

// The running kernel contains a valid symbol table.  We can use this to find
// the address of any "external" kernel symbol, including those considered
// "private".  'symbol' should be exactly what's listed in the symbol table,
// including the "extra" leading underscore.
void *kernel_dlsym(const char *symbol)
{
  if (!find_kernel_header()) {
    return NULL;
  }

  static bool found_symbol_table = false;

  static vm_offset_t symbolTableOffset = 0;
  static vm_offset_t stringTableOffset = 0;
  static uint32_t symbols_index = 0;
  static uint32_t symbols_count = 0;

  // Find the symbol table
  if (!found_symbol_table) {
    vm_offset_t linkedit_fileoff_increment = 0;
    bool found_linkedit_segment = false;
    bool found_symtab_segment = false;
    bool found_dysymtab_segment = false;
    uint32_t num_commands = g_kernel_header->ncmds;
    const struct load_command *load_command = (struct load_command *)
      ((vm_offset_t)g_kernel_header + sizeof(struct mach_header_64));
    uint32_t i;
    for (i = 1; i <= num_commands; ++i) {
      uint32_t cmd = load_command->cmd;
      switch (cmd) {
        case LC_SEGMENT_64: {
          if (found_linkedit_segment) {
            return NULL;
          }
          struct segment_command_64 *command =
            (struct segment_command_64 *) load_command;
          if (!strcmp(command->segname, "__LINKEDIT")) {
            linkedit_fileoff_increment = command->vmaddr - command->fileoff;
            found_linkedit_segment = true;
          }
          break;
        }
        case LC_SYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct symtab_command *command =
            (struct symtab_command *) load_command;
          symbolTableOffset = command->symoff + linkedit_fileoff_increment;
          stringTableOffset = command->stroff + linkedit_fileoff_increment;
          found_symtab_segment = true;
          break;
        }
        case LC_DYSYMTAB: {
          if (!found_linkedit_segment) {
            return NULL;
          }
          struct dysymtab_command *command =
            (struct dysymtab_command *) load_command;
          symbols_index = command->iextdefsym;
          symbols_count = symbols_index + command->nextdefsym;
          found_dysymtab_segment = true;
          break;
        }
        default: {
          if (found_linkedit_segment) {
            return NULL;
          }
          break;
        }
      }
      if (found_linkedit_segment && found_symtab_segment && found_dysymtab_segment) {
        found_symbol_table = true;
        break;
      }
      load_command = (struct load_command *)
        ((vm_offset_t)load_command + load_command->cmdsize);
    }
    if (!found_symbol_table) {
      return NULL;
    }
  }

  // Search the symbol table
  uint32_t i;
  for (i = symbols_index; i < symbols_count; ++i) {
    struct nlist_64 *symbolTableItem = (struct nlist_64 *)
      (symbolTableOffset + i * sizeof(struct nlist_64));

    uint8_t type = symbolTableItem->n_type;
    if ((type & N_STAB) || ((type & N_TYPE) != N_SECT)) {
      continue;
    }
    uint8_t sect = symbolTableItem->n_sect;
    if (!sect) {
      continue;
    }
    const char *stringTableItem = (char *)
      (stringTableOffset + symbolTableItem->n_un.n_strx);
    if (stringTableItem && !strcmp(stringTableItem, symbol)) {
      return (void *) symbolTableItem->n_value;
    }
  }

  return NULL;
}

// The system call table (aka the sysent table) is used by the kernel to
// process system calls from userspace.  Apple tries to hide it, but not
// very effectively.  We need to hook one entry in the table to intercept
// calls from userspace to check sandbox permissions.  Most of this happens
// via MAC framework hooks, called from the kernel.  But some permission
// checking also happens via explicit calls from userspace, for example to
// sandbox_check(pid_t pid, const char *operation, int32_t type, ...);

typedef int32_t sy_call_t(struct proc *, void *, int *);
typedef void sy_munge_t(void *); // For OS X 10.10 and above
typedef void sy_munge_t_mavericks(const void *, void *); // For OS X 10.9

struct sysent {          // system call table, OS X 10.10 and above
  sy_call_t *sy_call;    // implementing function
  sy_munge_t *sy_arg_munge32; // system call arguments munger for 32-bit process
  int32_t  sy_return_type; // system call return types
  int16_t  sy_narg;      // number of args
  uint16_t sy_arg_bytes; // Total size of args in bytes for 32-bit system calls
};

struct sysent_mavericks {// system call table, OS X 10.9
  sy_call_t *sy_call;    // implementing function
  sy_munge_t_mavericks *sy_arg_munge32; // arguments munger for 32-bit process
  sy_munge_t_mavericks *sy_arg_munge64; // arguments munger for 64-bit process
  int32_t  sy_return_type; // system call return types
  int16_t  sy_narg;      // number of args
  uint16_t sy_arg_bytes; // Total size of args in bytes for 32-bit system calls
};

void *g_sysent_table = NULL;

bool find_sysent_table()
{
  if (g_sysent_table) {
    return true;
  }
  if (!find_kernel_header()) {
    return false;
  }

  // The first three entries of the sysent table point to these functions.
  sy_call_t *nosys = (sy_call_t *) kernel_dlsym("_nosys");
  sy_call_t *exit = (sy_call_t *) kernel_dlsym("_exit");
  sy_call_t *fork = (sy_call_t *) kernel_dlsym("_fork");
  if (!nosys || !exit || !fork) {
    return false;
  }

  uint32_t num_data_sections = 0;
  struct section_64 *data_sections = NULL;
  const char *data_segment_name;
  const char *const_section_name;
  if (macOS_Sierra()) {
    data_segment_name = "__CONST";
    const_section_name = "__constdata";
  } else {
    data_segment_name = "__DATA";
    const_section_name = "__const";
  }

  // The definition of the sysent table is "const struct sysent sysent[]",
  // so we look for it in the __DATA segment's __const section (on ElCapitan
  // and below) or in the __CONST segment's __constdata section (on Sierra).
  // Note that this section's contents have been set read-only, which we need
  // to work around below in hook_sysent_call().
  uint32_t num_commands = g_kernel_header->ncmds;
  const struct load_command *load_command = (struct load_command *)
    ((vm_offset_t)g_kernel_header + sizeof(struct mach_header_64));
  bool found_data_segment = false;
  uint32_t i;
  for (i = 1; i <= num_commands; ++i) {
    uint32_t cmd = load_command->cmd;
    switch (cmd) {
      case LC_SEGMENT_64: {
        struct segment_command_64 *command =
          (struct segment_command_64 *) load_command;
        if (!strcmp(command->segname, data_segment_name)) {
          num_data_sections = command->nsects;
          data_sections = (struct section_64 *)
            ((vm_offset_t)command + sizeof(struct segment_command_64));
          found_data_segment = true;
        }
        break;
      }
      default: {
        break;
      }
    }
    if (found_data_segment) {
      break;
    }
    load_command = (struct load_command *)
      ((vm_offset_t)load_command + load_command->cmdsize);
  }
  if (!found_data_segment) {
    return false;
  }

  vm_offset_t const_section = 0;
  vm_offset_t const_section_size = 0;

  bool found_const_section = false;
  for (i = 0; i < num_data_sections; ++i) {
    if (!strcmp(data_sections[i].sectname, const_section_name)) {
      const_section = data_sections[i].addr;
      const_section_size = data_sections[i].size;
      found_const_section = true;
      break;
    }
  }
  if (!found_const_section) {
    return false;
  }

  bool found_sysent_table = false;
  vm_offset_t offset;
  for (offset = 0; offset < const_section_size; offset += 16) {
    struct sysent *table = (struct sysent *) (const_section + offset);
    if (table->sy_call != nosys) {
      continue;
    }
    vm_offset_t next_entry_offset = sizeof(sysent);
    if (OSX_Mavericks()) {
      next_entry_offset = sizeof(sysent_mavericks);
    }
    struct sysent *next_entry = (struct sysent *)
      ((vm_offset_t)table + next_entry_offset);
    if (next_entry->sy_call != exit) {
      continue;
    }
    next_entry = (struct sysent *)
      ((vm_offset_t)next_entry + next_entry_offset);
    if (next_entry->sy_call != fork) {
      continue;
    }
    g_sysent_table = table;
    found_sysent_table = true;
    break;
  }

  return found_sysent_table;
}

bool hook_sysent_call(uint32_t offset, sy_call_t *hook, sy_call_t **orig)
{
  if (orig) {
    *orig = NULL;
  }
  if (!find_sysent_table() || !hook) {
    return false;
  }

  static int *pnsysent = NULL;
  if (!pnsysent) {
    pnsysent = (int *) kernel_dlsym("_nsysent");
    if (!pnsysent) {
      return false;
    }
  }
  if (offset >= *pnsysent) {
    return false;
  }

  sy_call_t *orig_local = NULL;
  void *orig_addr = NULL;
  if (OSX_Mavericks()) {
    struct sysent_mavericks *table = (struct sysent_mavericks *) g_sysent_table;
    orig_local = table[offset].sy_call;
    orig_addr = &(table[offset].sy_call);
  } else {
    struct sysent *table = (struct sysent *) g_sysent_table;
    orig_local = table[offset].sy_call;
    orig_addr = &(table[offset].sy_call);
  }

  bool retval = true;

  // In principle, in kernel mode we should be able to write to RAM even if
  // it's been set read-only -- but not if the WP bit of the CR0 control
  // register is set, as it is by default in Apple's kernel mode.  Since the
  // const section containing the sysent table is read-only, we need to
  // temporarily unset this bit.
  uintptr_t org_cr0 = get_cr0();
  set_cr0(org_cr0 & ~CR0_WP);

  if (!OSCompareAndSwapPtr((void *) orig_local, (void *) hook, orig_addr)) {
    retval = false;
  }

  set_cr0(org_cr0);

  if (orig && retval) {
    *orig = orig_local;
  }

  return retval;
}

// SandboxMirror's logging is configured using environment variables of the
// form "SM_...".  If a process has one of these "trigger" variables set,
// SandboxMirror logs that process's sandbox-constrained behavior accordingly.

// SM_TRACE ---- Which rules to log that a process might be constrained by
//
// Set this to one or more rule names, separated by commas.  Add a wildcard
// ('*') to the end of a (partial) rule specification to make it include every
// rule beginning with that string.  The specification "*" includes every
// rule.  Prepend a '~' character to negate the rule specification -- to make
// it exclude every rule that it matches.  All "positive" specifications are
// ORed together, then ANDed with each "negative" specification.

// SM_LOGFILE -- Name of the file (if any) to which to append logging
//
// By default SandboxMirror only logs to the Console.  (On OS X 10.11 and
// below these entries get written to /var/log/system.log.)  Set this to make
// it also append logging to a file in /var/log/sandboxmirrord.

// SM_DOSTACK -- Also log stack traces
//
// By default, SandboxMirror logs the name of the rule being checked, the path
// to the process's executable, and similar information to identify exactly
// when and where a particular constraint has (potentially) been applied to a
// particular process.  Set this (to any value) to make SandboxMirror also log
// a stack trace for each instance of potential "constraint".

// SM_KIDSONLY - Only log for child processes
//
// By default SandboxMirror logs for a given process and all its children
// (though on OS X 10.9 and 10.10 only if they inherit their parent's
// environment, and aren't XPC processes).  But often a developer will only
// want to sandbox an app's child processes (each of whose functionality can
// be more narrowly defined than that of the parent process).  Set this (to
// any value) to make SandboxMirror not log anything for the parent process.

#define SM_TRACE_ENV_VAR "SM_TRACE"
#define SM_LOGFILE_ENV_VAR "SM_LOGFILE"
#define SM_DOSTACK_ENV_VAR "SM_DOSTACK"
#define SM_KIDSONLY_ENV_VAR "SM_KIDSONLY"
#define SM_TRACE_PARTIAL_MATCH_CHAR '*'
#define SM_TRACE_NEGATIVE_MATCH_CHAR '~'
#define SM_TRACE_DELIM ","

#define SM_FILENAME_SIZE 1024
typedef char sm_filename_t[SM_FILENAME_SIZE];
#define SM_PATH_SIZE 1024
typedef char sm_path_t[SM_PATH_SIZE];
#define SM_REPORT_SIZE 2048
typedef char sm_report_t[SM_REPORT_SIZE];

// From ElCapitan's xnu kernel's osfmk/mach/coalition.h [begin]

#define COALITION_TYPE_RESOURCE  (0)
#define COALITION_TYPE_JETSAM    (1)
#define COALITION_TYPE_MAX       (1)

#define COALITION_NUM_TYPES      (COALITION_TYPE_MAX + 1)

#define COALITION_TASKROLE_UNDEF  (0)
#define COALITION_TASKROLE_LEADER (1)
#define COALITION_TASKROLE_XPC    (2)
#define COALITION_TASKROLE_EXT    (3)

#define COALITION_NUM_TASKROLES   (4)

#define COALITION_ROLEMASK_ALLROLES ((1 << COALITION_NUM_TASKROLES) - 1)
#define COALITION_ROLEMASK_UNDEF    (1 << COALITION_TASKROLE_UNDEF)
#define COALITION_ROLEMASK_LEADER   (1 << COALITION_TASKROLE_LEADER)
#define COALITION_ROLEMASK_XPC      (1 << COALITION_TASKROLE_XPC)
#define COALITION_ROLEMASK_EXT      (1 << COALITION_TASKROLE_EXT)

#define COALITION_SORT_NOSORT     (0)
#define COALITION_SORT_DEFAULT    (1)
#define COALITION_SORT_MEM_ASC    (2)
#define COALITION_SORT_MEM_DEC    (3)
#define COALITION_SORT_USER_ASC   (4)
#define COALITION_SORT_USER_DEC   (5)

#define COALITION_NUM_SORT        (6)

// From ElCapitan's xnu kernel's osfmk/mach/coalition.h [end]

// typedefs for kernel private functions needed by get_xpc_parent()
typedef task_t (*proc_task_t)(proc_t process);
typedef void (*task_coalition_ids_t)(task_t task,
                                     uint64_t ids[COALITION_NUM_TYPES]);
typedef coalition_t (*coalition_find_by_id_t)(uint64_t coal_id);
typedef void (*coalition_release_t)(coalition_t coal);
typedef int (*coalition_get_pid_list_t)(coalition_t coal, uint32_t rolemask,
                                        int sort_order, int *pid_list, int list_sz);

// Many Apple applications (like Safari) now use XPC to launch child
// processes.  But unlike ordinary child processes, these don't inherit their
// parents' environment (with its SM_... trigger variables).  That makes it
// difficult to use SandboxMirror with Apple applications.  As it happens,
// though, an XPC child (like an ordinary child process) does become a member
// of its parent process's "coalition".  The coalition infrastructure's
// intended use is to deal with memory pressure
// (http://apple.stackexchange.com/questions/155458/strange-message-in-console-about-dirtyjetsammemorylimit-key,
// http://newosxbook.com/articles/MemoryPressure.html).  But we can lean on it
// to find a given child process's "XPC parent" (if it has one).  Coalitions
// are supported on Yosemite and above.  But the following would be much more
// difficult on Yosemite, and isn't possible at all on Mavericks.  So it's
// probably best just to implement this method on ElCapitan (and above).
pid_t get_xpc_parent(pid_t possible_child)
{
  if (!possible_child || (!OSX_ElCapitan() && !macOS_Sierra())) {
    return 0;
  }

  static proc_task_t proc_task = NULL;
  if (!proc_task) {
    proc_task = (proc_task_t) kernel_dlsym("_proc_task");
    if (!proc_task) {
      return 0;
    }
  }
  static task_coalition_ids_t task_coalition_ids = NULL;
  if (!task_coalition_ids) {
    task_coalition_ids = (task_coalition_ids_t)
      kernel_dlsym("_task_coalition_ids");
    if (!task_coalition_ids) {
      return 0;
    }
  }
  static coalition_find_by_id_t coalition_find_by_id = NULL;
  if (!coalition_find_by_id) {
    coalition_find_by_id = (coalition_find_by_id_t)
      kernel_dlsym("_coalition_find_by_id");
    if (!coalition_find_by_id) {
      return 0;
    }
  }
  static coalition_release_t coalition_release = NULL;
  if (!coalition_release) {
    coalition_release = (coalition_release_t)
      kernel_dlsym("_coalition_release");
    if (!coalition_release) {
      return 0;
    }
  }
  static coalition_get_pid_list_t coalition_get_pid_list = NULL;
  if (!coalition_get_pid_list) {
    coalition_get_pid_list = (coalition_get_pid_list_t)
      kernel_dlsym("_coalition_get_pid_list");
    if (!coalition_get_pid_list) {
      return 0;
    }
  }

  proc_t child_process = proc_find(possible_child);
  if (!child_process) {
    return 0;
  }
  task_t child_task = proc_task(child_process);
  proc_rele(child_process);
  if (!child_task) {
    return 0;
  }
  uint64_t coal_ids[COALITION_NUM_TYPES];
  task_coalition_ids(child_task, coal_ids);
  coalition_t coal = NULL;
  int i;
  for (i = 0; i < COALITION_NUM_TYPES; ++i) {
    coal = coalition_find_by_id(coal_ids[i]);
    if (coal) {
      break;
    }
  }
  if (!coal) {
    return 0;
  }

  // Get a list of the pids of all the processes in 'possible_child's
  // coalition.  This will be ordered from the topmost parent to its most
  // recently created descendant (maybe newer than 'possible_child').
  pid_t coal_pid_list[50];
  int npids = coalition_get_pid_list(coal, COALITION_ROLEMASK_ALLROLES,
                                     COALITION_SORT_NOSORT, coal_pid_list,
                                     sizeof(coal_pid_list)/sizeof(pid_t));
  coalition_release(coal);
  // Given a list of two or more items:  Starting from its end, look first for
  // 'possible_child'.  Then look for the first child process whose parent
  // isn't launchd (whose 'parent_pid' isn't '1') -- in other words for the
  // first "ordinary" child (which isn't an XPC child).  Break without setting
  // 'xpc_parent' if this is 'possible_child' itself.  If no such process is
  // found before the top, choose the top process.  (The XPC parent may have
  // been launched from the command line -- in which case Terminal will be at
  // the top of the list, and be the XPC parent's ancestor.  Otherwise the XPC
  // parent will be at the top of the list.)
  pid_t xpc_parent = 0;
  bool found_possible_child = false;
  for (i = npids - 1; i > 0; --i) {
    if (!found_possible_child && (coal_pid_list[i] != possible_child)) {
      continue;
    }
    found_possible_child = true;
    proc_t a_process = proc_find(coal_pid_list[i]);
    if (!a_process) {
      continue;
    }
    pid_t parent_pid = proc_ppid(a_process);
    proc_rele(a_process);
    if ((parent_pid != coal_pid_list[i]) && (parent_pid > 0) &&
        (parent_pid != 1))
    {
      if (coal_pid_list[i] != possible_child) {
        xpc_parent = coal_pid_list[i];
      }
      break;
    }
    if (i == 1) {
      xpc_parent = coal_pid_list[i - 1];
    }
  }

  return xpc_parent;
}

typedef struct vm_map_copy *vm_map_copy_t;
extern "C" void vm_map_deallocate(vm_map_t map);

// Kernel private functions needed by get_proc_info().
typedef vm_map_t (*get_task_map_reference_t)(task_t task);
typedef kern_return_t (*vm_map_copyin_t)(vm_map_t src_map,
                                         vm_map_address_t src_addr,
                                         vm_map_size_t len,
                                         boolean_t src_destroy,
                                         vm_map_copy_t *copy_result);
typedef kern_return_t (*vm_map_copy_overwrite_t)(vm_map_t dst_map,
                                                 vm_map_address_t dst_addr,
                                                 vm_map_copy_t copy,
                                                 boolean_t interruptible);
typedef void (*vm_map_copy_discard_t)(vm_map_copy_t copy);

// See source for exec_copyout_strings() in bsd/kern/kern_exec.c for layout of
// beginning of user stack.  "struct proc" is defined in the xnu kernel's
// bsd/sys/proc_internal.h.

typedef struct _proc_fake {
  uint64_t pad[84];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack
  int32_t p_argc;         // saved argc for sysctl_procargs()
  user_addr_t user_stack; // where user stack was allocated
} *proc_fake_t;

typedef struct _proc_fake_elcapitan {
  uint64_t pad[86];
  uint32_t p_argslen;     // Length of "string area" at beginning of user stack
  int32_t p_argc;         // saved argc for sysctl_procargs()
  user_addr_t user_stack; // where user stack was allocated
} *proc_fake_elcapitan_t;

// The caller must call IOFree() on *envp and *buffer.  '*buffer' is workspace
// that holds the strings pointed to by *path and *envp.  Every process's full
// path, arguments and environment are stored (in user space) just before its
// "user stack".  p_argslen includes all of these.  p_argc includes argv[0]
// (the process name) but not the process path.
//
// The environment we examine here is the one with which the process 'pid' was
// created (and which may have been inherited from a parent process).  It
// doesn't contain any changes the process may have made to its own environment
// (for example using setenv()).  We may find use cases that require a change
// to this behavior.
bool get_proc_info(int32_t pid, char **path, char ***envp,
                   vm_size_t *envp_size, void **buffer, vm_size_t *buf_size)
{
  if (!path || !envp || !envp_size || !buffer || !buf_size) {
    return false;
  }

  static proc_task_t proc_task = NULL;
  if (!proc_task) {
    proc_task = (proc_task_t) kernel_dlsym("_proc_task");
    if (!proc_task) {
      return false;
    }
  }
  static get_task_map_reference_t get_task_map_reference = NULL;
  if (!get_task_map_reference) {
    get_task_map_reference = (get_task_map_reference_t)
      kernel_dlsym("_get_task_map_reference");
    if (!get_task_map_reference) {
      return false;
    }
  }
  static vm_map_copyin_t vm_map_copyin = NULL;
  if (!vm_map_copyin) {
    vm_map_copyin = (vm_map_copyin_t) kernel_dlsym("_vm_map_copyin");
    if (!vm_map_copyin) {
      return false;
    }
  }
  static vm_map_copy_overwrite_t vm_map_copy_overwrite = NULL;
  if (!vm_map_copy_overwrite) {
    vm_map_copy_overwrite = (vm_map_copy_overwrite_t)
      kernel_dlsym("_vm_map_copy_overwrite");
    if (!vm_map_copy_overwrite) {
      return false;
    }
  }
  static vm_map_copy_discard_t vm_map_copy_discard = NULL;
  if (!vm_map_copy_discard) {
    vm_map_copy_discard = (vm_map_copy_discard_t)
      kernel_dlsym("_vm_map_copy_discard");
    if (!vm_map_copy_discard) {
      return false;
    }
  }

  proc_t our_proc = proc_find(pid);
  if (!our_proc) {
    return false;
  }
  task_t our_task = proc_task(our_proc);
  if (!our_task) {
    proc_rele(our_proc);
    return false;
  }
  task_reference(our_task);

  uint32_t p_argslen = 0;
  int32_t p_argc = 0;
  user_addr_t user_stack = 0;
  if (OSX_ElCapitan() || macOS_Sierra()) {
    proc_fake_elcapitan_t proc = (proc_fake_elcapitan_t) our_proc;
    if (proc) {
      p_argslen = proc->p_argslen;
      p_argc = proc->p_argc;
      user_stack = proc->user_stack;
    }
  } else {
    proc_fake_t proc = (proc_fake_t) our_proc;
    if (proc) {
      p_argslen = proc->p_argslen;
      p_argc = proc->p_argc;
      user_stack = proc->user_stack;
    }
  }
  proc_rele(our_proc);
  if (!p_argslen || !user_stack) {
    task_deallocate(our_task);
    return false;
  }
  *path = NULL;
  *envp = NULL;
  *envp_size = 0;
  *buffer = NULL;
  *buf_size = 0;

  vm_size_t desired_buf_size = p_argslen;
  char *holder = (char *) IOMalloc(desired_buf_size);
  if (!holder) {
    task_deallocate(our_task);
    return false;
  }
  user_addr_t source = user_stack - desired_buf_size;
  vm_map_t proc_map = get_task_map_reference(our_task);
  task_deallocate(our_task);
  if (!proc_map) {
    IOFree(holder, desired_buf_size);
    return false;
  }
  vm_map_copy_t copy;
  // vm_map_copyin() can fail with KERN_INVALID_ADDRESS if our_proc/our_task
  // is quitting.
  kern_return_t rv = vm_map_copyin(proc_map, source, desired_buf_size,
                                   false, &copy);
  vm_map_deallocate(proc_map);
  if (rv != KERN_SUCCESS) {
    IOFree(holder, desired_buf_size);
    return false;
  }
  rv = vm_map_copy_overwrite(kernel_map, (vm_map_address_t) holder,
                             copy, false);
  if (rv != KERN_SUCCESS) {
    IOFree(holder, desired_buf_size);
    vm_map_copy_discard(copy);
    return false;
  }

  char *holder_past_end = holder + desired_buf_size;
  holder_past_end[-1] = 0;
  holder_past_end[-2] = 0;

  int args_env_count = 0;
  int i; char *item;
  for (i = 0, item = holder; item < holder_past_end; ++i) {
    if (!item[0]) {
      args_env_count = i;
      break;
    }
    if (i == 0) {
      const char *path_header = "executable_path=";
      size_t path_header_len = strlen(path_header);
      if (!strncmp(item, path_header, path_header_len)) {
        item += path_header_len;
      }
      *path = item;
    }
    item += strlen(item) + 1;
    // The process path (the first 'item') is padded (at the end) with
    // multiple NULLs.  Presumably a fixed amount of storage has been set
    // aside for it.
    if (i == 0) {
      while (!item[0]) {
        ++item;
      }
    }
  }
  int args_count = p_argc + 1; // Including the process path
  int env_count = args_env_count - args_count;
  // Though it's very unlikely, we might have a process path and no environment.
  if (env_count <= 0) {
    return true;
  }

  vm_size_t desired_envp_size = (env_count + 1) * sizeof(char *);
  char **envp_holder = (char **) IOMalloc(desired_envp_size);
  // Do an error return if we're out of memory -- even if we already have the
  // process path.
  if (!envp_holder) {
    *path = NULL;
    IOFree(holder, desired_buf_size);
    return false;
  }

  for (i = 0, item = holder; i < args_env_count; ++i) {
    if (i >= args_count) {
      envp_holder[i - args_count] = item;
    }
    item += strlen(item) + 1;
    if (i == 0) {
      while (!item[0]) {
        ++item;
      }
    }
  }
  envp_holder[env_count] = NULL;

  *envp = envp_holder;
  *envp_size = desired_envp_size;
  *buffer = holder;
  *buf_size = desired_buf_size;
  return true;
}

// All characters in 'spec' after the first "*" are ignored.  'rule' can
// end in "*".  Beware that whitespace is not ignored.
bool spec_matches_rule(char *spec, const char *rule)
{
  if (!spec || !spec[0] || !rule || !rule[0]) {
    return false;
  }

  //printf("spec_matches_rule(1): spec %s, rule %s\n", spec, rule);
  bool positive_match = false;
  bool negative_match = false;
  bool positive_token_seen = false;
  bool negative_token_seen = false;

  char rule_holder[1024];
  strncpy(rule_holder, rule, sizeof(rule_holder));
  size_t rule_length = strlen(rule_holder);
  bool rule_is_partial = false;
  if (rule_holder[rule_length - 1] == SM_TRACE_PARTIAL_MATCH_CHAR) {
    rule_is_partial = true;
    rule_holder[rule_length - 1] = 0; --rule_length;
  }
  if (!rule_length) {
    return true;
  }

  char spec_holder[1024];
  strncpy(spec_holder, spec, sizeof(spec_holder));
  char *spec_ptr = spec_holder;

  char *token;
  while ((token = strsep(&spec_ptr, SM_TRACE_DELIM)) != NULL) {
    //printf("spec_matches_rule(2): token %s\n", token);
    size_t token_length = strlen(token);
    bool negative_token = false;
    if (token[0] == SM_TRACE_NEGATIVE_MATCH_CHAR) {
      ++token; --token_length;
      negative_token = true;
      negative_token_seen = true;
    } else {
      positive_token_seen = true;
    }
    bool partial_match_allowed = false;
    if (token[token_length - 1] == SM_TRACE_PARTIAL_MATCH_CHAR) {
      token[token_length - 1] = 0; --token_length;
      partial_match_allowed = true;
    }
    bool match = false;
    if (token_length) {
      if (rule_is_partial && (token_length > rule_length)) {
          match = (strncmp(token, rule_holder, rule_length) == 0);
      } else {
        if (partial_match_allowed) {
          match = (strncmp(token, rule_holder, token_length) == 0);
        } else {
          match = (strcmp(token, rule_holder) == 0);
        }
      }
    } else if (partial_match_allowed) {
      match = true;
    }
    if (match) {
      if (negative_token) {
        negative_match = true;
      } else {
        positive_match = true;
      }
    }
  }

  // Any number of "positive matches" without a negative match will make us
  // return 'true'.  Even one "negative match" will make us return 'false'.
  // If no positive match was attempted, we return 'true' for a failed
  // negative match.

  //printf("spec_matches_rule(3): positive_match %d, negative_match %d, positive_token_seen %d, negative_token_seen %d\n",
  //       positive_match, negative_match, positive_token_seen, negative_token_seen);
  return (!negative_match && (positive_match || !positive_token_seen));
}

typedef struct _match_info {
  const char *rule;
  bool matched;
} match_info;

void get_report_info(match_info *info, bool *found_trace_variable,
                     bool *do_stacktrace, sm_filename_t log_file,
                     sm_path_t proc_path)
{
  if (!info || !found_trace_variable || !do_stacktrace ||
      !log_file || !proc_path)
  {
    return;
  }
  int i, j;
  for (i = 0; info[i].rule; ++i) {
    info[i].matched = false;
  }
  *found_trace_variable = false;
  *do_stacktrace = false;
  log_file[0] = 0;
  proc_path[0] = 0;

  char *path_ptr = NULL;
  char **envp = NULL;
  vm_size_t envp_size = 0;
  void *buffer = NULL;
  vm_size_t buf_size = 0;
  int32_t pid = proc_selfpid();
  if (!get_proc_info(pid, &path_ptr, &envp, &envp_size, &buffer, &buf_size)) {
    return;
  }

  if (path_ptr) {
    strncpy(proc_path, path_ptr, SM_PATH_SIZE);
  }

  // Though it's very unlikely, we might have a process path and no environment.
  if (!envp) {
    IOFree(buffer, buf_size);
    return;
  }

  bool kids_only = false;

  bool found_trigger_variable = false;
  for (i = 0; envp[i]; ++i) {
    //printf("   %s\n", envp[i]);
    char *value = envp[i];
    char *key = strsep(&value, "=");
    //printf("   key %s, value %s\n", key, value ? value : "");
    if (key && value && value[0]) {
      if (!strcmp(key, SM_TRACE_ENV_VAR)) {
        for (j = 0; info[j].rule; ++j) {
          info[j].matched = spec_matches_rule(value, info[j].rule);
        }
        found_trigger_variable = true;
        *found_trace_variable = true;
      } else if (!strcmp(key, SM_DOSTACK_ENV_VAR)) {
        *do_stacktrace = true;
        found_trigger_variable = true;
      } else if (!strcmp(key, SM_LOGFILE_ENV_VAR)) {
        strncpy(log_file, value, SM_FILENAME_SIZE);
        found_trigger_variable = true;
      } else if (!strcmp(key, SM_KIDSONLY_ENV_VAR)) {
        kids_only = true;
        found_trigger_variable = true;
      }
    }
  }
  IOFree(envp, envp_size);
  IOFree(buffer, buf_size);

  bool is_child = false;

  // If we didn't find any trigger variable in the current process's
  // environment, look for an "XPC parent" process and examine its
  // environment.  XPC children don't inherit their parent's environment.
  if (!found_trigger_variable) {
    pid_t xpc_parent = get_xpc_parent(pid);
    if (xpc_parent) {
      is_child = true;
      if (get_proc_info(xpc_parent, &path_ptr, &envp, &envp_size,
                        &buffer, &buf_size))
      {
        if (envp) {
          for (i = 0; envp[i]; ++i) {
            char *value = envp[i];
            char *key = strsep(&value, "=");
            if (key && value && value[0]) {
              if (!strcmp(key, SM_TRACE_ENV_VAR)) {
                for (j = 0; info[j].rule; ++j) {
                  info[j].matched = spec_matches_rule(value, info[j].rule);
                }
                *found_trace_variable = true;
              } else if (!strcmp(key, SM_DOSTACK_ENV_VAR)) {
                *do_stacktrace = true;
              } else if (!strcmp(key, SM_LOGFILE_ENV_VAR)) {
                strncpy(log_file, value, SM_FILENAME_SIZE);
              } else if (!strcmp(key, SM_KIDSONLY_ENV_VAR)) {
                kids_only = true;
              }
            }
          }
          IOFree(envp, envp_size);
        }
        IOFree(buffer, buf_size);
      }
    }
  }

  // If kids_only is true and we didn't find an XPC parent process, look for
  // an ordinary parent with SM_KIDSONLY set.  If found, the current process
  // is a child process of a parent that's of interest to us.  Otherwise treat
  // the current process as the parent process, and turn logging off.
  if (kids_only && !is_child) {
    proc_t our_proc = proc_self();
    if (our_proc) {
      pid_t normal_parent = proc_ppid(our_proc);
      proc_rele(our_proc);
      if ((normal_parent > 0) && (normal_parent != 1)) {
        if (get_proc_info(normal_parent, &path_ptr, &envp, &envp_size,
                          &buffer, &buf_size))
        {
          if (envp) {
            for (i = 0; envp[i]; ++i) {
              char *value = envp[i];
              char *key = strsep(&value, "=");
              if (key && value && value[0]) {
                if (!strcmp(key, SM_KIDSONLY_ENV_VAR)) {
                  is_child = true;
                  break;
                }
              }
            }
            IOFree(envp, envp_size);
          }
          IOFree(buffer, buf_size);
        }
      }
    }
  }

  if (kids_only && !is_child) {
    for (i = 0; info[i].rule; ++i) {
      info[i].matched = false;
    }
    *found_trace_variable = false;
  }
}

// We need a "host port" to communicate with sandboxmirrord.  But in recent
// versions of the OS X kernel, Apple reserves all "legal" host ports for its
// own purposes.  So, if possible, we need to steal one.  Apple's CHUD kernel
// extension is obsolete, and very unlikely to be present.  So it's very
// likely that we can safely steal its "host port".
mach_port_t get_server_port()
{
  mach_port_t server_port = 0;
  host_get_special_port(host_priv_self(), HOST_LOCAL_NODE,
                        HOST_CHUD_PORT, &server_port);
  return server_port;
}

// sm_report() and its associated structures and defines are derived from the
// sm_report* files that come with the sandboxmirrord distro -- specifically
// from the files that are generated from sm_report.defs by running 'mig' on
// it.  'mig' "generates" an "interface" whereby we can send Mach messages to
// sandboxmirrord (and receive messages from it).

#define MSGID_BASE 666

#pragma pack(4)
typedef struct {
  mach_msg_header_t Head;
  /* start of the kernel processed data */
  mach_msg_body_t msgh_body;
  mach_msg_port_descriptor_t task;
  /* end of the kernel processed data */
  NDR_record_t NDR;
  int32_t do_stacktrace;
  int32_t pid;
  uint64_t tid;
  mach_msg_type_number_t log_fileOffset; /* MiG doesn't use it */
  mach_msg_type_number_t log_fileCnt;
  char log_file[SM_FILENAME_SIZE];
  mach_msg_type_number_t proc_pathOffset; /* MiG doesn't use it */
  mach_msg_type_number_t proc_pathCnt;
  char proc_path[SM_PATH_SIZE];
  mach_msg_type_number_t reportOffset; /* MiG doesn't use it */
  mach_msg_type_number_t reportCnt;
  char report[SM_REPORT_SIZE];
} Request;

typedef struct {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
} Reply;
#pragma pack()

#define _WALIGN_(x) (((x) + 3) & ~3)

// Kernel private functions needed by sm_report().
typedef mach_port_t (*convert_task_to_port_t)(task_t);
typedef void (*ipc_port_release_send_t)(ipc_port_t port);

kern_return_t sm_report(mach_port_t server_port,
                        task_t task,
                        int32_t do_stacktrace,
                        int32_t pid,
                        uint64_t tid,
                        sm_filename_t log_file,
                        sm_path_t proc_path,
                        sm_report_t report)
{
  static convert_task_to_port_t convert_task_to_port = NULL;
  if (!convert_task_to_port) {
    convert_task_to_port = (convert_task_to_port_t)
      kernel_dlsym("_convert_task_to_port");
    if (!convert_task_to_port) {
      return KERN_FAILURE;
    }
  }
  static ipc_port_release_send_t ipc_port_release_send = NULL;
  if (!ipc_port_release_send) {
    ipc_port_release_send = (ipc_port_release_send_t)
      kernel_dlsym("_ipc_port_release_send");
    if (!ipc_port_release_send) {
      return KERN_FAILURE;
    }
  }

  Request Out;

  Out.msgh_body.msgh_descriptor_count = 1;
  if (task && do_stacktrace) {
    task_reference(task);
    Out.task.name = convert_task_to_port(task);
  } else {
    Out.task.name = MACH_PORT_NULL;
  }
  Out.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  Out.task.type = MACH_MSG_PORT_DESCRIPTOR;

  Out.NDR = NDR_record;
  Out.do_stacktrace = do_stacktrace;
  Out.pid = pid;
  Out.tid = tid;

  Out.log_fileCnt =
    mig_strncpy(Out.log_file, log_file, SM_FILENAME_SIZE);
  unsigned int msgh_size_delta = _WALIGN_(Out.log_fileCnt);
  unsigned int msgh_size = (mach_msg_size_t)
    (sizeof(Request) - (SM_FILENAME_SIZE + SM_PATH_SIZE + SM_REPORT_SIZE)) +
    msgh_size_delta;

  Request *OutP = (Request *)
    (((pointer_t) &Out) + msgh_size_delta - SM_FILENAME_SIZE);
  OutP->proc_pathCnt = mig_strncpy(OutP->proc_path, proc_path, SM_PATH_SIZE);
  msgh_size_delta = _WALIGN_(OutP->proc_pathCnt);
  msgh_size += msgh_size_delta;

  OutP = (Request *)
    (((pointer_t) OutP) + msgh_size_delta - SM_PATH_SIZE);
  OutP->reportCnt = mig_strncpy(OutP->report, report, SM_REPORT_SIZE);
  msgh_size += _WALIGN_(OutP->reportCnt);

  Out.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                       MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  Out.Head.msgh_remote_port = server_port;
  Out.Head.msgh_local_port = mig_get_reply_port();
  Out.Head.msgh_id = MSGID_BASE;

  // This method sends a Mach message concurrently to sandboxmirrord, which
  // makes it possible for sandboxmirrord to take an up-to-date snapshot of
  // the current process.
  mach_msg_return_t msg_result =
    mach_msg_rpc_from_kernel(&Out.Head, msgh_size,
                             (mach_msg_size_t) sizeof(Reply));

  if (msg_result != KERN_SUCCESS) {
    ipc_port_release_send(Out.task.name);
  }

  return msg_result;
}

bool check_should_report(match_info *info, bool report_if_trace_variable_found,
                         bool *do_stacktrace, sm_filename_t log_file,
                         sm_path_t proc_path)
{
  if (!info || !do_stacktrace || !log_file || !proc_path) {
    return false;
  }

  bool found_trace_variable = false;
  get_report_info(info, &found_trace_variable, do_stacktrace, log_file, proc_path);

  bool do_trace = (report_if_trace_variable_found && found_trace_variable);
  if (!do_trace) {
    int i;
    for (i = 0; info[i].rule; ++i) {
      if (info[i].matched) {
        do_trace = true;
        break;
      }
    }
  }

  return do_trace;
}

void do_report(bool do_stacktrace, sm_path_t log_file,
               sm_filename_t proc_path, sm_report_t report)
{
  if (!log_file || !proc_path || !report) {
    return;
  }

  uint32_t pid = proc_selfpid();
  uint64_t tid = thread_tid(current_thread());
  task_t task = current_task();
  sm_report(get_server_port(), task, do_stacktrace, pid, tid,
            log_file, proc_path, report);
}

bool get_vnode_path(struct vnode *vp, char **path, vm_size_t *path_size)
{
  if (!path || !path_size) {
    return false;
  }
  *path = NULL;
  *path_size = 0;

  char vnode_path[MAXPATHLEN];
  strncpy(vnode_path, "null", sizeof(vnode_path));
  if (vp) {
    int length = MAXPATHLEN;
    if (vn_getpath(vp, vnode_path, &length) != 0) {
      const char *vnode_name = vnode_getname(vp);
      if (vnode_name) {
        strncpy(vnode_path, vnode_name, sizeof(vnode_path));
        vnode_putname(vnode_name);
      } else {
        strncpy(vnode_path, "unknown", sizeof(vnode_path));
      }
    }
  }

  vm_size_t size = strlen(vnode_path) + 1;
  char *holder = (char *) IOMalloc(size);
  if (!holder) {
    return false;
  }
  strncpy(holder, vnode_path, size);
  *path_size = size;
  *path = holder;
  return true;
}

void hook_policy_init(struct mac_policy_conf *mpc)
{
}

int hook_policy_syscall(struct proc *p,
                        int call,
                        user_addr_t arg)
{
  return 0;
}

// We need to hook the __mac_syscall system call to intercept calls from
// userspace that check sandbox permissions -- notably to check_sandbox().
// Most sandbox permission checks take place via calls from the kernel to
// hooks in the installed MAC policy modules (including Sandbox.kext and
// SandboxMirror.kext).  These are handled below.  But the few permission
// checks that arrive directly from userspace need to be handled here.

// Offset in the sysent table
#define MAC_SYSCALL_SYSENT_OFFSET 381

struct __mac_syscall_args {
  char *policy;
  int call;
  user_addr_t args;
};

typedef int (*__mac_syscall_t)(proc_t, struct __mac_syscall_args *, int *);

__mac_syscall_t g_mac_syscall_orig = NULL;

// Values not listed here are invalid.  These are different from the values
// passed to the userland sandbox_check() call.
enum sandbox_filter_type {
  SANDBOX_FILTER_NONE        = 0,
  SANDBOX_FILTER_PATH        = 1,
  SANDBOX_FILTER_GLOBAL_NAME = 6,
  SANDBOX_FILTER_LOCAL_NAME  = 7,
  SANDBOX_FILTER_UNKNOWN_25  = 25,
  SANDBOX_FILTER_UNKNOWN_27  = 27,
  SANDBOX_FILTER_UNKNOWN_28  = 28,
  SANDBOX_FILTER_UNKNOWN_33  = 33,
  SANDBOX_FILTER_UNKNOWN_34  = 34,
  SANDBOX_FILTER_INFO        = 35,
  SANDBOX_FILTER_UNKNOWN_38  = 38,
};

#define SB_CHECK_FLAGS_NOREPORT  (1 << 0)
#define SB_CHECK_FLAGS_CANONICAL (1 << 1)
#define SB_CHECK_FLAGS_UNKNOWN4  (1 << 2)
#define SB_CHECK_FLAGS_IDVERSION (1 << 30) // proc_special_id is p_idversion in proc_t
#define SB_CHECK_FLAGS_UNIQUEID  (1 << 31) // proc_special_id is p_uniqueid in proc_t

typedef struct _filter_info
{
  user_addr_t name;          // char *
  uint64_t unknown;
} filter_info, *filter_info_t;

// Because there's enough room on Mavericks for this full structure (including
// proc_special_id), we don't need to have two OS-specific variants of it.
// (For to the call to __mac_syscall, it's stored in struct uthread's
// u_int64_t uu_arg[8].  See unix_syscall() and unix_syscall64() in the xnu
// kernel's bsd/dev/i386/systemcalls.c.)
typedef struct _check_sandbox_args
{
  user_addr_t result;        // uint64_t *
  uint64_t pid;
  user_addr_t operation;     // char *
  uint64_t filter_type;      // sandbox_filter_type
  union {
    user_addr_t name;        // char *
    user_addr_t info;        // filter_info_t
  } filter_info;
  uint64_t flags;
  uint64_t proc_special_id;  // Present on OS X 10.10 and up
} check_sandbox_args, *check_sandbox_args_t;

void hook_check_sandbox(check_sandbox_args_t args, int retval)
{
  if (!args) {
    return;
  }

  check_sandbox_args args_local;
  if (copyin((user_addr_t) args, &args_local,
             sizeof(check_sandbox_args)) != 0)
  {
    return;
  }

  char operation_local[PATH_MAX];
  size_t size;
  if (!args_local.operation ||
      copyinstr(args_local.operation, operation_local, 
                sizeof(operation_local), &size))
  {
    operation_local[0] = 0;
  }

  char filter_name_local[PATH_MAX];
  user_addr_t filter_name_user = args_local.filter_info.name;
  uint64_t filter_unknown = 0;
  if (args_local.filter_type == SANDBOX_FILTER_INFO) {
    filter_info filter_info_local;
    if (args_local.filter_info.info &&
        !copyin(args_local.filter_info.info, &filter_info_local,
                sizeof(filter_info)))
    {
      filter_name_user = filter_info_local.name;
      filter_unknown = filter_info_local.unknown;
    }
  }
  if (!filter_name_user ||
      copyinstr(filter_name_user, filter_name_local,
                sizeof(filter_name_local), &size))
  {
    filter_name_local[0] = 0;
  }

  if (!operation_local[0]) {
    return;
  }

  match_info minfo[2];
  minfo[0].rule = operation_local;
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  sm_report_t report;
  if (filter_name_local[0]) {
    snprintf(report, sizeof(report), "check_sandbox(): Query rule \"%s\" for object \"%s\" and pid \'%u\' with filter_type \'0x%llx\' and flags \'0x%llx\'",
             minfo[0].rule, filter_name_local, (pid_t) args_local.pid, args_local.filter_type, args_local.flags);
  } else {
    snprintf(report, sizeof(report), "check_sandbox(): Query rule \"%s\" for pid \'%u\' with filter_type \'0x%llx\' and flags \'0x%llx\'",
             minfo[0].rule, (pid_t) args_local.pid, args_local.filter_type, args_local.flags);
  }
  do_report(do_stacktrace, log_file, proc_path, report);
}

typedef struct _check_get_task_args
{
  uint64_t pid;
} check_get_task_args, *check_get_task_args_t;

// Only supported on Yosemite and above.  It's (indirectly) invoked from
// userspace via calls to rootless_allows_task_for_pid(), which (at least for
// now) is only called from libdtrace.dylib.
void hook_check_get_task(check_get_task_args_t args, int retval)
{
  if (!args) {
    return;
  }

  check_get_task_args args_local;
  if (copyin((user_addr_t) args, &args_local,
             sizeof(check_get_task_args)) != 0)
  {
    return;
  }

  match_info minfo[2];
  minfo[0].rule = "mach-priv-task-port";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "check_get_task(): Query rule \"%s\" for pid \'%u\'",
           minfo[0].rule, (pid_t) args_local.pid);
  do_report(do_stacktrace, log_file, proc_path, report);
}

void hook_apply_sandbox(int retval)
{
  match_info minfo[1];
  minfo[0].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, true, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "Initializing sandbox");
  do_report(do_stacktrace, log_file, proc_path, report);
}

int hook__mac_syscall(proc_t p, struct __mac_syscall_args *uap, int *retv)
{
  int retval = ENOENT;
  if (g_mac_syscall_orig) {
    retval = g_mac_syscall_orig(p, uap, retv);
    char policy[MAC_MAX_POLICY_NAME];
    size_t ulen;
    if (!copyinstr((const user_addr_t)(uap->policy), policy,
                   sizeof(policy), &ulen))
    {
      if (!strcmp(policy, "Sandbox")) {
        if ((uap->call == 0) || (uap->call == 1)) {
          hook_apply_sandbox(retval);
        }
        if (uap->call == 2) {
          hook_check_sandbox((check_sandbox_args_t) uap->args, retval);
        }
        int check_get_task_call = -1;
        if (OSX_Yosemite()) {
          check_get_task_call = 18;
        } else if (OSX_ElCapitan()) {
          check_get_task_call = 21;
        } else if (macOS_Sierra()) {
          check_get_task_call = 22;
        }
        if ((check_get_task_call >= 0) && (uap->call == check_get_task_call)) {
          hook_check_get_task((check_get_task_args_t) uap->args, retval);
        }
      }
    }
  }
  return retval;
}

// What follows are all the hooks that can be called from the kernel for MAC
// permission checks.  Sandbox.kext implements these same hooks, and is also
// called for the same permission checks.  But, whereas we always return 0
// (permission granted), Sandbox.kext contains code to check whether or not
// permission should be granted.

// From the xnu kernel's bsd/sys/file_internal.h

typedef enum {
  DTYPE_VNODE = 1,  /* file */
  DTYPE_SOCKET,     /* communications endpoint */
  DTYPE_PSXSHM,     /* POSIX Shared memory */
  DTYPE_PSXSEM,     /* POSIX Semaphores */
  DTYPE_KQUEUE,     /* kqueue */
  DTYPE_PIPE,       /* pipe */
  DTYPE_FSEVENTS,   /* fsevents */
  DTYPE_ATALK       /* (obsolete) */
} file_type_t;

typedef struct _fileglob_fake
{
  uint64_t pad1[5];
  const struct fileops_fake {
    file_type_t fo_type;    /* descriptor type */
  } *fg_ops;
  uint64_t pad2[1];
  void *fg_data;   /* vnode or socket or SHM or semaphore */
} *fileglob_fake_t;

// Sandbox always returns 0 here.
int hook_file_check_fcntl(kauth_cred_t cred,
                          struct fileglob *fg,
                          struct label *label,
                          int cmd,
                          user_long_t arg)
{
  return 0;
}

static void do_file_check_mmap(struct fileglob *fg, int prot, int flags)
{
  match_info minfo[2];
  minfo[0].rule = "file-map-executable";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  struct vnode *mapped_file = NULL;
  fileglob_fake_t info = (fileglob_fake_t) fg;
  if (info && (info->fg_ops->fo_type == DTYPE_VNODE)) {
    mapped_file = (struct vnode *) info->fg_data;
  }

  char *mf_path;
  vm_size_t mf_path_size;
  if (!get_vnode_path(mapped_file, &mf_path, &mf_path_size)) {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "file_check_mmap(): Query rule \"%s\" for file \"%s\" with prot \'0x%x\' and flags \'0x%x\'",
           minfo[0].rule, mf_path, prot, flags);
  IOFree(mf_path, mf_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);
}

// Only called on OS X 10.10 and up.
// Exists in this form on 10.9 and 10.10.
int hook_file_check_mmap_v1(kauth_cred_t cred,
                            struct fileglob *fg,
                            struct label *label,
                            int prot,
                            int flags,
                            int *maxprot)
{
  do_file_check_mmap(fg, prot, flags);
  return 0;
}

// Only called on OS X 10.10 and up.
// Exists in this form on 10.11.
int hook_file_check_mmap_v2(kauth_cred_t cred,
                            struct fileglob *fg,
                            struct label *label,
                            int prot,
                            int flags,
                            uint64_t file_pos,
                            int *maxprot)
{
  do_file_check_mmap(fg, prot, flags);
  return 0;
}

// This check is only used by the MAC framework infrastructure (to get
// permission to allocate a label), not (even indirectly) by anything
// from userspace.
int hook_file_check_set(kauth_cred_t cred,
                        struct fileglob *fg,
                        char *elements,
                        int len)
{
  return 0;
}

// From the xnu kernel's bsd/sys/mount_internal.h

typedef struct _mount_fake {
  uint64_t pad1[7];
  struct vnode *mnt_vnodecovered;  /* vnode we mounted on */
  uint64_t pad2[8];
  uint32_t pad3[1];
  struct vfsstatfs mnt_vfsstat;    /* cache of filesystem stats */
} *mount_fake_t;

int hook_mount_check_fsctl(kauth_cred_t cred,
                           struct mount *mp,
                           struct label *label,
                           unsigned int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "system-fsctl";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  struct vnode *mount_point = NULL;
  mount_fake_t mp_info = (mount_fake_t) mp;
  if (mp_info) {
    mount_point = mp_info->mnt_vnodecovered;
  }

  char *mp_path;
  vm_size_t mp_path_size;
  if (!get_vnode_path(mount_point, &mp_path, &mp_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_fsctl(): Query rule \"%s\" for mount point \"%s\" and cmd \'0x%x\'",
           minfo[0].rule, mp_path, cmd);
  IOFree(mp_path, mp_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_mount_check_mount(kauth_cred_t cred,
                           struct vnode *vp,
                           struct label *vlabel,
                           struct componentname *cnp,
                           const char *vfc_name)
{
  match_info minfo[2];
  minfo[0].rule = "file-mount";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char mp_name[MAXPATHLEN];
  size_t mp_namelen = sizeof(mp_name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (mp_namelen > cnp->cn_pnlen) {
      mp_namelen = cnp->cn_pnlen + 1;
    }
    strncpy(mp_name, cnp->cn_pnbuf, mp_namelen);
  } else {
    strncpy(mp_name, "null", mp_namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_mount(): Query rule \"%s\" for mount point \"%s\" with vfc_name \"%s\"",
           minfo[0].rule, mp_name, vfc_name ? vfc_name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_mount_check_remount(kauth_cred_t cred,
                             struct mount *mp,
                             struct label *mlabel)
{
  match_info minfo[2];
  if (OSX_ElCapitan() || macOS_Sierra()) {
    minfo[0].rule = "file-mount-update";
  } else {
    minfo[0].rule = "file-mount";
  }
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  struct vnode *mount_point = NULL;
  mount_fake_t mp_info = (mount_fake_t) mp;
  if (mp_info) {
    mount_point = mp_info->mnt_vnodecovered;
  }

  char *mp_path;
  vm_size_t mp_path_size;
  if (!get_vnode_path(mount_point, &mp_path, &mp_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_remount(): Query rule \"%s\" for mount point \"%s\"",
           minfo[0].rule, mp_path);
  IOFree(mp_path, mp_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_mount_check_umount(kauth_cred_t cred,
                            struct mount *mp,
                            struct label *mlabel)
{
  match_info minfo[2];
  minfo[0].rule = "file-unmount";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  struct vnode *mount_point = NULL;
  mount_fake_t mp_info = (mount_fake_t) mp;
  if (mp_info) {
    mount_point = mp_info->mnt_vnodecovered;
  }

  char *mp_path;
  vm_size_t mp_path_size;
  if (!get_vnode_path(mount_point, &mp_path, &mp_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_umount(): Query rule \"%s\" for mount point \"%s\"",
           minfo[0].rule, mp_path);
  IOFree(mp_path, mp_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.10 and up.
int hook_system_check_sysctlbyname(kauth_cred_t cred,
                                   const char *namestring,
                                   int *name,
                                   u_int namelen,
                                   user_addr_t old, /* NULLOK */
                                   size_t oldlen,
                                   user_addr_t newvalue, /* NULLOK */
                                   size_t newlen)
{
  match_info minfo[3];
  minfo[0].rule = "process-info-pidinfo";
  if (newvalue && newlen) {
    minfo[1].rule = "sysctl-write";
  } else {
    minfo[1].rule = "sysctl-read";
  }
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  u_int namelen_fixed = namelen;
  if (namelen_fixed > CTL_MAXNAME) {
    namelen_fixed = CTL_MAXNAME;
  }
  char name_array[(CTL_MAXNAME * 11) + 1];
  int i;
  for (i = 0, name_array[0] = 0; i < namelen_fixed; ++i) {
    int nameval;
    if (name) {
      nameval = name[i];
    } else {
      nameval = 0;
    }
    size_t offset = strlen(name_array);
    const char *format;
    if (i == 0) {
      format = "%d";
    } else {
      format = ":%d";
    }
    snprintf(name_array + offset, 12, format, nameval);
  }

  sm_report_t report;

  if (OSX_ElCapitan() || macOS_Sierra()) {
    if ((namelen >= 4) && (name[0] == CTL_KERN)) {
      pid_t info_for = -1;
      switch (name[1]) {
        case KERN_PROC:
          if (name[2] == KERN_PROC_PID) {
            info_for = name[3];
          }
          break;
        case KERN_PROCARGS:
        case KERN_PROCARGS2:
          if (namelen >= 3) {
            info_for = name[2];
          }
          break;
        default:
          info_for = -1;
          break;
      }
      if (info_for != -1) {
        if (minfo[0].matched) {
          snprintf(report, sizeof(report), "system_check_sysctlbyname(): Query rule \"%s\" for pid \'%d\' with name \"%s[%s]\" and namelen \'%d\'",
                   minfo[0].rule, info_for, namestring ? namestring : "null", name_array, namelen);
          do_report(do_stacktrace, log_file, proc_path, report);
        }
      }
    }
  }

  if (!minfo[1].matched) {
    return 0;
  }

  snprintf(report, sizeof(report), "system_check_sysctlbyname(): Query rule \"%s\" with name \"%s[%s]\" and namelen \'%d\'",
           minfo[1].rule, namestring ? namestring : "null", name_array, namelen);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.10 and up.
int hook_vnode_check_rename(kauth_cred_t cred,
                            struct vnode *dvp,
                            struct label *dlabel,
                            struct vnode *vp,
                            struct label *label,
                            struct componentname *cnp,
                            struct vnode *tdvp,
                            struct label *tdlabel,
                            struct vnode *tvp,
                            struct label *tlabel,
                            struct componentname *tcnp)
{
  match_info minfo[3];
  minfo[0].rule = "file-write-unlink";
  minfo[1].rule = "file-write-create";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char oldname[MAXPATHLEN];
  size_t oldnamelen = sizeof(oldname);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (oldnamelen > cnp->cn_pnlen) {
      oldnamelen = cnp->cn_pnlen + 1;
    }
    strncpy(oldname, cnp->cn_pnbuf, oldnamelen);
  } else {
    strncpy(oldname, "null", oldnamelen);
  }
  char newname[MAXPATHLEN];
  size_t newnamelen = sizeof(newname);
  if (tcnp && tcnp->cn_pnbuf && tcnp->cn_pnlen) {
    if (newnamelen > tcnp->cn_pnlen) {
      newnamelen = tcnp->cn_pnlen + 1;
    }
    strncpy(newname, tcnp->cn_pnbuf, newnamelen);
  } else {
    strncpy(newname, "null", newnamelen);
  }

  sm_report_t report;
  if (minfo[0].matched) {
    snprintf(report, sizeof(report), "vnode_check_rename(): Query rule \"%s\" for old name \"%s\"",
             minfo[0].rule, oldname);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  if (minfo[1].matched) {
    snprintf(report, sizeof(report), "vnode_check_rename(): Query rule \"%s\" for new name \"%s\"",
             minfo[1].rule, newname);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_kext_check_query(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "system-kext-query";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "kext_check_query(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_iokit_check_nvram_get(kauth_cred_t cred,
                               const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "nvram-get";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_nvram_get(): Query rule \"%s\" for name \"%s\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_iokit_check_nvram_set(kauth_cred_t cred,
                               const char *name,
                               io_object_t value)
{
  match_info minfo[3];
  minfo[0].rule = "nvram-set";
  if (macOS_Sierra()) {
    minfo[1].rule = "boot-arg-set";
    minfo[2].rule = NULL;
  } else {
    minfo[1].rule = NULL;
  }
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *valueUTF8;
  OSString *valueStr = NULL;
  if (value) {
    valueStr = OSDynamicCast(OSString, value);
  }
  if (valueStr) {
    valueUTF8 = valueStr->getCStringNoCopy();
  } else if (value) {
    valueUTF8 = "non-string";
  } else {
    valueUTF8 = "null";
  }

  if (minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "iokit_check_nvram_set(): Query rule \"%s\" for name \"%s\" and value \"%s\"",
             minfo[0].rule, name ? name : "null", valueUTF8);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[1].rule && minfo[1].matched && name && !strcmp(name, "boot-args")) {
    sm_report_t report;
    snprintf(report, sizeof(report), "iokit_check_nvram_set(): Query rule \"%s\" for name \"%s\" and value \"%s\"",
             minfo[1].rule, name ? name : "null", valueUTF8);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_iokit_check_nvram_delete(kauth_cred_t cred,
                                  const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "nvram-delete";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_nvram_delete(): Query rule \"%s\" for name \"%s\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_proc_check_expose_task(kauth_cred_t cred,
                                struct proc *p)
{
  match_info minfo[2];
  minfo[0].rule = "mach-priv-task-port";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_expose_task(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, p ? proc_pid(p) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

const char *get_host_special_port_name(int id)
{
  switch (id) {
    case 1: return "HOST_PORT";
    case 2: return "HOST_PRIV_PORT";
    case 3: return "HOST_IO_MASTER_PORT";
    case 8: return "HOST_DYNAMIC_PAGER_PORT";
    case 9: return "HOST_AUDIT_CONTROL_PORT";
    case 10: return "HOST_USER_NOTIFICATION_PORT";
    case 11: return "HOST_AUTOMOUNTD_PORT";
    case 12: return "HOST_LOCKD_PORT";
    case 14: return "HOST_SEATBELT_PORT";
    case 15: return "HOST_KEXTD_PORT";
    case 16: return "HOST_CHUD_PORT";
    case 17: return "HOST_UNFREED_PORT";
    case 18: return "HOST_AMFID_PORT";
    case 19: return "HOST_GSSD_PORT";
    case 20: return "HOST_TELEMETRY_PORT";
    case 21: return "HOST_ATM_NOTIFICATION_PORT";
    case 22: return "HOST_COALITION_PORT";
    case 23: return "HOST_SYSDIAGNOSE_PORT";
    case 24: return "HOST_XPC_EXCEPTION_PORT";
    case 25: return "HOST_CONTAINERD_PORT";
    default: return "unknown";
  }
}

// Only hooked on OS X 10.11 and up.
int hook_proc_check_set_host_special_port(kauth_cred_t cred,
                                          int id,
                                          struct ipc_port *port)
{
  match_info minfo[2];
  minfo[0].rule = "mach-host-special-port-set";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_set_host_special_port(): Query rule \"%s\" for id \"%s(%d)\"",
           minfo[0].rule, get_host_special_port_name(id), id);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.11 and up.
int hook_proc_check_set_host_exception_port(kauth_cred_t cred,
                                            unsigned int exception)
{
  match_info minfo[2];
  minfo[0].rule = "mach-host-exception-port-set";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_set_host_exception_port(): Query rule \"%s\" for exception \'0x%x\'",
           minfo[0].rule, exception);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixsem_check_create(kauth_cred_t cred,
                               const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixsem_check_create(): Query rule \"%s\" for semaphore \"%s\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixsem_check_open(kauth_cred_t cred,
                             struct pseminfo *ps,
                             struct label *semlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSEMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->psem_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixsem_check_open(): Query rule \"%s\" for semaphore \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixsem_check_post(kauth_cred_t cred,
                             struct pseminfo *ps,
                             struct label *semlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSEMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->psem_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixsem_check_post(): Query rule \"%s\" for semaphore \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixsem_check_unlink(kauth_cred_t cred,
                               struct pseminfo *ps,
                               struct label *semlabel,
                               const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixsem_check_unlink(): Query rule \"%s\" for semaphore \"%s\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixsem_check_wait(kauth_cred_t cred,
                             struct pseminfo *ps,
                             struct label *semlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSEMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->psem_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixsem_check_wait(): Query rule \"%s\" for semaphore \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixshm_check_create(kauth_cred_t cred,
                               const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-shm-write-create";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixshm_check_create(): Query rule \"%s\" for region \"%s\"\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixshm_check_open(kauth_cred_t cred,
                             struct pshminfo *ps,
                             struct label *shmlabel,
                             int fflags)
{
  match_info minfo[3];
  minfo[0].rule = "ipc-posix-shm-read-data";
  minfo[1].rule = "ipc-posix-shm-write-data";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSHMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->pshm_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  if ((fflags & FREAD) && minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "posixshm_check_open(): Query rule \"%s\" for region \"%s\" and fflags \'0x%x\'",
             minfo[0].rule, name, fflags);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  if ((fflags & (O_RDWR | O_TRUNC)) && minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "posixshm_check_open(): Query rule \"%s\" for region \"%s\" and fflags \'0x%x\'",
             minfo[1].rule, name, fflags);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  return 0;
}

int hook_posixshm_check_stat(kauth_cred_t cred,
                             struct pshminfo *ps,
                             struct label *shmlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-shm-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSHMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->pshm_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixshm_check_stat(): Query rule \"%s\" for region \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixshm_check_truncate(kauth_cred_t cred,
                                 struct pshminfo *ps,
                                 struct label *shmlabel,
                                 off_t len)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-shm-write-data";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[PSHMNAMLEN + 1];
  if (ps) {
    strncpy(name, ps->pshm_name, sizeof(name));
  } else {
    strncpy(name, "null", sizeof(name));
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixshm_check_truncate(): Query rule \"%s\" for region \"%s\" with length \'%lld\'",
           minfo[0].rule, name, len);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_posixshm_check_unlink(kauth_cred_t cred,
                               struct pshminfo *ps,
                               struct label *shmlabel,
                               const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-posix-shm-write-unlink";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "posixshm_check_unlink(): Query rule \"%s\" for region \"%s\"\"",
           minfo[0].rule, name ? name : "null");
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Always responds "forbidden-debug" on OS X 10.9.  The rule name
// "system-debug" may not be correct -- I can't find instances in any *.sb
// file.
int hook_proc_check_debug(kauth_cred_t cred,
                          struct proc *proc)
{
  match_info minfo[2];
  minfo[0].rule = "system-debug";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_debug(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, proc ? proc_pid(proc) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_fork(kauth_cred_t cred,
                         struct proc *proc)
{
  match_info minfo[2];
  minfo[0].rule = "process-fork";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_fork(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, proc ? proc_pid(proc) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_get_task_name(kauth_cred_t cred,
                                  struct proc *p)
{
  match_info minfo[2];
  minfo[0].rule = "mach-task-name";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_get_task_name(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, p ? proc_pid(p) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_get_task(kauth_cred_t cred,
                             struct proc *p)
{
  match_info minfo[2];
  minfo[0].rule = "mach-priv-task-port";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_get_task(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, p ? proc_pid(p) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_sched(kauth_cred_t cred,
                          struct proc *proc)
{
  match_info minfo[2];
  minfo[0].rule = "system-sched";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_sched(): Query rule \"%s\" for process \'%d\'\"",
           minfo[0].rule, proc ? proc_pid(proc) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_setaudit(kauth_cred_t cred,
                             struct auditinfo_addr *ai)
{
  match_info minfo[2];
  minfo[0].rule = "system-audit";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  au_id_t auid = -1;
  au_asid_t asid = 0;
  if (ai) {
    auid = ai->ai_auid;
    asid = ai->ai_asid;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_setauid(): Query rule \"%s\" with auid \'%d\' and asid \'%d\'",
           minfo[0].rule, auid, asid);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_setauid(kauth_cred_t cred,
                            uid_t auid)
{
  match_info minfo[2];
  minfo[0].rule = "system-audit";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_setauid(): Query rule \"%s\" with auid \'%d\'",
           minfo[0].rule, auid);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Apple has changed how the MAC_OS_X_VERSION_... variables are defined in
// AvailabilityMacros.h on OS X 10.10 and up.  Now minor versions may also be
// defined, and the "base" is 100 times what it was on OS X 10.9 and below.
#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
// From /usr/include/sys/lctx.h, which isn't in Kernel framework on 10.11 and up.
#define LCID_REMOVE     (-1)
#define LCID_CREATE     (0)
#endif

// Only hooked on OS X 10.9 and 10.10.
int hook_proc_check_setlcid(struct proc *p0,
                            struct proc *p,
                            pid_t pid,
                            pid_t lcid)
{
  match_info minfo[2];
  minfo[0].rule = "system-lcid";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *lcid_name;
  switch (lcid) {
    case LCID_REMOVE: lcid_name = "LCID_REMOVE"; break;
    case LCID_CREATE: lcid_name = "LCID_CREATE"; break;
    default: lcid_name = "unknown"; break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_setlcid(): Query rule \"%s\" with pid \'%d\' and lcid \"%s(%d)\"",
           minfo[0].rule, pid, lcid_name, lcid);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_proc_check_signal(kauth_cred_t cred,
                           struct proc *proc,
                           int signum)
{
  match_info minfo[2];
  minfo[0].rule = "signal";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *signal_name;
  switch (signum) {
    case 1: signal_name = "SIGHUP"; break;
    case 2: signal_name = "SIGINT"; break;
    case 3: signal_name = "SIGQUIT"; break;
    case 4: signal_name = "SIGILL"; break;
    case 5: signal_name = "SIGTRAP"; break;
    case 6: signal_name = "SIGABRT"; break;
    case 7: signal_name = "SIGEMT"; break;
    case 8: signal_name = "SIGFPE"; break;
    case 9: signal_name = "SIGKILL"; break;
    case 10: signal_name = "SIGBUS"; break;
    case 11: signal_name = "SIGSEGV"; break;
    case 12: signal_name = "SIGSYS"; break;
    case 13: signal_name = "SIGPIPE"; break;
    case 14: signal_name = "SIGALRM"; break;
    case 15: signal_name = "SIGTERM"; break;
    case 16: signal_name = "SIGURG"; break;
    case 17: signal_name = "SIGSTOP"; break;
    case 18: signal_name = "SIGTSTP"; break;
    case 19: signal_name = "SIGCONT"; break;
    case 20: signal_name = "SIGCHLD"; break;
    case 21: signal_name = "SIGTTIN"; break;
    case 22: signal_name = "SIGTTOU"; break;
    case 23: signal_name = "SIGIO"; break;
    case 24: signal_name = "SIGXCPU"; break;
    case 25: signal_name = "SIGXFSZ"; break;
    case 26: signal_name = "SIGVTALRM"; break;
    case 27: signal_name = "SIGPROF"; break;
    case 28: signal_name = "SIGWINCH"; break;
    case 29: signal_name = "SIGINFO"; break;
    case 30: signal_name = "SIGUSR1"; break;
    case 31: signal_name = "SIGUSR2"; break;
    default: signal_name = "unknown"; break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_signal(): Query rule \"%s\" for signal \"%s(%d) to process \'%d\'\"",
           minfo[0].rule, signal_name, signum, proc ? proc_pid(proc) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// struct socket defined in xnu kernel's bsd/sys/socketvar.h
typedef struct _socket_fake {
  int so_zone;          /* zone we were allocated from */
  short so_type;        /* generic type, see socket.h */
  u_int32_t so_options; /* from socket call, see socket.h */
} *socket_fake_t;

const char *get_socket_type_name(short type)
{
  switch (type) {
    case SOCK_STREAM: return "SOCK_STREAM";
    case SOCK_DGRAM: return "SOCK_DGRAM";
    case SOCK_RAW: return "SOCK_RAW";
    case SOCK_RDM: return "SOCK_RDM";
    case SOCK_SEQPACKET: return "SOCK_SEQPACKET";
    default: return "unknown";
  }
}

const char *get_addr_family_name(sa_family_t addr_family)
{
  switch (addr_family) {
    case 0: return "AF_UNSPEC";
    case 1: return "AF_UNIX";
    case 2: return "AF_INET";
    case 3: return "AF_IMPLINK";
    case 4: return "AF_PUP";
    case 5: return "AF_CHAOS";
    case 6: return "AF_NS";
    case 7: return "AF_ISO";
    case 8: return "AF_ECMA";
    case 9: return "AF_DATAKIT";
    case 10: return "AF_CCITT";
    case 11: return "AF_SNA";
    case 12: return "AF_DECnet";
    case 13: return "AF_DLI";
    case 14: return "AF_LAT";
    case 15: return "AF_HYLINK";
    case 16: return "AF_APPLETALK";
    case 17: return "AF_ROUTE";
    case 18: return "AF_LINK";
    case 19: return "pseudo_AF_XTP";
    case 20: return "AF_COIP";
    case 21: return "AF_CNT";
    case 22: return "pseudo_AF_RTIP";
    case 23: return "AF_IPX";
    case 24: return "AF_SIP";
    case 25: return "pseudo_AF_PIP";
    case 26: return "pseudo_AF_BLUE";
    case 27: return "AF_NDRV";
    case 28: return "AF_ISDN";
    case 29: return "pseudo_AF_KEY";
    case 30: return "AF_INET6";
    case 31: return "AF_NATM";
    case 32: return "AF_SYSTEM";
    case 33: return "AF_NETBIOS";
    case 34: return "AF_PPP";
    case 35: return "pseudo_AF_HDRCMPLT";
    case 36: return "AF_AFP";
    case 37: return "AF_IEEE80211";
    case 38: return "AF_UTUN";
    case 39: return "AF_MULTIPATH";
    default: return "unknown";
  }
}

const char *get_protocol_name(int protocol)
{
  switch (protocol) {
    case 0: return "IP";
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 3: return "GGP";
    case 4: return "IP-ENCAP";
    case 5: return "ST2";
    case 6: return "TCP";
    case 7: return "CBT";
    case 8: return "EGP";
    case 9: return "IGP";
    case 10: return "BBN-RCC-MON";
    case 11: return "NVP-II";
    case 12: return "PUP";
    case 13: return "ARGUS";
    case 14: return "EMCON";
    case 15: return "XNET";
    case 16: return "CHAOS";
    case 17: return "UDP";
    case 18: return "MUX";
    case 19: return "DCN-MEAS";
    case 20: return "HMP";
    case 21: return "PRM";
    case 22: return "XNS-IDP";
    case 23: return "TRUNK-1";
    case 24: return "TRUNK-2";
    case 25: return "LEAF-1";
    case 26: return "LEAF-2";
    case 27: return "RDP";
    case 28: return "IRTP";
    case 29: return "ISO-TP4";
    case 30: return "NETBLT";
    case 31: return "MFE-NSP";
    case 32: return "MERIT-INP";
    case 33: return "SEP";
    case 34: return "3PC";
    case 35: return "IDPR";
    case 36: return "XTP";
    case 37: return "DDP";
    case 38: return "IDPR-CMTP";
    case 39: return "TP++";
    case 40: return "IL";
    case 41: return "IPV6";
    case 42: return "SDRP";
    case 43: return "IPV6-ROUTE";
    case 44: return "IPV6-FRAG";
    case 45: return "IDRP";
    case 46: return "RSVP";
    case 47: return "GRE";
    case 48: return "MHRP";
    case 49: return "BNA";
    case 50: return "ESP";
    case 51: return "AH";
    case 52: return "I-NLSP";
    case 53: return "SWIPE";
    case 54: return "NARP";
    case 55: return "MOBILE";
    case 56: return "TLSP";
    case 57: return "SKIP";
    case 58: return "IPV6-ICMP";
    case 59: return "IPV6-NONXT";
    case 60: return "IPV6-OPTS";
    case 61: return "(any host internal protocol)";
    case 62: return "CFTP";
    case 63: return "(any local network)";
    case 64: return "SAT-EXPAK";
    case 65: return "KRYPTOLAN";
    case 66: return "RVD";
    case 67: return "IPPC";
    case 68: return "(any distributed file system)";
    case 69: return "SAT-MON";
    case 70: return "VISA";
    case 71: return "IPCV";
    case 72: return "CPNX";
    case 73: return "CPHB";
    case 74: return "WSN";
    case 75: return "PVP";
    case 76: return "BR-SAT-MON";
    case 77: return "SUN-ND";
    case 78: return "WB-MON";
    case 79: return "WB-EXPAK";
    case 80: return "ISO-IP";
    case 81: return "VMTP";
    case 82: return "SECURE-VMTP";
    case 83: return "VINES";
    case 84: return "TTP";
    case 85: return "NSFNET-IGP";
    case 86: return "DGP";
    case 87: return "TCF";
    case 88: return "EIGRP";
    case 89: return "OSPFIGP";
    case 90: return "Sprite-RPC";
    case 91: return "LARP";
    case 92: return "MTP";
    case 93: return "AX.25";
    case 94: return "IPIP";
    case 95: return "MICP";
    case 96: return "SCC-SP";
    case 97: return "ETHERIP";
    case 98: return "ENCAP";
    case 99: return "(any private encryption scheme)";
    case 100: return "GMTP";
    case 101: return "IFMP";
    case 102: return "PNNI";
    case 103: return "PIM";
    case 104: return "ARIS";
    case 105: return "SCPS";
    case 106: return "QNX";
    case 107: return "A/N";
    case 108: return "IPComp";
    case 109: return "SNP";
    case 110: return "Compaq-Peer";
    case 111: return "IPX-in-IP";
    case 112: return "VRRP";
    case 113: return "PGM";
    case 114: return "(any 0-hop protocol)";
    case 115: return "L2TP";
    case 116: return "DDX";
    case 117: return "IATP";
    case 118: return "ST";
    case 119: return "SRP";
    case 120: return "UTI";
    case 121: return "SMP";
    case 122: return "SM";
    case 123: return "PTP";
    case 124: return "ISIS";
    case 125: return "FIRE";
    case 126: return "CRTP";
    case 127: return "CRUDP";
    case 128: return "SSCOPMCE";
    case 129: return "IPLT";
    case 130: return "SPS";
    case 131: return "PIPE";
    case 132: return "SCTP";
    case 133: return "FC";
    case 254: return "DIVERT";
    default: return "unknown";
  }
}

int hook_socket_check_bind(kauth_cred_t cred,
                           socket_t so,
                           struct label *socklabel,
                           struct sockaddr *addr)
{
  match_info minfo[2];
  minfo[0].rule = "network-bind";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  short socket_type = 0;
  uint32_t socket_options = 0;
  sa_family_t addr_family = 0;
  if (so) {
    socket_type = ((socket_fake_t)so)->so_type;
    socket_options = ((socket_fake_t)so)->so_options;
  }
  if (addr) {
    addr_family = addr->sa_family;
  }
  const char *socket_type_name = get_socket_type_name(socket_type);
  const char *addr_family_name = get_addr_family_name(addr_family);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_bind(): Query rule \"%s\" for socket type \"%s(%d)\" with options \'0x%x\' and address family \"%s(%d)\"",
           minfo[0].rule, socket_type_name, socket_type, socket_options, addr_family_name, addr_family);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_socket_check_connect(kauth_cred_t cred,
                              socket_t so,
                              struct label *socklabel,
                              struct sockaddr *addr)
{
  match_info minfo[2];
  minfo[0].rule = "network-outbound";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  short socket_type = 0;
  uint32_t socket_options = 0;
  sa_family_t dest_addr_family = 0;
  if (so) {
    socket_type = ((socket_fake_t)so)->so_type;
    socket_options = ((socket_fake_t)so)->so_options;
  }
  if (addr) {
    dest_addr_family = addr->sa_family;
  }
  const char *socket_type_name = get_socket_type_name(socket_type);
  const char *dest_addr_family_name = get_addr_family_name(dest_addr_family);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_connect(): Query rule \"%s\" for socket type \"%s(%d)\" with options \'0x%x\' and destination address family \"%s(%d)\"",
           minfo[0].rule, socket_type_name, socket_type, socket_options, dest_addr_family_name, dest_addr_family);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_socket_check_create(kauth_cred_t cred,
                             int domain,
                             int type,
                             int protocol)
{
  match_info minfo[2];
  minfo[0].rule = "system-socket";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *domain_name = get_addr_family_name(domain);
  const char *type_name = get_socket_type_name(type);
  const char *protocol_name = get_protocol_name(protocol);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_create(): Query rule \"%s\" for domain \"%s(%d)\" socket type \"%s(%d)\" and protocol \"%s(%d)\"",
           minfo[0].rule, domain_name, domain, type_name, type, protocol_name, protocol);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_socket_check_listen(kauth_cred_t cred,
                             socket_t so,
                             struct label *socklabel)
{
  match_info minfo[2];
  minfo[0].rule = "network-inbound";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  short socket_type = 0;
  uint32_t socket_options = 0;
  if (so) {
    socket_type = ((socket_fake_t)so)->so_type;
    socket_options = ((socket_fake_t)so)->so_options;
  }
  const char *socket_type_name = get_socket_type_name(socket_type);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_listen(): Query rule \"%s\" for socket type \"%s(%d)\" with options \'0x%x\'",
           minfo[0].rule, socket_type_name, socket_type, socket_options);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_socket_check_receive(kauth_cred_t cred,
                              socket_t so,
                              struct label *socklabel)
{
  match_info minfo[2];
  minfo[0].rule = "network-inbound";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  short socket_type = 0;
  uint32_t socket_options = 0;
  if (so) {
    socket_type = ((socket_fake_t)so)->so_type;
    socket_options = ((socket_fake_t)so)->so_options;
  }
  const char *socket_type_name = get_socket_type_name(socket_type);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_receive(): Query rule \"%s\" for socket type \"%s(%d)\" with options \'0x%x\'",
           minfo[0].rule, socket_type_name, socket_type, socket_options);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_socket_check_send(kauth_cred_t cred,
                           socket_t so,
                           struct label *socklabel,
                           struct sockaddr *addr)
{
  match_info minfo[2];
  minfo[0].rule = "network-outbound";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  short socket_type = 0;
  uint32_t socket_options = 0;
  sa_family_t dest_addr_family = 0;
  if (so) {
    socket_type = ((socket_fake_t)so)->so_type;
    socket_options = ((socket_fake_t)so)->so_options;
  }
  if (addr) {
    dest_addr_family = addr->sa_family;
  }
  const char *socket_type_name = get_socket_type_name(socket_type);
  const char *dest_addr_family_name = get_addr_family_name(dest_addr_family);

  sm_report_t report;
  snprintf(report, sizeof(report), "socket_check_send(): Query rule \"%s\" for socket type \"%s(%d)\" with options \'0x%x\' and destination address family \"%s(%d)\"",
           minfo[0].rule, socket_type_name, socket_type, socket_options, dest_addr_family_name, dest_addr_family);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_acct(kauth_cred_t cred,
                           struct vnode *vp,
                           struct label *vlabel)
{
  match_info minfo[2];
  minfo[0].rule = "system-acct";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_acct(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_audit(kauth_cred_t cred,
                            void *record,
                            int length)
{
  match_info minfo[2];
  minfo[0].rule = "system-audit";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_audit(): Query rule \"%s\" for record of length \'%d\'",
           minfo[0].rule, length);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_auditctl(kauth_cred_t cred,
                               struct vnode *vp,
                               struct label *vl)
{
  match_info minfo[2];
  minfo[0].rule = "system-audit";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_auditctl(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_auditon(kauth_cred_t cred,
                              int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "system-audit";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *cmd_name;
  switch (cmd) {
    case A_SETPOLICY:
      cmd_name = "A_SETPOLICY";
      break;
    case A_OLDSETPOLICY:
      cmd_name = "A_OLDSETPOLICY";
      break;
    case A_SETKMASK:
      cmd_name = "A_SETKMASK";
      break;
    case A_SETQCTRL:
      cmd_name = "A_SETQCTRL";
      break;
    case A_OLDSETQCTRL:
      cmd_name = "A_OLDSETQCTRL";
      break;
    case A_SETSTAT:
      cmd_name = "A_SETSTAT";
      break;
    case A_SETUMASK:
      cmd_name = "A_SETUMASK";
      break;
    case A_SETSMASK:
      cmd_name = "A_SETSMASK";
      break;
    case A_SETCOND:
      cmd_name = "A_SETCOND";
      break;
    case A_OLDSETCOND:
      cmd_name = "A_OLDSETCOND";
      break;
    case A_SETCLASS:
      cmd_name = "A_SETCLASS";
      break;
    case A_SETPMASK:
      cmd_name = "A_SETPMASK";
      break;
    case A_SETFSIZE:
      cmd_name = "A_SETFSIZE";
      break;
    case A_SETKAUDIT:
      cmd_name = "A_SETKAUDIT";
      break;
    case A_GETCLASS:
      cmd_name = "A_GETCLASS";
      break;
    case A_GETPINFO:
      cmd_name = "A_GETPINFO";
      break;
    case A_GETPINFO_ADDR:
      cmd_name = "A_GETPINFO_ADDR";
      break;
    case A_SENDTRIGGER:
      cmd_name = "A_SENDTRIGGER";
      break;
    case A_GETSINFO_ADDR:
      cmd_name = "A_GETSINFO_ADDR";
      break;
    case A_GETSFLAGS:
      cmd_name = "A_GETSFLAGS";
      break;
    case A_SETSFLAGS:
      cmd_name = "A_SETSFLAGS";
      break;
    case A_GETKMASK:
      cmd_name = "A_GETKMASK";
      break;
    case A_GETQCTRL:
      cmd_name = "A_GETQCTRL";
      break;
    case A_OLDGETQCTRL:
      cmd_name = "A_OLDGETQCTRL";
      break;
    case A_GETCWD:
      cmd_name = "A_GETCWD";
      break;
    case A_GETCAR:
      cmd_name = "A_GETCAR";
      break;
    case A_GETSTAT:
      cmd_name = "A_GETSTAT";
      break;
    case A_GETCOND:
      cmd_name = "A_GETCOND";
      break;
    case A_OLDGETCOND:
      cmd_name = "A_OLDGETCOND";
      break;
    case A_GETFSIZE:
      cmd_name = "A_GETFSIZE";
      break;
    case A_GETKAUDIT:
      cmd_name = "A_GETKAUDIT";
      break;
    case A_GETPOLICY:
      cmd_name = "A_GETPOLICY";
      break;
    case A_OLDGETPOLICY:
      cmd_name = "A_OLDGETPOLICY";
      break;
    default:
      cmd_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_auditon(): Query rule \"%s\" with cmd \"%s(%d)\"",
           minfo[0].rule, cmd_name, cmd);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_host_priv(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "mach-priv-host-port";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_host_priv(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_nfsd(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "system-nfssvc";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_nfsd(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_reboot(kauth_cred_t cred,
                             int howto)
{
  match_info minfo[2];
  minfo[0].rule = "system-reboot";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_reboot(): Query rule \"%s\" with howto \'0x%x\'",
           minfo[0].rule, howto);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_settime(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "system-set-time";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_settime(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_swapoff(kauth_cred_t cred,
                              struct vnode *vp,
                              struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "system-swap";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_swapoff(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_swapon(kauth_cred_t cred,
                             struct vnode *vp,
                             struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "system-swap";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_swapon(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.9.
int hook_system_check_sysctl(kauth_cred_t cred,
                             int *name,
                             u_int namelen,
                             user_addr_t old,      /* NULLOK */
                             user_addr_t oldlenp,  /* NULLOK */
                             int inkernel,
                             user_addr_t newvalue, /* NULLOK */
                             size_t newlen)
{
  match_info minfo[2];
  if (newvalue && newlen) {
    minfo[0].rule = "sysctl-write";
  } else {
    minfo[0].rule = "sysctl-read";
  }
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  u_int namelen_fixed = namelen;
  if (namelen_fixed > CTL_MAXNAME) {
    namelen_fixed = CTL_MAXNAME;
  }
  char name_array[(CTL_MAXNAME * 11) + 1];
  int i;
  for (i = 0, name_array[0] = 0; i < namelen_fixed; ++i) {
    int nameval;
    if (name) {
      nameval = name[i];
    } else {
      nameval = 0;
    }
    size_t offset = strlen(name_array);
    const char *format;
    if (i == 0) {
      format = "%d";
    } else {
      format = ":%d";
    }
    snprintf(name_array + offset, 12, format, nameval);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_sysctl(): Query rule \"%s\" with name \"[%s]\" and namelen \'%d\'",
           minfo[0].rule, name_array, namelen);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_enqueue(kauth_cred_t cred,
                               struct msg *msgptr,
                               struct label *msglabel,
                               struct msqid_kernel *msqptr,
                               struct label *msqlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  long type = 0;
  unsigned short size = 0;
  if (msgptr) {
    type = msgptr->msg_type;
    size = msgptr->msg_ts;
  }
  key_t key = -1;
  unsigned short seq_num = 0;
  if (msqptr) {
    key = msqptr->u.msg_perm._key;
    seq_num = msqptr->u.msg_perm._seq;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_enqueue(): Query rule \"%s\" with message type \'0x%lx\' and size \'%d\' for queue key \'0x%x\' and sequence number \'0x%x\'",
           minfo[0].rule, type, size, key, seq_num);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msgrcv(kauth_cred_t cred,
                              struct msg *msgptr,
                              struct label *msglabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  long type = 0;
  unsigned short size = 0;
  if (msgptr) {
    type = msgptr->msg_type;
    size = msgptr->msg_ts;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_msgrcv(): Query rule \"%s\" with message type \'0x%lx\' and size \'%d\'",
           minfo[0].rule, type, size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msgrmid(kauth_cred_t cred,
                               struct msg *msgptr,
                               struct label *msglabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  long type = 0;
  unsigned short size = 0;
  if (msgptr) {
    type = msgptr->msg_type;
    size = msgptr->msg_ts;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_msgrmid(): Query rule \"%s\" with message type \'0x%lx\' and size \'%d\'",
           minfo[0].rule, type, size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msqctl(kauth_cred_t cred,
                              struct msqid_kernel *msqptr,
                              struct label *msqlabel,
                              int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (msqptr) {
    key = msqptr->u.msg_perm._key;
    seq_num = msqptr->u.msg_perm._seq;
  }

  const char *cmd_name;
  switch (cmd) {
    case IPC_RMID:
      cmd_name = "IPC_RMID";
      break;
    case IPC_SET:
      cmd_name = "IPC_SET";
      break;
    case IPC_STAT:
      cmd_name = "IPC_STAT";
      break;
    default:
      cmd_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvsem_check_msqctl(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' and accesstype \"%s(0x%x)\"",
           minfo[0].rule, key, seq_num, cmd_name, cmd);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msqget(kauth_cred_t cred,
                              struct msqid_kernel *msqptr,
                              struct label *msqlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (msqptr) {
    key = msqptr->u.msg_perm._key;
    seq_num = msqptr->u.msg_perm._seq;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_msqget(): Query rule \"%s\" with key \'0x%x\' and sequence number \'0x%x\'",
           minfo[0].rule, key, seq_num);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msqrcv(kauth_cred_t cred,
                              struct msqid_kernel *msqptr,
                              struct label *msqlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (msqptr) {
    key = msqptr->u.msg_perm._key;
    seq_num = msqptr->u.msg_perm._seq;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_msqrcv(): Query rule \"%s\" with key \'0x%x\' and sequence number \'0x%x\'",
           minfo[0].rule, key, seq_num);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvmsq_check_msqsnd(kauth_cred_t cred,
                              struct msqid_kernel *msqptr,
                              struct label *msqlabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-msg";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (msqptr) {
    key = msqptr->u.msg_perm._key;
    seq_num = msqptr->u.msg_perm._seq;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvmsq_check_msqsnd(): Query rule \"%s\" with key \'0x%x\' and sequence number \'0x%x\'",
           minfo[0].rule, key, seq_num);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// From the xnu kernel's bsd/sys/sem_internal.h

#pragma pack(4)
struct user_semid_ds {
  struct ipc_perm sem_perm; /* [XSI] operation permission struct */
  struct sem *sem_base;     /* 32 bit base ptr for semaphore set */
  unsigned short sem_nsems; /* [XSI] number of sems in set */
  user_time_t sem_otime;    /* [XSI] last operation time */
  int32_t sem_pad1;         /* RESERVED: DO NOT USE! */
  user_time_t sem_ctime;    /* [XSI] last change time */
  /* Times measured in secs since */
  /* 00:00:00 GMT, Jan. 1, 1970 */
  int32_t sem_pad2;         /* RESERVED: DO NOT USE! */
  int32_t sem_pad3[4];      /* RESERVED: DO NOT USE! */
};
#pragma pack()

struct semid_kernel {
  struct user_semid_ds u;
  struct label *label;  /* MAC framework label */
};

int hook_sysvsem_check_semctl(kauth_cred_t cred,
                              struct semid_kernel *semakptr,
                              struct label *semaklabel,
                              int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (semakptr) {
    key = semakptr->u.sem_perm._key;
    seq_num = semakptr->u.sem_perm._seq;
  }

  const char *cmd_name;
  switch (cmd) {
    case IPC_RMID:
      cmd_name = "IPC_RMID";
      break;
    case IPC_SET:
      cmd_name = "IPC_SET";
      break;
    case IPC_STAT:
      cmd_name = "IPC_STAT";
      break;
    case GETNCNT:
      cmd_name = "GETNCNT";
      break;
    case GETPID:
      cmd_name = "GETPID";
      break;
    case GETVAL:
      cmd_name = "GETVAL";
      break;
    case GETALL:
      cmd_name = "GETALL";
      break;
    case GETZCNT:
      cmd_name = "GETZCNT";
      break;
    case SETVAL:
      cmd_name = "SETVAL";
      break;
    case SETALL:
      cmd_name = "SETALL";
      break;
    default:
      cmd_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvsem_check_semctl(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' and accesstype \"%s(0x%x)\"",
           minfo[0].rule, key, seq_num, cmd_name, cmd);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvsem_check_semget(kauth_cred_t cred,
                              struct semid_kernel *semakptr,
                              struct label *semaklabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (semakptr) {
    key = semakptr->u.sem_perm._key;
    seq_num = semakptr->u.sem_perm._seq;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvsem_check_semget(): Query rule \"%s\" with key \'0x%x\' and sequence number \'0x%x\'",
           minfo[0].rule, key, seq_num);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvsem_check_semop(kauth_cred_t cred,
                             struct semid_kernel *semakptr,
                             struct label *semaklabel,
                             size_t accesstype)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-sem";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  if (semakptr) {
    key = semakptr->u.sem_perm._key;
    seq_num = semakptr->u.sem_perm._seq;
  }

  const char *accesstype_name;
  switch (accesstype) {
    case SEM_A:
      accesstype_name = "SEM_A";
      break;
    case SEM_R:
      accesstype_name = "SEM_R";
      break;
    default:
      accesstype_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvsem_check_semop(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' and accesstype \"%s(0%lo)\"",
           minfo[0].rule, key, seq_num, accesstype_name, accesstype);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// From the xnu kernel's bsd/sys/shm_internal.h

#pragma pack(4)
struct user_shmid_ds {
  struct ipc_perm shm_perm;     /* operation permission structure */
  user_size_t     shm_segsz;    /* size of segment in bytes */
  pid_t           shm_lpid;     /* PID of last shared memory op */
  pid_t           shm_cpid;     /* PID of creator */
  short           shm_nattch;   /* number of current attaches */
  user_time_t     shm_atime;    /* time of last shmat() */
  user_time_t     shm_dtime;    /* time of last shmdt() */
  user_time_t     shm_ctime;    /* time of last change by shmctl() */
  user_addr_t     shm_internal; /* reserved for kernel use */
};
#pragma pack()

struct shmid_kernel {
  struct user_shmid_ds u;
  struct label *label;  /* MAC label */
};

int hook_sysvshm_check_shmat(kauth_cred_t cred,
                             struct shmid_kernel *shmsegptr,
                             struct label *shmseglabel,
                             int shmflg)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-shm";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  user_size_t size = 0;
  if (shmsegptr) {
    key = shmsegptr->u.shm_perm._key;
    seq_num = shmsegptr->u.shm_perm._seq;
    size = shmsegptr->u.shm_segsz;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvshm_check_shmat(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' size \'%lld\' and shmflg \'0%o\'",
           minfo[0].rule, key, seq_num, size, shmflg);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvshm_check_shmctl(kauth_cred_t cred,
                              struct shmid_kernel *shmsegptr,
                              struct label *shmseglabel,
                              int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-shm";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  user_size_t size = 0;
  if (shmsegptr) {
    key = shmsegptr->u.shm_perm._key;
    seq_num = shmsegptr->u.shm_perm._seq;
    size = shmsegptr->u.shm_segsz;
  }

  const char *cmd_name;
  switch (cmd) {
    case IPC_RMID:
      cmd_name = "IPC_RMID";
      break;
    case IPC_SET:
      cmd_name = "IPC_SET";
      break;
    case IPC_STAT:
      cmd_name = "IPC_STAT";
      break;
    default:
      cmd_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvshm_check_shmctl(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' size \'%lld\' and cmd \"%s(%d)\"",
           minfo[0].rule, key, seq_num, size, cmd_name, cmd);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvshm_check_shmdt(kauth_cred_t cred,
                             struct shmid_kernel *shmsegptr,
                             struct label *shmseglabel)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-shm";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  user_size_t size = 0;
  if (shmsegptr) {
    key = shmsegptr->u.shm_perm._key;
    seq_num = shmsegptr->u.shm_perm._seq;
    size = shmsegptr->u.shm_segsz;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvshm_check_shmdt(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' and size \'%lld\'",
           minfo[0].rule, key, seq_num, size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_sysvshm_check_shmget(kauth_cred_t cred,
                              struct shmid_kernel *shmsegptr,
                              struct label *shmseglabel,
                              int shmflg)
{
  match_info minfo[2];
  minfo[0].rule = "ipc-sysv-shm";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  key_t key = -1;
  unsigned short seq_num = 0;
  user_size_t size = 0;
  if (shmsegptr) {
    key = shmsegptr->u.shm_perm._key;
    seq_num = shmsegptr->u.shm_perm._seq;
    size = shmsegptr->u.shm_segsz;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "sysvshm_check_shmget(): Query rule \"%s\" with key \'0x%x\' sequence number \'0x%x\' size \'%lld\' and shmflg \'0%o\'",
           minfo[0].rule, key, seq_num, size, shmflg);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Called only on macOS 10.12 (and up).
int hook_mount_check_snapshot_create(kauth_cred_t cred,
                                     struct mount *mp,
                                     const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "fs-snapshot-create";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  struct vnode *mount_point = NULL;
  mount_fake_t mp_info = (mount_fake_t) mp;
  if (mp_info) {
    mount_point = mp_info->mnt_vnodecovered;
  }

  char *mp_path;
  vm_size_t mp_path_size;
  if (!get_vnode_path(mount_point, &mp_path, &mp_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_snapshot_create(): Query rule \"%s\" for object \"%s\" at mount point \"%s\"",
           minfo[0].rule, name ? name : "null", mp_path);
  IOFree(mp_path, mp_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Called only on macOS 10.12 (and up).
int hook_mount_check_snapshot_delete(kauth_cred_t cred,
                                     struct mount *mp,
                                     const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "fs-snapshot-delete";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  struct vnode *mount_point = NULL;
  mount_fake_t mp_info = (mount_fake_t) mp;
  if (mp_info) {
    mount_point = mp_info->mnt_vnodecovered;
  }

  char *mp_path;
  vm_size_t mp_path_size;
  if (!get_vnode_path(mount_point, &mp_path, &mp_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "mount_check_snapshot_delete(): Query rule \"%s\" for object \"%s\" at mount point \"%s\"",
           minfo[0].rule, name ? name : "null", mp_path);
  IOFree(mp_path, mp_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Called only on macOS 10.12 (and up).
int hook_vnode_check_clone(kauth_cred_t cred,
                           struct vnode *dvp,
                           struct label *dlabel,
                           struct vnode *vp,
                           struct label *label,
                           struct componentname *cnp)
{
  match_info minfo[4];
  minfo[0].rule = "file-read-data";
  minfo[1].rule = "file-write-create";
  minfo[2].rule = "file-read-metadata";
  minfo[3].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *dest;
  vm_size_t dest_size;
  if (!get_vnode_path(dvp, &dest, &dest_size)) {
    return 0;
  }

  char *source;
  vm_size_t source_size;
  if (!get_vnode_path(vp, &source, &source_size)) {
    IOFree(dest, dest_size);
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  if (minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_clone(): Query rule \"%s\" for source vnode \"%s\"",
             minfo[0].rule, source);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_clone(): Query rule \"%s\" for name \"%s\" in directory vnode \"%s\"",
             minfo[1].rule, name, dest);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[2].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_clone(): Query rule \"%s\" for source vnode \"%s\" and directory vnode \"%s\"",
             minfo[2].rule, source, dest);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  IOFree(dest, dest_size);
  IOFree(source, source_size);

  return 0;
}

// Called only on macOS 10.12 (and up).
int hook_proc_check_get_cs_info(kauth_cred_t cred,
                                struct proc *target,
                                unsigned int op)
{
  match_info minfo[2];
  minfo[0].rule = "process-info-codesignature";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_get_cs_info(): Query rule \"%s\" for target pid \'%d\' with op \'0x%x\'",
           minfo[0].rule, target ? proc_pid(target) : -1, op);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Called only on macOS 10.12 (and up).
int hook_proc_check_set_cs_info(kauth_cred_t cred,
                                struct proc *target,
                                unsigned int op)
{
  match_info minfo[2];
  minfo[0].rule = "process-codesigning-status-set";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_set_cs_info(): Query rule \"%s\" for target pid \'%d\' with op \'0x%x\'",
           minfo[0].rule, target ? proc_pid(target) : -1, op);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_iokit_check_hid_control(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "hid-control";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_hid_control(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_access(kauth_cred_t cred,
                            struct vnode *vp,
                            struct label *label,
                            int acc_mode)
{
  match_info minfo[4];
  minfo[0].rule = "file-read-data";
  minfo[1].rule = "file-write-data";
  if (OSX_Mavericks()) {
    minfo[2].rule = "process-exec";
  } else {
    minfo[2].rule = "process-exec*";
  }
  minfo[3].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  if ((acc_mode & 0400) && minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_access(): Query rule \"%s\" for vnode \"%s\" with mode \'0%o\'",
             minfo[0].rule, vnode_path, acc_mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if ((acc_mode & 0200) && minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_access(): Query rule \"%s\" for vnode \"%s\" with mode \'0%o\'",
             minfo[1].rule, vnode_path, acc_mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[2].matched && vnode_isdir(vp) && (acc_mode & 0100)) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_access(): Query rule \"%s\" for vnode \"%s\" with mode \'0%o\'",
             minfo[2].rule, vnode_path, acc_mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  IOFree(vnode_path, vnode_path_size);

  return 0;
}

int hook_vnode_check_chroot(kauth_cred_t cred,
                            struct vnode *dvp,
                            struct label *dlabel,
                            struct componentname *cnp)
{
  match_info minfo[2];
  minfo[0].rule = "file-chroot";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_chroot(): Query rule \"%s\" for object \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_create(kauth_cred_t cred,
                            struct vnode *dvp,
                            struct label *dlabel,
                            struct componentname *cnp,
                            struct vnode_attr *vap)
{
  match_info minfo[3];
  minfo[0].rule = "file-mknod";
  minfo[1].rule = "file-write-create";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  enum vtype type = (enum vtype) 0;
  if (vap) {
    type = vap->va_type;
  }
  const char *type_name;
  switch (type) {
    case 0: type_name = "VNON"; break;
    case 1: type_name = "VREG"; break;
    case 2: type_name = "VDIR"; break;
    case 3: type_name = "VBLK"; break;
    case 4: type_name = "VCHR"; break;
    case 5: type_name = "VLNK"; break;
    case 6: type_name = "VSOCK"; break;
    case 7: type_name = "VFIFO"; break;
    case 8: type_name = "VBAD"; break;
    case 9: type_name = "VSTR"; break;
    case 10: type_name = "VCPLX"; break;
    default: type_name = "unknown"; break;
  }

  if ((type == VBLK) || (type == VCHR) || (type == VBAD)) {
    if (minfo[0].matched) {
      sm_report_t report;
      snprintf(report, sizeof(report), "vnode_check_create(): Query rule \"%s\" for object \"%s\" of type \"%s(%d)\"",
               minfo[0].rule, name, type_name, type);
      do_report(do_stacktrace, log_file, proc_path, report);
    }
  }
  if ((type == VREG) || (type == VDIR) || (type == VLNK) ||
      (type == VSOCK) || (type == VFIFO))
  {
    if (minfo[1].matched) {
      sm_report_t report;
      snprintf(report, sizeof(report), "vnode_check_create(): Query rule \"%s\" for object \"%s\" of type \"%s(%d)\"",
               minfo[1].rule, name, type_name, type);
      do_report(do_stacktrace, log_file, proc_path, report);
    }
  }

  return 0;
}

int hook_vnode_check_deleteextattr(kauth_cred_t cred,
                                   struct vnode *vp,
                                   struct label *vlabel,
                                   const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-xattr";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_deleteextattr(): Query rule \"%s\" for vnode \"%s\" with name \"%s\"",
           minfo[0].rule, vnode_path, name ? name : "null");
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_exchangedata(kauth_cred_t cred,
                                  struct vnode *v1,
                                  struct label *vl1,
                                  struct vnode *v2,
                                  struct label *vl2)
{
  match_info minfo[3];
  minfo[0].rule = "file-read*";
  minfo[1].rule = "file-write*";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode1_path;
  vm_size_t vnode1_path_size;
  if (!get_vnode_path(v1, &vnode1_path, &vnode1_path_size)) {
    return 0;
  }
  char *vnode2_path;
  vm_size_t vnode2_path_size;
  if (!get_vnode_path(v2, &vnode2_path, &vnode2_path_size)) {
    return 0;
  }

  sm_report_t report;
  if (minfo[0].matched) {
    snprintf(report, sizeof(report), "vnode_check_exchangedata(): Query rule \"%s\" for vnode1 \"%s\" and vnode2 \"%s\"",
             minfo[0].rule, vnode1_path, vnode2_path);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[1].matched) {
    snprintf(report, sizeof(report), "vnode_check_exchangedata(): Query rule \"%s\" for vnode1 \"%s\" and vnode2 \"%s\"",
             minfo[1].rule, vnode1_path, vnode2_path);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  IOFree(vnode1_path, vnode1_path_size);
  IOFree(vnode2_path, vnode2_path_size);

  return 0;
}

static void do_vnode_check_exec(struct componentname *cnp)
{
  match_info minfo[2];
  if (OSX_Mavericks()) {
    minfo[0].rule = "process-exec";
  } else {
    minfo[0].rule = "process-exec*";
  }
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_exec(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);
}

// Exists in this form on OS X 10.9.
int hook_vnode_check_exec_v1(kauth_cred_t cred,
                             struct vnode *vp,
                             struct label *label,
                             struct label *execlabel, /* NULLOK */
                             struct componentname *cnp,
                             u_int *csflags,
                             void *macpolicyattr,
                             size_t macpolicyattrlen)
{
  do_vnode_check_exec(cnp);
  return 0;
}

// Exists in this form on OS X 10.10, 10.11 and 10.12
int hook_vnode_check_exec_v2(kauth_cred_t cred,
                             struct vnode *vp,
                             struct vnode *scriptvp,
                             struct label *vnodelabel,
                             struct label *scriptlabel,
                             struct label *execlabel, /* NULLOK */
                             struct componentname *cnp,
                             u_int *csflags,
                             void *macpolicyattr,
                             size_t macpolicyattrlen)
{
  do_vnode_check_exec(cnp);
  return 0;
}

int hook_vnode_check_getattrlist(kauth_cred_t cred,
                                 struct vnode *vp,
                                 struct label *vlabel,
                                 struct attrlist *alist)
{
  match_info minfo[2];
  minfo[0].rule = "file-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_getattrlist(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_getextattr(kauth_cred_t cred,
                                struct vnode *vp,
                                struct label *label, /* NULLOK */
                                const char *name,
                                struct uio *uio)     /* NULLOK */
{
  match_info minfo[2];
  minfo[0].rule = "file-read-xattr";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_getextattr(): Query rule \"%s\" for vnode \"%s\" with name \"%s\"",
           minfo[0].rule, vnode_path, name ? name : "null");
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_ioctl(kauth_cred_t cred,
                           struct vnode *vp,
                           struct label *label,
                           unsigned int cmd)
{
  match_info minfo[2];
  minfo[0].rule = "file-ioctl";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;

  if ((cmd != 0x4004667a) &&
      (cmd != 0x4004667f) &&
      (cmd != 0x40087468) &&
      (cmd != 0x402c7413) &&
      (cmd != 0x40487413) &&
      (cmd != 0x8004667d) &&
      (cmd != 0x8004667e))
  {
    if (!check_should_report(minfo, false, &do_stacktrace,
                             log_file, proc_path))
    {
      return 0;
    }
  } else {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_ioctl(): Query rule \"%s\" for vnode \"%s\" with cmd \'0x%x\'",
           minfo[0].rule, vnode_path, cmd);
  do_report(do_stacktrace, log_file, proc_path, report);

  IOFree(vnode_path, vnode_path_size);

  return 0;
}

int hook_vnode_check_link(kauth_cred_t cred,
                          struct vnode *dvp,
                          struct label *dlabel,
                          struct vnode *vp,
                          struct label *label,
                          struct componentname *cnp)
{
  match_info minfo[3];
  minfo[0].rule = "file-write-create";
  if (OSX_ElCapitan() || macOS_Sierra()) {
    minfo[1].rule = "file-link";
    minfo[2].rule = NULL;
  } else {
    minfo[1].rule = NULL;
  }
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char link[MAXPATHLEN];
  size_t linklen = sizeof(link);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (linklen > cnp->cn_pnlen) {
      linklen = cnp->cn_pnlen + 1;
    }
    strncpy(link, cnp->cn_pnbuf, linklen);
  } else {
    strncpy(link, "null", linklen);
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  if (minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_link(): Query rule \"%s\" for link \"%s\" to vnode \"%s\"",
             minfo[0].rule, link, vnode_path);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if (minfo[1].rule && minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_link(): Query rule \"%s\" for link \"%s\" to vnode \"%s\"",
             minfo[1].rule, link, vnode_path);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  IOFree(vnode_path, vnode_path_size);

  return 0;
}

int hook_vnode_check_listextattr(kauth_cred_t cred,
                                 struct vnode *vp,
                                 struct label *vlabel)
{
  match_info minfo[2];
  minfo[0].rule = "file-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_listextattr(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_open(kauth_cred_t cred,
                          struct vnode *vp,
                          struct label *label,
                          int acc_mode)
{
  match_info minfo[3];
  minfo[0].rule = "file-read-data";
  minfo[1].rule = "file-write-data";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  if ((acc_mode & FREAD) && minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_open(): Query rule \"%s\" for vnode \"%s\" with mode \'0x%x\'",
             minfo[0].rule, vnode_path, acc_mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if ((acc_mode & (O_RDWR | O_TRUNC)) && minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_open(): Query rule \"%s\" for vnode \"%s\" with mode \'0x%x\'",
             minfo[1].rule, vnode_path, acc_mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  IOFree(vnode_path, vnode_path_size);

  return 0;
}

int hook_vnode_check_readlink(kauth_cred_t cred,
                              struct vnode *vp,
                              struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "file-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_readlink(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.9.
int hook_vnode_check_rename_from(kauth_cred_t cred,
                                 struct vnode *dvp,
                                 struct label *dlabel,
                                 struct vnode *vp,
                                 struct label *label,
                                 struct componentname *cnp)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-unlink";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_rename_from(): Query rule \"%s\" for old name \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on OS X 10.9.
int hook_vnode_check_rename_to(kauth_cred_t cred,
                               struct vnode *dvp,
                               struct label *dlabel,
                               struct vnode *vp,    /* NULLOK */
                               struct label *label, /* NULLOK */
                               int samedir,
                               struct componentname *cnp)
{
  match_info minfo[3];
  minfo[0].rule = "file-write-unlink";
  minfo[1].rule = "file-write-create";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (minfo[0].matched && get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_rename_to(): Query rule \"%s\" for old vnode \"%s\"",
             minfo[0].rule, vnode_path);
    do_report(do_stacktrace, log_file, proc_path, report);
    IOFree(vnode_path, vnode_path_size);
  }

  if (minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_rename_to(): Query rule \"%s\" for new name \"%s\"",
             minfo[1].rule, name);
    do_report(do_stacktrace, log_file, proc_path, report);
  }

  return 0;
}

int hook_vnode_check_revoke(kauth_cred_t cred,
                            struct vnode *vp,
                            struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "file-revoke";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_revoke(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_setattrlist(kauth_cred_t cred,
                                 struct vnode *vp,
                                 struct label *vlabel,
                                 struct attrlist *alist)
{
  match_info minfo[2];
  minfo[0].rule = "file-write*";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setattrlist(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_setextattr(kauth_cred_t cred,
                                struct vnode *vp,
                                struct label *label,
                                const char *name,
                                struct uio *uio)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-xattr";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setextattr(): Query rule \"%s\" for vnode \"%s\" with name \"%s\"",
           minfo[0].rule, vnode_path, name ? name : "null");
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_setflags(kauth_cred_t cred,
                              struct vnode *vp,
                              struct label *label,
                              u_long flags)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-flags";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setflags(): Query rule \"%s\" for vnode \"%s\" with flags \'0x%lx\'",
           minfo[0].rule, vnode_path, flags);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_setmode(kauth_cred_t cred,
                             struct vnode *vp,
                             struct label *label,
                             mode_t mode)
{
  match_info minfo[3];
  minfo[0].rule = "file-write-mode";
  minfo[1].rule = "file-write-setugid";
  minfo[2].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  if (minfo[0].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_setmode(): Query rule \"%s\" for vnode \"%s\" with mode \'0%o\'",
             minfo[0].rule, vnode_path, mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  if ((mode & 06000) && minfo[1].matched) {
    sm_report_t report;
    snprintf(report, sizeof(report), "vnode_check_setmode(): Query rule \"%s\" for vnode \"%s\" with mode \'0%o\'",
             minfo[1].rule, vnode_path, mode);
    do_report(do_stacktrace, log_file, proc_path, report);
  }
  IOFree(vnode_path, vnode_path_size);

  return 0;
}

int hook_vnode_check_setowner(kauth_cred_t cred,
                              struct vnode *vp,
                              struct label *label,
                              uid_t uid,
                              gid_t gid)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-owner";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setowner(): Query rule \"%s\" for vnode \"%s\" with uid \'%d\' and gid \'%d\'",
           minfo[0].rule, vnode_path, uid, gid);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_setutimes(kauth_cred_t cred,
                               struct vnode *vp,
                               struct label *label,
                               struct timespec atime,
                               struct timespec mtime)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-times";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setutimes(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_stat(struct ucred *active_cred,
                          struct ucred *file_cred, /* NULLOK */
                          struct vnode *vp,
                          struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "file-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_stat(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_truncate(kauth_cred_t active_cred,
                              kauth_cred_t file_cred, /* NULLOK */
                              struct vnode *vp,
                              struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-data";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_truncate(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_unlink(kauth_cred_t cred,
                            struct vnode *dvp,
                            struct label *dlabel,
                            struct vnode *vp,
                            struct label *label,
                            struct componentname *cnp)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-unlink";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_unlink(): Query rule \"%s\" for object \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_uipc_bind(kauth_cred_t cred,
                               struct vnode *dvp,
                               struct label *dlabel,
                               struct componentname *cnp,
                               struct vnode_attr *vap)
{
  match_info minfo[2];
  minfo[0].rule = "network-bind";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char name[MAXPATHLEN];
  size_t namelen = sizeof(name);
  if (cnp && cnp->cn_pnbuf && cnp->cn_pnlen) {
    if (namelen > cnp->cn_pnlen) {
      namelen = cnp->cn_pnlen + 1;
    }
    strncpy(name, cnp->cn_pnbuf, namelen);
  } else {
    strncpy(name, "null", namelen);
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_uipc_bind(): Query rule \"%s\" for socket \"%s\"",
           minfo[0].rule, name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

static void do_vnode_check_uipc_connect(struct vnode *vp)
{
  match_info minfo[2];
  minfo[0].rule = "network-outbound";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_uipc_connect(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);
}

// Exists in this form on OS X 10.11 and below.
int hook_vnode_check_uipc_connect_v1(kauth_cred_t cred,
                                     struct vnode *vp,
                                     struct label *label)
{
  do_vnode_check_uipc_connect(vp);
  return 0;
}

// Exists in this form on OS X 10.12 (and up).
int hook_vnode_check_uipc_connect_v2(kauth_cred_t cred,
                                     struct vnode *vp,
                                     struct label *label,
                                     socket_t so)
{
  do_vnode_check_uipc_connect(vp);
  return 0;
}

// From the xnu kernel's security/mac.h
/*
 * Flags for mac_proc_check_suspend_resume()
 */
#define MAC_PROC_CHECK_SUSPEND          0
#define MAC_PROC_CHECK_RESUME           1
#define MAC_PROC_CHECK_HIBERNATE        2
#define MAC_PROC_CHECK_SHUTDOWN_SOCKETS 3
#define MAC_PROC_CHECK_PIDBIND          4

int hook_proc_check_suspend_resume(kauth_cred_t cred,
                                   struct proc *proc,
                                   int sr)
{
  match_info minfo[2];
  minfo[0].rule = "system-suspend-resume";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *sr_name;
  switch (sr) {
    case MAC_PROC_CHECK_SUSPEND:
      sr_name = "MAC_PROC_CHECK_SUSPEND";
      break;
    case MAC_PROC_CHECK_RESUME:
      sr_name = "MAC_PROC_CHECK_RESUME";
      break;
    case MAC_PROC_CHECK_HIBERNATE:
      sr_name = "MAC_PROC_CHECK_HIBERNATE";
      break;
    case MAC_PROC_CHECK_SHUTDOWN_SOCKETS:
      sr_name = "MAC_PROC_CHECK_SHUTDOWN_SOCKETS";
      break;
    case MAC_PROC_CHECK_PIDBIND:
      sr_name = "MAC_PROC_CHECK_PIDBIND";
      break;
    default:
      sr_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_suspend_resume(): Query rule \"%s\" for process pid \'%d\' with flag \"%s(%d)\"",
           minfo[0].rule, proc ? proc_pid(proc) : -1, sr_name, sr);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Called from io_registry_entry_set_properties() in the xnu kernel's
// iokit/kernel/IOUserClient.cpp, where 'entry' is an IORegistryEntry
// object.
int hook_iokit_check_set_properties(kauth_cred_t cred,
                                    io_object_t entry,
                                    io_object_t properties)
{
  match_info minfo[2];
  minfo[0].rule = "iokit-set-properties";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *entry_name = NULL;
  if (entry) {
    IORegistryEntry *rentry = OSDynamicCast(IORegistryEntry, entry);
    if (rentry) {
      entry_name = rentry->getName();
    }
  }
  if (!entry_name) {
    entry_name = "null";
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_set_properties(): Query rule \"%s\" for object \"%s\"",
           minfo[0].rule, entry_name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_chud(kauth_cred_t cred)
{
  match_info minfo[2];
  minfo[0].rule = "system-chud";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_chud(): Query rule \"%s\"",
           minfo[0].rule);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_searchfs(kauth_cred_t cred,
                              struct vnode *vp,
                              struct label *vlabel,
                              struct attrlist *alist)
{
  match_info minfo[2];
  minfo[0].rule = "file-search";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_searchfs(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// From the xnu kernel's bsd/sys/dtrace_glue.h

#define PRIV_DTRACE_KERNEL        3
#define PRIV_DTRACE_PROC          4
#define PRIV_DTRACE_USER          5
#define PRIV_PROC_OWNER          30
#define PRIV_PROC_ZONE           35
#define PRIV_ALL               (-1)     /* All privileges required */
/* Privilege sets */
#define PRIV_EFFECTIVE            0

// From the xnu kernel's bsd/sys/priv.h

#define PRIV_ADJTIME               1000    /* Set time adjustment. */
#define PRIV_PROC_UUID_POLICY      1001    /* Change process uuid policy table. */
#define PRIV_GLOBAL_PROC_INFO      1002    /* Query information for processes owned by other users */
#define PRIV_SYSTEM_OVERRIDE       1003    /* Override global system settings for various subsystems for a limited duration/system-mode */
#define PRIV_HW_DEBUG_DATA         1004    /* Extract hw-specific debug data (e.g. ECC data) */
#define PRIV_SELECTIVE_FORCED_IDLE 1005    /* Configure and control Selective Forced Idle (SFI) subsystem */
#define PRIV_PROC_TRACE_INSPECT    1006    /* Request trace memory of arbitrary process to be inspected */
#define PRIV_DARKBOOT              1007    /* Manipulate the darkboot flag */
#define PRIV_WORK_INTERVAL         1008    /* Express details about a work interval */
/*
 * Virtual memory privileges.
 */
#define PRIV_VM_PRESSURE        6000    /* Check VM pressure. */
#define PRIV_VM_JETSAM          6001    /* Adjust jetsam configuration. */
#define PRIV_VM_FOOTPRINT_LIMIT 6002    /* Adjust physical footprint limit. */
/*
 * Network stack privileges.
 */
#define PRIV_NET_PRIVILEGED_TRAFFIC_CLASS       10000   /* Set SO_PRIVILEGED_TRAFFIC_CLASS. */ 
#define PRIV_NET_PRIVILEGED_SOCKET_DELEGATE     10001   /* Set delegate on a socket */
#define PRIV_NET_INTERFACE_CONTROL              10002   /* Enable interface debug logging. */
#define PRIV_NET_PRIVILEGED_NETWORK_STATISTICS  10003   /* Access to all sockets */
#define PRIV_NET_PRIVILEGED_NECP_POLICIES       10004   /* Access to privileged Network Extension policies */
#define PRIV_NET_RESTRICTED_AWDL                10005   /* Access to restricted AWDL mode */
#define PRIV_NET_PRIVILEGED_NECP_MATCH          10006   /* Privilege verified by Network Extension policies */
/*
 * IPv4 and IPv6 privileges.
 */
#define PRIV_NETINET_RESERVEDPORT  11000    /* Bind low port number. */
/*
 * VFS privileges
 */
#define PRIV_VFS_OPEN_BY_ID        14000    /*Allow calling openbyid_np()*/

int hook_priv_check(kauth_cred_t cred,
                    int priv)
{
  match_info minfo[2];
  if (OSX_Mavericks()) {
    minfo[0].rule = "priv*";
  } else {
    minfo[0].rule = "system-privilege";
  }
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *priv_name;
  switch (priv) {
    case 0:
      priv_name = "PRIV_EFFECTIVE";
      break;
    case -1:
      priv_name = "PRIV_ALL";
      break;
    case 3:
      priv_name = "PRIV_DTRACE_KERNEL";
      break;
    case 4:
      priv_name = "PRIV_DTRACE_PROC";
      break;
    case 5:
      priv_name = "PRIV_DTRACE_USER";
      break;
    case 30:
      priv_name = "PRIV_PROC_OWNER";
      break;
    case 35:
      priv_name = "PRIV_PROC_ZONE";
      break;
    case 1000:
      priv_name = "PRIV_ADJTIME";
      break;
    case 1001:
      priv_name = "PRIV_PROC_UUID_POLICY";
      break;
    case 1002:
      priv_name = "PRIV_GLOBAL_PROC_INFO";
      break;
    case 1003:
      priv_name = "PRIV_SYSTEM_OVERRIDE";
      break;
    case 1004:
      priv_name = "PRIV_HW_DEBUG_DATA";
      break;
    case 1005:
      priv_name = "PRIV_SELECTIVE_FORCED_IDLE";
      break;
    case 1006:
      priv_name = "PRIV_PROC_TRACE_INSPECT";
      break;
    case 1007:
      priv_name = "PRIV_DARKBOOT";
      break;
    case 1008:
      priv_name = "PRIV_WORK_INTERVAL";
      break;
    case 6000:
      priv_name = "PRIV_VM_PRESSURE";
      break;
    case 6001:
      priv_name = "PRIV_VM_JETSAM";
      break;
    case 6002:
      priv_name = "PRIV_VM_FOOTPRINT_LIMIT";
      break;
    case 10000:
      priv_name = "PRIV_NET_PRIVILEGED_TRAFFIC_CLASS";
      break;
    case 10001:
      priv_name = "PRIV_NET_PRIVILEGED_SOCKET_DELEGATE";
      break;
    case 10002:
      priv_name = "PRIV_NET_INTERFACE_CONTROL";
      break;
    case 10003:
      priv_name = "PRIV_NET_PRIVILEGED_NETWORK_STATISTICS";
      break;
    case 10004:
      priv_name = "PRIV_NET_PRIVILEGED_NECP_POLICIES";
      break;
    case 10005:
      priv_name = "PRIV_NET_RESTRICTED_AWDL";
      break;
    case 10006:
      priv_name = "PRIV_NET_PRIVILEGED_NECP_MATCH";
      break;
    case 11000:
      priv_name = "PRIV_NETINET_RESERVEDPORT";
      break;
    case 14000:
      priv_name = "PRIV_VFS_OPEN_BY_ID";
      break;
    default:
      priv_name = "unknown";
      break;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "priv_check(): Query rule \"%s\" for priv \"%s(%d)\"",
           minfo[0].rule, priv_name, priv);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_vnode_check_fsgetpath(kauth_cred_t cred,
                               struct vnode *vp,
                               struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "file-read-metadata";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_fsgetpath(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  IOFree(vnode_path, vnode_path_size);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// From IOGraphics' IOGraphicsFamily/IOKit/graphics/IOGraphicsTypes.h
enum {
    // connection types for IOServiceOpen
    kIOFBServerConnectType              = 0,
    kIOFBSharedConnectType              = 1
};

// Called from is_io_service_open_extended() in xnu kernel's
// IOKit/kernel/IOUserClient.cpp.  That code appears to guarantee that
// user_client is a pointer to a IOUserClient object, which inherits
// (indirectly) from IORegistryEntry.
int hook_iokit_check_open(kauth_cred_t cred,
                          io_object_t user_client,
                          unsigned int user_client_type)
{
  match_info minfo[2];
  minfo[0].rule = "iokit-open";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *client_type_name;
  switch (user_client_type) {
    case kIOFBServerConnectType:
      client_type_name = "kIOFBServerConnectType";
      break;
    case kIOFBSharedConnectType:
      client_type_name = "kIOFBSharedConnectType";
      break;
    default:
      client_type_name = "unknown";
      break;
  }

  const char *client_name = NULL;
  if (user_client) {
    IORegistryEntry *entry = OSDynamicCast(IORegistryEntry, user_client);
    if (entry) {
      client_name = entry->getName();
    }
  }
  if (!client_name) {
    client_name = "null";
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_open(): Query rule \"%s\" for object \"%s\" of type \"%s(%d)\"",
           minfo[0].rule, client_name, client_type_name, user_client_type);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only called on macOS 10.12 (and up).
int hook_vnode_check_setacl(kauth_cred_t cred,
                            struct vnode *vp,
                            struct label *label,
                            struct kauth_acl *acl)
{
  match_info minfo[2];
  minfo[0].rule = "file-write-acl";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  char *vnode_path;
  vm_size_t vnode_path_size;
  if (!get_vnode_path(vp, &vnode_path, &vnode_path_size)) {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "vnode_check_setacl(): Query rule \"%s\" for vnode \"%s\"",
           minfo[0].rule, vnode_path);
  do_report(do_stacktrace, log_file, proc_path, report);

  IOFree(vnode_path, vnode_path_size);

  return 0;
}

// See xnu kernel's bsd/sys/kas_info.h for more information.
// Returns "forbidden-kas-info" for all sandboxed processes on OS X 10.10 and
// below.  The rule name "system-kas-info" may not be correct -- I can't find
// instances in any *.sb file.
int hook_system_check_kas_info(kauth_cred_t cred,
                               int selector)
{
  match_info minfo[2];
  minfo[0].rule = "system-kas-info";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "check_kas_info(): Query rule \"%s\" for selector \'0x%x\'",
           minfo[0].rule, selector);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_system_check_info(kauth_cred_t cred,
                           const char *info_type)
{
  match_info minfo[2];
  minfo[0].rule = "system-info";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  if (!info_type) {
    info_type = "null";
  }
  sm_report_t report;
  snprintf(report, sizeof(report), "system_check_info(): Query rule \"%s\" for info type \"%s\"",
           minfo[0].rule, info_type);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

void hook_pty_notify_grant(proc_t p,
                           struct tty *tp,
                           dev_t dev,
                           struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "pseudo-tty";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "pty_notify_grant(): Query rule \"%s\" for device \'0x%x\' in process \'%d\'",
           minfo[0].rule, dev, p ? proc_pid(p) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);
}

void hook_pty_notify_close(proc_t p,
                           struct tty *tp,
                           dev_t dev,
                           struct label *label)
{
  match_info minfo[2];
  minfo[0].rule = "pseudo-tty";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "pty_notify_close(): Query rule \"%s\" for device \'0x%x\' in process \'%d\'",
           minfo[0].rule, dev, p ? proc_pid(p) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);
}

int hook_kext_check_load(kauth_cred_t cred,
                         const char *identifier)
{
  match_info minfo[2];
  minfo[0].rule = "system-kext-load";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  if (!identifier) {
    identifier = "null";
  }
  sm_report_t report;
  snprintf(report, sizeof(report), "kext_check_load(): Query rule \"%s\" for identifier \"%s\"",
           minfo[0].rule, identifier);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

int hook_kext_check_unload(kauth_cred_t cred,
                           const char *identifier)
{
  match_info minfo[2];
  minfo[0].rule = "system-kext-unload";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  if (!identifier) {
    identifier = "null";
  }
  sm_report_t report;
  snprintf(report, sizeof(report), "kext_check_unload(): Query rule \"%s\" for identifier \"%s\"",
           minfo[0].rule, identifier);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// From xnu kernel's bsd/sys/proc_info.h
// __proc_info() call numbers
#define PROC_INFO_CALL_LISTPIDS         0x1
#define PROC_INFO_CALL_PIDINFO          0x2
#define PROC_INFO_CALL_PIDFDINFO        0x3
#define PROC_INFO_CALL_KERNMSGBUF       0x4
#define PROC_INFO_CALL_SETCONTROL       0x5
#define PROC_INFO_CALL_PIDFILEPORTINFO  0x6
#define PROC_INFO_CALL_TERMINATE        0x7
#define PROC_INFO_CALL_DIRTYCONTROL     0x8
#define PROC_INFO_CALL_PIDRUSAGE        0x9
#define PROC_INFO_CALL_PIDORIGINATORINFO 0xa
#define PROC_INFO_CALL_LISTCOALITIONS   0xb
#define PROC_INFO_CALL_CANUSEFGHW       0xc

// This can be called with target == NULL, from proc_listpids() in
// the xnu kernel's bsd/kern/proc_info.c.
int hook_proc_check_proc_info(kauth_cred_t cred,
                              struct proc *target,
                              int callnum,
                              int flavor)
{
  match_info minfo[2];
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;

  switch (callnum) {
    case PROC_INFO_CALL_LISTPIDS:
    case PROC_INFO_CALL_KERNMSGBUF:
    case PROC_INFO_CALL_TERMINATE:
      minfo[0].rule = "process-info-listpids";
      break;
    case PROC_INFO_CALL_PIDINFO:
      minfo[0].rule = "process-info-pidinfo";
      break;
    case PROC_INFO_CALL_PIDFDINFO:
      minfo[0].rule = "process-info-pidfdinfo";
      break;
    case PROC_INFO_CALL_SETCONTROL:
      minfo[0].rule = "process-info-setcontrol";
      break;
    case PROC_INFO_CALL_PIDFILEPORTINFO:
      minfo[0].rule = "process-info-pidfilereportinfo";
      break;
    case PROC_INFO_CALL_DIRTYCONTROL:
      minfo[0].rule = "process-info-dirtycontrol";
      break;
    case PROC_INFO_CALL_PIDRUSAGE:
      minfo[0].rule = "process-info-rusage";
      break;
    default:
      return 0;
  }

  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "proc_check_proc_info(): Query rule \"%s\" for target pid \'%d\'",
           minfo[0].rule, target ? proc_pid(target) : -1);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on 10.10 and up
int hook_iokit_check_filter_properties(kauth_cred_t cred,
                                       io_object_t entry)
{
  match_info minfo[2];
  minfo[0].rule = "iokit-get-properties";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *entry_name = NULL;
  if (entry) {
    IORegistryEntry *rentry = OSDynamicCast(IORegistryEntry, entry);
    if (rentry) {
      entry_name = rentry->getName();
    }
  }
  if (!entry_name) {
    entry_name = "null";
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_filter_properties(): Query rule \"%s\" for some property on object \"%s\"",
           minfo[0].rule, entry_name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

// Only hooked on 10.10 and up
int hook_iokit_check_get_property(kauth_cred_t cred,
                                  io_object_t entry,
                                  const char *name)
{
  match_info minfo[2];
  minfo[0].rule = "iokit-get-properties";
  minfo[1].rule = NULL;
  bool do_stacktrace = false;
  sm_filename_t log_file;
  sm_path_t proc_path;
  if (!check_should_report(minfo, false, &do_stacktrace,
                           log_file, proc_path))
  {
    return 0;
  }

  const char *entry_name = NULL;
  if (entry) {
    IORegistryEntry *rentry = OSDynamicCast(IORegistryEntry, entry);
    if (rentry) {
      entry_name = rentry->getName();
    }
  }
  if (!entry_name) {
    entry_name = "null";
  }

  sm_report_t report;
  snprintf(report, sizeof(report), "iokit_check_get_property(): Query rule \"%s\" for property \"%s\" on object \"%s\"",
           minfo[0].rule, name ? name : "null", entry_name);
  do_report(do_stacktrace, log_file, proc_path, report);

  return 0;
}

#define SET_HOOK(x) .mpo_##x = hook_##x,

struct mac_policy_ops sPolicyOps = {

  //SET_HOOK(file_check_fcntl) // Sandbox returns 0 without doing any checks
  //SET_HOOK(file_check_set) // Needed only for allocating labels, which we don't do.
  SET_HOOK(mount_check_fsctl)
  SET_HOOK(mount_check_mount)
  SET_HOOK(mount_check_remount)
  SET_HOOK(mount_check_umount)

  /* special hooks for policy inits */
  SET_HOOK(policy_init)
  //SET_HOOK(policy_syscall)

  SET_HOOK(posixsem_check_create)
  SET_HOOK(posixsem_check_open)
  SET_HOOK(posixsem_check_post)
  SET_HOOK(posixsem_check_unlink)
  SET_HOOK(posixsem_check_wait)

  SET_HOOK(posixshm_check_create)
  SET_HOOK(posixshm_check_open)
  SET_HOOK(posixshm_check_stat)
  SET_HOOK(posixshm_check_truncate)
  SET_HOOK(posixshm_check_unlink)

  SET_HOOK(proc_check_debug)
  SET_HOOK(proc_check_fork)
  SET_HOOK(proc_check_get_task_name)
  SET_HOOK(proc_check_get_task)
  SET_HOOK(proc_check_sched)
  SET_HOOK(proc_check_setaudit)
  SET_HOOK(proc_check_setauid)
  SET_HOOK(proc_check_signal)

  SET_HOOK(socket_check_bind)
  SET_HOOK(socket_check_connect)
  SET_HOOK(socket_check_create)
  SET_HOOK(socket_check_listen)
  SET_HOOK(socket_check_receive)
  SET_HOOK(socket_check_send)

  SET_HOOK(system_check_acct)
  SET_HOOK(system_check_audit)
  SET_HOOK(system_check_auditctl)
  SET_HOOK(system_check_auditon)
  SET_HOOK(system_check_host_priv)
  SET_HOOK(system_check_nfsd)
  SET_HOOK(system_check_reboot)
  SET_HOOK(system_check_settime)
  SET_HOOK(system_check_swapoff)
  SET_HOOK(system_check_swapon)

  SET_HOOK(sysvmsq_check_enqueue)
  SET_HOOK(sysvmsq_check_msgrcv)
  SET_HOOK(sysvmsq_check_msgrmid)
  SET_HOOK(sysvmsq_check_msqctl)
  SET_HOOK(sysvmsq_check_msqget)
  SET_HOOK(sysvmsq_check_msqrcv)
  SET_HOOK(sysvmsq_check_msqsnd)

  SET_HOOK(sysvsem_check_semctl)
  SET_HOOK(sysvsem_check_semget)
  SET_HOOK(sysvsem_check_semop)

  SET_HOOK(sysvshm_check_shmat)
  SET_HOOK(sysvshm_check_shmctl)
  SET_HOOK(sysvshm_check_shmdt)
  SET_HOOK(sysvshm_check_shmget)

  SET_HOOK(iokit_check_hid_control)

  SET_HOOK(vnode_check_access)
  SET_HOOK(vnode_check_chroot)
  SET_HOOK(vnode_check_create)
  SET_HOOK(vnode_check_deleteextattr)
  SET_HOOK(vnode_check_exchangedata)
  SET_HOOK(vnode_check_getattrlist)
  SET_HOOK(vnode_check_getextattr)
  SET_HOOK(vnode_check_ioctl)
  SET_HOOK(vnode_check_link)
  SET_HOOK(vnode_check_listextattr)
  SET_HOOK(vnode_check_open)
  SET_HOOK(vnode_check_readlink)
  SET_HOOK(vnode_check_revoke)
  SET_HOOK(vnode_check_setattrlist)
  SET_HOOK(vnode_check_setextattr)
  SET_HOOK(vnode_check_setflags)
  SET_HOOK(vnode_check_setmode)
  SET_HOOK(vnode_check_setowner)
  SET_HOOK(vnode_check_setutimes)
  SET_HOOK(vnode_check_stat)
  SET_HOOK(vnode_check_truncate)
  SET_HOOK(vnode_check_unlink)
  SET_HOOK(vnode_check_uipc_bind)

  SET_HOOK(proc_check_suspend_resume)

  SET_HOOK(iokit_check_set_properties)

  SET_HOOK(system_check_chud)

  SET_HOOK(vnode_check_searchfs)

  SET_HOOK(priv_check)

  SET_HOOK(vnode_check_fsgetpath)

  SET_HOOK(iokit_check_open)

  SET_HOOK(system_check_kas_info)

  SET_HOOK(system_check_info)

  SET_HOOK(pty_notify_grant)
  SET_HOOK(pty_notify_close)

  SET_HOOK(kext_check_load)
  SET_HOOK(kext_check_unload)

  SET_HOOK(proc_check_proc_info)
};

#undef SET_HOOK
#define SET_HOOK(x) sPolicyOps.mpo_##x = hook_##x;
#define SET_HOOK_OVERRIDE(x,y) sPolicyOps.mpo_##y = (mpo_##y##_t *)hook_##x;
#define SET_HOOK_OVERRIDE_RES(x,y) sPolicyOps.mpo_##y = (mpo_reserved_hook_t *)hook_##x;

mac_policy_handle_t sHandle = 0;

const char *sLabelnames[] = {"sm"};

struct mac_policy_conf sPolicyConf = {
  .mpc_name               = "SandboxMirror",
  .mpc_fullname           = "Empty policy, mirrors Sandbox",
  .mpc_field_off          = NULL, // No label slot, no state needed
  .mpc_labelnames         = sLabelnames,
  .mpc_labelname_count    = sizeof(sLabelnames)/sizeof(char*),
  .mpc_ops                = &sPolicyOps,
  .mpc_loadtime_flags     = MPC_LOADTIME_FLAG_UNLOADOK,
  .mpc_runtime_flags      = 0,
};

extern "C" kern_return_t SandboxMirror_start(kmod_info_t *ki, void *d);
extern "C" kern_return_t SandboxMirror_stop(kmod_info_t *ki, void *d);

kern_return_t SandboxMirror_start(kmod_info_t *ki, void *d)
{
  if (OSX_Version_Unsupported()) {
    printf("SandboxMirror requires OS X Mavericks (10.9), Yosemite (10.10), El Capitan (10.11) or macOS Sierra (10.12): current version %s\n",
           gOSVersionString ? gOSVersionString : "null");
    if (gOSVersionString) {
      IOFree(gOSVersionString, gOSVersionStringLength);
    }
    return KERN_NOT_SUPPORTED;
  }

  if (OSX_Mavericks()) {
    SET_HOOK(proc_check_setlcid);
    SET_HOOK_OVERRIDE(vnode_check_exec_v1, vnode_check_exec);
    SET_HOOK_OVERRIDE(vnode_check_uipc_connect_v1, vnode_check_uipc_connect);
#if defined(MAC_OS_X_VERSION_10_9) && MAC_OS_X_VERSION_MAX_ALLOWED == MAC_OS_X_VERSION_10_9
    SET_HOOK(system_check_sysctl);
#else
#if MAC_POLICY_OPS_VERSION <= 45
    SET_HOOK_OVERRIDE_RES(system_check_sysctl, reserved31);
#else
    SET_HOOK_OVERRIDE_RES(system_check_sysctl, reserved7);
#endif
#endif
    SET_HOOK(vnode_check_rename_from);
    SET_HOOK(vnode_check_rename_to);
  } else if (OSX_Yosemite()) {
    SET_HOOK_OVERRIDE(file_check_mmap_v1, file_check_mmap);
    SET_HOOK(proc_check_setlcid);
    SET_HOOK_OVERRIDE(vnode_check_exec_v2, vnode_check_exec);
    SET_HOOK_OVERRIDE(vnode_check_uipc_connect_v1, vnode_check_uipc_connect);
#if defined(MAC_OS_X_VERSION_10_9) && MAC_OS_X_VERSION_MAX_ALLOWED == MAC_OS_X_VERSION_10_9
    SET_HOOK_OVERRIDE(system_check_sysctlbyname, port_check_copy_send);
    SET_HOOK_OVERRIDE(vnode_check_rename, port_check_hold_send_once);
    SET_HOOK_OVERRIDE_RES(iokit_check_filter_properties, reserved28);
    SET_HOOK_OVERRIDE_RES(iokit_check_get_property, reserved29);
#else
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#endif
  } else if (OSX_ElCapitan()) {
    SET_HOOK_OVERRIDE(file_check_mmap_v2, file_check_mmap);
    SET_HOOK_OVERRIDE(vnode_check_exec_v2, vnode_check_exec);
    SET_HOOK_OVERRIDE(vnode_check_uipc_connect_v1, vnode_check_uipc_connect);
#if defined(MAC_OS_X_VERSION_10_9) && MAC_OS_X_VERSION_MAX_ALLOWED == MAC_OS_X_VERSION_10_9
    SET_HOOK_OVERRIDE(system_check_sysctlbyname, port_check_copy_send);
    SET_HOOK_OVERRIDE(vnode_check_rename, port_check_hold_send_once);
    SET_HOOK_OVERRIDE(kext_check_query, port_check_hold_send);
    SET_HOOK_OVERRIDE(iokit_check_nvram_get, port_check_label_update);
    SET_HOOK_OVERRIDE(iokit_check_nvram_set, port_check_make_send_once);
    SET_HOOK_OVERRIDE(iokit_check_nvram_delete, port_check_make_send);
    SET_HOOK_OVERRIDE(proc_check_expose_task, port_check_method);
    SET_HOOK_OVERRIDE(proc_check_set_host_special_port, port_check_move_receive);
    SET_HOOK_OVERRIDE(proc_check_set_host_exception_port, port_check_move_send_once);
    SET_HOOK_OVERRIDE_RES(iokit_check_filter_properties, reserved28);
    SET_HOOK_OVERRIDE_RES(iokit_check_get_property, reserved29);
#elif defined(MAC_OS_X_VERSION_10_10) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) == (MAC_OS_X_VERSION_10_10 / 100)
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK_OVERRIDE_RES(kext_check_query, reserved4);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_get, reserved5);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_set, reserved6);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_delete, reserved7);
    SET_HOOK_OVERRIDE_RES(proc_check_expose_task, reserved8);
    SET_HOOK_OVERRIDE_RES(proc_check_set_host_special_port, reserved9);
    SET_HOOK_OVERRIDE_RES(proc_check_set_host_exception_port, reserved10);
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#else
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK(kext_check_query);
    SET_HOOK(iokit_check_nvram_get);
    SET_HOOK(iokit_check_nvram_set)
    SET_HOOK(iokit_check_nvram_delete)
    SET_HOOK(proc_check_expose_task)
    SET_HOOK(proc_check_set_host_special_port)
    SET_HOOK(proc_check_set_host_exception_port)
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#endif
  } else if (macOS_Sierra()) {
    SET_HOOK_OVERRIDE(file_check_mmap_v2, file_check_mmap);
    SET_HOOK_OVERRIDE(vnode_check_exec_v2, vnode_check_exec);
    SET_HOOK_OVERRIDE(vnode_check_uipc_connect_v2, vnode_check_uipc_connect);
#if defined(MAC_OS_X_VERSION_10_9) && MAC_OS_X_VERSION_MAX_ALLOWED == MAC_OS_X_VERSION_10_9
    SET_HOOK_OVERRIDE(system_check_sysctlbyname, port_check_copy_send);
    SET_HOOK_OVERRIDE(vnode_check_rename, port_check_hold_send_once);
    SET_HOOK_OVERRIDE(kext_check_query, port_check_hold_send);
    SET_HOOK_OVERRIDE(iokit_check_nvram_get, port_check_label_update);
    SET_HOOK_OVERRIDE(iokit_check_nvram_set, port_check_make_send_once);
    SET_HOOK_OVERRIDE(iokit_check_nvram_delete, port_check_make_send);
    SET_HOOK_OVERRIDE(proc_check_expose_task, port_check_method);
    SET_HOOK_OVERRIDE(proc_check_set_host_special_port, port_check_move_receive);
    SET_HOOK_OVERRIDE(proc_check_set_host_exception_port, port_check_move_send_once);
    SET_HOOK_OVERRIDE(mount_check_snapshot_create, task_label_destroy);
    SET_HOOK_OVERRIDE(mount_check_snapshot_delete, task_label_externalize);
    SET_HOOK_OVERRIDE(vnode_check_clone, task_label_init);
    SET_HOOK_OVERRIDE(proc_check_get_cs_info, task_label_internalize);
    SET_HOOK_OVERRIDE(proc_check_set_cs_info, task_label_update);
    SET_HOOK_OVERRIDE(vnode_check_setacl, thread_label_init);
    SET_HOOK_OVERRIDE_RES(iokit_check_filter_properties, reserved28);
    SET_HOOK_OVERRIDE_RES(iokit_check_get_property, reserved29);
#elif defined(MAC_OS_X_VERSION_10_10) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) == (MAC_OS_X_VERSION_10_10 / 100)
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK_OVERRIDE_RES(kext_check_query, reserved4);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_get, reserved5);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_set, reserved6);
    SET_HOOK_OVERRIDE_RES(iokit_check_nvram_delete, reserved7);
    SET_HOOK_OVERRIDE_RES(proc_check_expose_task, reserved8);
    SET_HOOK_OVERRIDE_RES(proc_check_set_host_special_port, reserved9);
    SET_HOOK_OVERRIDE_RES(proc_check_set_host_exception_port, reserved10);
    SET_HOOK_OVERRIDE_RES(mount_check_snapshot_create, reserved26);
    SET_HOOK_OVERRIDE_RES(mount_check_snapshot_delete, reserved27);
    SET_HOOK_OVERRIDE_RES(vnode_check_clone, reserved28);
    SET_HOOK_OVERRIDE_RES(proc_check_get_cs_info, reserved29);
    SET_HOOK_OVERRIDE_RES(proc_check_set_cs_info, reserved30);
    SET_HOOK_OVERRIDE(vnode_check_setacl, thread_label_init);
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#elif defined(MAC_OS_X_VERSION_10_11) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) == (MAC_OS_X_VERSION_10_11 / 100)
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK(kext_check_query);
    SET_HOOK(iokit_check_nvram_get);
    SET_HOOK(iokit_check_nvram_set)
    SET_HOOK(iokit_check_nvram_delete)
    SET_HOOK(proc_check_expose_task)
    SET_HOOK(proc_check_set_host_special_port)
    SET_HOOK(proc_check_set_host_exception_port)
    SET_HOOK_OVERRIDE_RES(mount_check_snapshot_create, reserved26);
    SET_HOOK_OVERRIDE_RES(mount_check_snapshot_delete, reserved27);
    SET_HOOK_OVERRIDE_RES(vnode_check_clone, reserved28);
    SET_HOOK_OVERRIDE_RES(proc_check_get_cs_info, reserved29);
    SET_HOOK_OVERRIDE_RES(proc_check_set_cs_info, reserved30);
    SET_HOOK_OVERRIDE_RES(vnode_check_setacl, reserved32);
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#else
    SET_HOOK(system_check_sysctlbyname);
    SET_HOOK(vnode_check_rename);
    SET_HOOK(kext_check_query);
    SET_HOOK(iokit_check_nvram_get);
    SET_HOOK(iokit_check_nvram_set)
    SET_HOOK(iokit_check_nvram_delete)
    SET_HOOK(proc_check_expose_task)
    SET_HOOK(proc_check_set_host_special_port)
    SET_HOOK(proc_check_set_host_exception_port)
    SET_HOOK(mount_check_snapshot_create);
    SET_HOOK(mount_check_snapshot_delete);
    SET_HOOK(vnode_check_clone);
    SET_HOOK(proc_check_get_cs_info);
    SET_HOOK(proc_check_set_cs_info);
    SET_HOOK(vnode_check_setacl);
    SET_HOOK(iokit_check_filter_properties);
    SET_HOOK(iokit_check_get_property);
#endif
  }

  kern_return_t retval = mac_policy_register(&sPolicyConf, &sHandle, NULL);

  hook_sysent_call(MAC_SYSCALL_SYSENT_OFFSET, (sy_call_t *) hook__mac_syscall,
                   (sy_call_t **) &g_mac_syscall_orig);

  return retval;
}

kern_return_t SandboxMirror_stop(kmod_info_t *ki, void *d)
{
  if (g_mac_syscall_orig) {
    hook_sysent_call(MAC_SYSCALL_SYSENT_OFFSET,
                     (sy_call_t *) g_mac_syscall_orig, NULL);
  }

  if (gOSVersionString) {
    IOFree(gOSVersionString, gOSVersionStringLength);
  }
  return mac_policy_unregister(sHandle);
}
