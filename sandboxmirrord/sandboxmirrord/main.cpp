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

// sandboxmirrord is a daemon, meant to be launched by launchctl and run as
// root, which accepts Mach messages from SandboxMirror.kext and logs their
// contents to the appropriate locations.  By default it logs to the system
// log (/var/log/system.log).  But SandboxMirror.kext can tell it to also log
// to a file in /var/log/sandboxmirrord.  sandboxmirrord uses Apple's Grand
// Central Dispatch, and is modeled on sandboxd, which performs similar
// services for Sandbox.kext.
//
// [1]https://en.wikipedia.org/wiki/Grand_Central_Dispatch
// [2]https://developer.apple.com/library/mac/documentation/Performance/Reference/GCD_libdispatch_Ref/index.html

#include <sys/types.h>
#include <mach/std_types.h>
#include <mach/mach_types.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <libproc.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <asl.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <mach/mach_error.h>
#include <mach/ndr.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/notify.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/port.h>
#include <mach/mig.h>
#include <mach/host_priv.h>
#include <mach-o/ldsyms.h>
#include <servers/bootstrap.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
// Apple has changed how the MAC_OS_X_VERSION_... variables are defined in
// AvailabilityMacros.h on OS X 10.10 and up.  Now minor versions may also be
// defined, and the "base" is 100 times what it was on OS X 10.9 and below.
#if (defined(MAC_OS_X_VERSION_10_11) || defined(MAC_OS_X_VERSION_10_12)) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) >= (MAC_OS_X_VERSION_10_11 / 100)
#include <kern/kern_cdata.h>
#endif
#if defined(MAC_OS_X_VERSION_10_12) && \
    (MAC_OS_X_VERSION_MAX_ALLOWED / 100) == (MAC_OS_X_VERSION_10_12 / 100)
#include <os/log.h>
#endif

#import <CoreFoundation/CoreFoundation.h>

//#define DEBUG 1

/*------------------------------*/

#define MAC_OS_X_VERSION_10_9_HEX  0x00000A90
#define MAC_OS_X_VERSION_10_10_HEX 0x00000AA0
#define MAC_OS_X_VERSION_10_11_HEX 0x00000AB0
#define MAC_OS_X_VERSION_10_12_HEX 0x00000AC0

// The following are undocumented, but have been present in the same form
// since at least OS X 10.5.
extern "C" CFDictionaryRef _CFCopySystemVersionDictionary();
extern "C" CFStringRef _kCFSystemVersionProductVersionKey;

CFStringRef gOSVersionString = NULL;

int32_t OSX_Version()
{
  static int32_t version = -1;
  if (version != -1) {
    return version;
  }

  version = 0;
  CFDictionaryRef version_dict = _CFCopySystemVersionDictionary();
  if (!version_dict) {
    return version;
  }
  gOSVersionString = (CFStringRef)
    CFDictionaryGetValue(version_dict, _kCFSystemVersionProductVersionKey);
  if (!gOSVersionString) {
    return version;
  }
  CFRetain(gOSVersionString);
  CFRelease(version_dict);
  CFArrayRef components =
    CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault,
                                           gOSVersionString, CFSTR("."));
  CFIndex count = CFArrayGetCount(components);
  for (CFIndex i = 0; (i < count) && (i < 3); ++i) {
    CFStringRef part = (CFStringRef) CFArrayGetValueAtIndex(components, i);
    version += (CFStringGetIntValue(part) << ((2 - i) * 4));
  }

  CFRelease(components);
  return version;
}

const char *OSX_Version_String()
{
  static char *version_string_UTF8 = NULL;
  if (version_string_UTF8) {
    return version_string_UTF8;
  }

  if (!gOSVersionString) {
    OSX_Version();
  }
  if (!gOSVersionString) {
    version_string_UTF8 = (char *) "Unknown";
  } else {
    CFIndex length = (CFStringGetLength(gOSVersionString) + 1) * 2;
    version_string_UTF8 = (char *) calloc(length, sizeof(char));
    if (version_string_UTF8) {
      CFStringGetCString(gOSVersionString, version_string_UTF8, length,
                         kCFStringEncodingUTF8);
    } else {
      version_string_UTF8 = (char *) "Unknown";
    }
  }

  return version_string_UTF8;
}

bool OSX_Mavericks()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_9_HEX);
}

bool OSX_Yosemite()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_10_HEX);
}

bool OSX_ElCapitan()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_11_HEX);
}

bool macOS_Sierra()
{
  return ((OSX_Version() & 0xFFF0) == MAC_OS_X_VERSION_10_12_HEX);
}

bool OSX_Version_Unsupported()
{
  return (((OSX_Version() & 0xFFF0) < MAC_OS_X_VERSION_10_9_HEX) ||
          ((OSX_Version() & 0xFFF0) > MAC_OS_X_VERSION_10_12_HEX));
}

void error_log(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  asl_vlog(NULL, NULL, ASL_LEVEL_ERR, format, args);
  va_end(args);
}

#define LOG_ITEM_INITIAL_SIZE 4096
#define LOGGING_DIR "/var/log/sandboxmirrord"

#if !defined(MAC_OS_X_VERSION_10_12) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12

typedef struct os_log_s *os_log_t;

enum {
  OS_LOG_TYPE_DEFAULT = 0x00,
  OS_LOG_TYPE_INFO    = 0x01,
  OS_LOG_TYPE_DEBUG   = 0x02,
  OS_LOG_TYPE_ERROR   = 0x10,
  OS_LOG_TYPE_FAULT   = 0x11
};

typedef uint8_t os_log_type_t;

extern "C" {
os_log_t os_log_create(const char *subsystem, const char *category);
void _os_log_internal(void *dso, os_log_t log, os_log_type_t type, const char *message, ...);
}

#endif // MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12

typedef os_log_t (*os_log_create_type)(const char *subsystem,
                                       const char *category);
typedef void (*_os_log_internal_type)(void *dso, os_log_t log,
                                      os_log_type_t type, const char *message, ...);

// asl_create_auxiliary_file() and asl_add_log_file() no longer work properly
// on Sierra (and up).  So we need to go through hoops to keep supporting them
// on older versions and to approximate their functionality on Sierra.  That's
// what this class is for.
class InfoLogItem {
public:
  InfoLogItem()
    : mStringBuffer(NULL), mStringBufferSize(0), mLogFile(-1),
      mMsg(NULL), mAuxFile(-1), mDoStacktrace(false) {}

  ~InfoLogItem()
  {
    // mAuxFile must be closed before mLogFile on OS X 10.11 and below.
    // Otherwise mMsg's MSG doesn't get written to mLogFile (which happens
    // during the call to asl_close_auxiliary_file()).
    if (mAuxFile != -1) {
      asl_close_auxiliary_file(mAuxFile);
    }
    if (mMsg) {
      asl_free(mMsg);
    }
    if (mLogFile != -1) {
      if (!macOS_Sierra()) {
        asl_remove_log_file(NULL, mLogFile);
      }
      close(mLogFile);
    }
    free(mStringBuffer);
  }

  static InfoLogItem *Create(bool do_stacktrace, char *log_file_name,
                             char *proc_path, int32_t pid,
                             char *thread_name, uint64_t tid, char *report)
  {
    if (macOS_Sierra()) {
      if (!os_log_create_ptr) {
        os_log_create_ptr = (os_log_create_type)
          dlsym(RTLD_DEFAULT, "os_log_create");
        if (!os_log_create_ptr) {
          error_log("InfoLogItem::Create() can't find os_log_create()");
          return NULL;
        }
      }
      if (!_os_log_internal_ptr) {
        _os_log_internal_ptr = (_os_log_internal_type)
          dlsym(RTLD_DEFAULT, "_os_log_internal");
        if (!_os_log_internal_ptr) {
          error_log("InfoLogItem::Create() can't find _os_log_internal()");
          return NULL;
        }
      }
      if (!mLogObject) {
        // On Sierra, we have to pretend to be an Apple daemon that uses the
        // os_log subsystem (that calls os_log_create(), for example sandboxd
        // or blued) to stop our console stack traces being truncated (at 1024
        // bytes).  Shame on you, Apple!
        //
        // Sierra uses plist files in /System/Library/Preferences/Logging/Subsystems/
        // to override logging defaults for sandboxd, blued and other Apple
        // "subsystems".  Since we're running as root, it may be possible to
        // create our own overrides (possibly by installing our own plist file
        // there).
        mLogObject = os_log_create_ptr("com.apple.sandbox.reporting", "violation");
      }
    }

    InfoLogItem *new_item = new InfoLogItem;
    if (!new_item) {
      error_log("InfoLogItem::Create() out of memory constructing an InfoLogItem");
      return NULL;
    }
    new_item->mDoStacktrace = do_stacktrace;
    new_item->mStringBuffer = (char *) calloc(1, LOG_ITEM_INITIAL_SIZE);
    if (!new_item->mStringBuffer) {
      error_log("InfoLogItem::Create() out of memory initializing an InfoLogItem");
      delete new_item;
      return NULL;
    }
    new_item->mStringBufferSize = LOG_ITEM_INITIAL_SIZE;

    MaybeAddLogFile(log_file_name, &(new_item->mLogFile));

    if (!new_item->mDoStacktrace || macOS_Sierra()) {
      new_item->AppendLine("%s(%u) %s[%llx] %s", proc_path, pid,
                           thread_name, tid, report);
      return new_item;
    }

    aslmsg msg = CreateAslStacktraceMsg(proc_path, pid, thread_name,
                                        tid, report);
    if (!msg) {
      error_log("InfoLogItem::Create() failed calling CreateAslStacktraceMsg()");
      free(new_item->mStringBuffer);
      delete new_item;
      return NULL;
    }
    int aux_file = -1;
    if (asl_create_auxiliary_file(msg, "Stack trace", "public.text", &aux_file)) {
      error_log("InfoLogItem::Create() failed calling asl_create_auxiliary_file()");
      asl_free(msg);
      free(new_item->mStringBuffer);
      delete new_item;
      return NULL;
    }
    new_item->mMsg = msg;
    new_item->mAuxFile = aux_file;
    return new_item;
  }

  bool AppendLine(const char *format, ...)
  {
    va_list args;
    va_start(args, format);
    char *line_buffer = NULL;
    vasprintf(&line_buffer, format, args);
    va_end(args);
    if (!line_buffer) {
      error_log("InfoLogItem::AppendLine() out of memory calling vasprintf()");
      return false;
    }

    size_t item_length = strlen(mStringBuffer);
    size_t line_length = strlen(line_buffer);
    // Allow for terminating NULLs, plus a newline after the end of line_buffer
    size_t new_total_length = item_length + line_length + 3;

    if (new_total_length > mStringBufferSize) {
      size_t new_size = mStringBufferSize;
      while (new_size < new_total_length) {
        new_size *= 2;
      }
      char *new_buffer = (char *) calloc(1, new_size);
      if (!new_buffer) {
        error_log("InfoLogItem::AppendLine() out of memory calling calloc()");
        free(line_buffer);
        return false;
      }
      strcpy(new_buffer, mStringBuffer);
      free(mStringBuffer);
      mStringBuffer = new_buffer;
      mStringBufferSize = new_size;
    }

    strcat(mStringBuffer, line_buffer);
    strcat(mStringBuffer, "\n");
    free(line_buffer);
    return true;
  }

  void Process()
  {
    ssize_t rv;
    size_t item_length = strlen(mStringBuffer);
    if (item_length) {
      if (mAuxFile != -1) {
        rv = write(mAuxFile, mStringBuffer, item_length);
        if (rv < 0) {
          error_log("InfoLogItem::Process() failed calling write() on mAuxFile: %s",
                    strerror(errno));
        }
        // We must close mAuxFile now, to make sure its MSG gets written to mLogFile
        // before any of the stack trace does.
        asl_close_auxiliary_file(mAuxFile);
        mAuxFile = -1;
      } else {
        if (!macOS_Sierra() || !mLogObject) {
          asl_log(NULL, NULL, ASL_LEVEL_NOTICE, "%s", mStringBuffer);
        } else {
          _os_log_internal_ptr((void*)&_mh_execute_header, mLogObject,
                               OS_LOG_TYPE_DEFAULT, "%{public}s", mStringBuffer);
        }
      }
      if ((mLogFile != -1) && (mDoStacktrace || macOS_Sierra())) {
        if (macOS_Sierra()) {
          const time_t currentTime = time(NULL);
          char timestamp[30] = {0};
          ctime_r(&currentTime, timestamp);
          // Get rid of newline at end
          timestamp[strlen(timestamp) - 1] = 0;
          char *buffer = NULL;
          asprintf(&buffer, "(%s) %s", timestamp, mStringBuffer);
          if (!buffer) {
            error_log("InfoLogItem::Process() out of memory calling asprintf()");
            rv = 0;
          } else {
            rv = write(mLogFile, buffer, strlen(buffer));
            free(buffer);
          }
        } else {
          rv = write(mLogFile, mStringBuffer, item_length);
        }
        if (rv < 0) {
          error_log("InfoLogItem::Process() failed calling write() on mLogFile: %s",
                    strerror(errno));
        }
      }
    }
    delete this;
  }

private:
  static bool MaybeAddLogFile(char *log_file_name, int *log_file_descriptor)
  {
    *log_file_descriptor = -1;

    int err = mkdir(LOGGING_DIR, 0755);
    if ((err < 0) && (errno != EEXIST)) {
      error_log("InfoLogItem::MaybeAddLogFile() failed calling mkdir(): %s",
                strerror(errno));
      return false;
    }
    err = chmod(LOGGING_DIR, 0755);
    if (err < 0) {
      error_log("InfoLogItem::MaybeAddLogFile() failed calling chmod(): %s",
                strerror(errno));
      return false;
    }

    if (log_file_name[0] == 0) {
      return false;
    }

    char log_path[MAXPATHLEN];
    snprintf(log_path, sizeof(log_path), "%s/%s", LOGGING_DIR, log_file_name);
    *log_file_descriptor = open(log_path, O_APPEND | O_CREAT | O_RDWR, 0644);
    if (*log_file_descriptor < 0) {
      error_log("InfoLogItem::MaybeAddLogFile() failed calling open(): %s",
                strerror(errno));
      return false;
    }

    if (!macOS_Sierra()) {
      if (asl_add_log_file(NULL, *log_file_descriptor) != 0) {
        close(*log_file_descriptor);
        *log_file_descriptor = -1;
        error_log("InfoLogItem::MaybeAddLogFile() failed calling asl_add_log_file()");
        return false;
      }
    }

    return true;
  }

  static aslmsg CreateAslStacktraceMsg(char *proc_path, int32_t pid,
                                       char *thread_name, uint64_t tid,
                                       char *report)
  {
    aslmsg msg = asl_new(ASL_TYPE_MSG);
    if (!msg) {
      return NULL;
    }
    if (asl_set(msg, ASL_KEY_FACILITY, "org.smichaud.SandboxMirror")) {
      asl_free(msg);
      return NULL;
    }
    if (asl_set(msg, ASL_KEY_LEVEL, ASL_STRING_NOTICE)) {
      asl_free(msg);
      return NULL;
    }
    char *report_str = NULL;
    asprintf(&report_str, "%s(%u) %s[%llx] %s",
             proc_path, pid, thread_name, tid, report);
    int rv = asl_set(msg, ASL_KEY_MSG, report_str);
    free(report_str);
    if (rv) {
      asl_free(msg);
      return NULL;
    }
    return msg;
  }

  char *mStringBuffer;
  size_t mStringBufferSize;
  int mLogFile;
  aslmsg mMsg;
  int mAuxFile;
  bool mDoStacktrace;
  static os_log_t mLogObject;
  static os_log_create_type os_log_create_ptr;
  static _os_log_internal_type _os_log_internal_ptr;
};

os_log_t InfoLogItem::mLogObject = NULL;
os_log_create_type InfoLogItem::os_log_create_ptr = NULL;
_os_log_internal_type InfoLogItem::_os_log_internal_ptr = NULL;

// From OS X 10.10 and 10.11 xnu source tarballs' osfmk/kern/debug.h
#define STACKSHOT_IO_NUM_PRIORITIES     4
#define STACKSHOT_MAX_THREAD_NAME_SIZE  64

// From OS X 10.9.5 xnu source tarball's osfmk/kern/debug.h
struct thread_snapshot {
  uint32_t      snapshot_magic;
  uint32_t      nkern_frames;
  uint32_t      nuser_frames;
  uint64_t      wait_event;
  uint64_t      continuation;
  uint64_t      thread_id;
  uint64_t      user_time;
  uint64_t      system_time;
  int32_t       state;
  int32_t       priority;    // static priority
  int32_t       sched_pri;   // scheduled (current) priority
  int32_t       sched_flags; // scheduler flags
  char          ss_flags;
} __attribute__ ((packed));

// From OS X 10.10.5 xnu source tarball's osfmk/kern/debug.h
struct thread_snapshot_Yosemite {
  uint32_t      snapshot_magic;
  uint32_t      nkern_frames;
  uint32_t      nuser_frames;
  uint64_t      wait_event;
  uint64_t      continuation;
  uint64_t      thread_id;
  uint64_t      user_time;
  uint64_t      system_time;
  int32_t       state;
  int32_t       priority;    /* static priority */
  int32_t       sched_pri;   /* scheduled (current) priority */
  int32_t       sched_flags; /* scheduler flags */
  char          ss_flags;
  char          ts_qos;
  char          io_tier;

  /*
   * I/O Statistics
   * XXX: These fields must be together
   */
  uint64_t      disk_reads_count;
  uint64_t      disk_reads_size;
  uint64_t      disk_writes_count;
  uint64_t      disk_writes_size;
  uint64_t      io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      paging_count;
  uint64_t      paging_size;
  uint64_t      non_paging_count;
  uint64_t      non_paging_size;
  uint64_t      data_count;
  uint64_t      data_size;
  uint64_t      metadata_count;
  uint64_t      metadata_size;
  /* XXX: I/O Statistics end */

  uint64_t      voucher_identifier; /* obfuscated voucher identifier */
  uint64_t      total_syscalls;
  char          pth_name[STACKSHOT_MAX_THREAD_NAME_SIZE];
} __attribute__ ((packed));

// From OS X 10.11.3 xnu source tarball's osfmk/kern/debug.h
struct thread_snapshot_ElCapitan {
  uint32_t      snapshot_magic;
  uint32_t      nkern_frames;
  uint32_t      nuser_frames;
  uint64_t      wait_event;
  uint64_t      continuation;
  uint64_t      thread_id;
  uint64_t      user_time;
  uint64_t      system_time;
  int32_t       state;
  int32_t       priority;    /* static priority */
  int32_t       sched_pri;   /* scheduled (current) priority */
  int32_t       sched_flags; /* scheduler flags */
  char          ss_flags;
  char          ts_qos;      /* effective qos */
  char          ts_rqos;     /* requested qos */
  char          ts_rqos_override; /* requested qos override */
  char          io_tier;
  char          _reserved[3]; /* pad for 4 byte alignement packing */

  /*
   * I/O Statistics
   * XXX: These fields must be together
   */
  uint64_t      disk_reads_count;
  uint64_t      disk_reads_size;
  uint64_t      disk_writes_count;
  uint64_t      disk_writes_size;
  uint64_t      io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      paging_count;
  uint64_t      paging_size;
  uint64_t      non_paging_count;
  uint64_t      non_paging_size;
  uint64_t      data_count;
  uint64_t      data_size;
  uint64_t      metadata_count;
  uint64_t      metadata_size;
  /* XXX: I/O Statistics end */

  uint64_t      voucher_identifier; /* obfuscated voucher identifier */
  uint64_t      total_syscalls;
  char          pth_name[STACKSHOT_MAX_THREAD_NAME_SIZE];
} __attribute__ ((packed));

// From OS X 10.9.5 xnu source tarball's osfmk/kern/debug.h
struct task_snapshot {
  uint32_t      snapshot_magic;
  int32_t       pid;
  uint64_t      uniqueid;
  uint64_t      user_time_in_terminated_threads;
  uint64_t      system_time_in_terminated_threads;
  uint8_t       shared_cache_identifier[16];
  uint64_t      shared_cache_slide;
  uint32_t      nloadinfos;
  int           suspend_count; 
  int           task_size;  // pages
  int           faults;     // number of page faults
  int           pageins;    // number of actual pageins
  int           cow_faults; // number of copy-on-write faults
  uint32_t      ss_flags;
  /* We restrict ourselves to a statically defined
   * (current as of 2009) length for the
   * p_comm string, due to scoping issues (osfmk/bsd and user/kernel
   * binary compatibility).
   */
  char          p_comm[17];
  uint32_t      was_throttled;
  uint32_t      did_throttle;
  uint32_t      latency_qos;
} __attribute__ ((packed));

// From OS X 10.10.5 xnu source tarball's osfmk/kern/debug.h
struct task_snapshot_Yosemite {
  uint32_t      snapshot_magic;
  int32_t       pid;
  uint64_t      uniqueid;
  uint64_t      user_time_in_terminated_threads;
  uint64_t      system_time_in_terminated_threads;
  uint8_t       shared_cache_identifier[16];
  uint64_t      shared_cache_slide;
  uint32_t      nloadinfos;
  int           suspend_count; 
  int           task_size;      /* pages */
  int           faults;         /* number of page faults */
  int           pageins;        /* number of actual pageins */
  int           cow_faults;     /* number of copy-on-write faults */
  uint32_t      ss_flags;
  uint64_t      p_start_sec;    /* from the bsd proc struct */
  uint64_t      p_start_usec;   /* from the bsd proc struct */
  /* 
   * We restrict ourselves to a statically defined
   * (current as of 2009) length for the
   * p_comm string, due to scoping issues (osfmk/bsd and user/kernel
   * binary compatibility).
   */
  char          p_comm[17];
  uint32_t      was_throttled;
  uint32_t      did_throttle;
  uint32_t      latency_qos;

  /*
   * I/O Statistics
   * XXX: These fields must be together.
   */
  uint64_t      disk_reads_count;
  uint64_t      disk_reads_size;
  uint64_t      disk_writes_count;
  uint64_t      disk_writes_size;
  uint64_t      io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      paging_count;
  uint64_t      paging_size;
  uint64_t      non_paging_count;
  uint64_t      non_paging_size;
  uint64_t      data_count;
  uint64_t      data_size;
  uint64_t      metadata_count;
  uint64_t      metadata_size;
  /* XXX: I/O Statistics end */

  uint32_t      donating_pid_count;
} __attribute__ ((packed));

// From OS X 10.11.3 xnu source tarball's osfmk/kern/debug.h.  Same as
// Yosemite's.
struct task_snapshot_ElCapitan {
  uint32_t      snapshot_magic;
  int32_t       pid;
  uint64_t      uniqueid;
  uint64_t      user_time_in_terminated_threads;
  uint64_t      system_time_in_terminated_threads;
  uint8_t       shared_cache_identifier[16];
  uint64_t      shared_cache_slide;
  uint32_t      nloadinfos;
  int           suspend_count; 
  int           task_size;      /* pages */
  int           faults;         /* number of page faults */
  int           pageins;        /* number of actual pageins */
  int           cow_faults;     /* number of copy-on-write faults */
  uint32_t      ss_flags;
  uint64_t      p_start_sec;    /* from the bsd proc struct */
  uint64_t      p_start_usec;   /* from the bsd proc struct */
  /* 
   * We restrict ourselves to a statically defined
   * (current as of 2009) length for the
   * p_comm string, due to scoping issues (osfmk/bsd and user/kernel
   * binary compatibility).
   */
  char          p_comm[17];
  uint32_t      was_throttled;
  uint32_t      did_throttle;
  uint32_t      latency_qos;

  /*
   * I/O Statistics
   * XXX: These fields must be together.
   */
  uint64_t      disk_reads_count;
  uint64_t      disk_reads_size;
  uint64_t      disk_writes_count;
  uint64_t      disk_writes_size;
  uint64_t      io_priority_count[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      io_priority_size[STACKSHOT_IO_NUM_PRIORITIES];
  uint64_t      paging_count;
  uint64_t      paging_size;
  uint64_t      non_paging_count;
  uint64_t      non_paging_size;
  uint64_t      data_count;
  uint64_t      data_size;
  uint64_t      metadata_count;
  uint64_t      metadata_size;
  /* XXX: I/O Statistics end */

  uint32_t      donating_pid_count;
} __attribute__ ((packed));

#define SIZEOF(task_or_thread_snap)                           \
  OSX_Mavericks() ? sizeof(task_or_thread_snap)               \
    : OSX_Yosemite() ? sizeof(task_or_thread_snap##_Yosemite) \
    : sizeof(task_or_thread_snap##_ElCapitan)

// From xnu source tarball's osfmk/kern/debug.h
struct snapshot_frame32 {
  uint32_t lr; // Value of $eip in frame
  uint32_t sp; // Value of $ebp in frame
} __attribute__ ((packed));

// From xnu source tarball's osfmk/kern/debug.h
struct snapshot_frame64 {
  uint64_t lr; // Value of $rip in frame
  uint64_t sp; // Value of $rbp in frame
} __attribute__ ((packed));

// From xnu source tarball's osfmk/kern/debug.h
#define STACKSHOT_THREAD_SNAPSHOT_MAGIC     0xfeedface
#define STACKSHOT_TASK_SNAPSHOT_MAGIC       0xdecafbad

// From xnu source tarball's osfmk/kern/debug.h
enum generic_snapshot_flags {
  kUser64_p         = 0x1,
  kKernel64_p       = 0x2
};

#define task_has_64BitAddr(task) \
  (((task)->ss_flags & kUser64_p) != 0)

#define SNAPSHOT_BUFSIZE 0x500000
#define FRAME_MAX 256

// Returns the number of frames copied to **addresses.  **addresses must be
// freed by the caller.
uint32_t create_backtrace(char *snapshot, uint32_t frames, bool is_64bit,
                          user_addr_t **addresses)
{
  if (!frames) {
    return 0;
  }
  if (frames > FRAME_MAX) {
    frames = FRAME_MAX;
  }
  *addresses = (user_addr_t *) calloc(frames, sizeof(user_addr_t));
  if (!*addresses) {
    return 0;
  }

  uint32_t frame_offset = 0;
  while (frame_offset < frames) {
    if (is_64bit) {
      (*addresses)[frame_offset] =
        ((struct snapshot_frame64 *)snapshot)[frame_offset].lr;
    } else {
      (*addresses)[frame_offset] =
        ((struct snapshot_frame32 *)snapshot)[frame_offset].lr;
    }
    ++frame_offset;
  }

  return frames;
}

// From the ElCapitan xnu kernel's bsd/sys/stackshot.h.  These methods are
// available on OS X 10.11 and up.

struct stackshot_config;
typedef struct stackshot_config stackshot_config_t;

extern "C" {
stackshot_config_t *stackshot_config_create(void);
int stackshot_config_set_pid(stackshot_config_t *stackshot_config,
                             int pid);
int stackshot_config_set_flags(stackshot_config_t *stackshot_config,
                               uint32_t flags);
int stackshot_capture_with_config(stackshot_config_t *stackshot_config);
void * stackshot_config_get_stackshot_buffer(stackshot_config_t *stackshot_config);
uint32_t stackshot_config_get_stackshot_size(stackshot_config_t *stackshot_config);
int stackshot_config_set_size_hint(stackshot_config_t *stackshot_config,
                                   uint32_t suggested_size);
int stackshot_config_dealloc_buffer(stackshot_config_t *stackshot_config);
int stackshot_config_dealloc(stackshot_config_t *stackshot_config);
}

typedef stackshot_config_t *(*stackshot_config_create_type)();
typedef int (*stackshot_config_dealloc_type)(stackshot_config_t *stackshot_config);
typedef int (*stackshot_config_set_pid_type)(stackshot_config_t *stackshot_config,
                                             int pid);
typedef int (*stackshot_config_set_flags_type)(stackshot_config_t *stackshot_config,
                                               uint32_t flags);
typedef int (*stackshot_capture_with_config_type)(stackshot_config_t *stackshot_config);
typedef void *(*stackshot_config_get_stackshot_buffer_type)(stackshot_config_t *stackshot_config);
typedef uint32_t (*stackshot_config_get_stackshot_size_type)(stackshot_config_t *stackshot_config);

// Possible values for 'flags' in stackshot_config_set_flags() above.
enum {
  STACKSHOT_GET_DQ                           =    0x01,
  STACKSHOT_SAVE_LOADINFO                    =    0x02,
  STACKSHOT_GET_GLOBAL_MEM_STATS             =    0x04,
  STACKSHOT_SAVE_KEXT_LOADINFO               =    0x08,
  STACKSHOT_GET_MICROSTACKSHOT               =    0x10,
  STACKSHOT_GLOBAL_MICROSTACKSHOT_ENABLE     =    0x20,
  STACKSHOT_GLOBAL_MICROSTACKSHOT_DISABLE    =    0x40,
  STACKSHOT_SET_MICROSTACKSHOT_MARK          =    0x80,
  STACKSHOT_SAVE_KERNEL_FRAMES_ONLY          =   0x100,
  STACKSHOT_GET_BOOT_PROFILE                 =   0x200,
  STACKSHOT_GET_WINDOWED_MICROSTACKSHOTS     =   0x400,
  STACKSHOT_WINDOWED_MICROSTACKSHOTS_ENABLE  =   0x800,
  STACKSHOT_WINDOWED_MICROSTACKSHOTS_DISABLE =  0x1000,
  STACKSHOT_SAVE_IMP_DONATION_PIDS           =  0x2000,
  STACKSHOT_SAVE_IN_KERNEL_BUFFER            =  0x4000,
  STACKSHOT_RETRIEVE_EXISTING_BUFFER         =  0x8000,
  STACKSHOT_KCDATA_FORMAT                    = 0x10000,
  STACKSHOT_ENABLE_FAULTING                  = 0x20000
};

#if !defined(MAC_OS_X_VERSION_10_11) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_11

struct kcdata_item {
  uint32_t type;
  uint32_t size; /* len(data)  */
  uint64_t flags;
  char data[];  /* must be at the end */
};

#define KCDATA_ITEM_HEADER_SIZE (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t))

#define KCDATA_BUFFER_BEGIN_STACKSHOT      0x59a25807
#define KCDATA_TYPE_ARRAY                  0x11
#define KCDATA_TYPE_CONTAINER_BEGIN        0x13
#define KCDATA_TYPE_CONTAINER_END          0x14

#endif // MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_11

#if !defined(MAC_OS_X_VERSION_10_12) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12

#define KCDATA_TYPE_ARRAY_PAD0 0x20u /* Array of data with 0 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD1 0x21u /* Array of data with 1 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD2 0x22u /* Array of data with 2 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD3 0x23u /* Array of data with 3 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD4 0x24u /* Array of data with 4 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD5 0x25u /* Array of data with 5 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD6 0x26u /* Array of data with 6 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD7 0x27u /* Array of data with 7 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD8 0x28u /* Array of data with 8 byte of padding*/
#define KCDATA_TYPE_ARRAY_PAD9 0x29u /* Array of data with 9 byte of padding*/
#define KCDATA_TYPE_ARRAY_PADa 0x2au /* Array of data with a byte of padding*/
#define KCDATA_TYPE_ARRAY_PADb 0x2bu /* Array of data with b byte of padding*/
#define KCDATA_TYPE_ARRAY_PADc 0x2cu /* Array of data with c byte of padding*/
#define KCDATA_TYPE_ARRAY_PADd 0x2du /* Array of data with d byte of padding*/
#define KCDATA_TYPE_ARRAY_PADe 0x2eu /* Array of data with e byte of padding*/
#define KCDATA_TYPE_ARRAY_PADf 0x2fu /* Array of data with f byte of padding*/

#define STACKSHOT_KCCONTAINER_TASK         0x903
#define STACKSHOT_KCCONTAINER_THREAD       0x904
#define STACKSHOT_KCTYPE_TASK_SNAPSHOT     0x905  /* task_snapshot_v2 */
#define STACKSHOT_KCTYPE_THREAD_SNAPSHOT   0x906  /* thread_snapshot_v2 */
#define STACKSHOT_KCTYPE_USER_STACKFRAME   0x90C  /* struct stack_snapshot_frame32 */
#define STACKSHOT_KCTYPE_USER_STACKFRAME64 0x90D  /* struct stack_snapshot_frame64 */

struct task_snapshot_v2 {
  uint64_t ts_unique_pid;
  uint64_t ts_ss_flags;
  uint64_t ts_user_time_in_terminated_threads;
  uint64_t ts_system_time_in_terminated_threads;
  uint64_t ts_p_start_sec;
  uint64_t ts_task_size;
  uint64_t ts_max_resident_size;
  uint32_t ts_suspend_count;
  uint32_t ts_faults;
  uint32_t ts_pageins;
  uint32_t ts_cow_faults;
  uint32_t ts_was_throttled;
  uint32_t ts_did_throttle;
  uint32_t ts_latency_qos;
  int32_t  ts_pid;
  char     ts_p_comm[32];
} __attribute__ ((packed));

struct thread_snapshot_v2 {
  uint64_t ths_thread_id;
  uint64_t ths_wait_event;
  uint64_t ths_continuation;
  uint64_t ths_total_syscalls;
  uint64_t ths_voucher_identifier;
  uint64_t ths_dqserialnum;
  uint64_t ths_user_time;
  uint64_t ths_sys_time;
  uint64_t ths_ss_flags;
  uint64_t ths_last_run_time;
  uint64_t ths_last_made_runnable_time;
  uint32_t ths_state;
  uint32_t ths_sched_flags;
  int16_t  ths_base_priority;
  int16_t  ths_sched_priority;
  uint8_t  ths_eqos;
  uint8_t  ths_rqos;
  uint8_t  ths_rqos_override;
  uint8_t  ths_io_tier;
} __attribute__ ((packed));

#endif // MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12

#define task_has_64BitAddr_kcdata(task) \
  (((task)->ts_ss_flags & kUser64_p) != 0)

class AutoreleaseStackshotConfig {
public:
  AutoreleaseStackshotConfig(stackshot_config_t *config)
  {
    if (!stackshot_config_dealloc_ptr) {
      stackshot_config_dealloc_ptr = (stackshot_config_dealloc_type)
        dlsym(RTLD_DEFAULT, "stackshot_config_dealloc");
      if (!stackshot_config_dealloc_ptr) {
        error_log("Can't find stackshot_config_dealloc()");
      }
    }
    mConfig = config;
  }
  ~AutoreleaseStackshotConfig()
  {
    if (stackshot_config_dealloc_ptr) {
      stackshot_config_dealloc_ptr(mConfig);
    }
  }
private:
  stackshot_config_t *mConfig;
  static stackshot_config_dealloc_type
    stackshot_config_dealloc_ptr;
};

stackshot_config_dealloc_type
  AutoreleaseStackshotConfig::stackshot_config_dealloc_ptr = NULL;

// The kcdata format is supported (for stacktraces) on OS X 10.11 and up, and
// is (apparently) required on Sierra (10.12) and up.
uint32_t get_backtrace_kcdata(user_addr_t **addresses, int32_t pid, uint64_t tid)
{
  static stackshot_config_create_type
    stackshot_config_create_ptr = NULL;
  static stackshot_config_set_pid_type
    stackshot_config_set_pid_ptr = NULL;
  static stackshot_config_set_flags_type
    stackshot_config_set_flags_ptr = NULL;
  static stackshot_capture_with_config_type
    stackshot_capture_with_config_ptr = NULL;
  static stackshot_config_get_stackshot_buffer_type
    stackshot_config_get_stackshot_buffer_ptr = NULL;
  static stackshot_config_get_stackshot_size_type
    stackshot_config_get_stackshot_size_ptr = NULL;

  if (!stackshot_config_create_ptr) {
    stackshot_config_create_ptr = (stackshot_config_create_type)
      dlsym(RTLD_DEFAULT, "stackshot_config_create");
    if (!stackshot_config_create_ptr) {
      error_log("Can't find stackshot_config_create()");
      return 0;
    }
  }
  if (!stackshot_config_set_pid_ptr) {
    stackshot_config_set_pid_ptr = (stackshot_config_set_pid_type)
      dlsym(RTLD_DEFAULT, "stackshot_config_set_pid");
    if (!stackshot_config_set_pid_ptr) {
      error_log("Can't find stackshot_config_set_pid()");
      return 0;
    }
  }
  if (!stackshot_config_set_flags_ptr) {
    stackshot_config_set_flags_ptr = (stackshot_config_set_flags_type)
      dlsym(RTLD_DEFAULT, "stackshot_config_set_flags");
    if (!stackshot_config_set_flags_ptr) {
      error_log("Can't find stackshot_config_set_flags()");
      return 0;
    }
  }
  if (!stackshot_capture_with_config_ptr) {
    stackshot_capture_with_config_ptr = (stackshot_capture_with_config_type)
      dlsym(RTLD_DEFAULT, "stackshot_capture_with_config");
    if (!stackshot_capture_with_config_ptr) {
      error_log("Can't find stackshot_capture_with_config()");
      return 0;
    }
  }
  if (!stackshot_config_get_stackshot_buffer_ptr) {
    stackshot_config_get_stackshot_buffer_ptr = (stackshot_config_get_stackshot_buffer_type)
      dlsym(RTLD_DEFAULT, "stackshot_config_get_stackshot_buffer");
    if (!stackshot_config_get_stackshot_buffer_ptr) {
      error_log("Can't find stackshot_config_get_stackshot_buffer()");
      return 0;
    }
  }
  if (!stackshot_config_get_stackshot_size_ptr) {
    stackshot_config_get_stackshot_size_ptr = (stackshot_config_get_stackshot_size_type)
      dlsym(RTLD_DEFAULT, "stackshot_config_get_stackshot_size");
    if (!stackshot_config_get_stackshot_size_ptr) {
      error_log("Can't find stackshot_config_get_stackshot_size()");
      return 0;
    }
  }

  stackshot_config_t *config = stackshot_config_create_ptr();
  if (!config) {
    error_log("Out of memory calling stackshot_config_create() for pid %u",
              pid);
    return 0;
  }
  AutoreleaseStackshotConfig autorelease(config);
  // Without this flag, you get an "unsupported" error on Sierra (and up).
  stackshot_config_set_flags_ptr(config, STACKSHOT_KCDATA_FORMAT);
  stackshot_config_set_pid_ptr(config, pid);
  int rv = stackshot_capture_with_config_ptr(config);
  if (rv) {
    error_log("stackshot_capture_with_config() failed for pid %u with error %s",
              pid, strerror(rv));
    return 0;
  }
  char *snapshot_buffer = (char *)
    stackshot_config_get_stackshot_buffer_ptr(config);
  uint32_t snapshot_length = stackshot_config_get_stackshot_size_ptr(config);

  struct kcdata_item *item = (struct kcdata_item *) snapshot_buffer;
  if (item->type != KCDATA_BUFFER_BEGIN_STACKSHOT) {
    error_log("stackshot_capture_with_config() returned data with wrong type (0x%x) for pid %u",
              item->type, pid);
    return 0;
  }

  unsigned offset = KCDATA_ITEM_HEADER_SIZE + item->size;
  uint64_t task_uniqueid = 0;
  uint64_t thread_uniqueid = 0;
  bool task_is_64bit = false;
  bool seen_task_snapshot = false;
  while (offset < snapshot_length) {
    item = (struct kcdata_item *) (snapshot_buffer + offset);
    switch (item->type) {
      case KCDATA_TYPE_CONTAINER_BEGIN: {
        uint32_t container_type = *((uint32_t *)(item->data));
        if (container_type == STACKSHOT_KCCONTAINER_TASK) {
          if (task_uniqueid) {
            error_log("Nested STACKSHOT_KCCONTAINER_TASK containers for pid %u",
                      pid);
            return 0;
          }
          task_uniqueid = item->flags;
        } else if (container_type == STACKSHOT_KCCONTAINER_THREAD) {
          if (!task_uniqueid) {
            error_log("STACKSHOT_KCCONTAINER_THREAD not in STACKSHOT_KCCONTAINER_TASK for pid %u",
                      pid);
            return 0;
          }
          if (thread_uniqueid) {
            error_log("Nested STACKSHOT_KCCONTAINER_THREAD containers for pid %u",
                      pid);
            return 0;
          }
          thread_uniqueid = item->flags;
        }
        break;
      }
      case KCDATA_TYPE_CONTAINER_END: {
        if (item->flags == task_uniqueid) {
          task_uniqueid = 0;
        } else if (item->flags == thread_uniqueid) {
          thread_uniqueid = 0;
        }
        break;
      }
      case STACKSHOT_KCTYPE_TASK_SNAPSHOT: {
        if (!task_uniqueid) {
          error_log("Task snapshot not in STACKSHOT_KCCONTAINER_TASK for pid %u",
                    pid);
          return 0;
        }
        struct task_snapshot_v2 *task_snap = (struct task_snapshot_v2 *) (item->data);
        if (task_snap->ts_pid != pid) {
          error_log("Task snapshot is for wrong process: %u, should be %u",
                    task_snap->ts_pid, pid);
          return 0;
        }
        task_is_64bit = task_has_64BitAddr_kcdata(task_snap);
        seen_task_snapshot = true;
        break;
      }
      case STACKSHOT_KCTYPE_THREAD_SNAPSHOT: {
        if (!thread_uniqueid) {
          error_log("Thread snapshot not in STACKSHOT_KCCONTAINER_THREAD for pid %u",
                    pid);
          return 0;
        }
        if (!seen_task_snapshot) {
          error_log("No task snapshot before thread snapshot for pid %u",
                    pid);
          return 0;
        }
        struct thread_snapshot_v2 *thread_snap = (struct thread_snapshot_v2 *) (item->data);
        if (thread_snap->ths_thread_id != thread_uniqueid) {
          error_log("Snapshot for thread 0x%llx in wrong STACKSHOT_KCCONTAINER_THREAD (0x%llx) for pid %u",
                    thread_snap->ths_thread_id, thread_uniqueid, pid);
          return 0;
        }
        break;
      }
      case KCDATA_TYPE_ARRAY:
      case KCDATA_TYPE_ARRAY_PAD0:
      case KCDATA_TYPE_ARRAY_PAD1:
      case KCDATA_TYPE_ARRAY_PAD2:
      case KCDATA_TYPE_ARRAY_PAD3:
      case KCDATA_TYPE_ARRAY_PAD4:
      case KCDATA_TYPE_ARRAY_PAD5:
      case KCDATA_TYPE_ARRAY_PAD6:
      case KCDATA_TYPE_ARRAY_PAD7:
      case KCDATA_TYPE_ARRAY_PAD8:
      case KCDATA_TYPE_ARRAY_PAD9:
      case KCDATA_TYPE_ARRAY_PADa:
      case KCDATA_TYPE_ARRAY_PADb:
      case KCDATA_TYPE_ARRAY_PADc:
      case KCDATA_TYPE_ARRAY_PADd:
      case KCDATA_TYPE_ARRAY_PADe:
      case KCDATA_TYPE_ARRAY_PADf: {
        uint32_t element_type = ((item->flags >> 32) & UINT32_MAX);
        uint32_t element_count = (item->flags & UINT32_MAX);
        if ((element_type == STACKSHOT_KCTYPE_USER_STACKFRAME) ||
            (element_type == STACKSHOT_KCTYPE_USER_STACKFRAME64))
        {
          if (!thread_uniqueid) {
            error_log("Stack frames not in STACKSHOT_KCCONTAINER_THREAD for pid %u",
                      pid);
            return 0;
          }
          if (task_is_64bit) {
            if (element_type == STACKSHOT_KCTYPE_USER_STACKFRAME) {
              error_log("32-bit stack frames for 64-bit process pid %u",
                        pid);
              return 0;
            }
          } else {
            if (element_type == STACKSHOT_KCTYPE_USER_STACKFRAME64) {
              error_log("64-bit stack frames for 32-bit process pid %u",
                        pid);
              return 0;
            }
          }
          if (tid == thread_uniqueid) {
            if (!element_count) {
              error_log("No stack frames for thread %llx (for pid %u)",
                        tid, pid);
              return 0;
            }
            return create_backtrace(item->data, element_count,
                                    task_is_64bit, addresses);
          }
        }
        break;
      }
      default:
        break;
    }
    offset += (KCDATA_ITEM_HEADER_SIZE + item->size);
  }

  error_log("No thread %llx found in snapshot for pid %u", tid, pid);
  return 0;
}

// Returns the number of frames copied to **addresses.  **addresses must be
// freed by the caller.
uint32_t get_backtrace(user_addr_t **addresses, int32_t pid, uint64_t tid)
{
  *addresses = NULL;

  if (macOS_Sierra() || OSX_ElCapitan()) {
    return get_backtrace_kcdata(addresses, pid, tid);
  }

  static char snapshot_buffer[SNAPSHOT_BUFSIZE];
  int snapshot_length;
  bool task_is_64bit;

  snapshot_length = syscall(365, pid, snapshot_buffer, sizeof(snapshot_buffer), 0, 0);
  if (snapshot_length < 0) {
    error_log("syscall(STACKSNAPSHOT) failed to create stack snapshot for pid %u: %s",
              pid, strerror(errno));
    return 0;
  }

  task_is_64bit = false;
  unsigned offset = 0;
  bool seen_task_snapshot = false;
  while (offset < snapshot_length) {
    // The fields we're interested in are at the same offsets in all the
    // different OS-specific variants of these structures, so we can use the
    // Mavericks variants to access these fields on all platforms.
    struct task_snapshot *task_snap =
      (struct task_snapshot *) (snapshot_buffer + offset);
    struct thread_snapshot *thread_snap =
      (struct thread_snapshot *) (snapshot_buffer + offset);
    // 'snapshot_magic' is the first field in both 'struct task_snapshot' and
    // 'struct thread_snapshot'.
    switch (task_snap->snapshot_magic) {
      case STACKSHOT_TASK_SNAPSHOT_MAGIC:
        if (task_snap->pid != pid) {
          error_log("Snapshot is for wrong process: %u, should be %u",
                    task_snap->pid, pid);
          return 0;
        }
        offset += SIZEOF(struct task_snapshot);
        seen_task_snapshot = true;
        task_is_64bit = task_has_64BitAddr(task_snap);
        continue;
      case STACKSHOT_THREAD_SNAPSHOT_MAGIC: {
        if (!seen_task_snapshot) {
          error_log("No task snapshot before thread snapshot for pid %u",
                    pid);
          return 0;
        }
        offset += SIZEOF(struct thread_snapshot);
        offset += (thread_snap->nkern_frames * sizeof(snapshot_frame64));
        if (thread_snap->thread_id != tid) {
          if (task_is_64bit) {
            offset += (thread_snap->nuser_frames * sizeof(snapshot_frame64));
          } else {
            offset += (thread_snap->nuser_frames * sizeof(snapshot_frame32));
          }
          continue;
        }
        if (!thread_snap->nuser_frames) {
          error_log("Snapshot for thread %llx (for pid %u) has 0 frames",
                    tid, pid);
          return 0;
        }
        return create_backtrace(snapshot_buffer + offset,
                                thread_snap->nuser_frames,
                                task_is_64bit, addresses);
        }
      default:
        error_log("Unexpected snapshot_magic (0x%x) for pid %u",
                  task_snap->snapshot_magic, pid);
        return 0;
    }
  }

  error_log("No thread %llx found in snapshot for pid %u", tid, pid);
  return 0;
}

// Definitions and declarations of stuff used by us from the CoreSymbolication
// framework.  This is an undocumented, private framework available on OS X
// 10.6 and up.  It's used by Apple utilities like dtrace, atos, ReportCrash
// and crashreporterd.

typedef struct _CSTypeRef {
  unsigned long type;
  void* contents;
} CSTypeRef;

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSymbolRef;

typedef struct _CSRange {
  unsigned long long location;
  unsigned long long length;
} CSRange;

#define kCSNow LONG_MAX

extern "C" {

uint32_t
CSSymbolicatorGetFlagsForNListOnlyData(void);

CSSymbolicatorRef
CSSymbolicatorCreateWithTaskFlagsAndNotification(task_t task,
                                                 uint32_t flags,
                                                 uint32_t notification);

CSSymbolicatorRef
CSSymbolicatorCreateWithPidFlagsAndNotification(pid_t pid,
                                                uint32_t flags,
                                                uint32_t notification);

CSSymbolOwnerRef
CSSymbolicatorGetSymbolOwnerWithAddressAtTime(CSSymbolicatorRef symbolicator,
                                              unsigned long long address,
                                              long time);

const char*
CSSymbolOwnerGetName(CSSymbolOwnerRef owner);

unsigned long long
CSSymbolOwnerGetBaseAddress(CSSymbolOwnerRef owner);

CSSymbolRef
CSSymbolOwnerGetSymbolWithAddress(CSSymbolOwnerRef owner,
                                  unsigned long long address);

const char*
CSSymbolGetName(CSSymbolRef symbol);

CSRange
CSSymbolGetRange(CSSymbolRef symbol);

CSTypeRef
CSRetain(CSTypeRef);

void
CSRelease(CSTypeRef);

bool
CSIsNull(CSTypeRef);

void
CSShow(CSTypeRef);

} // extern "C"

char *GetOwnerName(CSTypeRef owner)
{
  char *retval = NULL;
  const char *ownerName = "unknown";

  if (!CSIsNull(owner)) {
    ownerName = CSSymbolOwnerGetName(owner);
  }

  asprintf(&retval, "%s", ownerName);

  return retval;
}

char *GetAddressString(user_addr_t address, CSTypeRef owner)
{
  char *retval = NULL;
  const char* addressName = "unknown";
  unsigned long long addressOffset = 0;
  bool addressOffsetIsBaseAddress = false;

  if (!CSIsNull(owner)) {
    CSSymbolRef symbol =
      CSSymbolOwnerGetSymbolWithAddress(owner,
                                        (unsigned long long) address);
    if (!CSIsNull(symbol)) {
      addressName = CSSymbolGetName(symbol);
      CSRange range = CSSymbolGetRange(symbol);
      addressOffset = (unsigned long long) address;
      if (range.location <= addressOffset) {
        addressOffset -= range.location;
      } else {
        addressOffsetIsBaseAddress = true;
      }
    } else {
      addressOffset = (unsigned long long) address;
      unsigned long long baseAddress = CSSymbolOwnerGetBaseAddress(owner);
      if (baseAddress <= addressOffset) {
        addressOffset -= baseAddress;
      } else {
        addressOffsetIsBaseAddress = true;
      }
    }
  }

  if (addressOffsetIsBaseAddress) {
    asprintf(&retval, "%s 0x%llx", addressName, addressOffset);
  } else {
    asprintf(&retval, "%s + 0x%llx", addressName, addressOffset);
  }

  return retval;
}

bool WriteStackFrame(user_addr_t address, CSSymbolicatorRef symbolicator,
                     InfoLogItem *log_item)
{
  bool retval = true;

  const char *ownerName = "unknown";
  const char *addressString = "unknown + 0";
  const char *stackFrame = "    (unknown) unknown + 0";

  char *allocatedOwnerName = NULL;
  char *allocatedAddressString = NULL;
  char *allocatedStackFrame = NULL;

  CSSymbolOwnerRef owner =
    CSSymbolicatorGetSymbolOwnerWithAddressAtTime(symbolicator,
                                                  (unsigned long long) address,
                                                  kCSNow);
  if (!CSIsNull(owner)) {
    allocatedOwnerName = GetOwnerName(owner);
    allocatedAddressString = GetAddressString(address, owner);
    if (allocatedOwnerName) {
      ownerName = allocatedOwnerName;
    }
    if (allocatedAddressString) {
      addressString = allocatedAddressString;
    }
  }

  asprintf(&allocatedStackFrame, "    (%s) %s", ownerName, addressString);
  if (allocatedStackFrame) {
    stackFrame = allocatedStackFrame;
  }

  if (!log_item->AppendLine("%s", stackFrame)) {
    retval = false;
  }

  free(allocatedOwnerName);
  free(allocatedAddressString);
  free(allocatedStackFrame);

  return retval;
}

void WriteStackTrace(CSSymbolicatorRef symbolicator, user_addr_t *backtrace,
                     uint32_t backtrace_count, InfoLogItem *log_item)
{
  for (uint32_t i = 0; i < backtrace_count; ++i) {
    if (!WriteStackFrame(backtrace[i], symbolicator, log_item)) {
      break;
    }
  }
}

dispatch_queue_t gReportingQueue = 0;

#define SM_FILENAME_SIZE 1024
typedef char sm_filename_t[SM_FILENAME_SIZE];
#define SM_PATH_SIZE 1024
typedef char sm_path_t[SM_PATH_SIZE];
#define SM_REPORT_SIZE 2048
typedef char sm_report_t[SM_REPORT_SIZE];

void sm_report(task_t task, int32_t do_stacktrace, int32_t pid,
               uint64_t tid, sm_filename_t log_file, sm_path_t proc_path,
               sm_report_t report)
{
  char thread_name[MAXTHREADNAMESIZE];
  struct proc_threadinfo tinfo;
  if (proc_pidinfo(pid, PROC_PIDTHREADID64INFO, tid,
                   &tinfo, PROC_PIDTHREADID64INFO_SIZE) <= 0)
  {
    error_log("Error calling proc_pidinfo() for thread %llx in pid %u: %s",
              tid, pid, strerror(errno));
    thread_name[0] = 0;
  } else {
    strncpy(thread_name, tinfo.pth_name, sizeof(thread_name));
  }

  if (!do_stacktrace) {
    if (task != MACH_PORT_NULL) {
      mach_port_deallocate(mach_task_self(), task);
    }
    InfoLogItem *item =
      InfoLogItem::Create(do_stacktrace, log_file, proc_path, pid,
                          thread_name, tid, report);
    if (item) {
      item->Process();
    }
    return;
  }

  user_addr_t *backtrace = NULL;
  uint32_t backtrace_count = 0;
  CSSymbolicatorRef symbolicator;
  // If we can, use the task method to create a symbolicator instead of the
  // pid method.  The pid method gets the task from the pid internally.  But
  // this is considered sensitive information, and triggers an annoying
  // warning in the system log on OS X 10.11 and up (even though we're running
  // as root).
  if (task != MACH_PORT_NULL) {
    symbolicator =
      CSSymbolicatorCreateWithTaskFlagsAndNotification(task,
                                                       CSSymbolicatorGetFlagsForNListOnlyData(),
                                                       0);
    mach_port_deallocate(mach_task_self(), task);
  } else {
    symbolicator =
      CSSymbolicatorCreateWithPidFlagsAndNotification(pid,
                                                      CSSymbolicatorGetFlagsForNListOnlyData(),
                                                      0);
  }
  // The backtrace must be created now, while we're handling a synchronous
  // Mach message from SandboxMirror.kext.  Otherwise it wouldn't be current.
  // We also create the symbolicator synchronously, which may not be
  // necessary.  But the actual symbolication takes place asynchronously,
  // below.
  bool have_symbolicator = !CSIsNull(symbolicator);
  if (have_symbolicator) {
    backtrace_count = get_backtrace(&backtrace, pid, tid);
  } else {
    error_log("Could not create symbolicator for pid %u", pid);
  }

  if (!backtrace_count) {
    if (backtrace) {
      free(backtrace);
    }
    if (have_symbolicator) {
      CSRelease(symbolicator);
    }
    InfoLogItem *item =
      InfoLogItem::Create(false, log_file, proc_path, pid,
                          thread_name, tid, report);
    if (item) {
      item->Process();
    }
    return;
  }

  char *proc_path_buf = (char *) calloc(strlen(proc_path) + 1, 1);
  if (!proc_path_buf) {
    error_log("Out of memory for proc_path_buf in sm_report()");
    return;
  }
  strcpy(proc_path_buf, proc_path);
  char *thread_name_buf = (char *) calloc(strlen(thread_name) + 1, 1);
  if (!thread_name_buf) {
    error_log("Out of memory for thread_name_buf in sm_report()");
    return;
  }
  strcpy(thread_name_buf, thread_name);
  char *report_buf = (char *) calloc(strlen(report) + 1, 1);
  if (!report_buf) {
    error_log("Out of memory for report_buf in sm_report()");
    return;
  }
  strcpy(report_buf, report);
  char *log_file_buf = (char *) calloc(strlen(log_file) + 1, 1);
  if (!log_file_buf) {
    error_log("Out of memory for log_file_buf in sm_report()");
    return;
  }
  strcpy(log_file_buf, log_file);

  // Though we create the symbolicator and backtrace synchronously, we handle
  // symbolication and logging asynchronously.  Both can be very time
  // consuming.
  dispatch_async(gReportingQueue,
    ^{
      InfoLogItem *item =
        InfoLogItem::Create(true, log_file_buf, proc_path_buf, pid,
                            thread_name_buf, tid, report_buf);
      free(log_file_buf);
      free(proc_path_buf);
      free(thread_name_buf);
      free(report_buf);
      if (!item) {
        return;
      }

      WriteStackTrace(symbolicator, backtrace, backtrace_count, item);
      item->Process();

      CSRelease(symbolicator);
      free(backtrace);
    });
}

// dispatch_mig_callback() and its associated structures and defines are
// derived from the sm_report* files that come with the sandboxmirrord distro
// -- specifically from the files that are generated from sm_report.defs by
// running 'mig' on it.  'mig' "generates" an "interface" whereby we can
// receive Mach messages from SandboxMirror.kext.

#define MSGID_BASE 666

typedef boolean_t (*dispatch_mig_callback_t)(mach_msg_header_t *message,
                                             mach_msg_header_t *reply);
extern "C" mach_msg_return_t
dispatch_mig_server(dispatch_source_t ds, size_t maxmsgsz,
                    dispatch_mig_callback_t callback);

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

// This handler is called every time SandboxMirror.kext sends us a Mach
// message.  SandboxMirror.kext does this synchronously -- it waits for our
// reply.
boolean_t dispatch_mig_callback(mach_msg_header_t *message,
                                mach_msg_header_t *reply)
{
  reply->msgh_bits =
    MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(message->msgh_bits), 0);
  reply->msgh_remote_port = message->msgh_remote_port;
  /* Minimal size for error reply */
  reply->msgh_size = (mach_msg_size_t) sizeof(mig_reply_error_t);
  reply->msgh_local_port = MACH_PORT_NULL;
  reply->msgh_id = message->msgh_id + 100;

  if (message->msgh_id != MSGID_BASE) {
    ((mig_reply_error_t *)reply)->NDR = NDR_record;
    ((mig_reply_error_t *)reply)->RetCode = MIG_BAD_ID;
    return FALSE;
  }

  Request *request_ptr = (Request *) message;
  Request *request_ptr2 = (Request *)
    (((pointer_t)request_ptr) + _WALIGN_(request_ptr->log_fileCnt)
     - SM_FILENAME_SIZE);
  Request *request_ptr3 = (Request *)
    (((pointer_t)request_ptr2) + _WALIGN_(request_ptr2->proc_pathCnt)
     - SM_PATH_SIZE);

  if ((request_ptr->task.type != MACH_MSG_PORT_DESCRIPTOR) ||
      (request_ptr->task.disposition != MACH_MSG_TYPE_MOVE_SEND))
  {
    ((mig_reply_error_t *)reply)->NDR = NDR_record;
    ((mig_reply_error_t *)reply)->RetCode = MIG_TYPE_ERROR;
    return FALSE;
  }

  unsigned int in_msgh_size = request_ptr->Head.msgh_size;
  unsigned int char_fields_max =
    SM_FILENAME_SIZE + SM_PATH_SIZE + SM_REPORT_SIZE;
  if (!(request_ptr->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) ||
      (request_ptr->msgh_body.msgh_descriptor_count != 1) ||
      (in_msgh_size < (mach_msg_size_t) (sizeof(Request) - char_fields_max)) ||
      (in_msgh_size > (mach_msg_size_t) sizeof(Request)) ||
      (request_ptr->log_fileCnt > SM_FILENAME_SIZE) ||
      (request_ptr2->proc_pathCnt > SM_PATH_SIZE) ||
      (request_ptr3->reportCnt > SM_REPORT_SIZE))
  {
    ((mig_reply_error_t *)reply)->NDR = NDR_record;
    ((mig_reply_error_t *)reply)->RetCode = MIG_BAD_ARGUMENTS;
    return FALSE;
  }

  sm_report(request_ptr->task.name, request_ptr->do_stacktrace,
            request_ptr->pid, request_ptr->tid, request_ptr->log_file,
            request_ptr2->proc_path, request_ptr3->report);

  Reply *reply_ptr = (Reply *) reply;

  reply->msgh_size = (mach_msg_size_t) sizeof(Reply);
  reply_ptr->NDR = NDR_record;
  reply_ptr->RetCode = MACH_MSG_SUCCESS;

  return TRUE;
}

void init_service()
{
  if (OSX_Version_Unsupported()) {
    error_log("sandboxmirrord requires OS X Mavericks (10.9), Yosemite (10.10), El Capitan (10.11) or macOS_Sierra (10.12): current version %s(%x)",
              OSX_Version_String(), OSX_Version());
    exit(1);
  }

  gReportingQueue = dispatch_queue_create("org.smichaud.sandboxmirrord.reporting-queue",
                                          DISPATCH_QUEUE_SERIAL);
  if (!gReportingQueue) {
    error_log("dispatch_queue_create() failed to create reporting queue");
    exit(1);
  }
  dispatch_queue_t background_queue = dispatch_get_global_queue(INT16_MIN, 0);
  if (!background_queue) {
    error_log("dispatch_get_global_queue() failed to find background queue");
    exit(1);
  }
  dispatch_set_target_queue(gReportingQueue, background_queue);

  mach_port_t bootstrap_port = 0;
  kern_return_t status =
    task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
  if (status != KERN_SUCCESS) {
    error_log("task_get_bootstrap_port() failed with error %s",
              mach_error_string(status));
    exit(1);
  }

  mach_port_t service_port = 0;
  status = bootstrap_check_in(bootstrap_port, "org.smichaud.sandboxmirrord",
                              &service_port);
  if (status != KERN_SUCCESS) {
    error_log("bootstrap_check_in() failed with error %s",
              mach_error_string(status));
    exit(1);
  }

#ifdef DEBUG
  mach_port_t special_port = 0;
  host_get_special_port(mach_host_self(), HOST_LOCAL_NODE,
                        HOST_CHUD_PORT, &special_port);
  error_log("service_port %x, special_port %x", service_port, special_port);
#endif

  dispatch_queue_t main_queue = dispatch_get_main_queue();
  if (!main_queue) {
    error_log("dispatch_get_main_queue() failed");
    exit(1);
  }

  dispatch_source_t main_source =
    dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
                           service_port, 0, main_queue);
  if (!main_source) {
    error_log("dispatch_source_create() failed");
    exit(1);
  }

  dispatch_source_set_event_handler(main_source,
    ^{
      // Together with setting EnableTransactions in our plist file, the calls
      // to xpc_transaction_begin() and xpc_transaction_end() guarantee that
      // sandboxmirrord won't be killed/unloaded (by launchctl) in the middle
      // of a call to dispatch_mig_callback().
      xpc_transaction_begin();
      dispatch_mig_server(main_source, sizeof(Request), dispatch_mig_callback);
      xpc_transaction_end();
    });

  dispatch_resume(main_source);
  dispatch_main(); // Never returns
}

int main(int argc, const char * argv[])
{
    init_service(); // Never returns
    return 0;
}
