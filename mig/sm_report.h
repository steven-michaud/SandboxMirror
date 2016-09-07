#ifndef	_sm_report_user_
#define	_sm_report_user_

/* Module sm_report */

#include <string.h>
#include <mach/ndr.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/notify.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/port.h>
#if	(__MigKernelSpecificCode) || (_MIG_KERNEL_SPECIFIC_CODE_)
#include <kern/ipc_mig.h>
#endif /* __MigKernelSpecificCode */

#ifdef AUTOTEST
#ifndef FUNCTION_PTR_T
#define FUNCTION_PTR_T
typedef void (*function_ptr_t)(mach_port_t, char *, mach_msg_type_number_t);
typedef struct {
        char            *name;
        function_ptr_t  function;
} function_table_entry;
typedef function_table_entry   *function_table_t;
#endif /* FUNCTION_PTR_T */
#endif /* AUTOTEST */

#ifndef	sm_report_MSG_COUNT
#define	sm_report_MSG_COUNT	1
#endif	/* sm_report_MSG_COUNT */

#include <mach/std_types.h>
#include <mach/mig.h>
#include <mach/mig.h>
#include <mach/mach_types.h>

#ifdef __BeforeMigUserHeader
__BeforeMigUserHeader
#endif /* __BeforeMigUserHeader */

#include <sys/cdefs.h>
__BEGIN_DECLS


/* Routine sm_report */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t sm_report
(
	mach_port_t server_port,
	task_t task,
	int32_t do_stacktrace,
	int32_t pid,
	uint64_t tid,
	sm_filename_t log_file,
	sm_path_t proc_path,
	sm_report_t report
);

__END_DECLS

/********************** Caution **************************/
/* The following data types should be used to calculate  */
/* maximum message sizes only. The actual message may be */
/* smaller, and the position of the arguments within the */
/* message layout may vary from what is presented here.  */
/* For example, if any of the arguments are variable-    */
/* sized, and less than the maximum is sent, the data    */
/* will be packed tight in the actual message to reduce  */
/* the presence of holes.                                */
/********************** Caution **************************/

/* typedefs for all requests */

#ifndef __Request__sm_report_subsystem__defined
#define __Request__sm_report_subsystem__defined

#ifdef  __MigPackStructs
#pragma pack(4)
#endif
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
		char log_file[1024];
		mach_msg_type_number_t proc_pathOffset; /* MiG doesn't use it */
		mach_msg_type_number_t proc_pathCnt;
		char proc_path[1024];
		mach_msg_type_number_t reportOffset; /* MiG doesn't use it */
		mach_msg_type_number_t reportCnt;
		char report[2048];
	} __Request__sm_report_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack()
#endif
#endif /* !__Request__sm_report_subsystem__defined */

/* union of all requests */

#ifndef __RequestUnion__sm_report_subsystem__defined
#define __RequestUnion__sm_report_subsystem__defined
union __RequestUnion__sm_report_subsystem {
	__Request__sm_report_t Request_sm_report;
};
#endif /* !__RequestUnion__sm_report_subsystem__defined */
/* typedefs for all replies */

#ifndef __Reply__sm_report_subsystem__defined
#define __Reply__sm_report_subsystem__defined

#ifdef  __MigPackStructs
#pragma pack(4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		kern_return_t RetCode;
	} __Reply__sm_report_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack()
#endif
#endif /* !__Reply__sm_report_subsystem__defined */

/* union of all replies */

#ifndef __ReplyUnion__sm_report_subsystem__defined
#define __ReplyUnion__sm_report_subsystem__defined
union __ReplyUnion__sm_report_subsystem {
	__Reply__sm_report_t Reply_sm_report;
};
#endif /* !__RequestUnion__sm_report_subsystem__defined */

#ifndef subsystem_to_name_map_sm_report
#define subsystem_to_name_map_sm_report \
    { "sm_report", 666 }
#endif

#ifdef __AfterMigUserHeader
__AfterMigUserHeader
#endif /* __AfterMigUserHeader */

#endif	 /* _sm_report_user_ */
