/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef __LIBPKI_BASE_H__
#define __LIBPKI_BASE_H__

/* BEGIN_C_DECLS should be used at the beginning of your declarations,
so that C++ compilers don't mangle their names.  Use END_C_DECLS at
the end of C declarations. */
#undef BEGIN_C_DECLS
#undef END_C_DECLS
#ifdef __cplusplus
  # define BEGIN_C_DECLS extern "C" {
  # define END_C_DECLS }
#else
  # define BEGIN_C_DECLS /* empty */
  # define END_C_DECLS /* empty */
#endif
     
/* PARAMS is a macro used to wrap function prototypes, so that
compilers that don't understand ANSI C prototypes still work,
and ANSI C compilers can issue warnings about type mismatches. */
#undef PARAMS
#if defined (__STDC__) || defined (_AIX) \
  || (defined (__mips) && defined (_SYSTYPE_SVR4)) \
    || defined(WIN32) || defined(__cplusplus)
  # define PARAMS(protos) protos
#else
  # define PARAMS(protos) ()
#endif

#ifdef __LIB_BUILD__
#include <libpki/config.h>
#endif

#include <libpki/os.h>

#include <limits.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>

#define __XOPEN_OR_POSIX
#include <signal.h>
#undef __XOPEN_OR_POSIX

#include <sys/stat.h>

#include <sys/file.h>
#include <sys/times.h>

#include <sys/sem.h>
#include <sys/ipc.h>

#ifdef LIBPKI_TARGET_SOLARIS
#include <fcntl.h>
#endif


#if defined (__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
  /* Ok, Semafores are correctly supported */
#elif defined (_SYS_SEM_H_)
  /* OpenBSD is not a GNU_LIBRARY but knows semaphores */
#else
  /* We should define here the structure */
  union semun {
    int val;                  /* value for SETVAL */
    struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
    unsigned short *array;    /* array for GETALL, SETALL */
                              /* Linux specific part: */
    struct seminfo *__buf;    /* buffer for IPC_INFO */
  };

#endif

extern const long LIBPKI_OS_DETAILS;

BEGIN_C_DECLS

#define PKI_ERR	0
#define PKI_OK	1

END_C_DECLS

#endif // End of __LIBPKI_BASE_H__

