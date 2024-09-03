/* libconf/system.h - LibPKI operating system layer */

#ifndef _LIBPKI_SYSTEM_H
#define _LIBPKI_SYSTEM_H

#ifdef __LIB_BUILD__
#include <libpki/libconf/defines.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/libconf/compat.h>
#endif

#ifndef _LIBPKI_FEATURES_H
#include <libpki/libconf/features.h>
#endif

#ifndef _LIBPKI_VERSION_H
#include <libpki/libconf/version.h>
#endif

#ifndef _LIBPKI_CORE_TYPES_H
#include <libpki/libconf/types.h>
#endif

# include <sys/param.h>
# include <sys/types.h>
# include <unistd.h>
# include <string.h>

#include <stdlib.h>

#include <limits.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/stat.h>
#include <sys/file.h>
#include <sys/times.h>

#define __XOPEN_OR_POSIX
#include <signal.h>
#undef __XOPEN_OR_POSIX

#include <sys/sem.h>
#include <sys/ipc.h>

#ifdef LIBPKI_TARGET_SOLARIS
#include <fcntl.h>
#endif

#ifndef _SYS_UTSNAME_H
#include <sys/utsname.h>
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

// ---------------------- ENDIANNESS defines ----------------------

#define  LIBPKI_LITTLE_ENDIAN   1
#define  LIBPKI_BIG_ENDIAN      2

# ifdef __BYTE_ORDER
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define LIBPKI_ENDIANNESS  LIBPKI_LITTLE_ENDIAN
#  else
#   if __BYTE_ORDER == __BIG_ENDIAN
#    define LIBPKI_ENDIANNESS  LIBPKI_BIG_ENDIAN
#   endif
#  endif
# endif /* __BYTE_ORDER */

# ifdef BYTE_ORDER
#  if BYTE_ORDER == LITTLE_ENDIAN
#   define LIBPKI_ENDIANNESS LIBPKI_LITTLE_ENDIAN
#  else
#   if BYTE_ORDER == BIG_ENDIAN
#    define LIBPKI_ENDIANNESS LIBPKI_BIG_ENDIAN
#    endif
#  endif
# endif /* _DARWIN_BYTE_ORDER */

# ifndef LIBPKI_ENDIANNESS
#  if defined (i386) || defined (__i386__) || defined (_M_IX86) || \
                defined (vax) || defined (__alpha)
#   define LIBPKI_ENDIANNESS  LIBPKI_LITTLE_ENDIAN
#  endif
# endif

// ---------------------- OS and ARCH defines ----------------------
// Bits
#define LIBPKI_OS32          1
#define LIBPKI_OS64          2
// Types of OSes
#define LIBPKI_OS_POSIX      4
#define LIBPKI_OS_WIN        8
// Specific OSes
#define LIBPKI_OS_BSD        16
#define LIBPKI_OS_LINUX      32
#define LIBPKI_OS_SOLARIS    64
#define LIBPKI_OS_MACOS      128
// Win
#define LIBPKI_OS_WINCE      256
#define LIBPKI_OS_WINNT      512
#define LIBPKI_OS_WINXP      1024
#define LIBPKI_OS_WIN2003    2048
#define LIBPKI_OS_VISTA      4096
#define LIBPKI_OS_WIN7       8192
// Mobile Env
#define LIBPKI_OS_IPHONE     16384
#define LIBPKI_OS_SYMBIAN    32768


# if defined(_WINCE) || defined(WINCE)
// Windows CE (WINCE and _WIN32 defined)
#  define LIBPKI_WIN        1
#  define LIBPKI_OS_BITS    LIBPKI_OS32
#  define LIBPKI_OS_CLASS   LIBPKI_OS_WIN
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_WINCE
# elif defined(_WIN64) || defined(WIN64)
// 64 bit Windows (_WIN64 and _WIN32 defined)
#  define LIBPKI_WIN        1
#  define LIBPKI_OS_BITS    LIBPKI_OS64
#  define LIBPKI_OS_CLASS   LIBPKI_OS_WIN
# elif defined(_WIN32) || defined(WIN32) || defined(__WIN32_) || \
            defined (__WINDOW__)
// 32 bit Windows (only _WIN32 defined)
#  define LIBPKI_WIN        1
#  define LIBPKI_OS_BITS    LIBPKI_OS32
#  define LIBPKI_OS_CLASS   LIBPKI_OS_WIN
# elif defined(__linux) || defined(linux)
// Generic Linux
#  define LIBPKI_LINUX      1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_LINUX
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
# elif defined(macintosh) || defined(Macintosh) || defined(MACOS)
// MACOS
#  define LIBPKI_MACOS      1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_MACOS
# elif defined(__bsdi__) || defined (BSD)
// BSD
#  define LIBPKI_BSD        1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_BSD
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
# elif defined(__IPHONE_OS)
// iPHONE
#  define LIBPKI_IPHONE     1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_BITS    LIBPKI_OS64
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_IPHONE
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
# elif defined(__sun) || defined(sun)
/*
# if defined(__SVR4) || defined(__svr4__)
// SOLARIS
*/
#  define LIBPKI_SOLARIS    1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_SOLARIS
/*
# else
// SUN
#define LIBPKI_OS_CLASS    LIBPKI_OS_POSIX
#define LIBPKI_OS_VENDOR  LIBPKI_OS_SOLARIS
# endif
*/
# elif defined(__SYMBIAN32__)
// SYMBIAN
#  define LIBPKI_SYMBIAN    1
#  define LIBPKI_UNIX       1
#  define LIBPKI_OS_CLASS   LIBPKI_OS_POSIX
#  define LIBPKI_OS_VENDOR  LIBPKI_OS_SYMBIAN
# endif

# if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
#  if (_WIN32_WINNT  == 0x500)
// Windows 2000
#   define LIBPKI_OS_VENDOR  LIBPKI_OS_WINNT
#  elif (_WIN32_WINNT  == 0x501)
// Windows XP
#   define LIBPKI_OS_VENDOR  LIBPKI_OS_WINXP
#  elif (_WIN32_WINNT  == 0x502)
// Windows Server 2003
#   define LIBPKI_OS_VENDOR  LIBPKI_OS_WIN2003
#  elif (_WIN32_WINNT  == 0x600)
// Windows Vista or Server 2008
#   define LIBPKI_OS_VENDOR  LIBPKI_OS_VISTA
#  elif (_WIN32_WINNT  == 0x601)
// Windows 7
#   define LIBPKI_OS_VENDOR  LIBPKI_OS_WIN7
#  endif
# define LDAP_VENDOR_MICROSOFT    1
# endif /* LIBPKI_OS_WIN */

/* Check for word size */
# if (LIBPKI_OS_CLASS == LIBPKI_OS_POSIX)
#  if defined(__x86_64__) || defined(__AMD64__) || defined(__amd64__)
#   define LIBPKI_OS_BITS    LIBPKI_OS64
#  else
#   ifdef ENABLE_ARCH_64
#    define LIBPKI_OS_BITS    LIBPKI_OS64
#   else
#    define LIBPKI_OS_BITS    LIBPKI_OS32
#   endif
# endif
# endif /* LIBPKI_OS_POSIX */

// ---------------------- OS Specific Includes -----------------------

# if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
#  include <limits.h>
#  include <intrin.h>
#  include <windows.h>
typedef int pki_int32_t;
typedef unsigned int pki_uint32_t;
typedef __int64 pki_int64_t;
typedef unsigned __int64 pki_uint64_t;

#define LIBPKI_PATH_SEPARATOR  "\\"
#define LIBPKI_PATH_SEPARATOR_CHAR  '\\'

# else
#  include <unistd.h>
#  if defined(LIBPKI_LINUX) || defined(LIBPKI_MACOS)
#   include <stdint.h>
#  endif // LIBPKI_UNIX
#  include <sys/types.h>
typedef int32_t  pki_int32_t;
typedef uint32_t pki_uint32_t;
typedef int64_t  pki_int64_t;
typedef uint64_t pki_uint64_t;

#define LIBPKI_PATH_SEPARATOR  "/"
#define LIBPKI_PATH_SEPARATOR_CHAR  '/'

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
  // Do we need any includes for the threads on WIN (???)
  typedef SRWLOCK PKI_RWLOCK;
  typedef CONDITION_VARIABLE PKI_COND;
  typedef CRITICAL_SECTION	PKI_MUTEX;

  typedef struct timespec {
		long long tv_sec;
		long long tv_nsec;
  };

  typedef struct _thread_v {
	void *ret_arg;
	void *(* func)(void *);
	_pthread_cleanup *clean;
	HANDLE h;
	int cancelled;
	unsigned p_state;
	int keymax;
	void **keyval;
	
	jmp_buf jb;
  };

  typedef _thread_v PKI_THREAD;

  typedef struct pthread_attr_t {
	unsigned p_state;
	void *stack;
	size_t s_size;
  } PKI_PTHREAD_ATTR;

#define PKI_THREAD_CREATE_JOINABLE       0
#define PKI_THREAD_CREATE_DETACHED       0x04

#define PKI_THREAD_EXPLICT_SCHED         0
#define PKI_THREAD_INHERIT_SCHED         0x08

#define PKI_THREAD_SCOPE_PROCESS 		 0
#define PKI_THREAD_SCOPE_SYSTEM 		 0x10

#define PKI_THREAD_DESTRUCTOR_ITERATIONS 256

#define PKI_THREAD_PRIO_NONE 			 0
#define PKI_THREAD_PRIO_INHERIT 		 8
#define PKI_THREAD_PRIO_PROTECT 		 16
#define PKI_THREAD_PRIO_MULT 			 32

#define PKI_THREAD_PROCESS_SHARED 		 0
#define PKI_THREAD_PROCESS_PRIVATE 		 1

#else
/* Pthread lib include */
  #include <pthread.h>

#ifdef __LIB_BUILD__
# ifndef HAVE_PTHREAD_RWLOCK
  typedef struct pthread_rwlock_t
  {
    pthread_cond_t cond_var;
    pthread_mutex_t lock_mutex;
    pthread_mutex_t data_mutex;

    uint64_t n_readers;
    uint64_t n_writers;
    uint64_t n_writers_waiting;
  } PKI_RWLOCK;
# else
  typedef pthread_rwlock_t PKI_RWLOCK;
# endif
#else
  typedef pthread_rwlock_t PKI_RWLOCK;
#endif

  typedef pthread_mutex_t PKI_MUTEX;
  typedef pthread_cond_t PKI_COND;

  typedef pthread_t PKI_THREAD;

  typedef pthread_attr_t PKI_THREAD_ATTR;
  typedef pthread_t PKI_THREAD_ID;

#define PKI_THREAD_CREATE_JOINABLE 		PTHREAD_CREATE_JOINABLE 
#define PKI_THREAD_CREATE_DETACHED 		PTHREAD_CREATE_DETACHED 

#define PKI_THREAD_EXPLICT_SCHED 		PTHREAD_EXPLICT_SCHED 
#define PKI_THREAD_INHERIT_SCHED 		PTHREAD_INHERIT_SCHED 

#define PKI_THREAD_SCOPE_PROCESS 		PTHREAD_SCOPE_PROCESS 
#define PKI_THREAD_SCOPE_SYSTEM 		PTHREAD_SCOPE_SYSTEM 

#define PKI_THREAD_DESTRUCTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS 

#define PKI_THREAD_PRIO_NONE 			PTHREAD_PRIO_NONE 
#define PKI_THREAD_PRIO_INHERIT 		PTHREAD_PRIO_INHERIT 
#define PKI_THREAD_PRIO_PROTECT 		PTHREAD_PRIO_PROTECT 
#define PKI_THREAD_PRIO_MULT 			PTHREAD_PRIO_MULT 

#define PKI_THREAD_PROCESS_SHARED 		PTHREAD_PROCESS_SHARED 
#define PKI_THREAD_PROCESS_PRIVATE 		PTHREAD_PROCESS_PRIVATE 

#endif /* LIBPKI_OS_WIN */

# endif /* LIBPKI_OS_WIN */

#endif /* _LIBPKI_SYSTEM_H */
