/* OpenCA libpki package
* (c) 2000-2010 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_OS_H
# define _LIBPKI_OS_H  1

# include <sys/param.h>
# include <sys/types.h>
# include <unistd.h>

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
#   define LIBPKI_OS_BITS    LIBPKI_OS32
#  endif
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

# endif // LIBPKI_OS_CLASS

#endif /* _LIBPKI_OS_H */
