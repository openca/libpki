/* src/libpki/libconf/defines.h.  Generated from defines.h.in by configure.  */
/* src/libpki/libconf/defines.h.in.  Generated from configure.ac by autoheader.  */

/* Forces 32bits builds */
/* #undef ENABLE_ARCH_32 */

/* Forces 64bits builds */
#define ENABLE_ARCH_64 1

/* Composite Crypto Native OpenSSL Support */
/* #undef ENABLE_COMPOSITE */

/* ECC Support for OpenSSL */
#define ENABLE_ECDSA 1

/* OPENSSL */
#define ENABLE_OPENSSL 1

/* Open Quantum Safe Library */
/* #undef ENABLE_OQS */

/* Open Quantum Safe Library */
/* #undef ENABLE_OQSPROV */

/* Define to 1 if you have the `bzero' function. */
#define HAVE_BZERO 1

/* Calloc in C library */
#define HAVE_CALLOC 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* GCC pragma ignored */
#define HAVE_GCC_PRAGMA_IGNORED 1

/* GCC pragma pop */
#define HAVE_GCC_PRAGMA_POP 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* HAVE LDAP */
#define HAVE_LDAP 1

/* PTHREAD Library */
#define HAVE_LIBPTHREAD 1

/* DNS Library */
#define HAVE_LIBRESOLV 1

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* test "${enablemysql}" = "yes" */
/* #undef HAVE_MYSQL */

/* test "${enablepg}" = "yes" */
/* #undef HAVE_PG */

/* PKCS11 */
/* #undef HAVE_PKCS11 */

/* HAVE_PTHREAD_RWLOCK */
#define HAVE_PTHREAD_RWLOCK 1

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* LIBXML2 */
#define HAVE_XML2 1

/* HAVE OPENLDAP */
#define LDAP_VENDOR_OPENLDAP 1

/* HAVE SUN LDAP */
/* #undef LDAP_VENDOR_SUN */

/* BSD */
/* #undef LIBPKI_TARGET_BSD */

/* HP-UX */
/* #undef LIBPKI_TARGET_HPUX */

/* IPHONE */
/* #undef LIBPKI_TARGET_IPHONE */

/* Linux */
#define LIBPKI_TARGET_LINUX 1

/* OSX */
/* #undef LIBPKI_TARGET_OSX */

/* Solaris */
/* #undef LIBPKI_TARGET_SOLARIS */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libpki"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libpki-users@lists.sourceforge.net"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libpki"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libpki 0.9.9"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libpki"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.9.9"

/* Define to 1 if all of the C90 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#define STDC_HEADERS 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Version number of package */
#define VERSION "0.9.9"

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define as a signed integer type capable of holding a process identifier. */
/* #undef pid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
