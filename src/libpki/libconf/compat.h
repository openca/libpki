/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_COMPAT_H
#define _LIBPKI_COMPAT_H

// Basic Definitions for return codes
#define PKI_ERR					0
#define PKI_OK					1

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

/* This is to enable support for -fsanitize=address extra checks */
#if defined(__clang__) || defined (__GNUC__)
# define ATTRIBUTE_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#else
# define ATTRIBUTE_NO_SANITIZE_ADDRESS
#endif

#endif // End of _LIBPKI_COMPAT_H
