/* libpki/support.h */
/*
 * LibPKI - Easy-to-use PKI library
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2006-2007
 *
 * Copyright (c) 2001-2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef _LIBPKI_SUPPORT_H
#define _LIBPKI_SUPPORT_H

#include <sys/types.h>
#include <unistd.h>

#define	BUFF_MAX_SIZE	2048

/* Functions */

char * get_env_string(const char *str);

char * PKI_get_env(const char * name);

int PKI_set_env(const char * name,
		        const char * value);

/*!
 * @brief Compares two strings
 *
 * This function compares two strings and returns 0 if they are equal.
 * The comparison can be limited to the first n characters of the strings
 * by setting n to a value greater than 0. When set to 0, the comparison
 * is performed on the whole strings (and the size of the strings will
 * also be checked to be equal).
 * 
 * If the nocase flag is set, the comparison is case insensitive.
 * 
 * @param st1 The first string
 * @param st2 The second string
 * @param n Compare only the first n characters
 * @param nocase Set to non-zero for case insensitive comparisons
 * @return [int] 0 if the strings are equal, non-zero otherwise
 */
int str_cmp_ex(const char * st1,
		   	   const char * st2,
		   	   int          n,
		   	   int          nocase);

int strcmp_nocase(const char * st1,
		          const char * st2);

int strncmp_nocase(const char * st1,
		           const char * st2,
				   int          n);

const char * strstr_nocase(const char * buf,
		                   const char * string);

#endif /* _LIBPKI_SUPPORT_H */

