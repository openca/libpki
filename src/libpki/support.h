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

char * get_env_string ( const char *str );

char * PKI_get_env ( char * name );
int PKI_set_env ( char *name, char *value );

int strcmp_nocase( char *st1, char *st2);
int strncmp_nocase( char *st1, char *st2, int n);
char * strstr_nocase ( char *buf, char *string );

#endif /* _LIBPKI_SUPPORT_H */

