/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
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

/* Functions prototypes*/

#ifndef _LIBPKI_PKI_MEMORY_H
#define _LIBPKI_PKI_MEMORY_H

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

/* Function prototypes */

void *PKI_Malloc( size_t size );
void PKI_Free( void *ret );
void PKI_ZFree ( void *pnt, size_t size );
void PKI_ZFree_str ( char *str );

#endif
