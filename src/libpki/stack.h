/* src/stack.h */
/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA Licensed Software
 *
 * Copyright (c) 2001-2006 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef _LIBPKI_STACK_H
#define _LIBPKI_STACK_H

#ifndef _LIBPKI_STACK_TYPES_H
#include <libpki/stack_types.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

/* ----------------------- STACK Function prototypes --------------------- */

PKI_STACK * PKI_STACK_new( void (*)(void *) );
PKI_STACK * PKI_STACK_new_type ( PKI_DATATYPE type );
PKI_STACK * PKI_STACK_new_null( void );

int     PKI_STACK_free ( PKI_STACK * st );
int     PKI_STACK_free_all ( PKI_STACK * st );

int     PKI_STACK_elements ( PKI_STACK *st );

int     PKI_STACK_push ( PKI_STACK *st, void *obj );

void  * PKI_STACK_pop ( PKI_STACK *st );
int     PKI_STACK_pop_free ( PKI_STACK *st );

void  * PKI_STACK_get_num ( PKI_STACK *st, int num );
void  * PKI_STACK_del_num ( PKI_STACK *st, int num );
int     PKI_STACK_ins_num ( PKI_STACK *st, int num, void *obj );

/* END of _PKI_STACK_H */
#endif


