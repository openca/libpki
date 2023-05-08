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

#ifndef _LIBPKI_PKI_MEM_TYPES_H
#define _LIBPKI_PKI_MEM_TYPES_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_STACK_TYPES_H
#include <libpki/stack_types.h>
#endif

// =================================
// PKI_MEM data structure definition
// =================================

/*! \brief PKI_MEM is a generic data wrapper used for encoding or decoding */
typedef struct pki_mem_st {
	unsigned char * data;
	// size_t current;
	size_t size;
} PKI_MEM;

// ========================
// PKI_MEM Stack Definition
// ========================

//! \brief PKI_MEM_STACK is the STACK of PKI_MEM
#define PKI_MEM_STACK 				PKI_STACK

/* define for PKI_MEM stacks - implement object type casting */
#define PKI_STACK_MEM_new() (PKI_MEM_STACK *) PKI_STACK_new((void (*)(void *))PKI_MEM_free)
#define PKI_STACK_MEM_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_MEM_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_MEM_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_MEM_pop(p) (PKI_MEM *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_MEM_get_num(p,n) (PKI_MEM *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_MEM_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_MEM_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_MEM_elements(p) PKI_STACK_elements((PKI_STACK *)p)


#endif
