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

#ifndef HEADER_SAFESTACK_H
#include <openssl/safestack.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

/*!
 * \brief Data structure for PKI_STACK nodes (INTERNAL ONLY)
 */
typedef struct pki_stack_node_st {
	struct pki_stack_node_st *next;
	struct pki_stack_node_st *prev;

	void *data;
} PKI_STACK_NODE;

/*!
 * \brief Data structure for PKI_STACK
 *
 * The PKI_STACK is the basic structure for storing a stack of generic
 * elements. Fields SHOULD NOT be accessed directly, instead specific
 * PKI_STACK_new(), PKI_STACK_free(), etc... functions exist that take
 * care about details and initialization of the structure.
 */
typedef struct pki_stack_st {
	/*!  \brief Number of elements in the PKI_STACK */
	int elements;

	/*! \brief Pointer to the first node of the PKI_STACK */
	PKI_STACK_NODE *head;
	/*! \brief Pointer to the last node of the PKI_STACK */
	PKI_STACK_NODE *tail;

	/*! \brief Pointer to the function called to free the data object */
	void (*free)( void *);
} PKI_STACK;


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

#define PKI_STACK_ERR		PKI_ERR
#define PKI_STACK_OK		PKI_OK

#define PKI_MEM_STACK 				PKI_STACK
#define PKI_X509_STACK				PKI_STACK
#define PKI_X509_KEYPAIR_STACK 		PKI_STACK
#define PKI_X509_CERT_STACK			PKI_STACK
#define PKI_X509_REQ_STACK 			PKI_STACK
#define PKI_X509_CRL_STACK  		PKI_STACK
#define PKI_X509_XPAIR_STACK 		PKI_STACK
#define PKI_X509_PROFILE_STACK 		PKI_STACK
#define PKI_X509_EXTENSION_STACK 	PKI_STACK
#define PKI_X509_CRL_ENTRY_STACK 	PKI_STACK
#define PKI_X509_CRL_STACK 			PKI_STACK
#define PKI_CONFIG_STACK 			PKI_STACK
#define PKI_CONFIG_ELEMENT_STACK	PKI_STACK
#define PKI_OID_STACK				PKI_STACK
#define PKI_ID_INFO_STACK			PKI_STACK
#define PKI_TOKEN_STACK				PKI_STACK
#define PKI_X509_OCSP_REQ_STACK		PKI_STACK
#define PKI_X509_OCSP_RESP_STACK	PKI_STACK

#define PKI_RESOURCE_IDENTIFIER_STACK		PKI_STACK
#define PKI_RESOURCE_RESPONSE_TOKEN_STACK	PKI_STACK


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

/* define for X509 stacks - implement object type casting */
#define PKI_STACK_X509_new() (PKI_X509_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_free)
#define PKI_STACK_X509_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_pop(p) (PKI_X509 *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_get_num(p,n) \
		(PKI_X509 *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_ins_num(p,n,obj) \
		PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_del_num(p,n) \
		PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for X509_CERT (certs) stacks - implement object type casting */
#define PKI_STACK_X509_CERT_new() (PKI_X509_CERT_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CERT_free)
#define PKI_STACK_X509_CERT_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_CERT_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_CERT_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_CERT_pop(p) (PKI_X509_CERT *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_CERT_get_num(p,n) (PKI_X509_CERT *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_CERT_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_CERT_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_CERT_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for X509_REQ (requests) stacks - implement object type casting */
#define PKI_STACK_X509_REQ_new() (PKI_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_REQ_free)
#define PKI_STACK_X509_REQ_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_REQ_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_REQ_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_REQ_pop(p) (PKI_X509_REQ *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_REQ_get_num(p,n) (PKI_X509_REQ *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_REQ_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_REQ_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_REQ_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for X509_PROFILE stacks - implement object type casting */
#define PKI_STACK_X509_PROFILE_new() (PKI_X509_PROFILE_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_PROFILE_free)
#define PKI_STACK_X509_PROFILE_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_PROFILE_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_PROFILE_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_PROFILE_pop(p) (PKI_X509_PROFILE *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_PROFILE_get_num(p,n) (PKI_X509_PROFILE *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_PROFILE_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_PROFILE_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_PROFILE_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for X509_EXTENSION stacks - implement object type casting */
#define PKI_STACK_X509_EXTENSION_new() (PKI_X509_EXTENSION_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_EXTENSION_free)
#define PKI_STACK_X509_EXTENSION_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_EXTENSION_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_EXTENSION_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_EXTENSION_pop(p) (PKI_X509_EXTENSION *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_EXTENSION_get_num(p,n) (PKI_X509_EXTENSION *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_EXTENSION_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_EXTENSION_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_EXTENSION_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_STACK_X509_CRL_ENTRY stacks - implement object type casting */
#define PKI_STACK_X509_CRL_ENTRY_new() (PKI_X509_CRL_ENTRY_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CRL_ENTRY_free)
#define PKI_STACK_X509_CRL_ENTRY_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_CRL_ENTRY_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_CRL_ENTRY_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_CRL_ENTRY_pop(p) (PKI_X509_CRL_ENTRY *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_CRL_ENTRY_get_num(p,n) (PKI_X509_CRL_ENTRY *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_CRL_ENTRY_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_CRL_ENTRY_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_CRL_ENTRY_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_X509_CRL stacks - implement object type casting */
#define PKI_STACK_X509_CRL_new(a) (PKI_X509_CRL_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CRL_free_void)
#define PKI_STACK_X509_CRL_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_CRL_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_CRL_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_CRL_pop(p) (PKI_X509_CRL *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_CRL_get_num(p,n) (PKI_X509_CRL *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_CRL_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_CRL_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_CRL_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for CONFIG (configs) stacks - implement object type casting */
#define PKI_STACK_CONFIG_new() (PKI_CONFIG_STACK *) PKI_STACK_new((void (*)(void *))PKI_CONFIG_free)
#define PKI_STACK_CONFIG_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_CONFIG_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_CONFIG_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_CONFIG_pop(p) (PKI_CONFIG *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_CONFIG_get_num(p,n) (PKI_CONFIG *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_CONFIG_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_CONFIG_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_CONFIG_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for CONFIG_ELEMENT stacks - implement object type casting */
// #define PKI_STACK_CONFIG_ELEMENT_new() (PKI_CONFIG_ELEMENT_STACK *) PKI_STACK_new((void (*)(void *))xmlFreeNode)
#define PKI_STACK_CONFIG_ELEMENT_new() (PKI_CONFIG_ELEMENT_STACK *) PKI_STACK_new(NULL)
#define PKI_STACK_CONFIG_ELEMENT_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_CONFIG_ELEMENT_free_all( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_CONFIG_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_CONFIG_ELEMENT_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_CONFIG_ELEMENT_pop(p) (PKI_CONFIG_ELEMENT *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_CONFIG_ELEMENT_get_num(p,n) (PKI_CONFIG_ELEMENT *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_CONFIG_ELEMENT_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_CONFIG_ELEMENT_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_CONFIG_ELEMENT_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_OID stacks - implement object type casting */
#define PKI_STACK_OID_new() (PKI_OID_STACK *) PKI_STACK_new((void (*)(void *))PKI_OID_free)
#define PKI_STACK_OID_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_OID_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_OID_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_OID_pop(p) (PKI_OID *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_OID_get_num(p,n) (PKI_OID *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_OID_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_OID_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_OID_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_ID_INFO stacks - implement object type casting */
#define PKI_STACK_INFO_ID_new() (PKI_ID_INFO_STACK *) PKI_STACK_new((void (*)(void *))PKI_STACK_INFO_ID_free)
#define PKI_STACK_INFO_ID_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_INFO_ID_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_INFO_ID_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_INFO_ID_pop(p) (PKI_ID_INFO*) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_INFO_ID_get_num(p,n) (PKI_ID_INFO*) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_INFO_ID_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_INFO_ID_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_INFO_ID_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_TOKEN stacks - implement object type casting */
#define PKI_STACK_TOKEN_new() (PKI_TOKEN_STACK *) PKI_STACK_new((void (*)(void *))PKI_TOKEN_free)
#define PKI_STACK_TOKEN_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_TOKEN_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_TOKEN_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_TOKEN_pop(p) (PKI_TOKEN *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_TOKEN_get_num(p,n) (PKI_TOKEN *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_TOKEN_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_TOKEN_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_TOKEN_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PKI_X509_KEYPAIR stacks - implement object type casting */
#define PKI_STACK_X509_KEYPAIR_new() (PKI_X509_KEYPAIR_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_KEYPAIR_free)
#define PKI_STACK_X509_KEYPAIR_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_KEYPAIR_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_KEYPAIR_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_KEYPAIR_pop(p) (PKI_X509_KEYPAIR *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_KEYPAIR_get_num(p,n) (PKI_X509_KEYPAIR *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_KEYPAIR_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_KEYPAIR_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_KEYPAIR_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for X509_XPAIR (crossCertPair) stacks - object type casting */
#define PKI_STACK_X509_XPAIR_new() (PKI_X509_XPAIR_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_XPAIR_free)
#define PKI_STACK_X509_XPAIR_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_XPAIR_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_XPAIR_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_XPAIR_pop(p) (PKI_X509_XPAIR *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_XPAIR_get_num(p,n) (PKI_X509_XPAIR *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_XPAIR_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_XPAIR_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_XPAIR_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for OCSP_REQ (ocsp requests) stacks - object type casting */
#define PKI_STACK_OCSP_REQ_new() (PKI_X509_OCSP_REQ_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_OCSP_REQ_free)
#define PKI_STACK_OCSP_REQ_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_OCSP_REQ_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_OCSP_REQ_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_OCSP_REQ_pop(p) (PKI_X509_OCSP_REQ *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_OCSP_REQ_get_num(p,n) (PKI_X509_OCSP_REQ *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_OCSP_REQ_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_OCSP_REQ_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_OCSP_REQ_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for OCSP_RESP (ocsp responses) stacks - object type casting */
#define PKI_STACK_OCSP_RESP_new() (PKI_X509_OCSP_RESP_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_OCSP_RESP_free)
#define PKI_STACK_OCSP_RESP_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_OCSP_RESP_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_OCSP_RESP_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_OCSP_RESP_pop(p) (PKI_X509_OCSP_RESP *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_OCSP_RESP_get_num(p,n) (PKI_X509_OCSP_RESP *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_OCSP_RESP_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_OCSP_RESP_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_OCSP_RESP_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* END of _PKI_STACK_H */
#endif


