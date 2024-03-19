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

#ifndef _LIBPKI_STACK_UTILS_ST_H
#define _LIBPKI_STACK_UTILS_ST_H
# pragma once

#include <libpki/compat.h>

#ifndef HEADER_SAFESTACK_H
#include <openssl/safestack.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

BEGIN_C_DECLS

// Forward Declarations for the PKI_STACK structure
typedef struct pki_stack_node_st    PKI_STACK_NODE;
typedef struct pki_stack_st         PKI_STACK;

#define DECLARE_OSSL_STACK_FN(TYPE) \
typedef TYPE TYPE##_STACK; \
inline TYPE##_STACK *TYPE##_STACK_new() { return (TYPE##_STACK *)sk_##TYPE##_new_null(); } \
inline TYPE##_STACK *TYPE##_STACK_new_null() { return (TYPE##_STACK *)sk_##TYPE##_new_null(); } \
inline void  TYPE##_STACK_free(stack_st_##TYPE *sk) { sk_##TYPE##_free(sk); } \
inline int   TYPE##_STACK_push(stack_st_##TYPE *sk, TYPE * val) { return sk_##TYPE##_push(sk, val); } \
inline TYPE *TYPE##_STACK_pop(stack_st_##TYPE *sk) { return sk_##TYPE##_pop(sk); } \
inline void  TYPE##_STACK_pop_free(stack_st_##TYPE *sk) { return sk_##TYPE##_pop_free(sk, TYPE##_free); } \
inline int   TYPE##_STACK_num(stack_st_##TYPE *sk) { return sk_##TYPE##_num(sk); } \
inline TYPE *TYPE##_STACK_value(stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline int   TYPE##_STACK_add(stack_st_##TYPE *sk, TYPE * value, int num) { return sk_##TYPE##_insert(sk, value, num); } \
inline void  TYPE##_STACK_del(stack_st_##TYPE *sk, int num) { return TYPE##_free(sk_##TYPE##_delete(sk, num)); } \
inline TYPE *TYPE##_STACK_get0(stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline void  TYPE##_STACK_clear(stack_st_##TYPE *sk) { for( ; sk_##TYPE##_num(sk) > 0 ; ) TYPE##_free(sk_##TYPE##_pop(sk)); }

#define DECLARE_OSSL_STACK_FN_EX(TYPE, st) \
typedef struct st TYPE##_STACK; \
inline struct st *TYPE##_STACK_new() { return (struct st *)sk_##TYPE##_new_null(); } \
inline struct st *TYPE##_STACK_new_null() { return (struct st *)sk_##TYPE##_new_null(); } \
inline void  TYPE##_STACK_free(TYPE *sk) { sk_##TYPE##_free(sk); } \
inline int   TYPE##_STACK_push(struct stack_st_##TYPE *sk, TYPE * val) { return sk_##TYPE##_push(sk, val); } \
inline struct st *TYPE##_STACK_pop(struct stack_st_##TYPE *sk) { return sk_##TYPE##_pop(sk); } \
inline void  TYPE##_STACK_pop_free(struct stack_st_##TYPE *sk) { return sk_##TYPE##_pop_free(sk, TYPE##_free); } \
inline int   TYPE##_STACK_num(struct stack_st_##TYPE *sk) { return sk_##TYPE##_num(sk); } \
inline struct st *TYPE##_STACK_value(struct stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline int   TYPE##_STACK_add(struct stack_st_##TYPE *sk, TYPE * value, int num) { return sk_##TYPE##_insert(sk, value, num); } \
inline void  TYPE##_STACK_del(struct stack_st_##TYPE *sk, int num) { return TYPE##_free(sk_##TYPE##_delete(sk, num)); } \
inline struct st *TYPE##_STACK_get0(struct stack_st_##TYPE *sk, int num) { return sk_##TYPE##_value(sk, num); } \
inline void  TYPE##_STACK_clear(struct stack_st_##TYPE *sk) { for( ; sk_##TYPE##_num(sk) > 0 ; ) TYPE##_free(sk_##TYPE##_pop(sk)); }

#define DECLARE_OSSL_STACK_FN_DUP(TYPE) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, TYPE##_dup, TYPE##_free); }

#define DECLARE_STACK_FN_DUP_EX(TYPE, dup_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, dup_func, TYPE##_free); }

#define DECLARE_STACK_FN_DUP_EX_FREE(TYPE, dup_func, free_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_dup(sk, dup_func, free_func); }

#define DECLARE_OSSL_STACK_FN_DEEP_COPY(TYPE) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, TYPE##_dup, TYPE##_free); }

#define DECLARE_OSSL_STACK_FN_DEEP_COPY_EX(TYPE, dup_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, dup_func, TYPE##_free); }

#define DECLARE_OSSL_STACK_FN_DEEP_COPY_EX_FREE(TYPE, dup_func, free_func) \
    DECLARE_OSSL_STACK_FN(TYPE) \
    inline TYPE##_STACK *TYPE##_STACK_dup(struct stack_st_##TYPE *sk) { return sk_##TYPE##_deep_copy(sk, dup_func, free_func); }

#define DECLARE_LIBPKI_STACK_FN(TYPE) \
typedef struct pki_stack_st TYPE##_STACK; \
inline TYPE##_STACK * TYPE##_STACK_new() { return (TYPE##_STACK *)PKI_STACK_new((void (*)(void *))NULL); } \
inline TYPE##_STACK * TYPE##_STACK_new_null() { return (TYPE##_STACK *)PKI_STACK_new_null(); } \
inline void    TYPE##_STACK_free(TYPE##_STACK *sk) { PKI_STACK_free((TYPE##_STACK *)sk); return; } \
inline void    TYPE##_STACK_free_all(TYPE##_STACK *sk) { PKI_STACK_free_all((TYPE##_STACK *)sk); return; } \
inline void    TYPE##_STACK_free_all_ex(TYPE##_STACK *sk, void (*free_func)(void *)) { for( ; PKI_STACK_elements(sk) > 0 ; ) { TYPE##_free((TYPE *)PKI_STACK_pop((TYPE##_STACK *)sk)); } ; PKI_STACK_free((TYPE##_STACK *)sk); } \
inline int     TYPE##_STACK_push(TYPE##_STACK *sk, TYPE * val) { return PKI_STACK_push((TYPE##_STACK *)sk, (void *)val); } \
inline TYPE  * TYPE##_STACK_pop(TYPE##_STACK *sk) { return PKI_STACK_pop((TYPE##_STACK *)sk); } \
inline void    TYPE##_STACK_pop_free(TYPE##_STACK *sk) { PKI_STACK_free_all_ex((TYPE##_STACK *)sk, (void (*)(void *))TYPE##_free); } \
inline int     TYPE##_STACK_num(TYPE##_STACK  *sk) { return PKI_STACK_elements((TYPE##_STACK *)sk); } \
inline TYPE  * TYPE##_STACK_value(TYPE##_STACK  *sk, int num) { return PKI_STACK_get_num((TYPE##_STACK *)sk, num); } \
inline int     TYPE##_STACK_add(TYPE##_STACK  *sk, TYPE *obj, int num) { return PKI_STACK_ins_num((TYPE##_STACK *)sk, num, (void *)obj); } \
inline void    TYPE##_STACK_del(TYPE##_STACK  *sk, int num) { return TYPE##_free(PKI_STACK_del_num((TYPE##_STACK *)sk, num)); } \
inline TYPE  * TYPE##_STACK_get0(TYPE##_STACK  *sk, int num) { return PKI_STACK_get_num((TYPE##_STACK *)sk, num); } \
inline void    TYPE##_STACK_clear(TYPE##_STACK  *sk) { for( ; PKI_STACK_elements(sk) > 0 ; ) TYPE##_free((TYPE *)PKI_STACK_pop((TYPE##_STACK *)sk)); }

#define DECLARE_LIBPKI_STACK_FN_DUP(TYPE) \
    DECLARE_LIBPKI_STACK_FN(TYPE) \
    inline TYPE##_STACK * TYPE##_STACK_dup(TYPE##_STACK  *sk) { return TYPE##_dup(sk); }

#define DECLARE_LIBPKI_STACK_FN_DUP_EX(TYPE, dup_func) \
    DECLARE_LIBPKI_STACK_FN(TYPE) \
    inline TYPE##_STACK * TYPE##_STACK_dup(TYPE##_STACK *sk) { return TYPE##_dup(sk); }

#define DECLARE_LIBPKI_STACK_FN_DUP_EX_FREE(TYPE, dup_func, free_func) \
    DECLARE_LIBPKI_STACK_FN(TYPE) \
    inline TYPE##_STACK * TYPE##_STACK_dup(TYPE##_STACK *sk) { return TYPE##_dup(sk); }


// #define PKI_MEM_STACK 				PKI_STACK
// #define PKI_X509_STACK				PKI_STACK
// #define PKI_X509_KEYPAIR_STACK 		PKI_STACK
// #define PKI_X509_CERT_STACK			PKI_STACK
// #define PKI_X509_REQ_STACK 			PKI_STACK
// #define PKI_X509_CRL_STACK  		PKI_STACK
// #define PKI_X509_XPAIR_STACK 		PKI_STACK
// #define PKI_X509_PROFILE_STACK 		PKI_STACK
// #define PKI_X509_EXTENSION_STACK 	PKI_STACK
// #define PKI_X509_CRL_ENTRY_STACK 	PKI_STACK
// #define PKI_X509_CRL_STACK 			PKI_STACK
// #define PKI_CONFIG_STACK 			PKI_STACK
// #define PKI_CONFIG_ELEMENT_STACK	PKI_STACK
// #define PKI_OID_STACK				PKI_STACK
// #define PKI_ID_INFO_STACK			PKI_STACK
// #define PKI_TOKEN_STACK				PKI_STACK
// #define PKI_X509_OCSP_REQ_STACK		PKI_STACK
// #define PKI_X509_OCSP_RESP_STACK	PKI_STACK

// #define PKI_RESOURCE_IDENTIFIER_STACK		PKI_STACK
// #define PKI_RESOURCE_RESPONSE_TOKEN_STACK	PKI_STACK


// /* define for PKI_MEM stacks - implement object type casting */
// #define PKI_STACK_MEM_new() (PKI_MEM_STACK *) PKI_STACK_new((void (*)(void *))PKI_MEM_free)
// #define PKI_STACK_MEM_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_MEM_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_MEM_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_MEM_pop(p) (PKI_MEM *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_MEM_get_num(p,n) (PKI_MEM *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_MEM_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_MEM_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_MEM_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509 stacks - implement object type casting */
// #define PKI_STACK_X509_new() (PKI_X509_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_free)
// #define PKI_STACK_X509_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_pop(p) (PKI_X509 *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_get_num(p,n) \
// 		(PKI_X509 *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_ins_num(p,n,obj) \
// 		PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_del_num(p,n) \
// 		PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509_CERT (certs) stacks - implement object type casting */
// #define PKI_STACK_X509_CERT_new() (PKI_X509_CERT_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CERT_free)
// #define PKI_STACK_X509_CERT_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CERT_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CERT_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_CERT_pop(p) (PKI_X509_CERT *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_CERT_get_num(p,n) (PKI_X509_CERT *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_CERT_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_CERT_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_CERT_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509_REQ (requests) stacks - implement object type casting */
// #define PKI_STACK_X509_REQ_new() (PKI_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_REQ_free)
// #define PKI_STACK_X509_REQ_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_REQ_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_REQ_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_REQ_pop(p) (PKI_X509_REQ *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_REQ_get_num(p,n) (PKI_X509_REQ *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_REQ_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_REQ_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_REQ_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509_PROFILE stacks - implement object type casting */
// #define PKI_STACK_X509_PROFILE_new() (PKI_X509_PROFILE_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_PROFILE_free)
// #define PKI_STACK_X509_PROFILE_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_PROFILE_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_PROFILE_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_PROFILE_pop(p) (PKI_X509_PROFILE *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_PROFILE_get_num(p,n) (PKI_X509_PROFILE *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_PROFILE_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_PROFILE_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_PROFILE_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509_EXTENSION stacks - implement object type casting */
// #define PKI_STACK_X509_EXTENSION_new() (PKI_X509_EXTENSION_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_EXTENSION_free)
// #define PKI_STACK_X509_EXTENSION_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_EXTENSION_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_EXTENSION_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_EXTENSION_pop(p) (PKI_X509_EXTENSION *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_EXTENSION_get_num(p,n) (PKI_X509_EXTENSION *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_EXTENSION_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_EXTENSION_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_EXTENSION_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_STACK_X509_CRL_ENTRY stacks - implement object type casting */
// #define PKI_STACK_X509_CRL_ENTRY_new() (PKI_X509_CRL_ENTRY_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CRL_ENTRY_free)
// #define PKI_STACK_X509_CRL_ENTRY_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CRL_ENTRY_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CRL_ENTRY_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_CRL_ENTRY_pop(p) (PKI_X509_CRL_ENTRY *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_CRL_ENTRY_get_num(p,n) (PKI_X509_CRL_ENTRY *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_CRL_ENTRY_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_CRL_ENTRY_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_CRL_ENTRY_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_X509_CRL stacks - implement object type casting */
// #define PKI_STACK_X509_CRL_new(a) (PKI_X509_CRL_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_CRL_free_void)
// #define PKI_STACK_X509_CRL_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CRL_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_CRL_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_CRL_pop(p) (PKI_X509_CRL *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_CRL_get_num(p,n) (PKI_X509_CRL *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_CRL_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_CRL_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_CRL_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for CONFIG (configs) stacks - implement object type casting */
// #define PKI_STACK_CONFIG_new() (PKI_CONFIG_STACK *) PKI_STACK_new((void (*)(void *))PKI_CONFIG_free)
// #define PKI_STACK_CONFIG_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_CONFIG_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_CONFIG_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_CONFIG_pop(p) (PKI_CONFIG *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_CONFIG_get_num(p,n) (PKI_CONFIG *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_CONFIG_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_CONFIG_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_CONFIG_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for CONFIG_ELEMENT stacks - implement object type casting */
// // #define PKI_STACK_CONFIG_ELEMENT_new() (PKI_CONFIG_ELEMENT_STACK *) PKI_STACK_new((void (*)(void *))xmlFreeNode)
// #define PKI_STACK_CONFIG_ELEMENT_new() (PKI_CONFIG_ELEMENT_STACK *) PKI_STACK_new(NULL)
// #define PKI_STACK_CONFIG_ELEMENT_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_CONFIG_ELEMENT_free_all( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_CONFIG_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_CONFIG_ELEMENT_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_CONFIG_ELEMENT_pop(p) (PKI_CONFIG_ELEMENT *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_CONFIG_ELEMENT_get_num(p,n) (PKI_CONFIG_ELEMENT *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_CONFIG_ELEMENT_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_CONFIG_ELEMENT_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_CONFIG_ELEMENT_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_OID stacks - implement object type casting */
// #define PKI_STACK_OID_new() (PKI_OID_STACK *) PKI_STACK_new((void (*)(void *))PKI_OID_free)
// #define PKI_STACK_OID_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_OID_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_OID_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_OID_pop(p) (PKI_OID *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_OID_get_num(p,n) (PKI_OID *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_OID_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_OID_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_OID_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_ID_INFO stacks - implement object type casting */
// #define PKI_STACK_INFO_ID_new() (PKI_ID_INFO_STACK *) PKI_STACK_new((void (*)(void *))PKI_STACK_INFO_ID_free)
// #define PKI_STACK_INFO_ID_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_INFO_ID_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_INFO_ID_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_INFO_ID_pop(p) (PKI_ID_INFO*) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_INFO_ID_get_num(p,n) (PKI_ID_INFO*) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_INFO_ID_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_INFO_ID_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_INFO_ID_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_TOKEN stacks - implement object type casting */
// #define PKI_STACK_TOKEN_new() (PKI_TOKEN_STACK *) PKI_STACK_new((void (*)(void *))PKI_TOKEN_free)
// #define PKI_STACK_TOKEN_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_TOKEN_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_TOKEN_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_TOKEN_pop(p) (PKI_TOKEN *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_TOKEN_get_num(p,n) (PKI_TOKEN *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_TOKEN_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_TOKEN_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_TOKEN_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for PKI_X509_KEYPAIR stacks - implement object type casting */
// #define PKI_STACK_X509_KEYPAIR_new() (PKI_X509_KEYPAIR_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_KEYPAIR_free)
// #define PKI_STACK_X509_KEYPAIR_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_KEYPAIR_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_KEYPAIR_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_KEYPAIR_pop(p) (PKI_X509_KEYPAIR *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_KEYPAIR_get_num(p,n) (PKI_X509_KEYPAIR *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_KEYPAIR_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_KEYPAIR_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_KEYPAIR_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for X509_XPAIR (crossCertPair) stacks - object type casting */
// #define PKI_STACK_X509_XPAIR_new() (PKI_X509_XPAIR_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_XPAIR_free)
// #define PKI_STACK_X509_XPAIR_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_X509_XPAIR_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_X509_XPAIR_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_X509_XPAIR_pop(p) (PKI_X509_XPAIR *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_X509_XPAIR_get_num(p,n) (PKI_X509_XPAIR *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_X509_XPAIR_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_X509_XPAIR_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_X509_XPAIR_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for OCSP_REQ (ocsp requests) stacks - object type casting */
// #define PKI_STACK_OCSP_REQ_new() (PKI_X509_OCSP_REQ_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_OCSP_REQ_free)
// #define PKI_STACK_OCSP_REQ_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_OCSP_REQ_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_OCSP_REQ_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_OCSP_REQ_pop(p) (PKI_X509_OCSP_REQ *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_OCSP_REQ_get_num(p,n) (PKI_X509_OCSP_REQ *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_OCSP_REQ_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_OCSP_REQ_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_OCSP_REQ_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// /* define for OCSP_RESP (ocsp responses) stacks - object type casting */
// #define PKI_STACK_OCSP_RESP_new() (PKI_X509_OCSP_RESP_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_OCSP_RESP_free)
// #define PKI_STACK_OCSP_RESP_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
// #define PKI_STACK_OCSP_RESP_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
// #define PKI_STACK_OCSP_RESP_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
// #define PKI_STACK_OCSP_RESP_pop(p) (PKI_X509_OCSP_RESP *) PKI_STACK_pop( (PKI_STACK *) p )
// #define PKI_STACK_OCSP_RESP_get_num(p,n) (PKI_X509_OCSP_RESP *) PKI_STACK_get_num( (PKI_STACK *)p, n)
// #define PKI_STACK_OCSP_RESP_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
// #define PKI_STACK_OCSP_RESP_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
// #define PKI_STACK_OCSP_RESP_elements(p) PKI_STACK_elements((PKI_STACK *)p)

END_C_DECLS

#endif // END of _LIBPKI_STACK_UTILS_ST_H


