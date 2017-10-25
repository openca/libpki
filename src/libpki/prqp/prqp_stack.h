/* PRQP Message implementation
 * (c) 2006 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPK_PRQP_STACK_H
#define _LIBPK_PRQP_STACK_H
                                                                                
#ifdef  __cplusplus
extern "C" {
#endif

#define PKI_X509_PRQP_REQ_STACK		PKI_STACK
#define PKI_X509_PRQP_RESP_STACK	PKI_STACK

/* Define Stacks for RESOURCE_IDENTIFIER, RESOURCE_RESPONSE_TOKEN and
   ASN1_IA5STRING */

/* RESOURCE_IDENTIFIER stack definitions */
/*
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
# define sk_RESOURCE_IDENTIFIER_new(st) SKM_sk_new(RESOURCE_IDENTIFIER, (st))
# define sk_RESOURCE_IDENTIFIER_new_null() SKM_sk_new(RESOURCE_IDENTIFIER, NULL)
# define sk_RESOURCE_IDENTIFIER_free(st) SKM_sk_free(RESOURCE_IDENTIFIER, (st))
# define sk_RESOURCE_IDENTIFIER_num(st) SKM_sk_num(RESOURCE_IDENTIFIER, (st))
# define sk_RESOURCE_IDENTIFIER_value(st, i) SKM_sk_value(RESOURCE_IDENTIFIER, (st), (i))
# define sk_RESOURCE_IDENTIFIER_push(st, val) SKM_sk_push(RESOURCE_IDENTIFIER, (st), (val))
# define sk_RESOURCE_IDENTIFIER_dup(st) SKM_sk_dup(RESOURCE_IDENTIFIER, st)
# define sk_RESOURCE_IDENTIFIER_pop_free(st, free_func) SKM_sk_pop_free(RESOURCE_IDENTIFIER, (st), (free_func))
# define sk_RESOURCE_IDENTIFIER_pop(st) SKM_sk_pop(RESOURCE_IDENTIFIER, (st))
#endif
*/

/* define for PRQP's RESOURCE_IDENTIFIER stacks - implement object type
 * casting */
#define PKI_STACK_RESOURCE_IDENTIFIER_new_null() (PKI_RESOURCE_IDENTIFIER_STACK *) PKI_STACK_new( NULL )
#define PKI_STACK_RESOURCE_IDENTIFIER_new() (PKI_RESOURCE_IDENTIFIER_STACK *) PKI_STACK_new(PKI_RESOURCE_IDENTIFIER_free_void)
#define PKI_STACK_RESOURCE_IDENTIFIER_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_RESOURCE_IDENTIFIER_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_RESOURCE_IDENTIFIER_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_RESOURCE_IDENTIFIER_pop(p) (RESOURCE_IDENTIFIER *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_RESOURCE_IDENTIFIER_get_num(p,n) (RESOURCE_IDENTIFIER *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_RESOURCE_IDENTIFIER_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_RESOURCE_IDENTIFIER_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_RESOURCE_IDENTIFIER_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* RESOURCE_RESPONSE_TOKEN stack definitions */
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
# define sk_RESOURCE_RESPONSE_TOKEN_new(st) SKM_sk_new(RESOURCE_RESPONSE_TOKEN, (st))
# define sk_RESOURCE_RESPONSE_TOKEN_new_null() SKM_sk_new_null(RESOURCE_RESPONSE_TOKEN)
# define sk_RESOURCE_RESPONSE_TOKEN_free(st) SKM_sk_free(RESOURCE_RESPONSE_TOKEN, (st))
# define sk_RESOURCE_RESPONSE_TOKEN_num(st) SKM_sk_num(RESOURCE_RESPONSE_TOKEN, (st))
# define sk_RESOURCE_RESPONSE_TOKEN_value(st, i) SKM_sk_value(RESOURCE_RESPONSE_TOKEN, (st), (i))
# define sk_RESOURCE_RESPONSE_TOKEN_push(st, val) SKM_sk_push(RESOURCE_RESPONSE_TOKEN, (st), (val))
# define sk_RESOURCE_RESPONSE_TOKEN_dup(st) SKM_sk_dup(RESOURCE_RESPONSE_TOKEN, st)
# define sk_RESOURCE_RESPONSE_TOKEN_pop_free(st, free_func) SKM_sk_pop_free(RESOURCE_RESPONSE_TOKEN, (st), (free_func))
# define sk_RESOURCE_RESPONSE_TOKEN_pop(st) SKM_sk_pop(RESOURCE_RESPONSE_TOKEN, (st))
#endif

/* define for PRQP's RESOURCE_RESPONSE_TOKEN stacks - implement object type
 * casting */
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_new_null() (PKI_RESOURCE_RESPONSE_TOKEN_STACK *) PKI_STACK_new( NULL )
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_new() (PKI_RESOURCE_RESPONSE_TOKEN_STACK *) PKI_STACK_new(PKI_RESOURCE_RESPONSE_TOKEN_free_void)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_pop(p) (RESOURCE_RESPONSE_TOKEN *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_get_num(p,n) (RESOURCE_RESPONSE_TOKEN *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_RESOURCE_RESPONSE_TOKEN_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* RESOURCE_INFO stack definitions */
/* @DEPRECATED/REMOVED
# define sk_RESOURCE_INFO_new(st) SKM_sk_new(RESOURCE_INFO, (st))
# define sk_RESOURCE_INFO_new_null() SKM_sk_new_null(RESOURCE_INFO)
# define sk_RESOURCE_INFO_free(st) SKM_sk_free(RESOURCE_INFO, (st))
# define sk_RESOURCE_INFO_num(st) SKM_sk_num(RESOURCE_INFO, (st))
# define sk_RESOURCE_INFO_value(st, i) SKM_sk_value(RESOURCE_INFO, (st), (i))
# define sk_RESOURCE_INFO_push(st, val) SKM_sk_push(RESOURCE_INFO, (st), (val))
# define sk_RESOURCE_INFO_dup(st) SKM_sk_dup(RESOURCE_INFO, st)
# define sk_RESOURCE_INFO_pop_free(st, free_func) SKM_sk_pop_free(RESOURCE_INFO, (st), (free_func))
# define sk_RESOURCE_INFO_pop(st) SKM_sk_pop(RESOURCE_INFO, (st))
*/

/* ASN1_IA5STRING stack definitions */
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
DEFINE_STACK_OF(ASN1_IA5STRING)
#else
# define sk_ASN1_IA5STRING_new(st) SKM_sk_new(ASN1_IA5STRING, (st))
# define sk_ASN1_IA5STRING_new_null() SKM_sk_new_null(ASN1_IA5STRING)
# define sk_ASN1_IA5STRING_free(st) SKM_sk_free(ASN1_IA5STRING, (st))
# define sk_ASN1_IA5STRING_num(st) SKM_sk_num(ASN1_IA5STRING, (st))
# define sk_ASN1_IA5STRING_value(st, i) SKM_sk_value(ASN1_IA5STRING, (st), (i))
# define sk_ASN1_IA5STRING_push(st, val) SKM_sk_push(ASN1_IA5STRING, (st), (val))
# define sk_ASN1_IA5STRING_dup(st) SKM_sk_dup(ASN1_IA5STRING, st)
# define sk_ASN1_IA5STRING_pop_free(st, free_func) SKM_sk_pop_free(ASN1_IA5STRING, (st), (free_func))
# define sk_ASN1_IA5STRING_pop(st) SKM_sk_pop(ASN1_IA5STRING, (st))
#endif

/* define for PRQP's REQUESTS stacks - implement object type casting */
#define PKI_STACK_X509_PRQP_REQ_new_null() (PKI_X509_PRQP_REQ_STACK *) PKI_STACK_new( NULL )
#define PKI_STACK_X509_PRQP_REQ_new() (PKI_X509_PRQP_REQ_STACK *) PKI_STACK_new(PKI_X509_PRQP_REQ_free_void)
#define PKI_STACK_X509_PRQP_REQ_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_PRQP_REQ_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_PRQP_REQ_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_PRQP_REQ_pop(p) (PKI_X509_PRQP_REQ *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_PRQP_REQ_get_num(p,n) (PKI_X509_PRQP_REQ *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_PRQP_REQ_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_PRQP_REQ_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_PRQP_REQ_elements(p) PKI_STACK_elements((PKI_STACK *)p)

/* define for PRQP's RESPONSE stacks - implement object type casting */
#define PKI_STACK_X509_PRQP_RESP_new_null() (PKI_X509_PRQP_RESP_STACK *) PKI_STACK_new( NULL )
#define PKI_STACK_X509_PRQP_RESP_new() (PKI_X509_PRQP_RESP_STACK *) PKI_STACK_new(PKI_X509_PRQP_RESP_free_void)
#define PKI_STACK_X509_PRQP_RESP_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_PRQP_RESP_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_PRQP_RESP_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_PRQP_RESP_pop(p) (PKI_X509_PRQP_RESP *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_PRQP_RESP_get_num(p,n) (PKI_X509_PRQP_RESP *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_PRQP_RESP_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_PRQP_RESP_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_PRQP_RESP_elements(p) PKI_STACK_elements((PKI_STACK *)p)


#ifdef  __cplusplus
}
#endif
#endif

/* end */

