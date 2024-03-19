/*
 * LibPKI - X509 Profile Management functionality
 * (c) 2006-2007 by Massimiliano Pala and OpenCA Project
 * OpenCA LICENSED software
 *
*/

#ifndef _LIBPKI_X509_PROFILE_H
#define _LIBPKI_X509_PROFILE_H
# pragma once

// System Includes
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

// LibPKI Includes
#include <libpki/stack.h>
#include <libpki/support.h>
#include <libpki/pki_config.h>
#include <libpki/profile.h>
#include <libpki/pki_mem.h>

BEGIN_C_DECLS

// ===========================
// PKI_X509_PROFILE definition
// ===========================

// Forward declaration of PKI_X509_PROFILE
typedef struct _xmlDoc PKI_X509_PROFILE;

// Stack Declarations
DECLARE_LIBPKI_STACK_FN(PKI_X509_PROFILE)

						// ====================
						// Functions Prototypes
						// ====================

PKI_X509_PROFILE * PKI_X509_PROFILE_get ( char *url );
PKI_X509_PROFILE * PKI_X509_PROFILE_write( PKI_X509_PROFILE *prof, char *url );

PKI_X509_PROFILE * PKI_X509_PROFILE_get_default (PKI_X509_PROFILE_TYPE profile_id);

char * PKI_X509_PROFILE_get_value(const PKI_X509_PROFILE *doc, 
				  const char *path );
char * PKI_X509_PROFILE_get_name(const PKI_X509_PROFILE *doc );

PKI_X509_PROFILE * PKI_X509_PROFILE_load(const char *urlPath);
int PKI_X509_PROFILE_free ( PKI_X509_PROFILE * doc );

PKI_X509_PROFILE *PKI_X509_PROFILE_new (const char *name );

PKI_CONFIG_ELEMENT * PKI_X509_PROFILE_add_child(PKI_X509_PROFILE *doc, 
						const char *name, 
						const char *value );

PKI_CONFIG_ELEMENT * PKI_X509_PROFILE_add_child_el(PKI_X509_PROFILE *doc, 
				PKI_CONFIG_ELEMENT *el );

int PKI_X509_PROFILE_put_file ( PKI_X509_PROFILE *doc, const char *url );

int PKI_X509_PROFILE_get_exts_num ( const PKI_X509_PROFILE *doc );

PKI_X509_EXTENSION *PKI_X509_PROFILE_get_ext_by_num (
				const PKI_X509_PROFILE *doc,
				int num, 
				PKI_TOKEN *tk);

PKI_CONFIG_ELEMENT *PKI_X509_PROFILE_get_extensions(const PKI_X509_PROFILE *doc);

PKI_CONFIG_ELEMENT *PKI_X509_PROFILE_add_extension (PKI_X509_PROFILE *doc, 
						    const char *name, 
						    const char *value, 
						    const char *type, 
						    int crit );

END_C_DECLS

#endif


