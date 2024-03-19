/* PKI PROFILE Management Functions */

#ifndef _LIBPKI_PROFILE_HEADERS_H
#define _LIBPKI_PROFILE_HEADERS_H

// System Includes
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

// LibPKI Includes
#include <libpki/datatypes.h>
#include <libpki/support.h>

BEGIN_C_DECLS

// Stack Declarations
DECLARE_LIBPKI_STACK_FN(PKI_X509_PROFILE)

						// ====================
						// Functions Prototypes
						// ====================

PKI_X509_PROFILE * PKI_X509_PROFILE_get_default ( 
				PKI_X509_PROFILE_TYPE profile_id );

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

#endif // End of _LIBPKI_PROFILE_HEADERS_H


