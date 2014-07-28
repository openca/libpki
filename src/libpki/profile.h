/* PKI PROFILE Management Functions */

#ifndef _LIBPKI_PROFILE_HEADERS_H
#define _LIBPKI_PROFILE_HEADERS_H

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libpki/support.h>

typedef enum {
	PKI_X509_PROFILE_USER = 0,
	PKI_X509_PROFILE_PROXY,
	PKI_X509_PROFILE_WEB_SERVER,
	PKI_X509_PROFILE_MAIL_SERVER
} PKI_X509_PROFILE_TYPE;

#define PKI_PROFILE_DEFAULT_PROXY_NAME "__DEFAULT_PROXY_PROFILE__"
#define PKI_PROFILE_DEFAULT_USER_NAME "__DEFAULT_USER_PROFILE__"

PKI_X509_PROFILE * PKI_X509_PROFILE_get_default ( 
				PKI_X509_PROFILE_TYPE profile_id );

char * PKI_X509_PROFILE_get_value ( PKI_X509_PROFILE *doc, char *path );
char * PKI_X509_PROFILE_get_name ( PKI_X509_PROFILE *doc );

PKI_X509_PROFILE * PKI_X509_PROFILE_load(char *urlPath);
int PKI_X509_PROFILE_free ( PKI_X509_PROFILE * doc );

PKI_X509_PROFILE *PKI_X509_PROFILE_new ( char *name );
PKI_CONFIG_ELEMENT * PKI_X509_PROFILE_add_child(PKI_X509_PROFILE *doc, 
				char *name, char *value );
PKI_CONFIG_ELEMENT * PKI_X509_PROFILE_add_child_el(PKI_X509_PROFILE *doc, 
				PKI_CONFIG_ELEMENT *el );
int PKI_X509_PROFILE_put_file ( PKI_X509_PROFILE *doc, char *url );

int PKI_X509_PROFILE_get_exts_num ( PKI_X509_PROFILE *doc );
PKI_X509_EXTENSION *PKI_X509_PROFILE_get_ext_by_num (PKI_X509_PROFILE *doc,
		int num, PKI_TOKEN *tk);

PKI_CONFIG_ELEMENT *PKI_X509_PROFILE_get_extensions ( PKI_X509_PROFILE *doc );
PKI_CONFIG_ELEMENT *PKI_X509_PROFILE_add_extension ( PKI_X509_PROFILE *doc, 
				char *name, char *value, char *type, int crit );

#endif


