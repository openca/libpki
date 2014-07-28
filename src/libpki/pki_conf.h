/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_CONF_H
#define _LIBPKI_CONF_H

#define PKI_DEFAULT_ETC_DIR  			"/usr/etc"

#define PKI_DEFAULT_CONF_DIR			"file:///usr/etc/libpki"
#define PKI_DEFAULT_PROFILE_DIR		"profile.d"
#define PKI_DEFAULT_TOKEN_DIR			"token.d"
#define PKI_DEFAULT_HSM_DIR				"hsm.d"
#define PKI_DEFAULT_STORE_DIR			"store.d"
#define PKI_DEFAULT_CONF_OID_FILE	"objectIdentifiers.xml"

typedef enum {
	PKI_CONF_PROFILE = 0,
	PKI_CONF_TOKEN,
	PKI_CONF_HSM,
	PKI_CONF_STORE,
	PKI_CONF_OID
} PKI_CONF_TYPE;

int PKI_CONFIG_free ( PKI_CONFIG * doc );
void PKI_CONFIG_free_void ( void * doc );

PKI_CONFIG * PKI_CONFIG_load(char *urlPath);
PKI_CONFIG_STACK * PKI_CONFIG_load_dir ( char *dir, PKI_CONFIG_STACK *sk );
PKI_CONFIG_STACK * PKI_CONFIG_load_all ( char * dir );

PKI_CONFIG * PKI_CONFIG_OID_load ( char *oidFile );
PKI_OID * PKI_CONFIG_OID_search ( PKI_CONFIG *doc, char *searchName );

/* Config Options */
char * PKI_CONFIG_get_value ( PKI_CONFIG *doc, char *search );
PKI_STACK * PKI_CONFIG_get_stack_value ( PKI_CONFIG *doc, char *search );

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_stack ( PKI_CONFIG *doc, 
							char *search );

char * PKI_CONFIG_get_element_name (PKI_CONFIG_ELEMENT *e);
char * PKI_CONFIG_get_element_value (PKI_CONFIG_ELEMENT *e);

char * PKI_CONFIG_get_attribute_value ( PKI_CONFIG *doc, 
					char *search, char *attr_name );

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_root ( PKI_CONFIG *doc );
int PKI_CONFIG_get_elements_num ( PKI_CONFIG *doc, char *search );
PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element(PKI_CONFIG *doc, char *search, int num);

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_child (PKI_CONFIG_ELEMENT *e);
PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_next (PKI_CONFIG_ELEMENT *e);
PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_prev (PKI_CONFIG_ELEMENT *e);

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_children ( 
							PKI_CONFIG_ELEMENT *e);

char * PKI_CONFIG_find ( char *dir, char *name );
char * PKI_CONFIG_find_all ( char *dir, char *name, char *subdir );

PKI_STACK *PKI_CONFIG_get_search_paths ( char *dir );

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_new ( char *name, char *value );
int PKI_CONFIG_ELEMENT_add_attribute ( PKI_CONFIG *doc,
		PKI_CONFIG_ELEMENT *node, char *name, char *value );
PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child ( PKI_CONFIG *doc, 
			PKI_CONFIG_ELEMENT *node, char *name, char *value );
PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child_el ( PKI_CONFIG * doc, 
			PKI_CONFIG_ELEMENT *node, PKI_CONFIG_ELEMENT *el);

#endif
