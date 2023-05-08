/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_CONF_H
#define _LIBPKI_CONF_H

#ifndef _LIBPKI_CONF_TYPES_H
#include <libpki/pki_config_types.h>
#endif

#ifndef _LIBPKI_STACK_H
# include <libpki/stack.h>
#endif

#ifndef _LIBPKI_PKI_IO_H
# include <libpki/pki_io.h>
#endif

							// ====================
							// Function Definitions
							// ====================

int PKI_CONFIG_free ( PKI_CONFIG * doc );

void PKI_CONFIG_free_void ( void * doc );

PKI_CONFIG * PKI_CONFIG_load(const char *urlPath);

PKI_CONFIG_STACK * PKI_CONFIG_load_dir(const char       * dir, 
									   PKI_CONFIG_STACK * sk);

PKI_CONFIG_STACK * PKI_CONFIG_load_all(const char * dir);

PKI_CONFIG * PKI_CONFIG_OID_load(const char *oidFile);

PKI_OID * PKI_CONFIG_OID_search(const PKI_CONFIG * doc, 
				 				const char       * searchName);

/* Config Options */
char * PKI_CONFIG_get_value(const PKI_CONFIG * doc,
			    			const char       * search);

PKI_STACK * PKI_CONFIG_get_stack_value(const PKI_CONFIG * doc,
				       				   const char       * search);

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_stack(const PKI_CONFIG * doc, 
														const char       * search );

char * PKI_CONFIG_get_element_name(PKI_CONFIG_ELEMENT *e);

char * PKI_CONFIG_get_element_value(PKI_CONFIG_ELEMENT *e);

char * PKI_CONFIG_get_attribute_value(const PKI_CONFIG * doc, 
				       				  const char       * search,
				       				  const char       * attr_name);

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_root(PKI_CONFIG *doc);

int PKI_CONFIG_get_elements_num(const PKI_CONFIG * doc, 
			          			const char       * search );

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element(const PKI_CONFIG * doc,
					    					const char       * search, 
					    					int                num);

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_child(PKI_CONFIG_ELEMENT *e);

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_next(PKI_CONFIG_ELEMENT *e);

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_prev(PKI_CONFIG_ELEMENT *e);

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_children(PKI_CONFIG_ELEMENT *e);

char * PKI_CONFIG_find(const char * dir, 
			 		   const char * name );

char * PKI_CONFIG_find_all(const char * dir, 
			     		   const char * name, 
			     		   const char * subdir );

PKI_STACK *PKI_CONFIG_get_search_paths(const char *dir);

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_new(const char * name, 
					     				   const char * value);

int PKI_CONFIG_ELEMENT_add_attribute(PKI_CONFIG         * doc,
				       				 PKI_CONFIG_ELEMENT * node, 
				       				 const char         * name, 
				       				 const char         * value );

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child(PKI_CONFIG         * doc, 
						   						 PKI_CONFIG_ELEMENT * node, 
						   						 const char         * name, 
						   						 const char         * value);

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child_el(PKI_CONFIG         * doc, 
						      						PKI_CONFIG_ELEMENT * node, 
						      						PKI_CONFIG_ELEMENT * el);

#endif
