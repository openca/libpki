/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_CONF_TYPES_H
#define _LIBPKI_CONF_TYPES_H

#ifndef _LIBPKI_XMLINCLUDES_H
#define _LIBPKI_XMLINCLUDES_H

# include <libxml/xmlmemory.h>
# include <libxml/parser.h>
# include <libxml/xpath.h>
# include <libxml/xpathInternals.h>

#endif // End of _LIBPKI_XMLINCLUDES_H

#define PKI_CONFIG                xmlDoc
#define PKI_CONFIG_ELEMENT        xmlNode

#define PKI_DEFAULT_ETC_DIR  			"/opt/libpki-pqc/etc"

#define PKI_DEFAULT_CONF_DIR			"file:///opt/libpki-pqc/etc/libpki"
#define PKI_DEFAULT_PROFILE_DIR			"profile.d"
#define PKI_DEFAULT_TOKEN_DIR			"token.d"
#define PKI_DEFAULT_HSM_DIR				"hsm.d"
#define PKI_DEFAULT_STORE_DIR			"store.d"
#define PKI_DEFAULT_CONF_OID_FILE		"objectIdentifiers.xml"

typedef enum {
	PKI_CONF_PROFILE = 0,
	PKI_CONF_TOKEN,
	PKI_CONF_HSM,
	PKI_CONF_STORE,
	PKI_CONF_OID
} PKI_CONF_TYPE;

#endif // End of _LIBPKI_CONF_TYPES_H
