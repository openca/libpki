/* Extension value building - driver specific part */

#include <libpki/pki.h>

#ifndef _LIBPKI_X509_EXTENSION_H
#include <libpki/pki_x509_extension.h>
#endif

static char *ext_txt_db [] = {
	/* Tags */
	"permitted",
	"excluded",
	"OCSP",
	"caIssuers",
	"critical",
	/* Types */
	"email",
	"URI",
	"IP",
	"IPv6",
	"DNS",
	"RID",
	"caIssuers",
	"ia5org",
	"otherName",
	"dirName",
	"ASN1:IA5STRING",
	"ASN1:BMPSTRING",
	"ASN1:UTF8String",
	"ASN1:INTEGER",
	"ASN1:SEQUENCE",
	"CA",
	"requireExplicitPolicy",
	"UTF8",
	"DER",
	/* KeyUsage */
	"digitalSignature",
	"nonRepudiation",
	"keyEncipherment",
	"dataEncipherment",
	"keyAgreement",
	"keyCertSign"
	"cRLSign", 
	"encipherOnly",
	"decipherOnly",
	/* extendedKeyUsage */
	"serverAuth",
	"clientAuth",
	"codeSigning",
	"emailProtection",
	"timeStamping",
	"msCodeInd",
	"msCodeCom",
	"msCTLSign",
	"msSGC",
	"msEFS",
	"msSGC",
	/* End */
	NULL
};

			// ================
			// Static Functions
			// ================

static char * _ext_txt ( unsigned char * str ) {

	char ** pnt = NULL;

	if( !str ) return ( NULL );

	pnt = ext_txt_db;

	while ( *pnt != NULL ) {
		if( (strcmp_nocase( (char * )str, *pnt ) == 0 ) &&
				( strlen( (char *) str ) == strlen( *pnt ))) {
			 return ( *pnt );
		}
		pnt++;
	}
	return ( (char *) str );
}


			// ====================
			// Extensions Functions
			// ====================

PKI_X509_EXTENSION *PKI_X509_EXTENSION_new( void ) {
	
	PKI_X509_EXTENSION *ret = NULL;
		// Memory Pointer

	// Allocates the memory
	ret = (PKI_X509_EXTENSION *) PKI_Malloc ( sizeof( PKI_X509_EXTENSION ));
	if (ret) {
		// Generates a new generic extension
		ret->value.ptr = X509_EXTENSION_new();
		if(ret->value.ptr == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "X509_EXTENSION_new()");
		}
	}

	return ret;
}

void PKI_X509_EXTENSION_free_void ( void *ext ) {
	PKI_X509_EXTENSION_free ( (PKI_X509_EXTENSION *) ext );
}

void PKI_X509_EXTENSION_free ( PKI_X509_EXTENSION *ext ) {

	if (ext) {
		if (ext->value.ptr) X509_EXTENSION_free (ext->value.ptr);
		PKI_Free (ext);
	}

	return;
}


PKI_X509_EXTENSION *PKI_X509_EXTENSION_value_new_profile ( 
						const PKI_X509_PROFILE   * profile,
						const PKI_CONFIG         * oids,
						const PKI_CONFIG_ELEMENT * extNode,
						const PKI_TOKEN          * tk) {

	/* TODO: Implement the extended version of the extensions, this
	   should allow better extensions management. That is, the value
	   will be encoded as:

		extName=@section

		[ section ]
		extName=value
		otherVal=val
		otherVal=val
		...

	   The corresponding XML should be:

		<pki:extension name=".." critical=".." >
		   <pki:value type=".." tag=".." oid=".."> .. </pki:value>
		   <pki:value type=".." tag=".." oid=".."> .. </pki:value>
		</pki:extension>

	  */

	PKI_X509_EXTENSION *ret = NULL;

	PKI_CONFIG_ELEMENT *valNode = NULL;
	PKI_X509_EXTENSION_VALUE *ext = NULL;

	xmlChar *type_s = NULL;
	xmlChar *tag_s = NULL;
	xmlChar *oid_s = NULL;
	xmlChar *value_s = NULL;
	xmlChar *name_s = NULL;
	xmlChar *crit_s = NULL;

	PKI_OID *oid = NULL;

	X509V3_CTX v3_ctx;
	CONF *conf = NULL;

	char *envValString = NULL;
	char *valString = NULL;
	char *tmpValue = NULL;
	int crit = 0;

	if (!profile || !extNode) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, "No profile or extNode provided");
		return NULL;
	}

	if ((crit_s = xmlGetProp((PKI_CONFIG_ELEMENT *)extNode, BAD_CAST "critical" )) != NULL ) {

		if( strncmp_nocase((char *) crit_s, "y", 1 ) == 0) {
			crit = 1;
		} else {
			crit = 0;
		}
	}

	if((name_s = xmlGetProp((PKI_CONFIG_ELEMENT *)extNode, BAD_CAST "name" )) == NULL ) {
		PKI_DEBUG("ERROR: no name property in node %s", extNode->name);
		if (crit_s) xmlFree(crit_s);
		return NULL;
	}

	if ((oid = PKI_OID_get((char *) name_s)) == NULL)
	{
		if ((oid = PKI_CONFIG_OID_search((PKI_CONFIG *)oids, (char *)name_s)) == NULL)
		{
			PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
			return NULL;
		}
	}
	else
	{
		PKI_OID_free ( oid );
	}


	if ((valString = (char *) PKI_Malloc(BUFF_MAX_SIZE)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if( name_s ) xmlFree ( name_s );
		if( crit_s ) xmlFree (crit_s);
		return( NULL );
	}

	memset(valString, 0, BUFF_MAX_SIZE);

	if (crit == 1) snprintf(valString, BUFF_MAX_SIZE-1, "%s", "critical");

	for (valNode = extNode->children; valNode; valNode = valNode->next)
	{
		PKI_DEBUG("Building %s Extension", name_s);

		if ((valNode->type == XML_ELEMENT_NODE) &&
				((strncmp_nocase((char *)(valNode->name),"value",5)) == 0))
		{
			char tmp[BUFF_MAX_SIZE];

			type_s = xmlGetProp( valNode, BAD_CAST "type" );
			tag_s = xmlGetProp( valNode, BAD_CAST "tag" );
			oid_s = xmlGetProp( valNode, BAD_CAST "oid" );

			value_s = xmlNodeListGetString((PKI_X509_PROFILE *)profile, 
						       valNode->xmlChildrenNode, 0);

			if( oid_s ) {
				/* Let's be sure the OID is created */
				if((oid = PKI_CONFIG_OID_search((PKI_CONFIG *)oids, 
						(char *) value_s)) == NULL ) {
					PKI_DEBUG("No oid created for %s!", oid_s );
				} else {
					PKI_OID_free(oid);
				}
			}

			memset ((unsigned char * )tmp, 0, BUFF_MAX_SIZE);

			if( tag_s ) {
				snprintf( tmp, BUFF_MAX_SIZE - 1, "%s;", 
					_ext_txt( tag_s ) );
			}

			if( type_s == NULL ) {
				if( !oid_s ) {
					strncat(tmp, (char *) value_s, 
							BUFF_MAX_SIZE - strlen(tmp));
				} else {
					if( value_s && (strlen((char *) value_s) > 0) ) {
						strncat( tmp, (char *) oid_s, 
						 	BUFF_MAX_SIZE - strlen( tmp ) );
						strncat( tmp, ":", 
							BUFF_MAX_SIZE - strlen ( tmp ));
						strncat( tmp, (char *) value_s,
							BUFF_MAX_SIZE - strlen (tmp ));
					} else {
						strncat( tmp, "OID:", 
							BUFF_MAX_SIZE - strlen(tmp));
						strncat( tmp, (char *) oid_s, 
							BUFF_MAX_SIZE - strlen( tmp ));
					}
				}
			} else {
				strncat( tmp, (char *) _ext_txt(type_s), 
						BUFF_MAX_SIZE - strlen( tmp ));
				if( value_s && (strlen((char*)value_s) > 0) ) {
					if(strcmp_nocase( (char*) type_s, "ia5org")) {
					    strncat( tmp, ":", 
						BUFF_MAX_SIZE - strlen( tmp ));
					} else {
					    strncat( tmp, ",", 
						BUFF_MAX_SIZE - strlen( tmp ));
					}
					strncat( tmp, (char *) value_s, 
						BUFF_MAX_SIZE - strlen( tmp ));
				}
			}
				
			if (strlen(valString) > 0) {
				strncat(valString, ",", BUFF_MAX_SIZE - 1);
			}

			tmpValue = (char *) tmp;
			strncat(valString, tmpValue, BUFF_MAX_SIZE - strlen(valString));

			if( type_s ) xmlFree ( type_s );
			if( oid_s ) xmlFree ( oid_s );
			if( tag_s ) xmlFree ( tag_s );
			if( value_s ) xmlFree ( value_s );
        	}
	}

	v3_ctx.db = NULL;
	v3_ctx.db_meth = NULL;
	v3_ctx.crl = NULL;
	v3_ctx.flags = 0;

	if ( tk ) {
		v3_ctx.issuer_cert  =  (X509 *)
			PKI_X509_get_value ( tk->cacert );
		v3_ctx.subject_cert =  (X509 *)
			PKI_X509_get_value ( tk->cert );
		v3_ctx.subject_req  =  (X509_REQ *)
			PKI_X509_get_value ( tk->req );
		
		if (!v3_ctx.issuer_cert) 
			PKI_DEBUG("No CA Detected in Token, Cannot Encode CA-Bound extensions");

	} else {

		v3_ctx.issuer_cert = NULL;
		v3_ctx.subject_cert = NULL;
		v3_ctx.subject_req = NULL;
	}

	/* Sets the ctx.db and ctx.method */
	conf = NCONF_new( NULL );
	X509V3_set_nconf(&v3_ctx, conf);

	if (valString) {
		ext = X509V3_EXT_conf(NULL, &v3_ctx, (char *) name_s, 
						(char *) valString);
	} else if ((envValString = get_env_string(valString)) != NULL) {
		ext = X509V3_EXT_conf(NULL, &v3_ctx, (char *) name_s, 
						(char *) envValString);
		PKI_Free(envValString);
	}

	if (!ext) {
		PKI_DEBUG("Can not generate the extension value from (%s=%s)", 
			name_s, valString);
		PKI_ERROR(PKI_ERR_X509_CERT_CREATE_EXT, 
                           ERR_error_string(ERR_get_error(), NULL));
		goto err;
	}

        if(( ret = PKI_X509_EXTENSION_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		X509_EXTENSION_free ( ext );
		return NULL;
	}

	ret->value.x509_ext = ext;
	ret->oid = X509_EXTENSION_get_object(ext);

err:
	if( name_s ) xmlFree ( name_s );
	if( crit_s ) xmlFree (crit_s );

	if( valString ) PKI_Free ( valString );
	if( conf ) NCONF_free ( conf );

	return ( ret );
}

PKI_X509_EXTENSION_STACK *PKI_X509_CERT_VALUE_ext_list(PKI_X509_CERT_VALUE * x) {

	PKI_X509_EXTENSION_STACK *ret = NULL;
		// Return Stack

	int i = 0;
	int ext_count = 0;

	// Input checks
	if (!x) return NULL;

	// Gets the number of extensions
	if ((ext_count = X509_get_ext_count (x)) <= 0 ) return NULL;

	// Builds the LibPKI wrapper
	if(( ret = PKI_STACK_X509_EXTENSION_new()) == NULL ) return NULL;

	// Process all extensions
	for ( i=0; i < ext_count; i++ ) {

		PKI_X509_EXTENSION *pki_ext = NULL;
			// LibPKI extension

		PKI_X509_EXTENSION_VALUE *ext = NULL;
			// Crypto Layer extension
		
		// Recovers the i-th extension from the certificate
		if ((ext = X509_get_ext(x, i)) == NULL) {
			continue;
		}

		// Allocates the LibPKI wrapper
		if((pki_ext = PKI_X509_EXTENSION_new()) == NULL ) {
			PKI_log_err ( "Memory Allocation");
			continue;
		}

		// Sets the fields in the LibPKI's Extension
		pki_ext->oid = X509_EXTENSION_get_object(ext);
		pki_ext->type = OBJ_obj2nid(pki_ext->oid);
		pki_ext->critical = X509_EXTENSION_get_critical(ext);

		// Parses the extension into the generic pointer
		if ((pki_ext->value.ptr = X509V3_EXT_d2i(ext)) == NULL) {
			PKI_ERROR(PKI_ERR_GENERAL, "Could not parse Extension Num. %d", i);
			PKI_X509_EXTENSION_free(pki_ext);
			continue;
		}

		// Push the extension to the return list
		PKI_STACK_X509_EXTENSION_push ( ret, pki_ext );
	}

	// All Done
	return ret;
}

PKI_X509_EXTENSION_STACK *PKI_X509_CERT_ext_list(PKI_X509_CERT * x) {

	// Input Checks
	if (!x || !x->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	return PKI_X509_CERT_VALUE_ext_list(x->value);
}