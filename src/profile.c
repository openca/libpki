/* Profile management for libpki */

#include <libpki/pki.h>

static xmlNsPtr _get_pki_ns ( PKI_CONFIG_ELEMENT *node );

char * PKI_X509_PROFILE_get_value (PKI_X509_PROFILE *doc, char *path ) {
	return PKI_CONFIG_get_value ( (PKI_CONFIG *) doc, path );
}

char *PKI_X509_PROFILE_get_name ( PKI_X509_PROFILE *doc ) {

	// snprintf(search, (size_t) BUFF_MAX_SIZE, "/profile/name", 
	// 		PKI_NAMESPACE_PREFIX, PKI_NAMESPACE_PREFIX );

	return PKI_X509_PROFILE_get_value( doc, "/profile/name" );
}

PKI_X509_PROFILE * PKI_X509_PROFILE_load(char *urlPath) {

    PKI_X509_PROFILE *doc = NULL;
    // xmlNode *root_element = NULL;
    URL *url = NULL;

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    if( urlPath ) {
        url = URL_new( urlPath );
    } else {
        url = URL_new ( PKI_DEFAULT_PROFILE_DIR );
    }

    if( !url ) {
	PKI_log_debug("ERROR, can not parse URL when loading profile (%s)!\n",
							urlPath );
	return(PKI_ERR);
    }

    /*parse the file and get the DOM */
    doc = (PKI_X509_PROFILE *) xmlReadFile(url->addr, NULL, 0);

    if (doc == NULL) {
        PKI_log_debug("ERROR, could not parse file %s\n", url->addr);
	return (PKI_ERR);
    }

    return( doc );
}

void PKI_X509_PROFILE_free_void ( void * doc ) {
	PKI_X509_PROFILE_free( (PKI_X509_PROFILE *) doc );
}

int PKI_X509_PROFILE_free ( PKI_X509_PROFILE * doc ) {
	if( !doc ) return (PKI_OK);

	xmlFreeDoc( doc );

	/*
	*Free the global variables that may
	*have been allocated by the parser.
	*/
	//xmlCleanupParser();

	return( PKI_OK );
}

/* ------------------------- Node Generation Code ------------------ */

static xmlNsPtr _get_pki_ns ( PKI_CONFIG_ELEMENT *node ) {

	xmlNsPtr ns = NULL;

	ns = xmlNewNs ( node, (unsigned char *) PKI_NAMESPACE_HREF, 
				(unsigned char *) PKI_NAMESPACE_PREFIX );

	return ( ns );
}

/*! \brief Create a new PKI_X509_PROFILE */

PKI_X509_PROFILE *PKI_X509_PROFILE_new ( char *name ) {

	PKI_X509_PROFILE *doc = NULL;
	xmlNodePtr root_node = NULL;
	xmlNsPtr ns = NULL;

	if ( !name ) return NULL;

	doc = xmlNewDoc( BAD_CAST "1.0");

	// root_node = xmlNewNode(NULL, BAD_CAST PKI_NAMESPACE_PREFIX ":profile");
	root_node = xmlNewNode(NULL, BAD_CAST "profile");

	if((ns = _get_pki_ns ( root_node )) == NULL ) {
		xmlFreeDoc ( doc );
		xmlFreeNode ( root_node );
		return ( NULL );
	}

	xmlSetNs ( root_node, ns );
        xmlDocSetRootElement( doc, root_node );

	PKI_CONFIG_ELEMENT_add_child ( doc, root_node, "name", name );
	PKI_CONFIG_ELEMENT_add_child ( doc, root_node, "extensions", NULL);

	return ( doc );
}


int PKI_X509_PROFILE_put_file ( PKI_X509_PROFILE *doc, char *url ) {
	xmlSaveFormatFileEnc( url, doc, "UTF-8", 1 );
	return PKI_OK;
}

/*
PKI_X509_PROFILE *PKI_X509_PROFILE_update ( PKI_X509_PROFILE *doc ) {

	return ( PKI_CONFIG_update (doc));
}
*/

int PKI_X509_PROFILE_get_exts_num ( PKI_X509_PROFILE *doc ) {

	PKI_CONFIG_ELEMENT *curr = NULL;
	PKI_CONFIG_ELEMENT *exts = NULL;

	int size = 0;

	if( !doc ) return (PKI_ERR);

	if((exts = PKI_X509_PROFILE_get_extensions ( doc )) == NULL ) {
		PKI_log_debug("get_exts_num()::Can not get exts pointer!!!");
		return PKI_ERR;
	}

	// PKI_log_debug("GET number of exts... ");
	if ( (curr = exts->children ) == NULL ) return 0;

	/*
	while( (curr = xmlNextElementSibling ( curr )) != NULL ) {
		size++;
	}
	*/

	while ( curr ) {
		if( curr->type == XML_ELEMENT_NODE ) {
			// PKI_log_debug("get_exts_num()::curr->name=%s", curr->name );
			size++;
		}
		curr = curr->next;
	}

	// PKI_log_debug("NUMBER OF EXTENSIONS is %d", size );

	return size;
}

PKI_X509_EXTENSION *PKI_X509_PROFILE_get_ext_by_num (PKI_X509_PROFILE *doc, 
								int num, PKI_TOKEN *tk ){

	PKI_CONFIG_ELEMENT *curr = NULL;
	PKI_CONFIG_ELEMENT *exts = NULL;

	int size = 0;

	if(!doc) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	};

	if((exts = PKI_X509_PROFILE_get_extensions ( doc )) == NULL ) {
		return PKI_ERR;
	}

	for ( curr = exts->children; curr ; curr = curr->next ) {
		if ( curr->type == XML_ELEMENT_NODE ) {
			// PKI_log_debug("GET EXT by NUM: %s (%d)", 
			// 			curr->name, size );
			if ( size == num )  {
				break;
			};
			size++;
		}
	}

	return PKI_X509_EXTENSION_value_new_profile ( doc, NULL, curr, tk );
}

PKI_CONFIG_ELEMENT *PKI_X509_PROFILE_get_extensions ( PKI_X509_PROFILE *doc ) {

	PKI_CONFIG_ELEMENT *curr = NULL;

	if((curr = PKI_CONFIG_get_element ( doc, 
					"/profile/extensions", -1)) == NULL ) {
		PKI_log_err ("Failed to get /profile/extensions from profile!");
		return NULL;
	} else {
		return curr;
	}

	/*
	if((root = xmlDocGetRootElement ( doc )) == NULL ) {
		PKI_log_err ("Can not get Root Element!");
	}

	for ( curr = root->children; curr; curr = curr->next ) {
		PKI_log_debug("LOOPING (curr = %p)", curr );

		if ( curr->type == XML_ELEMENT_NODE ) {
			PKI_log_debug ("LOOPING::Node Name=%s", curr->name );
			if ( curr->name ) {
				if ( strcmp ( curr->name, 
					PKI_NAMESPACE_PREFIX ":extensions") 
								== 0 ) {
					break;
				}
			}
		}
	}
	*/

	return curr;
};

PKI_CONFIG_ELEMENT * PKI_X509_PROFILE_add_extension ( PKI_X509_PROFILE *doc, 
			char *name, char *value, char *type, int crit ) {

	PKI_CONFIG_ELEMENT * exts = NULL;
	PKI_CONFIG_ELEMENT * child = NULL;
	PKI_CONFIG_ELEMENT * next = NULL;

	if ( !doc || !name ) return NULL;

	if((exts = PKI_X509_PROFILE_get_extensions( doc)) == NULL) {
		PKI_log_debug ("PKI_X509_PROFILE_add_extension()::No Exts found!");
		return NULL;
		/*
		PKI_log_debug (">>>>>>>>>>>>>>NAME: %s", 
				PKI_CONFIG_get_value ( doc, "/profile/name"));
		if((root = PKI_CONFIG_get_element ( doc, "/profile" )) == NULL ) {
			PKI_log_debug ("NO /profile SECTION in PROFILE!!!!!!!");
			return NULL;
		}

		PKI_log_debug ("ADDING EXTS to /profile SECTION.....");
		exts = PKI_CONFIG_ELEMENT_add_child (doc, root, "extensions", NULL);
		*/
	}

	if( !exts ) {
		PKI_log_debug("ERROR, no EXTENSIONS found or created!");
		return NULL;
	}

	if((child = PKI_CONFIG_ELEMENT_add_child ( doc, exts, 
			"extension", NULL )) == NULL ) {
		PKI_log_debug("ERROR, CAN not add 'extension' child!");
		return NULL;
	}

	PKI_CONFIG_ELEMENT_add_attribute ( doc, child, "name", name );
	if( crit > 0 ) {
		PKI_CONFIG_ELEMENT_add_attribute ( doc, child, "critical", "yes" );
	}

	next = PKI_CONFIG_ELEMENT_add_child ( doc, child, "value", value );
	if ( next && type  ) {
		PKI_CONFIG_ELEMENT_add_attribute ( doc, next, "type", type );
	}

	return child;
}

PKI_X509_PROFILE * PKI_X509_PROFILE_get_default ( PKI_X509_PROFILE_TYPE profile_id ) {

	PKI_X509_PROFILE *prof = NULL;
	PKI_CONFIG_ELEMENT *next = NULL;
	PKI_CONFIG_ELEMENT *child = NULL;
	PKI_CONFIG_ELEMENT *exts = NULL;

	if (profile_id == PKI_X509_PROFILE_PROXY)
	{
		prof = PKI_X509_PROFILE_new( PKI_PROFILE_DEFAULT_PROXY_NAME );
		exts = PKI_X509_PROFILE_get_extensions ( prof );

		/* keyUsage */
		next = PKI_CONFIG_ELEMENT_add_child( prof, exts, "extension", NULL);
		PKI_CONFIG_ELEMENT_add_attribute( prof, next, "name", "keyUsage" );
		PKI_CONFIG_ELEMENT_add_attribute( prof, next, "critical", "yes" );

		child = PKI_CONFIG_ELEMENT_add_child(prof, next, "value", "digitalSignature");

		/* ExtendedKeyUsage */
		next = PKI_CONFIG_ELEMENT_add_child( prof, exts, "extension", NULL );
		PKI_CONFIG_ELEMENT_add_attribute( prof, next, "name", "extendedKeyUsage" );

		child = PKI_CONFIG_ELEMENT_add_child (prof, next, "value", "emailProtection");
		child = PKI_CONFIG_ELEMENT_add_child (prof, next, "value", "clientAuth" );

		/* proxyCertInfo extension */
		next = PKI_CONFIG_ELEMENT_add_child( prof, exts, "extension", NULL );
		PKI_CONFIG_ELEMENT_add_attribute ( prof, next, "name", "proxyCertInfo" );
		PKI_CONFIG_ELEMENT_add_attribute ( prof, next, "critical", "yes" );

		/* language value */
		child = PKI_CONFIG_ELEMENT_add_child ( prof, next, "value", "id-ppl-inheritAll" );
		PKI_CONFIG_ELEMENT_add_attribute( prof, child, "type", "language" );

		/* pathlen value */
		child = PKI_CONFIG_ELEMENT_add_child( prof, next, "value", "0" );
		PKI_CONFIG_ELEMENT_add_attribute( prof, child, "type", "pathlen" );
	}

	return prof;
}


