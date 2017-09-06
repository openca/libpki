/* Config management for libpki */

#include <libpki/pki.h>

#include <sys/types.h>
#include <dirent.h>
#include <libxml/xmlerror.h>

/* Static function, to be used only internally */
static char * _xml_search_namespace_add ( char *search );

static char *def_conf_dirs[] = {
	PKI_DEFAULT_CONF_DIR,
	LIBPKI_PATH_SEPARATOR "etc" LIBPKI_PATH_SEPARATOR "libpki",
	NULL
};

#define PKI_DEF_CONF_DIRS_SIZE	2
#define LIBXML_MIN_VERSION 20600

#if LIBXML_VERSION < LIBXML_MIN_VERSION
#define xmlErrorPtr void *
#endif

/*
#if LIBXML_VERSION >= LIBXML_MIN_VERSION
#define logXmlMessages(a,b) PKI_log_debug("XML I/O Error: %s", b)
#else
#define logXmlMessages(a,b) PKI_log_debug("XML I/O Error", b)
#endif
*/

void logXmlMessages( void *userData, xmlErrorPtr error ) {
#if LIBXML_VERSION >= LIBXML_MIN_VERSION
	PKI_log_err( "XML I/O Error: %s", error->message);
#else
	PKI_log_err( "XML I/O Error");
#endif
	return;
}

static char * _xml_search_namespace_add ( char *search ) {

	char *my_search = NULL;
	char *my_arg = NULL;
	char *ret = NULL;

	int r = 0;
	int i = 0;

	// return strdup ( search );

	/* Let's alloc enough memory for the arguments, maybe this is
	   too much, but for the moment, let's keep it big */
	my_arg = PKI_Malloc ( BUFF_MAX_SIZE );
	my_search = PKI_Malloc ( BUFF_MAX_SIZE );

	/* Now let's take care about setting the appropriate namespace
	   if it is not passed, already */
	i = 0;
	while( search[i] == LIBPKI_PATH_SEPARATOR_CHAR ) {
		i++;
		strncat(my_search, LIBPKI_PATH_SEPARATOR, BUFF_MAX_SIZE );
	}

	while( (i < strlen( search )) &&
			 (sscanf( search + i, "%[^" LIBPKI_PATH_SEPARATOR "]%n", 
				my_arg, &r ) > 0 )) {
		i = i + r;

		if( strchr( my_arg, ':' ) == NULL ) {
			strncat( my_search, PKI_NAMESPACE_PREFIX ":",
					BUFF_MAX_SIZE - strlen(my_search) );
		}
		strncat( my_search, my_arg, BUFF_MAX_SIZE - strlen(my_search));

		while( search[i] == LIBPKI_PATH_SEPARATOR_CHAR ) {
			i++;
			strncat(my_search, LIBPKI_PATH_SEPARATOR, 
				BUFF_MAX_SIZE - strlen( my_search ));
		}
	}
	PKI_Free( my_arg );

	ret = PKI_Malloc ( strlen( my_search ) + 1);
	strncpy( ret, my_search, strlen(my_search) );

	PKI_Free ( my_search );
	return( ret );
}

/*! \brief Loads a PKI_CONFIG object (XML config file) */

PKI_CONFIG * PKI_CONFIG_load(const char *urlPath)
{
	FILE *file = NULL;
	PKI_CONFIG *doc = NULL;
	URL *url = NULL;
	xmlParserCtxt *parserCtxt = NULL;

	LIBXML_TEST_VERSION

	if (urlPath) url = URL_new( urlPath );
  else return ( NULL );

	// Let's check the URL was parsed correctly
	if( !url || !url->addr ) return(PKI_ERR);

	if ((file = fopen(url->addr, "r")) == NULL)
	{
		URL_free(url);
		return PKI_ERR;
	}
	fclose(file);

	if ((parserCtxt = xmlNewParserCtxt()) == NULL )
	{
		URL_free( url );
		return(PKI_ERR);
	}

#if LIBXML_VERSION > LIBXML_MIN_VERSION
	xmlSetStructuredErrorFunc( parserCtxt, logXmlMessages );
#endif

	/* Do not Keep Blank Nodes */
	xmlKeepBlanksDefault(0);

	/*parse the file and get the DOM */
#if LIBXML_VERSION > LIBXML_MIN_VERSION
	doc = (PKI_CONFIG *) xmlCtxtReadFile(parserCtxt, url->addr, NULL, 
				XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | 
				XML_PARSE_NOENT );
#else
	doc = (PKI_CONFIG *) xmlCtxtReadFile(parserCtxt, url->addr, NULL, 0);
#endif

	// xmlClearParserCtxt ( parserCtxt );
	xmlFreeParserCtxt ( parserCtxt );
	URL_free(url);

	return( doc );
}

void PKI_CONFIG_free_void ( void * doc )
{
	PKI_CONFIG *my_doc = NULL;

	my_doc = (PKI_CONFIG *) doc;
	PKI_CONFIG_free( my_doc);

	return;
}

/*! \brief Frees the memory associated with a PKI_CONFIG object */

int PKI_CONFIG_free ( PKI_CONFIG * doc ) {
	if( !doc ) return (PKI_OK);

	xmlFreeDoc( doc );

	/*
	*Free the global variables that may
	*have been allocated by the parser.
	*/
	//xmlCleanupParser();

	return( PKI_OK );
}

/*! \brief Gets the root element of a PKI_CONFIG document */

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_root ( PKI_CONFIG *doc ) {
	
	if ( !doc ) return ( NULL );

	return ( xmlDocGetRootElement( doc ));
}

/*! \brief Loads an OID file and creates internal OIDs */

PKI_CONFIG * PKI_CONFIG_OID_load(const char *oidFile ) {

	PKI_OID *oid = NULL;
	PKI_CONFIG *doc = NULL;
	PKI_CONFIG_ELEMENT *curr = NULL;
	PKI_CONFIG_ELEMENT_STACK *sk = NULL;

	int size = 0;
	int i = 0;

	if ( !oidFile ) return NULL;

	if((doc = PKI_CONFIG_load ( oidFile)) == NULL ) {
		PKI_log_err ("Can not open OID file %s", oidFile );
		return (NULL);
	};

	if (( sk = PKI_CONFIG_get_element_stack ( doc, 
					(char *) "/objectIdentifiers/oid" )) == NULL ) {
		// PKI_log_debug("[WARNING] no OID found in %s", oidFile );
		return NULL;
	}
	size = PKI_STACK_CONFIG_ELEMENT_elements ( sk );

	for( i = 0; i < size; i++ ) {
		curr = PKI_STACK_CONFIG_ELEMENT_get_num ( sk, i );

		if( curr && curr->type == XML_ELEMENT_NODE ) {
			xmlChar *name = NULL;
			xmlChar *descr = NULL;
			xmlChar *val = NULL;

			name = xmlGetProp( curr, (xmlChar *) "name" );
			descr = xmlGetProp( curr, (xmlChar *) "description" );
			val = xmlNodeListGetString(doc, curr->xmlChildrenNode, 1);

			PKI_log_debug("[OID load] Creating OID (%s, %s, %s)",
				name, descr, val );

			oid = PKI_OID_new ( (char *) val, (char *) name, 
							(char *) descr);

			if( descr ) xmlFree ( descr  );
			if( name ) xmlFree ( name );
			if( val ) xmlFree ( val );

			if( oid == NULL ) {
				PKI_log_debug("Failed Creating OID (%s, %s, %s)",
					name, descr, val );
			}
		}
	}

	return (doc);
}

/*! \brief Searches for a specific OID inside a PKI_CONFIG object */

PKI_OID * PKI_CONFIG_OID_search(const PKI_CONFIG *doc, const char *searchName ) {

	PKI_OID *oid = NULL;
	PKI_CONFIG_ELEMENT *curr = NULL;
	PKI_CONFIG_ELEMENT_STACK *sk = NULL;

	xmlChar oidSearchBuff[BUFF_MAX_SIZE];

	int size = 0;
	int i = 0;

	if( !doc || !searchName ) return (NULL);

	if((oid = PKI_OID_get( searchName )) != NULL ) {
		return ( oid );
	}

	snprintf( (char *) oidSearchBuff, BUFF_MAX_SIZE,
		"/objectIdentifiers/oid[@name=\"%s\"]", searchName );

	if (( sk = PKI_CONFIG_get_element_stack ( doc, 
					(char *)oidSearchBuff )) == NULL ) {
		return NULL;
	}

	size = PKI_STACK_CONFIG_ELEMENT_elements ( sk );

	for( i = 0; i < size; i++ ) {
		curr = PKI_STACK_CONFIG_ELEMENT_get_num ( sk, i );

		if( curr && curr->type == XML_ELEMENT_NODE ) {
			xmlChar *name = NULL;
			xmlChar *descr = NULL;
			xmlChar *val = NULL;

			name = xmlGetProp( curr, (xmlChar *) "name" );
			descr = xmlGetProp( curr, (xmlChar *) "description" );
			val = xmlNodeListGetString((PKI_CONFIG *)doc, 
						curr->xmlChildrenNode, 1);

			oid = PKI_OID_new ( (char *) val, (char *) name, 
							(char *) descr);

			if( descr ) xmlFree ( descr  );
			if( name ) xmlFree ( name );
			if( val ) xmlFree ( val );

			if( oid != NULL ) {
				PKI_log_debug("Failed Creating OID (%s, %s, %s)",
					name, descr, val );
				continue;
			}
		}
	}

	return (oid);
}

/*! \brief Returns a stack of values for the selected search path */

PKI_STACK * PKI_CONFIG_get_stack_value(const PKI_CONFIG *doc, const char *search ) {

	PKI_CONFIG_ELEMENT_STACK *sk = NULL;
	PKI_STACK *ret = NULL;
	PKI_CONFIG_ELEMENT *curr = NULL;

	int size = -1;
	char *val = NULL;

	if ((sk = PKI_CONFIG_get_element_stack((PKI_CONFIG *)doc, search)) == NULL ) {
		return NULL;
	}

	if((size = PKI_STACK_CONFIG_ELEMENT_elements ( sk )) <= 0 ) {
		return  NULL;
	}

	ret = PKI_STACK_new( NULL );

	while ((curr = PKI_STACK_CONFIG_ELEMENT_pop ( sk )) != NULL ) {
		if( curr && curr->type == XML_ELEMENT_NODE ) {
			if((val = PKI_CONFIG_get_element_value ( curr )) != NULL ) {
				PKI_STACK_push ( ret, strdup (val) );
			}
		}
	}

	PKI_STACK_free_all ( sk );

	return ret;
}


/*! \brief Returns the first value found via the provided search path */

char * PKI_CONFIG_get_value(const PKI_CONFIG *doc, const char *search ) {

	PKI_CONFIG_ELEMENT *curr = NULL;

	if (( curr = PKI_CONFIG_get_element ( doc, search, -1 )) == NULL ) {
		return NULL;
	}

	return PKI_CONFIG_get_element_value ( curr );
}
 
/*! \brief Returns the value of the named attribute in the searched item */

char * PKI_CONFIG_get_attribute_value(const PKI_CONFIG *doc, 
				      const char *search,
				      const char *attr_name ) {

	PKI_CONFIG_ELEMENT *el = NULL;
	char * ret = NULL;

	if( !doc || !search || !attr_name ) {
		return ( NULL );
	}

	if((el = PKI_CONFIG_get_element ( doc, search, -1 )) == NULL ) {
		return ( NULL );
	};

	ret = (char * ) xmlGetProp( el, BAD_CAST attr_name );

	return ( ret );
}

/*! \brief Returns the number of items identified by the search path */

int PKI_CONFIG_get_elements_num(const PKI_CONFIG *doc, const char *search ) {

	PKI_STACK *sk = NULL;
	int ret = -1;
	PKI_CONFIG_ELEMENT *pnt = NULL;

	if((sk = PKI_CONFIG_get_element_stack((PKI_CONFIG *)doc, search )) == NULL ) {
		return -1;
	}

	ret = PKI_STACK_elements ( sk );

	while((pnt = PKI_STACK_pop ( sk)) != NULL ) {
		// Nothing, we do not want to free the node's memory!
	}

	PKI_STACK_free ( sk );

	return ret;
}

/*! \brief Returns the n-th PKI_CONFIG_ELEMENT identified by the search path */

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element(const PKI_CONFIG * doc, 
					    const char       * search,
					    int                num ) {

	PKI_CONFIG_ELEMENT_STACK *sk = NULL;
	PKI_CONFIG_ELEMENT *ret = NULL;

	if ( !doc || !search ) return NULL;

	// PKI_log_debug ("PKI_CONFIG_get_element()::Start");

	if(( sk = PKI_CONFIG_get_element_stack((PKI_CONFIG *)doc, search )) == NULL ) {
		// PKI_log_debug ("PKI_CONFIG_get_element()::No Stack Returned");
		return NULL;
	}

	if ( num < 0 ) num = PKI_STACK_CONFIG_ELEMENT_elements ( sk ) - 1;
	// PKI_log_debug ("PKI_CONFIG_get_element()::Stack Elements => %d",
	// 			PKI_STACK_CONFIG_ELEMENT_elements( sk ));
	
	ret = PKI_STACK_CONFIG_ELEMENT_get_num ( sk, num );

	while ( PKI_STACK_CONFIG_ELEMENT_pop ( sk ));

	PKI_STACK_CONFIG_ELEMENT_free ( sk );

	// PKI_log_debug ("PKI_CONFIG_get_element()::End (ret => %p", ret);

	return ret;
		
	

	/*
	xmlXPathContext *xpathCtx = NULL; 
	xmlXPathObject *xpathObj = NULL;
	xmlNodeSet *nodes = NULL;

	PKI_CONFIG_ELEMENT *curr = NULL;

	xmlParserCtxt *parserCtxt = NULL;

	int size = 0;
	int i = 0;

	char *my_search = NULL;

	if( !doc || !search ) return (NULL);

	xpathCtx = xmlXPathNewContext(doc);
	if(xpathCtx == NULL) {
        	PKI_log_debug("ERROR, unable to create new XPath context!\n");
		return(NULL);
	}

	xmlXPathRegisterNs(xpathCtx, (xmlChar *) PKI_NAMESPACE_PREFIX, 
					(xmlChar *) PKI_NAMESPACE_HREF);

	my_search = _xml_search_namespace_add ( search );
	// my_search = strdup ( search );

	PKI_log_debug (">>>> SEARCHING ====> %s (%s)", my_search, search );

	xpathObj = xmlXPathEvalExpression( (xmlChar *) my_search, xpathCtx);
	if( xpathObj == NULL ) {
		PKI_log_debug("<<<< xpathObj is NULL >>>>>" );

		xmlXPathFreeContext(xpathCtx);
		PKI_Free ( my_search );
		return(NULL);
	}

	nodes = xpathObj->nodesetval;
	if( nodes ) {
		size = nodes->nodeNr;
	}

	if( size >= 1 ) {
		curr = nodes->nodeTab[size-1];
	} else {
		PKI_log_debug("<<<<<<< returned vals size=%d >>>>>>>", size );
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);

	PKI_Free ( my_search );

	PKI_log_debug ( ">>>>>>>>>>>> SEARCH SUCCESSFUL!!! <<<<<<<<<<<<<<<<<<");


	return (curr);
	*/
}

/*! \brief Returns the stack of elements identified by the search path */

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_stack(const PKI_CONFIG * doc, 
							const char * search ) {

	xmlXPathContext *xpathCtx = NULL; 
	xmlXPathObject *xpathObj = NULL;
	xmlNodeSet *nodes = NULL;

	PKI_CONFIG_ELEMENT_STACK *ret = NULL;

	int size = 0;
	int i = 0;

	char *my_search = NULL;

	if( !doc || !search ) return (NULL);

	xpathCtx = xmlXPathNewContext((PKI_CONFIG *)doc);
	if(xpathCtx == NULL) {
        	PKI_log_debug("ERROR, unable to create new XPath context!\n");
		return(NULL);
	}

	xmlXPathRegisterNs(xpathCtx, (xmlChar *) PKI_NAMESPACE_PREFIX, 
					(xmlChar *) PKI_NAMESPACE_HREF);

	my_search = _xml_search_namespace_add((char *)search);

	xpathObj = xmlXPathEvalExpression( (xmlChar *) my_search, xpathCtx);
	if( xpathObj == NULL ) {
		xmlXPathFreeContext(xpathCtx);
		PKI_Free ( my_search );
		return(NULL);
	}

	nodes = xpathObj->nodesetval;
	if( nodes ) {
		size = nodes->nodeNr;
	} else {
		size = -1;
	}

	// PKI_log_debug ( "PKI_CONFIG_get_element_stack()::Returned nodes => %d", size);

	if( size > 0 ) {
		ret = PKI_STACK_CONFIG_ELEMENT_new();

		/* recursively copy the node */
		for( i = size-1; i >= 0; i-- ) {
			if( nodes->nodeTab[i]->type != XML_ELEMENT_NODE )
				continue;
			// curr = xmlCopyNode( nodes->nodeTab[i], 1);
			PKI_STACK_CONFIG_ELEMENT_push( ret, nodes->nodeTab[i] );
		}
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);

	PKI_Free ( my_search );

	return (ret);
}

/*! \brief Returns the value of a PKI_CONFIG_ELEMENT */

char * PKI_CONFIG_get_element_value (PKI_CONFIG_ELEMENT *e)
{
	char *val = NULL;
	char *ret = NULL;

	if (!e) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	val = (char *)xmlNodeGetContent ( e );

	if (val)
	{
		if(strchr(val, '$')) ret = get_env_string( val );
		else ret = strdup(val);

		xmlFree(val);
	}

	return ret;
}

/*! \brief Returns the name of a PKI_CONFIG_ELEMENT */

char * PKI_CONFIG_get_element_name (PKI_CONFIG_ELEMENT *e)
{
	if (!e)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return( (char *) e->name );
}

/*! \brief Returns the child of a PKI_CONFIG_ELEMENT */

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_child (PKI_CONFIG_ELEMENT *e)
{
	PKI_CONFIG_ELEMENT *ret = NULL;

	if(!e)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	if(!e->children) return NULL;
	else ret = e->children;

	while (ret && ret->type != XML_ELEMENT_NODE)
	{
		ret = ret->next;
	}

	return( ret );
}

/*! \brief Returns the next PKI_CONFIG_ELEMENT */

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_next ( PKI_CONFIG_ELEMENT *e)
{
	PKI_CONFIG_ELEMENT *ret = NULL;

	if (!e)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}
	
	if (!e->next) return (NULL);

	ret = e->next;
	while (ret && ret->type != XML_ELEMENT_NODE)
	{
		ret = ret->next;
	}

	return( ret );
}

/*! \brief Returns the previous PKI_CONFIG_ELEMENT */

PKI_CONFIG_ELEMENT * PKI_CONFIG_get_element_prev ( PKI_CONFIG_ELEMENT *e)
{
	PKI_CONFIG_ELEMENT *ret = NULL;

	if(!e)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	if (!e->prev) return NULL;

	ret = e->prev;
	while (ret && ret->type != XML_ELEMENT_NODE)
	{
		ret = ret->prev;
	}

	return (PKI_CONFIG_ELEMENT *) e->prev;
}

/*! \brief Returns the stack of a PKI_CONFIG_ELEMENT's children */

PKI_CONFIG_ELEMENT_STACK * PKI_CONFIG_get_element_children(PKI_CONFIG_ELEMENT *e)
{
	PKI_CONFIG_ELEMENT_STACK *ret = NULL;
	PKI_CONFIG_ELEMENT *curr = NULL;

	if (!e)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	if ((curr = e->children) == NULL) return NULL;

	if ((ret = PKI_STACK_CONFIG_ELEMENT_new()) == NULL) return NULL;

	while (curr)
	{
		if( curr->type != XML_ELEMENT_NODE ) continue;

		PKI_STACK_CONFIG_ELEMENT_push( ret, curr );
		curr = curr->next;
	}

	return( ret );
}

/*!
 * \brief Returns a pointer to the filename of the configuration file that
          contains the configuration named 'name'.
 */

char * PKI_CONFIG_find(const char *dir, const char *name )
{
	struct dirent *dd = NULL;
	DIR *dirp = NULL;
	URL *url = NULL;

	int found = 0;
	char *ret = NULL;

	/* Check input */
	if( !dir || !name )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (PKI_ERR);
	}

	if ((url = URL_new(dir)) == NULL)
	{
		PKI_log_debug("Dir [%s] is not a valid URI", dir );
		return (PKI_ERR);
	}

	if (url->proto != URI_PROTO_FILE)
	{
		PKI_log_debug("URL is not a file, skipping!", dir );
		return (PKI_ERR);
	}

	if ((dirp = opendir(url->addr)) == NULL)
	{
		PKI_log_debug("Can not open directory [%s]", url->addr );
		return (PKI_ERR);
	}
	else
	{
		while(( dd = readdir( dirp )) != NULL )
		{
			long len;
			char *filename = NULL;

			filename = dd->d_name;
			len = (long) strlen( filename );

			PKI_log_debug("Processing file [%s]", filename );

			if (len < 4 || strcmp(".xml", filename +len-4) != 0)
			{
				PKI_log_debug("Skipping %s", filename );
				continue;
			}
			else
			{
				char fullpath[BUFF_MAX_SIZE];
				size_t fullsize = 0;

				PKI_CONFIG *tmp_cfg = NULL;
				char *tmp_name = NULL;

				snprintf(fullpath, BUFF_MAX_SIZE,
					"%s/%s", url->addr, filename );

				PKI_log_debug("Opening File %s", fullpath );

				// Check the allowed size
				fullsize = strlen(url->addr) + strlen( filename ) + 1;
				if (fullsize > BUFF_MAX_SIZE) continue;
				
				if ((tmp_cfg = PKI_CONFIG_load(fullpath)) == NULL)
				{
					PKI_log_debug("Can not load %s", fullpath );
					continue;
				}

				PKI_log_debug("Getting Name Param... ");
				tmp_name = PKI_CONFIG_get_value(tmp_cfg, "/*/name");
				PKI_CONFIG_free(tmp_cfg);

				if (tmp_name != NULL)
				{
					PKI_log_debug("Got Name::%s", tmp_name);
					if (strcmp_nocase(tmp_name, name) == 0)
					{
						PKI_Free(tmp_name);
						tmp_name = NULL; // Safety

						found = 1;
						ret = strdup(fullpath);
						PKI_log_debug("File successfully loaded %s", fullpath );
						break;
					}
					PKI_Free(tmp_name);
					tmp_name = NULL; // Safety
				}
				else PKI_log_debug("No Name found!");
			}
		}
		closedir( dirp );
	}

	// Let's free the URL memory
	if (url) URL_free(url);

	// If found, let's return it
	if (found == 1) return ret;

	// If not found, we return NULL
	return NULL;
}

/*!
 * \brief Returns a pointer to the filename of the configuration file that
          contains the configuration named 'name'.
 */

char * PKI_CONFIG_find_all(const char *dir, 
			   const char *name,
			   const char *subdir) {

	PKI_STACK *dir_list = NULL;
	char * dir_name = NULL;
	char * ret = NULL;

	int i = 0;

	// Checks the input
	if (!dir || !name )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Get the list of entries for the directory
	if ((dir_list = PKI_CONFIG_get_search_paths(dir)) == NULL) return NULL;
	
	// Some debugging
	PKI_log_debug( "GOT SEARCH PATHS => %d", PKI_STACK_elements( dir_list ));

	// Go throught the different elements of the directory and search them
	for ( i=0; i < PKI_STACK_elements( dir_list ); i++ )
	{
		char buff[BUFF_MAX_SIZE];

		dir_name = PKI_STACK_get_num(dir_list, i);

		if (subdir != NULL) snprintf(buff, sizeof(buff), "%s/%s", dir_name, subdir);
		else snprintf(buff, sizeof(buff), "%s", dir_name );

		// Debugging
		PKI_log_debug("SEARCHING FOR %s in dir %s", name, buff );

		if ((ret = PKI_CONFIG_find(buff, name)) != NULL)
		{
			PKI_log_debug("FOUND => %s [%s]", name, buff );
			break;
		}
	}

	// Free all the contents
	if (dir_list) PKI_STACK_free_all(dir_list);

	// Let's return the results
	return ret;
}

/*!
 * \brief Returns a stack of all configuration files found in the passed
 *        directory.
 */

PKI_CONFIG_STACK * PKI_CONFIG_load_dir(const char *dir,
				       PKI_CONFIG_STACK *sk ) {

        struct dirent *dd = NULL;
	DIR *dirp = NULL;
	URL *url = NULL;

	int found = 0;
	PKI_CONFIG_STACK *ret = NULL;

	/* Check input */
	if( !dir ) {
		return (NULL);
	}

	if(( url = URL_new ( dir )) == NULL ) {
		PKI_log_debug( "Dir not valid for config (%s)", dir );
		return ( NULL );
	}

	if( url->proto != URI_PROTO_FILE ) {
		PKI_log_debug( "Dir not valid for config (%s)", dir );
		return (NULL);
	}

	if((dirp = opendir( url->addr )) == NULL ) {
		PKI_log_debug("ERROR, Can not open dir %s!\n", url->addr );
		return (NULL);
	} else {
		if( !sk ) {
			if((ret = PKI_STACK_CONFIG_new()) == NULL ) {
				PKI_log_debug("Memory Error (%s:%d)", 
							__FILE__, __LINE__ );
				return(NULL);
			}
		} else {
			ret = sk;
		}

		while(( dd = readdir( dirp )) != NULL ) {
			long len;
			char *filename = NULL;

			filename = dd->d_name;
			len = (long) strlen( filename );

			if( (len < 4) || (strcmp( ".xml", filename +len -4 ))) {
				PKI_log_debug( "Skipping file %s", filename);
				continue;
			} else {
			
				char fullpath[BUFF_MAX_SIZE];
				size_t fullsize = 0;

				PKI_CONFIG *tmp_cfg = NULL;

				PKI_log_debug( "Loading file %s" LIBPKI_PATH_SEPARATOR "%s", 
							url->addr, filename );

				snprintf(fullpath, BUFF_MAX_SIZE,
					"%s" LIBPKI_PATH_SEPARATOR "%s", url->addr, filename );

				if((fullsize = strlen(url->addr) + 
					strlen( filename ) + 1) > 
							BUFF_MAX_SIZE) {
					continue;
				}
				
				if((tmp_cfg = PKI_CONFIG_load( fullpath )) ==
									NULL ) {
					continue;
				}

				PKI_log_debug( "Loaded %s file", fullpath );
				PKI_STACK_CONFIG_push( ret, tmp_cfg );
				found = 1;
			}
		}
		closedir( dirp );
	}
	if( url ) URL_free (url);

	if( found == 1 ) {
		return (ret);
	} else {
		PKI_STACK_CONFIG_free( ret );
		PKI_log_debug("PKI_CONFIG_load_dir() Failed!\n" );
		return ( NULL );
	}
}

/*!
 * \brief Returns a stack of all configurations files found in the passed
 *        directory plush the default search paths
 */

PKI_CONFIG_STACK *PKI_CONFIG_load_all(const char * dir ) {

	PKI_STACK *dir_list = NULL;
	PKI_CONFIG_STACK *sk = NULL;
	char *name = NULL;

	if((dir_list = PKI_CONFIG_get_search_paths ( dir )) == NULL ) {
		return ( NULL );
	}

	while( (name =  PKI_STACK_pop ( dir_list )) != NULL ) {
		PKI_CONFIG_load_dir ( name, sk );
		PKI_Free ( name );
	}

	return ( sk );
}

/*! \brief Returns a PKI_STACK of directories (useful to search in default
           dirs for config files */

PKI_STACK *PKI_CONFIG_get_search_paths(const char *dir ) {

	char *homedir = NULL;
	char buff[BUFF_MAX_SIZE];

	PKI_STACK *list = NULL;
	int i = 0;

	// PKI_log_debug("get_search_paths() start");

	if((list = PKI_STACK_new_null()) == NULL ) {
		return ( NULL );
	}

	/* If passed as an argument, dir is the first dir in the search path */
	if( dir ) {
		PKI_STACK_push( list, strdup(dir) );
		return list;
	}

	/* Check for the HOME environment variable */
	if(( homedir = getenv("HOME")) != NULL ) {
		memset(buff, '\x0', sizeof( buff ));
                snprintf( buff, sizeof( buff), "%s"
				LIBPKI_PATH_SEPARATOR ".libpki", homedir );

		/* Adds the user's home directory to the search path */
		PKI_STACK_push ( list, strdup( buff ) );
	};

	/* Adds all the 'default' libpki config directories */
	for( i = 0 ; i < PKI_DEF_CONF_DIRS_SIZE; i++ ) {
		PKI_STACK_push ( list, strdup(def_conf_dirs[i]) );
	}

	// PKI_log_debug("get_search_paths()::Entries in list %d", 
	//				PKI_STACK_elements ( list ));

	// PKI_log_debug("get_search_paths()::ENDING");
	return ( list );
}


/*! \brief Create a new Node for a PKI_X509_PROFILE */

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_new(const char *name, 
					   const char *value ) {

	PKI_CONFIG_ELEMENT *ret = NULL;
	// xmlNsPtr ns = NULL;

	if( !name ) return ( NULL );

	if((ret = xmlNewNode( NULL, BAD_CAST name )) == NULL ) {
		return ( NULL );
	}

	// ns = xmlNewNs ( ret, PKI_NAMESPACE_PREFIX, NULL );

	if( value ) {
		xmlAddChild( ret, xmlNewText ( BAD_CAST value ));
	}

	return ( ret );

}

/*! \brief Adds an attribute to an existing profile element */
int PKI_CONFIG_ELEMENT_add_attribute(PKI_CONFIG         * doc,
				     PKI_CONFIG_ELEMENT * node,
				     const char         * name,
				     const char         * value ) {

	if( (node == NULL) || ( name == NULL )) {
		return ( PKI_ERR );
	}

	// snprintf(buf, sizeof(buf), "%s", PKI_NAMESPACE_PREFIX, name );
	xmlNewProp( node, BAD_CAST name, BAD_CAST value );

	// if( doc ) _pki_update_config ( &doc );
	 
	return ( PKI_OK );
}

PKI_CONFIG_ELEMENT *PKI_CONFIG_add_node ( PKI_CONFIG *doc,
			char *parent, char *name, char *value ) {

	
	PKI_CONFIG_ELEMENT *p_node = NULL;

	// PKI_log_debug("add_node()::parent=%s, name=%s, value=%s",
	// 			parent, name, value );

	if((p_node = PKI_CONFIG_get_element( doc, parent, -1 )) == NULL ) {
		PKI_log_debug("ERROR::Can not find Parent node (%s)", parent );
		return NULL;
	}

	return PKI_CONFIG_ELEMENT_add_child ( doc, p_node, name, value );
}

/*! \brief Add a child element to an existing node */

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child(PKI_CONFIG         * doc, 
						 PKI_CONFIG_ELEMENT * node,
						 const char         * name,
						 const char         * value) {

	PKI_CONFIG_ELEMENT *ret = NULL;

	// PKI_log_debug ( "add_child():: name=%s, value=%s", name, value );

	if(!node || !name ) return NULL;

	// snprintf(buf, sizeof(buf), "%s:%s", PKI_NAMESPACE_PREFIX, name );
	// ns = xmlNewNs ( node, NULL, PKI_NAMESPACE_PREFIX);

	// PKI_log_debug ( "add_child():: New Name::%s", name);

	if((ret = xmlNewTextChild( node, NULL, BAD_CAST name, BAD_CAST value ))
								== NULL ) {
		// PKI_log_debug("add_child()::Failed!");
	}


	// xmlFreeNs ( ns );

	// if(doc) _pki_update_config( &doc );

	return ( ret );
}

/*! \brief Add a child element to an existing node */

PKI_CONFIG_ELEMENT *PKI_CONFIG_ELEMENT_add_child_el ( PKI_CONFIG * doc, 
			PKI_CONFIG_ELEMENT *node, PKI_CONFIG_ELEMENT *el) {

	if(!node || !el ) return ( PKI_ERR );

	xmlAddChild( node, el );

	// if ( doc ) _pki_update_config ( &doc );

	return ( el );
}

/*
PKI_CONFIG *PKI_CONFIG_update ( PKI_CONFIG *doc ) {

	// PKI_X509_PROFILE *origDoc = NULL;
	PKI_X509_PROFILE *newDoc = NULL;
	xmlParserCtxt *parserCtxt = NULL;
	PKI_MEM *mem = NULL;

	// PKI_CONFIG_ELEMENT *root = NULL;
	// root = xmlDocGetRootElement ( doc );
	// xmlSetTreeDoc ( root, *doc );
	// return;

	// xmlChar *mem = NULL;
	// int size = 0;

	// origDoc = *doc;

	// newDoc = xmlCopyDoc ( *doc, 1 );
	// xmlFreeDoc ( *doc );

	// *doc = newDoc;

	// return PKI_OK;

	if((parserCtxt = xmlNewParserCtxt()) == NULL ) {
        	return(PKI_ERR);
    	}

#if LIBXML_VERSION > LIBXML_MIN_VERSION
    	xmlSetStructuredErrorFunc( parserCtxt, logXmlMessages );
#endif

    	xmlKeepBlanksDefault(0);

	mem = PKI_MEM_new_null();

	xmlDocDumpMemory( doc, &mem->data, &mem->size);

	newDoc = (PKI_CONFIG *) xmlCtxtReadDoc(parserCtxt, mem->data, 
			"noname.xml", NULL, 
			XML_PARSE_RECOVER | XML_PARSE_NOERROR |
                                XML_PARSE_NOWARNING | XML_PARSE_NOENT );

	// xmlInitParser();

	// *doc = xmlParseMemory ( mem->data, mem->size );
	//
	// *doc = xmlReadMemory( (char*) mem, size, "noname.xml", NULL, 
	// 		XML_PARSE_RECOVER | XML_PARSE_NOERROR |
        //                         XML_PARSE_NOWARNING | XML_PARSE_NOENT );
	//

	PKI_MEM_free ( mem );

	if( newDoc == NULL ) {
		return ( PKI_ERR );
	}

	//
	// PKI_log_debug ( "[UPDATE] >>>> FLAGS => %d  PROPERTIES => %d   TYPE => %d",
	// 			(*doc)->parseFlags, (*doc)->properties, (*doc)->type );

	// (*doc)->parseFlags = 0;
	// (*doc)->properties = 32;
	//

	// *doc = newDoc;
	xmlClearParserCtxt ( parserCtxt );

	return newDoc;
}
*/
