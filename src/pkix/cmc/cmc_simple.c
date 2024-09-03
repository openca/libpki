/* CMS Simple - PKIX Message Management */

#include <libpki/pki.h>

typedef void PKI_CMS_RESP;
typedef void PKI_CMS_REQ;

PKI_CMS_RESP *PKI_MSG_CMS_write ( PKI_CMS_REQ *req, URL *url ) {

	int rv = 0;
	PKI_MEM_STACK *data = NULL;
	PKI_MEM *req_data = NULL;

	// PKI_CMS_RESP *cms_resp = NULL;

	if( !req || !url ) return (PKI_ERR);

	/* Here we have to process the request in order to find out:
	   1-the type of the request
	   2-convert to a memory data chunk
	   3-save the content to a PKI_MEM data structure (req_data)
	*/

	rv = URL_put_data_url ( url, req_data, CMS_REQ_SIMPLE_DATATYPE,
				 &data, 0, 0, NULL );

	/*
	if( url->proto == URI_PROTO_HTTP ) {
		data = URL_post_data_http(url, req_data->data, req_data->size, 
						CMS_REQ_SIMPLE_DATATYPE );
	} else if( url->proto == URI_PROTO_FILE ) {
		// data = URL_write( url, req_data );
	} else if( url->proto == URI_PROTO_LDAP ) {
		// data = URL_LDAP_post_data( url, req_data);
	};
	*/

	if( (rv == PKI_ERR ) || ( data == NULL )) {
		return ( PKI_ERR );
	}

	/* Else process the CMS data */
	// cms = PKI_CMS_new_mem( data );

	// if( req_data ) PKI_MEM_free (req_data);

	return( NULL );
}
