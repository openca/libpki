/* TOKEN Object Management Functions */

#include <strings.h>
#include <libpki/pki.h>

/* Retrieval function (internal ) */
static PKI_MEM_STACK *PKI_TOKEN_get_data ( PKI_TOKEN *tk,
			PKI_TOKEN_DATATYPE dt, PKI_DATA_FORMAT format );

/*!
 * \brief Returns a PKI_MEM that contains a keypair in the specified
 *        format (eg., PKI_FORMAT_TXT, PKI_FORMAT_PEM, etc... )
 */

PKI_MEM *PKI_TOKEN_get_keypair_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if (!tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_KEYPAIR, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}

PKI_MEM *PKI_TOKEN_get_pubkey_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if (!tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_PUBKEY, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}

PKI_MEM *PKI_TOKEN_get_privkey_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if (!tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_PRIVKEY, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}

PKI_MEM *PKI_TOKEN_get_cert_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if (!tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_CERT, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}

PKI_MEM *PKI_TOKEN_get_identity_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if (!tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_IDENTITY, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}

PKI_MEM *PKI_TOKEN_get_cacert_data ( PKI_TOKEN *tk, PKI_DATA_FORMAT format ) {

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *ret = NULL;

	if( !tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data ( tk, PKI_TOKEN_DATATYPE_CACERT, format );
	if( !mem_sk ) return ( NULL );

	ret = PKI_STACK_MEM_pop( mem_sk );
	PKI_STACK_MEM_free ( mem_sk );

	return ( ret );
}


/* Trusted Certs Stack Retrieval */
PKI_MEM_STACK *PKI_TOKEN_get_trustedCerts_data ( PKI_TOKEN *tk,
						PKI_DATA_FORMAT format ) {
	PKI_MEM_STACK *mem_sk = NULL;

	if( !tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data(tk,PKI_TOKEN_DATATYPE_TRUSTEDCERT,format);

	return ( mem_sk );
}

/* Other Certs Stack Retrieval */
PKI_MEM_STACK *PKI_TOKEN_get_otherCerts_data ( PKI_TOKEN *tk,
						PKI_DATA_FORMAT format ) {
	PKI_MEM_STACK *mem_sk = NULL;

	if( !tk ) return ( NULL );

	mem_sk = PKI_TOKEN_get_data(tk, PKI_TOKEN_DATATYPE_OTHERCERT, format);

	return ( mem_sk );
}

static PKI_MEM_STACK *PKI_TOKEN_get_data ( PKI_TOKEN *tk, 
			PKI_TOKEN_DATATYPE dt, PKI_DATA_FORMAT format ) {


	if( !tk ) return ( NULL );

	switch ( dt ) {
		case PKI_TOKEN_DATATYPE_KEYPAIR:
		case PKI_TOKEN_DATATYPE_PUBKEY:
		case PKI_TOKEN_DATATYPE_PRIVKEY:
		case PKI_TOKEN_DATATYPE_CERT:
		case PKI_TOKEN_DATATYPE_CACERT:
		case PKI_TOKEN_DATATYPE_OTHERCERT:
		case PKI_TOKEN_DATATYPE_TRUSTEDCERT:
		case PKI_TOKEN_DATATYPE_IDENTITY:
		default:
			PKI_log_err("%s:%d::Format %d not supported!",
				__FILE__, __LINE__, dt );
	}

	return ( NULL );
}

