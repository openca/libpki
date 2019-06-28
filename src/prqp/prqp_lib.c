/* 
 * PKI Resource Query Protocol Message implementation
 * (c) 2006 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#define __PKI_PRQP_LIB_C__

#include <libpki/pki.h>
#include <libpki/prqp/prqp_asn1.h>

#include "../openssl/internal/x509_data_st.h"

/* PKIX Defaults from http://www.imc.org/ietf-pkix/pkix-oid.asn
 *
 * 	id-pkix ::= { 1.3.6.1.5.5.7 }
 * 	id-kp   ::= { id-pkix 3 }
 * 	id-ad   ::= { id-pkix 48 }
 */

//static char *prqp_exts_services[] = {
//	"1.3.6.1.5.5.7.48.12.0", "unknown", "Unknown Service",
//	"1.3.6.1.5.5.7.48.12.1", "ocsp", "OCSP Service",
//	"1.3.6.1.5.5.7.48.12.2", "caIssuers", "CA Information",
//	"1.3.6.1.5.5.7.48.12.3", "timeStamping", "TimeStamping Service",
//	/* PKIX - not yet defined */
//	"1.3.6.1.5.5.7.48.12.4", "scvp", "SCVP Service",
//	"1.3.6.1.5.5.7.48.12.5", "caRepository", "CA Repository",
//	/* HTTP certificate Repository */
//	"1.3.6.1.5.5.7.48.12.6", "httpCertRepository", "HTTP Certificate Repository",
//	/* HTTP CRL Repository */
//	"1.3.6.1.5.5.7.48.12.7", "httpCRLRepository", "HTTP CRL Repository",
//	"1.3.6.1.5.5.7.48.12.8", "httpCrossCertRepository", "HTTP Cross Certificate Repository",
//	/* Gateways */
//	"1.3.6.1.5.5.7.48.12.10", "xkmsGateway", "XKMS Gateway",
//	"1.3.6.1.5.5.7.48.12.11", "cmsGateway", "CMS Gateway",
//	"1.3.6.1.5.5.7.48.12.12", "scepGateway", "SCEP Gateway",
//	/* Certificate Policies */
//	"1.3.6.1.5.5.7.48.12.20", "certPolicy", "Certificate Policy (CP) URL",
//	"1.3.6.1.5.5.7.48.12.21", "certPracticesStatement", "Certificate Practices Statement (CPS) URL",
//	/* Level of Assurance (LOA) */
//	"1.3.6.1.5.5.7.48.12.25", "certLOAPolicy", "LOA Policy URL",
//	"1.3.6.1.5.5.7.48.12.26", "certLOALevel", "Certificate LOA Modifier URL",
//	/* HTTP (Browsers) based services */
//	"1.3.6.1.5.5.7.48.12.30", "htmpRevoke", "HTML Based Certificate Revocation Service URL",
//	"1.3.6.1.5.5.7.48.12.31", "htmlRequest", "HTML Certificate Request Service URL",
//	"1.3.6.1.5.5.7.48.12.32", "htmlRenew", "HTML Certificate Renewal Service URL",
//	"1.3.6.1.5.5.7.48.12.33", "htmlSuspend", "HTML Certificate Suspension Service",
//	/* Webdav Services */
//	"1.3.6.1.5.5.7.48.12.40", "webdavCert", "Webdav Certificate Validation URL",
//	"1.3.6.1.5.5.7.48.12.41", "webdavRev", "Webdav Certificate Revocation URL",
//	/* Grid Specific Services */
//	"1.3.6.1.5.5.7.48.12.50", "gridAccreditationBody", "CA Accreditation Bodies",
//	"1.3.6.1.5.5.7.48.12.51", "gridAccreditationPolicy", "CA Accreditation Policy Document(s) URL",
//	"1.3.6.1.5.5.7.48.12.52", "gridAccreditationStatus", "CA Accreditation Status Document(s) URL",
//	"1.3.6.1.5.5.7.48.12.53", "gridDistributionUpdate", "Grid Distribution Package(s) URL",
//	"1.3.6.1.5.5.7.48.12.54", "gridAccreditedCACerts", "Certificates of Currently Accredited CAs",
//	/* Trust Anchors Publishing */
//	"1.3.6.1.5.5.7.48.70", "tampUpdate", "Trust Anchors Update URL",
//	/* PRQP Service */
//	"1.3.6.1.5.5.7.48.12.100", "prqp", "PRQP Service",
//	/* Other PKI */
//	"2.5.29.27", "deltaCrl", "Delta CRL Base Address",
//	"2.5.29.31", "crl", "CRL Repository",
//	/* End of the List */
 //      	NULL, NULL, NULL
//};

//static char *prqp_exts[] = {
//	/* PRQP extended key usage - id-kp-PRQPSigning ::= { id-kp 10 }*/
//	"1.3.6.1.5.5.7.3.10", "prqpSigning", "PRQP Signing",
//	/* PRQP PKIX identifier - id-prqp ::= { id-pkix 23 } */
//	"1.3.6.1.5.5.7.23", "PRQP", "PKI Resource Query Protocol",
//	/* PRQP PKIX - PTA identifier - { id-prqp 1 } */
//	"1.3.6.1.5.5.7.23.1", "PTA", "PRQP Trusted Authority",
//	/* PRQP AD id-ad-prqp ::= { id-ad   12 } */
//	"1.3.6.1.5.5.7.48.12", "prqp", "PRQP Service",
//	/* End of the List */
 //      	NULL, NULL, NULL
//};

char *PKI_X509_PRQP_STATUS_STRING[] = {
	PKI_X509_PRQP_STATUS_STRING_OK,
	PKI_X509_PRQP_STATUS_STRING_BAD_REQUEST,
	PKI_X509_PRQP_STATUS_STRING_CA_NOT_PRESENT,
	PKI_X509_PRQP_STATUS_STRING_SYS_FAILURE
};

/* ---------------------------- Static Functions ------------------------ */
static int PKI_X509_PRQP_RESP_get_status_value ( PKI_X509_PRQP_RESP_VALUE *r );

static void *PKI_X509_PRQP_REQ_VALUE_get_data ( PKI_X509_PRQP_REQ_VALUE *r,
					PKI_X509_DATA type );
static void *PKI_X509_PRQP_RESP_VALUE_get_data ( PKI_X509_PRQP_RESP_VALUE *r,
					PKI_X509_DATA type );

/* -------------------------------- Proper Code -------------------------- */

int CERT_IDENTIFIER_cmp ( CERT_IDENTIFIER *a, CERT_IDENTIFIER *b) {

	int ret = 0;

	EXTENDED_CERT_INFO * aInfo = NULL;
	EXTENDED_CERT_INFO * bInfo = NULL;
	
	if( !a || !a->hashAlgorithm || !a->basicCertId ) return (-10);
	if( !b || !b->hashAlgorithm || !b->basicCertId ) return (-20);

	if((ret = OBJ_cmp(a->hashAlgorithm->algorithm, 
				b->hashAlgorithm->algorithm)) != 0 ) {
		return 1;
	}

	if( !a->basicCertId->issuerNameHash ) return ( -11 );
	if( !b->basicCertId->issuerNameHash ) return ( -21 );

	if((ret = ASN1_OCTET_STRING_cmp(a->basicCertId->issuerNameHash, 
				b->basicCertId->issuerNameHash)) != 0 ) {
		return 2;
	};

	if((ret = ASN1_INTEGER_cmp( a->basicCertId->serialNumber,
			b->basicCertId->serialNumber)) != 0 ) {
		return 3;
	};

	if( a->extInfo && b->extInfo ) {

		char *tmp_a = NULL;
		char *tmp_b = NULL;

		aInfo = a->extInfo;
		bInfo = b->extInfo;

		if((ret = ASN1_STRING_cmp(aInfo->certificateHash, 
				bInfo->certificateHash)) != 0 ) {

			tmp_a = PKI_STRING_get_utf8( aInfo->certificateHash );
			tmp_b = PKI_STRING_get_utf8( bInfo->certificateHash );

			PKI_log_debug( "aInfo->certHash => %s", tmp_a );
			PKI_log_debug( "bInfo->certHash => %s", tmp_b );

			PKI_Free ( tmp_a );
			PKI_Free ( tmp_b );

			return 4;
		};

		if((ret = ASN1_OCTET_STRING_cmp(aInfo->subjectKeyHash, 
				bInfo->subjectKeyHash)) != 0 ) {
			return 5;
		};

		if( aInfo->subjectKeyId && bInfo->subjectKeyId ) {

			/*
			if((ret = ASN1_OCTET_STRING_cmp(aInfo->subjectKeyId, 
				bInfo->subjectKeyId)) != 0 ) {
				PKI_log_debug("PRQP_CMP (%d): a=%s, b=%s",
					ret,
					i2s_ASN1_OCTET_STRING( NULL, 
						aInfo->subjectKeyId), 
					i2s_ASN1_OCTET_STRING( NULL,
						bInfo->subjectKeyId ));
				return 6;
			};
			*/
		}

		if( aInfo->issuerKeyId && bInfo->issuerKeyId ) {

			if((ret = ASN1_OCTET_STRING_cmp(aInfo->issuerKeyId, 
				bInfo->issuerKeyId)) != 0 ) {
				return 7;
			};
		}
	}
		
	return 0;
}

int PRQP_init_all_services ( void ) {

	int i, ret;

        i = 0;

	// PKI_log_debug("PRQP_init_all_services() started!");

        while( prqp_exts[i] && prqp_exts[i+1] ) {
		// PKI_log_debug("PRQP_init_all_services():adding PRQP ext %s",
		// 					prqp_exts[i+1] );
                if((ret = OBJ_create(prqp_exts[i], prqp_exts[i+1], 
				prqp_exts[i+2])) == NID_undef) {
			PKI_log_debug("PRQP_init_all_services():Failed to add "
				" PRQP ext %s", prqp_exts[i+1] );
                        return 0;
                }
                i = i+3;
        }

	i = 0;
        while( prqp_exts_services[i] && prqp_exts_services[i+1] ) {
		// PKI_log_debug("PRQP_init_all_services():adding PRQP service %s",
		// 				prqp_exts_services[i+1] );
                if((ret = OBJ_create(prqp_exts_services[i], 
			prqp_exts_services[i+1], prqp_exts_services[i+2])) 
								== NID_undef) {
			PKI_log_debug("PRQP_init_all_services():Failed to add "
				" PRQP service %s", prqp_exts_services[i+1] );
                        return 0;
                }
                i = i+3;
        }

        return 1;

}

/*! \brief Generates a new CERT_IDENTIFIER to be used in a PRQP request */

CERT_IDENTIFIER * PKI_PRQP_CERTID_new_cert(PKI_X509_CERT  * caCert, 
					   PKI_X509_CERT  * issuerCert,
					   PKI_X509_CERT  * issuedCert,
					   char           * subject_s,
					   char           * serial_s,
					   PKI_DIGEST_ALG * dgst) {

	const PKI_X509_NAME *s_name = NULL;
	const PKI_X509_NAME *i_name = NULL;
	PKI_INTEGER *serial = NULL;
	/* BIT STRINGS */
	PKI_STRING *caKeyHash = NULL;
	PKI_STRING *issKeyHash = NULL;
	PKI_STRING *cHash = NULL;
	/* OCTET STRINGS */
	const PKI_STRING *skid = NULL;
	const PKI_STRING *ikid = NULL;

	CERT_IDENTIFIER *ret = NULL;

	if (!dgst) dgst = (PKI_DIGEST_ALG *) PKI_DIGEST_ALG_SHA1;

	/* Now get the IssuerName and the Serial of the Certificate x */
	if (caCert && caCert->value)
	{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
		LIBPKI_X509_CERT *xx = NULL;
#else
		PKI_X509_CERT_VALUE *xx = NULL;
#endif
		PKI_DIGEST *myDigest = NULL;

		xx = (X509 *) caCert->value;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL

		// Gets the SKID
		skid = X509_get0_subject_key_id(xx);

		/*
		int num = 0;
		PKI_X509_EXTENSION_VALUE *ext_v = NULL;

		// Gets the SKID
		num = X509_get_ext_by_NID(xx, NID_subject_key_identifier,-1);
		if (num < 0) {
			// Can not get SKID
			skid = NULL;
		} else if ((ext_v = X509_get_ext(xx, num)) != NULL) {
			skid = ext_v->value;
		}
		*/

		// Gets the AKID
		if (xx->akid) ikid = xx->akid->keyid;

		/*
		num = X509_get_ext_by_NID(xx, NID_authority_key_identifier,-1);
		if (num < 0) {
			// Can not get SKID
			skid = NULL;
		} else if ((ext_v = X509_get_ext(xx, num)) != NULL) {
			skid = ext_v->value;
		}
		*/
#else
		if (xx->skid) skid = xx->skid;
		if (xx->akid) ikid = xx->akid->keyid;
#endif

		s_name = (X509_NAME *) 
			PKI_X509_CERT_get_data( caCert, PKI_X509_DATA_SUBJECT );

		i_name = (X509_NAME *)
			PKI_X509_CERT_get_data( caCert, PKI_X509_DATA_ISSUER );

		serial = (ASN1_INTEGER *) 
			PKI_X509_CERT_get_data( caCert, PKI_X509_DATA_SERIAL);

		/* calculate the certificate Hash */
		/*
		if((cHash = PKI_STRING_new( PKI_STRING_OCTET )) == NULL ) {
			return NULL;
		};
		*/

		if ((myDigest = PKI_X509_CERT_fingerprint(caCert, dgst)) == NULL)
		{
			PKI_ERROR(PKI_ERR_GENERAL, "Can not get the CA certificate fingerprint");
			return NULL;
		}

		if ((cHash = PKI_STRING_new(PKI_STRING_OCTET, (char *) myDigest->digest, 
			(int) myDigest->size)) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}
		PKI_DIGEST_free(myDigest);

		/*
		else if (!X509_digest((X509 *)caCert->value, 
				(EVP_MD *) dgst, md, (unsigned int *) &i)) {
			ASN1_OCTET_STRING_free( cHash );
			return(NULL);
		}

		if (!(ASN1_OCTET_STRING_set(cHash, md, (int) i))) {
			ASN1_OCTET_STRING_free( cHash );
			return( NULL );
		}
		*/

		/* Calculate the Hash of the certificate Key */
		/*
		if((caKeyHash = ASN1_OCTET_STRING_new()) == NULL ) {
			if( cHash ) ASN1_OCTET_STRING_free ( cHash );
			return ( NULL );
		}
		*/
 
		if ((myDigest = PKI_X509_CERT_key_hash(caCert, dgst)) == NULL)
		{
			PKI_log_debug( "Can not get CA Cert key hash");
			PKI_STRING_free ( cHash );
			return NULL;
		}

		if (( caKeyHash = PKI_STRING_new( PKI_STRING_OCTET, 
				(char *) myDigest->digest, (int) myDigest->size)) == NULL )
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			PKI_DIGEST_free ( myDigest );
			PKI_STRING_free ( cHash );
			return NULL;
		}
		PKI_DIGEST_free ( myDigest );

		/*
		if(X509_pubkey_digest((X509 *) caCert->value, 
				(EVP_MD *)dgst, md, (unsigned int *) &i) == 0) {
			if( caKeyHash ) ASN1_OCTET_STRING_free( caKeyHash );
			if( cHash ) ASN1_OCTET_STRING_free( cHash );
			return (NULL);
		}

	        if (!(ASN1_OCTET_STRING_set(caKeyHash, md, i))) {
			if( caKeyHash ) ASN1_OCTET_STRING_free( caKeyHash );
			if( cHash ) ASN1_OCTET_STRING_free( cHash );
			return( NULL );
		}
		*/

	} 
	else
	{
		if (serial_s) serial = PKI_INTEGER_new_char ( serial_s );
		if (!serial)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}

		if (subject_s)
		{
			s_name = PKI_X509_NAME_new(subject_s);
			if(!s_name)
			{
				PKI_log_debug("%s:%d::Can not parse X509 NAME "
					"%s!", __FILE__, __LINE__, subject_s );
			}
		}
		else if (issuedCert && issuedCert->value)
		{
			s_name = PKI_X509_CERT_get_data( issuedCert, PKI_X509_DATA_ISSUER);
			if (!s_name)
			{
				PKI_log_debug("%s:%d::Can not get issuer from issuedCert [%s]",
					__FILE__, __LINE__, subject_s );
			}
		} 
		else 
		{
			if (serial) PKI_INTEGER_free ( serial );
			return (NULL);
		}
	}

	if (issuerCert && issuerCert->value)
	{
		PKI_DIGEST *myDigest = NULL;

		if ((myDigest = PKI_X509_CERT_key_hash(issuerCert, dgst)) == NULL)
		{
			PKI_ERROR(PKI_ERR_GENERAL, "Can not get issuerCert key Hash");
			PKI_STRING_free ( cHash );
			return NULL;
		}

		issKeyHash = PKI_STRING_new ( PKI_STRING_OCTET, 
			(char *) myDigest->digest, (int) myDigest->size);

		if (issKeyHash == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

			if (myDigest) PKI_DIGEST_free(myDigest);
			if (caKeyHash) PKI_STRING_free(caKeyHash);
			if (cHash) PKI_STRING_free(cHash);

			return NULL;
		}
			
		PKI_DIGEST_free ( myDigest );

		/* Calculate the Hash of the certificate Key */
		/*
		if((issKeyHash = ASN1_OCTET_STRING_new()) == NULL ) {
			return ( NULL );
		}

		if(X509_pubkey_digest((X509 *) issuerCert->value, 
				(EVP_MD *)dgst, md, (unsigned int *) &i) == 0){
			if( issKeyHash ) ASN1_OCTET_STRING_free( issKeyHash );
			return (NULL);
		}

	        if (!(ASN1_OCTET_STRING_set(issKeyHash, md, i))) {
			if( issKeyHash ) ASN1_OCTET_STRING_free( issKeyHash );
			return( NULL );
		}
		*/
	}

	/* Build the CERT_IDENTIFIER */
	if ((ret = PKI_PRQP_CERTID_new( s_name, i_name, serial, 
				cHash, caKeyHash, skid, ikid, dgst)) != NULL)
	{
		/* Now let's add the certificates to the identifier */
		/*
		if( caCert ) {
			ret->caCert = X509_dup( (X509 *) caCert );
		}

		if( issuedCert ) {
			ret->issuedCert = X509_dup( (X509 *) issuedCert );
		}
		*/
	}

	/* Free data */
	if( cHash ) PKI_STRING_free ( cHash );
	if( caKeyHash ) PKI_STRING_free ( caKeyHash );

	// if( skid ) PKI_STRING_free ( skid );
	// if( ikid ) PKI_STRING_free ( ikid );
	
	/* return the resulting data structure */
	return( ret );
}


CERT_IDENTIFIER *PKI_PRQP_CERTID_new( 
		const PKI_X509_NAME  * caName,
		const PKI_X509_NAME  * caIssuerName,
		const PKI_INTEGER    * serial,
		const PKI_STRING     * caCertHash,
		const PKI_STRING     * caKeyHash,
		const PKI_STRING     * caKeyId,
		const PKI_STRING     * issKeyId,
		const PKI_DIGEST_ALG * dgst) {
	int nid;
	PKI_ALGOR *alg;
	CERT_IDENTIFIER *ca_id = NULL;

	/* To build the Basic Cert Info we need these informations! */
	if( !dgst || !caName || !caIssuerName) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	if (!(ca_id = CERT_IDENTIFIER_new()))
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return (NULL);
	}

	if((ca_id->hashAlgorithm = X509_ALGOR_new()) == NULL )
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		if(ca_id) CERT_IDENTIFIER_free (ca_id);
		return(NULL);
	}

	alg = ca_id->hashAlgorithm;
	if (alg->algorithm != NULL) ASN1_OBJECT_free(alg->algorithm);

	if (((nid = EVP_MD_type(dgst)) == NID_undef) || 
		(!(alg->algorithm=OBJ_nid2obj(nid))) || 
		((alg->parameter=ASN1_TYPE_new()) == NULL))
	{

		if(ca_id) CERT_IDENTIFIER_free( ca_id );
		return( NULL );
	}

	alg->parameter->type=V_ASN1_NULL;

	/* Now build the BasicCertIdentifier */

	if ((ca_id->basicCertId = BASIC_CERT_IDENTIFIER_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if( ca_id ) CERT_IDENTIFIER_free( ca_id );
		return( NULL );
	}

	PKI_DIGEST *digest = NULL;
	PKI_STRING *str = NULL;

	digest = PKI_X509_NAME_get_digest(caIssuerName, dgst);
	if (digest == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		return NULL;
	}

	if ((str = PKI_STRING_new(PKI_STRING_OCTET, (char *) digest->digest, 
		(int) digest->size))==NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		PKI_DIGEST_free ( digest );
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		return NULL;
	}

	ca_id->basicCertId->issuerNameHash = str;

	PKI_DIGEST_free ( digest );

	if ((serial) && (!(ca_id->basicCertId->serialNumber = PKI_INTEGER_dup(serial))))
	{
		if(ca_id) CERT_IDENTIFIER_free( ca_id );
		return( NULL );
	}

	/* Now build the extInfo structure (if we have enough data!) */

	if (caCertHash != NULL)
	{
		if ((ca_id->extInfo = EXTENDED_CERT_INFO_new()) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			if( ca_id ) CERT_IDENTIFIER_free (ca_id);
			return( NULL );
		}

		ca_id->extInfo->certificateHash = PKI_STRING_dup(caCertHash);

		if (caKeyHash)
			ca_id->extInfo->subjectKeyHash = PKI_STRING_dup(caKeyHash);

		if (caKeyId)
			ca_id->extInfo->subjectKeyId = PKI_STRING_dup(caKeyId);

		if (issKeyId)
			ca_id->extInfo->issuerKeyId = PKI_STRING_dup(issKeyId);
	}

	return ca_id;
}

void *PKI_X509_PRQP_REQ_new_null( void )
{
	return PKI_X509_new(PKI_DATATYPE_X509_PRQP_REQ, NULL);
}

void PKI_X509_PRQP_REQ_free_void( void *x ) {
	PKI_X509_free_void( x );
	return;
}

void PKI_X509_PRQP_REQ_free ( PKI_X509_PRQP_REQ *x ) {
	PKI_X509_free ( x );

	return;
}

PKI_X509_PRQP_REQ *PKI_PRQP_REQ_new_cert(PKI_X509_CERT *caCert, 
		PKI_X509_CERT *caIssuerCert, PKI_X509_CERT *issuedCert,
			char *subject_s, char *serial_s, PKI_DIGEST_ALG *md ) {

	CERT_IDENTIFIER *ca_id = NULL;
	RESOURCE_REQUEST_TOKEN *token = NULL;
	PKI_X509_PRQP_REQ *p = NULL;
	PKI_X509_PRQP_REQ_VALUE *val = NULL;

	if((token = RESOURCE_REQUEST_TOKEN_new()) == NULL ) {
		return(NULL);
	}

	ca_id = PKI_PRQP_CERTID_new_cert ( caCert, caIssuerCert, issuedCert, 
						subject_s, serial_s, md );
	if( ca_id == NULL ) {
		PKI_log_debug( "Can not Generate the CA CERT identifier");
		if( token ) RESOURCE_REQUEST_TOKEN_free( token );
		return(NULL);
	}

	if(( val = PKI_PRQP_REQ_new ()) == NULL ) {
		PKI_log_debug( "Memory Error");
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		if( token ) RESOURCE_REQUEST_TOKEN_free( token );
		return(NULL);
	}

	if((val->requestData = PRQP_TBS_REQ_DATA_new()) == NULL ) {
		PKI_log_debug( "Memory Error");
		if( val   ) PKI_PRQP_REQ_free ( val );
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		if( token ) RESOURCE_REQUEST_TOKEN_free( token );
	}

	if (!ASN1_INTEGER_set(val->requestData->version, 1)) {
		PKI_log_debug( "Can not set version in requestData");
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		if( token ) RESOURCE_REQUEST_TOKEN_free( token );
		if( val ) PKI_PRQP_REQ_free ( val );
		return(NULL);
	}

	if (( p = PKI_X509_new_value ( PKI_DATATYPE_X509_PRQP_REQ, 
				val, NULL)) == NULL ) {
		PKI_log_err ( "Can not create a new PKI_X509 object.");
		if( ca_id ) CERT_IDENTIFIER_free ( ca_id );
		if( token ) RESOURCE_REQUEST_TOKEN_free( token );
		if( val ) PKI_PRQP_REQ_free ( val );
		return(NULL);
	}

	token->ca = ca_id;
	token->resourceList = sk_RESOURCE_IDENTIFIER_new_null();

	val->requestData->serviceToken = token;
	val->requestData->nonce = PKI_X509_PRQP_NONCE_new(80);

        val->requestData->producedAt = (ASN1_GENERALIZEDTIME *) PKI_TIME_new(0);

	return(p);
}

PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_new_url( char * ca_cert_s, char *ca_issuer_cert_s, 
	char *issued_cert_s, char *subject_s, char *serial_s, EVP_MD *md ) {

	PKI_X509_PRQP_REQ *p = NULL;

	PKI_X509_CERT *caCert = NULL;
	PKI_X509_CERT *caIssuerCert = NULL;
	PKI_X509_CERT *issuedCert = NULL;

	if( ca_cert_s &&
		((caCert = PKI_X509_CERT_get( ca_cert_s, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL )) == NULL)) {
		PKI_log_err ("Can not get CA Certificate from %s", ca_cert_s );
		return( NULL );
	}

	if( ca_issuer_cert_s &&
		( ( caIssuerCert = PKI_X509_CERT_get (
			(char *)ca_issuer_cert_s, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL ))== NULL)){
		if( caCert ) PKI_X509_CERT_free ( caCert );
		PKI_log_err ("Can not get Issuer Certificate from %s", 
							ca_issuer_cert_s );
		return( NULL );
	}

	if( issued_cert_s &&
		(( issuedCert = PKI_X509_CERT_get ( 
			(char *) issued_cert_s, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL ) )== NULL) ){
		if( caIssuerCert ) PKI_X509_CERT_free ( caIssuerCert );
		if( caCert ) PKI_X509_CERT_free ( caCert );
		PKI_log_err ("Can not get Issued Certificate from %s", 
							issued_cert_s );
		return( NULL );
	}

	if((p = PKI_PRQP_REQ_new_cert(caCert, caIssuerCert, issuedCert, 
					subject_s, serial_s, md)) == NULL) {
		if( issuedCert ) PKI_X509_CERT_free ( issuedCert );
		if( caIssuerCert ) PKI_X509_CERT_free ( caIssuerCert );
		if( caCert ) PKI_X509_CERT_free ( caCert );
	}

	return( p );

}

/*
PKI_X509_PRQP_REQ *PKI_X509_PRQP_REQ_new_file( char *file, PKI_DATA_FORMAT format) {

	PKI_X509_PRQP_REQ *p = NULL;
	BIO *req_bio = NULL;

	if ((req_bio=BIO_new(BIO_s_file())) == NULL) {
		return(NULL);
	}

	if (BIO_read_filename(req_bio,file) <= 0) {
		return(NULL);
        }

	if( format == PKI_DATA_FORMAT_PEM ) {
		p = PEM_read_bio_PRQP_REQ( req_bio );
	} else if ( format == PKI_DATA_FORMAT_ASN1 ) {
		// return d2i_PKI_PRQP_REQ_bio ( req_bio, NULL );
	} else {
		return(NULL);
	}

	return(p);
}
*/

PKI_X509_PRQP_REQ * PKI_X509_PRQP_REQ_new_certs_res( PKI_X509_CERT *caCert, 
		PKI_X509_CERT *caIssuerCert, PKI_X509_CERT *issuedCert,
		PKI_STACK *sk_services ) {

	PKI_X509_PRQP_REQ *p = NULL;
	PKI_X509_PRQP_REQ_VALUE *val = NULL;

	p = PKI_PRQP_REQ_new_cert( caCert, caIssuerCert, 
					issuedCert, NULL, NULL, NULL );
	if( !p || !p->value ) {
		PKI_log_err ( "Cannot generate request!");
		return(NULL);
	}

	val = p->value;

	if( !val->requestData || !val->requestData->serviceToken ||
				!val->requestData->serviceToken->resourceList ) {
		PKI_X509_PRQP_REQ_free ( p );
		return( NULL );
	}

	if((PKI_X509_PRQP_REQ_add_service_stack ( p, sk_services )) == PKI_ERR ) {
		PKI_X509_PRQP_REQ_free ( p );
		return ( NULL );
	}

	return( p );
}

/*! \brief Adds a stack of services to a PRQP REQUEST */

int PKI_X509_PRQP_REQ_add_service_stack ( PKI_X509_PRQP_REQ *p, 
					PKI_STACK *sk_services ) {

	int i = 0;

	if( !p || !p->value || !sk_services ) return ( PKI_ERR );

	for( i = 0; i < PKI_STACK_elements(sk_services); i++ ) {
		char *ss = NULL;

		ss = PKI_STACK_get_num( sk_services, i);
		if(PKI_X509_PRQP_REQ_add_service( p, ss ) == PKI_ERR ) {
			PKI_log( PKI_LOG_INFO, "PRQP REQ, Can not add %s", ss);
		}
	}

	return ( PKI_OK );
}

/*! \brief Adds a service identifier to a PRQP REQUEST */

int PKI_X509_PRQP_REQ_add_service ( PKI_X509_PRQP_REQ *p, char *ss ) {

	char tmp_str[1024];
	char *ver_s = NULL;

	PKI_OID *obj = NULL;
	STACK_OF(RESOURCE_IDENTIFIER) *list = NULL;

	RESOURCE_IDENTIFIER *new_item = NULL;
	PKI_X509_PRQP_REQ_VALUE *val = NULL;

	if( !p || !p->value || !ss ) return (PKI_ERR);

	val = p->value;

	if( !val->requestData || !val->requestData->serviceToken ||
		!val->requestData->serviceToken->resourceList ) return (PKI_ERR);

	list = val->requestData->serviceToken->resourceList;

	if((new_item = RESOURCE_IDENTIFIER_new()) == NULL ) {
		PKI_log_err("Can not allocate memory!");
		return ( PKI_ERR );
	}

	new_item->resourceId = NULL;
	new_item->version = NULL;
	new_item->oid = NULL;

	strncpy(tmp_str, ss, sizeof(tmp_str));
	if(( ver_s = strchr(tmp_str, ':')) != NULL ) {
		*ver_s = '\x0';
		ver_s++;
	};

	if((obj = PKI_OID_get ( tmp_str )) != NULL ) {
		new_item->resourceId = obj;
	} else {
		if((obj = PKI_OID_new( tmp_str, tmp_str, tmp_str )) == NULL) {
			PKI_log_debug( "ERROR::Can not add %s", tmp_str );
			return( PKI_ERR );
		} else {
			new_item->resourceId = obj;
		}
	}

	if( ver_s != NULL ) {
		char * oid_s = NULL;

		if(( oid_s = strchr(ver_s, ':')) != NULL ) {
			*oid_s = '\x0';
			oid_s++;
		};

		new_item->version = PKI_INTEGER_new_char( ver_s );

		if( oid_s ) {
			new_item->oid = PKI_OID_get( oid_s );
		}
	}

	/* Now we shall parse for the Version - for now we skip it! */
	sk_RESOURCE_IDENTIFIER_push( list, new_item );

	PKI_log_debug( "Service %s added ok!", ss );
	return( PKI_OK );
}


PKI_INTEGER *PKI_X509_PRQP_NONCE_new(int bits) {

        unsigned char buf[33];
        ASN1_INTEGER *nonce = NULL;
        int len;
        int i;

	if(bits <= 0 ) {
		bits = 80;
	}

	len = (bits - 1) / 8 + 1;

        if (len > (int)sizeof(buf))
		return(NULL);

        if (!RAND_bytes(buf, len))
		return(NULL);

        for (i = 0; i < len && !buf[i]; ++i);
        if (!(nonce = ASN1_INTEGER_new())) return (NULL);
        OPENSSL_free(nonce->data);

        nonce->length = len - i;
        if (!(nonce->data = OPENSSL_malloc((size_t)(nonce->length + 1))))
		return (NULL);

        memcpy(nonce->data, buf + i, (size_t) nonce->length);

        return(nonce);

}

// ***************** RESPONSE ******************

/*! \brief Sets the protocol version of a PRQP_RESP object */

int PKI_X509_PRQP_RESP_version_set ( PKI_X509_PRQP_RESP *resp, int ver ) {

	PKI_X509_PRQP_RESP_VALUE * val = NULL;

	if( !resp || !resp->value ) return PKI_ERR;

	val = resp->value;

	if ( !val->respData ) return PKI_ERR;

	ASN1_INTEGER_set(val->respData->version, ver);

	return PKI_OK;
}

/*! \brief Duplicates the NONCE from a PRQP REQ to a PRQP RESP */

int PKI_X509_PRQP_RESP_nonce_dup ( PKI_X509_PRQP_RESP *resp, PKI_X509_PRQP_REQ *req ) {

	PKI_X509_PRQP_REQ_VALUE *req_val = NULL;
	PKI_X509_PRQP_RESP_VALUE *resp_val = NULL;

	if( !resp || !req ) return PKI_ERR;

	req_val = req->value;
	resp_val = resp->value;

	if (!resp_val->respData || !req_val->requestData ) return PKI_ERR;

	if( req_val->requestData->nonce != NULL ) {
		resp_val->respData->nonce = 
			ASN1_OCTET_STRING_dup(req_val->requestData->nonce);
	}

	return (PKI_OK);
}

/*! \brief Sets the status of a PKI_X509_PRQP_RESP object */

int PKI_X509_PRQP_RESP_pkistatus_set ( PKI_X509_PRQP_RESP *resp, 
						long v, char *info ) {

	PKI_X509_PRQP_RESP_VALUE *resp_val = NULL;

	if( !resp || !resp->value ) return PKI_ERR;

	resp_val = resp->value;

	if (!resp_val->respData ) {
		PKI_log_debug( "Memory Error (missing resp/respData)");
		return (PKI_ERR);
	}

	/*
	if(resp->respData->pkiStatus == NULL) {
		if((resp->respData->pkiStatus = ASN1_INTEGER_new()) 
								== NULL) {
			PKI_log_debug( "Memory Error (Alloc) [%s:%d]",
							__FILE__, __LINE__ );
			return ( PKI_ERR );
		}
	}
	*/

	ASN1_INTEGER_set( resp_val->respData->pkiStatus->status, v);

	if (info)
	{
		PKI_STRING *str = NULL;

		if ((str = PKI_STRING_new_null( PKI_STRING_UTF8 )) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return( PKI_ERR );
		}

		if (PKI_STRING_set( str, info, (ssize_t) strlen(info)) == PKI_ERR)
		{
			PKI_ERROR(PKI_ERR_GENERAL, "Can not set STRING content");
			PKI_STRING_free(str);
			return PKI_ERR;
		}
		resp_val->respData->pkiStatus->statusString = str;
	}

	return PKI_OK;
}

/*! \brief Adds a stack of referrals (PKI_STACK) to a PRQP_RESP object */

int PKI_X509_PRQP_RESP_add_referrals ( PKI_X509_PRQP_RESP *resp, PKI_STACK *referrals)
{
	PKI_X509_PRQP_RESP_VALUE *r = NULL;
	STACK_OF(ASN1_IA5STRING) *sk = NULL;
	int i = 0;

	if( !resp || !resp->value || !referrals )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( PKI_ERR );
	}

	r = resp->value;

	if( !r->respData || !r->respData->pkiStatus )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if ((sk = r->respData->pkiStatus->referrals) != NULL)
		sk_ASN1_IA5STRING_free ( sk );

	if ((sk = sk_ASN1_IA5STRING_new_null()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	for ( i = 0; i < PKI_STACK_elements(referrals); i++)
	{
		PKI_STRING *st = NULL;
		char *val = NULL;

		if ((val = PKI_STACK_get_num(referrals, i)) == NULL)
			continue;

		st = PKI_STRING_new( PKI_STRING_IA5, val, (ssize_t) strlen(val));
		if (st == NULL ) continue;
		
		sk_ASN1_IA5STRING_push( sk, (ASN1_IA5STRING *) st); 
	}

	r->respData->pkiStatus->referrals = sk;

	return PKI_OK;
}

/*! \brief Adds a new service (single URL) to the stack of services
 *         in a PRQP_RESP */

int PKI_X509_PRQP_RESP_add_service ( PKI_X509_PRQP_RESP *r,
		PKI_OID * resId, char * url, long long version, 
			char *comment, PKI_OID *oid )
{

	PKI_STACK *sk = NULL;
	int ret = PKI_OK;

	if((sk = PKI_STACK_new_null()) == NULL )
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	ret = PKI_X509_PRQP_RESP_add_service_stack ( r, resId, sk,
				version, comment, oid );

	if ( sk ) PKI_STACK_free_all ( sk );

	return ret;
	
}

/*! \brief Adds a new service (stack of URLs) to the stack of services 
 *         in a PRQP_RESP */

int PKI_X509_PRQP_RESP_add_service_stack ( PKI_X509_PRQP_RESP *r,
		PKI_OID *resId, PKI_STACK *url_stack, long long version,
			char *comment, PKI_OID *oid )
{
	PKI_X509_PRQP_RESP_VALUE *r_val = NULL;
	RESOURCE_RESPONSE_TOKEN * resp_tk = NULL;

	int i = 0;

	if (!r || !r->value || !resId)
	{
		if ( !r || !r->value ) PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing PRQP RESP object");
		if (!resId) PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing service OID");
		return PKI_ERR;
	}

	r_val = r->value;

	if (!r_val->respData) 
		PKI_log_debug("ERROR in PRQP RESP format (missing respData)");


	if ((resp_tk = RESOURCE_RESPONSE_TOKEN_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	resp_tk->resourceId = PKI_OID_dup ( resId );

	if (version > -1)
		resp_tk->version = PKI_INTEGER_new (version);
	else
		resp_tk->version = NULL;

	if (oid != NULL)
		resp_tk->oid = PKI_OID_dup ( oid );
	else
		resp_tk->oid = NULL;

	if (comment != NULL && strlen(comment) > 0 )
	{
		resp_tk->textInfo = PKI_STRING_new(PKI_STRING_UTF8,
				comment, (ssize_t) strlen(comment));
	}
	else
	{
		resp_tk->textInfo = NULL;
	}

	if (url_stack)
	{
		for (i = 0; i < PKI_STACK_elements( url_stack ); i++)
		{
			PKI_STRING *string = NULL;
			char * tmp_s = NULL;

			if ((tmp_s = PKI_STACK_get_num(url_stack, i)) != NULL)
			{
				string = PKI_STRING_new(PKI_STRING_IA5, tmp_s, (ssize_t) strlen( tmp_s));
				sk_ASN1_IA5STRING_push( resp_tk->resLocatorList, string );
			}
		}
	}

	if (!r_val->respData->responseToken )
	{
		if((r_val->respData->responseToken = 
			sk_RESOURCE_RESPONSE_TOKEN_new_null()) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			RESOURCE_RESPONSE_TOKEN_free ( resp_tk );
			return PKI_ERR;
		}
	}

	sk_RESOURCE_RESPONSE_TOKEN_push(r_val->respData->responseToken, resp_tk );

	return PKI_OK;
}

/*! \brief Creates a new PRQP_RESP empty object */

void *PKI_X509_PRQP_RESP_new_null(void)
{
	return ((void *) PKI_X509_new( PKI_DATATYPE_X509_PRQP_RESP, NULL));
}

void PKI_X509_PRQP_RESP_free_void( void *x )
{
	PKI_X509_free_void ( x );
	return;
}

/*! \brief Releases the memory associated with a PRQP_RESP object */

void PKI_X509_PRQP_RESP_free(PKI_X509_PRQP_RESP *x)
{
	PKI_X509_free ( x );

	return;
}

/*! \brief Created a new PRQP_RESP from the contents of a PRQP_REQ */

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_new_req ( PKI_X509_PRQP_RESP **resp_pnt, 
			PKI_X509_PRQP_REQ *x_req, int status, long secs )
{
	PKI_X509_PRQP_RESP_VALUE *resp = NULL;
	PKI_X509_PRQP_REQ_VALUE *req = NULL;
	PKI_X509_PRQP_RESP *r = NULL;

	if (resp_pnt)
	{
		if( *resp_pnt == NULL)
		{
			r = PKI_X509_PRQP_RESP_new_null();
			*resp_pnt = r;
		}
		else r = (*resp_pnt)->value;
	}
	else r = PKI_X509_PRQP_RESP_new_null();

	if(r == NULL) 
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (!r->value ) r->value = r->cb->create();

	resp = r->value;

	if( resp->respData == NULL)
	{
		if ((resp->respData = PRQP_TBS_RESP_DATA_new()) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			PKI_X509_PRQP_RESP_free(r);

			resp = NULL; // Safety
			return PKI_ERR;
		}
	}

	/*
	if( resp->respData->pkiStatus == NULL ) {
		if((resp->respData->pkiStatus = PKI_STATUS_INFO_new()) 
								== NULL) {
			if( resp ) PKI_PRQP_RESP_free( resp );
			return ( PKI_ERR );
		}
	}
	*/

	PKI_X509_PRQP_RESP_version_set( r, 1);

	if (status)
		PKI_X509_PRQP_RESP_pkistatus_set( r, status, NULL );
	else
		PKI_X509_PRQP_RESP_pkistatus_set( r, 0, NULL );

	resp->respData->producedAt = (ASN1_GENERALIZEDTIME *) PKI_TIME_new(0);

	if (x_req) req = x_req->value;

	if (req && req->requestData)
	{
		CERT_IDENTIFIER * req_caId = NULL;
		CERT_IDENTIFIER * resp_caId = NULL;

		/* Let's duplicate the nonce */
		if(req->requestData->nonce) PKI_X509_PRQP_RESP_nonce_dup ( r, x_req );

		if( !req->requestData || !req->requestData->serviceToken ||
				!req->requestData->serviceToken->ca )
		{
			PKI_X509_PRQP_RESP_pkistatus_set( r, PKI_X509_PRQP_STATUS_BAD_REQUEST,
						"Response is Malformed" );

			PKI_log_debug("PKI_PRQP_RESP, error missing fields in REQ!");
		}

		// Let's duplicate the CA Id, maybe it is not needed 
		// as the request/response is tied by the NONCE, but
		// it could be useful for forensics, in case a 
		// response is involved for later verifications

		PKI_log_debug( "Adding caCertId to Response!");

		req_caId = req->requestData->serviceToken->ca;

		// Alloc new memory for the response cert identifier
		/* resp_caId = CERT_IDENTIFIER_new(); */

		resp_caId = (CERT_IDENTIFIER *) CERT_IDENTIFIER_dup( req_caId );

		/* memset( resp_caId, 0, sizeof( BASIC_CERT_IDENTIFIER )); */

		// Now let's duplicate the data
		// resp_caId->subjectNameHash =
		// 	ASN1_OCTET_STRING_dup ( req_caId->subjectNameHash );

		/*
		if( req_caId->hashAlgorithm ) {
			resp_caId->hashAlgorithm = 
				X509_ALGOR_dup( req_caId->hashAlgorithm );
		}
		
		if( req_caId->basicCertId ) {
			BASIC_CERT_IDENTIFIER_dup( resp_caId->basicCertId,
				req_caId->basicCertId );
			// Theese field is optional 
			// resp_caId->serialNumber = 
			// 	ASN1_INTEGER_dup( req_caId->serialNumber );
		}

		if( req_caId->extInfo ) {
			EXTENDED_CERT_INFO_dup( resp_caId->extInfo,
				req_caId->extInfo );
		}
		*/

		/*
		if( req_caId->issuerNameHash ) {
			// Theese field is optional
			resp_caId->issuerNameHash =
				ASN1_OCTET_STRING_dup(req_caId->issuerNameHash);
		}
		*/

		resp->respData->caCertId = resp_caId;

		//
		// resp->respData->caCertId = (BASIC_CERT_IDENTIFIER *)
		// 	BASIC_CERT_IDENTIFIER_dup( 
		// 			req->requestData->serviceToken->ca->basicCertId);
		/*
		} else {
			PKI_log_debug("Some fields are missing!");
			if( !req->requestData->serviceToken ) {
				PKI_log_debug("Field [serviceToken] is missing in req!");
			} else if( !req->requestData->serviceToken->ca ) {
				PKI_log_debug("Field [serviceToken->ca] is missing in req!");
			} else if( !req->requestData->serviceToken->ca->basicCertId ) {
				PKI_log_debug("Field [serviceToken->ca->basicCertId] is missing in req!");
			}
		}
		*/
	}

	if( secs > 0  ) {
		resp->respData->nextUpdate = PKI_TIME_new ( secs );
	}

	return r;
}

/*! \brief Returns a PKI_STACK of URLs from a PRQP RESP object */

PKI_STACK * PKI_X509_PRQP_RESP_url_sk ( PKI_X509_PRQP_RESP *r ) {

	PKI_STACK *url_sk = NULL;
	STACK_OF(PKI_RESOURCE_RESPONSE_TOKEN_STACK) *pki_sk=NULL;

	if( !r ) return (NULL);

	if((url_sk = PKI_STACK_new_null()) == NULL) {
		return (NULL);
	}

	if(( pki_sk = PKI_X509_PRQP_RESP_get_data( r, 
				PKI_X509_DATA_PRQP_SERVICES) ) != NULL){
		int i = 0;
                RESOURCE_RESPONSE_TOKEN *res = NULL;

		url_sk = PKI_STACK_new_null();

		for( i = 0; i < 
			PKI_STACK_RESOURCE_RESPONSE_TOKEN_elements (pki_sk ); 
									i++) {
			ASN1_IA5STRING *resInfo = NULL;
			char *url_s = NULL;
			int j = 0;

			res = PKI_STACK_RESOURCE_RESPONSE_TOKEN_get_num (
								pki_sk, i);

			if( !res ) {
				continue;
			}

			for ( j = 0; j < sk_ASN1_IA5STRING_num(
						res->resLocatorList); j++ ) {

				resInfo = sk_ASN1_IA5STRING_value(
						res->resLocatorList, j );

				url_s = PKI_STRING_get_utf8 ( resInfo );
				
				if( url_s ) PKI_STACK_push( url_sk, url_s );
			}
		}
	}

	return ( url_sk );
}

/*! \brief Signs a PRQP object */

int PKI_X509_PRQP_sign( PKI_X509 *obj, PKI_X509_KEYPAIR *k, 
			PKI_X509_CERT *x, PKI_DIGEST_ALG *dgst, 
					PKI_X509_CERT_STACK * certs ) {

	PKI_X509_PRQP_REQ_VALUE *req = NULL;
	PKI_X509_PRQP_RESP_VALUE *resp = NULL;

	PKI_DIGEST_ALG *dd = NULL;
	int i = 0;

	PRQP_SIGNATURE *psig = NULL;

	if( !k || !k->value || !x || !x->value || !obj || !obj->value ) {
		PKI_log_debug("ERROR:PRQP:Sign key=%p, cert=%p\n", k, x );
		PKI_log_debug( "ERROR, missing needed args 2 signing PRQP!");
		return (PKI_ERR);
	}

	if( !dgst )
		dd = PKI_DIGEST_ALG_get( PKI_ALGOR_SHA256 );
	else
		dd = dgst;

	switch ( obj->type ) {
		case PKI_DATATYPE_X509_PRQP_REQ:
			req = obj->value;
			break;
		case PKI_DATATYPE_X509_PRQP_RESP:
			resp = obj->value;
			break;
		default:
			PKI_log_err("PRQP_sign called on non PRQP object %d (%d,%d)!",
				obj->type, PKI_DATATYPE_X509_PRQP_REQ, PKI_DATATYPE_X509_PRQP_RESP );
			return ( PKI_ERR );
	}

	if ( req && !req->prqpSignature ) {
                if((psig = PRQP_SIGNATURE_new()) == NULL ) {
                        PKI_log_err("Memory Allocation");
                        return( PKI_ERR );
                } else {
			req->prqpSignature = psig;
		}
        } else if ( resp && !resp->prqpSignature ) {
                if((psig = PRQP_SIGNATURE_new()) == NULL ) {
                        PKI_log_err("Memory Allocation");
                        return( PKI_ERR );
                } else {
			resp->prqpSignature = psig;
		}
	}

	if( PKI_X509_sign ( obj, dd, k ) == PKI_ERR ) {
		PKI_log_debug("ERROR, PRQP Sign Failed [%s]!",
			ERR_error_string(ERR_get_error(), NULL));
		return(PKI_ERR);
	}

	if( certs && psig ) {
		if( psig->otherCerts == NULL ) {
			if((psig->otherCerts = sk_X509_new_null()) == NULL) {
				PKI_log_debug("ERROR, Can not Create stack "
						"of certs in signature!");
				return( PKI_ERR );
			}
		}

		for( i = 0; i < PKI_STACK_X509_CERT_elements( certs ); i++ ) {
			PKI_X509_CERT *x_tmp = NULL;

			x_tmp = PKI_STACK_X509_CERT_get_num( certs, i );
			if (x_tmp && x_tmp->value ) {
				sk_X509_push( psig->otherCerts, 
					PKI_X509_dup_value ( x_tmp ));
			}
		}
	}

	PKI_log_debug("INFO, Adding certificate signer's certificate "
								"to RESP!");
	psig->signerCert = PKI_X509_dup_value ( x );

	return( PKI_OK );
}

/*! \brief Signs a PRQP object by using a provided TOKEN object */

int PKI_X509_PRQP_sign_tk ( PKI_X509_PRQP_RESP *resp, PKI_TOKEN *tk, 
						PKI_DIGEST_ALG *dgst ){

	if( !tk || !tk->keypair || !tk->cert ) return ( PKI_ERR );
	
	return ( PKI_X509_PRQP_sign( resp, tk->keypair, tk->cert, dgst, 
						tk->otherCerts ));
}

/*! \brief Verifies that the signature on a PRQP object is correct */

int PKI_X509_PRQP_verify ( PKI_X509 *r ) {

	PKI_X509_CERT *x = NULL;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;
	PKI_X509_KEYPAIR *key = NULL;
	int ret = PKI_OK;

	if ( (r->type != PKI_DATATYPE_X509_PRQP_REQ ) &&
			(r->type != PKI_DATATYPE_X509_PRQP_RESP ) ) {
		return PKI_ERR;
	}

	if( PKI_X509_is_signed ( r ) == PKI_ERR ) {
		PKI_log_err("PKI_PRQP_verify() - Object not signed!");
		return ( PKI_ERR );
	}

	if( (x = PKI_X509_get_data ( r, 
				PKI_X509_DATA_SIGNER_CERT )) == NULL ) {
		PKI_log_err("PKI_PRQP_verify() - Can not get Signer Cert!");
		return ( PKI_ERR );
	}

	if((pkey = PKI_X509_get_data( x, 
				PKI_X509_DATA_KEYPAIR_VALUE)) == NULL ) {
		PKI_log_err("PKI_PRQP_verify() - Can not get Signer's Key!");
		return PKI_ERR;
	}

	if (( key = PKI_X509_new_value ( PKI_DATATYPE_X509_KEYPAIR, 
						pkey, NULL)) == NULL ) {
		return PKI_ERR;
	}

	ret = PKI_X509_verify ( r, key );

	key->value = NULL;
	PKI_X509_KEYPAIR_free ( key );

	return ret;
	
}

/*! \brief Verify Signature on the PRQP REQUEST */

int PKI_X509_PRQP_REQ_verify ( PKI_X509_PRQP_REQ *r ) {

	return PKI_X509_PRQP_verify ( r );
}

int PKI_X509_PRQP_RESP_verify ( PKI_X509_PRQP_RESP *r ) {

	return PKI_X509_PRQP_verify ( r );
}

// ===================== Print Functions for REQ/RESP =================

/*! \brief Prints out the contents of a PRQP_REQ on stdout */

int PKI_X509_PRQP_REQ_print ( PKI_X509_PRQP_REQ *req ) {
	return PKI_X509_PRQP_REQ_print_fp( stdout, req );
}

/*! \brief Writes a PRQP_REQ in text format in the passed file pointer */

int PKI_X509_PRQP_REQ_print_fp ( FILE *fp, PKI_X509_PRQP_REQ *req ) {

	BIO *bio = NULL;
	int ret = -1;

	if ( !req || !req->value ) return PKI_ERR;

	if ( !fp ) fp = stdout;

	if((bio = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
		return PKI_ERR;
	}

	ret = PKI_X509_PRQP_REQ_VALUE_print_bio( req->value, bio );

	BIO_free ( bio );

	return ret;
	
}

int PKI_X509_PRQP_REQ_VALUE_print_bio ( PKI_PRQP_REQ *req, BIO *bio ) {

	PRQP_TBS_REQ_DATA *rd = NULL;
	BASIC_CERT_IDENTIFIER *ci = NULL;
	RESOURCE_REQUEST_TOKEN *rt = NULL;
	STACK_OF(RESOURCE_IDENTIFIER) *list = NULL;

	PKI_TIME *time = NULL;
	int i = 0;

	if( !req || !req->requestData || !bio ) return (PKI_ERR);

	rd = req->requestData;

	BIO_printf( bio, "PRQP Request:\r\n");
	BIO_printf( bio, "    Version: %s (0x%s)\r\n", 
			i2s_ASN1_INTEGER(NULL, rd->version ),
			i2s_ASN1_INTEGER(NULL, rd->version ));

	if( rd->nonce ) {
		BIO_printf( bio, "    Nonce: %s\r\n", 
			i2s_ASN1_OCTET_STRING(NULL, rd->nonce));
				// i2s_ASN1_INTEGER( NULL, rd->nonce ));
	} else {
		BIO_printf( bio, "    Nonce: %s\r\n", "[ Not Present ]");
	}
	if ( (time = rd->producedAt) != NULL ) {
		char *tmp_time = NULL;
		tmp_time = PKI_TIME_get_parsed ( time );
		BIO_printf( bio, "    Produced At: %s\r\n", tmp_time);
		PKI_Free ( tmp_time );
	}

	ci = rd->serviceToken->ca->basicCertId;

	BIO_printf( bio, "\r\n");
	BIO_printf( bio, "    Certification Authority Identifier:\r\n" );

	if( ci->serialNumber ) {
		BIO_printf( bio, "        Serial Number:\r\n");
		BIO_printf( bio, "            %s (0x%s)\r\n", 
			i2s_ASN1_INTEGER(NULL,ci->serialNumber),
			i2s_ASN1_OCTET_STRING(NULL,ci->serialNumber));
	} else {
		BIO_printf( bio, "        Serial Number: %s\r\n", 
			"[ Not Present ]" );
	}

	/*
	if( ci->subjectNameHash ) {
		fprintf( fp, "        Subject Name Hash:\r\n");
		fprintf( fp, "            %s\r\n", 
			i2s_ASN1_OCTET_STRING( NULL, ci->subjectNameHash) );
	} else {
		fprintf( fp, "         Subject Name Hash:\r\n");
		fprintf( fp, "            %s\r\n", 
			"[ Not Present ]" );
	}
	*/

	if( ci->issuerNameHash ) {
		BIO_printf( bio, "        Issuer Name Hash:\r\n");
		BIO_printf( bio, "            %s\r\n", 
			i2s_ASN1_OCTET_STRING(NULL, ci->issuerNameHash));
	}

	BIO_printf( bio, "\r\n    Requested Services:\r\n" );
	rt = req->requestData->serviceToken;
	if( (rt == NULL) || ( rt->resourceList == NULL ) || 
			(sk_RESOURCE_IDENTIFIER_num( rt->resourceList ) < 1) ) {
		BIO_printf( bio, "        ALL\r\n");
	} else {
		list = req->requestData->serviceToken->resourceList;

		for( i=0; i < sk_RESOURCE_IDENTIFIER_num( list ); i++ ) {

			RESOURCE_IDENTIFIER *ri = NULL;

			ri = sk_RESOURCE_IDENTIFIER_value(list, i);

                        BIO_printf( bio, "        %s:\r\n", 
				(char *) PKI_OID_get_descr ( ri->resourceId ));

			if( ri->version != NULL ) {
				char *tmp_str = NULL;
				tmp_str = PKI_INTEGER_get_parsed ( ri->version);
				BIO_printf(bio, "            Version: %s\r\n", 
					tmp_str);
				PKI_Free ( tmp_str );
			} else {
				BIO_printf(bio, "            Version: Any\r\n");
			}

			if( ri->oid != NULL ) {
				// char *oid_str = NULL;

				BIO_printf(bio, "            "
					"Identifier: %s\r\n", 
						PKI_OID_get_descr (ri->oid ));
				/*
				if(( oid_str = PKI_OID_get_descr ( ri->oid ))
								!= NULL ) {
					fprintf(fp, "            "
						"Identifier: %s\r\n", oid_str);
					// PKI_Free ( oid_str );
				}

				*/
			} else {
				BIO_printf( bio, 
					"            Identifier: Any\r\n");
			}
               }
	}

	if( rd->extensions ) {
		BIO_printf( bio, "   Extensions:\r\n");
		BIO_printf( bio, "      *** EXTENSIONS PRESENT ***\r\n");
	}

	if( req->prqpSignature && req->prqpSignature->signature ) {
		PKI_X509_PRQP_REQ *x_obj = NULL;

		//if((out = BIO_new_fp( fp, BIO_NOCLOSE )) != NULL ) {
			X509_signature_print( bio, 
				req->prqpSignature->signatureAlgorithm, 
					req->prqpSignature->signature );
		//	BIO_free ( out );
		//}
		
		BIO_printf( bio, "    Signature Verification: ");
		if(( x_obj = PKI_X509_new_dup_value (PKI_DATATYPE_X509_PRQP_REQ,
					req, NULL )) == NULL ) {
			BIO_printf( bio, "ERROR.");
		} else {
			if(PKI_X509_PRQP_REQ_verify( x_obj ) == PKI_OK ) {
				BIO_printf( bio, "Ok.\r\n" );
			} else {
				BIO_printf( bio, "Error => %s\r\n",
					ERR_error_string(ERR_get_error(),NULL));
			}

			PKI_X509_PRQP_REQ_free ( x_obj );
		}
	}

	return (PKI_OK);
}

/*! \brief Prints out the contents of a PRQP_RESP to stdout */

int PKI_X509_PRQP_RESP_print ( PKI_X509_PRQP_RESP *resp ) {
	return PKI_X509_PRQP_RESP_print_fp( stdout, resp );
}

/*! \brief Writes a PRQP_RESP in text format to the passed file pointer */

int PKI_X509_PRQP_RESP_print_fp ( FILE *fp, PKI_X509_PRQP_RESP *resp ) {

	BIO *bio = NULL;
	int ret = -1;

	if ( !resp || !resp->value ) return PKI_ERR;

	if ( !fp ) fp = stdout;

	if((bio = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
		return PKI_ERR;
	}

	ret = PKI_X509_PRQP_RESP_VALUE_print_bio( resp->value , bio );

	BIO_free ( bio );

	return ret;
}


int PKI_X509_PRQP_RESP_VALUE_print_bio (PKI_X509_PRQP_RESP_VALUE *resp, BIO *bio) {

	PRQP_TBS_RESP_DATA *rd = NULL;
	CERT_IDENTIFIER *ci = NULL;
	BASIC_CERT_IDENTIFIER *bci = NULL;
	STACK_OF(RESOURCE_RESPONSE_TOKEN) *pki_sk=NULL;
	PKI_STACK *referrals = NULL;

	int i = 0;
	int status = 0;

	PKI_TIME *time = NULL;

	if( !resp || !resp->respData || !bio ) return PKI_ERR;

	rd = resp->respData;

	BIO_printf( bio, "PRQP Response:\r\n");

	BIO_printf( bio, "    Version: %s (0x%s)\r\n", 
			i2s_ASN1_INTEGER(NULL, rd->version ),
			i2s_ASN1_INTEGER(NULL, rd->version ));
	ci = rd->caCertId;
	if( rd->nonce ) {
		BIO_printf( bio, "    Nonce: %s\r\n", 
			i2s_ASN1_OCTET_STRING(NULL, rd->nonce));
				// i2s_ASN1_INTEGER( NULL, rd->nonce ));
	} else {
		BIO_printf( bio, "    Nonce: %s\r\n", "[ Not Present ]");
	}

	if ( (time = rd->producedAt) != NULL ) {
		char * tmp_time = NULL;
		BIO_printf( bio, "    Produced At: ");
		tmp_time = PKI_TIME_get_parsed ( time );
		BIO_printf( bio, "%s\r\n", tmp_time);
		PKI_Free ( tmp_time );
	}

	if ( (time = rd->nextUpdate) != NULL ) {
		char * tmp_time = NULL;
		BIO_printf( bio, "    Next Update: ");
		tmp_time = PKI_TIME_get_parsed ( time );
		BIO_printf( bio, "%s\r\n", tmp_time);
		PKI_Free ( tmp_time );
	}

	BIO_printf( bio, "\r\n");
	status = PKI_X509_PRQP_RESP_get_status_value ( resp );
	BIO_printf( bio, "    PKI Status:\r\n        %s (%d)\r\n", 
			(char *) PKI_X509_PRQP_RESP_VALUE_get_data( resp, 
				PKI_X509_DATA_PRQP_STATUS_VALUE ), status);


	if((referrals = PKI_X509_PRQP_RESP_VALUE_get_data(resp, 
				PKI_X509_DATA_PRQP_REFERRALS)) != NULL ) {
		BIO_printf( bio, "\r\n");
		BIO_printf( bio, "    Referrals:\r\n");
		for(i=0; i < PKI_STACK_elements ( referrals ); i++ ) {
			char * val = NULL;

			if((val = PKI_STACK_get_num( referrals, i)) == NULL ) {
				continue;
			}

			BIO_printf( bio, "        %s\r\n", val);
		}

		PKI_STACK_free_all ( referrals );
	}


	/*
	fprintf( fp, "    PRQP Referrals:\r\n");

	if((referrals=PKI_PRQP_RESP_get_data(resp, PKI_X509_DATA_REFERRALS))
							== NULL ) {
		fprintf(fp, "        None.\r\n");
	} else {
		for(i=0; i < PKI_STACK_elements ( referrals ); i++ ) {
			char * val = NULL;

			if((val = PKI_STACK_get_num( referrals, i)) == NULL ) {
				continue;
			}

			fprintf( fp, "        %s\r\n", val);
		}
		fprintf( fp, "\r\n");

		PKI_STACK_free_all ( referrals );
	}
	*/

	ci = rd->caCertId;
	if((bci = ci->basicCertId) != NULL ) {
		BIO_printf( bio, 
			"\r\n    Certification Authority Identifier:\r\n");
		if( bci->serialNumber ) {
			BIO_printf( bio, "        Serial Number:\r\n");
			BIO_printf( bio, "            %s (0x%s)\r\n", 
				i2s_ASN1_INTEGER(NULL,bci->serialNumber),
				i2s_ASN1_OCTET_STRING(NULL,bci->serialNumber));
		} else {
			BIO_printf( bio, "        Serial Number: %s\r\n", 
				"[ Not Present ]" );
		}

		if( bci->issuerNameHash ) {
			BIO_printf( bio, "        Issuer Name Hash:\r\n");
			BIO_printf( bio, "            %s\r\n", 
			   i2s_ASN1_OCTET_STRING(NULL, bci->issuerNameHash));
		}
	}
	BIO_printf( bio, "\r\n");

	if( strcmp ( PKI_X509_PRQP_RESP_VALUE_get_data( resp, 
				PKI_X509_DATA_PRQP_STATUS_VALUE ),
					PKI_X509_PRQP_STATUS_STRING_OK) == 0 ) {
	   BIO_printf( bio, "    Requested Services:\r\n");
	   if(( pki_sk=PKI_X509_PRQP_RESP_VALUE_get_data(resp,
					PKI_X509_DATA_PRQP_SERVICES))!= NULL){

		RESOURCE_RESPONSE_TOKEN *res = NULL;

		for( i = 0; i < 
			PKI_STACK_RESOURCE_RESPONSE_TOKEN_elements (pki_sk ); 
									i++) {
		/*
		while( (res = PKI_STACK_RESOURCE_RESPONSE_TOKEN_pop( pki_sk ))
								!= NULL ) {
		*/
			ASN1_IA5STRING *resInfo = NULL;

			res = PKI_STACK_RESOURCE_RESPONSE_TOKEN_get_num (
								pki_sk,i);

			if( PKI_OID_get_id ( res->resourceId ) 
							!= PKI_ID_UNKNOWN ) {
				BIO_printf( bio, "        %s:\r\n", 
					PKI_OID_get_descr( res->resourceId ));

			} else {
				char *tmpIdStr = NULL;
				tmpIdStr = PKI_OID_get_str ( res->resourceId);
				if( tmpIdStr ) {
					BIO_printf( bio, "        %s:\r\n", 
						tmpIdStr);
					PKI_Free ( tmpIdStr );
				} else {
					BIO_printf( bio, "        %s:\r\n", 
						"Unknown Service ID");
				}
			}

			if( res->version != NULL ) {
				BIO_printf(bio, "            Version: %s\r\n",
					PKI_INTEGER_get_parsed( res->version ));
			} else {
				BIO_printf(bio, "            Version: Any\r\n");
			}

			if( res->oid != NULL ) {
				char *tmp_ID = NULL;

				if( (tmp_ID = PKI_OID_get_str ( res->oid ))
								!= NULL ) {
					BIO_printf ( bio, "            "
						"OID: %s\r\n", tmp_ID );
				} else {
				BIO_printf(bio, "            OID: None\r\n");
				}
			}
			
			if( res->textInfo != NULL ) {
				char *tmp_str = NULL;
				tmp_str = PKI_STRING_get_utf8 ( res->textInfo );
				BIO_printf(bio, "            Extra Information:"
						"\r\n%s\r\n", tmp_str );
				PKI_Free ( tmp_str );
			} else {
				BIO_printf(bio, "            "
					"Extra Information: None\r\n" );
			}

			while((resInfo = sk_ASN1_IA5STRING_pop( 
					res->resLocatorList )) != NULL) {
				char *tmp_str = NULL;
				BIO_printf( bio, "            URI:");
				tmp_str = PKI_STRING_get_utf8(resInfo);
				BIO_printf( bio, "%s\r\n", tmp_str);
				PKI_Free ( tmp_str );
			}
			BIO_printf (bio, "\r\n");

		}
		// if( res ) RESOURCE_RESPONSE_TOKEN_free ( res );
	   } else {
		PKI_log_debug("Parsing Response, no SERVICES found!");
	   }
	}

	BIO_printf( bio, "\r\n" );

	if( rd->extensions ) {
		BIO_printf( bio, "   Extensions:\r\n");
		BIO_printf( bio, "      *** EXTENSIONS PRESENT ***\r\n");
	}

	if( resp->prqpSignature && resp->prqpSignature->signature ) {
		PKI_X509_PRQP_RESP *x_obj = NULL;

		// if((out = BIO_new_fp( fp, BIO_NOCLOSE )) != NULL ) {
			X509_signature_print( bio, 
				resp->prqpSignature->signatureAlgorithm, 
					resp->prqpSignature->signature );
			// BIO_free ( out );
		// }

		BIO_printf(bio, "    Signature Verification: ");
		if(( x_obj = PKI_X509_new_dup_value(PKI_DATATYPE_X509_PRQP_RESP,
					resp, NULL )) == NULL ) {
			BIO_printf( bio, "ERROR.");
		} else {
			if(PKI_X509_PRQP_verify( x_obj ) == PKI_OK ) {
				BIO_printf( bio, "Ok.\r\n" );
			} else {
				BIO_printf( bio, "Error => %s",
					ERR_error_string(ERR_get_error(),NULL));
				BIO_printf(bio, "\r\n");
			}

			PKI_X509_PRQP_RESP_free ( x_obj );
		}
	}

	return PKI_OK;
}

/* --------------------------- Data Retrieval --------------------------- */

/*! \brief Returns data pointers from a PRQP request  */

void * PKI_X509_PRQP_REQ_get_data ( PKI_X509_PRQP_REQ *obj, PKI_X509_DATA type ) {

	PKI_X509_PRQP_REQ_VALUE *r = NULL;

	if( !obj || !obj->value ) return ( NULL );

	r = obj->value;

	return PKI_X509_PRQP_REQ_VALUE_get_data( r, type );

}

/*! \brief Returns data pointers from a PRQP_REQ_VALUE  */

static void * PKI_X509_PRQP_REQ_VALUE_get_data ( PKI_X509_PRQP_REQ_VALUE *r,
					PKI_X509_DATA type ) {

	PKI_X509_CERT_VALUE *cert_val = NULL;
	void * ret = NULL;

	if (!r || !r->requestData ) return NULL;

	switch ( type )
	{
		case PKI_X509_DATA_VERSION:
			ret = r->requestData->version;
			break;

		case PKI_X509_DATA_NONCE:
			ret = r->requestData->nonce;
			break;

		case PKI_X509_DATA_PRODUCEDAT:
		case PKI_X509_DATA_NOTBEFORE:
			ret = r->requestData->producedAt;
			break;

		case PKI_X509_DATA_SIGNATURE_CERTS:
			if( r->prqpSignature && r->prqpSignature->otherCerts)
			{
				int i = 0;
				PKI_X509_CERT_STACK *s = NULL;

				s = PKI_STACK_X509_CERT_new();
				for (i = 0 ; i < sk_X509_num(r->prqpSignature->otherCerts ); i++ )
				{
					PKI_STACK_X509_CERT_push(ret, 
						sk_X509_value(r->prqpSignature->otherCerts, i));
				}
				ret = s;
			}
			break;

		case PKI_X509_DATA_SIGNATURE:
			if (r->prqpSignature) ret = r->prqpSignature->signature;
			break;

		case PKI_X509_DATA_ALGORITHM:
		case PKI_X509_DATA_SIGNATURE_ALG1:
			if (r->prqpSignature) ret = r->prqpSignature->signatureAlgorithm;
			break;

		case PKI_X509_DATA_SIGNER_CERT:
			if (r->prqpSignature)
			{
				cert_val = r->prqpSignature->signerCert;
				if (cert_val)
				{
					ret = PKI_X509_new_dup_value(PKI_DATATYPE_X509_CERT,
						cert_val, NULL);
				}
				ret = r->prqpSignature->signerCert;
			}
			break;

		case PKI_X509_DATA_SIGNATURE_ALG2:
			// Nothing to do here
			break;

/*
		// This shall be replaced with a dedicated
		// function because this violates the memory
		// contract (const for the returned item)
		// PKI_X509_get_tbs_asn1();
		case PKI_X509_DATA_TBS_MEM_ASN1:
			if ((mem = PKI_MEM_new_null()) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				break;
			}
			mem->size = (size_t) ASN1_item_i2d((void *) r->requestData,
				&(mem->data), &PRQP_TBS_REQ_DATA_it );
			ret = mem;
			break;
*/

		case PKI_X509_DATA_PRQP_CAID:
			if (r->requestData && r->requestData->serviceToken)
				ret = r->requestData->serviceToken->ca;
			break;

		case PKI_X509_DATA_PRQP_SERVICES:
			if(r->requestData && r->requestData->serviceToken  &&
				  r->requestData->serviceToken->resourceList)
			{
				STACK_OF(RESOURCE_IDENTIFIER) *ri_sk = NULL;
				PKI_RESOURCE_IDENTIFIER_STACK *ret_sk = NULL;

				int i = 0;

				PKI_log_debug("get_data() - Request has a resourceList");

				ret_sk = PKI_STACK_RESOURCE_IDENTIFIER_new_null();
				ri_sk = r->requestData->serviceToken->resourceList;

				PKI_log_debug("get_data() - Number of OIDs in request is %d", 
					PKI_STACK_RESOURCE_IDENTIFIER_elements( ri_sk ) );

				for( i=0; i < sk_RESOURCE_IDENTIFIER_num (ri_sk); i++ )
				{
					RESOURCE_IDENTIFIER *p = NULL;

					p = sk_RESOURCE_IDENTIFIER_value(ri_sk, i);
					PKI_STACK_RESOURCE_IDENTIFIER_push(ret_sk, p );
				}

				ret = ret_sk;

			}
			else
			{
				PKI_log_debug( "get_data() - No resources in request");
				PKI_log_debug( "get_data() - r->requestData %p", r->requestData );
				PKI_log_debug( "get_data() - " "r->requestData->serviceToken %p",
						r->requestData->serviceToken );
				PKI_log_debug( "get_data() - " "r->requestData->serviceToken->resourceList %p",
					r->requestData->serviceToken->resourceList );
			}
			break;

		default:
			/* Datatype not supported */
			return ( NULL );
	}

	return ret;
}

/*! \brief Returns a pointer to the specified PKI_X509_DATA field of a
 *         PRQP response */

void * PKI_X509_PRQP_RESP_get_data ( PKI_X509_PRQP_RESP *obj, 
						PKI_X509_DATA type ) {

	PKI_X509_PRQP_RESP_VALUE *r = NULL;

	if( !obj || !obj->value ) return ( NULL );

	r = obj->value;

	return PKI_X509_PRQP_RESP_VALUE_get_data ( r, type );

}

/*! \brief Returns a pointer to the specified PKI_X509_DATA field of a
 *         PKI_X509_PRQP_RESP_VALUE data structure */

static void *PKI_X509_PRQP_RESP_VALUE_get_data ( PKI_X509_PRQP_RESP_VALUE *r,
					PKI_X509_DATA type ) {

	PKI_X509_CERT_VALUE *cert_val = NULL;
	void *ret = NULL;

	if ( !r || !r->respData ) return NULL;

	switch (type)
	{
		case PKI_X509_DATA_VERSION:
			ret = r->respData->version;
			break;

		case PKI_X509_DATA_NONCE:
			ret = r->respData->nonce;
			break;

		case PKI_X509_DATA_PRODUCEDAT:
		case PKI_X509_DATA_NOTBEFORE:
			ret = r->respData->producedAt;
			break;

		case PKI_X509_DATA_NEXTUPDATE:
		case PKI_X509_DATA_NOTAFTER:
			ret = r->respData->nextUpdate;
			break;

		case PKI_X509_DATA_PRQP_STATUS_VALUE:
			if(r->respData && r->respData->pkiStatus)
			{
				ASN1_INTEGER *tmp_int = NULL;
				long a = 0;

				tmp_int = r->respData->pkiStatus->status;
				ret = i2s_ASN1_INTEGER( NULL, tmp_int );
				if (ret)
				{
					a = atol( ret );
					PKI_Free( ret );

					if (a < PKI_X509_PRQP_STATUS_STRING_NUM)
						ret=PKI_X509_PRQP_STATUS_STRING[a];
					else
						ret=PKI_X509_PRQP_STATUS_STRING_UNKNOWN;
				}
				else ret = PKI_X509_PRQP_STATUS_STRING_UNKNOWN;
			}
			break;

		case PKI_X509_DATA_PRQP_REFERRALS:
			if( r->respData && r->respData->pkiStatus &&
					r->respData->pkiStatus->referrals )
			{
				int i = 0;
				PKI_STACK *s = NULL;
				STACK_OF(ASN1_IA5STRING) *sk = NULL;

				sk = r->respData->pkiStatus->referrals;

				if((s = PKI_STACK_new_null()) == NULL )
				{
					PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
					ret = NULL;
					break;
				}

				for ( i = 0; i < sk_ASN1_IA5STRING_num(sk); i++)
				{ 
					PKI_STRING *st = NULL;
					char *val = NULL;

					st = sk_ASN1_IA5STRING_value( sk, i);
					if( !st ) continue;

					val = PKI_STRING_get_utf8(st);
					if (val) PKI_STACK_push ( s, val);
				}
				ret = s;
			}
			break;

		case PKI_X509_DATA_PRQP_STATUS_STRING:
			if( r->respData && r->respData->pkiStatus )
			{
				PKI_STRING *s = NULL;
				s = r->respData->pkiStatus->statusString;
				ret = PKI_STRING_get_utf8( s );
			}
			break;

		case PKI_X509_DATA_PRQP_CAID:
			if (r->respData) ret = r->respData->caCertId;
			break;

		case PKI_X509_DATA_SIGNATURE_CERTS:
			if( r->prqpSignature && r->prqpSignature->otherCerts)
			{
				int i = 0;
				PKI_X509_CERT_STACK *s = NULL;

				s = PKI_STACK_X509_CERT_new();
				for( i = 0 ; i < sk_X509_num( r->prqpSignature->otherCerts ); i++ )
				{
					PKI_STACK_X509_CERT_push( ret, 
						sk_X509_value( r->prqpSignature->otherCerts, i));
				}
				ret = s;
			}
			break;

		case PKI_X509_DATA_SIGNER_CERT:
			if (r->prqpSignature)
			{
				cert_val = r->prqpSignature->signerCert;
				if (cert_val)
				{
					ret = PKI_X509_new_dup_value(PKI_DATATYPE_X509_CERT,
						cert_val, NULL);
				}
			}
			break;

		case PKI_X509_DATA_SIGNATURE:
			if (r->prqpSignature) ret = r->prqpSignature->signature;
			break;

		case PKI_X509_DATA_ALGORITHM:
		case PKI_X509_DATA_SIGNATURE_ALG1:
		if (r->prqpSignature)
			ret = r->prqpSignature->signatureAlgorithm;
		else
			PKI_log_debug("DEBUG::No DATA_SIGNATURE_ALG1");
		break;

		case PKI_X509_DATA_SIGNATURE_ALG2:
			// Nothing to do here
			break;

/*
		// This shall be replaced with a dedicated
		// function because this violates the memory
		// contract (const for the returned item)
		// PKI_X509_get_tbs_asn1();
		case PKI_X509_DATA_TBS_MEM_ASN1:
			if ((mem = PKI_MEM_new_null()) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				break;
			}
			mem->size = (size_t) ASN1_item_i2d ( (void *) r->respData,
				&(mem->data), &PRQP_TBS_RESP_DATA_it );
			ret = mem;
			break;
*/

		case PKI_X509_DATA_PRQP_SERVICES:
			if( r->respData && r->respData->responseToken )
			{
				int i = 0;
				int num = 0;

				STACK_OF(RESOURCE_RESPONSE_TOKEN) *rrt = NULL;
				PKI_RESOURCE_RESPONSE_TOKEN_STACK *pki_sk=NULL;

				PKI_log_debug("Response Token Present");

				pki_sk = PKI_STACK_RESOURCE_RESPONSE_TOKEN_new_null();
				if( !pki_sk ) return ( NULL );

				rrt = r->respData->responseToken;
 
				num = sk_RESOURCE_RESPONSE_TOKEN_num ( rrt );
				PKI_log_debug("Services in Response Token: %d", num);

				for (i=0; i < num; i++)
				{
					RESOURCE_RESPONSE_TOKEN *p = NULL;

					p = sk_RESOURCE_RESPONSE_TOKEN_value(rrt, i);
					PKI_STACK_RESOURCE_RESPONSE_TOKEN_push(pki_sk, 
						RESOURCE_RESPONSE_TOKEN_dup( p ) );
				}
				ret = pki_sk;
			}
			else
			{
				if (!r->respData)
						PKI_log_debug("PRQP RESP:Missing r->respData [get_data]");
				else if (!r->respData->responseToken)
						PKI_log_debug("PRQP RESP:Missing r->respData->responseToken [get_data]");
			}
			break;

		default:
			/* Datatype not supported */
			return ( NULL );
	}

	return ( ret );
}

PKI_OID *PRQP_RESOURCE_RESPONSE_TOKEN_get_oid ( RESOURCE_RESPONSE_TOKEN *rrt )
{
	if (!rrt)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	}

	return (PKI_OID *) rrt->resourceId;
}

PKI_STACK *PRQP_RESOURCE_RESPONSE_TOKEN_get_services( RESOURCE_RESPONSE_TOKEN *rrt ) {

	int i = 0;
	PKI_STACK *ret = NULL;
	ASN1_IA5STRING *resInfo = NULL;

	if ( !rrt || !rrt->resourceId ) return (NULL);

	if((ret = PKI_STACK_new( NULL )) == NULL ) {
		PKI_log_debug( "Memory Allocation Failed");
		return ( NULL );
	}

	for(i=0; i< sk_ASN1_IA5STRING_num( rrt->resLocatorList ); i++ ) {

		char *ret_s = NULL;

		resInfo = sk_ASN1_IA5STRING_value( rrt->resLocatorList, i );
		if( !resInfo ) {
			continue;
		}

		// s = sk_ASN1_IA5STRING_value( rrt->resLocatorList, i );
		// ret_s = i2s_ASN1_IA5STRING( NULL, resInfo );
		ret_s = PKI_STRING_get_parsed ( resInfo );
		PKI_STACK_push( ret, ret_s );
	}

	return( ret );
}

/*! \brief Returns the PKI_X509_PRQP_STATUS associated to a PRQP
 *         response */

int PKI_X509_PRQP_RESP_get_status ( PKI_X509_PRQP_RESP *obj ) {

	PKI_X509_PRQP_RESP_VALUE *r = NULL;

	if ( !obj || !obj->value ) return PKI_X509_PRQP_STATUS_UNKNOWN;

	r = obj->value;

	return PKI_X509_PRQP_RESP_get_status_value ( r );

}

static int PKI_X509_PRQP_RESP_get_status_value(PKI_X509_PRQP_RESP_VALUE *r)
{
	ASN1_INTEGER *tmp_int = NULL;
	char *tmp_s = NULL;

	long a = 0;
	int ret = PKI_X509_PRQP_STATUS_UNKNOWN;
	if( !r || !r->respData || !r->respData->pkiStatus )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( PKI_X509_PRQP_STATUS_UNKNOWN );
	}

	tmp_int = r->respData->pkiStatus->status;
	tmp_s = i2s_ASN1_INTEGER( NULL, tmp_int );
				
	if (tmp_s) 
	{
		a = atol(tmp_s);
		PKI_Free(tmp_s);

		if (a < PKI_X509_PRQP_STATUS_STRING_NUM)
			ret = (int) a;
		else
			ret = PKI_X509_PRQP_STATUS_UNKNOWN;
	}

	return ret;
}

