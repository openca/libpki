/* ID management for libpki */

#include <libpki/pki.h>

int pqc_sig_nids_list[] = {

#ifdef ENABLE_PQC
        NID_dilithium2,
        NID_dilithium3,
        NID_dilithium5,
        NID_falcon512,
        NID_falcon1024,
        NID_sphincsharaka128frobust,
        NID_sphincsharaka128fsimple,
        NID_sphincssha256128frobust,
        NID_sphincssha256128ssimple,
        NID_sphincsshake256128fsimple
#endif
		NID_undef

};

int pqc_kem_nids_list[] = {

#ifdef ENABLE_PQC
        NID_frodo640aes,
        NID_frodo640shake,
        NID_frodo976aes,
        NID_frodo976shake,
        NID_frodo1344aes,
        NID_frodo1344shake,
        NID_kyber512,
        NID_kyber768,
        NID_kyber1024,
        NID_bikel1,
        NID_bikel3,
        NID_hqc128,
        NID_hqc192,
        NID_hqc256,
#endif
		NID_undef
};

PKI_ID PKI_ID_get_by_name ( char *name ) {

	int ret = PKI_ID_UNKNOWN;

	if( !name ) return ( PKI_ID_UNKNOWN );

	/* Check if the object already exists */
	if( (ret = OBJ_sn2nid(name)) == PKI_ID_UNKNOWN) {
		ret = OBJ_ln2nid(name);
	}

	return ( ret );
}

PKI_ID PKI_ID_get( PKI_ID id ) {

	PKI_OID *obj = NULL;

	/* Check if the object already exists */
	if( (obj = OBJ_nid2obj( id )) == NULL ) {
		return ( PKI_ID_UNKNOWN );
	}

	/* Free the memory */
	ASN1_OBJECT_free ( obj );

	/* The ID exists, let's return it */
	return ( id );
}

const char * PKI_ID_get_txt( PKI_ID id ) {

	return ( OBJ_nid2sn( id ) );
	
}

int PKI_ID_is_composite(PKI_ID id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

	// Checks if the ID is a composite one
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_NAME) == id) return PKI_OK;

	// If reaches here, not composite
	return PKI_ERR;
}

int PKI_ID_is_explicit_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

	// Input checks
	if (id <= 0 || !scheme_id) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Checks if the ID is a composite one
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME) == id) {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME) == id) {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_P256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_BRAINPOOL256;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME) == id) {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_ED25519;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME) == id) {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA;
		return PKI_OK;
	}
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_RSA;
		return PKI_OK;
	}

	// If reaches here, not composite
	return PKI_ERR;
}

int PKI_ID_is_pqc(PKI_ID id) {

	// Checks the PKEY / Signatures
	switch (id) {

		// Signature Algorithms
		case NID_dilithium2:
        case NID_dilithium3:
        case NID_dilithium5:
        case NID_falcon512:
        case NID_falcon1024:
        case NID_sphincsharaka128frobust:
        case NID_sphincsharaka128fsimple:
        case NID_sphincssha256128frobust:
        case NID_sphincssha256128ssimple:
        case NID_sphincsshake256128fsimple: {
			// Verified PQC algorithm
			return PKI_OK;
		} break;

		// KEM/Encryption Algorithms
		case NID_frodo640aes:
        case NID_frodo640shake:
        case NID_frodo976aes:
        case NID_frodo976shake:
        case NID_frodo1344aes:
        case NID_frodo1344shake:
        case NID_kyber512:
        case NID_kyber768:
        case NID_kyber1024:
        case NID_bikel1:
        case NID_bikel3:
        case NID_hqc128:
        case NID_hqc192:
        case NID_hqc256: {
			// Nothing to do here
			break;
		}

	}

	// If here, not a PQC algorithm
	return PKI_ERR;
}

int PKI_ID_requires_digest(PKI_ID id) {

	int sig_id = 0;
	PKI_SCHEME_ID scheme_id;

	// Input checks
	if (id <= 0) return PKI_ERR;

	// PQC do not require digests
	if (PKI_ID_is_pqc(id) == PKI_OK) return PKI_ERR;

	// Explicit does not require digests
	if (PKI_ID_is_explicit_composite(id, &scheme_id) == PKI_OK) return PKI_ERR;

	// Classical Territory
	switch (id) {

		case NID_rsassaPss:
		case NID_ED25519:
		case NID_ED448: {
			// No digest required
			return PKI_ERR;
		} break;

		default:
			// Digest is required for all remaining
			// classical algorithm
			return PKI_OK;
	}

	// Checks if the ID supports a NULL digest
	OBJ_find_sigid_by_algs(&sig_id, NID_undef, id);

	// If not found, digest is actually required
	if (sig_id == NID_undef) return PKI_OK;

	// Digest not required here
	return PKI_OK;
}