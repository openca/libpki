/* ID management for libpki */

#include <libpki/pki.h>

int pqc_sig_nids_list[] = {

#ifdef ENABLE_PQC
        NID_dilithium2,
        NID_dilithium3,
        NID_dilithium5,
        NID_falcon512,
        NID_falcon1024,
		NID_sphincssha2128fsimple,
		NID_sphincssha2128ssimple,
		NID_sphincssha2192fsimple,
		NID_sphincssha2192ssimple
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
		NID_bikel5,
        NID_hqc128,
        NID_hqc192,
        NID_hqc256,
#endif
		NID_undef
};

PKI_ID PKI_ID_get_by_name ( const char *name ) {

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

int PKI_ID_is_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

	// Checks if the ID is a composite one
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_NAME) == id) {
		if (scheme_id) *scheme_id = PKI_SCHEME_COMPOSITE;
		return PKI_OK;
	}

	// If reaches here, not composite
	return PKI_ERR;
}

int PKI_ID_is_explicit_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

	PKI_SCHEME_ID found_id = PKI_SCHEME_UNKNOWN;
		// Internal variable

	// Input checks
	if (id <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
		return PKI_ERR;
	}

	// Checks if the ID is a composite one
	if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME) == id) {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME) == id)  {
		*scheme_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME) == id) {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521;
	} else if (OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME) == id)  {
		found_id = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA;
	} else {
		// Not found
		// PKI_DEBUG("Provided PKI_ID (%d) is not an explicit Composite scheme!", id);
		return PKI_ERR;
	}

	// Sets the output variable (if provided)
	if (scheme_id) *scheme_id = found_id;

	// All Done
	return PKI_OK;
}

int PKI_ID_is_traditional(PKI_ID key_id, PKI_SCHEME_ID * scheme_id) {

	// Maps the type of the keypair to the scheme
	switch(key_id) {

		// case PKI_ALGOR_DH: {
		// 	if (scheme_id) *scheme_id = PKI_SCHEME_DH;
		// } break;

		case PKI_ALGOR_DSA: {
			if (scheme_id) *scheme_id = PKI_SCHEME_DSA;
		} break;

		case PKI_ALGOR_RSA: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_RSA;
		} break;

		case PKI_ALGOR_RSAPSS: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_RSAPSS;
		} break;

#ifdef ENABLE_ECDSA
		case PKI_ALGOR_ECDSA: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ECDSA;
		} break;
#endif

		case PKI_ALGOR_X448:
		case PKI_ALGOR_ED448: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ED448;
		} break;

		case PKI_ALGOR_X25519:
		case PKI_ALGOR_ED25519: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ED25519;
		} break;

		default:
			PKI_DEBUG("Provided PKI_ID (%d) is not a traditional scheme!", key_id);
			return PKI_ERR;
	}

	return PKI_OK;
}

int PKI_ID_is_pqc(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

	// Checks the PKEY / Signatures
	switch (id) {

		// Signature Algorithms
		case NID_dilithium2:
        case NID_dilithium3:
        case NID_dilithium5:{
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_DILITHIUM;
			return PKI_OK;
		} break;

        case NID_falcon512:
        case NID_falcon1024:{
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_FALCON;
			return PKI_OK;
		} break;

#ifdef NID_sphincssha2128fsimple
        case NID_sphincssha2128fsimple:
#endif
#ifdef NID_sphincssha2128ssimple
        case NID_sphincssha2128ssimple:
#endif
#ifdef NID_sphincssha2192fsimple
        case NID_sphincssha2192fsimple:
#endif
		{
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_SPHINCS;
			return PKI_OK;
		} break;

		// KEM/Encryption Algorithms
		case NID_frodo640aes:
        case NID_frodo640shake:
        case NID_frodo976aes:
        case NID_frodo976shake:
        case NID_frodo1344aes:
        case NID_frodo1344shake:{
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_FRODOKEM;
			return PKI_OK;
		} break;

        case NID_kyber512:
        case NID_kyber768:
        case NID_kyber1024: {
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_KYBER;
			return PKI_OK;
		} break;

        case NID_bikel1:
        case NID_bikel3:
		case NID_bikel5: {
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_BIKE;
			return PKI_OK;
		} break;

		case PKI_ALGOR_ID_CLASSIC_MCELIECE1: {
			// Verified PQC algorithm
			if (scheme_id) *scheme_id = PKI_SCHEME_CLASSIC_MCELIECE;
			return PKI_OK;
		} break;

		default:
			break;
	}

	// If here, not a PQC algorithm
	return PKI_ERR;
}

int PKI_ID_requires_digest(PKI_ID id) {

	int sig_id = 0;

	// Input checks
	if (id <= 0) return PKI_ERR;

	// PQC do not require digests
	if (PKI_ID_is_pqc(id, NULL) == PKI_OK) return PKI_ERR;

	// Generic Composite does not require digests
	if (PKI_ID_is_composite(id, NULL) == PKI_OK) return PKI_ERR;

	// Explicit does not require digests
	if (PKI_ID_is_explicit_composite(id, NULL) == PKI_OK) return PKI_ERR;

	// Classical Territory
	switch (id) {

		case PKI_ALGOR_ID_RSAPSS:
		case PKI_ALGOR_ID_ED25519:
		case PKI_ALGOR_ID_X25519:
		case PKI_ALGOR_ID_ED448:
		case PKI_ALGOR_ID_X448: {
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