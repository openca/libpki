/* HSM Object Management Functions */

#include <libpki/crypto/hsm/hsm_crypto.h>

/* ------------------- Keypair Gen/Free -------------------------------- */

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new( PKI_KEYPARAMS *params, 
			char *label, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR *ret = NULL;
	URL *url = NULL;

	if( hsm && !url && (hsm->type == HSM_TYPE_PKCS11) ) {
		PKI_DEBUG("Label is required when using HSM");
		return NULL;
	}

	if ( label ) {
		if(( url = URL_new(label)) == NULL ) {
			PKI_ERROR(PKI_ERR_URI_PARSE, label);
			return ( NULL );
		}
	};

	ret = HSM_X509_KEYPAIR_new_url ( params, url, cred, hsm );
	
	if( url ) URL_free( url );

	return ( ret );
}

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_new_url( PKI_KEYPARAMS *params,
			URL *url, PKI_CRED *cred, HSM *driver ) {

	PKI_X509_KEYPAIR *ret = NULL;
	HSM *hsm = NULL;

	if ( !params ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	};

	if( driver ) {
		hsm = driver;
	} else {
		hsm = (HSM *) HSM_get_default();
	}
	
	if( hsm && hsm->callbacks && hsm->callbacks->keypair_new_url ) {
		ret = hsm->callbacks->keypair_new_url(params,url,cred,hsm);
	} else {
		PKI_log_err("HSM does not provide key generation");
		// ret = HSM_OPENSSL_KEYPAIR_new( type, bits, url, cred, NULL );
	}

	return ( ret );
}


PKI_MEM *HSM_X509_KEYPAIR_wrap ( PKI_X509_KEYPAIR *key, PKI_CRED *cred) {

	const HSM *hsm = NULL;

	if ( !key || !key->value ) return NULL;

	if ( key->hsm ) {
		hsm = key->hsm;
	} else {
		hsm = HSM_get_default();
	}

	if ( hsm && hsm->callbacks && hsm->callbacks->key_wrap ) {
		return hsm->callbacks->key_wrap ( key, cred );
	}

	return NULL;

/*
	int i = 0;

	PKI_X509 *obj = NULL;
	PKI_MEM_STACK *ret_sk = NULL;
	PKI_MEM *mem = NULL;

	if ( !sk ) return NULL;

	if ((ret_sk = PKI_STACK_MEM_new()) == NULL ) {
		return NULL;
	}

	for ( i = 0; i < PKI_STACK_X509_KEYPAIR_elements ( sk ); i++ ) {
		obj = PKI_STACK_X509_KEYPAIR_get_num ( sk, i );

		if (!obj || !obj->value ) continue;

		if ( obj->hsm ) {
			if( obj->hsm && obj->hsm->callbacks && 
					obj->hsm->callbacks->key_wrap ) { 
				mem = obj->hsm->callbacks->key_wrap ( obj, 
									cred);
				if ( mem == NULL ) break;

				PKI_STACK_MEM_push ( ret_sk, mem );
			}
		}
	}

	return ret_sk;
*/
}

PKI_X509_KEYPAIR *HSM_X509_KEYPAIR_unwrap ( PKI_MEM *mem,
				URL *url, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR *ret = NULL;

	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	/* Now Put the stack of objects in the HSM */
	if( hsm && hsm->callbacks && hsm->callbacks->key_unwrap ) { 
		ret = hsm->callbacks->key_unwrap ( mem, url, cred, hsm );
	};

	/* Return value */
	return ret;
}

// /* ------------------------ General PKI Signing ---------------------------- */

// /* !\brief Signs the data from a PKI_MEM structure by using the
//  *      passed key and digest algorithm. 
//  *
//  * This function signs the data passed in the PKI_MEM structure.
//  * Use PKI_DIGEST_ALG_NULL for using no hash algorithm when calculating
//  * the signature.
//  * Use NULL for the digest (PKI_DIGEST_ALG) pointer to use the data signing
//  * functions directly (i.e., signing the PKI_MEM data directly instead of
//  * first performing the digest calculation and then generating the signture
//  * over the digest)
//  * 
//  * @param der The pointer to a PKI_MEM structure with the data to sign
//  * @param digest The pointer to a PKI_DIGEST_ALG method
//  * @param key The pointer to the PKI_X509_KEYPAIR used for signing
//  * @return A PKI_MEM structure with the signature value.
//  */

// int PKI_X509_sign(PKI_X509               * x, 
// 		          const PKI_DIGEST_ALG   * digest,
// 		          const PKI_X509_KEYPAIR * key) {

// 	// PKI_MEM *der = NULL;
// 	// PKI_MEM *sig = NULL;
// 	//   // Data structure for the signature

// 	PKI_STRING * sigPtr = NULL;
// 	  // Pointer for the Signature in the PKIX data

// 	int pkey_type = NID_undef;
// 	  // Key Type

// 	PKI_SCHEME_ID pkey_scheme = PKI_SCHEME_UNKNOWN;
// 	  // Signature Scheme

// 	PKI_X509_KEYPAIR_VALUE * pkey = NULL;
// 	  // Internal Value

// 	int sig_nid = -1;
// 		// Signature Algorithm identifier

// 	// Input Checks
// 	if (!x || !x->value || !key || !key->value ) 
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	
// 	// Extracts the internal value
// 	pkey = PKI_X509_get_value(key);
// 	if (!pkey) {
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing Key's Internal Value");
// 		return PKI_ERR;
// 	}

// // 	// Gets the PKEY type
// // 	pkey_id = PKI_X509_KEYPAIR_VALUE_get_id(pkey);
// // 	pkey_type = EVP_PKEY_type(pkey_id);
// // 	if (pkey_type == NID_undef) {
// // #if OPENSSL_VERSION_NUMBER > 0x30000000L
// // 		pkey_type = pkey_id;
// // #else
// // 		PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing Key's Internal Value");
// // 		return PKI_ERR;
// // #endif
// // 	}

// 	pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(pkey);
// 	if (!pkey_type) {
// 		PKI_DEBUG("Cannot get the key's type (nid: %d)", PKI_X509_KEYPAIR_VALUE_get_id(pkey));
// 		return PKI_ERR;
// 	}

// 	// Gets the Signature Scheme
// 	pkey_scheme = PKI_X509_KEYPAIR_VALUE_get_scheme(pkey);
// 	if (pkey_scheme == PKI_SCHEME_UNKNOWN) {
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, "Scheme not recognized for key (scheme: %d, type: %d)", 
// 			PKI_SCHEME_ID_get_parsed(pkey_scheme), pkey_type);
// 		return PKI_ERR;
// 	}

// 	// Sets the default Algorithm if none is provided
// 	if (!digest) {
// 		PKI_DEBUG("No digest was used, getting the default for the key.");
// 		if (PKI_SCHEME_ID_is_explicit_composite(pkey_scheme)) {
// 			PKI_DEBUG("Explicit Composite Scheme, no digest allowed (overriding choice)");
// 			digest = PKI_DIGEST_ALG_NULL;
// 		} else {
// 			digest = PKI_DIGEST_ALG_get_default(key);
// 		}
// 	}

// 	// PKI_DEBUG("Digest Algorithm set to %s", PKI_DIGEST_ALG_get_parsed(digest));

// 	// Let's make sure we do not use a digest with explicit composite
// 	if (PKI_ID_is_explicit_composite(pkey_type, NULL)) {
// 		// No digest is allowed
// 		digest = PKI_DIGEST_ALG_NULL;
// 	}

// 	// Handles the weirdness of OpenSSL - we want to check if the signing algorithm
// 	// is actually allowed with the selected public key
// 	if (digest != NULL && digest != PKI_DIGEST_ALG_NULL) {

// 		// Finds the associated signing algorithm identifier, if any
// 		if (OBJ_find_sigid_by_algs(&sig_nid, EVP_MD_nid(digest), pkey_type) != 1) {
// 			PKI_DEBUG("Cannot Get The Signing Algorithm for %s with %s",
// 				PKI_ID_get_txt(pkey_type), digest ? PKI_DIGEST_ALG_get_parsed(digest) : "NULL");
// 			// Fatal Error
// 			return PKI_ERR;
// 		}

// 	} else {
		
// 		if (PKI_ID_requires_digest(pkey_type) == PKI_OK) {
// 			PKI_DEBUG("%s scheme does not support arbitrary signing, hashing is required",
// 					  PKI_SCHEME_ID_get_parsed(pkey_scheme));
// 			// Error condition
// 			return PKI_ERR;
// 		}

// 		// Checks if we can use the NULL digest
// 		if (PKI_ID_is_composite(pkey_type, NULL) || 
// 		    PKI_ID_is_explicit_composite(pkey_type, NULL)) {

// 			// Finds the associated signing algorithm identifier, if any
// 			if (OBJ_find_sigid_by_algs(&sig_nid, NID_undef, pkey_type) != 1) {
// 				PKI_DEBUG("Cannot Get The Signing Algorithm for %s with %s",
// 					PKI_ID_get_txt(pkey_type), digest ? PKI_DIGEST_ALG_get_parsed(digest) : "NULL");
// 				// Fatal Error
// 				return PKI_ERR;
// 			}
// 			// Use the appropriate digest to avoid the OpenSSL weirdness
// 			digest = EVP_md_null();

// 		} else if (PKI_ID_is_pqc(pkey_type, NULL)) {

// 			// Use the Same ID for Key and Signature
// 			sig_nid = pkey_type;
// 		}

// 		// if (PKI_ID_requires_digest(EVP_PKEY_id(pkey) == PKI_OK)) {
// 		// 	// If the key requires a digest, we need to find the default
// 		// 	// digest algorithm for the key type
// 		// 	if (PKI_ID_get_digest(EVP_PKEY_id(pkey), &scheme_id) != PKI_OK) {
// 		// 		PKI_DEBUG("Cannot Get The Digest Algorithm for %s",
// 		// 			PKI_ID_get_txt(PKI_X509_KEYPAIR_VALUE_get_id(pkey)));
// 		// 		// Fatal Error
// 		// 		return PKI_ERR;
// 		// 	}
// 		// }
// 		// if (PKI_ID_is_explicit_composite(EVP_PKEY_id(pkey), &scheme_id) != PKI_OK) {

// 		// 	PKI_DEBUG("Got The Scheme ID => %d", scheme_id);

// 		// 	switch (scheme_id) {

// 		// 		// Algorithms that do not require hashing
// 		// 		/* case PKI_SCHEME_ED448: */
// 		// 		/* case PKI_SCHEME_X25519: */
// 		// 		case PKI_SCHEME_DILITHIUM:
// 		// 		case PKI_SCHEME_FALCON:
// 		// 		case PKI_SCHEME_COMPOSITE:
// 		// 		case PKI_SCHEME_COMBINED:
// 		// 		case PKI_SCHEME_KYBER:
// 		// 		case PKI_SCHEME_CLASSIC_MCELIECE: {
// 		// 			// No-hashing is supported by the algorithm
// 		// 			// If the find routine returns 1 it was successful, however
// 		// 			// for PQC it seems to return NID_undef for the sig_nid, this fixes it
// 		// 			if (sig_nid == NID_undef) sig_nid = EVP_PKEY_id(pkey);
// 		// 		} break;
				

// 		// 		// Hashing required
// 		// 		default:
// 		// 			PKI_DEBUG("%s does not support arbitrary signing, hashing is required",
// 		// 				PKI_SCHEME_ID_get_parsed(scheme_id));
// 		// 			// Error condition
// 		// 			return PKI_ERR;
// 		// 	}
// 		// }
// 	}

// 	// // Debugging Information
// 	// PKI_DEBUG("Signing Algorithm Is: %s", PKI_ID_get_txt(sig_nid));
// 	// PKI_DEBUG("Digest Signing Algorithm: %p (%s)", digest, PKI_DIGEST_ALG_get_parsed(digest));

// 	// Since we are using the DER representation for signing, we need to first
// 	// update the data structure(s) with the right OIDs - we use the default
// 	// ASN1_item_sign() with a NULL buffer parameter to do that.

// 	// ASN1_item_sign behaviour:
// 	// - signature: we must provide an ASN1_BIT_STRING pointer, the pnt->data
// 	//              will be freed and replaced with the signature data
// 	// - pkey: we must provide an EVP_PKEY pointer
// 	// - data: is the pointer to an internal value (e.g., a PKI_X509_VALUE
// 	//         or a PKI_X509_REQ_VALUE))
// 	// - type: is the pointer to the const EVP_MD structure for the hash-n-sign
// 	//         digest

// 	ASN1_BIT_STRING sig_asn1 = { 0x0 };
// 		// Pointer to the ASN1_BIT_STRING structure for the signature

// 	// Note that only COMPOSITE can properly handle passing the EVP_md_null()
// 	// for indicating that we do not need a digest algorithm, however that is
// 	// not well supported by OQS. Let's just pass NULL if the algorithm is not
// 	// composite and the requested ditest is EVP_md_null().
// 	if (digest == PKI_DIGEST_ALG_NULL) {
// 		if (!PKI_SCHEME_ID_is_composite(pkey_scheme) &&
// 		    !PKI_SCHEME_ID_is_explicit_composite(pkey_scheme)) {
// 			// The algorithm is not composite, but the digest is EVP_md_null()
// 			PKI_DEBUG("Digest is EVP_md_null(), but the algorithm is not composite, replacing the digest with NULL");
// 			digest = NULL;
// 		}
// 	}
	
// 	// Special case for non-basic types to be signed. The main example is
// 	// the OCSP response where we have three different internal fields
// 	// suche as status, resp, and bs. We need to sign the bs field in
// 	// this case.
// 	void * item_data = NULL;
// 	switch (x->type) {
// 		case PKI_DATATYPE_X509_OCSP_RESP: {
// 			PKI_X509_OCSP_RESP_VALUE * ocsp_resp = NULL;

// 			// For OCSP Responses we need to sign the TBSResponseData
// 			ocsp_resp = (PKI_X509_OCSP_RESP_VALUE *) x->value;
// 			item_data = ocsp_resp->bs;
// 		} break;

// 		default: {
// 			// Default use-case
// 			item_data = x->value;
// 		} break;
// 	}

// 	// Sets the right OID for the signature
// 	int success = ASN1_item_sign(x->it, 
// 								 PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG1),
// 								 PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG2),
// 								 &sig_asn1,
// 								 item_data,
// 								 pkey,
// 								 digest);

// 	if (!success || !sig_asn1.data || !sig_asn1.length) {
// 		PKI_DEBUG("Error while creating the signature: %s (success: %d, sig_asn1.data: %p, sig_asn1.length: %d)",
// 			ERR_error_string(ERR_get_error(), NULL), success, sig_asn1.data, sig_asn1.length);
// 		PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
// 		return PKI_ERR;
// 	}

// 			// EVP_MD_CTX * md_ctx_tmp = EVP_MD_CTX_new();
// 			// if (!md_ctx_tmp) {
// 			// 	PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not allocate memory for the EVP_MD_CTX");
// 			// 	return PKI_ERR;
// 			// }

// 			// EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
// 			// if (!pkey_ctx) {
// 			// 	PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not allocate memory for the EVP_PKEY_CTX");
// 			// 	return PKI_ERR;
// 			// }

// 			// X509_ALGORS * signature_algors = sk_X509_ALGOR_new_null();
// 			// if (!signature_algors) {
// 			// 	PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not allocate memory for the X509_ALGORS");
// 			// 	return PKI_ERR;
// 			// }

// 			// X509_ALGOR * signature_algor = X509_ALGOR_new();

// 			// EVP_MD_CTX_set_pkey_ctx(md_ctx_tmp, pkey_ctx);

// 			// EVP_MD_CTX_ctrl(md_ctx_tmp, EVP_MD_CTRL_SET_SIGNAME, sig_nid, NULL);

// 			// int success = ASN1_item_sign_ctx(x->it, 
// 			//                		         PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG1),
// 			// 			   				 PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG2),
// 			// 							 &sig_asn1,
// 			// 			                 x->value,
// 			// 							 md_ctx_tmp);

// 			// if (!success || !sig_asn1.data || !sig_asn1.length) {
// 			// 	PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Can not sign the data");
// 			// 	return PKI_ERR;
// 			// }

// 	// // Retrieves the DER representation of the data to be signed
// 	// if ((der = PKI_X509_get_tbs_asn1(x)) == NULL) {
// 	// 	// Logs the issue
// 	// 	PKI_DEBUG("Can not get the DER representation of the PKIX data via tbs func");
// 	// 	// Builds the DER representation in a PKI_MEM structure
// 	// 	if ((der = PKI_X509_put_mem(x, 
// 	// 								PKI_DATA_FORMAT_ASN1, 
// 	// 	                            NULL,
// 	// 								NULL )) == NULL) {
// 	// 		// Logs the issue
// 	// 		PKI_DEBUG("Can not get the DER representation directly, aborting.");
// 	// 		// Can not encode into DER
// 	// 		return PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, NULL);
// 	// 	}
// 	// }

// 	// // Generates the Signature
// 	// if ((sig = PKI_sign(der, digest, key)) == NULL) {
// 	// 	// Error while creating the signature, aborting
// 	// 	if (der) PKI_MEM_free(der);
// 	// 	// Report the issue
// 	// 	return PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, NULL);
// 	// }

// 			// // Debugging
// 			// FILE * fp = fopen("signature_create.der", "w");
// 			// if (fp) {
// 			// 	fwrite(sig->data, sig->size, 1, fp);
// 			// 	fclose(fp);
// 			// }
// 			// fp = fopen("signed_data_create.der", "w");
// 			// if (fp) {
// 			// 	fwrite(der->data, der->size, 1, fp);
// 			// 	fclose(fp);
// 			// }

// 	// // der work is finished, let's free the memory
// 	// if (der) PKI_MEM_free(der);
// 	// der = NULL;

// 	// // Gets the reference to the X509 signature field
// 	// if ((sigPtr = PKI_X509_get_data(x,
// 	// 	                            PKI_X509_DATA_SIGNATURE)) == NULL) {
// 	// 	// Error: Can not retrieve the generated signature, aborting
// 	// 	PKI_MEM_free (sig);
// 	// 	// Return the error
// 	// 	return PKI_ERROR(PKI_ERR_POINTER_NULL, "Can not get signature data");
// 	// }

// 	// Gets the reference to the X509 signature field
// 	if ((sigPtr = PKI_X509_get_data(x,
// 		                            PKI_X509_DATA_SIGNATURE)) == NULL) {
// 		// Error: Can not retrieve the generated signature, aborting
// 		if (sig_asn1.data) PKI_Free(sig_asn1.data);
// 		// Return the error
// 		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can not get signature data");
// 		return PKI_ERR;
// 	}

// 	// // Transfer the ownership of the generated signature data (sig)
// 	// // to the signature field in the X509 structure (signature)
// 	// sigPtr->data   = sig->data;
// 	// sigPtr->length = (int) sig->size;

// 	// Transfer the ownership of the generated signature data (sig)
// 	// // to the signature field in the X509 structure (signature)
// 	sigPtr->data   = sig_asn1.data;
// 	sigPtr->length = sig_asn1.length;

// 	// Sets the flags into the signature field
// 	sigPtr->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
// 	sigPtr->flags |= ASN1_STRING_FLAG_BITS_LEFT;

// 	// // We can not free the data in the sig PKI_MEM because that is
// 	// // actually owned by the signature now, so let's change the
// 	// // data pointer and then free the PKI_MEM data structure
// 	// sig->data = NULL;
// 	// sig->size = 0;

// 	// // Now we can free the signature mem
// 	// PKI_MEM_free(sig);

// 	// Success
// 	return PKI_OK;
// }

// /*! \brief General signature function on data */

// PKI_MEM *PKI_sign(const PKI_MEM          * der,
// 		          const PKI_DIGEST_ALG   * alg,
// 		          const PKI_X509_KEYPAIR * key ) {

// 	PKI_MEM *sig = NULL;
// 	const HSM *hsm = NULL;

// 	// Input check
// 	if (!der || !der->data || !key || !key->value)	{
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 		return NULL;
// 	}

// 	// If no HSM is provided, let's get the default one
// 	hsm = (key->hsm != NULL ? key->hsm : HSM_get_default());

// 	// Debugging Info
// 	PKI_DEBUG("Calling Callback with Digest = %p (Null =? %s)\n",
// 		alg, alg == EVP_md_null() ? "Yes" : "No");

// 	// Requires the use of the HSM's sign callback
// 	if (hsm && hsm->callbacks && hsm->callbacks->sign) {

// 		// Generates the signature by using the HSM callback
// 		if ((sig = hsm->callbacks->sign(
// 			           (PKI_MEM *)der, 
// 			           (PKI_DIGEST_ALG *)alg, 
// 			           (PKI_X509_KEYPAIR *)key)) == NULL) {

// 			// Error: Signature was not generated
// 			PKI_DEBUG("Can not generate signature (returned from sign cb)");
// 		}

// 	} else {

// 		// There is no callback for signing the X509 structure
// 		PKI_ERROR(PKI_ERR_SIGNATURE_CREATE_CALLBACK,
// 			  "No sign callback for key's HSM");

// 		// Free Memory
// 		PKI_MEM_free(sig);

// 		// All Done
// 		return NULL;
// 	}

// 	// Let's return the output of the signing function
// 	return sig;
// }

// /*!
//  * \brief Verifies a PKI_X509 by using a key from a certificate
//  */

// int PKI_X509_verify_cert(const PKI_X509 *x, const PKI_X509_CERT *cert) {

// 	const PKI_X509_KEYPAIR *kval = NULL;

// 	PKI_X509_KEYPAIR *kp = NULL;

// 	int ret = -1;

// 	// Input Check
// 	if (!x || !x->value || !cert || !cert->value)
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

// 	// Gets the internal value of the public key from the certificate
// 	kval = PKI_X509_CERT_get_data(cert, PKI_X509_DATA_KEYPAIR_VALUE);
// 	if (!kval) return PKI_ERR;

// 	// Use the internal value to generate a new PKI_X509_KEYPAIR
// 	kp = PKI_X509_new_value(PKI_DATATYPE_X509_KEYPAIR, 
// 				            (PKI_X509_KEYPAIR_VALUE *)kval,
// 				            NULL);

// 	// Checks if the operation was successful
// 	if ( !kp ) return PKI_ERR;

// 	// Verifies the certificate by using the extracted public key
// 	ret = PKI_X509_verify(x, kp);

// 	// Take back the ownership of the internal value (avoid freeing
// 	// the memory when freeing the memory associated with the
// 	// PKI_X509_KEYPAIR data structure)
// 	kp->value = NULL;

// 	// Free the Memory
// 	PKI_X509_KEYPAIR_free(kp);
	
// 	return ret;
// }

// /*!
//  * \brief Verifies a signature on a PKI_X509 object (not for PKCS7 ones)
//  */

// int PKI_X509_verify(const PKI_X509 *x, const PKI_X509_KEYPAIR *key ) {

// 	int ret = PKI_ERR;
// 	const HSM *hsm = NULL;

// 	// PKI_MEM *data = NULL;
// 	// PKI_MEM *sig = NULL;

// 	// PKI_STRING *sig_value = NULL;
// 	// PKI_X509_ALGOR_VALUE *alg = NULL;

// 	// Make sure the library is initialized
// 	PKI_init_all();

// 	// Input Checks
// 	if (!x || !x->value || !key || !key->value) {

// 		// Checks the X509 structure to verify
// 		if (!x || !x->value)
// 			return PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing data to verify");

// 		// Checks the key value
// 		if (!key || !key->value)
// 			return PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing keypair to verify with");
// 	}

// 	// Gets the reference to the HSM to use
// 	hsm = key->hsm != NULL ? key->hsm : HSM_get_default();

// 	// Uses the callback to verify the signature that was copied
// 	// in the sig (PKI_MEM) structure
// 	if (hsm && hsm->callbacks && hsm->callbacks->asn1_verify) {

// 		// Debugging Info
// 		PKI_log_debug( "HSM verify() callback called " );

// 		// // Calls the callback function
// 		// ret = hsm->callbacks->verify(data,
// 		// 			     sig,
// 		// 			     alg,
// 		// 			     (PKI_X509_KEYPAIR *)key );
// 		// Calls the callback function
// 		ret = hsm->callbacks->asn1_verify(x, key);

// 	} else {

// 		// Experimental: use ASN1_item_verify()
// 		// ret = ASN1_item_verify(x->it, 
// 		// 			   			  PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG1),
// 		// 		    			  PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE),
// 		// 	             		  x->value, 
// 		// 			     		  key->value
// 		// );

// 		ret = PKI_X509_ITEM_verify(x->it,
// 								   PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG1),
// 								   PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE),
// 								   x->value,
// 								   key->value
// 		);
// 	}
	
// 	// if (success == 1) {
// 	// 	PKI_DEBUG("PKI_X509_verify()::Signature Verified!");
// 	// } else {
// 	// 	PKI_DEBUG("PKI_X509_verify()::Signature Verification Failed!");
// 	// }

// 	// // Gets the algorithm from the X509 data
// 	// if (( alg = PKI_X509_get_data(x, PKI_X509_DATA_ALGORITHM)) == NULL) {

// 	// 	// Reports the error
// 	// 	return PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN,
// 	// 		"Can not get algorithm from object!");
// 	// }

// 	// // Gets the DER representation of the data to be signed

// 	// // if ((data = PKI_X509_get_der_tbs(x)) == NULL) {
// 	// // if ((data = PKI_X509_get_data(x, PKI_X509_DATA_TBS_MEM_ASN1)) == NULL) {
// 	// if ((data = PKI_X509_get_tbs_asn1(x)) == NULL) {
// 	// 	return PKI_ERROR(PKI_ERR_DATA_ASN1_ENCODING, 
// 	// 		"Can not get To Be signed object!");
// 	// }

// 	// // Gets a reference to the Signature field in the X509 structure
// 	// if ((sig_value = PKI_X509_get_data(x, 
// 	// 				PKI_X509_DATA_SIGNATURE)) == NULL) {

// 	// 	// Free the memory
// 	// 	PKI_MEM_free(data);

// 	// 	// We could not get the reference to the signature field
// 	// 	return PKI_ERROR(PKI_ERR_POINTER_NULL,
// 	// 		"Can not get Signature field from the X509 object!");
// 	// }

// 	// // Copies the signature data structure from the sig_value (PKI_STRING)
// 	// // of the X509 structure to the sig one (PKI_MEM)
// 	// if ((sig = PKI_MEM_new_data((size_t)sig_value->length,
// 	// 						(unsigned char *)sig_value->data)) == NULL) {

// 	// 	// Free memory
// 	// 	PKI_MEM_free(data);

// 	// 	// Reports the memory error
// 	// 	return PKI_ERR;
// 	// }

// 	// // Uses the callback to verify the signature that was copied
// 	// // in the sig (PKI_MEM) structure
// 	// if (hsm && hsm->callbacks && hsm->callbacks->verify) {

// 	// 	// Debugging Info
// 	// 	PKI_log_debug( "HSM verify() callback called " );

// 	// 	// Calls the callback function
// 	// 	ret = hsm->callbacks->verify(data,
// 	// 				     sig,
// 	// 				     alg,
// 	// 				     (PKI_X509_KEYPAIR *)key );

// 	// } else {

// 	// 	// // Debugging
// 	// 	// FILE * fp = fopen("signature_verify.der", "w");
// 	// 	// if (fp) {
// 	// 	// 	fwrite(sig->data, sig->size, 1, fp);
// 	// 	// 	fclose(fp);
// 	// 	// }
// 	// 	// fp = fopen("signed_data_verify.der", "w");
// 	// 	// if (fp) {
// 	// 	// 	fwrite(data->data, data->size, 1, fp);
// 	// 	// 	fclose(fp);
// 	// 	// }

// 	// 	// If there is no verify callback, let's call the internal one
// 	// 	ret = PKI_verify_signature(data, sig, alg, x->it, key);

// 	// }

// 	// // Free the allocated memory
// 	// if ( data ) PKI_MEM_free ( data );
// 	// if ( sig  ) PKI_MEM_free ( sig  );

// 	// Provides some additional information in debug mode
// 	if (ret != PKI_OK) {
// 		PKI_DEBUG("Crypto Layer Error: %s (%d)", 
// 			HSM_get_errdesc(HSM_get_errno(hsm), hsm), 
// 			HSM_get_errno(hsm));
// 	} else {
// 		PKI_DEBUG("Validation Completed Successfully!");
// 	}

// 	return ret;
// }

// /*! \brief Verifies a signature */

// int PKI_verify_signature(const PKI_MEM              * data,
//                          const PKI_MEM              * sig,
//                          const PKI_X509_ALGOR_VALUE * alg,
// 						 const ASN1_ITEM            * it,
//                          const PKI_X509_KEYPAIR     * key ) {
// 	int v_code = 0;
// 		// OpenSSL return code

// 	EVP_MD_CTX *ctx = NULL;
// 		// PKey Context

// 	PKI_X509_KEYPAIR_VALUE * k_val = PKI_X509_get_value(key);
// 		// Internal representation of the key

// 	const PKI_DIGEST_ALG *dgst = NULL;
// 		// Digest Algorithm

// 	// Input Checks
// 	if (!data || !data->data || !sig || !sig->data ||
// 		!alg  || !key || !k_val )  {
// 		// Reports the Input Error
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 	}

// 	// Gets the Digest Algorithm to verify with
// 	if ((dgst = PKI_X509_ALGOR_VALUE_get_digest(alg)) == PKI_ID_UNKNOWN) {
// 		// Reports the error
// 		return PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN,  NULL);
// 	}

// 	// PKI_DEBUG("Executing ASN1_item_verify()");

// 	// ASN1_BIT_STRING signature;
// 	// signature.data = sig->data;
// 	// signature.length = (int)sig->size;

// 	// ASN1_item_verify(it, (X509_ALGOR *)alg, &signature, NULL, k_val);
// 	// PKI_DEBUG("Done with ASN1_item_verify()");

// 	// Only use digest when we have not digest id
// 	// that was returned for the algorithm
// 	if (dgst != NULL && dgst != EVP_md_null()) {

// 		EVP_PKEY_CTX * pctx = NULL;

// 		// Creates and Initializes a new crypto context (CTX)
// 		if ((ctx = EVP_MD_CTX_new()) == NULL) {
// 			// Can not alloc memory, let's report the error
// 			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 		}

// 		// Initializes the new CTX
// 		EVP_MD_CTX_init(ctx);

// 		// Initializes the verify function
// 		if (!EVP_DigestVerifyInit(ctx, &pctx, dgst, NULL, k_val)) {
// 			// Error in initializing the signature verification function
// 			PKI_DEBUG("Signature Verify Initialization (Crypto Layer Error): %s (%d)", 
// 				HSM_get_errdesc(HSM_get_errno(NULL), NULL), HSM_get_errno(NULL));
// 			// Done working
// 			goto err;
// 		}

// 		// Finalizes the validation
// 		if ((v_code = EVP_DigestVerify(ctx, sig->data, sig->size, data->data, data->size)) <= 0) {
// 			// Reports the error
// 			PKI_DEBUG("Signature Verify Final Failed (Crypto Layer Error): %s (%d - %d)", 
// 				HSM_get_errdesc(HSM_get_errno(NULL), NULL), v_code,	HSM_get_errno(NULL));
// 			// Done working
// 			goto err;
// 		}

// 	} else {

// 		EVP_PKEY_CTX * pctx = EVP_PKEY_CTX_new(key->value, NULL);
// 			// Context for the verify operation

// 		// If we are in composite, we should attach the X509_ALGOR pointer
// 		// to the application data for the PMETH verify() to pick that up
// 		if (alg) {
// 			PKI_DEBUG("Setting App Data (We Should use the CTRL interface?): %p", alg);
// 			EVP_PKEY_CTX_set_app_data(pctx, (void *)alg);
// 		}

// 		// Initialize the Verify operation
// 		if ((v_code = EVP_PKEY_verify_init(pctx)) <= 0) {
// 			PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, "cannot initialize direct (no-hash) sig verification");
// 			goto err;
// 		}

// 		// Verifies the signature
// 		if ((v_code = EVP_PKEY_verify(pctx, sig->data, sig->size, data->data, data->size)) <= 0) {
// 			PKI_ERROR(PKI_ERR_SIGNATURE_VERIFY, NULL);
// 			goto err;
// 		}
// 	}

// 	// Free the memory
// #if OPENSSL_VERSION_NUMBER < 0x1010000fL
// 	EVP_MD_CTX_cleanup(ctx);
// #else
// 	EVP_MD_CTX_reset(ctx);
// #endif
// 	EVP_MD_CTX_free(ctx);

// 	// All Done
// 	return PKI_OK;

// err:
// 	// Free Memory
// 	if (ctx) {
// #if OPENSSL_VERSION_NUMBER < 0x1010000fL
// 		EVP_MD_CTX_cleanup(ctx);
// #else
// 		EVP_MD_CTX_reset(ctx);
// #endif
// 		EVP_MD_CTX_free(ctx);
// 	}

// 	// Returns the error
// 	return PKI_ERR;
// }