/* openssl/pki_pkey.c */

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_HSM_OPENSSL_PKEY_H
#define _LIBPKI_HSM_OPENSSL_PKEY_H

#include <libpki/pki.h>

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp );
PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp );
#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp);
#else
void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp );
#endif

int _evp_ctx_key_generation(int pkey_type, PKI_X509_KEYPAIR_VALUE ** pkey) {

    EVP_PKEY_CTX * pctx = NULL;
        // Key generation context

    // Input Checks
    if (!pkey) {
        PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
        return PKI_ERR;
    }

    if (pkey_type <= 0) {
        PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
        return PKI_ERR;
    }
    
    pctx = EVP_PKEY_CTX_new_id(pkey_type, NULL);
    if (!pctx) {
        PKI_DEBUG("Can not create context for key generation (%d)", pkey_type);
        return PKI_ERR;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        PKI_DEBUG("Can not init ED448 context");
        EVP_PKEY_CTX_free(pctx);
        return PKI_ERR;
    }

    if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
        PKI_DEBUG("Can not generate ED448 key");
        EVP_PKEY_CTX_free(pctx);
        return PKI_ERR;
    }

    EVP_PKEY_CTX_free(pctx);
    if (!*pkey) {
        PKI_DEBUG("Can not generate ED448 key");
        return PKI_ERR;
    }

    return PKI_OK;
}

int _evp_ctx_key_generation_rsa(PKI_KEYPARAMS * const params, PKI_X509_KEYPAIR_VALUE ** pkey) {

    EVP_PKEY_CTX * pctx = NULL;
        // Key generation context

    // Input Checks
    if (!pkey || !params) {
        PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
        return PKI_ERR;
    }

    if (params->pkey_type <= 0) {
        PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
        return PKI_ERR;
    }
    
    pctx = EVP_PKEY_CTX_new_id(params->pkey_type, NULL);
    if (!pctx) {
        PKI_DEBUG("Can not create context for key generation (%d)", params->pkey_type);
        return PKI_ERR;
    }

    // ====================
    // Set the RSA key size
    // ====================

    int bits = params->rsa.bits;
    if (bits <= 0) {
        if (bits <= 0) {
            if (bits <= 0) bits = PKI_RSA_KEY_DEFAULT_SIZE;
        }
        bits = PKI_SCHEME_ID_get_bitsize(params->scheme, params->sec_bits);
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        PKI_DEBUG("Can not init ED448 context");
        EVP_PKEY_CTX_free(pctx);
        return PKI_ERR;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0) {
        PKI_DEBUG("Can not set RSA key size (%d)", bits);
        EVP_PKEY_CTX_free(pctx);
        return PKI_ERR;
    }
    params->bits = bits;
    params->rsa.bits = bits;

    if (EVP_PKEY_keygen(pctx, pkey) <= 0) {
        PKI_DEBUG("Can not generate ED448 key");
        EVP_PKEY_CTX_free(pctx);
        return PKI_ERR;
    }

    EVP_PKEY_CTX_free(pctx);
    if (!*pkey) {
        PKI_DEBUG("Can not generate ED448 key");
        return PKI_ERR;
    }

    return PKI_OK;
}

int _pki_rand_init( void );

/* End of _LIBPKI_INTERNAL_PKEY_H */
#endif

int _pki_rand_seed( void ) {
    unsigned char seed[20];

    if (!RAND_bytes(seed, 20)) return 0;

    RAND_seed(seed, sizeof seed);

    return(1);
}

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp ) {

    BIGNUM *bne = NULL;
    PKI_RSA_KEY *rsa = NULL;
    int ossl_rc = 0;

    int bits = PKI_RSA_KEY_DEFAULT_SIZE;

    unsigned long e = RSA_F4;
        // Default exponent (65537)

    if ( kp && kp->bits > 0 ) bits = kp->bits;

    if ( bits < PKI_RSA_KEY_MIN_SIZE ) {
        PKI_DEBUG("WARNING: RSA Key size smaller than minimum safe size (%d vs. %d)", 
            bits, PKI_RSA_KEY_DEFAULT_SIZE);
        return NULL;
    } else if ( bits < PKI_RSA_KEY_DEFAULT_SIZE ) {
        PKI_DEBUG("WARNING: RSA Key size smaller than default safe size (%d vs. %d)", 
            bits, PKI_RSA_KEY_DEFAULT_SIZE);
    }

    if ((bne = BN_new()) != NULL) {
        if (1 != BN_set_word(bne, e)) {
            PKI_ERROR(PKI_ERR_GENERAL, NULL);
            return NULL;
        }
    } else {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return NULL;
    }
        
    if ((rsa = RSA_new()) == NULL) {
        BN_free(bne);
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return NULL;
    }

    if ((ossl_rc = RSA_generate_key_ex(rsa, bits, bne, NULL)) != 1 ) {
        /* Error */
        BN_free(bne);
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
        return NULL;
    }

    BN_free(bne);

    /* Let's return the RSA_KEY infrastructure */
    return (rsa);
};

PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp ) {

    PKI_DSA_KEY *k = NULL;
    unsigned char seed[20];

    int bits = PKI_DSA_KEY_DEFAULT_SIZE;

    if ( kp && kp->bits > 0 ) bits = kp->bits;

    if ( bits < PKI_DSA_KEY_MIN_SIZE ) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
        return NULL;
    };

    if (!RAND_bytes(seed, 20)) {
        /* Not enought rand ? */
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Too low Entropy");
        return NULL;
    }

    if ((k = DSA_new()) == NULL) {
        // Memory Allocation Error
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Too low Entropy");
        return NULL;
    }

    if (1 != DSA_generate_parameters_ex(k, bits, seed, 20, NULL, NULL, NULL)) {
        if( k ) DSA_free( k );
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generated DSA params");
        return NULL;
    }

    return( k );
}

#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
    /* ECDSA is a little more complicated than the other
       schemes as it involves a group of functions. As the
       purpose of this library is to provide a very hi-level
       easy to use library, we will provide some hardwired
       parameters.
    */
    PKI_EC_KEY *k = NULL;
    EC_builtin_curve *curves = NULL;
    EC_GROUP *group = NULL;
    size_t num_curves = 0;
    int degree = 0;

    int bits    = PKI_EC_KEY_DEFAULT_SIZE;
    int curve   = PKI_EC_KEY_CURVE_DEFAULT;
    int flags   = PKI_EC_KEY_ASN1_DEFAULT;

    PKI_EC_KEY_FORM form     = PKI_EC_KEY_FORM_DEFAULT;

    /* Get the number of available ECDSA curves in OpenSSL */
    if ((num_curves = EC_get_builtin_curves(NULL, 0)) < 1 ) {
        /* No curves available! */
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Builtin EC curves");
        return NULL;
    }

    /* Alloc the needed memory */
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * num_curves));
#else
    curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * num_curves);
#endif

    /* Check for memory allocation */
    if (curves == NULL) return NULL;

    /* Get the builtin curves */
    if (!EC_get_builtin_curves(curves, (size_t) num_curves))
    {
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Can not get builtin EC curves (%d)", num_curves);
        goto err;
        return NULL;
    }

    /* We completely change behavior - we adopt one of the two
         * curves suggested by NIST. In particular:
         * - NID_secp384r1
         * - NID_secp521r1
         * For today (2008) usage, the first curve + SHA256 seems to be
         * the best approach
         */

    if( kp && kp->bits > 0 ) {
        bits = kp->bits;
    };

    if(bits < PKI_EC_KEY_MIN_SIZE ){
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, "%d", bits);
        return NULL;
    };

    if( kp && kp->ec.curve > 0 ) {
        curve = kp->ec.curve;
    } else {
        if( bits <= 112 ) {
            bits = 112;
            curve = NID_secp112r1;
        } else if( bits <= 128 ) {
            bits = 128;
            curve = NID_secp128r1;
        } else if( bits <= 160 ) {
            bits = 160;
            curve = NID_secp160r1;
        } else if( bits <= 192 ) {
            bits = 192;
            curve = NID_X9_62_prime192v1;
        } else if( bits <= 224 ) {
            bits = 224;
            curve = NID_secp224r1;
        } else if( bits <= 256 ) {
            bits = 256;
            curve = NID_X9_62_prime256v1;
        } else if( bits <= 384 ) {
            bits = 384;
            curve = NID_secp384r1;
        } else {
            bits = 512;
            curve = NID_secp521r1;
        };
    };

    /* Initialize the key */
    if ((k = EC_KEY_new()) == NULL) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
        goto err;
        return NULL;
    }

    if((group = EC_GROUP_new_by_curve_name(curve)) == NULL ) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Curve - %d", curve);
        goto err;
        return NULL;
    };

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group, form);

    /* Assign the group to the key */
    if (EC_KEY_set_group(k, group) == 0) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Group");
        goto err;
        return NULL;
    }

    /* Sets the point compression */
    if ( kp && kp->ec.form != PKI_EC_KEY_FORM_UNKNOWN ) {
        form = kp->ec.form;
    };
    EC_KEY_set_conv_form(k, (point_conversion_form_t)form);

    /* Sets the type of parameters, flags > 0 ==> by OID, 
      * flags == 0 ==> specifiedCurve
      */
    if ( kp->ec.asn1flags > -1 ) {
        flags = kp->ec.asn1flags;
    };
    EC_KEY_set_asn1_flag(k, flags);

    /* We do not need it now, let's free the group */
    if ( group ) EC_GROUP_free( group );
    group = NULL;

    if((group = (EC_GROUP *) EC_KEY_get0_group(k)) != NULL ) {
        EC_GROUP_set_asn1_flag( group, OPENSSL_EC_NAMED_CURVE );
    };

    degree = EC_GROUP_get_degree(EC_KEY_get0_group(k));

    if( degree < bits ) {
        /* Fix the problem, let's get the right bits */
        bits = degree;
    }

    //    // Let's cycle through all the available curves
    //    // until we find one that matches (if any)
    //    i = (i + 1 ) % num_curves;
    //
    // } while ( (degree < bits ) && (i != n_start) );

    /* Now generate the key */
    if (!EC_KEY_generate_key(k)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL );
        goto err;
        return NULL;
    }

    /* Verify the Key to be ok */
    if (!EC_KEY_check_key(k)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Verify failed for ECDSA key" );
        goto err;
        return NULL;
    }

    // EC_KEY_set_enc_flags(k, EC_PKEY_NO_PARAMETERS);
    // ecKeyPnt = (struct __ec_key_st2 *) k;
    // ecKeyPnt->version = 1;

    goto end;

err:
    if( curves ) free ( curves );
    if ( group ) EC_GROUP_free( group );

    if( k ) {
        EC_KEY_free ( k );
        k = NULL;
    };

end:
    return ( k );
}

#else /* EVP_PKEY_EC */

void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
    PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
    return ( NULL );
}

#endif

#ifdef ENABLE_OQS

EVP_PKEY_CTX * _pki_get_evp_pkey_ctx(PKI_KEYPARAMS *kp) {

    const EVP_PKEY_ASN1_METHOD *ameth;

    ENGINE *tmpeng = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    int pkey_id = -1;

    if (!kp->oqs.algId) {
        PKI_DEBUG("Missing algorithm ID for OQS key generation");
        return NULL;
    }

    ameth = EVP_PKEY_asn1_find(&tmpeng, kp->oqs.algId);
    if (!ameth) {
       PKI_log_debug("Missing ASN1 Method for algorithm '%s' (%d)", 
           PKI_ALGOR_ID_txt(kp->oqs.algId), kp->oqs.algId);
       return NULL;
    }

    ERR_clear_error();

    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);

    if ((ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL)) == NULL)
        goto err;

    // Let's set the operation (check EVP_PKEY_CTX_ctrl function -pmeth_lib.c:432)
    // Use the EVP interface to initialize the operation (crypto/evp/pmeth_gn.c:69)
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot Initialize Key Generation");
        goto err;
    }

#ifdef ENABLE_COMPOSITE

    // CTX operations for Composite Crypto
    //
    // EVP_PKEY_CTRL_COMPOSITE_PUSH       
    // EVP_PKEY_CTRL_COMPOSITE_POP        
    // EVP_PKEY_CTRL_COMPOSITE_ADD        
    // EVP_PKEY_CTRL_COMPOSITE_DEL        
    // EVP_PKEY_CTRL_COMPOSITE_CLEAR      


    if ((kp->scheme == PKI_SCHEME_COMPOSITE ||
         kp->scheme == PKI_SCHEME_COMBINED)
         && kp->comp.k_stack != NULL) {

        for (int i = 0; i < PKI_STACK_X509_KEYPAIR_elements(kp->comp.k_stack); i++) {

            PKI_X509_KEYPAIR * tmp_key = NULL;

            // Let's get the i-th PKI_X509_KEYPAIR
            tmp_key = PKI_STACK_X509_KEYPAIR_get_num(kp->comp.k_stack, i);
            // Now we can use the CRTL interface to pass the new keys
            if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
                                  EVP_PKEY_CTRL_COMPOSITE_PUSH, 0, tmp_key->value) <= 0) {
                PKI_log_debug("Cannot add key via the CTRL interface");
                goto err;
            }
        }
    }
#endif

    return ctx;

 err:

    PKI_log_debug("Error initializing context for [scheme: %d, algId: %d]\n", 
        kp->scheme, kp->oqs.algId);

    if (ctx) EVP_PKEY_CTX_free(ctx);
    return NULL;
}

#endif

#ifdef ENABLE_COMPOSITE
PKI_COMPOSITE_KEY * _pki_composite_new( PKI_KEYPARAMS *kp ) {

    PKI_COMPOSITE_KEY *k = NULL;
    const char * scheme_name = PKI_SCHEME_ID_get_parsed(kp->scheme);
    if (!scheme_name) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Unknown Scheme");
        return NULL;
    }

    if ((k = COMPOSITE_KEY_new()) == NULL) {
        // Memory Allocation Error
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return NULL;
    }

    int pkey_type = kp->pkey_type; // PKI_ID_get_by_name(PKI_SCHEME_ID_get_parsed(kp->scheme));
    if (pkey_type <= 0) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Unknown Algorithm");
        COMPOSITE_KEY_free(k);
        return NULL;
    }

    // Let's set the algorithm
    k->algorithm = pkey_type;

    PKI_DEBUG("Creating a Composite Key");
    PKI_DEBUG("Scheme: %d (%s)", kp->scheme, PKI_SCHEME_ID_get_parsed(kp->scheme));
    PKI_DEBUG("Pkey Type: %d (%s)", pkey_type, OBJ_nid2sn(pkey_type));

    // if (PKI_SCHEME_ID_is_explicit_composite(kp->scheme)) {
    //     PKI_DEBUG("Explicit Composite Key");
    //     k->algorithm = pkey_type;
    // } else if (PKI_SCHEME_ID_is_composite(kp->scheme)) {
    //     PKI_DEBUG("Gemeric Composite Key");
    //     k->algorithm = pkey_type;
    // } else if (PKI_SCHEME_ID_is_post_quantum(kp->scheme)) {
    //     PKI_DEBUG("Unknown Composite Key");
    //     k->algorithm = kp->oqs.algId;
    // }

    if (kp->comp.k_stack != NULL) {

        for (int i = 0; i < PKI_STACK_X509_KEYPAIR_elements(kp->comp.k_stack); i++) {

            PKI_X509_KEYPAIR * tmp_key = NULL;
            // PKI_X509_KEYPAIR_VALUE * tmp_val = NULL;

            // Let's get the i-th PKI_X509_KEYPAIR
            tmp_key = PKI_STACK_X509_KEYPAIR_get_num(kp->comp.k_stack, i);
            if (!tmp_key) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot get key from stack");
                COMPOSITE_KEY_free(k);
                return NULL;
            }

            // // Let's get the internal value
            // PKI_X509_detach(tmp_key, (void **)&tmp_val, NULL, NULL);
            // if (!tmp_val) {
            //     PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot get key value");
            //     COMPOSITE_KEY_free(k);
            //     return NULL;
            // }

            // // Free the memory associated with the PKI_X509_KEYPAIR
            // PKI_X509_KEYPAIR_free(tmp_key);

            // Pushes the Key onto the stack
            // COMPOSITE_KEY_push(k, tmp_key->value);
            COMPOSITE_KEY_push(k, tmp_key->value);

            // // Now we can use the CRTL interface to pass the new keys
            // if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            //                       EVP_PKEY_CTRL_COMPOSITE_PUSH, 0, tmp_key->value) <= 0) {
            //     PKI_log_debug("Cannot add key via the CTRL interface");
            //     goto err;
            // }
        }
    }

    // Adds the Parameter (k-of-n) to the key
    if (kp->comp.k_of_n != NULL) {
        if (k->params) ASN1_INTEGER_free(k->params);
        k->params = ASN1_INTEGER_dup(kp->comp.k_of_n);
    }

    // All Done.
    return k;
}
#endif

PKI_X509_KEYPAIR *HSM_OPENSSL_X509_KEYPAIR_new(PKI_KEYPARAMS * kp, 
                                               URL           * url, 
                                               PKI_CRED      * cred, 
                                               HSM           * driver ) {

    PKI_X509_KEYPAIR *ret = NULL;
    PKI_X509_KEYPAIR_VALUE * value = NULL;
    // PKI_RSA_KEY *rsa = NULL;
    PKI_DSA_KEY *dsa = NULL;

#ifdef ENABLE_ECDSA
    PKI_EC_KEY *ec = NULL;
#endif

#ifdef ENABLE_OQS
    EVP_PKEY_CTX * ctx = NULL;
#endif

#ifdef ENABLE_COMPOSITE
    COMPOSITE_KEY * composite = NULL;
#endif

#ifdef ENABLE_COMBINED
    EVP_PKEY_COMBINED * combined = NULL;
#endif

    PKI_SCHEME_ID type = PKI_SCHEME_DEFAULT;

    if (!kp) {
        PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
        return NULL;
    }

    if ( kp && kp->scheme != PKI_SCHEME_UNKNOWN ) type = kp->scheme;

    // if ((ret = PKI_X509_new(PKI_DATATYPE_X509_KEYPAIR, driver)) == NULL) {
    //     PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair");
    //     return NULL;
    // }

    // if((ret->value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
    //     PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
    //     return NULL;
    // }

    if( _pki_rand_seed() == 0 ) {
        /* Probably low level of randomization available */
        PKI_log_debug("WARNING, low rand available!");
    }

    switch (type) {

#ifdef ENABLE_ED448
        case PKI_SCHEME_ED448: {
            int success = _evp_ctx_key_generation(PKI_ALGOR_ID_ED448, &value);
            if (!success) {
                PKI_DEBUG("Cannot generate the ED448 key");
                goto err;
            }
        } break;
#endif

#ifdef ENABLE_X448
        case PKI_SCHEME_X448: {
            int success = _evp_ctx_key_generation(PKI_ALGOR_ID_X448, &value);
            if (!success) {
                PKI_DEBUG("Cannot generate the X448 key");
                goto err;
            }
        } break;
#endif

#ifdef ENABLE_ED25519
        case PKI_SCHEME_ED25519: {
            int success = _evp_ctx_key_generation(PKI_ALGOR_ID_ED25519, &value);
            if (!success) {
                PKI_DEBUG("Cannot generate the ED448 key");
                goto err;
            }
        } break;
#endif

#ifdef ENABLE_X25519
        case PKI_SCHEME_X25519: {
            int success = _evp_ctx_key_generation(PKI_ALGOR_ID_X25519, &value);
            if (!success) {
                PKI_DEBUG("Cannot generate the ED448 key");
                goto err;
            }
        } break;
#endif

        case PKI_SCHEME_RSAPSS:
        case PKI_SCHEME_RSA: {
            // if ((rsa = _pki_rsakey_new( kp )) == NULL ) {
            //     PKI_DEBUG("Cannot generate the RSA key");
            //     goto err;
            // }
            // if (!EVP_PKEY_assign_RSA((EVP_PKEY *) value, rsa)) {
            //     PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign RSA key");
            //     if( rsa ) RSA_free( rsa );
            //     goto err;
            // }
            int success = _evp_ctx_key_generation_rsa(kp, &value);
            if (!success) {
                PKI_DEBUG("Cannot generate the RSA key");
                goto err;
            }
        } break;

        case PKI_SCHEME_DSA: {
            if ((dsa = _pki_dsakey_new( kp )) == NULL ) {
                PKI_DEBUG("Cannot generate the DSA key");
                goto err;
            }
            if (!DSA_generate_key( dsa )) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
                goto err;
            }
            if ((value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
                PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
                return NULL;
            }
            if (!EVP_PKEY_assign_DSA(value, dsa)) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign DSA key");
                if( dsa ) DSA_free ( dsa );
                goto err;
            }
            dsa=NULL;
        } break;

#ifdef ENABLE_ECDSA

        case PKI_SCHEME_ECDSA: {
            if ((ec = _pki_ecdsakey_new( kp )) == NULL ) {
                PKI_DEBUG("Cannot generate the ECDSA key");
                goto err;
            }
            if ((value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
                PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
                return NULL;
            }
            if (!EVP_PKEY_assign_EC_KEY(value, ec)){
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign ECDSA key");
                if( ec ) EC_KEY_free ( ec );
                goto err;
            }
        } break;

#ifdef ENABLE_COMPOSITE

        // Generic Composite
        case PKI_SCHEME_COMPOSITE:
        // Explicit Composite
        case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521:
	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
            
            if ((composite = _pki_composite_new(kp)) == NULL) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not initiate keypair generation");
                goto err;
            }
            if ((value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
                PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
                return NULL;
            }
            if (!EVP_PKEY_assign_COMPOSITE(value, composite)) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign COMPOSITE key");
                if (composite) COMPOSITE_KEY_free(composite);
                goto err;
            }
        } break;
#endif

#ifdef ENABLE_COMBINED
        case PKI_SCHEME_COMBINED:
        if ((combined = _pki_combined_new(kp)) == NULL) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not initiate keypair generation");
                return NULL;
            };
            if ((value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
                PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
                return NULL;
            }
            if (!EVP_PKEY_assign_COMBINED(value, combined)) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign COMBINED key");
                if (combined) COMBINED_KEY_free(combined);
                return NULL;
            }
            combined=NULL;
            break;
#endif

#endif // ENABLE_ECDSA

        default:

#ifdef ENABLE_OQS
            if ((ctx = _pki_get_evp_pkey_ctx(kp)) == NULL) {
                PKI_DEBUG("Cannot generate the PQC key");
                goto err;
            }
            if (EVP_PKEY_keygen(ctx, &value) <= 0) {
                if (ctx) EVP_PKEY_CTX_free(ctx);
                goto err;
            }
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;

#else
            /* No recognized scheme */
            PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "%d", type );
            goto err;

#endif // ENABLE_OQS

    }

    // Checks that a Key was generated
    if (!value) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generate keypair");
        goto err;
    }

    // Allocates the PKI_X509_KEYPAIR structure
    if ((ret = PKI_X509_new(PKI_DATATYPE_X509_KEYPAIR, driver)) == NULL) {
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair");
        return NULL;
    }

    /* Sets the value in the PKI_X509_KEYPAIR structure */
    if (PKI_ERR == PKI_X509_attach(ret, PKI_DATATYPE_X509_KEYPAIR, value, driver)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not attach keypair");
        goto err;
    }

    // Sets the requirement for the digest in the key
    if (PKI_SCHEME_ID_requires_digest(type)) {
        ret->signature_digest_required = 1;
    }

    /* Let's return the PKEY infrastructure */
    return ret;

err:

    // Memory Cleanup
    if (value) EVP_PKEY_free(value);
    if (ret) PKI_X509_KEYPAIR_free(ret);
    if (ctx) EVP_PKEY_CTX_free(ctx);

    // Error
    return NULL;
}

/* Key Free function */
void HSM_OPENSSL_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey ) {

    if( !pkey) return;

    PKI_X509_free ( pkey );

    return;
}

// OpenSSL Fix
// When writing PEM formatted Keys the wrong version "0" is
// used by the default EVP_PKEY_ write functions for EC keys,
// we have to provide our own function until OpenSSL solve
// this issue

int OPENSSL_HSM_write_bio_PrivateKey (BIO *bp, EVP_PKEY *x, 
        const EVP_CIPHER *enc, unsigned char *out_buffer, int klen, 
        pem_password_cb *cb, void *u) {

    int ret = PKI_ERR;

    // Input Check
    if (!x || !bp) return PKI_ERR;

    // Different functions depending on the Key type
    switch(EVP_PKEY_type(EVP_PKEY_id(x)))
    {

#ifdef ENABLE_ECDSA
        case EVP_PKEY_EC: {
# if OPENSSL_VERSION_NUMBER < 0x1010000fL
            ret = PEM_write_bio_ECPrivateKey(bp, 
                x->pkey.ec, enc, (unsigned char *) out_buffer, klen, cb, u);
# else
            ret = PEM_write_bio_ECPrivateKey(bp, 
                EVP_PKEY_get0_EC_KEY(x), enc, (unsigned char *) out_buffer, klen, cb, u);
# endif
            if (!ret) {
                PKI_DEBUG("Internal Error while encoding EC Key (PEM).");
                return PKI_ERR;
            }
        } break;
#endif

        default: {
            if ((ret = PEM_write_bio_PKCS8PrivateKey(bp, x, enc, 
                (char *) out_buffer, klen, cb, u)) != 1) {
                // Debug Info
                PKI_DEBUG("Key Type NOT supported (%d)", 
                    EVP_PKEY_type(EVP_PKEY_id(x)));
                // Error Condition
                return PKI_ERR;
            }
        }
    }

    // All Done
    return ret;
}

// OpenSSL Fix
//
// Strangely enough OpenSSL does not provide an EVP_PKEY_dup()
// function, we supply it

EVP_PKEY *OPENSSL_HSM_KEYPAIR_dup(EVP_PKEY *kVal)
{
    // Input checks
    if (!kVal) {
        PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
        return NULL;
    }

    // Update the reference for the PKEY
    if (!EVP_PKEY_up_ref(kVal)) {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot update PKEY references");
        return NULL;
    }

    // All Done
    return kVal;
};

