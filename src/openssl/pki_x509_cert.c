/* PKI_X509 object management */

#include <libpki/pki.h>
#include <sys/utsname.h>

#include "internal/x509_data_st.h"

#if OPENSSL_VERSION_NUMBER < 0x00908000
extern int NID_proxyCertInfo;
#endif

/*! \brief Returns an empty PKI_X509_CERT data structure */
PKI_X509_CERT *PKI_X509_CERT_new_null ( void ) {
  return PKI_X509_new ( PKI_DATATYPE_X509_CERT, NULL );
}

void PKI_X509_CERT_free_void( void *x ) {
  PKI_X509_free( (PKI_X509 *) x );

  return;
}

/*! \brief Frees the memory associated with a certificate */

void PKI_X509_CERT_free( PKI_X509_CERT *x ) {

   if (x) PKI_X509_free ( x );
  return;
}

/*! \brief Returns a copy of the PKI_X509_CERT structure */

PKI_X509_CERT *PKI_X509_CERT_dup(const PKI_X509_CERT *x ) {

  if( !x ) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return ( NULL );
  };

  return PKI_X509_dup ( x );
}

/*! \brief Generates a new certificate */

PKI_X509_CERT * PKI_X509_CERT_new (const PKI_X509_CERT *ca_cert, 
    				   const PKI_X509_KEYPAIR *kPair,
				   const PKI_X509_REQ *req,
				   const char *subj_s, 
    				   const char *serial_s,
				   uint64_t validity,
				   const PKI_X509_PROFILE *conf,
    				   const PKI_ALGOR *algor,
				   const PKI_CONFIG *oids,
				   HSM *hsm )
{
  PKI_X509_CERT *ret = NULL;
  PKI_X509_CERT_VALUE *val = NULL;
  PKI_X509_NAME *subj = NULL;
  PKI_X509_NAME *issuer = NULL;
  PKI_DIGEST_ALG *digest = NULL;
  PKI_X509_KEYPAIR_VALUE *signingKey = NULL;
  PKI_TOKEN *tk = NULL;

  PKI_X509_KEYPAIR_VALUE  *certPubKeyVal = NULL;

  int rv = 0;
  int ver = 2;

  int64_t notBeforeVal = 0;

  ASN1_INTEGER *serial = NULL;

  char *ver_s = NULL;

  /* Check if the REQUIRED PKEY has been passed */
  if (!kPair || !kPair->value) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return (NULL);
  };

  signingKey = kPair->value;

  /* TODO: This has to be fixed, to work on every option */
  if ( subj_s )
  {
    subj = PKI_X509_NAME_new ( subj_s );
  }
  else if ( conf )
  {
    char *tmp_s = NULL;

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
          "/profile/subject/dn")) != NULL )
    {
      subj = PKI_X509_NAME_new ( tmp_s );
      PKI_Free ( tmp_s );
    }
    else
    {
      subj = PKI_X509_NAME_new( "" );
    }
  }
  else if ( req )
  {
    const PKI_X509_NAME * req_subj = NULL;

    /* Copy the name from the request */
    if ((req_subj = PKI_X509_REQ_get_data(req, 
				    PKI_X509_DATA_SUBJECT)) != NULL) {
	    subj = PKI_X509_NAME_dup(req_subj);
    }
  }
  else
  {
    struct utsname myself;
    char tmp_name[1024];

    if (uname(&myself) < 0) {
      subj = PKI_X509_NAME_new( "" );
    } else {
      sprintf( tmp_name, "CN=%s", myself.nodename );
      subj = PKI_X509_NAME_new( tmp_name );
    }
  }

  if( !subj ) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_SUBJECT, subj_s );
    goto err;
  }

  if( ca_cert ) {
    const PKI_X509_NAME *ca_subject = NULL;

    /* Let's get the ca_cert subject and dup that data */
    // ca_subject = (PKI_X509_NAME *) 
    //     X509_get_subject_name( (X509 *) ca_cert );
    ca_subject = PKI_X509_CERT_get_data( ca_cert, 
        PKI_X509_DATA_SUBJECT );

    if( ca_subject ) {
      issuer = (PKI_X509_NAME *) X509_NAME_dup((X509_NAME *)ca_subject);
    } else {
      PKI_ERROR(PKI_ERR_X509_CERT_CREATE_ISSUER, NULL);
      goto err;
    }

  } else {
    issuer = (PKI_X509_NAME *) X509_NAME_dup((X509_NAME *) subj);
  }

  if( !issuer ) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_ISSUER, NULL);
    goto err;
  }

  if(( ret = PKI_X509_CERT_new_null()) == NULL ) {
    PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
    goto err;
  }

  /* Alloc memory structure for the Certificate */
  if((ret->value = ret->cb->create()) == NULL ) {
    PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
    return (NULL);
  }

  val = ret->value;

  if(( ver_s = PKI_CONFIG_get_value( conf, "/profile/version")) != NULL ) {
    ver = atoi( ver_s ) - 1;
    if ( ver < 0 ) 
      ver = 0;
    PKI_Free ( ver_s );
  } else {
    ver = 2;
  };

  if (!X509_set_version(val,ver)) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_VERSION, NULL);
    goto err;
  }

  if (serial_s) {
    char * tmp_s = (char *) serial_s;
    serial = s2i_ASN1_INTEGER(NULL, tmp_s);
  } else {
    // If cacert we assume it is a normal cert - let's create a
    // random serial number, otherwise - it's a self-signed, use
    // the usual 'fake' 0
    if ( ca_cert ) {
      unsigned char bytes[11];
      RAND_bytes(bytes, sizeof(bytes));
      bytes[0] = 0;

      serial = PKI_INTEGER_new_bin(bytes, sizeof(bytes));
    } else {
      serial = s2i_ASN1_INTEGER( NULL, "0");
    };
  };

  if(!X509_set_serialNumber( val, serial )) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_SERIAL, serial_s);
    goto err;
  }

  /* Set the issuer Name */
  // rv = X509_set_issuer_name((X509 *) ret, (X509_NAME *) issuer);
  if(!X509_set_issuer_name( val, (X509_NAME *) issuer)) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_ISSUER, NULL);
    goto err;
  }

  /* Set the subject Name */
  if(!X509_set_subject_name(val, (X509_NAME *) subj)) {
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_SUBJECT, NULL);
    goto err;
  }

  /* Set the start date (notBefore) */
  if (conf)
  {
    int years = 0;
    int days  = 0;
    int hours = 0;
    int mins  = 0;
    int secs  = 0;

    char *tmp_s = NULL;

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/notBefore/years")) != NULL ) {
      years = atoi( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/notBefore/days")) != NULL ) {
      days = atoi( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/notBefore/hours")) != NULL ) {
      hours = atoi( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/notBefore/minutes")) != NULL ) {
      mins = atoi( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/notBefore/seconds")) != NULL ) {
      secs = atoi( tmp_s );
      PKI_Free ( tmp_s );
    };

    notBeforeVal =   secs +
            ( mins * 60 ) + 
            ( hours * 3600 ) + 
            ( days   * 3600 * 24 ) + 
            ( years * 3600 * 24 * 365 );
  };

  /* Set the validity (notAfter) */
  if( conf && validity == 0 )
  {
    long long years = 0;
    long long days  = 0;
    long long hours = 0;
    long long mins  = 0;
    long long secs  = 0;

    char *tmp_s = NULL;

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/validity/years")) != NULL ) {
      years = atoll( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/validity/days")) != NULL ) {
      days = atoll( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/validity/hours")) != NULL ) {
      hours = atoll( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/validity/minutes")) != NULL ) {
      mins = atoll( tmp_s );
      PKI_Free ( tmp_s );
    };

    if(( tmp_s = PKI_CONFIG_get_value( conf, 
        "/profile/validity/minutes")) != NULL ) {
      secs = atoll( tmp_s );
      PKI_Free ( tmp_s );
    };

    validity =   (unsigned long long) secs +
          (unsigned long long) ( mins   * 60 ) + 
          (unsigned long long) ( hours * 3600 ) + 
          (unsigned long long) ( days   * 3600 * 24 ) + 
          (unsigned long long) ( years * 3600 * 24 * 365 );
  };

  if ( validity <= 0 ) {
    validity = 30 * 3600 * 24;
  };

#if ( LIBPKI_OS_BITS == LIBPKI_OS32 )
  long notBeforeVal32 = (long) notBeforeVal;
  if (X509_gmtime_adj(X509_get_notBefore(val), notBeforeVal32 ) == NULL)
  {
#else
  if (X509_gmtime_adj(X509_get_notBefore(val), notBeforeVal ) == NULL)
  {
#endif
    PKI_ERROR(PKI_ERR_X509_CERT_CREATE_NOTBEFORE, NULL);
    goto err;
  }

  /* Set the end date in a year */
  if (X509_gmtime_adj(X509_get_notAfter(val),(long int) validity) == NULL)
  {
    PKI_log_debug("ERROR, can not set notAfter field!");
    goto err;
  }

  /* Copy the PKEY if it is in the request, otherwise use the
     public part of the PKI_X509_CERT */
  if (req)
  {
    certPubKeyVal = (PKI_X509_KEYPAIR_VALUE *) PKI_X509_REQ_get_data ( req, 
          PKI_X509_DATA_KEYPAIR_VALUE );

    if( !certPubKeyVal )
    {
      PKI_log_debug("ERROR, can not get pubkey from req!");
      goto err;
    }
  }
  else
  {
    /* Self Signed -- Same Public Key! */
    certPubKeyVal = signingKey;
  }

  if (!ca_cert && conf)
  {
    char *tmp_s = NULL;

    if(( tmp_s = PKI_X509_PROFILE_get_value( conf, 
        "/profile/keyParams/algorithm")) != NULL )
    {
      PKI_ALGOR *myAlg = NULL;
      PKI_DIGEST_ALG *dgst = NULL;

      if((myAlg = PKI_ALGOR_get_by_name( tmp_s )) != NULL )
      {
        if(!algor) algor = myAlg;

        if((dgst = PKI_ALGOR_get_digest( myAlg )) != NULL )
        {
          PKI_log_debug("Got Signing Algorithm: %s, %s",
            PKI_DIGEST_ALG_get_parsed(dgst), PKI_ALGOR_get_parsed(myAlg));
          digest = dgst;
        }
        else
        {
          PKI_log_debug("Can not parse digest algorithm from %s", tmp_s);
        }
      }
      else
      {
        PKI_log_debug("Can not parse key algorithm from %s", tmp_s);
      }
      PKI_Free ( tmp_s );
    }
  }

  if (conf)
  {
    PKI_KEYPARAMS *kParams = NULL;
    PKI_SCHEME_ID scheme;

    scheme = PKI_ALGOR_get_scheme( algor );

    kParams = PKI_KEYPARAMS_new(scheme, conf);
    if (kParams)
    {
      /* Sets the point compression */
      switch ( kParams->scheme )
      {
#ifdef ENABLE_ECDSA
        case PKI_SCHEME_ECDSA:
            if ( (int) kParams->ec.form > 0 )
            {
# if OPENSSL_VERSION_NUMBER < 0x1010000fL
              EC_KEY_set_conv_form(certPubKeyVal->pkey.ec, 
              			   (point_conversion_form_t) kParams->ec.form);
# else
              EC_KEY_set_conv_form(EVP_PKEY_get0_EC_KEY(certPubKeyVal), 
              (point_conversion_form_t) kParams->ec.form);
# endif
            }
          if ( kParams->ec.asn1flags > -1 )
          {
# if OPENSSL_VERSION_NUMBER < 0x1010000fL
            EC_KEY_set_asn1_flag(certPubKeyVal->pkey.ec,
              kParams->ec.asn1flags );
# else
            EC_KEY_set_asn1_flag(EVP_PKEY_get0_EC_KEY(certPubKeyVal),
              kParams->ec.asn1flags );
# endif
          }
          break;
#endif
        case PKI_SCHEME_RSA:
        case PKI_SCHEME_DSA:
          break;

        default:
          // Nothing to do
          PKI_ERROR(PKI_ERR_GENERAL, "Signing Scheme Uknown %d!", kParams->scheme);
          break;
      }
    }
  }

  if (!X509_set_pubkey(val, certPubKeyVal))
  {
    PKI_log_debug("ERROR, can not set pubkey in cert!");
    goto err;
  }

  if (conf)
  {
    if((tk = PKI_TOKEN_new_null()) == NULL )
    {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
      goto err;
    }

    PKI_TOKEN_set_cert ( tk, ret );

    if (ca_cert)
    {
      PKI_TOKEN_set_cacert(tk, (PKI_X509_CERT *)ca_cert);
    }
    else
    {
      PKI_TOKEN_set_cacert ( tk, (PKI_X509_CERT *)ret );
    }

    if (req) PKI_TOKEN_set_req ( tk, (PKI_X509_REQ *)req );
    if (kPair) PKI_TOKEN_set_keypair ( tk, (PKI_X509_KEYPAIR *)kPair );

    rv = PKI_X509_EXTENSIONS_cert_add_profile(conf, oids, ret, tk);
    if (rv != PKI_OK)
    {
      PKI_log_debug( "ERROR, can not set extensions!");

      tk->cert = NULL;
      tk->cacert = NULL;
      tk->req = NULL;
      tk->keypair = NULL;

      PKI_TOKEN_free ( tk );

      goto err;
    }

    // Cleanup for the token (used only to add extensions)
    tk->cert = NULL;
    tk->cacert = NULL;
    tk->req = NULL;
    tk->keypair = NULL;
    PKI_TOKEN_free ( tk );
  }

  if (!digest)
  {
    if (!algor)
    {
      PKI_log_debug("Getting the Digest Algorithm from the CA cert");

      // Let's get the Digest Algorithm from the CA Cert
      if (ca_cert)
      {
        if((algor = PKI_X509_CERT_get_data(ca_cert,
              PKI_X509_DATA_ALGORITHM )) == NULL)
        {
          PKI_log_err("Can not retrieve DATA algorithm from CA cert");
        }
      }
    }

    // If we have an Algor from either the passed argument or
    // the CA Certificate, extract the digest from it. Otherwise
    // get the digest from the signing key
    if (algor)
    {
      if((digest = PKI_ALGOR_get_digest(algor)) == NULL )
      {
        PKI_log_err("Can not get digest from algor");
      }
    }

    // Check, if still no digest, let's try from the signing Key
    if (digest == NULL)
    {
      if ((digest = PKI_DIGEST_ALG_get_by_key( kPair )) == NULL)
      {
        PKI_log_err("Can not infer digest algor from the key pair");
      }
    }
  }

  // No Digest Here ? We failed...
  if (digest == NULL)
  {
    PKI_log_err("PKI_X509_CERT_new()::Can not get the digest!");
    return( NULL );
  }


  /*
  if(PKI_sign ( PKI_DATATYPE_X509_CERT,
      (void *) val->cert_info, &X509_CINF_it,
      val->cert_info->signature, val->sig_alg,
          val->signature, k, digest )==PKI_ERR) {
    PKI_log_err("PKI_X509_CERT_new()::Can not sign certificate!");
    goto err;
  }
  */

  // X509_sign ( val, k->value, digest );

  if (PKI_X509_sign(ret, digest, kPair) == PKI_ERR)
  {
    PKI_log_err ("Can not sign certificate [%s]",
      ERR_error_string(ERR_get_error(), NULL ));
    PKI_X509_CERT_free ( ret );
    return NULL;
  }

#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )

# if OPENSSL_VERSION_NUMBER < 0x1010000fL
  PKI_X509_CERT_VALUE *cVal = (PKI_X509_CERT_VALUE *) ret->value;

  if (cVal && cVal->cert_info)
  {
    PKI_log_debug("Signature = %s", 
      PKI_ALGOR_get_parsed(cVal->cert_info->signature));
  }
# endif

  //  PKI_X509_CINF_FULL *cFull = NULL;
  //  cFull = (PKI_X509_CINF_FULL *) cVal->cert_info;
  //  cFull->enc.modified = 1;
#endif

  /*
  if(PKI_sign ( PKI_DATATYPE_X509_CERT,
      (void *) val->cert_info, &X509_CINF_it,
      val->cert_info->signature, val->sig_alg,
      val->signature, 
      k, digest ) == PKI_ERR ) {
    PKI_log_err("PKI_X509_CERT_new()::Can not sign certificate!");
    goto err;
  }
  */

  /*
  if(!X509_sign( ret->value, k->value, digest)) {
    PKI_log_err("PKI_X509_CERT_new()::Can not sign certificate!");
    goto err;
  }
  */

  return(ret);

err:
  if( ret ) PKI_X509_CERT_free ( ret );
  if( subj ) PKI_X509_NAME_free (subj);
  if( issuer ) PKI_X509_NAME_free (issuer);

  return (NULL);
}

/*!
 * \brief Signs a PKI_X509_CERT
 */

int PKI_X509_CERT_sign(PKI_X509_CERT *cert, PKI_X509_KEYPAIR *kp,
    PKI_DIGEST_ALG *digest) {

  const PKI_ALGOR *alg = NULL;

  if( !cert || !cert->value || !kp || !kp->value ) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  }

  if(!digest) {
    if((alg = PKI_X509_CERT_get_data(cert, PKI_X509_DATA_ALGORITHM))!=NULL) {
      digest = PKI_ALGOR_get_digest ( alg );
    }
  }

  if(!digest) {
    if((digest = PKI_DIGEST_ALG_get_by_key(kp)) == NULL) {
      PKI_log_err("PKI_X509_CERT_new()::Can not get digest algor "
          "from key");
      return PKI_ERR;
    }
  }

  if( PKI_X509_sign(cert, digest, kp) == PKI_ERR) {
    PKI_log_err ("PKI_X509_CERT_new()::Can not sign certificate [%s]",
      ERR_error_string(ERR_get_error(), NULL ));
    return PKI_ERR;
  }

  return PKI_OK;
};

/*!
 * \brief Signs a PKI_X509_CERT by using a configured PKI_TOKEN
 */

int PKI_X509_CERT_sign_tk ( PKI_X509_CERT *cert, PKI_TOKEN *tk,
    PKI_DIGEST_ALG *digest) {

  PKI_X509_KEYPAIR *kp = NULL;

  if( !cert || !cert->value || !tk ) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return PKI_ERR;
  };

  if( PKI_TOKEN_login( tk ) == PKI_ERR ) {
    PKI_ERROR(PKI_ERR_HSM_LOGIN, NULL);
    return PKI_ERR;
  };

  if((kp = PKI_TOKEN_get_keypair( tk )) == NULL ) {
    return PKI_ERR;
  };

  return PKI_X509_CERT_sign ( cert, kp, digest );
};


/*! \brief Adds a specific extension to a certificate
 */

int PKI_X509_CERT_add_extension(PKI_X509_CERT *x, 
				const PKI_X509_EXTENSION *ext) {

  PKI_X509_CERT_VALUE *val = NULL;

  if( !x || !x->value || !ext || !ext->value ) return (PKI_ERR);

  val = x->value;

  if (!X509_add_ext(val, ext->value, -1)) return (PKI_ERR);

  return (PKI_OK);
}

/*! \brief Adds a stack of extensions to a certificate object
 */

int PKI_X509_CERT_add_extension_stack(PKI_X509_CERT *x, 
          			      const PKI_X509_EXTENSION_STACK *ext) {

  int i = 0;
  PKI_X509_EXTENSION *ossl_ext = NULL;

  if( !x || !x->value || !ext ) return (PKI_ERR);

  for( i = 0; i < PKI_STACK_X509_EXTENSION_elements(ext); i++ ) {
    
    ossl_ext = PKI_STACK_X509_EXTENSION_get_num( ext, i);
    if( !ossl_ext ) continue;

    if(!X509_add_ext ((X509 *) x->value, ossl_ext->value, -1 )) {
      PKI_log_err ( "Adding Extensions::%s", 
        ERR_error_string( ERR_get_error(), NULL ) );
      return ( PKI_ERR );
    };
  }

  return (PKI_OK);
}

/*! \brief Returns the size of the certificate public key
 */

int PKI_X509_CERT_get_keysize(const PKI_X509_CERT *x ) {

  const PKI_X509_KEYPAIR_VALUE *pkey = NULL;

  if (!x || !x->value) return (0);

  if ((pkey = PKI_X509_CERT_get_data(x, 
				     PKI_X509_DATA_KEYPAIR_VALUE)) == NULL) {
    return (0);
  }

  return PKI_X509_KEYPAIR_VALUE_get_size(pkey);
}


/*! \brief Returns a pointer to a specified data field in a certificate
 */

const void * PKI_X509_CERT_get_data(const PKI_X509_CERT * x,
				    PKI_X509_DATA         type) {

  const void *ret = NULL;
  LIBPKI_X509_CERT *tmp_x = NULL;

  if (!x || !x->value) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return (NULL);
  }

  tmp_x = x->value;

  switch (type)
  {
    case PKI_X509_DATA_VERSION:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->cert_info) ret = (tmp_x)->cert_info->version;
#else
      ret = (tmp_x)->cert_info.version;
#endif
      break;

    case PKI_X509_DATA_SERIAL:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->cert_info) ret = tmp_x->cert_info->serialNumber;
#else
      ret = &((tmp_x)->cert_info.serialNumber);
#endif
      // ret = X509_get_serialNumber ( (X509 *) x->value );
      break;

    case PKI_X509_DATA_SUBJECT:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->cert_info) ret = tmp_x->cert_info->subject;
#else
      ret = tmp_x->cert_info.subject;
#endif
      // ret = X509_get_subject_name( (X509 *) x->value );
      break;

    case PKI_X509_DATA_ISSUER:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->cert_info) ret = tmp_x->cert_info->issuer;
#else
      ret = tmp_x->cert_info.issuer;
#endif
      // ret = X509_get_issuer_name( (X509 *) x->value );
      break;

    case PKI_X509_DATA_NOTBEFORE:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      ret = tmp_x->cert_info->validity->notBefore;
#else
      ret = X509_get0_notBefore((X509 *)x->value);
#endif
      break;

    case PKI_X509_DATA_NOTAFTER:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      ret = tmp_x->cert_info->validity->notAfter;
#else
      ret = X509_get0_notAfter((X509 *)x->value);
#endif
      break;

    case PKI_X509_DATA_KEYPAIR_VALUE:
    case PKI_X509_DATA_PUBKEY:
      ret = X509_get_pubkey( (X509 *) x->value);
      break;

    case PKI_X509_DATA_PUBKEY_BITSTRING:
      ret = X509_get0_pubkey_bitstr((X509 *)x->value);
      break;

    case PKI_X509_DATA_SIGNATURE:
      ret = &(tmp_x)->signature;
      break;

    // Signature Algorithm within the certInfo structure
    case PKI_X509_DATA_ALGORITHM:
    case PKI_X509_DATA_SIGNATURE_ALG1:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->cert_info && tmp_x->cert_info->signature)
        ret = tmp_x->cert_info->signature;
#else
	ret = X509_get0_tbs_sigalg((const X509 *)x->value);
#endif
      break;

    case PKI_X509_DATA_SIGNATURE_ALG2:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (tmp_x->sig_alg) ret = tmp_x->sig_alg;
#else
      ret = &tmp_x->sig_alg;
#endif
      break;

    case PKI_X509_DATA_KEYSIZE:
    case PKI_X509_DATA_CERT_TYPE:
      PKI_ERROR(PKI_ERR_PARAM_TYPE, "Deprecated Cert Datatype");
      break;

/*
    case PKI_X509_DATA_KEYSIZE:
      tmp_int = PKI_Malloc ( sizeof( int ));
      *tmp_int = EVP_PKEY_size(X509_get_pubkey((X509 *)x->value));
      ret = tmp_int;
      break;

    case PKI_X509_DATA_CERT_TYPE:
      tmp_int = PKI_Malloc ( sizeof ( int ));
      *tmp_int = PKI_X509_CERT_get_type( x );
      break;
*/

    case PKI_X509_DATA_EXTENSIONS:
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      ret = tmp_x->cert_info->extensions;
#else
      ret = tmp_x->cert_info.extensions;
#endif
      break;

    default:
      /* Not Recognized/Supported DATATYPE */
      return (NULL);
  }

  return (ret);
}


/* !\brief Returns the DER encoded toBeSigned part of the certificate
 * */

PKI_MEM * PKI_X509_CERT_get_der_tbs(const PKI_X509_CERT *x ) {

	PKI_MEM * mem = NULL;
	LIBPKI_X509_CERT * tmp_x = NULL;

	// Input Check
	if (!x || !x->value || x->type != PKI_DATATYPE_X509_CERT)
		return NULL;

	// Gets the internal value
	tmp_x = x->value;

	// Allocates the return object
      	if ((mem = PKI_MEM_new_null()) != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
		mem->size = (size_t) ASN1_item_i2d((void *)tmp_x->cert_info, 
        					   &(mem->data),
						   &X509_CINF_it);
#else
		mem->size = (size_t) ASN1_item_i2d((void *)&tmp_x->cert_info, 
        					   &(mem->data),
						   &X509_CINF_it);
#endif
	}

	return mem;
}

/*!
 * \brief Sets Data in a PKI_X509_CERT
 */

int PKI_X509_CERT_set_data(PKI_X509_CERT *x, int type, void *data) {

  long *aLong = NULL;
  PKI_TIME *aTime = NULL;
  PKI_INTEGER *aInt = NULL;
  PKI_X509_NAME *aName = NULL;
  PKI_X509_KEYPAIR_VALUE *aKey = NULL;

  int ret = 0;

  LIBPKI_X509_CERT *xVal = NULL;
  LIBPKI_X509_ALGOR *alg = NULL;
  // PKI_X509_CERT_VALUE *xVal = NULL;

  if ( !x || !x->value || !data || x->type != PKI_DATATYPE_X509_CERT) {
    PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    return (PKI_ERR);
  }

  // xVal = PKI_X509_get_value( x );
  xVal = x->value;

  switch( type ) {

    case PKI_X509_DATA_VERSION:
      aLong = (long *) data;
      ret = X509_set_version( xVal, *aLong );
      break;

    case PKI_X509_DATA_SERIAL:
      aInt = (PKI_INTEGER *) data;
      ret = X509_set_serialNumber( xVal, aInt);
      break;

    case PKI_X509_DATA_SUBJECT:
      aName = (PKI_X509_NAME *) data;
      ret = X509_set_subject_name( xVal, aName );
      break;

    case PKI_X509_DATA_ISSUER:
      aName = (PKI_X509_NAME *) data;
      ret = X509_set_issuer_name( xVal, aName );
      break;

    case PKI_X509_DATA_NOTBEFORE:
      aTime = (PKI_TIME *) data;
      ret = X509_set_notBefore( xVal, aTime );
      break;

    case PKI_X509_DATA_NOTAFTER:
      aTime = (PKI_TIME *) data;
      ret = X509_set_notAfter( xVal, aTime );
      break;

    case PKI_X509_DATA_KEYPAIR_VALUE:
      aKey = data;
      ret = X509_set_pubkey( xVal, aKey);
      break;

    case PKI_X509_DATA_ALGORITHM:
    case PKI_X509_DATA_SIGNATURE_ALG1:
      alg = data;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      if (xVal->cert_info != NULL)
        xVal->cert_info->signature = alg;
#else
      // Transfer Ownership
      xVal->cert_info.signature.algorithm = alg->algorithm;
      xVal->cert_info.signature.parameter = alg->parameter;

      // Remove the transfered data
      alg->algorithm = NULL;
      alg->parameter = NULL;

      // Free memory
      X509_ALGOR_free((X509_ALGOR *)data);
      data = NULL;

#endif
	// Ok
	ret = 1;
      break;

    case PKI_X509_DATA_SIGNATURE_ALG2:
      // if (xVal->sig_alg != NULL ) X509_ALGOR_free(xVal->sig_alg);
      alg = data;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
      xVal->sig_alg = alg;
#else
      // Transfer Ownership
      xVal->sig_alg.algorithm = alg->algorithm;
      xVal->sig_alg.parameter = alg->parameter;

      // Remove the transfered data
      alg->algorithm = NULL;
      alg->parameter = NULL;

      // Free memory
      X509_ALGOR_free((X509_ALGOR *)alg);
      data = NULL;

      // Ok
      ret = 1;

#endif
      break;

    default:
      /* Not Recognized/Supported DATATYPE */
      ret = 0;
      break;
  }

  if (!ret) return PKI_ERR;

  return PKI_OK;

}

/*! \brief Print the contents of a certificate in a text format to
 *         the file descriptor (fd)
 */

int PKI_X509_CERT_print_parsed(const PKI_X509_CERT *x, 
          		       PKI_X509_DATA type,
			       int fd ) {

  char * data = NULL;
  int ret = PKI_OK;

  if((data = PKI_X509_CERT_get_parsed( x, type )) == NULL ) {
    return (PKI_ERR);
  } else {
    if( fd == 0 ) fd = 2;
    if(write(fd, data, strlen( data )) == -1 ) {
      ret = PKI_ERR;
    } else {
      ret = PKI_OK;
    }
    PKI_Free( data );
  }

  return (ret);
}

/*! \brief Returns a parsed (char *) representation of the requested
 *         data type (type)
 */

char * PKI_X509_CERT_get_parsed(const PKI_X509_CERT *x,
				PKI_X509_DATA type ) {

  char *ret = NULL;

  PKI_X509_KEYPAIR *k = NULL;
  const PKI_X509_KEYPAIR_VALUE *pkey = NULL;


  if( !x ) return (NULL);

  switch( type ) {
    case PKI_X509_DATA_SERIAL:
      ret = PKI_INTEGER_get_parsed((PKI_INTEGER *) 
		      		   PKI_X509_CERT_get_data(x, type));
      break;

    case PKI_X509_DATA_SUBJECT:
    case PKI_X509_DATA_ISSUER:
      ret = PKI_X509_NAME_get_parsed((PKI_X509_NAME *) 
		      		     PKI_X509_CERT_get_data(x, type));
      break;

    case PKI_X509_DATA_NOTBEFORE:
    case PKI_X509_DATA_NOTAFTER:
      ret = PKI_TIME_get_parsed((PKI_TIME *)PKI_X509_CERT_get_data(x, type));
      break;

    case PKI_X509_DATA_ALGORITHM:
      ret = (char *) PKI_ALGOR_get_parsed((PKI_ALGOR *) 
		      			  PKI_X509_CERT_get_data(x,type));
      break;

    case PKI_X509_DATA_PUBKEY:
    case PKI_X509_DATA_KEYPAIR_VALUE:
      if ((pkey = PKI_X509_CERT_get_data(x, type)) != NULL) {
        k = PKI_X509_new_dup_value(PKI_DATATYPE_X509_KEYPAIR, pkey, NULL);
        ret = PKI_X509_KEYPAIR_get_parsed( k );
        PKI_X509_KEYPAIR_free(k);
      }
      break;

    case PKI_X509_DATA_KEYSIZE:
      PKI_ERROR(PKI_ERR_PARAM_TYPE, "Deprecated Cert Datatype");
      break;

    case PKI_X509_DATA_CERT_TYPE:
    case PKI_X509_DATA_SIGNATURE:
    case PKI_X509_DATA_EXTENSIONS:
    default:
      /* Not Recognized/Supported DATATYPE */
      return (NULL);
  }

  return (ret);
}

/*! \brief Returns the stack of URL for the CRL Distribution Point(s) */

PKI_STACK *PKI_X509_CERT_get_cdp (const PKI_X509_CERT *x) {

  STACK_OF(DIST_POINT) *sk_cdp = NULL;
        DIST_POINT *cdp = NULL;

        STACK_OF(CONF_VALUE) *sk_val = NULL;
        CONF_VALUE *v = NULL;

        PKI_STACK *ret = NULL;
  PKI_X509_CERT_VALUE *cert = NULL;

  char *tmp_s = NULL;

        int k = -1;
  int i = 0;

  if ( !x || !x->value ) return NULL;

  cert = (PKI_X509_CERT_VALUE *) x->value;

        if(( sk_cdp = X509_get_ext_d2i(cert, 
        NID_crl_distribution_points,
                                                NULL, NULL)) == NULL ) {
                return NULL;
        }

  /* Should we go through the whole stack ? Maybe, now we just
     take the first value... */
  if ( sk_DIST_POINT_num ( sk_cdp ) < 1 ) {
    return NULL;
  }

  for ( i = 0 ; i < sk_DIST_POINT_num ( sk_cdp ); i++ ) {

    cdp = sk_DIST_POINT_value ( sk_cdp, i );

    if( cdp->distpoint ) {
                  if(cdp->distpoint->type == 0) {
                          if( cdp->distpoint->name.fullname ) {
                                  sk_val = i2v_GENERAL_NAMES(NULL,
                                          cdp->distpoint->name.fullname,
                                                  sk_val);
                                k=0;
                                for( ;; ) {
                                        v = sk_CONF_VALUE_value( sk_val, k++ );
                                        if( v == NULL ) break;

                                        if( strncmp_nocase("URI",
                                                        v->name, 3) == 0 ) {
                                                PKI_log_debug( "INFO::Found "
              "CDP in cert %s:%s", 
              v->name, v->value );

            if (!ret) {
              ret = PKI_STACK_new_null ();
              if (!ret) return NULL;
            }

                                                tmp_s = strdup( v->value );
            PKI_STACK_push ( ret, tmp_s );
                                        }
                                }

        // sk_CONF_VALUE_free(sk_val);
                          }
                  } // else {
                   //        DIST_POINT_free( cdp );
                   //        sk_DIST_POINT_free( sk_cdp );
                   //}
          }
  }

        return ret;
}

/*! \brief Calculates the fingerprint over a certificate by using the
 *         passed digest algorithm identifier
 */

PKI_DIGEST *PKI_X509_CERT_fingerprint(const PKI_X509_CERT *x,
				      const PKI_DIGEST_ALG *alg ){

  PKI_DIGEST *ret = NULL;
  PKI_X509_CERT_VALUE *cert = NULL;

  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int ret_size = 0;

  /* Check that we have a valid certificate */
  if( !x || !x->value || x->type != PKI_DATATYPE_X509_CERT ) 
              return ( NULL );

  cert = (PKI_X509_CERT_VALUE *) x->value;

  /* If no Algorithm is provided, we use the default one */
  if( alg == NULL ) {
    alg = PKI_DIGEST_ALG_DEFAULT;
  }

  /* Calculate the Digest */
  if (!X509_digest(cert,alg,buf,&ret_size)) {
    /* ERROR */
    return ( NULL );
  }

  /* Allocate the return structure */
        if((ret = PKI_Malloc ( sizeof( PKI_DIGEST) )) == NULL ) {
                /* Memory Allocation Error! */
                return( NULL );
        }

        /* Allocate the buffer */
        if((ret->digest = PKI_Malloc ( ret_size )) == NULL ) {
                /* Memory Error */
                PKI_Free ( ret );
                return( NULL );
        }

        /* Set the size of the Digest */
        ret->size = ret_size;

        /* Copy the Digest Data */
        memcpy( ret->digest, buf, ret->size );

  /* Sets the algorithm used */
  ret->algor = alg;

  return ( ret );

}

/*! \brief Calculates the fingerprint over a certificate by using the
 *         passed digest string (char *) identifier
 */

PKI_DIGEST *PKI_X509_CERT_fingerprint_by_name(const PKI_X509_CERT *x,
					      const char *alg ) {

  PKI_DIGEST_ALG *alg_id = NULL;

  alg_id = PKI_DIGEST_ALG_get_by_name ( alg );

  return ( PKI_X509_CERT_fingerprint( x, alg_id ));
}

/*! \brief Calculates the Hash of the Public Key of the certificate */

PKI_DIGEST *PKI_X509_CERT_key_hash(const PKI_X509_CERT *x,
				   const PKI_DIGEST_ALG *alg ) {

  const PKI_X509_KEYPAIR_VALUE *key = NULL;
  PKI_DIGEST *keyHash = NULL;

  if ( !x || !x->value ) return NULL;

  if ( !alg ) alg = PKI_DIGEST_ALG_DEFAULT;

  if ((key = PKI_X509_CERT_get_data(x, PKI_X509_DATA_KEYPAIR_VALUE)) == NULL)
    return NULL;

  if ((keyHash = PKI_X509_KEYPAIR_VALUE_pub_digest(key, alg)) == NULL)
    return NULL;

  return keyHash;
}

/*! \brief Calculates the Hash of the Public Key of the certificate by using
 *         the hash algorithm passed as a (char *) */

PKI_DIGEST *PKI_X509_CERT_key_hash_by_name (const PKI_X509_CERT *x,
					    const char *alg ) {
  PKI_DIGEST_ALG *alg_id = NULL;

  alg_id = PKI_DIGEST_ALG_get_by_name ( alg );

  return PKI_X509_CERT_key_hash ( x, alg_id );
}


/*! \brief Returs PKI_X509_CERT_TYPE (an int) with the type of certificate */

PKI_X509_CERT_TYPE PKI_X509_CERT_get_type(const PKI_X509_CERT *x) {

  PKI_X509_CERT_TYPE ret = PKI_X509_CERT_TYPE_USER;
  const PKI_X509_NAME *subj = NULL;
  const PKI_X509_NAME *issuer = NULL;
  BASIC_CONSTRAINTS *bs = NULL;
  PKI_X509_EXTENSION *ext = NULL;

  if (!x || !x->value || (x->type != PKI_DATATYPE_X509_CERT) ) 
          return PKI_X509_CERT_TYPE_UNKNOWN;

  subj = PKI_X509_CERT_get_data ( x, PKI_X509_DATA_SUBJECT );
  issuer = PKI_X509_CERT_get_data ( x, PKI_X509_DATA_ISSUER );

  if ( subj && issuer ) {
    if ( PKI_X509_NAME_cmp( subj, issuer ) == 0) {
      ret |= PKI_X509_CERT_TYPE_ROOT;
    }
  }

  if((ext = PKI_X509_CERT_get_extension_by_id ( x, 
          NID_basic_constraints)) != NULL ) {
    if(( bs = ext->value )) {
      if ( bs->ca ) ret |= PKI_X509_CERT_TYPE_CA;
      BASIC_CONSTRAINTS_free ( bs );
    }
    PKI_X509_EXTENSION_free ( ext );
  }

  if((ext = PKI_X509_CERT_get_extension_by_id ( x, 
          NID_proxyCertInfo )) != NULL ) {
    if ( ret & PKI_X509_CERT_TYPE_CA ) {
      PKI_log_err ( "Certificate Error, Proxy Cert info set",
              "in a CA certificate!");
    } else {
      ret |= PKI_X509_CERT_TYPE_PROXY;
    }

    PKI_X509_EXTENSION_free ( ext );
  }

  return ret;
  
}

/*! \brief Returns PKI_OK if a certificate is self-signed, PKI_ERR otherwise */

int PKI_X509_CERT_is_selfsigned(const PKI_X509_CERT *x ) {

  PKI_X509_KEYPAIR *kp = NULL;
  const PKI_X509_KEYPAIR *kval = NULL;
  int ret = -1;

  if (!x) return PKI_ERR;

  kval = PKI_X509_CERT_get_data ( x, PKI_X509_DATA_PUBKEY );
  if ( !kval ) return PKI_ERR;

  kp = PKI_X509_new_dup_value(PKI_DATATYPE_X509_KEYPAIR, kval, NULL);
  if ( !kp ) return PKI_ERR;

  ret = PKI_X509_verify ( x, kp );
  PKI_X509_KEYPAIR_free ( kp );
  
  return ret;
}


/*! \brief Returns PKI_OK if a certificate is allowed to sign certs */

int PKI_X509_CERT_is_ca(const PKI_X509_CERT *x) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return PKI_ERR;
}

/*! \brief Returns PKI_OK if a certificate is a Proxy Certificate */

int PKI_X509_CERT_is_proxy ( const PKI_X509_CERT *x ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return PKI_ERR;
}

/*! \brief Returns PKI_OK if a certificate is allowed to be used with the
           passed domain name */

int PKI_X509_CERT_check_domain ( const PKI_X509_CERT *x, const char *domain ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return PKI_ERR;
}

/*! \brief Returns the list of subject's email addresses embedded in the cert */

PKI_STACK * PKI_X509_CERT_get_email (const PKI_X509_CERT *x ) {

  PKI_STACK *sk = NULL;
  PKI_X509_NAME_RDN **list = NULL;
  const PKI_X509_NAME *name = NULL;

  // PKI_X509_EXTENSION_STACK * ext_list = NULL;

  PKI_X509_EXTENSION * ext = NULL;

  if(!x || !x->value) return NULL;

  if((sk = PKI_STACK_new_null()) == NULL)
    return NULL;

  name = PKI_X509_CERT_get_data(x, PKI_X509_DATA_SUBJECT);

  // Maybe we find something in the DN...
  if(name) {

    int curr = 0;

    PKI_X509_NAME_RDN *el = NULL;
    list = PKI_X509_NAME_get_list(name, PKI_X509_NAME_TYPE_EMAIL);
    
    for(curr = 0; el != NULL; curr++ ) {
      el = list[curr];
      PKI_STACK_push( sk, PKI_X509_NAME_RDN_value(el));
    }
  }
  
  if((ext = PKI_X509_CERT_get_extension_by_name(x, 
                                         "subjectAltName")) != NULL) {
      PKI_log_debug("Got subjectAltName: Code Still Missing!");
  }

  PKI_log_debug("Code still missing!");
  return sk;
}

PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_id(const PKI_X509_CERT  *x, 
                				       PKI_ID num ) {
  PKI_OID *oid = NULL;

  oid = PKI_OID_new_id ( num );

  if( !x || !oid ) return NULL;

  return PKI_X509_CERT_get_extension_by_oid ( x, oid );
}

PKI_X509_EXTENSION * PKI_X509_CERT_get_extension_by_name(const PKI_X509_CERT *x,
                					 const char * name ) {

  PKI_OID *oid = NULL;

  if ( !x || !name ) return NULL;

  if ((oid = PKI_OID_new_text(name)) == NULL ) return NULL;

  return PKI_X509_CERT_get_extension_by_oid ( x, oid );
}


PKI_X509_EXTENSION *PKI_X509_CERT_get_extension_by_oid(const PKI_X509_CERT  *x, 
                				       const PKI_OID *id ) {
  PKI_ID nid = PKI_ID_UNKNOWN;
  PKI_X509_EXTENSION *ext = NULL;

  if ( !x || !id ) return NULL;

  if((nid = PKI_OID_get_id ( id )) == PKI_ID_UNKNOWN ) {
    return NULL;
  }

  if(( ext = PKI_X509_EXTENSION_new()) == NULL ) {
    return NULL;
  }

  if((ext->value = X509_get_ext_d2i ( x->value, nid, 
            NULL, NULL )) == NULL ) {
    PKI_X509_EXTENSION_free ( ext );
    return ( NULL );
  }
  
  return ext;
}

PKI_X509_EXTENSION_STACK *PKI_X509_CERT_get_extensions(const PKI_X509_CERT *x) {

  PKI_X509_EXTENSION_STACK *ret = NULL;

  int i = 0;
  int ext_count = 0;

  if (!x) return NULL;

  if ((ext_count = X509_get_ext_count (x->value)) <= 0 ) return NULL;

  for ( i=0; i < ext_count; i++ ) {
    LIBPKI_X509_EXTENSION *ext = NULL;
    // PKI_X509_EXTENSION_VALUE *ext = NULL;
    PKI_X509_EXTENSION *pki_ext = NULL;
    
    if((ext = X509_get_ext ( x->value, i )) == NULL ) {
      continue;
    }

    if((pki_ext = PKI_X509_EXTENSION_new()) == NULL ) {
      PKI_log_err ( "Memory Allocation");
      continue;
    }

    if( ext->object == NULL ) {
      PKI_X509_EXTENSION_free ( pki_ext );
      continue;
    }

    pki_ext->oid = PKI_OID_dup ( ext->object );
    pki_ext->critical = ext->critical;

    if((pki_ext->value = X509V3_EXT_d2i ( ext )) == NULL ) {
      PKI_log_debug( "Extension %d -- not parsable", i);
      PKI_X509_EXTENSION_free ( pki_ext );
      continue;
    }
  }

  return ret;
}

int PKI_X509_CERT_check_pubkey(const PKI_X509_CERT *x, 
			       const PKI_X509_KEYPAIR *k)
{
  // Input checks
  if (!x || !x->value || !k || !k->value) return -2;

  // Checks that the private key corresponds to the public key in
  // the certificate. The '1' value corresponds to success in the
  // OpenSSL library. We return the '0' for success instead.
  if (X509_check_private_key(x->value, k->value) != 1) return -1;
  else return 0;

}
