/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_PKI_H
#define _LIBPKI_PKI_H

// ======================
// Internal Configuration
// ======================

#ifdef __LIB_BUILD__
#include <libpki/config.h>
#endif

#ifndef _LIBPKI_COMPAT_H
# include <libpki/compat.h>
#endif

#ifndef LIBPKI_VERSION_H
# include <libpki/libpkiv.h>
#endif

#ifndef _LIBPKI_ENABLED_FEATURES
# include <libpki/libpki_enables.h>
#endif

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

extern const long LIBPKI_OS_DETAILS;

// #include <libpki/pki_threads_vars.h>
// #include <libpki/pki_threads.h>
// #include <libpki/openssl/pthread_init.h>

// =================
// PKI Configuration
// =================

#ifndef _LIBPKI_CONF_H
#include <libpki/pki_config.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
# include <libpki/datatypes.h>
#endif

BEGIN_C_DECLS

#define PKI_NAMESPACE_PREFIX		"pki"
#define PKI_NAMESPACE_HREF		    "http://www.openca.org/openca/pki/1/0/0"

#define PKI_SUBSCRIBER_REQ_TYPE		"application/pki-subscriber-request"
#define PKI_SUBSCRIBER_RESP_TYPE	"application/pki-subscriber-response"
#define PKI_MANAGEMENT_REQ_TYPE		"application/pki-management-request"
#define PKI_MANAGEMENT_RESP_TYPE	"application/pki-management-response"

#ifdef HAVE_ENGINE
#define ENV_OPENCA_ENGINE		    "engine"
#define ENV_OPENCA_ENGINE_ID		"engine_id"
#define ENV_OPENCA_ENGINE_PRE		"engine_pre"
#define ENV_OPENCA_ENGINE_POST		"engine_post"
#endif

// ================
// General Includes
// ================

#include <libpki/pki_err.h>
#include <libpki/pki_cred.h>
#include <libpki/support.h>
#include <libpki/pki_mem.h>
#include <libpki/stack.h>

// ====================
// Networking Functions
// ====================

#include <libpki/pki_net.h>

#include <libpki/net/sock.h>
#include <libpki/net/ssl.h>
#include <libpki/net/pki_socket.h>
#include <libpki/net/url.h>
#include <libpki/net/http_s.h>
#include <libpki/net/ldap.h>
#include <libpki/net/dns.h>

/* General X509 object */
// #include <libpki/pki_x509_data_st.h>
#include <libpki/pki_x509.h>
#include <libpki/pki_x509_mime.h>

/* Forward declarations */
#define PKI_X509_CERT	PKI_X509
#define PKI_X509_REQ	PKI_X509

/* Libpki Includes */
#include <libpki/pki_time.h>
#include <libpki/pki_integer.h>
#include <libpki/pki_x509_profile.h>
#include <libpki/pki_x509_mem.h>
#include <libpki/pki_keyparams.h>
#include <libpki/pki_string.h>
#include <libpki/pki_init.h>
#include <libpki/pki_algor.h>
#include <libpki/pki_id.h>
#include <libpki/pki_oid.h>
#include <libpki/pki_digest.h>
#include <libpki/pki_hmac.h>
#include <libpki/pki_config.h>
#include <libpki/pki_keypair.h>
#include <libpki/pki_x509_attribute.h>
#include <libpki/pki_x509_signature.h>
#include <libpki/pki_x509_name.h>
#include <libpki/pki_x509_req.h>
#include <libpki/pki_x509_cert.h>
#include <libpki/pki_x509_crl.h>
#include <libpki/pki_x509_pkcs7.h>
#include <libpki/pki_x509_p12.h>
#include <libpki/pki_x509_cms.h>

#ifdef ENABLE_COMPOSITE
#include <libpki/openssl/pki_oid_defs.h>

#include <libpki/openssl/composite/composite_key.h>

#include <libpki/openssl/composite/composite_ctx.h>

#include <libpki/openssl/composite/composite_utils.h>

// #ifdef ENABLE_COMBINED
// #include <libpki/openssl/combined/combined_pmeth.h>
// #endif
#endif

/* OCSP support */

#include <libpki/pki_ocsp_req.h>
#include <libpki/pki_ocsp_resp.h>

/* HSM Support */
#include <libpki/drivers/hsm_keypair.h>
#include <libpki/drivers/hsm_main.h>
#include <libpki/drivers/hsm_slot.h>

/* Software HSM Support */
#include <libpki/drivers/openssl/openssl_hsm.h>
#include <libpki/drivers/openssl/openssl_hsm_pkey.h>
#include <libpki/drivers/openssl/openssl_hsm_obj.h>
#include <libpki/drivers/openssl/openssl_hsm_cb.h>

#ifdef HAVE_ENGINE /* ENGINE Support */
#include <openssl/engine.h>
#include <libpki/drivers/engine/engine_hsm.h>
#include <libpki/drivers/engine/engine_hsm_pkey.h>
#include <libpki/drivers/engine/engine_hsm_obj.h>
#endif

/* PKCS11 Support */
#include <libpki/drivers/pkcs11/rsa/cryptoki.h> /* Updated to pkcs11t */
#include <libpki/drivers/pkcs11/pkcs11_hsm.h>
#include <libpki/drivers/pkcs11/pkcs11_hsm_pkey.h>
#include <libpki/drivers/pkcs11/pkcs11_hsm_obj.h>
#include <libpki/drivers/pkcs11/pkcs11_utils.h>

/* Profile and Config support */
#include <libpki/profile.h>
#include <libpki/extensions.h>
#include <libpki/pki_x509_extension.h>

/* PKI_ID_INFO support */
#include <libpki/pki_id_info.h>

/* TOKEN interface */
#include <libpki/token_data.h>
#include <libpki/token_id.h>
#include <libpki/token.h>

/* Log Subsystem Support */
#include <libpki/pki_log.h>

/* DBMS support */
#ifdef __LIB_BUILD__
#include <libpki/net/pki_mysql.h>
#include <libpki/net/pki_pg.h>
#include <libpki/net/pkcs11.h>
#endif /* END of __LIB_BUILD__ */

/* EST Interface */
#include <libpki/est/est.h>

/* SCEP Interface */
#include <libpki/scep/scep.h>

/* CMC Interface */
#include <libpki/cmc.h>

// /* General PKI Messaging System */
// #include <libpki/pki_msg.h>
// #include <libpki/pki_msg_req.h>
// #include <libpki/pki_msg_resp.h>

// /* PRQP Support */
// #include <libpki/prqp/prqp.h>

// /* crossCertificatePair support */
// #include <libpki/pki_x509_xpair_asn1.h>
// #include <libpki/pki_x509_xpair.h>

/* I/O operations for PKIX objects */
#include <libpki/pki_io.h>

END_C_DECLS

#endif
