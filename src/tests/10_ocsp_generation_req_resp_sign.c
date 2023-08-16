
#include <libpki/pki.h>

// ==============
// Global Defines
// ==============

#define test_name "Test Ten (10) - OCSP Generation, Request and Response Sign"
#define log_name  "results/10-ocsp-generation-req-resp-sign.log"

// ===================
// Function Prototypes
// ===================

/* Function Prototypes */
int subtest1();
int subtest2();

// ====
// Main
// ====

int main (int argc, char *argv[] ) {

	// Changes the current directory to be the working
	// main directory to make sure all file paths are correct
	chdir("../..");

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if ((PKI_log_init(PKI_LOG_TYPE_STDERR,
					  PKI_LOG_ALWAYS,
					  log_name,
					  PKI_LOG_FLAGS_ENABLE_DEBUG,
					  NULL)) == PKI_ERR ) {
		fprintf(stderr, "ERROR: cannot initialize the log file!\n");
		exit(1);
	}

	// Info
	PKI_log(PKI_LOG_INFO, "===== %s Test Begin =====", test_name);

	// SubTests Execution
	int success = (
		subtest1()
		&& subtest2()
	);

	// Info
	if (success) {
		PKI_log(PKI_LOG_INFO, "===== %s: Passed Successfully =====", test_name);
	} else {
		PKI_log(PKI_LOG_INFO, "===== %s: Failed =====", test_name);
	}

	// Terminates the logging subsystem
	PKI_log_end();

	// Error Condition
	if (!success) return 1;

	// Success
	return 0;
}

int subtest1() {

	PKI_X509_OCSP_REQ * req = NULL;
	PKI_X509_CERT * x_cert = NULL;
	PKI_X509_CERT * x_issuer = NULL;

	PKI_log(PKI_LOG_ALWAYS, "[ Subtest 1 ] OCSP Request Generation - Begin");

	// Loads the certificates
	x_cert = PKI_X509_get("etc/certs.d/tests/ee_client_certificate.pem", PKI_DATATYPE_X509_CERT, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
	if (!x_cert) {
		PKI_log_err("ERROR::Cannot load the certificate from file %s", "etc/certs.d/tests/ee_client_certificate.pem");
		return 0;
	}

	x_issuer = PKI_X509_get("etc/certs.d/tests/ica_certificate.pem", PKI_DATATYPE_X509_CERT, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
	if (!x_issuer) {
		PKI_log_err("ERROR::Cannot load the certificate from file %s", "etc/certs.d/tests/ica_certificate.pem");
		return 0;
	}

	if ((req = PKI_X509_OCSP_REQ_new()) == NULL) {
		PKI_log_err("ERROR::Cannot generate a new OCSP request.\n\n");
		return 0;
	}

	if (PKI_ERR == PKI_X509_OCSP_REQ_add_cert(req, x_cert, x_issuer, (PKI_DIGEST_ALG *)EVP_sha256())) {
		PKI_log_err("ERROR::Cannot add the certificate to the OCSP request.\n\n");
		return 0;
	}

	if (PKI_ERR == PKI_X509_OCSP_REQ_add_nonce(req, 16)) {
		PKI_log_err("ERROR::Cannot add the nonce to the OCSP request.\n\n");
		return 0;
	}

	// Saves the OCSP request
	if (PKI_OK != PKI_X509_OCSP_REQ_put(req, PKI_DATA_FORMAT_PEM, "results/ocsp-req.pem", NULL, NULL, NULL)) {
		PKI_log_err("ERROR::Cannot save the OCSP request.\n\n");
		return 0;
	}

	PKI_log(PKI_LOG_ALWAYS, "[ Subtest 1 ] OCSP Request Generation - Passed.");


	return 1;
}

int subtest2() {

	PKI_log(PKI_LOG_ALWAYS, "[ Subtest 2 ] OCSP Response Generation - Begin");

	PKI_TOKEN * tk = NULL;
		// Signing token for response

	tk = PKI_TOKEN_new("etc", "tests-intermediate-ca");
	if (!tk) {
		PKI_log_err("ERROR::Cannot load the token from file %s", "etc/tokens/test-root-ca");
		return 0;
	}

	if (PKI_ERR == PKI_TOKEN_login(tk)) {
		PKI_log_err("ERROR::Cannot login into the token.\n\n");
		return 0;
	};

	PKI_X509_OCSP_RESP * resp = PKI_X509_OCSP_RESP_new();
	if (!resp) {
		if (tk) PKI_TOKEN_free(tk);
		return 0;
	}
	PKI_X509_OCSP_REQ * req = PKI_X509_get("results/ocsp-req.pem", PKI_DATATYPE_X509_OCSP_REQ, PKI_DATA_FORMAT_PEM, NULL, NULL);
	if (!req) {
		if (tk) PKI_TOKEN_free(tk);
		if (resp) PKI_X509_free(resp);
		return 0;
	}

	PKI_X509_OCSP_RESP_VALUE * r_value = PKI_X509_get_value(resp);
	if (!r_value || !r_value->bs) {
		PKI_log_err("Internal Pointer Error");
		return 0;
	}

	// OCSP_BASICRESP * basic_resp = r_value->bs;

	PKI_X509_KEYPAIR * c_keypair = PKI_TOKEN_get_keypair(tk);
	PKI_X509_CERT * c_subject = PKI_TOKEN_get_cert(tk);
	PKI_X509_CERT * c_issuer = PKI_TOKEN_get_cacert(tk);

	// PKI_X509_KEYPAIR_VALUE * c_keypair_ossl = PKI_X509_get_value(c_keypair);
	// PKI_X509_CERT_VALUE * c_subject_ossl = PKI_X509_get_value(c_subject);
	// // PKI_X509_CERT_VALUE * c_issuer_ossl = PKI_X509_get_value(c_issuer);

	PKI_TIME * thisUpdate = PKI_TIME_new(0);
	PKI_TIME * nextUpdate = PKI_TIME_new(PKI_VALIDITY_ONE_MONTH);

	// PKI_X509_OCSP_RESP_set_keytype_by_cert(resp, c_subject);

	int n_requests = PKI_X509_OCSP_REQ_elements(req);
	for (int i = 0; i < n_requests; i++) {
		
		OCSP_CERTID * cid = PKI_X509_OCSP_REQ_get_cid(req, i);
		PKI_INTEGER * serial = PKI_X509_OCSP_REQ_get_serial(req, i);

		if (!cid || !serial) {
			PKI_log_err("ERROR::Cannot get the serial number or the certificate ID from the request.");
			return 0;
		}
		
		// Debugging Info
		char * serial_s = PKI_INTEGER_get_parsed(serial);
		PKI_DEBUG("CID: Got Cert Serial Number => %s", serial_s);
		PKI_Free(serial_s);

		PKI_STRING * name = PKI_OCSP_CERTID_get_issuerNameHash(cid);
		PKI_STRING * key_id = PKI_OCSP_CERTID_get_issuerKeyHash(cid);
		PKI_INTEGER * serial_num = PKI_OCSP_CERTID_get_serialNumber(cid);
		const PKI_DIGEST_ALG * hash_alg = PKI_OCSP_CERTID_get_hashAlgorithm(cid);

		// Debugging Information
		PKI_DEBUG("CID: Details => serial (%s), hash (%s), name (%s), key (%s)", 
			PKI_INTEGER_get_parsed(serial_num), 
			PKI_DIGEST_ALG_get_parsed(hash_alg),
			PKI_STRING_get_parsed(key_id), 
			PKI_STRING_get_parsed(name)
		);

		if (PKI_ERR == PKI_X509_OCSP_RESP_add(resp, cid, PKI_OCSP_CERTSTATUS_GOOD, NULL, thisUpdate, nextUpdate, 0, NULL)) {
			PKI_log_err("ERROR::Cannot add the basic response for the certificate to the response.\n\n");
			return 0;
		}
	}

	if (PKI_X509_OCSP_REQ_has_nonce(req))	{
		if (PKI_X509_OCSP_RESP_copy_nonce(resp, req) == PKI_ERR) {
			if (req) PKI_X509_OCSP_REQ_free(req);
			if (resp) PKI_X509_free(resp);
			if (tk) PKI_TOKEN_free(tk);
			PKI_log_err("ERROR::Cannot copy the nonce from the request to the response.\n\n");
			return 0;
		}
	}

	// PKI_X509_OCSP_RESP_set_keytype_by_cert(resp, c_subject);

	// PKI_OCSP_CERTID * cid = OCSP_cert_to_id(EVP_sha1(), c_subject_ossl, c_issuer_ossl );
	// if (!cid) {
	// 	PKI_log_err("ERROR::Cannot create the certificate ID for the response.");
	// 	return 0;
	// }

	// if (!OCSP_basic_add1_status(r_value->bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL,thisUpdate, NULL)) {
	// 	PKI_log_err("ERROR::Cannot add the basic response for the certificate to the response.");
	// 	return 0;
	// }


	// if (!OCSP_basic_sign(r_value->bs, c_subject_ossl, c_keypair_ossl, EVP_sha256(), NULL, OCSP_NOCERTS | OCSP_RESPID_KEY)) {
	// 	PKI_DEBUG("ERROR::Cannot sign the basic response for the certificate to the response.");
	// 	return 0;
	// }

	// if (PKI_OK != PKI_X509_OCSP_RESP_sign_tk(resp,
	// 										 tk,
	// 										 PKI_DIGEST_ALG_DEFAULT,
	// 										 PKI_X509_OCSP_RESPID_TYPE_BY_KEYID)) {
	// 	PKI_log_err("Error while signing the response\n\n");
	// 	return 0;
	// }

	// if (PKI_OK != PKI_X509_OCSP_RESP_sign(resp,
	// 									  tk->keypair,
	// 									  tk->cert,
	// 									  tk->cacert,
	// 									  tk->otherCerts,
	// 									  PKI_DIGEST_ALG_DEFAULT,
	// 									  PKI_X509_OCSP_RESPID_TYPE_BY_KEYID)) {
	// 	PKI_log_err("Error while signing the response\n\n");
	// 	return 0;
	// }

	if (PKI_OK != PKI_X509_OCSP_RESP_sign(resp,
										  c_keypair,
										  c_subject,
										  c_issuer,
										  NULL,
										  PKI_DIGEST_ALG_DEFAULT,
										  PKI_X509_OCSP_RESPID_TYPE_BY_KEYID)) {
		PKI_log_err("Error while signing the response\n\n");
		return 0;
	}

	BIO * bio = BIO_new_file("results/ocsp-resp.der", "w");
	if (!i2d_PKI_X509_OCSP_RESP_VALUE_bio(bio, r_value)) {
		PKI_log_err("ERROR::Cannot write the response to the file.");
		return 0;
	}
	BIO_free_all(bio);
	bio = NULL;

	if (thisUpdate) PKI_TIME_free(thisUpdate);
	if (nextUpdate) PKI_TIME_free(nextUpdate);

	if (req) PKI_X509_free(req);
	if (resp) PKI_X509_free(resp);
	if (tk) PKI_TOKEN_free(tk);

	PKI_log(PKI_LOG_ALWAYS, "[ Subtest 2 ] OCSP Response Generation - Passed");

	return 1;
}

