## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..

LIBPKI_MYCFLAGS	= @libpki_cflags@

if STATIC_COMPILE
testLDFLAGS=@my_ldflags@ @rpath@
testLDADD=../libpki.la ../openssl/libpki-openssl.la
else
testLDFLAGS=@my_ldflags@ @rpath@
testLDADD=../libpki.la ../openssl/libpki-openssl.la
endif

SUBDIRS =

EXTRA_DIST =

check_PROGRAMS = \
	1-key-gen-key-digest \
	2-cert-gen-digest-alg-list \
	3-token-generation-rsa-ec-dilithium-falcon \
	4-token-generation-request-self-sign-export-cert-req \
	5-token-init-load-profile \
	6-token-digest-crl-sign \
	7-url-file-https-ldap-mysql-pg-pkcs11 \
	8-log-interface \
	9-public-key-encryption-decryption \
	10-ocsp-generation-req-resp-sign \
	11-ameth-traditional-pqc-composite-explicit

TESTS = $(check_PROGRAMS)

1_key_gen_key_digest_SOURCES = 1_key_gen_key_digest.c
1_key_gen_key_digest_LDFLAGS = $(testLDFLAGS)
1_key_gen_key_digest_LDADD   = $(testLDADD)
1_key_gen_key_digest_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

2_cert_gen_digest_alg_list_SOURCES = 2_cert_gen_digest_alg_list.c
2_cert_gen_digest_alg_list_LDFLAGS = $(testLDFLAGS)
2_cert_gen_digest_alg_list_LDADD   = $(testLDADD)
2_cert_gen_digest_alg_list_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

3_token_generation_rsa_ec_dilithium_falcon_SOURCES = 3_token_generation_rsa_ec_dilithium_falcon.c
3_token_generation_rsa_ec_dilithium_falcon_LDFLAGS = $(testLDFLAGS)
3_token_generation_rsa_ec_dilithium_falcon_LDADD   = $(testLDADD)
3_token_generation_rsa_ec_dilithium_falcon_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

4_token_generation_request_self_sign_export_cert_req_SOURCES = 4_token_generation_request_self_sign.c
4_token_generation_request_self_sign_export_cert_req_LDFLAGS = $(testLDFLAGS)
4_token_generation_request_self_sign_export_cert_req_LDADD   = $(testLDADD)
4_token_generation_request_self_sign_export_cert_req_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

5_token_init_load_profile_SOURCES = 5_token_init_load_profile.c
5_token_init_load_profile_LDFLAGS = $(testLDFLAGS)
5_token_init_load_profile_LDADD   = $(testLDADD)
5_token_init_load_profile_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

6_token_digest_crl_sign_SOURCES = 6_token_digest_crl_sign.c
6_token_digest_crl_sign_LDFLAGS = $(testLDFLAGS)
6_token_digest_crl_sign_LDADD   = $(testLDADD)
6_token_digest_crl_sign_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

7_url_file_https_ldap_mysql_pg_pkcs11_SOURCES = 7_url_file_https_ldap_mysql_pg_pkcs11.c
7_url_file_https_ldap_mysql_pg_pkcs11_LDFLAGS = $(testLDFLAGS)
7_url_file_https_ldap_mysql_pg_pkcs11_LDADD   = $(testLDADD)
7_url_file_https_ldap_mysql_pg_pkcs11_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

8_log_interface_SOURCES = 8_log_interface.c
8_log_interface_LDFLAGS = $(testLDFLAGS)
8_log_interface_LDADD   = $(testLDADD)
8_log_interface_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

9_public_key_encryption_decryption_SOURCES = 9_public_key_encryption_decryption.c
9_public_key_encryption_decryption_LDFLAGS = $(testLDFLAGS)
9_public_key_encryption_decryption_LDADD   = $(testLDADD)
9_public_key_encryption_decryption_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

10_ocsp_generation_req_resp_sign_SOURCES = 10_ocsp_generation_req_resp_sign.c
10_ocsp_generation_req_resp_sign_LDFLAGS = $(testLDFLAGS)
10_ocsp_generation_req_resp_sign_LDADD   = $(testLDADD)
10_ocsp_generation_req_resp_sign_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

11_ameth_traditional_pqc_composite_explicit_SOURCES = 11_ameth_traditional_pqc_composite_explicit.c
11_ameth_traditional_pqc_composite_explicit_LDFLAGS = $(testLDFLAGS)
11_ameth_traditional_pqc_composite_explicit_LDADD   = $(testLDADD)
11_ameth_traditional_pqc_composite_explicit_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -O0 -ggdb

