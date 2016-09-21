## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
-include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

OPENSSL_SRCS = \
	pthread_init.c \
	pki_id.c \
	pki_oid.c \
	pki_algor.c \
	pki_algorithm.c \
	pki_digest.c \
	pki_hmac.c \
	pki_string.c \
	pki_time.c \
	pki_integer.c \
	pki_keypair.c \
	pki_keyparams.c \
	pki_x509_name.c \
	pki_x509_cert.c \
	pki_x509_crl.c \
	pki_x509_req.c \
	pki_x509_pkcs7.c \
	pki_x509_p12.c \
	pki_x509_extension.c \
	pki_x509_signature.c \
	pki_x509_xpair.c \
	pki_x509_xpair_asn1.c \
	pki_ocsp_req.c \
	pki_ocsp_resp.c \
	pki_x509_attribute.c

noinst_LTLIBRARIES = libpki-openssl.la

libpki_openssl_la_SOURCES = $(OPENSSL_SRCS)
libpki_openssl_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)
# libpki_openssl_la_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)
# libpki_openssl_la_LIBADD = $(BUILD_LIBPKI_LDADD)

# libpki_token_a_LDFLAGS = -version-info 1:0:0

# $(OPENCA_INCLUDE_LIBS) \
#			$(openssl_cflags) $(openssl_libs)

#pki_token_a_LIBADD   = \
#			$(openssl_cflags) $(openssl_libs) \
#			$(libxml2_cflags) $(libxml2_libs) \
#			$(OPENCA_INCLUDE_LIBS)

