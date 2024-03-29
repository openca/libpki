## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

# Composite Support
if ENABLE_COMPOSITE
	COMPOSITE_SUBDIR = composite
	COMPOSITE_OBJ = composite/libpki-composite.la
else
	COMPOSITE_SUBDIR =
	COMPOSITE_OBJ =
endif

# OQS Support
if ENABLE_OQS
	PQC_SUBDIR = pqc
	PQC_OBJ = pqc/libpki-pqc.la
else
	PQC_SUBDIR =
	PQC_OBJ =
endif

OBJECTS = $(COMPOSITE_OBJ) $(PQC_OBJ)

SUBDIRS = $(COMPOSITE_SUBDIR) $(PQC_SUBDIR)

NOINST_SRCS = \
	internal/ossl_1_0_x/*.h \
	internal/ossl_1_1_0/*.h \
	internal/ossl_1_1_1/*.h \
	internal/x509_data_st.h \
	internal/ossl_lcl.h

OPENSSL_SRCS = \
	${NOINST_SRCS} \
	pthread_init.c \
	pki_id.c \
	pki_oid.c \
	pki_rand.c \
	pki_oid_defs.c \
	pki_algor.c \
	pki_digest.c \
	pki_hmac.c \
	pki_string.c \
	pki_time.c \
	pki_integer.c \
	pki_keypair.c \
	pki_keyparams.c \
	pki_x509_item.c \
	pki_x509_name.c \
	pki_x509_cert.c \
	pki_x509_crl.c \
	pki_x509_req.c \
	pki_x509_pkcs7.c \
	pki_x509_cms.c \
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
libpki_openssl_la_LIBADD = $(OBJECTS)

