## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2014 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	pki_keypair_io.c \
	pki_msg_resp_io.c \
	pki_ocsp_resp_io.c \
	pki_x509_crl_io.c \
	pki_x509_p12_io.c \
	pki_x509_req_io.c \
	pki_msg_req_io.c \
	pki_ocsp_req_io.c \
	pki_x509_cert_io.c \
	pki_x509_io.c \
	pki_x509_pkcs7_io.c \
	pki_x509_cms_io.c \
	pki_x509_xpair_io.c

noinst_LTLIBRARIES = libpki-io.la
libpki_io_la_SOURCES = $(SRCS)
libpki_io_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

