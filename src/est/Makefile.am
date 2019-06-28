## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

MYEST = \
	pki_x509_est_attr.c \
	pki_x509_est_data.c \
	pki_x509_est_asn1.c \
	pki_x509_est_msg.c

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

noinst_LTLIBRARIES = libpki-est.la
libpki_est_la_SOURCES = $(MYEST)
libpki_est_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

