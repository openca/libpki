## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2014 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
-include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	asn1.c \
	cms_cert_req.c \
	cms_simple.c

noinst_LTLIBRARIES = libpki-cms.la
libpki_cms_la_SOURCES = $(SRCS)
libpki_cms_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

