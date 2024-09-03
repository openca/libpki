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
	asn1.c \
	cmc_cert_req.c \
	cmc_simple.c

noinst_LTLIBRARIES = libpki-cmc.la
libpki_cmc_la_SOURCES = $(SRCS)
libpki_cmc_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

