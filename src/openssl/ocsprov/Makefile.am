## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2022 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

OPENSSL_INTERNAL_SRCS = 

nobase_include_HEADERS = \
	ocsprov_lcl.h \
	ocsprov_asn1.h \
	ocsprov_ctx.h \
	ocsprov.h

COMPOSITE_SRCS = \
	ocsprov_lcl.c \
	ocsprov_encoder.c \
	ocsprov_decoder.c \
	ocsprov_ctx.c \
	ocsprov_key.c \
	ocsprov.c \
	$(OPENSSL_INTERNAL_SRCS)

noinst_LTLIBRARIES = libpki-ocsprov.la

libpki_ocsprov_la_SOURCES = $(COMPOSITE_SRCS)
libpki_ocsprov_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

