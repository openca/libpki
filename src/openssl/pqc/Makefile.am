## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = \
	-I$(TOP)          \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

OPENSSL_INTERNAL_SRCS = 

LIBPKI_INTERNAL_SRCS = \
	pqc_init.h               \
	pqc_tools.h              \
	pqc_pkey_meth.h          \
	pqc_asn1_meth.h          \
	pqc_local.h

nobase_include_HEADERS =

PQC_SRCS = \
	$(OPENSSL_INTERNAL_SRCS) \
	$(LIBPKI_INTERNAL_SRCS)  \
	pqc_tools.c              \
	pqc_asn1_meth.c 		 \
	pqc_pkey_meth.c          \
	pqc_init.c

noinst_LTLIBRARIES = libpki-pqc.la

libpki_pqc_la_SOURCES = $(PQC_SRCS)
libpki_pqc_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)
# libpki_composite_la_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)
# libpki_composite_la_LIBADD = $(BUILD_LIBPKI_LDADD)

