## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

MYSCEP = \
	pki_x509_scep_attr.c \
	pki_x509_scep_data.c \
	pki_x509_scep_asn1.c \
	pki_x509_scep_msg.c

INCLUDES = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

# bin_PROGRAMS = scep
# scep_SOURCES = $(MYSCEP) scep.c
# scep_LDADD   = $(OPENSSL_LIBS)
# scep_CFLAGS  = $(BUILD_LIBPKI_CFLAGS)


noinst_LTLIBRARIES = libpki-scep.la
libpki_scep_la_SOURCES = $(MYSCEP)
libpki_scep_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

