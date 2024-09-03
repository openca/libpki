## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

if ENABLE_OPENSSL
OSSL_SUBDIRS = openssl
OSSL_SOFTWARE_OBJ = openssl/libpki-hsm-openssl.la
else
OSSL_SUBDIRS =
OSSL_SOFTWARE_OBJ =
endif

if ENABLE_WOLFSSL
# HSM_SOFTWARE = wolfssl
# HSM_SOFTWARE_OBJ = $(top_builddir)/src/drivers/wolfssl/libpki-token-wolfssl.la
WOLFSSL_SUBDIRS = wolfssl
WOLFSSL_SOFTWARE_OBJ = wolfssl/libpki-hsm-wolfssl.la
else
WOLFSSL_SUBDIRS =
WOLFSSL_SOFTWARE_OBJ =
endif

if ENABLE_PKCS11
PKCS11_SUBDIRS = pkcs11
PKCS11_SOFTWARE_OBJ = pkcs11/libpki-hsm-pkcs11.la
else
PKCS11_SUBDIRS =
PKCS11_SOFTWARE_OBJ =
endif

HSMS = $(OSSL_SOFTWARE_OBJ) $(WOLFSSL_SOFTWARE_OBJ) $(PKCS11_SOFTWARE_OBJ)
OBJECTS = $(HSM_SOFTWARE_OBJ) $(HSM_PKCS11_OBJ)

SUBDIRS = $(OSSL_SUBDIRS) $(WOLFSSL_SUBDIRS) $(PKCS11_SUBDIRS) .

AM_CPPFLAGS = -I$(TOP)

SRCS = \
	hsm_main.c \
	hsm_slot.c \
	hsm_keypair.c


noinst_LTLIBRARIES = libpki-hsm.la

libpki_hsm_la_SOURCES = $(SRCS)
libpki_hsm_la_CFLAGS  = $(BUILD_LIBPKI_CFLAGS)
libpki_hsm_la_LIBADD  = $(OBJECTS)

