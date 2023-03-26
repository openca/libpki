## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2006 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..

LIBPKI_MYCFLAGS	= @libpki_cflags@

if STATIC_COMPILE
testLDFLAGS=@my_ldflags@ @rpath@
testLDADD=../libpki.la ../openssl/libpki-openssl.la
else
testLDFLAGS=@my_ldflags@ @rpath@
testLDADD=../libpki.la ../openssl/libpki-openssl.la
endif

SUBDIRS =

EXTRA_DIST =

check_PROGRAMS = \
	test1 \
	test2 \
	test3 \
	test4 \
	test5 \
	test6 \
	test7 \
	test8 \
	test9 \
	testA \
	testB

test1_SOURCES = test1.c
test1_LDFLAGS = $(testLDFLAGS)
test1_LDADD   = $(testLDADD)
test1_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test2_SOURCES = test2.c
test2_LDFLAGS = $(testLDFLAGS)
test2_LDADD   = $(testLDADD)
test2_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test3_SOURCES = test3.c
test3_LDFLAGS = $(testLDFLAGS)
test3_LDADD   = $(testLDADD)
test3_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test4_SOURCES = test4.c
test4_LDFLAGS = $(testLDFLAGS)
test4_LDADD   = $(testLDADD)
test4_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test5_SOURCES = test5.c
test5_LDFLAGS = $(testLDFLAGS)
test5_LDADD   = $(testLDADD)
test5_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test6_SOURCES = test6.c
test6_LDFLAGS = $(testLDFLAGS)
test6_LDADD   = $(testLDADD)
test6_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test7_SOURCES = test7.c
test7_LDFLAGS = $(testLDFLAGS)
test7_LDADD   = $(testLDADD)
test7_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test8_SOURCES = test8.c
test8_LDFLAGS = $(testLDFLAGS)
test8_LDADD   = $(testLDADD)
test8_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS)

test9_SOURCES = test9.c
test9_LDFLAGS = $(testLDFLAGS)
test9_LDADD   = $(testLDADD)
test9_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

testA_SOURCES = test10.c
testA_LDFLAGS = $(testLDFLAGS)
testA_LDADD   = $(testLDADD)
testA_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

testB_SOURCES = test11.c
testB_LDFLAGS = $(testLDFLAGS)
testB_LDADD   = $(testLDADD)
testB_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb