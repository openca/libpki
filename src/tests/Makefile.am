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
	test10 \
	test11 \
	test12 \
	test13 \
	test14 \
	test15

TESTS = $(check_PROGRAMS)

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

test10_SOURCES = test10.c
test10_LDFLAGS = $(testLDFLAGS)
test10_LDADD   = $(testLDADD)
test10_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

test11_SOURCES = test11.c
test11_LDFLAGS = $(testLDFLAGS)
test11_LDADD   = $(testLDADD)
test11_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

test12_SOURCES = test12.c
test12_LDFLAGS = $(testLDFLAGS)
test12_LDADD   = $(testLDADD)
test12_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

test13_SOURCES = test13.c
test13_LDFLAGS = $(testLDFLAGS)
test13_LDADD   = $(testLDADD)
test13_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

test14_SOURCES = test14.c
test14_LDFLAGS = $(testLDFLAGS)
test14_LDADD   = $(testLDADD)
test14_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

test15_SOURCES = test15.c
test15_LDFLAGS = $(testLDFLAGS)
test15_LDADD   = $(testLDADD)
test15_CFLAGS = -I$(TOP) $(LIBPKI_MYCFLAGS) -ggdb

