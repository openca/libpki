# libpki Makefile
# © 1999-2006 by Massimiliano Pala and OpenCA Project
# OpenCA Licensed Software

PACKAGE_NAME		= @PACKAGE_NAME@
PACKAGE_VERSION		= @PACKAGE_VERSION@
VERSION				= @PACKAGE_VERSION@
RC					= @RC@

ARCH_TARGET			= @arch_target@
MYARCH				= @myarch@

#-------- installation paths: --------

srcdir			= @srcdir@
top_srcdir		= @top_srcdir@

DEST_BINDIR		= @bindir@
DEST_DATADIR	= @datadir@
DEST_INFODIR	= @infodir@
DEST_LIBDIR		= @libdir@
DEST_MANDIR		= @mandir@
DEST_SBINDIR	= @sbindir@
DEST_INCLUDES	= @includesdir@
SHLEXT			= @shlext@

#-------- --------

## HAVE_SHARED_LIBS	= @HAVE_SHARED_LIBS@
POD2MAN			= @POD2MAN@

#-------- user and group for installation: --------

openssl_prefix		= @openssl_prefix@
openssl_path		= @openssl_path@
openssl_libs		= @openssl_libs@
openssl_cflags		= @openssl_cflags@
openssl_static_libs	= @openssl_static_libs@

OPENSSL				= @OPENSSL@

PTHREAD_MYDEFS		= @PTHREAD_MYDEFS@

ACLOCAL_AMFLAGS = -I m4

#AUTOMAKE_OPTIONS = no-dependencies
SUBDIRS = src docs etc .

AUX_DIST = \
 	acinclude.m4 \
 	aclocal.m4 \
 	$(ac_aux_dir)/config.guess \
 	$(ac_aux_dir)/config.sub \
 	$(ac_aux_dir)/install-sh \
	$(ac_aux_dir)/ltmain.sh \
	$(ac_aux_dir)/mkinstalldirs \
	$(ac_aux_dir)/missing \
	$(ac_aux_dir)/depcomp

M4_EXTRA = \
	m4/*.m4

EXTRA_SCRIPTS = 

EXTRA_EXAMPLES = examples/profiles/* examples/crl/* examples/prqp/* examples/prqp/certs/* examples/token/* examples/token/etc/* examples/token/etc/profile.d/*  examples/token/etc/token.d/* examples/token/etc/hsm.d/*

INCLUDE_DIST = \
		README \
		README.OPENSOLARIS \
		README.SOLARIS_10 \
		README.SOLARIS_9 \
		ChangeLog

EXTRA_DIST = $(EXTRA_SCRIPTS) $(AUX_DIST) $(INCLUDE_DIST) \
	$(EXTRA_EXAMPLES) contrib

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 acinclude.m4 configure \
	$(AUX_DIST)

# pkgconfig_DATA  = contrib/libpki.pc contrib/openldap.pc
# pkgconfigdir    = @libdir@/pkgconfig

# TESTS_ENVIRONMENT = \
# 	LD_LIBRARY_PATH="@openssl_prefix@/lib:$$LD_LIBRARY_PATH"

TESTS = src/tests/test1 \
 	src/tests/test2 \
 	src/tests/test3 \
 	src/tests/test4 \
 	src/tests/test5 \
 	src/tests/test6 \
 	src/tests/test7 \
 	src/tests/test8 \
	src/tests/test9

rebuild::
	autoheader && aclocal && automake && autoconf

config::
	./configure --prefix=/usr/local/libpki

check:

tests::
	@$(mkinstalldirs) results
	@$(MAKE) check

help::
	@cat contrib/build-help.txt

install-data-local:
	@$(NORMAL_INSTALL) ; \
        $(mkinstalldirs) ${prefix}/include; \
        for file in src/install/* ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DEST_DATADIR)/libpki; \
            fi \
          done 
	@$(mkinstalldirs) $(etc_prefix)

# install-data-hook:
# 	@libfile="${prefix}/lib/libpki.$(SHLEXT)" ; \
#         if ! [ -e "$$libfile" ] ; then \
# 		target="${prefix}/lib/libpki.$(SHLEXT)" ; \
# 		file=`find ${prefix}/lib -name 'libpki*$(PKGVER)*$(SHLEXT)*'`; \
# 		$(LN_S) $$file $$target ; \
# 	else \
# 		echo "Def libfile exists ($$libfile)" ; \
# 	fi

docs:: hyperdocs

hyperdocs::
	@echo "Generating HTML and XML Docs ... "
	@if [ "$(DOXYGEN)" = "" ] ; then \
		echo "Doxygen Package not found!" ; \
	else \
		$(DOXYGEN) docs/doxygen/doxygen.conf ; \
		if ! [ "$(PDFLATEX)" = "" ] ; then \
			if [ -d "docs/latex" ] ; then \
				cd docs/latex ; \
				make ; \
			fi ; \
		fi ; \
	fi

pdfdocs::
	@echo "Generating PDF documentation (docs/latex/refman.pdf) ..."
	@if ! [ "$(DOXYGEN)" = "" ] ; then \
		$(DOXYGEN) docs/doxygen/doxygen-pdf.conf ; \
		if ! [ "$(PDFLATEX)" = "" ] ; then \
			if [ -d "docs/latex" ] ; then \
				cd docs/latex ; \
				make clean ; \
				$(PDFLATEX) refman.tex ; \
				makeindex refman.idx ; \
				$(PDFLATEX) refman.tex; \
			fi ; \
		fi ; \
	fi

man::

documentation:: pdfdocs
	@echo "Generating Manual Pages ... "
	@if [ "$(DOXYGEN)" = "" ] ; then \
		echo "Doxygen Package not found!" ; \
	else \
		rm -rf docs/man/mani*/* ; \
		$(DOXYGEN) docs/doxygen/doxygen-man.conf ; \
		if ! [ "$(MYARCH)" = "solaris" ] ; then \
			echo "Compressing man pages ... " ; \
			for i in docs/man/man*/* ; do \
				$(GZIP) $$i; \
			done ; \
		fi; \
	fi

distclean-local:
	@echo "Cleaning local autoconf cache... " ; \
	 rm -rf autom4te.cache/ contrib/libpki.spec .autotools .settings/ results

########################## BINARY DISTRO STUFF ###########################

MAKE=@MAKE@
MAKEFILE=Makefile
TODAY=`date +%Y%m%d`
# INSTALL_BUILDER = "$(HOME)/installbuilder-5.4.10/bin/builder"
INSTALL_BUILDER = @INSTALL_BUILDER@

snap:
	@$(MAKE) -f Makefile dist VERSION=SNAP-$(TODAY)

snaprpm: snap
	@$(MAKE) -f Makefile rpm VERSION="$(TODAY)" RC="snap"

rc1:
	$(MAKE) -f Makefile dist VERSION=$(VERSION)-rc1

rc1rpm: rc1
	$(MAKE) -f Makefile rpm RC="rc1"

rc2:
	$(MAKE) -f Makefile dist VERSION=$(VERSION)-rc2

rc2rpm: rc2
	$(MAKE) -f Makefile rpm RC="rc2"

rc3:
	$(MAKE) -f Makefile dist VERSION=$(VERSION)-rc3

rc3rpm: rc3
	$(MAKE) -f Makefile rpm RC="rc3"

pkgbuild:
	@rm -rf /tmp/$(PACKAGE_NAME)-build-$(VERSION)
	@DESTDIR=/tmp/$(PACKAGE_NAME)-build-$(VERSION) ./configure --prefix=/usr
	@$(MAKE) -f Makefile
	@$(MAKE) -f Makefile man
	@$(MAKE) DESTDIR=/tmp/$(PACKAGE_NAME)-build-$(VERSION) install
	@$(MAKE) -f Makefile pkgconfig

pkgconfig:
	@if [ "$(DIST_NAME)" = "darwin" ] ; then \
		IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		rm -rf $(PACKAGE_NAME)-*.app ; \
		$(INSTALL_BUILDER) build contrib/libpki-inst.xml && \
		hdiutil create -srcfolder "$$IB_OUTPUT" \
			-volname "$(PACKAGE_NAME) v$(VERSION) Install" \
			"$(PACKAGE_NAME)-$(VERSION)-$(RC)-osx-$(ARCH_TARGET).dmg" ; \
		rm -r $$IB_OUTPUT/$(PACKAGE_NAME)-*.app ; \
	else \
		ret=`echo ${build_os} | grep 'solaris'`; \
		if [ $$? -eq 0 ] ; then \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/* -name output` ; \
		else \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		fi ; \
		sudo $(INSTALL_BUILDER) build contrib/libpki-inst.xml && \
		$(SHELL) -c "cp -r $$IB_OUTPUT/$(PACKAGE_NAME)-* ." ; \
			$(SHELL) -c "sudo rm -f $$IB_OUTPUT/$(PACKAGE_NAME)-*" ; \
	fi

rpm:
	@echo
	@echo -n "Cleaning up old RPMs ... "
	@for i in $(PACKAGE_NAME)*.rpm ; do \
                rm -f $$i ; \
	done ; \
	echo "Done." \
	echo -n "Creating spec file ... " ; \
	filename="libpki.spec" ; \
	if [ -e "contrib/$$filename.orig" ] ; then \
		echo -n "($$filename.orig) --> "; \
		cat "contrib/$$filename.orig" | \
			sed -e "s/@RPM_VERSION@/$(VERSION)/g" | \
			sed -e "s/\@RC\@/$(RC)/g" | \
			sed -e "s/@PKGNAME@/$(PACKAGE_NAME)/g" | \
			sed -e "s/\@mybits\@/@mybits@/g" | \
			sed -e "s|@BUILDROOT@|/tmp/$(PACKAGE_NAME)-%{ver}-root|g" > \
			"contrib/libpki.spec" ; \
		echo "($$filename)"; \
	else \
		echo "contrib/$$filename ... not found" ; \
		exit 1 ; \
	fi ; \
	echo "Building source package... " ; \
	$(MAKE) -f $(MAKEFILE) dist ; \
	echo "Building RPM package(s)... " ; \
	sudo bash -c "rm -rf /usr/src/redhat/BUILD/$(PACKAGE_NAME)* \
		$(HOME)/rpmbuild/BUILD/$(PACKAGE_NAME)* ; \
		/root/rpmbuild/BUILD/$(PACKAGE_NAME)* " ; \
	sudo rpmbuild -ta $(PACKAGE_NAME)-$(VERSION).tar.gz ; \
	sudo bash -c " mv /usr/src/redhat/RPMS/*/$(PACKAGE_NAME)*.rpm . || \
		mv $(HOME)/tmp/rpm/RPMS/*/$(PACKAGE_NAME)*.rpm . || \
		mv $(HOME)/rpmbuild/RPMS/*/$(PACKAGE_NAME)*.rpm . || \
		mv /root/rpmbuild/RPMS/*/$(PACKAGE_NAME)*.rpm . " ; \
	sudo bash -c "mv /usr/src/redhat/SRPMS/$(PACKAGE_NAME)*.src.rpm . || \
		mv $(HOME)/tmp/rpm/SRPMS/$(PACKAGE_NAME)*.src.rpm . || \
		mv $(HOME)/rpmbuild/SRPMS/$(PACKAGE_NAME)*.src.rpm . || \
		mv /root/rpmbuild/SRPMS/$(PACKAGE_NAME)*.src.rpm . "; \
	echo


########################################################
##                END RELEASE STUFF                   ##
########################################################

########################################################
##                MINTENANCE TOOLS                    ##
########################################################

osslcompat:
	@for i in `find src/ -name '*.c'` ; do \
		$(GREP) "OPENSSL_VERSION_NUMBER" "$$i" >/dev/null ; \
		if [ $$? -eq 0 ] ; then \
			$(ECHO) "$$i" >> oss_version_files.txt ; \
		fi ; \
	 done

