## Process this file with automake to produce Makefile.in

TOP=../src

etc_prefix = $(DESTDIR)${prefix}/etc
lib_prefix = $(DESTDIR)@libdir@
var_prefix = $(DESTDIR)${prefix}/var
doc_prefix = $(DESTDIR)$datadir/libpki

EXTRA_DIST = \
	README.data_structures \
	README.functions \
	doxygen/doxygen.conf \
	doxygen/doxygen-man.conf \
	doxygen/doxygen-pdf.conf \
	pkginfo

MANLEV=6

man_MANS = \
	man/man$(MANLEV)/*

install-man::
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/man
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV)
	@echo "Installing Man pages is $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV) ... "
	@for file in $(man_MANS) ; do \
	   if test -f $$file ; then \
		$(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV) ; \
	   fi ; \
	done
	@echo "Done. Add $(DESTDIR)$(exec_prefix)/share/man to MANPATH."

install-data-am: install-man
	@$(NORMAL_INSTALL) ; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/libpki; \
        for file in $(EXTRA_DIST) latex/refman.pdf; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/share/libpki; \
            fi \
          done

clean:
	@rm -rf man/man$(MANLEV)/* html xml latex

distclean-local:
	@rm -rf html xml latex
