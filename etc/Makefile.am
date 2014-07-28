## Process this file with automake to produce Makefile.in

TOP=../src
include $(TOP)/global-vars

PROFILES = \
	profile.d/*.xml

TOKENS = \
	token.d/*.xml

HSMS = \
	hsm.d/*.xml

STORES = \
	store.d/*.xml

CONFIGS = \
	*.xml

PKI_CONFIG = \
	pki.conf

EXTRA_DIST = $(PROFILES) $(TOKENS) $(HSMS) $(STORES) $(CONFIGS) $(PKI_CONFIG)

install-data-local:
	@$(NORMAL_INSTALL) ; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/etc/libpki; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/etc/libpki/hsm.d; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/etc/libpki/token.d; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/etc/libpki/store.d; \
        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/etc/libpki/profile.d; \
        for file in $(PROFILES) ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/etc/libpki/profile.d; \
            fi \
          done
	@for file in $(TOKENS) ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/etc/libpki/token.d; \
            fi \
          done
	@for file in $(HSMS) ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/etc/libpki/hsm.d; \
            fi \
          done
	@for file in $(STORES) ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/etc/libpki/store.d; \
            fi \
          done
	@for file in $(CONFIGS) ; do \
            if test -f $$file; then \
              $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/etc/libpki; \
            fi \
          done
	@$(INSTALL_DATA) $(PKI_CONFIG) $(DESTDIR)$(exec_prefix)/etc


