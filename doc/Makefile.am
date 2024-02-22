dist_man_MANS = pound.8 poundctl.8 poundctl.tmpl.5
info_TEXINFOS = pound.texi
pound_TEXINFOS = metrics.texi strftime.texi fdl.texi

GENDOCS = perl gendocs.pl
EXTRA_DIST = gendocs.pl otherdoc.texi.in

if COND_MAKEINFO_INIT_FILE
  MAKEINFO_INIT_FILE_FLAG = --init-file=$(MAKEINFO_INIT_FILE)
endif

# Make sure you set TEXINPUTS.
# TEXINPUTS=/usr/share/texmf/pdftex/plain/misc/ is ok for most distributions
.PHONY: manual
manual:
	rm -rf manual
	TEXINPUTS=$(srcdir):$(top_srcdir)/build-aux:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS)" \
	 $(GENDOCS) -C manual -o otherdoc.texi $(PACKAGE) otherdoc.texi.in
	$(MAKEINFO) $(AM_MAKEINFOFLAGS) $(MAKEINFOFLAGS) -DWEBDOC \
	   --html $(MAKEINFO_INIT_FILE_FLAG) $(info_TEXINFOS) -o manual



