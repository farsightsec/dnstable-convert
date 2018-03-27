EXTRA_DIST = COPYRIGHT LICENSE README.md
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = -include $(top_builddir)/config.h
AM_CFLAGS = ${my_CFLAGS} \
	$(libdnstable_CFLAGS) \
	$(libmtbl_CFLAGS) \
	$(libwdns_CFLAGS)

bin_PROGRAMS = dnstable_convert
dnstable_convert_SOURCES = dnstable_convert.c \
	libmy/vector.h \
	libmy/ubuf.h \
	libmy/my_alloc.h \
	libmy/my_byteorder.h \
	dnstable-private.h

dnstable_convert_LDADD = \
	$(libdnstable_LIBS) \
	$(libmtbl_LIBS) \
	$(libnmsg_LIBS) \
	$(libwdns_LIBS) 

if BUILD_MAN
SUFFIXES = .1.txt .3.txt .5.txt .7.txt .1 .3 .5 .7

ASCIIDOC_PROCESS = $(AM_V_GEN) $(ASCIIDOC) -f manpage --no-xmllint --asciidoc-opt="-f man/asciidoc.conf" $<

.1.txt.1:
	$(ASCIIDOC_PROCESS)

.3.txt.3:
	$(ASCIIDOC_PROCESS)

.5.txt.5:
	$(ASCIIDOC_PROCESS)

.7.txt.7:
	$(ASCIIDOC_PROCESS)

dist_man_MANS = \
	man/dnstable_convert.1
endif

EXTRA_DIST += \
	man/dnstable_convert.1.txt
