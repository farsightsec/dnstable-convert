EXTRA_DIST = COPYRIGHT LICENSE README.md
CLEANFILES =
DISTCLEANFILES =
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

dnstable_convert_CFLAGS = $(AM_CFLAGS)

dnstable_convert_LDADD = \
	$(libdnstable_LIBS) \
	$(libmtbl_LIBS) \
	$(libnmsg_LIBS) \
	$(libwdns_LIBS) 

bin_PROGRAMS += dnstable_unconvert

dnstable_unconvert_SOURCES = dnstable_unconvert.c

dnstable_unconvert_CFLAGS = $(AM_CFLAGS)

dnstable_unconvert_LDADD = \
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
endif

dist_man_MANS = \
	man/dnstable_convert.1 \
	man/dnstable_unconvert.1

EXTRA_DIST += \
	man/dnstable_convert.1.txt \
	man/dnstable_unconvert.1.txt

TESTS = tests/tests.sh
EXTRA_DIST += \
	tests/broken-srv_soa.dns.mtbl \
	tests/dnstable_convert.output1 \
	tests/dnstable_convert.output2 \
	tests/dnstable_convert.output3 \
	tests/dnstable_dump.rdata.output1 \
	tests/dnstable_dump.rdata.output3 \
	tests/dnstable_dump.rrset.output1 \
	tests/dnstable_dump.rrset.output3 \
	tests/dnstable_dump.rrset.output5 \
	tests/dnstable_lookup.rdata.name.soa.output1 \
	tests/dnstable_lookup.rdata.name.srv.output1 \
	tests/dnstable_unconvert.output1 \
	tests/srv_soa.dnsdedupe.json \
	tests/srv_soa.dnsdedupe.nmsg \
	tests/unordered-rdata.dnsdedupe.json \
	tests/unordered-rdata.dnsdedupe.json.nmsg

DISTCLEANFILES += \
	tests/dnstable_convert.output1.tmp \
	tests/dnstable_convert.output2.tmp \
	tests/dnstable_convert.output3.tmp \
	tests/dnstable_dump.rdata.output1.tmp \
	tests/dnstable_dump.rdata.output2.tmp \
	tests/dnstable_dump.rdata.output3.tmp \
	tests/dnstable_dump.rdata.output4.tmp \
	tests/dnstable_dump.rrset.output1.tmp \
	tests/dnstable_dump.rrset.output2.tmp \
	tests/dnstable_dump.rrset.output3.tmp \
	tests/dnstable_dump.rrset.output4.tmp \
	tests/dnstable_dump.rrset.output5.tmp \
	tests/dnstable_lookup.rdata.name.soa.output1.tmp \
	tests/dnstable_lookup.rdata.name.soa.output2.tmp \
	tests/dnstable_lookup.rdata.name.srv.output1.tmp \
	tests/dnstable_lookup.rdata.name.srv.output2.tmp \
	tests/dnstable_unconvert.output1.tmp \
	tests/ordered-rdata.dnsdedupe.dns.mtbl \
	tests/ordered-rdata.dnsdedupe.dns.nmsg \
	tests/ordered-rdata.dnsdedupe.dnssec.mtbl \
	tests/srv_soa.dns.mtbl \
	tests/unordered-rdata.dnsdedupe.dns.mtbl

check_PROGRAMS =
