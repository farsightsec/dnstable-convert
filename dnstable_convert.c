/*
 * Copyright (c) 2024 DomainTools LLC
 * Copyright (c) 2012-2015, 2018, 2020, 2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/utsname.h>
#include <sys/resource.h>

#include <dnstable.h>
#include <mtbl.h>
#include <nmsg.h>
#include <nmsg/base/defs.h>
#include <nmsg/sie/defs.h>
#include <nmsg/sie/dnsdedupe.pb-c.h>
#include <wdns.h>

#include "dnstable-private.h"

#include "libmy/ubuf.h"
#include "libmy/my_byteorder.h"

#define DEFAULT_COMPRESSION_LEVEL (-1000)

static struct {
	uint8_t entry_type;
	uint32_t version;
} versions[] = {
	{ ENTRY_TYPE_RRSET, 0 },

	/* ENTRY_TYPE_RRSET_NAME_FWD version 1: add rrtype union as value */
	{ ENTRY_TYPE_RRSET_NAME_FWD, 1 },

	/* ENTRY_TYPE_RDATA version 1: fix the SRV slicing and add SVCB/HTTPS sliced entries */
	/* ENTRY_TYPE_RDATA version 2: Add SOA RNAME sliced entry */
	{ ENTRY_TYPE_RDATA, 1 },

	/* ENTRY_TYPE_RDATA_NAME_REV version 1: add SOA, SVCB, and HTTPS name indexing; add rrtype union as value */
	/* ENTRY_TYPE_RDATA_NAME_REV version 2: add SOA RNAME indexing */
	{ ENTRY_TYPE_RDATA_NAME_REV, 1 },
};

/*
 * Define SVCB and HTTPS types if we are compiling against a version
 * of wdns without them. The conversion logic specific to these types
 * is provided by dnstable_convert, so additional wdns library support
 * for these types is not required.
 */
#ifndef WDNS_TYPE_SVCB
#define WDNS_TYPE_SVCB		64
#endif
#ifndef WDNS_TYPE_HTTPS
#define WDNS_TYPE_HTTPS		65
#endif

static const char		*nmsg_fname;
static const char		*nmsg_source_info;
static const char		*db_dns_fname;
static const char		*db_dnssec_fname;
static bool			store_nmsg_source_info = false; /* Store nmsg source info */
static bool			migrate_dnssec;
static bool			preserve_empty = false;	/* Keep empty dns files? */
static bool			s_process_soa_rname = false;

static nmsg_input_t		input;
static struct mtbl_sorter	*sorter_dns;
static struct mtbl_sorter	*sorter_dnssec;
static struct mtbl_writer	*writer_dns;
static struct mtbl_writer	*writer_dnssec;

static uint64_t			min_time_first = UINT64_MAX;
static uint64_t			min_time_first_dnssec = UINT64_MAX;
static uint64_t			max_time_last;
static uint64_t			max_time_last_dnssec;

static struct timespec		start_time;
static uint64_t			count_messages;
static uint64_t			count_entries_dns;
static uint64_t			count_entries_dnssec;
/* Count merged entries correctly even when MTBL multithreading is enabled. */
static atomic_uint_fast64_t	count_entries_merged;

#define STATS_INTERVAL				1000000

#define DNS_MTBL_BLOCK_SIZE			8192
#define DNSSEC_MTBL_BLOCK_SIZE			65536

#define CASE_DNSSEC                        \
	case WDNS_TYPE_DS:                 \
	case WDNS_TYPE_CDS:                \
	case WDNS_TYPE_RRSIG:              \
	case WDNS_TYPE_NSEC:               \
	case WDNS_TYPE_DNSKEY:             \
	case WDNS_TYPE_CDNSKEY:            \
	case WDNS_TYPE_NSEC3:              \
	case WDNS_TYPE_NSEC3PARAM:         \
	case WDNS_TYPE_TA:                 \
	case WDNS_TYPE_DLV:

/* Display current soft- and hard-limits for # descriptors. */
static int
show_fd_limit(FILE *fp, struct rlimit *rl)
{
	int ret = getrlimit(RLIMIT_NOFILE, rl);

	if (ret == 0)
		fprintf(fp, "fd-limit: soft=%lu, hard=%lu\n",
			(unsigned long) rl->rlim_cur, (unsigned long) rl->rlim_max);
	else
		fprintf(fp, "getrlimit() failed, error=%d\n", errno);

	return(ret);
}

/* Check/increment the descriptor resource limit. */
static void
check_fd_limit(FILE *fp)
{
	struct rlimit rl;
	int ret;

	fputs("Checking resource limits\n", fp);

	ret = show_fd_limit(fp, &rl);

	if (ret == 0) {
		/* Increase soft-limit to hard-limit. */
		if (rl.rlim_cur < rl.rlim_max) {
			rl.rlim_cur = rl.rlim_max;

			ret = setrlimit(RLIMIT_NOFILE, &rl);
			if (ret == 0) {
				fprintf(fp, "fd-limit: Updated soft-limit\n");
				show_fd_limit(fp, &rl);
			}
			else
				fprintf(fp, "setrlimit() failed, error=%d\n", errno);
		}
	}
}

static void
abrt_handler(int sig __attribute__((unused)))
{
	int err = errno;

	fprintf(stderr, "ABRT handler called, errno=%d (%s)\n", err, strerror(err));
	/* Return, allowing a core-file to be produced. */
}

/* Catch certain signals. */
static void
setup_handlers(void)
{
	struct sigaction sa = { 0 };

	sigemptyset(&sa.sa_mask);

	/* Catch any assert() failures generated in other libraries. */
	sa.sa_handler = abrt_handler;
	sigaction(SIGABRT, &sa, NULL);
}

/* Show details about startup environment. */
static void
show_startup_details(FILE *fp)
{
	char buffer[PATH_MAX];
	struct utsname un;
	struct timeval tv;
	const char *startdir;

	uname(&un);
	gettimeofday(&tv, NULL);

	ctime_r(&tv.tv_sec, buffer);

	fprintf(fp, "Start: %s", buffer);
	fprintf(fp, "Host: %s\n", un.nodename);
	fprintf(fp, "Kernel: %s %s %s %s\n", un.sysname, un.machine, un.release, un.version);
	fprintf(fp, "Run by: UID=%lu EUID=%lu\n", (unsigned long) getuid(), (unsigned long) geteuid());
	startdir = getcwd(buffer, sizeof(buffer));
	if (startdir == NULL)
		startdir = "<Unknown>";
	fprintf(fp, "Start dir: %s\n", startdir);
	fputc('\n', fp);
}

static void
do_stats(void)
{
	struct timespec dur;
	double t_dur;
	int fd;

	nmsg_timespec_get(&dur);
	nmsg_timespec_sub(&start_time, &dur);
	t_dur = nmsg_timespec_to_double(&dur);
	fd = dup(2);

	fprintf(stderr, "processed "
			"%'" PRIu64 " messages, "
			"%'" PRIu64 " DNS entries, %'" PRIu64 " DNSSEC entries, %'" PRIu64 " merged "
			"in %'.2f sec, %'d msg/sec, %'d ent/sec, fd=%d"
			"\n",
		count_messages,
		count_entries_dns,
		count_entries_dnssec,
		atomic_load_explicit(&count_entries_merged, memory_order_relaxed),
		t_dur,
		(int) (count_messages / t_dur),
		(int) (count_entries_dns / t_dur), fd
	);
	close(fd);
}

static void
merge_func(void *clos,
	   const uint8_t *key, size_t len_key,
	   const uint8_t *val0, size_t len_val0,
	   const uint8_t *val1, size_t len_val1,
	   uint8_t **merged_val, size_t *len_merged_val)
{
	dnstable_merge_func(clos,
			    key, len_key,
			    val0, len_val0,
			    val1, len_val1,
			    merged_val, len_merged_val);
	atomic_fetch_add_explicit(&count_entries_merged, 1, memory_order_relaxed);
}

static void
add_entry(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val) {
	mtbl_res res;
	switch (dns->rrtype) {
	CASE_DNSSEC
		res = mtbl_sorter_add(sorter_dnssec,
				      ubuf_data(key), ubuf_size(key),
				      ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
		count_entries_dnssec += 1;
		if (!migrate_dnssec)
			break;
		if ((dns->rrtype != WDNS_TYPE_CDS) &&
		    (dns->rrtype != WDNS_TYPE_CDNSKEY) &&
		    (dns->rrtype != WDNS_TYPE_TA))
			break;
		/* fallthrough */
	default:
		res = mtbl_sorter_add(sorter_dns,
				      ubuf_data(key), ubuf_size(key),
				      ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
		count_entries_dns += 1;
	}
}

static size_t
pack_triplet(uint8_t *orig_buf, uint64_t val1, uint64_t val2, uint64_t val3)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	buf += mtbl_varint_encode64(buf, val3);
	return (buf - orig_buf);
}

static void
put_triplet(Nmsg__Sie__DnsDedupe *dns, ubuf *val)
{
	uint64_t time_first, time_last, count;
	bool is_dns = false, is_dnssec = false;

	switch(dns->rrtype) {
	CASE_DNSSEC
		is_dnssec = true;
		if (!migrate_dnssec)
			break;
		if ((dns->rrtype != WDNS_TYPE_CDS) &&
		    (dns->rrtype != WDNS_TYPE_CDNSKEY) &&
		    (dns->rrtype != WDNS_TYPE_TA))
			break;
		/* fallthrough */
	default:
		is_dns = true;
	}

	if (dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__AUTHORITATIVE ||
	    dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__MERGED_AUTHORITATIVE)
	{
		time_first = dns->zone_time_first;
		time_last = dns->zone_time_last;
	} else {
		time_first = dns->time_first;
		time_last = dns->time_last;
	}

	if (is_dns) {
		if (time_first < min_time_first)
			min_time_first = time_first;
		if (time_last > max_time_last)
			max_time_last = time_last;
	}

	if (is_dnssec) {
		if (time_first < min_time_first_dnssec)
			min_time_first_dnssec = time_first;
		if (time_last > max_time_last_dnssec)
			max_time_last_dnssec = time_last;
	}

	if (dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__INSERTION)
		count = 0;
	else
		count = dns->count;

	ubuf_reserve(val, 32);
	ubuf_advance(val, pack_triplet(ubuf_data(val), time_first, time_last, count));
}

/*
 * Output the RRtype in a value ubuf, assuming it's in range (1 to 65535).
 * Express the RRtype as 8-bit integer if it is less than 256 else as
 * a 16-bit network-order (little endian) integer.
 *
 * This value may be "upgraded" to an RRtype bitmap in the merging process
 * -- see dnstable-encoding(5).
 */
static void
put_rrtype(Nmsg__Sie__DnsDedupe *dns, ubuf *val)
{
	if (dns->rrtype >= 1 && dns->rrtype <= 65535) {
		if (dns->rrtype > 255) {
			uint16_t rrtype_le = htole16((uint16_t) dns->rrtype);
			ubuf_reserve(val, sizeof(uint16_t));
			ubuf_append(val, (uint8_t *) &rrtype_le, sizeof(uint16_t));
		} else {
			uint8_t rrtype_1byte = (uint8_t)dns->rrtype;
			ubuf_reserve(val, sizeof(uint8_t));
			ubuf_append(val, &rrtype_1byte, sizeof(uint8_t));
		}
	}
}

static void
process_rrset(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	wdns_res res;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RRSET);

	/* key: rrset owner name (label-reversed) */
	res = wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	assert(res == wdns_res_success);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: bailiwick name (label-reversed) */
	res = wdns_reverse_name(dns->bailiwick.data, dns->bailiwick.len, name);
	assert(res == wdns_res_success);
	ubuf_append(key, name, dns->bailiwick.len);

	/* key: rdata array (varint encoded rdata lengths) */
	for (size_t i = 0; i < dns->n_rdata; i++) {
		ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rdata[i].len));
		ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rdata[i].len));
		ubuf_append(key, dns->rdata[i].data, dns->rdata[i].len);
	}

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

static void
process_rrset_name_fwd(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val)
{
	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RRSET_NAME_FWD);

	/* key: rrset owner name */
	ubuf_append(key, dns->rrname.data, dns->rrname.len);

	/* value: the RRtype */
	put_rrtype(dns, val);

	add_entry(dns, key, val);
}

static void
process_rdata(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	uint16_t rdlen;
	wdns_res res;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA);

	/* key: rdata */
	ubuf_append(key, dns->rdata[i].data, dns->rdata[i].len);

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: rrname (label-reversed) */
	res = wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	assert(res == wdns_res_success);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rdlen */
	assert(dns->rdata[i].len <= 65535);
	rdlen = htole16((uint16_t) dns->rdata[i].len);
	ubuf_reserve(key, ubuf_size(key) + sizeof(uint16_t));
	ubuf_append(key, (uint8_t *) &rdlen, sizeof(uint16_t));

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

/*
 * SVCB and HTTPS records contain a hostname offset by a preference,
 * requiring slice encoding.  They also need reversed name
 * indexing. In addition, these newer types do not have
 * case-normalized hostnames, so the hostname portion needs to be
 * downcased for search purposes in the sliced encoding and reversed
 * name entry.
 */
static void
process_rdata_slice(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	const size_t rdata_len = dns->rdata[i].len;
	const uint8_t * const rdata_start = dns->rdata[i].data;
	const uint8_t * const rdata_end = rdata_start + rdata_len;
	uint8_t name[WDNS_MAXLEN_NAME];
	wdns_name_t downcase;
	size_t offset = 0, len;
	wdns_res res;

	if (rdata_len == 0)
		return;

	switch (dns->rrtype) {
	case WDNS_TYPE_MX:
	case WDNS_TYPE_SVCB:
	case WDNS_TYPE_HTTPS:
		offset = 2;	/* skip MX, SVCB, or HTTPS preference */
		break;
	case WDNS_TYPE_SRV:
		offset = 6;	/* skip SRV priority, weight, port */
		break;
	case WDNS_TYPE_SOA:
		if (!s_process_soa_rname)
			return;

		/* Find length of MNAME */
		res = wdns_len_uname(rdata_start, rdata_end, &len);
		if (res != wdns_res_success)
			return;

		if (len > rdata_len)
			return;

		offset = len;	/* skip MNAME */
		break;
	default:
		return;
	}

	if (rdata_len <= offset)
		return;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/*
	 * Key ::= TYPE DATA RRTYPE NAME SLICE DATALEN
	 *     TYPE: 1 octet, Type-Byte
	 *     DATA: Arbitrary length
	 *   RRTYPE: Varint
	 *     NAME: Arbitrary length (label-reversed)
	 *    SLICE: Data from front of DATA, arbitrary length
	 *  DATALEN: 2 octets, le16, length of DATA
	 */

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA);

	switch(dns->rrtype) {
	case WDNS_TYPE_MX:
	case WDNS_TYPE_SRV:
		/* key: data */
		ubuf_append(key, rdata_start + offset, rdata_len - offset);
		break;
	case WDNS_TYPE_SVCB:
	case WDNS_TYPE_HTTPS:
	case WDNS_TYPE_SOA:
		res = wdns_len_uname(rdata_start + offset, rdata_end, &len);
		if (res != wdns_res_success)
			return;

		/*
		 * wdns_len_uname can return a length one greater
		 * than the buffer length if the buffer ends with
		 * a nonzero length label. Treat this case as a malformed
		 * name.
		 */
		if (offset + len > rdata_len)
			return;

		if (dns->rrtype == WDNS_TYPE_SOA) {
			/* Do not process if MNAME and RNAME are the same. */
			if (offset == len && memcmp(rdata_start, rdata_start + offset, len) == 0)
				return;
		}

		/* key: downcased target name */
		ubuf_reserve(key, len);
		downcase.data = ubuf_ptr(key);
		downcase.len = len;
		memcpy(ubuf_ptr(key), rdata_start + offset, len);
		wdns_downcase_name(&downcase);
		ubuf_advance(key, len);

		/* key: rest of rdata */
		ubuf_append(key, rdata_start + (offset + len), rdata_len - (offset + len));
		break;
	}

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: rrname (label-reversed) */
	res = wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	assert(res == wdns_res_success);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rdata slice */
	ubuf_append(key, rdata_start, offset);

	/* key: data length */
	uint16_t dlen = htole16((uint16_t) rdata_len - offset);
	ubuf_reserve(key, ubuf_size(key) + sizeof(uint16_t));
	ubuf_append(key, (uint8_t *) &dlen, sizeof(uint16_t));

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

static void
rdata_name_rev_add(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val, const uint8_t *data, size_t len, bool do_downcase)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	wdns_name_t downcase;
	wdns_res res;

	/* clear key */
	ubuf_clip(key, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA_NAME_REV);

	/* key: rdata name (label-reversed) */
	res = wdns_reverse_name(data, len, name);
	assert(res == wdns_res_success);
	if (do_downcase) {
		downcase.data = name;
		downcase.len = len;
		wdns_downcase_name(&downcase);
	}
	ubuf_append(key, name, len);

	add_entry(dns, key, val);
}

static void
process_rdata_name_rev(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	const size_t rdata_len = dns->rdata[i].len;
	const uint8_t * const rdata_start = dns->rdata[i].data;
	const uint8_t * const rdata_end = rdata_start + rdata_len;
	size_t offset = 0, len = rdata_len;
	bool do_downcase = false;
	wdns_res res;

	if (rdata_len == 0)
		return;

	switch (dns->rrtype) {
	case WDNS_TYPE_SOA:
		res = wdns_len_uname(rdata_start, rdata_end, &len);
		if (res != wdns_res_success)
			return;
		/* fallthrough */
	case WDNS_TYPE_NS:
	case WDNS_TYPE_CNAME:
	case WDNS_TYPE_DNAME:
	case WDNS_TYPE_PTR:
		offset = 0;
		break;
	case WDNS_TYPE_SVCB:
	case WDNS_TYPE_HTTPS:
		offset = 2;
		do_downcase = true;
		res = wdns_len_uname(rdata_start + offset, rdata_end, &len);
		if (res != wdns_res_success)
			return;
		break;
	case WDNS_TYPE_MX:
		offset = 2;	/* skip MX preference */
		len -= offset;
		break;
	case WDNS_TYPE_SRV:
		offset = 6;	/* skip SRV priority, weight, port */
		len -= offset;
		break;
	default:
		return;		/* Other rrtypes are not indexed by name. */
	}

	if (rdata_len <= offset)
		return;

	/* check for a len that is longer than the data left in the packet */
	if (offset + len > rdata_len)
		return;

	/* value: the RRtype */
	ubuf_clip(val, 0);
	put_rrtype(dns, val);

	rdata_name_rev_add(dns, key, val, rdata_start + offset, len, do_downcase);

	/* For SOA RDATA, always process the MNAME, and then the RNAME if requested. */
	if (dns->rrtype == WDNS_TYPE_SOA && s_process_soa_rname) {
		offset = len;		/* Offset of RNAME (== length of MNAME). */
		res = wdns_len_uname(rdata_start + offset, rdata_end, &len);
		if (res != wdns_res_success)
			return;

		if (offset + len > rdata_len)
			return;

		rdata_name_rev_add(dns, key, val, rdata_start + offset, len, true);
	}
}

static void
process_time_range(ubuf *key, ubuf *val)
{
	mtbl_res res;

	ubuf_clip(key, 0);
	ubuf_add(key, ENTRY_TYPE_TIME_RANGE);

	ubuf_clip(val, 0);
	ubuf_reserve(val, ubuf_size(val) + mtbl_varint_length(min_time_first));
	ubuf_advance(val, mtbl_varint_encode64(ubuf_ptr(val), min_time_first));
	ubuf_reserve(val, ubuf_size(val) + mtbl_varint_length(max_time_last));
	ubuf_advance(val, mtbl_varint_encode64(ubuf_ptr(val), max_time_last));

	res = mtbl_sorter_add(sorter_dns, ubuf_data(key), ubuf_size(key),
				    ubuf_data(val), ubuf_size(val));
	assert(res == mtbl_res_success);

	ubuf_clip(val, 0);
	ubuf_reserve(val, ubuf_size(val) + mtbl_varint_length(min_time_first_dnssec));
	ubuf_advance(val, mtbl_varint_encode64(ubuf_ptr(val), min_time_first_dnssec));
	ubuf_reserve(val, ubuf_size(val) + mtbl_varint_length(max_time_last_dnssec));
	ubuf_advance(val, mtbl_varint_encode64(ubuf_ptr(val), max_time_last_dnssec));

	res = mtbl_sorter_add(sorter_dnssec, ubuf_data(key), ubuf_size(key),
				    ubuf_data(val), ubuf_size(val));
	assert(res == mtbl_res_success);
}

static void
process_version(ubuf *key, ubuf *val)
{
	mtbl_res res;
	size_t i;

	for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		ubuf_clip(key, 0);
		ubuf_add(key, ENTRY_TYPE_VERSION);
		ubuf_add(key, versions[i].entry_type);

		ubuf_clip(val, 0);
		ubuf_reserve(val, ubuf_size(val) + mtbl_varint_length(versions[i].version));
		ubuf_advance(val, mtbl_varint_encode32(ubuf_ptr(val), versions[i].version));
		res = mtbl_sorter_add(sorter_dns, ubuf_data(key), ubuf_size(key),
				ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
		res = mtbl_sorter_add(sorter_dnssec, ubuf_data(key), ubuf_size(key),
				ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
	}
}

static void
process_source_info(ubuf *key, ubuf *val)
{
	mtbl_res res;

	ubuf_clip(key, 0);
	ubuf_add(key, ENTRY_TYPE_SOURCE_INFO);
	ubuf_append(key, (const uint8_t *)nmsg_source_info, strlen(nmsg_source_info));
	ubuf_cterm(key);

	ubuf_clip(val, 0);

	res = mtbl_sorter_add(sorter_dns, ubuf_data(key), ubuf_size(key),
			ubuf_data(val), ubuf_size(val));
	assert(res == mtbl_res_success);
	res = mtbl_sorter_add(sorter_dnssec, ubuf_data(key), ubuf_size(key),
			ubuf_data(val), ubuf_size(val));
	assert(res == mtbl_res_success);
}

static void
do_read(void)
{
	Nmsg__Sie__DnsDedupe *dns;
	nmsg_message_t msg;
	nmsg_res res;
	ubuf *key, *val;

	key = ubuf_init(256);
	val = ubuf_init(256);

	fprintf(stderr, "dnstable_convert: reading input data\n");

	for (;;) {
		int32_t vid, msgtype;

		res = nmsg_input_read(input, &msg);
		if (res == nmsg_res_eof)
			break;
		if (res != nmsg_res_success) {
			fprintf(stderr, "Error reading nmsg input: %s\n", nmsg_res_lookup(res));
			exit(EXIT_FAILURE);
		}

		vid = nmsg_message_get_vid(msg);
		msgtype = nmsg_message_get_msgtype(msg);
		if ((vid != NMSG_VENDOR_SIE_ID) || (msgtype != NMSG_VENDOR_SIE_DNSDEDUPE_ID)) {
			if ((nmsg_msgmod_vid_to_vname(vid) != NULL) &&
			    (nmsg_msgmod_msgtype_to_mname(vid, msgtype) != NULL))
				fprintf(stderr, "Invalid msgtype %s:%s != sie:dnsdedupe, exiting.\n",
						nmsg_msgmod_vid_to_vname(vid),
						nmsg_msgmod_msgtype_to_mname(vid, msgtype));
			else
				fprintf(stderr, "Invalid msgtype %d:%d != sie:dnsdedupe, exiting.\n", vid, msgtype);

			exit(EXIT_FAILURE);
		}

		dns = (Nmsg__Sie__DnsDedupe *) nmsg_message_get_payload(msg);
		assert(dns != NULL);
		assert(dns->has_rrname);
		assert(dns->rrname.len < 256);
		assert(dns->has_rrtype);
		assert(dns->has_bailiwick);
		assert(dns->n_rdata > 0);

		process_rrset(dns, key, val);
		process_rrset_name_fwd(dns, key, val);

		for (size_t i = 0; i < dns->n_rdata; i++) {
			process_rdata(dns, i, key, val);
			process_rdata_slice(dns, i, key, val);
			process_rdata_name_rev(dns, i, key, val);
		}

		nmsg_message_destroy(&msg);
		count_messages += 1;

		if ((count_messages % STATS_INTERVAL) == 0)
			do_stats();
	}

	process_time_range(key, val);
	process_version(key, val);
	if (store_nmsg_source_info)
		process_source_info(key, val);

	ubuf_destroy(&key);
	ubuf_destroy(&val);
	do_stats();
}

struct write_thread_ctx
{
	const char		*n;
	struct mtbl_sorter	*s;
	struct mtbl_writer	*w;
	uint64_t		count;
	struct timespec		start;
};

static void
thread_stat(struct write_thread_ctx *ctx)
{
	struct timespec dur;
	double t_dur;
	nmsg_timespec_get(&dur);
	nmsg_timespec_sub(&ctx->start, &dur);
	t_dur = nmsg_timespec_to_double(&dur);
	fprintf(stderr,
		"wrote %'" PRIu64 " entries in %'.2f sec, %'d ent/sec [%s]\n",
		ctx->count, t_dur, (int) (ctx->count / t_dur), ctx->n);
}

static void *
write_thread(void *clos)
{
	struct write_thread_ctx *ctx = (struct write_thread_ctx *) clos;
	struct mtbl_iter *it = mtbl_sorter_iter(ctx->s);
	const uint8_t *key, *val;
	size_t len_key, len_val;

	assert(it != NULL);

	ctx->count = 0;
	nmsg_timespec_get(&ctx->start);

	while (mtbl_iter_next(it, &key, &len_key, &val, &len_val) == mtbl_res_success) {
		mtbl_res res = mtbl_writer_add(ctx->w, key, len_key, val, len_val);
		assert(res == mtbl_res_success);
		if ((++(ctx->count) % STATS_INTERVAL) == 0)
			thread_stat(ctx);
	}
	mtbl_iter_destroy(&it);
	mtbl_sorter_destroy(&ctx->s);
	mtbl_writer_destroy(&ctx->w);
	thread_stat(ctx);
	fprintf(stderr, "dnstable_convert: finished writing table [%s]\n", ctx->n);
	return (NULL);
}

static void
do_write(void)
{
	struct write_thread_ctx ctx_dns, ctx_dnssec;
	pthread_t thr_dns, thr_dnssec;
	int ret;

	ctx_dns.n = "dns";
	ctx_dns.s = sorter_dns;
	ctx_dns.w = writer_dns;

	ctx_dnssec.n = "dnssec";
	ctx_dnssec.s = sorter_dnssec;
	ctx_dnssec.w = writer_dnssec;

	fprintf(stderr, "dnstable_convert: writing tables\n");

	ret = pthread_create(&thr_dns, NULL, write_thread, (void *) &ctx_dns);
	assert(ret == 0);

	ret = pthread_create(&thr_dnssec, NULL, write_thread, (void *) &ctx_dnssec);
	assert(ret == 0);

	ret = pthread_join(thr_dns, NULL);
	assert(ret == 0);

	ret = pthread_join(thr_dnssec, NULL);
	assert(ret == 0);
}

static void
init_nmsg(void)
{
	int fd;
	nmsg_res res;
	nmsg_msgmod_t mod;

	res = nmsg_init();
	assert(res == nmsg_res_success);
	if (strcmp(nmsg_fname, "-") == 0)
		fd = STDIN_FILENO;
	else {
		fd = open(nmsg_fname, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Unable to open NMSG input file '%s': %s\n",
				nmsg_fname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	input = nmsg_input_open_file(fd);
	assert(input != NULL);

	mod = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	if (mod == NULL) {
		fprintf(stderr, "Unable to initialize SIE/dnsdedupe module\n");
		exit(EXIT_FAILURE);
	}
}

/* Update version of ENTRY_TYPE_RDATA_NAME_REV, if feature requested. */
static void
update_version_table(void)
{
	size_t i;

	if (!s_process_soa_rname)
		return;

	for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		switch (versions[i].entry_type) {
		case ENTRY_TYPE_RDATA_NAME_REV:
		case ENTRY_TYPE_RDATA:
			if (versions[i].version < 2)
				versions[i].version = 2;
			break;
		default:
			break;
		}
	}
}

static void
init_mtbl(mtbl_compression_type compression, int level, size_t dns_block_size,
	  size_t dnssec_block_size, struct mtbl_threadpool *pool, size_t mem_mb)
{
	struct mtbl_sorter_options *sopt;
	struct mtbl_writer_options *wopt;

	sopt = mtbl_sorter_options_init();

	mtbl_sorter_options_set_threadpool(sopt, pool);

	if (mem_mb == 0)
		mem_mb = 2UL * 1024;
	mtbl_sorter_options_set_max_memory(sopt, (mem_mb*1024*1024));

	mtbl_sorter_options_set_merge_func(sopt, merge_func, NULL);
	if (getenv("VARTMPDIR"))
		mtbl_sorter_options_set_temp_dir(sopt, getenv("VARTMPDIR"));

	wopt = mtbl_writer_options_init();

	mtbl_writer_options_set_threadpool(wopt, pool);

	mtbl_writer_options_set_compression(wopt, compression);
	if (level != DEFAULT_COMPRESSION_LEVEL)
		mtbl_writer_options_set_compression_level(wopt, level);

	mtbl_writer_options_set_block_size(wopt, dns_block_size);
	writer_dns = mtbl_writer_init(db_dns_fname, wopt);
	if (writer_dns == NULL) {
		perror(db_dns_fname);
		exit(EXIT_FAILURE);
	}

	mtbl_writer_options_set_block_size(wopt, dnssec_block_size);
	writer_dnssec = mtbl_writer_init(db_dnssec_fname, wopt);
	if (writer_dnssec == NULL) {
		perror(db_dnssec_fname);
		exit(EXIT_FAILURE);
	}

	sorter_dns = mtbl_sorter_init(sopt);
	sorter_dnssec = mtbl_sorter_init(sopt);

	mtbl_sorter_options_destroy(&sopt);
	mtbl_writer_options_destroy(&wopt);
}

static bool
parse_long(const char *str, long int *val)
{
	char *endptr;

	errno = 0;
	*val = strtol(str, &endptr, 0);

	if ((errno == ERANGE && (*val == LONG_MAX || *val == LONG_MIN))
	    || (errno != 0 && *val == 0))
	{
		return false;
	}

	return (*endptr == '\0');
}

static void
usage(const char *name)
{
	fprintf(stderr, "Usage: %s [-D] [-p] [-r] [-S] [-b dns_bsize[,dnssec_bsize]] "
			"[-c compression] [-l level] [-m megabytes] [-s name] [-t threads] "
			"<NMSG FILE> <DB FILE> <DB DNSSEC FILE>\n", name);

	fprintf(stderr, "Options:\n"
		" -b DNS[,DNSSEC]: set block size for dns and dnssec files (defaults: %u, %u).\n"
		" -c TYPE:         use type compression (default: zlib)\n"
		" -D:              put cds, cdnskey, and ta rrsets in both outputs\n"
		" -l LEVEL:        use numeric level of compression.\n"
		"                  default varies based on type.\n"
		" -m MMB:          set max amount of memory to use for in-memory sorting, in megabytes.\n"
		" -p:              preserve empty dns/dnssec files.\n"
		" -r:              emit rdata and rdata_name_rev dnstable entries for soa rname field.\n"
		" -s NAME:         nmsg source information to include in output if input is stdin.\n"
		" -s:              include nmsg source information in output.\n"
		" -t COUNT:        set size of mtbl thread pool for sorting and writing.\n",
		DNS_MTBL_BLOCK_SIZE, DNSSEC_MTBL_BLOCK_SIZE);
}

int
main(int argc, char **argv)
{
	long mmb = 0;
	long thread_count = 0;
	mtbl_compression_type compression = MTBL_COMPRESSION_ZLIB;
	long compression_level = DEFAULT_COMPRESSION_LEVEL;
	int dns_block_size = DNS_MTBL_BLOCK_SIZE;
	int dnssec_block_size = DNSSEC_MTBL_BLOCK_SIZE;
	struct mtbl_threadpool *pool = NULL;
	const char *name = argv[0];
	int c;

	setlocale(LC_ALL, "");

	while ((c = getopt(argc, argv, "b:Dc:l:m:t:prSs:")) != -1) {
		mtbl_res res;
		char *end;

		switch(c) {
		case 'b':
			dns_block_size = strtol(optarg, &end, 10);
			switch(*end) {
				char *new_end;

				case '\0':
					break;
				case ',':
					new_end = end + 1;
					dnssec_block_size = strtol(new_end, &end, 10);
					if (*end == '\0' && new_end != end)
						break;
					/* Intentional fallthrough */
				default:
					fprintf(stderr, "Malformed block size '%s'\n", optarg);
					usage(name);
					return (EXIT_FAILURE);
			}

			if (dns_block_size < 1) {
				fprintf(stderr, "Invalid DNS block size '%d'\n", dns_block_size);
				usage(name);
				return (EXIT_FAILURE);
			}
			if (dnssec_block_size < 1) {
				fprintf(stderr, "Invalid DNSSEC block size '%d'\n", dnssec_block_size);
				usage(name);
				return (EXIT_FAILURE);
			}
			break;
		case 'D':
			migrate_dnssec = true;
			break;
		case 'c':
			res = mtbl_compression_type_from_str(optarg, &compression);
			if (res != mtbl_res_success) {
				fprintf(stderr, "Invalid compression type '%s'\n", optarg);
				usage(name);
				return (EXIT_FAILURE);
			}
			break;
		case 'l':
			if (!parse_long(optarg, &compression_level)) {
				fprintf(stderr, "Invalid compression level '%s'\n", optarg);
				usage(name);
				return (EXIT_FAILURE);
			}
			break;
		case 'm':
			if (!parse_long(optarg, &mmb) || mmb < 1) {
				fprintf(stderr, "Invalid max mega bytes '%s'\n", optarg);
				usage(name);
				return (EXIT_FAILURE);
			}
			break;
		case 't':
			if (!parse_long(optarg, &thread_count) || thread_count < 1) {
				fprintf(stderr, "Invalid thread count '%s'\n", optarg);
				usage(name);
				return (EXIT_FAILURE);
			}
			break;
		case 'p':
			preserve_empty = true;
			break;
		case 'r':
			s_process_soa_rname = true;
			break;
		case 'S':
			store_nmsg_source_info = true;
			break;
		case 's':
			nmsg_source_info = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage(name);
			return (c == 'h')?(EXIT_SUCCESS):(EXIT_FAILURE);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 3) {
		usage(name);
		return (EXIT_FAILURE);
	}
	nmsg_fname = argv[0];
	db_dns_fname = argv[1];
	db_dnssec_fname = argv[2];

	if (store_nmsg_source_info && nmsg_source_info == NULL) {
		if (strcmp(nmsg_fname, "-") == 0) {
			fprintf(stderr, "Please provide NMSG source information\n");
			usage(name);
			return (EXIT_FAILURE);
		}
		nmsg_source_info = nmsg_fname;
	}

	update_version_table();

	show_startup_details(stderr);
	check_fd_limit(stderr);

	setup_handlers();

	init_nmsg();

	pool = mtbl_threadpool_init(thread_count);
	init_mtbl(compression, compression_level, dns_block_size, dnssec_block_size, pool, (size_t)mmb);

	nmsg_timespec_get(&start_time);
	do_read();
	nmsg_input_close(&input);
	do_write();
	do_stats();

	if (count_entries_dns == 0 && !preserve_empty) {
		fprintf(stderr, "no DNS entries generated, unlinking %s\n", db_dns_fname);
		unlink(db_dns_fname);
	}

	if (count_entries_dnssec == 0 && !preserve_empty) {
		fprintf(stderr, "no DNSSEC entries generated, unlinking %s\n", db_dnssec_fname);
		unlink(db_dnssec_fname);
	}

	mtbl_threadpool_destroy(&pool);

	return (EXIT_SUCCESS);
}
