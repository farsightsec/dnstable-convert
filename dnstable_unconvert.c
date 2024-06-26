/*
 * Copyright (c) 2024 DomainTools LLC
 * Copyright (c) 2019-2021 by Farsight Security, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <dnstable.h>
#include <mtbl.h>
#include <nmsg.h>
#include <nmsg/sie/dnsdedupe.pb-c.h>
#include <wdns.h>

#define STATS_INTERVAL	1000000

static nmsg_message_t entry_to_nmsg(struct dnstable_entry *, const uint8_t *, size_t);

static nmsg_msgmod_t	sie_dnsdedupe;
static uint64_t		count_rrsets;
static struct timespec	start_time;

static void usage(const char *progname) {
	fprintf(stderr, "Usage: %s [-z] <DB FILE> <NMSG FILE>\n", progname);
	exit(1);
}

static void do_stats(void) {
	struct timespec dur;
	double t_dur;

	nmsg_timespec_get(&dur);
	nmsg_timespec_sub(&start_time, &dur);
	t_dur = nmsg_timespec_to_double(&dur);

	fprintf(stderr, "processed %'" PRIu64 " RRSets in %'.2f sec, %'d rrsets/sec\n",
			count_rrsets, t_dur, (int)(count_rrsets / t_dur));
}

int main(int argc, char **argv) {
	int c, fd;
	nmsg_output_t out;
	nmsg_res nres;
	bool zlibout = false;
	const char *progname = argv[0];
	const char *input_fname;
	const char *output_fname;
	struct mtbl_reader *r;
	struct mtbl_iter *it;
	const uint8_t *key, *val;
	size_t len_key, len_val;

	while ((c = getopt(argc, argv, "z")) != -1) {
		switch(c) {
		case 'z':
			zlibout = true;
			break;
		default:
			usage(progname);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage(progname);

	nres = nmsg_init();
	assert(nres == nmsg_res_success);

	sie_dnsdedupe = nmsg_msgmod_lookup_byname("sie", "dnsdedupe");
	if (sie_dnsdedupe == NULL) {
		fprintf(stderr, "Failed to load sie:dnsdedupe module\n");
		exit(1);
	}

	input_fname = argv[0];
	output_fname = argv[1];

	if (strcmp(output_fname, "-") == 0)
		fd = STDOUT_FILENO;
	else {
		fd = open(output_fname, O_WRONLY|O_CREAT|O_EXCL, 0640);
		if (fd < 0) {
			fprintf(stderr, "open(%s) failed: %s\n", output_fname, strerror(errno));
			exit(1);
		}
	}

	out = nmsg_output_open_file(fd, NMSG_WBUFSZ_MAX);
	assert(out != NULL);
	nmsg_output_set_zlibout(out, zlibout);

	r = mtbl_reader_init(input_fname, NULL);
	if (r == NULL) {
		fprintf(stderr, "Failed to open %s as mtbl file\n", input_fname);
		exit(1);
	}

	it = mtbl_source_get_prefix(mtbl_reader_source(r), (const uint8_t *)"\x00", 1);
	assert(it != NULL);

	fprintf(stderr, "Reading RRSets from %s into nmsg file %s\n", input_fname, output_fname);
	nmsg_timespec_get(&start_time);

	while (mtbl_iter_next(it, &key, &len_key, &val, &len_val) == mtbl_res_success) {
		struct dnstable_entry *e;
		nmsg_message_t m;

		e = dnstable_entry_decode(key, len_key, val, len_val);
		assert(e != NULL);

		m = entry_to_nmsg(e, val, len_val);

		nres = nmsg_output_write(out, m);

		if (nres != nmsg_res_success) {
			if (nres == nmsg_res_errno)
				fprintf(stderr, "nmsg_output_write() failed, nres=%s, errno=%d\n",
					nmsg_res_lookup(nres), (int)errno);
			else
				fprintf(stderr, "nmsg_output_write() failed, nres=%s\n",
					nmsg_res_lookup(nres));
			exit(2);
		}
		nmsg_message_destroy(&m);
		dnstable_entry_destroy(&e);

		count_rrsets ++;
		if (count_rrsets % STATS_INTERVAL == 0)
			do_stats();
	}
	do_stats();
	fprintf(stderr, "Finished.\n");

	nmsg_output_close(&out);
	mtbl_iter_destroy(&it);
	mtbl_reader_destroy(&r);
}

static struct dnstable_entry *cmp_entry;

static int rdata_cmp(const void *a, const void *b) {
	size_t ia = *(const size_t *)a;
	size_t ib = *(const size_t *)b;
	size_t len_a, len_b;
	const uint8_t *rdata_a, *rdata_b;
	dnstable_res dres;

	dres = dnstable_entry_get_rdata(cmp_entry, ia, &rdata_a, &len_a);
	assert(dres == dnstable_res_success);
	dres = dnstable_entry_get_rdata(cmp_entry, ib, &rdata_b, &len_b);
	assert(dres == dnstable_res_success);

	if (len_a < len_b)
		return -1;
	if (len_a > len_b)
		return 1;

	return memcmp(rdata_a, rdata_b, len_a);
}

static nmsg_message_t entry_to_nmsg(struct dnstable_entry *e, const uint8_t *data, size_t len_data) {
	const uint8_t *rrname, *bailiwick;
	size_t len_rrname, len_bailiwick;
	uint16_t rrtype;
	uint16_t rrclass = WDNS_CLASS_IN;
	uint32_t msgtype = NMSG__SIE__DNS_DEDUPE_TYPE__EXPIRATION;
	size_t i, n_rdata, *indexes;
	dnstable_res dres;
	nmsg_res nres;

	uint32_t nm_time_first, nm_time_last, nm_count;

	nmsg_message_t m = nmsg_message_init(sie_dnsdedupe);
	assert(m != NULL);

	nres = nmsg_message_set_field(m, "rrclass", 0, (const uint8_t *)&rrclass, sizeof(rrclass));
	assert(nres == nmsg_res_success);

	dres = dnstable_entry_get_rrname(e, &rrname, &len_rrname);
	assert(dres == dnstable_res_success);
	nres = nmsg_message_set_field(m, "rrname", 0, rrname, len_rrname);
	assert(nres == nmsg_res_success);

	dres = dnstable_entry_get_rrtype(e, &rrtype);
	assert(dres == dnstable_res_success);
	nres = nmsg_message_set_field(m, "rrtype", 0, (const uint8_t *)&rrtype, sizeof(rrtype));
	assert(nres == nmsg_res_success);

	dres = dnstable_entry_get_bailiwick(e, &bailiwick, &len_bailiwick);
	assert(dres == dnstable_res_success);
	nres = nmsg_message_set_field(m, "bailiwick", 0, bailiwick, len_bailiwick);
	assert(nres == nmsg_res_success);

	dres = dnstable_entry_get_num_rdata(e, &n_rdata);
	assert(dres == dnstable_res_success);

	indexes = malloc(n_rdata * sizeof(*indexes));
	assert(indexes != NULL);
	for (i = 0; i < n_rdata; i++)
		indexes[i] = i;
	cmp_entry = e;
	qsort(indexes, n_rdata, sizeof(*indexes), rdata_cmp);
	for (i = 0; i < n_rdata; i++) {
		const uint8_t *rdata;
		size_t len_rdata;

		dres = dnstable_entry_get_rdata(e, indexes[i], &rdata, &len_rdata);
		assert(dres == dnstable_res_success);
		nres = nmsg_message_set_field(m, "rdata", i, rdata, len_rdata);
		assert(nres == nmsg_res_success);
	}
	free(indexes);

	/*
	 * We decode the value triplet here instead of using the dnstable_entry
	 * times and counts for two reasons:
	 *
	 *   1) The dnstable entry values are 64-bit integers, whereas the
	 *      nmsg fields are 32 bit integers.
	 *
	 *   2) The dnstable_entry count will never be presented as zero,
	 *      whereas the underlying count value is set to zero for
	 *      INSERTION records.
	 */

#define decode(v) do {							\
	unsigned vi_len = mtbl_varint_length_packed(data, len_data);	\
	uint64_t vi_val;						\
	assert(vi_len > 0);						\
	len_data -= vi_len;						\
	data += mtbl_varint_decode64(data, &vi_val);			\
	v = (uint32_t)vi_val;						\
} while(0)

	decode(nm_time_first);
	decode(nm_time_last);
	decode(nm_count);

#undef decode

	nres = nmsg_message_set_field(m, "time_first", 0,
					(const uint8_t *)&nm_time_first,
					sizeof(nm_time_first));
	assert(nres == nmsg_res_success);
	nres = nmsg_message_set_field(m, "time_last", 0,
					(const uint8_t *)&nm_time_last,
					sizeof(nm_time_last));
	assert(nres == nmsg_res_success);
	nres = nmsg_message_set_field(m, "count", 0,
					(const uint8_t *)&nm_count,
					sizeof(nm_count));
	assert(nres == nmsg_res_success);

	if (nm_count == 0)
		msgtype = NMSG__SIE__DNS_DEDUPE_TYPE__INSERTION;

	nres = nmsg_message_set_field(m, "type", 0,
					(const uint8_t *)&msgtype,
					sizeof(msgtype));
	assert(nres == nmsg_res_success);

	return m;
}
