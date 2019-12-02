/*
 * Copyright (c) 2019 by Farsight Security, Inc.
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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include <dnstable.h>
#include <mtbl.h>
#include <nmsg.h>
#include <nmsg/sie/dnsdedupe.pb-c.h>
#include <wdns.h>

static nmsg_message_t entry_to_nmsg(struct dnstable_entry *, const uint8_t *, size_t);
static nmsg_msgmod_t sie_dnsdedupe;

int main(int ac, char **av) {
	int fd;
	nmsg_output_t out;
	nmsg_res nres;

	struct mtbl_reader *r;
	struct mtbl_iter *it;
	const uint8_t *key, *val;
	size_t i, len_key, len_val;

	if (ac != 3) {
		fprintf(stderr, "Usage: %s <input.mtbl> <output.nmsg>\n", av[0]);
		exit(1);
	}

	nres = nmsg_init();
	assert(nres == nmsg_res_success);

	sie_dnsdedupe = nmsg_msgmod_lookup_byname("sie", "dnsdedupe");
	if (sie_dnsdedupe == NULL) {
		fprintf(stderr, "Failed to load sie:dnsdedupe module\n");
		exit(1);
	}

	fd = open(av[2], O_WRONLY|O_CREAT|O_EXCL, 0640);
	if (fd < 0) {
		fprintf(stderr, "open(%s) failed: %s\n", av[2], strerror(errno));
		exit(1);
	}

	out = nmsg_output_open_file(fd, NMSG_WBUFSZ_MAX);
	assert(out != NULL);

	r = mtbl_reader_init(av[1], NULL);
	assert(r != NULL);
	it = mtbl_source_get_prefix(mtbl_reader_source(r), (const uint8_t *)"\x00", 1);
	assert(it != NULL);

	while (mtbl_iter_next(it, &key, &len_key, &val, &len_val) == mtbl_res_success) {
		struct dnstable_entry *e;
		nmsg_message_t m;

		e = dnstable_entry_decode(key, len_key, val, len_val);
		assert(e != NULL);

		m = entry_to_nmsg(e, val, len_val);

		nres = nmsg_output_write(out, m);
		assert(nres == nmsg_res_success);

		nmsg_message_destroy(&m);
		dnstable_entry_destroy(&e);
	}

	nmsg_output_close(&out);
	mtbl_iter_destroy(&it);
	mtbl_reader_destroy(&r);

}

static nmsg_message_t entry_to_nmsg(struct dnstable_entry *e, const uint8_t *data, size_t len_data) {
	const uint8_t *rrname, *bailiwick;
	size_t len_rrname, len_bailiwick;
	uint16_t rrtype;
	uint16_t rrclass = WDNS_CLASS_IN;
	uint32_t msgtype = NMSG__SIE__DNS_DEDUPE_TYPE__EXPIRATION;
	size_t i, n_rdata;
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
	nres = nmsg_message_set_field(m, "bailiwick", 0, bailiwick, len_bailiwick);
	assert(nres == nmsg_res_success);

	dres = dnstable_entry_get_num_rdata(e, &n_rdata);
	assert(dres == dnstable_res_success);
	for (i = 0; i < n_rdata; i++) {
		const uint8_t *rdata;
		size_t len_rdata;

		dres = dnstable_entry_get_rdata(e, i, &rdata, &len_rdata);
		assert(dres == dnstable_res_success);
		nres = nmsg_message_set_field(m, "rdata", i, rdata, len_rdata);
		assert(nres == nmsg_res_success);
	}

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
} while(0);

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
