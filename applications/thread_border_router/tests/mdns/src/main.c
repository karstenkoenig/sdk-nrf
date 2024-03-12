/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/buf.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_if.h>
#include <zephyr/random/rand32.h>
#include <zephyr/ztest.h>
#include <zephyr/ztest_assert.h>

#include <udp_internal.h>
#include <ipv6.h>

#include <net/mdns_server.h>
#include <net/mdns_internal.h>

#define TEST_NAME_LEN(x) (sizeof(x) - 1)

#define TEST_REC_A_NAME "zephyr.local"
#define TEST_REC_DNAME "foo.bar.local"
#define TEST_REC_TTL 120

#define TEST_IPV4_ADDR {{{ 192, 168, 0, 2 }}}
#define TEST_IPV6_ADDR {{{ 0xfd, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 }}}
#define TEST_TXT { 0x7, 'f', 'o', 'o', '=', 'b', 'a', 'r' }

#define RESPONSE_TIMEOUT (K_MSEC(250))
#define MDNS_NAME_MAX_LEN 255
#define DATA_SIZE MDNS_NAME_MAX_LEN + 2

#define LABEL_POINTER_MARK 0xC0

struct record_data {
	bool additional;
	int32_t ttl;
	uint16_t type;
	uint16_t flags;
	uint8_t *name;
	uint8_t name_len;
	uint8_t *rdata;
	uint8_t rdata_len;
	sys_snode_t node;
};

static struct net_if *iface1;

static struct net_if_test {
	uint8_t idx; /* not used for anything, just a dummy value */
	uint8_t mac_addr[sizeof(struct net_eth_addr)];
	struct net_linkaddr ll_addr;
} net_iface1_data;

static bool test_started;
static struct k_sem wait_data;
static bool received_unicast = false;
static bool received_mcast = false;
static bool expect_unicast_response = false;
static bool expect_mcast_response = false;
static struct net_pkt *mcast_response_pkt = NULL;
static struct net_pkt *unicast_response_pkt = NULL;

static uint8_t data[DATA_SIZE];
static sys_slist_t decompressed_records;

static uint8_t mdns_server_ipv6_addr[] = {
0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb
};

static const uint8_t ipv6_hdr_start[] = {
0x60, 0x05, 0xe7, 0x00
};

static const uint8_t ipv6_hdr_rest[] = {
0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9f, 0x74, 0x88,
0x9c, 0x1b, 0x44, 0x72, 0x39, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb
};

/* Query: zephyr.local A */
static const uint8_t zephyr_local_a_query[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
0x7a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
0x00, 0x01, 0x00, 0x01
};

/* Query: zephyr.local A (unicast query) with TID = 0xabcd */
static const uint8_t zephyr_local_a_query_unicast[] = {
0xab, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
0x7a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
0x00, 0x01, 0x80, 0x01
};

/* Query (TID: 0xabcd):
 * zephyr.local A (unicast questio)
 * zephyr.local AAAA (multicast question)
 */
static const uint8_t zephyr_local_a_aaaa_query_mixed[] = {
0xab, 0xcd, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
0x7a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x80, 0x01
};


/* Query: zephyr.local ANY */
static const uint8_t zephyr_local_any_query[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
0x7a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
0x00, 0xff, 0x00, 0x01
};

/* Query: zephyr.local PTR */
static const uint8_t zephyr_local_ptr_query[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
0x7a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
0x00, 0x0c, 0x00, 0x01
};

/* Compressed query:
 * zephyr.local A
 * zephyr.local AAAA
 * a.few.labels.local A
 * a.few.labels.local AAAA
 * a.sequence.of.a.few.labels.local A
 * a.sequence.of.a.few.labels.local AAAA
 * very.long.a.sequence.of.a.few.labels.local A
 * very.long.a.sequence.of.a.few.labels.local AAAA
 */
static const uint8_t compressed_query[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x7a, 0x65, 0x70,
0x68, 0x79, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x04, 0x76,
0x65, 0x72, 0x79, 0x04, 0x6c, 0x6f, 0x6e, 0x67, 0x01, 0x61, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65,
0x6e, 0x63, 0x65, 0x02, 0x6f, 0x66, 0x01, 0x61, 0x03, 0x66, 0x65, 0x77, 0x06, 0x6c, 0x61, 0x62,
0x65, 0x6c, 0x73, 0xc0, 0x13, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x1e, 0x00, 0x01, 0x00, 0x01, 0xc0,
0x28, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x28, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x36, 0x00, 0x1c, 0x00,
0x01, 0xc0, 0x36, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01
};

static struct in6_addr ll_addr = {{{
0xfe, 0x80, 0x43, 0xb8, 0, 0, 0, 0, 0x9f, 0x74, 0x88, 0x9c, 0x1b, 0x44, 0x72, 0x39
}}};

static struct in6_addr sender_ll_addr = {{{
0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x9f, 0x74, 0x88, 0x9c, 0x1b, 0x44, 0x72, 0x39
}}};

static uint8_t *net_iface_get_mac(const struct device *dev)
{
	struct net_if_test *data = dev->data;

	if (data->mac_addr[2] == 0x00) {
		/* 00-00-5E-00-53-xx Documentation RFC 7042 */
		data->mac_addr[0] = 0x00;
		data->mac_addr[1] = 0x00;
		data->mac_addr[2] = 0x5E;
		data->mac_addr[3] = 0x00;
		data->mac_addr[4] = 0x53;
		data->mac_addr[5] = sys_rand32_get();
	}

	data->ll_addr.addr = data->mac_addr;
	data->ll_addr.len = 6U;

	return data->mac_addr;
}

static void net_iface_init(struct net_if *iface)
{
	uint8_t *mac = net_iface_get_mac(net_if_get_device(iface));

	net_if_set_link_addr(iface, mac, sizeof(struct net_eth_addr),
			     NET_LINK_ETHERNET);
}

static int sender_iface(const struct device *dev, struct net_pkt *pkt)
{
	struct net_ipv6_hdr *hdr;

	if (!pkt->buffer) {
		return -ENODATA;
	}

	if (test_started) {
		hdr = NET_IPV6_HDR(pkt);

		if (net_ipv6_addr_cmp_raw(hdr->dst, mdns_server_ipv6_addr)) {
			net_pkt_ref(pkt);
			mcast_response_pkt = pkt;
			received_mcast = true;
		} else if (net_ipv6_addr_cmp_raw(hdr->dst, sender_ll_addr.s6_addr)) {
			net_pkt_ref(pkt);
			unicast_response_pkt = pkt;
			received_unicast = true;
		}

		if (expect_mcast_response && !received_mcast) {
			return 0;
		}

		if (expect_unicast_response && !received_unicast) {
			return 0;
		}

		k_sem_give(&wait_data);
	}

	return 0;
}

static struct dummy_api net_iface_api = {
	.iface_api.init = net_iface_init,
	.send = sender_iface,
};

#define _ETH_L2_LAYER DUMMY_L2
#define _ETH_L2_CTX_TYPE NET_L2_GET_CTX_TYPE(DUMMY_L2)

NET_DEVICE_INIT_INSTANCE(net_iface1_test,
			 "iface1",
			 iface1,
			 NULL,
			 NULL,
			 &net_iface1_data,
			 NULL,
			 CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
			 &net_iface_api,
			 _ETH_L2_LAYER,
			 _ETH_L2_CTX_TYPE,
			 127);

static enum net_verdict remove_record(struct mdns_record_handle *handle, void *user_data)
{
	mdns_record_remove(handle, K_NO_WAIT);
	return NET_CONTINUE;
}

static void *test_setup(void)
{
	struct mdns_server_listener_config mdns_config = { 0 };
	struct net_if_addr *ifaddr;
	int err;
	int idx;

	/* The semaphore is there to wait the data to be received. */
	k_sem_init(&wait_data, 0, UINT_MAX);

	iface1 = net_if_get_by_index(1);

	((struct net_if_test *) net_if_get_device(iface1)->data)->idx =
		net_if_get_by_iface(iface1);

	idx = net_if_get_by_iface(iface1);
	zassert_equal(idx, 1, "Invalid index iface1");

	zassert_not_null(iface1, "Interface 1");

	ifaddr = net_if_ipv6_addr_add(iface1, &ll_addr,
				      NET_ADDR_MANUAL, 0);

	net_ipv6_nbr_add(iface1, &sender_ll_addr, net_if_get_link_addr(iface1), false,
			 NET_IPV6_NBR_STATE_STATIC);

	if (!ifaddr) {
		zassert_not_null(ifaddr, "Failed to add LL-addr");
	} else {
		/* we need to set the addresses preferred */
		ifaddr->addr_state = NET_ADDR_PREFERRED;
	}

	net_if_up(iface1);

	mdns_server_init();

	mdns_config.iface = iface1;
	mdns_config.setup_ipv6 = true;

	err = mdns_server_listener_start(&mdns_config);
	zassert_equal(err, 0, "Failed to add listener");

	return NULL;
}

static void try_allocation(const char *name, int expected, const char* msg) {
	struct mdns_record_handle *handle;
	int res = mdns_record_add_ptr(name, strlen(name), TEST_REC_TTL, TEST_REC_DNAME,
				      TEST_NAME_LEN(TEST_REC_DNAME), K_FOREVER, &handle);

	/* We are interested of the result only, perform cleanup on success */
	if (res == 0) {
		mdns_record_remove(handle, K_FOREVER);
	}

	zassert_equal(res, expected, "%s, val: %d, expected: %d", msg, res, expected);
}

static void free_record_data(struct record_data *data)
{
	if (!data) {
		return;
	}

	if (data->name) {
		k_free(data->name);
	}

	if (data->rdata) {
		k_free(data->rdata);
	}

	k_free(data);
}

static void before(void *d)
{
	test_started = true;
	sys_slist_init(&decompressed_records);
}

static void cleanup(void *d)
{
	ARG_UNUSED(d);

	struct record_data *current;
	struct record_data *next;
	test_started = false;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&decompressed_records, current, next, node) {
		current->node.next = NULL;
		free_record_data(current);
	}

	received_unicast = false;
	received_mcast = false;
	expect_unicast_response = false;
	expect_mcast_response = false;

	if (mcast_response_pkt) {
		net_pkt_unref(mcast_response_pkt);
		mcast_response_pkt = NULL;
	}

	if (unicast_response_pkt) {
		net_pkt_unref(unicast_response_pkt);
		unicast_response_pkt = NULL;
	}

	mdns_records_for_each(remove_record, NULL, K_FOREVER);
}

static void send_msg(const uint8_t *data, size_t len)
{
	struct net_pkt *pkt;
	int res;

	pkt = net_pkt_alloc_with_buffer(iface1, NET_IPV6UDPH_LEN + len, AF_UNSPEC,
					0, K_FOREVER);
	zassert_not_null(pkt, "PKT is null");

	res = net_pkt_write(pkt, ipv6_hdr_start, sizeof(ipv6_hdr_start));
	zassert_equal(res, 0, "pkt write for header start failed");

	res = net_pkt_write_be16(pkt, len + NET_UDPH_LEN);
	zassert_equal(res, 0, "pkt write for header length failed");

	res = net_pkt_write(pkt, ipv6_hdr_rest, sizeof(ipv6_hdr_rest));
	zassert_equal(res, 0, "pkt write for rest of the header failed");

	res = net_pkt_write_be16(pkt, 5353);
	zassert_equal(res, 0, "pkt write for UDP src port failed");

	res = net_pkt_write_be16(pkt, 5353);
	zassert_equal(res, 0, "pkt write for UDP dst port failed");

	res = net_pkt_write_be16(pkt, len + NET_UDPH_LEN);
	zassert_equal(res, 0, "pkt write for UDP length failed");

	/* to simplify testing checking of UDP checksum is disabled in prj.conf */
	res = net_pkt_write_be16(pkt, 0);
	zassert_equal(res, 0, "net_pkt_write_be16() for UDP checksum failed");

	res = net_pkt_write(pkt, data, len);
	zassert_equal(res, 0, "net_pkt_write() for data failed");

	res = net_recv_data(iface1, pkt);
	zassert_equal(res, 0, "net_recv_data() failed");
}

/* Add record with a given name, type, and mocked data */
static void add_rec_simple(const char *name, enum mdns_record_type type,
			   struct mdns_record_handle **handle)
{
	struct in_addr addrv4 = TEST_IPV4_ADDR;
	struct in6_addr addrv6 = TEST_IPV6_ADDR;
	const char *dname = TEST_REC_DNAME;
	uint8_t txt[] = TEST_TXT;
	int res;

	switch (type) {
	case MDNS_RECORD_TYPE_A:
		res = mdns_record_add_a(name, strlen(name), TEST_REC_TTL, &addrv4, K_FOREVER,
					handle);
		break;
	case MDNS_RECORD_TYPE_AAAA:
		res = mdns_record_add_aaaa(name, strlen(name), TEST_REC_TTL, &addrv6, K_FOREVER,
					   handle);
		break;
	case MDNS_RECORD_TYPE_CNAME:
		res = mdns_record_add_cname(name, strlen(name), TEST_REC_TTL, dname, strlen(dname),
					    K_FOREVER, handle);
		break;
	case MDNS_RECORD_TYPE_NS:
		res = mdns_record_add_ns(name, strlen(name), TEST_REC_TTL, dname, strlen(dname),
					 K_FOREVER, handle);
		break;
	case MDNS_RECORD_TYPE_PTR:
		res = mdns_record_add_ptr(name, strlen(name), TEST_REC_TTL, dname, strlen(dname),
					  K_FOREVER, handle);
		break;
	case MDNS_RECORD_TYPE_SRV:
		res = mdns_record_add_srv(name, strlen(name), TEST_REC_TTL, 0, 0, 0, dname,
					  strlen(dname), K_FOREVER, handle);
		break;
	case MDNS_RECORD_TYPE_TXT:
		res = mdns_record_add_txt(name, strlen(name), TEST_REC_TTL, txt, sizeof(txt),
					  K_FOREVER, handle);
		break;
	default:
		res = -1;
		break;
	}

	zassert_equal(res, 0, "record allocation failed");

}

static inline void unaligned_swap_u16(void *val)
{
	UNALIGNED_PUT(ntohs(UNALIGNED_GET((uint16_t *)val)), (uint16_t *)val);
}

static size_t decompress_labels(struct net_pkt *pkt, struct net_pkt_cursor *start)
{
	uint8_t label_len = 0;
	uint16_t label_ptr = 0;
	struct net_pkt_cursor next_label_pos = { 0 };
	size_t name_pos = 0;

	if (net_pkt_read_u8(pkt, &label_len) != 0) {
		return 0;
	}

	while (label_len && name_pos < MDNS_NAME_MAX_LEN) {
		/* Check for a pointer to another label */
		if ((label_len & LABEL_POINTER_MARK) == LABEL_POINTER_MARK) {
			label_ptr = ((label_len & (~LABEL_POINTER_MARK)) << 8);

			net_pkt_read_u8(pkt, &label_len);

			label_ptr += label_len;

			if (!next_label_pos.buf) {
				/* If it's a first pointer store the cursor to be restored later */
				net_pkt_cursor_backup(pkt, &next_label_pos);
			}

			net_pkt_cursor_restore(pkt, start);
			net_pkt_skip(pkt, label_ptr);
		} else {
			data[name_pos++] = '.';

			net_pkt_read(pkt, &data[name_pos], label_len);

			name_pos += label_len;
		}

		net_pkt_read_u8(pkt, &label_len);
	}

	if (next_label_pos.buf) {
		net_pkt_cursor_restore(pkt, &next_label_pos);
	}

	return name_pos;
}

static bool should_decompress_rdata(uint16_t rtype)
{
	switch (rtype) {
	case MDNS_RECORD_TYPE_NS:
	case MDNS_RECORD_TYPE_CNAME:
	case MDNS_RECORD_TYPE_PTR:
	case MDNS_RECORD_TYPE_SRV:
		return true;
	default:
		return false;
	}
}

static void decompress_mdns_pkt(struct net_pkt *pkt, struct mdns_msg_hdr *hdr)
{
	struct net_pkt_cursor start;
	struct record_data *record;
	size_t len;
	int res;
	uint16_t dlen;

	net_pkt_cursor_init(pkt);
	net_pkt_set_overwrite(pkt, true);

	res = net_pkt_skip(pkt, NET_IPV6UDPH_LEN);
	zassert_equal(res, 0, "net_pkt_skip() failed");

	net_pkt_cursor_backup(pkt, &start);

	res = net_pkt_read(pkt, hdr, sizeof(struct mdns_msg_hdr));
	zassert_equal(res, 0, "net_pkt_read() failed");

	unaligned_swap_u16(&hdr->tid);
	unaligned_swap_u16(&hdr->flags);
	unaligned_swap_u16(&hdr->questions);
	unaligned_swap_u16(&hdr->answer_rrs);
	unaligned_swap_u16(&hdr->authority_rrs);
	unaligned_swap_u16(&hdr->additional_rrs);

	for (uint16_t i = 0; i < hdr->answer_rrs + hdr->additional_rrs; ++i) {
		record = k_malloc(sizeof(struct record_data));
		zassert_not_null(record, "Failed to allocate record data");

		/* Ignore first dot */
		len = decompress_labels(pkt, &start);

		if (i >= hdr->answer_rrs) {
			record->additional = true;
		}

		/* Copy decompressed name from static buffer */
		record->name = k_malloc(len);
		record->name_len = len;
		zassert_not_null(record->name, "Failed to allocate record name");
		/* Skip first dot */
		memcpy(record->name, &data[1], len);
		record->name[len - 1] = '\0';

		net_pkt_read_be16(pkt, &record->type);
		net_pkt_read_be16(pkt, &record->flags);
		net_pkt_read_be32(pkt, &record->ttl);
		net_pkt_read_be16(pkt, &dlen);

		if (should_decompress_rdata(record->type)) {
			if (record->type == MDNS_RECORD_TYPE_SRV) {
				net_pkt_skip(pkt, sizeof(struct srv_rdata));
			}

			len = decompress_labels(pkt, &start);
			record->rdata = k_malloc(len);
			record->rdata_len = len;

			memcpy(record->rdata, data, len);
		} else {
			record->rdata = k_malloc(dlen);
			record->rdata_len = dlen;

			net_pkt_read(pkt, record->rdata, dlen);
		}

		sys_slist_append(&decompressed_records, &record->node);
	}
}

static struct record_data *find_record(const char *exp_name, enum mdns_record_type *exp_type,
				       bool *exp_additional)
{
	struct record_data *current;

	SYS_SLIST_FOR_EACH_CONTAINER(&decompressed_records, current, node) {
		if (exp_name && (strcmp(current->name, exp_name) != 0)) {
			continue;
		}

		if (exp_type && current->type != *exp_type) {
			continue;
		}

		if (exp_additional && current->additional != *exp_additional) {
			continue;
		}

		return current;
	}

	return NULL;
}

/* Return first occurence with a given name */
static inline struct record_data *find_by_rec_name(const char *name)
{
	return find_record(name, NULL, NULL);
}

/* Return first occurence of a given type */
static inline struct record_data *find_by_rec_type(enum mdns_record_type type)
{
	return find_record(NULL, &type, NULL);
}

static void assert_header(struct mdns_msg_hdr *hdr, uint16_t tid, uint16_t answers,
			  uint16_t additional_answers)
{
	zassert_equal(hdr->tid, tid, "Transaction ID: %u, expected: %u", hdr->tid, tid);
	zassert_equal(hdr->answer_rrs, answers, "Answers: %u, expected: %u", hdr->answer_rrs,
		      answers);
	zassert_equal(hdr->additional_rrs, additional_answers,
		      "Additional answers: %u, expected: %u",
		      hdr->additional_rrs, additional_answers);
}

ZTEST(test_mdns, test_data_keeping)
{
	/* Test: Verify that mDNS server holds a copy of a data and
	 * not the pointer itself.
	 */
	struct mdns_record_handle *handle;
	struct in_addr orig = TEST_IPV4_ADDR;
	struct in_addr addr;
	struct in_addr out;

	/* Prepare content */
	addr.s_addr = orig.s_addr;
	mdns_record_add_a(TEST_REC_A_NAME, TEST_NAME_LEN(TEST_REC_A_NAME), TEST_REC_TTL, &addr,
			  K_FOREVER, &handle);

	/* Read address and verify the content */
	mdns_record_get_rdata_a(handle, &out, K_FOREVER);
	zassert_equal(orig.s_addr, out.s_addr, "read address must match the original");

	/* Change content of a structure used previously */
	addr.s_addr = htonl(addr.s_addr);

	/* Read the data again and validate the output */
	out.s_addr = 0;
	mdns_record_get_rdata_a(handle, &out, K_FOREVER);
	zassert_not_equal(addr.s_addr, out.s_addr);
	zassert_equal(orig.s_addr, out.s_addr, "read address must match the original again");
}

ZTEST(test_mdns, test_name_validation)
{
	/* Test: Verify validation of record names and domain names in record data.
	 *
	 * Check different variants of valid names:
	 */
	try_allocation("zephyr.local", 0, "simple hostname must work");

	try_allocation("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.r.s.t.u.w.v.x.y.z.local", 0,
		       "multiple short labels must work");

	try_allocation("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde.local", 0,
		       "max label length (63 bytes) must work");

	try_allocation("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde."
		       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde."
		       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde."
		       "0123456789abcdef0123456789abcdef0123456789abcdef012345678.local", 0,
		       "max name length (255 bytes) must work");

	/* Different variats of invalid names */
	try_allocation("zephy\0r.local", -EFAULT, "label with NULL char must fail");

	try_allocation("local", -EFAULT, "domain only must fail");

	try_allocation(".local", -EFAULT, "empty label must fail");

	try_allocation("zephyr.", -EFAULT, "lack of doamin must fail");

	try_allocation("zephyr.global", -EFAULT, "invalid domain must fail");

	try_allocation("...x...s.local", -EFAULT, "garbage input must fail");

	try_allocation("zephyr.global", -EFAULT, "invalid domain must fail");

	try_allocation("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.local",
		       -EFAULT, "too long label must fail");
}

ZTEST(test_mdns, test_handle_validation)
{
	/* Test: Verify if handle validation works properly */
	struct in_addr addr = TEST_IPV4_ADDR;
	struct mdns_record_handle *valid;
	struct mdns_record_handle *freed;
	uint8_t *ptr;
	int32_t ttl;
	int res;

	/* Alloc record to get a valid handle */
	res = mdns_record_add_a(TEST_REC_A_NAME, TEST_NAME_LEN(TEST_REC_A_NAME), TEST_REC_TTL,
				&addr, K_FOREVER, &valid);
	zassert_equal(res, 0, "record allocation failed");

	/* Check that handle is valid by reading TTL */
	res = mdns_record_get_ttl(valid, K_FOREVER, &ttl);
	zassert_equal(res, 0, "Failed to read TTL");
	zassert_equal(ttl, TEST_REC_TTL, "Read TTL invalid");

	/* Check obviously invalid handles */
	res = mdns_record_get_ttl(NULL, K_FOREVER, &ttl);
	zassert_equal(res, -EINVAL, "NULL handle must fail");

	res = mdns_record_get_ttl((struct mdns_record_handle *)0x1, K_FOREVER, &ttl);
	zassert_equal(res, -EINVAL, "Invalid handle must fail");

	/* Check handle pointing to the middle of the record */
	ptr = ((uint8_t *)valid) + (sizeof(struct mdns_record) / 2);
	res = mdns_record_get_ttl((struct mdns_record_handle *)ptr, K_FOREVER, &ttl);
	zassert_equal(res, -EINVAL, "Handle pointing outside struct's start must fail");

	/* Check handle aligned properly but pointing to unallocated space */
	res = mdns_record_add_a(TEST_REC_A_NAME, TEST_NAME_LEN(TEST_REC_A_NAME), TEST_REC_TTL,
				&addr, K_FOREVER, &valid);
	zassert_equal(res, 0, "record allocation failed");

	freed = valid;
	res = mdns_record_remove(valid, K_FOREVER);
	zassert_equal(res, 0, "record freeing failed");

	res = mdns_record_get_ttl(freed, K_FOREVER, &ttl);
	zassert_equal(res, -EINVAL, "Handle pointing to freed memory must fail");
}

ZTEST(test_mdns, test_case_insensitive_matching)
{
	/* Test: Verify that mDNS server matches record names with case insensivity */
	int res;
	struct mdns_msg_hdr hdr;
	struct record_data* answer;
	struct mdns_record_handle *handle;

	const char * name1 = "zephyr.local";
	const char * name2 = "ZEPHYR.local";
	const char * name3 = "zEpHyR.local";

	add_rec_simple(name1, MDNS_RECORD_TYPE_A, &handle);
	add_rec_simple(name2, MDNS_RECORD_TYPE_A, &handle);
	add_rec_simple(name3, MDNS_RECORD_TYPE_A, &handle);

	expect_mcast_response = true;

	/* Query: zephyr.local, without compression */
	send_msg(zephyr_local_a_query, sizeof(zephyr_local_a_query));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive a response");

	decompress_mdns_pkt(mcast_response_pkt, &hdr);

	/* Expect: tid = 0, answers 3, additional answers = 0 */
	assert_header(&hdr, 0, 3, 0);

	answer = find_by_rec_name(name1);
	zassert_not_null(answer, "1st name not found");

	answer = find_by_rec_name(name1);
	zassert_not_null(answer, "2nd name not found");

	answer = find_by_rec_name(name1);
	zassert_not_null(answer, "3rd name not found");
}

ZTEST(test_mdns, test_any_type_matching)
{
	/* Test: Verify that mDNS server responds to questions with ANY type */
	struct mdns_msg_hdr hdr;
	const char *name = "zephyr.local";
	struct record_data* answer;
	struct mdns_record_handle *handle;
	int res;

	add_rec_simple(name, MDNS_RECORD_TYPE_A, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_AAAA, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_CNAME, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_NS, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_PTR, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_SRV, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_TXT, &handle);

	expect_mcast_response = true;

	send_msg(zephyr_local_any_query, sizeof(zephyr_local_any_query));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive a response");

	decompress_mdns_pkt(mcast_response_pkt, &hdr);

	/* Expect: tid = 0, answers 7, additional answers = 0 */
	assert_header(&hdr, 0, 7, 0);

	/* Verify that we received all the answers */
	answer = find_by_rec_type(MDNS_RECORD_TYPE_A);
	zassert_not_null(answer, "Answer with type A not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_AAAA);
	zassert_not_null(answer, "Answer with type AAAA not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_CNAME);
	zassert_not_null(answer, "Answer with type CNAME not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_NS);
	zassert_not_null(answer, "Answer with type NS not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_PTR);
	zassert_not_null(answer, "Answer with type PTR not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_SRV);
	zassert_not_null(answer, "Answer with type SRV not found");

	answer = find_by_rec_type(MDNS_RECORD_TYPE_TXT);
	zassert_not_null(answer, "Answer with type TXT not found");
}

ZTEST(test_mdns, test_record_linking)
{
	/* Test: Verify that linked records are added as additional answers */
	struct mdns_record_handle *handle_a;
	struct mdns_record_handle *handle_aaaa;
	struct mdns_record_handle *handle_ptr;
	struct record_data* answer;
	struct mdns_msg_hdr hdr;
	bool additional;
	enum mdns_record_type type;
	int res;
	const char *name_a = "ipv4.zephyr.local";
	const char *name_aaaa = "ipv6.zephyr.local";
	const char *name_ptr = "zephyr.local";

	add_rec_simple(name_a, MDNS_RECORD_TYPE_A, &handle_a);
	add_rec_simple(name_aaaa, MDNS_RECORD_TYPE_AAAA, &handle_aaaa);
	add_rec_simple(name_ptr, MDNS_RECORD_TYPE_PTR, &handle_ptr);

	res = mdns_link_records(handle_ptr, handle_a, K_FOREVER);
	zassert_equal(res, 0, "Failed to link A record");

	res = mdns_link_records(handle_ptr, handle_aaaa, K_FOREVER);
	zassert_equal(res, 0, "Failed to link AAAA record");

	expect_mcast_response = true;

	send_msg(zephyr_local_ptr_query, sizeof(zephyr_local_ptr_query));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive a response");

	decompress_mdns_pkt(mcast_response_pkt, &hdr);

	/* Expect: tid = 0, answers 1, additional answers = 2 */
	assert_header(&hdr, 0, 1, 2);

	/* Following records are expected to be in anwers section */
	additional = false;

	type = MDNS_RECORD_TYPE_PTR;
	answer = find_record(name_ptr, &type, &additional);
	zassert_not_null(answer, "Cannot find PTR answer");

	/* Following records are expected to be in additional anwers section */
	additional = true;

	type = MDNS_RECORD_TYPE_A;
	answer = find_record(name_a, &type, &additional);
	zassert_not_null(answer, "Cannot find additional A answer");

	type = MDNS_RECORD_TYPE_AAAA;
	answer = find_record(name_aaaa, &type, &additional);
	zassert_not_null(answer, "Cannot find additional AAAA answer");

}

ZTEST(test_mdns, test_question_decompression)
{
	/* Test: Verify that mDNS server is able to decompress questions */
	struct mdns_record_handle *handle_a;
	struct mdns_msg_hdr hdr;
	struct record_data* answer;
	const char *name = "a.sequence.of.a.few.labels.local";
	int res;

	add_rec_simple(name, MDNS_RECORD_TYPE_A, &handle_a);

	expect_mcast_response = true;

	send_msg(compressed_query, sizeof(compressed_query));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive a response");

	decompress_mdns_pkt(mcast_response_pkt, &hdr);

	/* Expect: tid = 0, answers = 1, additional answers = 0 */
	assert_header(&hdr, 0, 1, 0);

	answer = find_by_rec_name(name);
	zassert_not_null(answer, "Cannot find the record");
}

ZTEST(test_mdns, test_unicast_response)
{
	/* Test: Verify that mDNS server is able to decompress questions */
	struct mdns_record_handle *handle_a;
	struct mdns_msg_hdr hdr;
	struct record_data* answer;
	const char *name = "zephyr.local";
	int res;

	add_rec_simple(name, MDNS_RECORD_TYPE_A, &handle_a);

	expect_unicast_response = true;

	send_msg(zephyr_local_a_query_unicast, sizeof(zephyr_local_a_query_unicast));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive a response");

	decompress_mdns_pkt(unicast_response_pkt, &hdr);

	/* Expect: tid = 0xabcd, answers = 1, additional answers = 0 */
	assert_header(&hdr, 0xabcd, 1, 0);

	answer = find_by_rec_name(name);
	zassert_not_null(answer, "Cannot find the record");
}

ZTEST(test_mdns, test_mixed_response)
{
	/* Test: Verify that mDNS server is able to decompress questions */
	struct mdns_record_handle *handle;
	struct mdns_msg_hdr hdr;
	struct record_data* answer;
	const char *name = "zephyr.local";
	enum mdns_record_type type;
	int res;

	add_rec_simple(name, MDNS_RECORD_TYPE_A, &handle);
	add_rec_simple(name, MDNS_RECORD_TYPE_AAAA, &handle);

	expect_unicast_response = true;
	expect_mcast_response = true;

	send_msg(zephyr_local_a_aaaa_query_mixed, sizeof(zephyr_local_a_aaaa_query_mixed));

	res = k_sem_take(&wait_data, RESPONSE_TIMEOUT);
	zassert_equal(res, 0, "Did not receive responses");

	decompress_mdns_pkt(unicast_response_pkt, &hdr);

	/* Expect: tid = 0xabcd, answers = 1, additional answers = 0 */
	assert_header(&hdr, 0xabcd, 1, 0);

	type = MDNS_RECORD_TYPE_AAAA;
	answer = find_record(name, &type, NULL);
	zassert_not_null(answer, "Cannot find AAAA record");

	decompress_mdns_pkt(mcast_response_pkt, &hdr);

	/* Expect: tid = 0 (always for multicasts), answers = 1, additional answers = 0 */
	assert_header(&hdr, 0, 1, 0);

	type = MDNS_RECORD_TYPE_A;
	answer = find_record(name, &type, NULL);
	zassert_not_null(answer, "Cannot find A record");
}

ZTEST_SUITE(test_mdns, NULL, test_setup, before, cleanup, NULL);
