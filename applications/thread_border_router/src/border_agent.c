/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief nRF Thread Border Router's Border Agent's functions
 */

#include <string.h>

#include <openthread/border_agent.h>
#include <openthread/border_routing.h>
#include <openthread/backbone_router_ftd.h>
#include <openthread/thread.h>

#include <zephyr/net/net_config.h>
#include <zephyr/net/openthread.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/byteorder.h>

#include "backbone/backbone_agent.h"
#include "net/dns_sd.h"
#include "tbr.h"

LOG_MODULE_DECLARE(nrf_tbr, CONFIG_NRF_TBR_LOG_LEVEL);

#define TXT_BUFFER_SIZE 255

#define UPDATE_MESHCOP_FLAGS OT_CHANGED_THREAD_ROLE \
	| OT_CHANGED_THREAD_EXT_PANID		    \
	| OT_CHANGED_THREAD_NETWORK_NAME	    \
	| OT_CHANGED_THREAD_BACKBONE_ROUTER_STATE   \
	| OT_CHANGED_THREAD_NETDATA

#define BA_VENDOR_NAME  CONFIG_NRF_TBR_VENDOR_NAME
#define BA_PRODUCT_NAME CONFIG_NRF_TBR_PRODUCT_NAME
#define BA_SERVICE      "_meshcop"
#define BA_SERVICE_TTL  120
#define BA_DUMMY_PORT   0

#define BA_INSTANCE_NAME BA_VENDOR_NAME "-" BA_PRODUCT_NAME

#define BA_AAAA_RECORD_NAME BA_INSTANCE_NAME ".local"
#define BA_MAX_AAAA_RECORDS CONFIG_NRF_TBR_MAX_BORDER_AGENT_AAAA_RECORDS

#define OT_THREAD_VERSION_1_1 2
#define OT_THREAD_VERSION_1_2 3
#define OT_THREAD_VERSION_1_3 4

#define OT_INSTANCE openthread_get_default_instance()

#define TIMESTAMP_TICKS_POS     1
#define TIMESTAMP_SEC_POS       16

#define ACCESS_TIMEOUT 500

/* For ot-br-posix compatibility:
 *   -----------------------------------
 *   | bits  | flag                    |
 *   |---------------------------------|
 *   | 0 - 2 | connection mode         |
 *   | 3 - 4 | thread interface status |
 *   | 5 - 6 | availability            |
 *   |   7   | is BBR active           |
 *   |   8   | is BBR primary          |
 *   -----------------------------------
 */
#define CONNECTION_MODE_POS     0
#define IFACE_STATUS_POS        3
#define AVAILABILITY_POS        5
#define BBR_ACTIVE_POS          7
#define BBR_PRIMARY_POS         8

#define FLAG_SET_CONNECTION_MODE(_f, _m)     (_f |= ((_m & BIT_MASK(3)) << CONNECTION_MODE_POS))
#define FLAG_SET_IFACE_STATUS(_f, _s)        (_f |= ((_s & BIT_MASK(2)) << IFACE_STATUS_POS))
#define FLAG_SET_AVAILABILITY(_f, _a)        (_f |= ((_a & BIT_MASK(2)) << AVAILABILITY_POS))

typedef int (*value_encoder)(char *, size_t);

struct tbr_address_info {
	const struct in6_addr *address;
	struct mdns_record_handle *record;
};

static struct tbr_address_info addr_infos[BA_MAX_AAAA_RECORDS];
static size_t addr_info_count;

K_MUTEX_DEFINE(ba_mutex);

static struct dns_sd_service_handle *ba_service;

enum {
	CONNECTION_MODE_DISABLED        = 0,
	CONNECTION_MODE_PSKC            = 1,
	CONNECTION_MODE_PSKD            = 2,
	CONNECTION_MODE_VENDOR          = 3,
	CONNECTION_MODE_X509            = 4,
};

enum {
	INTERFACE_STATUS_NOT_INITIALIZED        = 0,
	INTERFACE_STATUS_INITIALIZED            = 1,
	INTERFACE_STATUS_ACTIVE                 = 2,
};

enum {
	AVAILABILITY_INFREQUENT = 0,
	AVAILABILITY_HIGH       = 1
};

static int encode_value(char *buffer, size_t max, const char *key,
			size_t key_len, const char *value, size_t value_len)
{
	int encoded_bytes = 0;
	uint8_t to_encode = key_len + value_len + 1;

	/* len + key + '=' + value */
	if (to_encode + 1 > max) {
		return -ENOBUFS;
	}

	memcpy(&buffer[encoded_bytes], &to_encode, sizeof(to_encode));
	encoded_bytes += sizeof(to_encode);

	memcpy(&buffer[encoded_bytes], key, key_len);
	encoded_bytes += key_len;

	memcpy(&buffer[encoded_bytes], "=", 1);
	encoded_bytes += 1;

	memcpy(&buffer[encoded_bytes], value, value_len);
	encoded_bytes += value_len;

	return encoded_bytes;
}

static int encode_vendor_name(char *buffer, size_t max)
{
	return encode_value(buffer, max, "vn", sizeof("vn") - 1, BA_VENDOR_NAME,
			    sizeof(BA_VENDOR_NAME) - 1);
}

static int encode_product_name(char *buffer, size_t max)
{
	return encode_value(buffer, max, "mn", sizeof("mn") - 1, BA_PRODUCT_NAME,
			    sizeof(BA_PRODUCT_NAME) - 1);
}

static int encode_network_name(char *buffer, size_t max)
{
	const char *nn = otThreadGetNetworkName(OT_INSTANCE);

	return encode_value(buffer, max, "nn", sizeof("nn") - 1, nn, strlen(nn));
}

static int encode_ext_pan_id(char *buffer, size_t max)
{
	const otExtendedPanId *extPanId = otThreadGetExtendedPanId(OT_INSTANCE);

	return encode_value(buffer, max, "xp", sizeof("xp") - 1, extPanId->m8,
			    sizeof(extPanId->m8));
}

static int encode_thread_version(char *buffer, size_t max)
{
	const char *version = "invalid";

	switch (otThreadGetVersion()) {
	case OT_THREAD_VERSION_1_1:
		version = "1.1.1";
		break;
	case OT_THREAD_VERSION_1_2:
		version = "1.2.0";
		break;
	case OT_THREAD_VERSION_1_3:
		version = "1.3.0";
		break;
	}

	return encode_value(buffer, max, "tv", sizeof("tv") - 1, version,
			    strlen(version));
}

static int encode_ext_address(char *buffer, size_t max)
{
	const otExtAddress *extAddr = otLinkGetExtendedAddress(OT_INSTANCE);

	return encode_value(buffer, max, "xa", sizeof("xa") - 1, extAddr->m8,
			    sizeof(extAddr->m8));
}

static int encode_state(char *buffer, size_t max)
{
	uint32_t flags = 0;
	int if_status;
	otBackboneRouterState bbr_state = otBackboneRouterGetState(OT_INSTANCE);

	switch (otThreadGetDeviceRole(OT_INSTANCE)) {
	case OT_DEVICE_ROLE_DISABLED:
		if_status = INTERFACE_STATUS_NOT_INITIALIZED;
		break;
	case OT_DEVICE_ROLE_DETACHED:
		if_status = INTERFACE_STATUS_INITIALIZED;
		break;
	default:
		if_status = INTERFACE_STATUS_ACTIVE;
	}

	FLAG_SET_CONNECTION_MODE(flags, CONNECTION_MODE_PSKC);
	FLAG_SET_IFACE_STATUS(flags, if_status);
	FLAG_SET_AVAILABILITY(flags, AVAILABILITY_HIGH);

	flags |= (if_status == INTERFACE_STATUS_ACTIVE &&
		  bbr_state != OT_BACKBONE_ROUTER_STATE_DISABLED) << BBR_ACTIVE_POS;
	flags |= (if_status == INTERFACE_STATUS_ACTIVE &&
		  bbr_state == OT_BACKBONE_ROUTER_STATE_PRIMARY) << BBR_PRIMARY_POS;

	flags = sys_cpu_to_be32(flags);

	return encode_value(buffer, max, "sb", sizeof("sb") - 1,
			    (const char *)&flags, sizeof(flags));
}

static int encode_active_timestamp(char *buffer, size_t max)
{
	otOperationalDataset dataset;
	uint64_t active_ts;

	if ((otDatasetGetActive(OT_INSTANCE, &dataset)) != OT_ERROR_NONE) {
		return 0;
	}

	/* 64 bits Timestamp fields layout
	 * -----48 bits------//-----15 bits-----//-------1 bit-------//
	 *      Seconds      //      Ticks      //  Authoritative    //
	 */
	active_ts = (dataset.mActiveTimestamp.mSeconds << TIMESTAMP_SEC_POS) |
		    (uint64_t)(dataset.mActiveTimestamp.mTicks << TIMESTAMP_TICKS_POS) |
		    (uint64_t)(dataset.mActiveTimestamp.mAuthoritative);

	active_ts = sys_cpu_to_be64(active_ts);

	return encode_value(buffer, max, "at", sizeof("at") - 1, (char *)&active_ts,
			    sizeof(active_ts));
}

static int encode_bbr_entries(char *buffer, size_t max)
{
	int res;
	int encoded = 0;
	otBackboneRouterConfig config;
	const char *name;
	size_t val_len;
	uint16_t port = htons(TBR_BACKBONE_AGENT_BBR_PORT);
	otBackboneRouterState state = otBackboneRouterGetState(OT_INSTANCE);

	if (state != OT_BACKBONE_ROUTER_STATE_DISABLED) {
		otBackboneRouterGetConfig(OT_INSTANCE, &config);

		res = encode_value(buffer, max, "sq", sizeof("sq") - 1,
				   (char *)&config.mSequenceNumber,
				   sizeof(config.mSequenceNumber));
		if (res < 0) {
			return res;
		}

		encoded += res;
		max -= res;

		res = encode_value(buffer, max, "bb", sizeof("bb") - 1,
				   (char *)&port, sizeof(port));

		if (res < 0) {
			return res;
		}

		encoded += res;
		max -= res;
	}

	name = otThreadGetDomainName(OT_INSTANCE);

	val_len = strlen(name);
	val_len = (val_len > 0) ? val_len - 1 : val_len;

	res = encode_value(buffer, max, "dn", sizeof("dn") - 1, name, val_len);

	if (res < 0) {
		return res;
	}

	return encoded + res;
}

static int encode_omr_entry(char *buffer, size_t max)
{
	otIp6Prefix omrPrefix;
	otRoutePreference preference;
	otError error;
	char prefix[OT_IP6_PREFIX_SIZE + 1];

	error = otBorderRoutingGetFavoredOmrPrefix(OT_INSTANCE, &omrPrefix, &preference);

	if (error != OT_ERROR_NONE) {
		return 0;
	}

	prefix[0] = omrPrefix.mLength;
	memcpy(&prefix[1], omrPrefix.mPrefix.mFields.m8, (omrPrefix.mLength + 7) / 8);

	return encode_value(buffer, max, "omr", sizeof("omr") - 1, prefix, sizeof(prefix));
}

static void update_meshcop_service()
{
	char buff[TXT_BUFFER_SIZE];
	int n = 0;
	int res = 0;
	struct dns_sd_service_info_in service_info;

	/* There are no backbone IPv6 addresses to be advertised */
	if (addr_info_count == 0) {
		return;
	}

	memset(&service_info, 0, sizeof(struct dns_sd_service_info_in));

	if (ba_service) {
		dns_sd_service_unpublish(ba_service, K_FOREVER);
	}

	/* encode elements: */
	value_encoder encoders[] = {
		encode_vendor_name,
		encode_product_name,
		encode_network_name,
		encode_ext_pan_id,
		encode_thread_version,
		encode_ext_address,
		encode_state,
		encode_active_timestamp,
		encode_bbr_entries,
		encode_omr_entry,
		NULL,
	};

	for (size_t i = 0; encoders[i] != NULL; ++i) {
		res = encoders[i](&buff[n], sizeof(buff) - n);
		if (res < 0) {
			LOG_ERR("Failed to encode TXT record, encoder: %p", &encoders[i]);
			return;
		}

		n += res;
	}

	service_info.ttl = BA_SERVICE_TTL;
	service_info.instance = BA_INSTANCE_NAME;
	service_info.service = BA_SERVICE;
	service_info.subtype = NULL;
	service_info.proto = DNS_SD_SERVICE_PROTO_UDP;
	service_info.weight = 0;
	service_info.priority = 0;
	service_info.port = BA_DUMMY_PORT;
	service_info.txt_data = buff;
	service_info.txt_data_len = n;
	service_info.target = addr_infos[0].record;

	/* When Thread interface is disabled we keep using dummy port so service
	 * status can be advertised
	 */
	if (otBorderAgentGetState(OT_INSTANCE) != OT_BORDER_AGENT_STATE_STOPPED) {
		service_info.port = otBorderAgentGetUdpPort(OT_INSTANCE);
	}

	if (dns_sd_service_publish(&service_info, K_FOREVER, &ba_service) < 0) {
		LOG_ERR("Failed to publish Border Agent service");
	}
}

static struct tbr_address_info *find_address_info(const struct in6_addr *addr)
{
	struct in6_addr rec_addr;

	for (int i = 0; i < addr_info_count; ++i) {
		if (mdns_record_get_rdata_aaaa(addr_infos[i].record, &rec_addr, K_FOREVER) < 0) {
			LOG_WRN("Failed to read mDNS record info");

			return NULL;
		}

		if (memcmp(addr, &rec_addr, sizeof(struct in6_addr)) == 0) {
			return &addr_infos[i];
		}
	}

	return NULL;
}

static void add_address_info(const struct in6_addr *addr)
{
	struct tbr_address_info *info;
	int err;
	char addr_str[INET6_ADDRSTRLEN];

	if (addr_info_count == BA_MAX_AAAA_RECORDS) {
		LOG_WRN("Reached maximum number of the records");
		return;
	}

	info = &addr_infos[addr_info_count];
	info->address = addr;

	err = mdns_record_add_aaaa(BA_AAAA_RECORD_NAME, sizeof(BA_AAAA_RECORD_NAME) - 1,
				   BA_SERVICE_TTL, addr, K_FOREVER, &info->record);

	inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));

	if (err < 0) {
		LOG_DBG("Failed to allocate mDNS record for addr: %s, err: %d", addr_str, err);
		return;
	}

	LOG_DBG("Added AAAA record for addr: %s (%p)", addr_str, addr);

	if (addr_info_count > 0) {
		mdns_link_records(addr_infos[addr_info_count - 1].record, info->record, K_FOREVER);
	}

	addr_info_count++;
}

static void remove_address_info(struct tbr_address_info *info)
{
	int res;

	res = mdns_record_remove(info->record, K_FOREVER);

	/* If we cannot remove the record with K_FOREVER we are facing something really bad */
	__ASSERT(res == 0, "Failed to remove mDNS record");

	/* If there are any other address infos swap it with the last one */
	if (addr_info_count > 1) {
		memcpy(info, &addr_infos[addr_info_count], sizeof(struct tbr_address_info));
		memset(&addr_infos[addr_info_count], 0, sizeof(struct tbr_address_info));
	} else {
		memset(info, 0, sizeof(struct tbr_address_info));
	}

	addr_info_count--;
}

static void on_thread_state_changed(otChangedFlags flags, struct openthread_context *ot_context,
				    void *user_data)
{
	if (flags & (UPDATE_MESHCOP_FLAGS)) {
		update_meshcop_service();
	}
}

static struct openthread_state_changed_cb ot_state_chaged_cb = {
	.state_changed_cb = on_thread_state_changed
};

void border_agent_handle_address_event(const struct in6_addr *addr, bool is_added)
{
	struct tbr_address_info *info;

	if (net_ipv6_is_ll_addr(addr)) {
		/* Link-Local addresses are ignored */
		return;
	}

	k_mutex_lock(&ba_mutex, K_FOREVER);

	info = find_address_info(addr);

	if (!info && is_added) {
		add_address_info(addr);
	} else if (info && !is_added) {
		remove_address_info(info);
	}

	k_mutex_unlock(&ba_mutex);
}

void border_agent_init(void)
{
	addr_info_count = 0;
	ba_service = NULL;

	memset(addr_infos, 0, sizeof(addr_infos));
}

void border_agent_start(void)
{
	const struct tbr_context *ctx = tbr_get_context();
	struct net_if_addr *addresses = ctx->backbone_iface->config.ip.ipv6->unicast;

	for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; ++i) {
		if (addresses[i].address.family == AF_INET6 &&
		    addresses[i].addr_state == NET_ADDR_PREFERRED && addresses[i].is_used) {
			border_agent_handle_address_event(&addresses[i].address.in6_addr, true);
		}
	}

	update_meshcop_service();
	openthread_state_changed_cb_register(openthread_get_default_context(), &ot_state_chaged_cb);

	LOG_INF("Border Agent started");
}
