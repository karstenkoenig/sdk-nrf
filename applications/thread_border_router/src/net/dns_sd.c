#include "dns_sd.h"
#include "mdns_internal.h"

#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/net/buf.h>
#include <zephyr/net/net_core.h>
#include <zephyr/sys/slist.h>

#define MAX_SERVICES CONFIG_NRF_TBR_DNS_SD_NUM_SERVICES
#define SLAB_ALIGN 4

/* By RFC 6763: */
#define MAX_SERVICE_NAME_LEN 16 /* including the underscore */
#define MAX_INSTANCE_LEN 63
#define MAX_SUBTYPE_LEN 63

#define SERVICE_ENUM_STR "_services._dns-sd._udp.local"
#define SERVICE_ENUM_STR_LEN (sizeof(SERVICE_ENUM_STR) - 1)
#define SUBTYPE_LABEL_STR "_sub"
#define PROTO_TCP_LABEL_STR "_tcp"
#define PROTO_UDP_LABEL_STR "_udp"
#define DOMAIN_LABEL_STR "local"

#define SERVICE_NAME_BUFFER_SIZE 128
#define SERVICE_DATA_BUFFER_SIZE 256

LOG_MODULE_REGISTER(dns_sd, CONFIG_NRF_TBR_DNS_SD_LOG_LEVEL);

K_MEM_SLAB_DEFINE_STATIC(service_slab, sizeof(struct dns_sd_service), MAX_SERVICES, SLAB_ALIGN);

static sys_slist_t service_list;

static char service_name_buffer[SERVICE_NAME_BUFFER_SIZE];
static char service_data_buffer[SERVICE_DATA_BUFFER_SIZE];

static void free_service(struct dns_sd_service *service)
{
	if (!service) {
		return;
	}

	if (service->enumerator_ptr) {
		free_mdns_record(FROM_HANDLE(service->enumerator_ptr));
	}

	if (service->subtype_ptr) {
		free_mdns_record(FROM_HANDLE(service->subtype_ptr));
	}

	if (service->service_ptr) {
		free_mdns_record(FROM_HANDLE(service->service_ptr));
	}

	if (service->service_srv) {
		free_mdns_record(FROM_HANDLE(service->service_srv));
	}

	if (service->service_txt) {
		free_mdns_record(FROM_HANDLE(service->service_txt));
	}

	k_mem_slab_free(&service_slab, (void **)&service);
}

static inline bool is_service_handle_valid(struct dns_sd_service_handle *handle)
{
	const size_t last_item_pos = service_slab.block_size * (service_slab.num_blocks - 1);
	const size_t handle_offset = (uint32_t)handle - (uint32_t)service_slab.buffer;

	/* Verify handle's address and that it's used */
	return (handle) && ((void *)handle >= (void *)service_slab.buffer) &&
	       ((handle_offset % service_slab.block_size) == 0) &&
	       ((void *)handle <= (void *)(service_slab.buffer + last_item_pos)) &&
	       (FROM_HANDLE(handle)->name_len);
}

static bool is_service_info_valid(struct dns_sd_service_info_in *info)
{
	if (!info || !info->instance || !info->service || !info->target ||
	    (info->proto != DNS_SD_SERVICE_PROTO_UDP && info->proto != DNS_SD_SERVICE_PROTO_TCP) ||
	    !is_record_handle_valid(info->target)) {
		return false;
	}

	if (strlen(info->instance) > MAX_INSTANCE_LEN) {
		return false;
	}

	if (info->service[0] != '_' || strlen(info->service) > MAX_SERVICE_NAME_LEN) {
		return false;
	}

	if (info->subtype && (info->subtype[0] != '_' ||
			      strlen(info->subtype) > MAX_SUBTYPE_LEN)) {
		return false;
	}

	return true;
}

static size_t generate_name(char* buffer, size_t max, const struct dns_sd_service_info_in *info,
			    size_t *service_name_pos)
{
	size_t pos;
	const char *proto_str = info->proto == DNS_SD_SERVICE_PROTO_TCP ? PROTO_TCP_LABEL_STR :
									  PROTO_UDP_LABEL_STR;
	pos = snprintf(buffer, max, "%s.", info->instance);

	if (service_name_pos) {
		*service_name_pos = pos;
	}

	return pos + snprintf(&buffer[pos], max - pos, "%s.%s.local", info->service, proto_str);
}

static size_t generate_subtype_name(char* buffer, size_t max,
				    const struct dns_sd_service_info_in *info)
{
	const char *proto_str = info->proto == DNS_SD_SERVICE_PROTO_TCP ? PROTO_TCP_LABEL_STR :
									  PROTO_UDP_LABEL_STR;
	return snprintf(buffer, max, "%s.%s.%s.%s.local", info->subtype, SUBTYPE_LABEL_STR,
			info->service, proto_str);
}

static void link_service_records(struct dns_sd_service *service)
{
	/* Set links between the record: PTR -> SRV -> TXT ->A/AAAA. This way,
	 * matching PTR records will put the rest in additional section of
	 * mDNS response.
	 */
	service->service_ptr->next_add_rr = service->service_srv;
	service->service_srv->next_add_rr = service->service_txt;
	service->service_txt->next_add_rr = service->target;

	/* In matching with subtype also include all other records (so two
	 * records mark service's SRV record as their 'next').
	 */
	if (service->subtype_ptr) {
		service->subtype_ptr->next_add_rr = service->service_srv;
	}
}

void dns_sd_init(void)
{
	sys_slist_init(&service_list);
}

int dns_sd_service_publish(struct dns_sd_service_info_in *info, k_timeout_t timeout,
			   struct dns_sd_service_handle **output)
{
	struct dns_sd_service *service = NULL;
	struct mdns_record *target;
	size_t name_len;
	size_t data_len;
	size_t service_name_pos;
	struct srv_rdata srv_rdata;
	int res;

	if (!output || !is_service_info_valid(info)) {
		return -EINVAL;
	}

	if (lock_mdns_mutex(timeout) != 0) {
		return -EBUSY;
	}

	if (k_mem_slab_alloc(&service_slab, (void **)output, K_NO_WAIT) != 0) {
		LOG_DBG("Failed to allocate memory for DNS-SD service");
		goto failure;
	}

	service = *(struct dns_sd_service **)output;
	memset(service, 0, sizeof(struct dns_sd_service));

	name_len = generate_name(service_name_buffer, sizeof(service_name_buffer), info,
				 &service_name_pos);

	/* Allocate all records required to publish a given service:
	 * 1. PTR record for service type enumeration:
	 *    name: "_services._dns-sd._udp.local" answer: "<service>.<proto>.local"
	 * 2. PTR record of the service:
	 *    name: "<service>.<proto>.local" answer: "<instance>.<service>.<proto>.local"
	 * 3. SRV record of the service
	 *    name: "<instance>.<service>.<proto>.local" answer: weight, priority, port, and target
	 *    (name of A or AAAA record provided as parameter of this function)
	 * 4. TXT record of the service:
	 *    name: "<instance>.<service>.<proto>.local" answer: TXT data
	 * 5. PTR record with a subtype (if requested)
	 *    name: "<sub>._sub.<service>.<proto>.local" answer "<instance>.<service>.<proto>.local"
	 */
	service->enumerator_ptr = alloc_mdns_record(SERVICE_ENUM_STR, SERVICE_ENUM_STR_LEN,
						    info->ttl, MDNS_RECORD_TYPE_PTR, NULL, 0,
						    &service_name_buffer[service_name_pos],
						    name_len - service_name_pos);
	if (!service->enumerator_ptr) {
		LOG_DBG("Failed to allocate record for enumeration");
		goto failure;
	}

	service->service_ptr = alloc_mdns_record(&service_name_buffer[service_name_pos],
						 name_len - service_name_pos, info->ttl,
						 MDNS_RECORD_TYPE_PTR, NULL, 0, service_name_buffer,
						 name_len);
	if (!service->service_ptr) {
		LOG_DBG("Failed to allocate PTR record");
		goto failure;
	}

	srv_rdata.weight = info->weight;
	srv_rdata.priority = info->priority;
	srv_rdata.port = info->port;

	target = FROM_HANDLE(info->target);
	service->target = target;

	res = mdns_record_get_name(info->target, service_data_buffer, sizeof(service_data_buffer),
				   K_NO_WAIT);

	if (res <= 0) {
		LOG_DBG("Failed to get target's name");
		goto failure;
	}

	service->service_srv = alloc_mdns_record(service_name_buffer, name_len, info->ttl,
						MDNS_RECORD_TYPE_SRV, &srv_rdata,
						sizeof(srv_rdata), service_data_buffer, res);
	if (!service->service_srv) {
		LOG_DBG("Failed to allocate SRV record");
		goto failure;
	}

	/* According to the RFC we must always add a corresponding TXT record even if its data
	 * length is 0 in order to control the record's TTL.
	 */
	service->service_txt = alloc_mdns_record(service_name_buffer, name_len, info->ttl,
						 MDNS_RECORD_TYPE_TXT, info->txt_data,
						 info->txt_data_len, NULL, 0);
	if (!service->service_txt) {
		LOG_DBG("Failed to allocate TXT record");
		goto failure;
	}

	if (info->subtype) {
		/* In few following steps swap usages of data buffers to avoid unnecessary copying
		 * of th service's name to the data buffer.
		 */
		data_len = generate_subtype_name(service_data_buffer, sizeof(service_data_buffer),
						 info);

		service->subtype_ptr = alloc_mdns_record(service_data_buffer, data_len,
							info->ttl, MDNS_RECORD_TYPE_PTR, NULL, 0,
							service_name_buffer, name_len);

		if (!service->subtype_ptr) {
			LOG_DBG("Failed to allocate subtype record");
			goto failure;
		}
	}

	link_service_records(service);

	sys_slist_append(&service_list, &service->node);

	unlock_mdns_mutex();

	return 0;
failure:
	free_service(service);
	unlock_mdns_mutex();

	/* If execution got to this point it means that we could not allocate new record */
	return -EFAULT;
}

int dns_sd_service_unpublish(struct dns_sd_service_handle *handle, k_timeout_t timeout)
{
	struct dns_sd_service *service = (struct dns_sd_service *)handle;

	if (!handle || !is_service_handle_valid(handle)) {
		return -EINVAL;
	}

	if (lock_mdns_mutex(timeout) != 0) {
		return -EBUSY;
	}

	if (!sys_slist_find_and_remove(&service_list, &service->node)) {
		unlock_mdns_mutex();
		return -EINVAL;
	}

	free_service(service);

	unlock_mdns_mutex();

	return 0;
}

int dns_sd_service_for_each(dns_sd_service_cb_t callback, void *user_data, k_timeout_t timeout)
{
	struct dns_sd_service *current;
	struct dns_sd_service *next;
	int res = 0;

	if (!callback) {
		return -EINVAL;
	}

	if (lock_mdns_mutex(timeout) != 0) {
		return -EBUSY;
	}

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&service_list, current, next, node) {
		enum net_verdict verdict = callback((struct dns_sd_service_handle *)current,
						    user_data);

		res++;
		if (verdict == NET_OK) {
			goto done;
		}
	}

done:
	unlock_mdns_mutex();
	return res;
}

int dns_sd_service_get_info(struct dns_sd_service_handle *handle,
			    struct dns_sd_service_info_out *info, k_timeout_t timeout)
{
	struct dns_sd_service *service;
	struct srv_rdata srv_rdata;
	size_t len;

	if (!handle || !is_service_handle_valid(handle) || !info) {
		return -EINVAL;
	}

	service = (struct dns_sd_service *)handle;

	if (lock_mdns_mutex(timeout) != 0) {
		return -EBUSY;
	}

	if (info->name.buf && info->name.len_max) {
		info->name.len_read = mdns_record_get_name(TO_HANDLE(service->service_srv),
							   info->name.buf, info->name.len_max,
							   K_NO_WAIT);
	}

	if (service->subtype_ptr && info->subtype.buf && info->subtype.len_max) {
		/* subtype is only a part of the name, find a position of its end */
		mdns_record_get_name(TO_HANDLE(service->subtype_ptr), service_name_buffer,
				     sizeof(service_name_buffer) - 1, K_NO_WAIT);

		len = strchr(service_name_buffer, '.') - service_name_buffer;
		info->subtype.len_read = MIN(len, info->subtype.len_max);

		memcpy(info->subtype.buf, service_name_buffer, info->subtype.len_read);
	}

	if (service->service_txt->rdata_len && info->txt_data.buf && info->txt_data.len_max) {
		net_buf_linearize(info->txt_data.buf, info->txt_data.len_max,
				  service->service_txt->rdata, 0, service->service_txt->rdata_len);
	}

	net_buf_linearize(&srv_rdata, sizeof(srv_rdata), service->service_srv->rdata, 0,
			  sizeof(srv_rdata));

	info->ttl = service->service_ptr->ttl;
	info->weight = srv_rdata.weight;
	info->priority = srv_rdata.priority;
	info->port = srv_rdata.port;
	info->target = TO_HANDLE(service->target);

	unlock_mdns_mutex();

	return 0;
}
