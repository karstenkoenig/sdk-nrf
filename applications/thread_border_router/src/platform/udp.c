/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/** @file
 * @brief OpenThread platform - UDP
 */

#include "tbr.h"

#include <ipv6.h>
#include <openthread/message.h>
#include <openthread/platform/udp.h>

#include <sys/errno.h>

#include <zephyr/logging/log.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/socket.h>

#define MAX_UDP_SIZE CONFIG_NRF_TBR_MAX_UDP_DGRAM_SIZE

LOG_MODULE_DECLARE(nrf_tbr, CONFIG_NRF_TBR_LOG_LEVEL);

K_MUTEX_DEFINE(udp_mutex);

static uint8_t dgram_buffer[MAX_UDP_SIZE];

static void udp_sent_cb(struct net_context *context, int status, void *user_data)
{
	LOG_DBG("OT socket (%p) - %s: %d", user_data,
		(status < 0 ? "transmission failed, error" : "bytes sent"), status);
}

static void udp_received_cb(struct net_context *context, struct net_pkt *pkt,
			    union net_ip_header *ip_hdr, union net_proto_header *proto_hdr,
			    int status, void *user_data)
{
	otError error = OT_ERROR_NONE;
	otMessageSettings msg_settings;
	otMessageInfo msg_info;
	otMessage *msg;
	size_t len;
	struct tbr_context *tbr_ctx = tbr_get_context();
	uint8_t *pos;
	otUdpSocket *socket = (otUdpSocket *)user_data;
	struct net_pkt_cursor payload_start;
	bool ow_flag;
	int res;

	__ASSERT(pkt, "udp_received_cb() without a packet");
	__ASSERT(socket, "udp_received_cb() without a socket");

	if (status != 0) {
		LOG_DBG("udp_received_cb() - invalid status");
	}

	msg_settings.mLinkSecurityEnabled = false;
	msg_settings.mPriority = OT_MESSAGE_PRIORITY_NORMAL;

	memcpy(msg_info.mSockAddr.mFields.m8, ip_hdr->ipv6->dst, NET_IPV6_ADDR_SIZE);
	memcpy(msg_info.mPeerAddr.mFields.m8, ip_hdr->ipv6->src, NET_IPV6_ADDR_SIZE);

	msg_info.mPeerPort = ntohs(proto_hdr->udp->src_port);
	msg_info.mSockPort = ntohs(proto_hdr->udp->dst_port);
	msg_info.mIsHostInterface = (pkt->iface == tbr_ctx->backbone_iface);

	msg = otUdpNewMessage(tbr_ctx->ot->instance, &msg_settings);

	if (!msg) {
		return;
	}

	net_pkt_cursor_backup(pkt, &payload_start);
	ow_flag = net_pkt_is_being_overwritten(pkt);

	net_pkt_set_overwrite(pkt, true);

	do {
		len = net_pkt_get_contiguous_len(pkt);
		pos = pkt->cursor.pos;

		error = otMessageAppend(msg, pos, len);

		res = net_pkt_skip(pkt, len);

	} while (len && error == OT_ERROR_NONE && res == 0);

	if (error == OT_ERROR_NONE) {
		LOG_DBG("udp_received_ch() - passing message to OT stack");
		socket->mHandler(socket->mContext, msg, &msg_info);
	}

	net_pkt_set_overwrite(pkt, ow_flag);
	net_pkt_cursor_restore(pkt, &payload_start);

	otMessageFree(msg);

	return;
}

otError otPlatUdpSocket(otUdpSocket *aUdpSocket)
{
	struct net_context *net_ctx;
	int res;

	if (!aUdpSocket) {
		return OT_ERROR_INVALID_ARGS;
	}

	res = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, &net_ctx);

	if (res < 0) {
		LOG_ERR("Failed to allocate network context, error: %d", res);
		return OT_ERROR_FAILED;
	}

	aUdpSocket->mHandle = net_ctx;

	LOG_DBG("OT socket (%p) - opened", aUdpSocket);

	return OT_ERROR_NONE;
}

otError otPlatUdpClose(otUdpSocket *aUdpSocket)
{
	if (!aUdpSocket || !aUdpSocket->mHandle) {
		return OT_ERROR_INVALID_ARGS;
	}

	LOG_DBG("OT socket (%p) - closing", aUdpSocket);

	/* Without CONFIG_NET_OFFLOAD this function call always succeeds */
	net_context_put(aUdpSocket->mHandle);

	return OT_ERROR_NONE;
}

otError otPlatUdpBind(otUdpSocket *aUdpSocket)
{
	int res;
	char addrstr[INET6_ADDRSTRLEN];
	struct sockaddr addr;

	if (!aUdpSocket || !aUdpSocket->mHandle) {
		return OT_ERROR_INVALID_ARGS;
	}

	net_sin6(&addr)->sin6_family = AF_INET6;
	net_sin6(&addr)->sin6_port = htons(aUdpSocket->mSockName.mPort);

	net_ipv6_addr_copy_raw((uint8_t *)&net_sin6(&addr)->sin6_addr,
				(uint8_t *)&aUdpSocket->mSockName.mAddress);

	res = net_context_bind(aUdpSocket->mHandle, &addr, sizeof(struct sockaddr_in6));
	if (res < 0) {
		LOG_WRN("OT socket (%p) - failed to bind", aUdpSocket);

		return OT_ERROR_FAILED;
	}

	res = net_context_recv(aUdpSocket->mHandle, udp_received_cb, K_NO_WAIT, aUdpSocket);
	if (res < 0) {
		LOG_WRN("OT socket (%p) - failed to enable receiving", aUdpSocket);

		net_context_put(aUdpSocket->mHandle);

		return OT_ERROR_FAILED;
	}

	inet_ntop(net_sin6(&addr)->sin6_family, &net_sin6(&addr)->sin6_addr,
		  addrstr, sizeof(addrstr));

	LOG_DBG("OT socket (%p) - bound to [%s]:%u", aUdpSocket,
		addrstr, ntohs(net_sin6(&addr)->sin6_port));

	return OT_ERROR_NONE;
}

otError otPlatUdpBindToNetif(otUdpSocket *aUdpSocket, otNetifIdentifier aNetifIdentifier)
{
	struct tbr_context *ctx = tbr_get_context();
	struct net_context *net_ctx;
	struct net_if *ot_iface;

	if (!aUdpSocket || !aUdpSocket->mHandle) {
		return OT_ERROR_INVALID_ARGS;
	}
	net_ctx = aUdpSocket->mHandle;

	switch(aNetifIdentifier) {
	case OT_NETIF_UNSPECIFIED:
		/* We cannot set iface with net_context_set_iface()
		 * as it would cause an assert. However, we can
		 * only clear the flag to remove the binding
		 */
		net_ctx->flags &= ~NET_CONTEXT_BOUND_TO_IFACE;
		break;
	case OT_NETIF_THREAD:
		ot_iface = openthread_get_default_context()->iface;

		if (!ot_iface) {
			return OT_ERROR_FAILED;
		}

		net_context_set_iface(net_ctx, ot_iface);
		net_ctx->flags |= NET_CONTEXT_BOUND_TO_IFACE;
		break;
	case OT_NETIF_BACKBONE:
		if (!ctx->backbone_iface) {
			return OT_ERROR_FAILED;
		}

		net_context_set_iface(net_ctx, ctx->backbone_iface);
		net_ctx->flags |= NET_CONTEXT_BOUND_TO_IFACE;
		break;
	default:
		__ASSERT(false, "Invalid netif identifier");
		break;
	}

	return OT_ERROR_NONE;
}

otError otPlatUdpConnect(otUdpSocket *aUdpSocket)
{
	struct sockaddr addr;
	int res;

	if (!aUdpSocket || !aUdpSocket->mHandle) {
		return OT_ERROR_INVALID_ARGS;
	}

	net_sin6(&addr)->sin6_family = AF_INET6;
	net_sin6(&addr)->sin6_port = aUdpSocket->mPeerName.mPort;

	net_ipv6_addr_copy_raw((uint8_t *)&net_sin6(&addr)->sin6_addr,
			       (uint8_t *)&aUdpSocket->mPeerName.mAddress);

	res = net_context_connect(aUdpSocket->mHandle, &addr, sizeof(struct sockaddr_in6),
				  /* callback */ NULL, K_NO_WAIT, aUdpSocket);

	if (res < 0) {
		LOG_ERR("OT socket (%p) - UDP connect failed: %d", aUdpSocket, res);
		return OT_ERROR_FAILED;
	}

	return OT_ERROR_NONE;;
}

otError otPlatUdpSend(otUdpSocket *aUdpSocket, otMessage *aMessage,
		      const otMessageInfo *aMessageInfo)
{
	int res;
	size_t len;
	struct sockaddr addr;
	socklen_t addrlen;

	if (!aUdpSocket || !aUdpSocket->mHandle || !aMessage || !aMessageInfo) {
		return OT_ERROR_INVALID_ARGS;
	}

	len = otMessageGetLength(aMessage);

	if (len > MAX_UDP_SIZE) {
		return OT_ERROR_NO_BUFS;
	}

	k_mutex_lock(&udp_mutex, K_FOREVER);

	if (len != otMessageRead(aMessage, 0, dgram_buffer, len)) {
		k_mutex_unlock(&udp_mutex);
		return OT_ERROR_FAILED;
	}

	LOG_DBG("OT socket (%p) - sending UDP datagram with len = %u, ", aUdpSocket, len);

	net_sin6(&addr)->sin6_family = AF_INET6;
	net_sin6(&addr)->sin6_port = htons(aMessageInfo->mPeerPort);
	addrlen = sizeof(struct sockaddr_in6);

	net_ipv6_addr_copy_raw((uint8_t *)&net_sin6(&addr)->sin6_addr,
			       (uint8_t *)&aMessageInfo->mPeerAddr);

	res = net_context_sendto(aUdpSocket->mHandle, dgram_buffer, len, &addr, addrlen,
				 udp_sent_cb, K_NO_WAIT, aUdpSocket);

	k_mutex_unlock(&udp_mutex);

	if (res < 0) {
		LOG_ERR("OT socket (%p) - failed to send UDP datagram, error: %d",
			aUdpSocket, res);
		return OT_ERROR_FAILED;
	}

	return OT_ERROR_NONE;
}

otError otPlatUdpJoinMulticastGroup(otUdpSocket        *aUdpSocket,
				    otNetifIdentifier   aNetifIdentifier,
				    const otIp6Address *aAddress)
{
	struct tbr_context *ctx = tbr_get_context();
	struct in6_addr maddr;
	char addrstr[INET6_ADDRSTRLEN];
	int res;

	if (!aUdpSocket || !aUdpSocket->mHandle || !aAddress ||
	    aNetifIdentifier != OT_NETIF_BACKBONE) {
		return OT_ERROR_INVALID_ARGS;
	}

	if (!ctx->backbone_iface) {
		return OT_ERROR_FAILED;
	}

	net_ipv6_addr_copy_raw((uint8_t *)&maddr, (uint8_t *)aAddress);

	res = net_ipv6_mld_join(ctx->backbone_iface, &maddr);

	inet_ntop(AF_INET6, &maddr, addrstr, sizeof(addrstr));

	if (res < 0 && res != -EALREADY) {
		LOG_ERR("OT socket (%p) - failed to join multicast group [%s], error:  %d",
			aUdpSocket, addrstr, res);
		return OT_ERROR_FAILED;
	}

	return OT_ERROR_NONE;
}

otError otPlatUdpLeaveMulticastGroup(otUdpSocket        *aUdpSocket,
				     otNetifIdentifier   aNetifIdentifier,
				     const otIp6Address *aAddress)
{
	struct tbr_context *ctx = tbr_get_context();
	struct in6_addr maddr;
	char addrstr[INET6_ADDRSTRLEN];
	int res;

	if (!aUdpSocket || !aUdpSocket->mHandle || !aAddress ||
	    aNetifIdentifier != OT_NETIF_BACKBONE) {
		return OT_ERROR_INVALID_ARGS;
	}

	if (!ctx->backbone_iface) {
		return OT_ERROR_FAILED;
	}

	net_ipv6_addr_copy_raw((uint8_t *)&maddr, (uint8_t *)aAddress);

	res = net_ipv6_mld_leave(ctx->backbone_iface, &maddr);

	inet_ntop(AF_INET6, &maddr, addrstr, sizeof(addrstr));

	if (res < 0) {
		LOG_ERR("OT socket (%p) - failed to leave multicast group [%s], error: %d",
			aUdpSocket, addrstr, res);
		return OT_ERROR_FAILED;
	}

	return OT_ERROR_NONE;
}
