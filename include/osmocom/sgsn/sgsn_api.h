#pragma once

#include <stdint.h>
#include <netinet/in.h>

struct sgsn_instance;

#define SGSN_API_DEFAULT_PORT 8088

struct sgsn_api_config {
	struct in_addr bind_addr;
	uint16_t port;
	char *token;
};

int sgsn_api_init(struct sgsn_instance *inst);
void sgsn_api_shutdown(void);

struct sgsn_mm_ctx;

bool sgsn_api_trace_active(const char *imsi);
void sgsn_api_trace_packet(const char *imsi, const char *proto, bool tx,
			   const uint8_t *data, size_t len);
void sgsn_api_trace_packet_mm(const struct sgsn_mm_ctx *mm, const char *proto,
			      bool tx, const uint8_t *data, size_t len);
