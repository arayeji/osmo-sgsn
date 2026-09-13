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
struct sgsn_pdp_ctx;

bool sgsn_api_trace_any_active(void);
bool sgsn_api_trace_active(const char *imsi);
void sgsn_api_trace_packet(const char *imsi, const char *proto, bool tx,
			   const uint8_t *data, size_t len);
void sgsn_api_trace_packet_mm(const struct sgsn_mm_ctx *mm, const char *proto,
			      bool tx, const uint8_t *data, size_t len);
void sgsn_api_trace_packet_pdp(const struct sgsn_pdp_ctx *pdp, const char *proto,
			       bool tx, const uint8_t *data, size_t len);
void sgsn_api_trace_packet_tlli(uint32_t tlli, const char *proto, bool tx,
				const uint8_t *data, size_t len);
#if BUILD_IU
struct ranap_ue_conn_ctx;
void sgsn_api_trace_packet_ue(const struct ranap_ue_conn_ctx *ue, const char *proto,
			      bool tx, const uint8_t *data, size_t len);
#endif
