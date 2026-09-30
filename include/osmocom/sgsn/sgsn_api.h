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

#define SGSN_API_TRACE_LINK_MAX 256

bool sgsn_api_trace_any_active(void);
bool sgsn_api_trace_active(const char *imsi);
/* link: optional " link=..." description of the transport the packet used */
void sgsn_api_trace_packet(const char *imsi, const char *proto, bool tx,
			   const char *link, const uint8_t *data, size_t len);
/* Derives the link from the MM context's current RAN connection. */
void sgsn_api_trace_packet_mm(const struct sgsn_mm_ctx *mm, const char *proto,
			      bool tx, const uint8_t *data, size_t len);
/* mm may be NULL; it is then resolved from the TLLI. */
void sgsn_api_trace_packet_gb(const struct sgsn_mm_ctx *mm, uint32_t tlli, uint16_t nsei,
			      const char *proto, bool tx, const uint8_t *data, size_t len);
const char *sgsn_api_trace_link_gb(char *buf, size_t buf_len, uint16_t nsei, bool tx);
#if BUILD_IU
struct ranap_ue_conn_ctx;
void sgsn_api_trace_packet_ue(const struct ranap_ue_conn_ctx *ue, const char *proto,
			      bool tx, const uint8_t *data, size_t len);
const char *sgsn_api_trace_link_iu(char *buf, size_t buf_len,
				   const struct ranap_ue_conn_ctx *ue, bool tx);
#endif
