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
