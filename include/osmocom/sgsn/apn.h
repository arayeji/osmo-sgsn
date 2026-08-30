#pragma once

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>

struct sgsn_ggsn_ctx;

#define GSM_APN_LENGTH 102

struct apn_ctx {
	struct llist_head list;
	struct sgsn_ggsn_ctx *ggsn;
	char *name;
	char *imsi_prefix;
	char *description;
};

struct apn_ctx *sgsn_apn_ctx_find_alloc(const char *name, const char *imsi_prefix);
void sgsn_apn_ctx_free(struct apn_ctx *actx);
struct apn_ctx *sgsn_apn_ctx_by_name(const char *name, const char *imsi_prefix);
struct apn_ctx *sgsn_apn_ctx_match(const char *name, const char *imsi_prefix);
/* True if config has "apn * imsi-prefix <imsi> …" for this IMSI */
bool sgsn_apn_ctx_allow_any_for_imsi(const char *imsi);
