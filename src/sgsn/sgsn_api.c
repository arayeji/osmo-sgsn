/* Embedded HTTP REST API for OsmoSGSN */

#include <stdarg.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <pthread.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/base64.h>
#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/pdp.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp_mme.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/sgsn_api.h>
#include <osmocom/gsupclient/gsup_client.h>
#if BUILD_IU
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/iu_rnc_fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/osmo_ss7.h>
#endif

#define API_CONN_BUF_SIZE (64 * 1024)
#define SGSN_API_TRACE_PKT_MAX 4096
#define SGSN_API_MAX_CLIENTS 16
#define SGSN_API_IDLE_SEC 5
#define SGSN_API_POLL_MS 500
#define SGSN_API_MAIN_WAIT_SEC 10
#define SGSN_API_SND_TIMEOUT_SEC 5
#define SGSN_API_PDP_DEFAULT_LIMIT 100
#define SGSN_API_PDP_MAX_LIMIT 1000
#define SGSN_API_PDP_MAX_SCAN 65535
#define SGSN_API_MM_MAX_PDP 16

struct api_pdp_list_query {
	char imsi_prefix[GSM23003_IMSI_MAX_DIGITS + 1];
	unsigned limit;
	bool has_imsi_prefix;
};

struct api_conn {
	int fd;
	char buf[API_CONN_BUF_SIZE];
	size_t len;
	time_t last_activity;
	char *resp;		/* malloc'd HTTP response, written by the API thread */
	size_t resp_len;
};

/* The API thread only does socket I/O. Parsed requests are handed to the
 * main loop through g_api_wake_pipe, because talloc, the logging core and
 * all SGSN state are single-threaded. Only malloc/free, stdio and the
 * g_api_lock-protected job fields may be used from the API thread. */
enum api_job_state {
	API_JOB_NONE,
	API_JOB_PENDING,
	API_JOB_RUNNING,
	API_JOB_DONE,
};

static int g_api_listen_fd = -1;
static void *g_api_ctx;
static unsigned g_api_client_count;
static struct api_conn *g_api_conns[SGSN_API_MAX_CLIENTS];
static pthread_t g_api_thread;
static volatile bool g_api_thread_run;
static pthread_mutex_t g_api_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_api_job_cond = PTHREAD_COND_INITIALIZER;
static struct api_conn *g_api_job_conn;
static enum api_job_state g_api_job_state;
static int g_api_wake_pipe[2] = { -1, -1 };
static struct osmo_fd g_api_wake_ofd;
static pthread_mutex_t g_api_trace_lock = PTHREAD_MUTEX_INITIALIZER;

static bool api_enabled(void)
{
	return sgsn && sgsn->cfg.api.token && sgsn->cfg.api.token[0];
}

static const char *pdp_addr_str(uint8_t *pdpa, uint8_t len, char *out, size_t out_len)
{
	if (!pdpa || len < 2) {
		osmo_strlcpy(out, "none", out_len);
		return out;
	}
	if ((pdpa[0] & 0x0f) == PDP_TYPE_ORG_IETF && pdpa[1] == PDP_TYPE_N_IETF_IPv4 && len >= 6) {
		osmo_strlcpy(out, "IPv4:", out_len);
		inet_ntop(AF_INET, pdpa + 2, out + 5, out_len - 5);
		return out;
	}
	osmo_strlcpy(out, "invalid", out_len);
	return out;
}

static void json_escape(const char *in, char *out, size_t out_len)
{
	size_t o = 0;

	if (!in) {
		out[0] = '\0';
		return;
	}

	for (; *in && o + 2 < out_len; in++) {
		if (*in == '"' || *in == '\\') {
			out[o++] = '\\';
			out[o++] = *in;
		} else if (*in >= 0x20 && *in < 0x7f)
			out[o++] = *in;
	}
	out[o] = '\0';
}

#if BUILD_IU
static void api_fmt_iu_rnc_state_cached(int state, char *out, size_t out_len)
{
	if (!out || !out_len)
		return;
	switch (state) {
	case IU_RNC_ST_READY:
		snprintf(out, out_len, "READY");
		break;
	case IU_RNC_ST_WAIT_RX_RESET:
		snprintf(out, out_len, "WAIT_RX_RESET");
		break;
	case IU_RNC_ST_WAIT_RX_RESET_ACK:
		snprintf(out, out_len, "WAIT_RX_RESET_ACK");
		break;
	case IU_RNC_ST_DISCARDING:
		snprintf(out, out_len, "DISCARDING");
		break;
	default:
		snprintf(out, out_len, "UNKNOWN");
		break;
	}
}

static void api_fmt_rnc_id(const struct osmo_rnc_id *id, char *out, size_t out_len)
{
	if (!out || !out_len)
		return;
	if (!id) {
		out[0] = '\0';
		return;
	}
	snprintf(out, out_len, "%u-%u-%u", id->plmn.mcc, id->plmn.mnc, id->rnc_id);
}

static void api_fmt_sccp_pc(const struct osmo_sccp_addr *addr, char *out, size_t out_len)
{
	if (!out || !out_len)
		return;
	if (!addr) {
		out[0] = '\0';
		return;
	}
	snprintf(out, out_len, "pc=%u", addr->pc);
}

#endif

static char *json_append(char *cur, char *start, size_t *space, const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

static char *json_append(char *cur, char *start, size_t *space, const char *fmt, ...)
{
	va_list ap;
	int rc;

	(void)start;
	if (*space == 0)
		return cur;

	va_start(ap, fmt);
	rc = vsnprintf(cur, *space, fmt, ap);
	va_end(ap);

	if (rc < 0)
		return cur;
	if ((size_t)rc >= *space) {
		*space = 0;
		return cur;
	}
	cur += rc;
	*space -= rc;
	return cur;
}

static uint64_t api_ctr_current(const struct rate_ctr_group *grp, const char *name)
{
	const struct rate_ctr *ctr;

	if (!grp || !name)
		return 0;
	ctr = rate_ctr_get_by_name(grp, name);
	return ctr ? ctr->current : 0;
}

static unsigned api_gtp_queue_backlog(const struct gsn_t *gsn)
{
	int diff;

	if (!gsn)
		return 0;
	diff = gsn->seq_last - gsn->seq_first;
	if (diff < 0)
		diff += 65536;
	return (unsigned)diff;
}

static unsigned api_stat_count(unsigned int idx)
{
	const struct osmo_stat_item *it;

	if (!sgsn || !sgsn->statg)
		return 0;
	it = osmo_stat_item_group_get_item(sgsn->statg, idx);
	if (!it)
		return 0;
	return (unsigned)osmo_stat_item_get_last(it);
}

static void api_timestamp_iso8601(char *buf, size_t buflen)
{
	time_t now = time(NULL);
	struct tm tm;

	buf[0] = '\0';
	if (!buflen)
		return;
	if (!gmtime_r(&now, &tm))
		return;
	strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

#if BUILD_IU
struct api_sigtran_ctx {
	char *asps;
	size_t asps_space;
	char *esc;
	struct osmo_ss7_instance *ss7;
	unsigned asp_up;
	uint64_t msu_rx;
	uint64_t msu_tx;
	uint64_t msu_disc;
	bool first_asp;
};

static int api_sigtran_group_cb(struct rate_ctr_group *grp, void *_ctx)
{
	struct api_sigtran_ctx *ctx = _ctx;
	struct osmo_ss7_asp *asp;
	uint64_t rx, tx, disc;
	char *asps_cur;
	size_t asps_space;

	if (!ctx || !ctx->ss7 || !grp || !grp->name || !grp->name[0])
		return 0;

	asp = osmo_ss7_asp_find_by_name(ctx->ss7, grp->name);
	if (!asp)
		return 0;

	rx = api_ctr_current(grp, "rx:msu:total");
	tx = api_ctr_current(grp, "tx:msu:total");
	disc = api_ctr_current(grp, "rx:packets:unknown");
	ctx->msu_rx += rx;
	ctx->msu_tx += tx;
	ctx->msu_disc += disc;
	if (osmo_ss7_asp_active(asp))
		ctx->asp_up++;

	if (!ctx->asps)
		return 0;

	asps_cur = ctx->asps;
	asps_space = ctx->asps_space;
	if (!ctx->first_asp)
		asps_cur = json_append(asps_cur, ctx->asps, &asps_space, ",");
	ctx->first_asp = false;

	json_escape(grp->name, ctx->esc, 512);
	asps_cur = json_append(asps_cur, ctx->asps, &asps_space, "{\"name\":\"%s\",", ctx->esc);
	asps_cur = json_append(asps_cur, ctx->asps, &asps_space,
			       "\"rx_packets\":%" PRIu64 ",\"tx_packets\":%" PRIu64 ",",
			       rx, tx);
	asps_cur = json_append(asps_cur, ctx->asps, &asps_space, "\"up\":%s}",
			       osmo_ss7_asp_active(asp) ? "true" : "false");
	ctx->asps_space = asps_space;
	return 0;
}
#endif

static char *build_stats_json(void)
{
	unsigned mm_count = 0, pdp_count = 0;
	uint64_t attach_req = 0, attach_acc = 0, attach_rej = 0, pdp_act = 0;
	char ts[32];
#if BUILD_IU
	int32_t iu_active = 0, iu_total = 0;
#endif

	if (!sgsn)
		return NULL;

	mm_count = api_stat_count(SGSN_STAT_MM_CONTEXTS);
	pdp_count = api_stat_count(SGSN_STAT_PDP_CONTEXTS);

	if (sgsn->rate_ctrs) {
		attach_req = api_ctr_current(sgsn->rate_ctrs, "gprs:attach_requested");
		attach_acc = api_ctr_current(sgsn->rate_ctrs, "gprs:attach_accepted");
		attach_rej = api_ctr_current(sgsn->rate_ctrs, "gprs:attach_rejected");
		pdp_act = api_ctr_current(sgsn->rate_ctrs, "pdp:activate_accepted");
	}

#if BUILD_IU
	if (sgsn->statg) {
		const struct osmo_stat_item *it;

		it = osmo_stat_item_group_get_item(sgsn->statg, SGSN_STAT_IU_PEERS_ACTIVE);
		if (it)
			iu_active = osmo_stat_item_get_last(it);
		it = osmo_stat_item_group_get_item(sgsn->statg, SGSN_STAT_IU_PEERS_TOTAL);
		if (it)
			iu_total = osmo_stat_item_get_last(it);
	}
#endif

	api_timestamp_iso8601(ts, sizeof(ts));

#if BUILD_IU
	return talloc_asprintf(g_api_ctx,
			       "{\"timestamp\":\"%s\","
			       "\"mm_contexts\":%u,"
			       "\"pdp_contexts\":%u,"
			       "\"iu\":{\"active_peers\":%d,\"total_peers_seen\":%d},"
			       "\"network\":{\"iu_rnc\":[]},"
			       "\"gmm\":{\"attach_requests\":%" PRIu64 ","
			       "\"attach_accepts\":%" PRIu64 ","
			       "\"attach_rejects\":%" PRIu64 ","
			       "\"pdp_activations\":%" PRIu64 "}}",
			       ts, mm_count, pdp_count, iu_active, iu_total,
			       attach_req, attach_acc, attach_rej, pdp_act);
#else
	return talloc_asprintf(g_api_ctx,
			       "{\"timestamp\":\"%s\","
			       "\"mm_contexts\":%u,"
			       "\"pdp_contexts\":%u,"
			       "\"iu\":{\"active_peers\":0,\"total_peers_seen\":0},"
			       "\"network\":{\"iu_rnc\":[]},"
			       "\"gmm\":{\"attach_requests\":%" PRIu64 ","
			       "\"attach_accepts\":%" PRIu64 ","
			       "\"attach_rejects\":%" PRIu64 ","
			       "\"pdp_activations\":%" PRIu64 "}}",
			       ts, mm_count, pdp_count,
			       attach_req, attach_acc, attach_rej, pdp_act);
#endif
}

static char *build_counts_json(void)
{
	unsigned mm_count = 0, pdp_count = 0;
	char *json;

	if (!sgsn)
		return NULL;

	mm_count = api_stat_count(SGSN_STAT_MM_CONTEXTS);
	pdp_count = api_stat_count(SGSN_STAT_PDP_CONTEXTS);

	json = talloc_asprintf(g_api_ctx,
			       "{\"mm_context_count\":%u,\"pdp_context_count\":%u,\"active_pdp_count\":%u}",
			       mm_count, pdp_count, pdp_count);
	return json;
}

static bool api_valid_imsi_prefix(const char *prefix)
{
	size_t n = 0;
	const char *p;

	if (!prefix || !prefix[0])
		return false;
	for (p = prefix; *p; p++, n++) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return n >= 1 && n <= GSM23003_IMSI_MAX_DIGITS;
}

static bool api_query_get(const char *query, const char *key, char *val, size_t val_len)
{
	size_t key_len;

	if (!query || !key || !val || val_len == 0)
		return false;

	key_len = strlen(key);
	while (*query) {
		const char *amp = strchr(query, '&');
		size_t pair_len = amp ? (size_t)(amp - query) : strlen(query);
		const char *eq = memchr(query, '=', pair_len);

		if (eq && (size_t)(eq - query) == key_len &&
		    memcmp(query, key, key_len) == 0) {
			size_t vlen = pair_len - key_len - 1;

			if (vlen >= val_len)
				vlen = val_len - 1;
			memcpy(val, eq + 1, vlen);
			val[vlen] = '\0';
			return true;
		}
		if (!amp)
			break;
		query = amp + 1;
	}
	return false;
}

static bool api_valid_imsi(const char *imsi)
{
	size_t n = 0;
	const char *p;

	if (!imsi || !imsi[0])
		return false;
	for (p = imsi; *p; p++, n++) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return n >= 5 && n <= GSM23003_IMSI_MAX_DIGITS;
}

static bool api_parse_include_pdp_query(const char *query, bool *include_pdp)
{
	char val[16];

	if (!include_pdp)
		return false;
	*include_pdp = true;
	if (!api_query_get(query, "include_pdp", val, sizeof(val)))
		return true;
	if (!strcasecmp(val, "false") || !strcasecmp(val, "0") || !strcasecmp(val, "no")) {
		*include_pdp = false;
		return true;
	}
	if (!strcasecmp(val, "true") || !strcasecmp(val, "1") || !strcasecmp(val, "yes")) {
		*include_pdp = true;
		return true;
	}
	return false;
}

static void api_mm_ran_info(const struct sgsn_mm_ctx *mm, uint32_t *id_out,
			    const char **state_out)
{
	*id_out = 0;
	*state_out = "unknown";

	if (!mm)
		return;

	switch (mm->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
#if BUILD_IU
		if (mm->iu.ue_ctx)
			*id_out = mm->iu.ue_ctx->conn_id;
		if (mm->iu.mm_state_fsm)
			*state_out = osmo_fsm_inst_state_name(mm->iu.mm_state_fsm);
#endif
		break;
	case MM_CTX_T_GERAN_Gb:
		*id_out = mm->gb.tlli;
		if (mm->gb.mm_state_fsm)
			*state_out = osmo_fsm_inst_state_name(mm->gb.mm_state_fsm);
		break;
	default:
		break;
	}
}

static char *api_append_mm_pdp_json(char *cur, char *start, size_t *space,
				    const struct sgsn_pdp_ctx *pdp);

static unsigned api_mm_pdp_count(const struct sgsn_mm_ctx *mm)
{
	struct sgsn_pdp_ctx *pdp;
	unsigned count = 0;

	if (!mm)
		return 0;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		count++;
		if (count >= SGSN_API_MM_MAX_PDP)
			break;
	}
	return count;
}

static char *build_mm_json(const struct sgsn_mm_ctx *mm, bool include_pdp)
{
	char *start, *cur;
	size_t space;
	char esc[256];
	struct sgsn_pdp_ctx *pdp;
	uint32_t ran_id = 0;
	const char *mm_state = "unknown";
	const char *gmm_state;
	unsigned pdp_n = 0;
	bool first_pdp;

	if (!mm)
		return NULL;

	start = talloc_zero_size(g_api_ctx, 64 * 1024);
	if (!start)
		return NULL;
	cur = start;
	space = 64 * 1024;

	api_mm_ran_info(mm, &ran_id, &mm_state);
	gmm_state = mm->gmm_fsm ? osmo_fsm_inst_state_name(mm->gmm_fsm) : "unknown";

	json_escape(mm->imsi, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "{\"imsi\":\"%s\",", esc);
	json_escape(mm->imei, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"imei\":\"%s\",", esc);
	json_escape(mm->msisdn, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"msisdn\":\"%s\",", esc);
	cur = json_append(cur, start, &space, "\"p_tmsi\":\"%08x\",", mm->p_tmsi);
	cur = json_append(cur, start, &space, "\"tlli\":\"%08x\",", ran_id);
	json_escape(gmm_state, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"gmm_state\":\"%s\",", esc);
	json_escape(osmo_rai_name2(&mm->ra), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"routing_area\":\"%s\",", esc);
	cur = json_append(cur, start, &space, "\"cell_id\":%u,", mm->gb.cell_id);
	json_escape(mm_state, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"mm_state\":\"%s\",", esc);
	json_escape(get_value_string(sgsn_ran_type_names, mm->ran_type), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"ran_type\":\"%s\",", esc);
	json_escape(mm->hlr, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"hlr\":\"%s\",", esc);

	if (!include_pdp) {
		cur = json_append(cur, start, &space, "\"pdp_count\":%u}",
				  api_mm_pdp_count(mm));
		return start;
	}

	cur = json_append(cur, start, &space, "\"pdp_contexts\":[");
	first_pdp = true;
	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp_n >= SGSN_API_MM_MAX_PDP)
			break;
		if (!first_pdp)
			cur = json_append(cur, start, &space, ",");
		first_pdp = false;
		cur = api_append_mm_pdp_json(cur, start, &space, pdp);
		if (space == 0)
			break;
		pdp_n++;
	}
	cur = json_append(cur, start, &space, "]}");
	return start;
}

static int api_parse_pdp_query(const char *query, struct api_pdp_list_query *out)
{
	char val[64];

	OSMO_ASSERT(out);
	memset(out, 0, sizeof(*out));
	out->limit = SGSN_API_PDP_DEFAULT_LIMIT;

	if (api_query_get(query, "imsi_prefix", val, sizeof(val)) ||
	    api_query_get(query, "imsi", val, sizeof(val))) {
		if (!api_valid_imsi_prefix(val))
			return -EINVAL;
		osmo_strlcpy(out->imsi_prefix, val, sizeof(out->imsi_prefix));
		out->has_imsi_prefix = true;
	}

	if (api_query_get(query, "limit", val, sizeof(val))) {
		char *end = NULL;
		unsigned long lim = strtoul(val, &end, 10);

		if (!val[0] || (end && *end != '\0') || lim == 0 || lim > SGSN_API_PDP_MAX_LIMIT)
			return -EINVAL;
		out->limit = (unsigned)lim;
	}

	return 0;
}

static bool api_pdp_imsi_matches(const struct sgsn_pdp_ctx *pdp, const char *prefix)
{
	size_t plen;

	if (!prefix || !prefix[0])
		return true;
	if (!pdp || !pdp->mm || !pdp->mm->imsi[0])
		return false;
	plen = strlen(prefix);
	return strncmp(pdp->mm->imsi, prefix, plen) == 0;
}

static void api_gtp_ip_str(struct ul16_t *ul, char *out, size_t out_len)
{
	struct in_addr ia;

	if (!out || out_len == 0)
		return;
	out[0] = '\0';
	if (!ul || gsna2in_addr(&ia, ul) != 0)
		return;
	inet_ntop(AF_INET, &ia, out, out_len);
}

static char *api_append_pdp_gtp_json(char *cur, char *start, size_t *space,
				     const struct sgsn_pdp_ctx *pdp)
{
	char lc_ip[INET_ADDRSTRLEN];
	char lu_ip[INET_ADDRSTRLEN];
	char rc_ip[INET_ADDRSTRLEN];
	char ru_ip[INET_ADDRSTRLEN];
	struct pdp_t *lib;

	if (!pdp || !pdp->lib)
		return json_append(cur, start, space, "\"gtp\":null");

	lib = pdp->lib;
	api_gtp_ip_str(&lib->gsnlc, lc_ip, sizeof(lc_ip));
	api_gtp_ip_str(&lib->gsnlu, lu_ip, sizeof(lu_ip));
	api_gtp_ip_str(&lib->gsnrc, rc_ip, sizeof(rc_ip));
	api_gtp_ip_str(&lib->gsnru, ru_ip, sizeof(ru_ip));

	cur = json_append(cur, start, space,
			  "\"gtp\":{\"version\":%u,"
			  "\"local\":{\"control_ip\":\"%s\",\"control_teid\":\"0x%08x\","
			  "\"user_ip\":\"%s\",\"user_teid\":\"0x%08x\"",
			  lib->version, lc_ip, lib->teic_own, lu_ip, lib->teid_own);
	if (pdp->sgsn_teid_own && pdp->sgsn_teid_own != lib->teid_own) {
		cur = json_append(cur, start, space, ",\"sgsn_user_teid\":\"0x%08x\"",
				  pdp->sgsn_teid_own);
	}
	cur = json_append(cur, start, space,
			  "},\"remote\":{\"control_ip\":\"%s\",\"control_teid\":\"0x%08x\","
			  "\"user_ip\":\"%s\",\"user_teid\":\"0x%08x\"}}",
			  rc_ip, lib->teic_gn, ru_ip, lib->teid_gn);
	return cur;
}

static char *api_append_pdp_entry_json(char *cur, char *start, size_t *space,
				       const struct sgsn_pdp_ctx *pdp, bool include_imsi)
{
	char esc[256];
	char addr[INET6_ADDRSTRLEN + 8];
	char apnbuf[APN_MAXLEN + 1];

	if (!pdp)
		return cur;

	cur = json_append(cur, start, space, "{");
	if (include_imsi) {
		const char *imsi = (pdp->mm && pdp->mm->imsi[0]) ? pdp->mm->imsi : "";

		json_escape(imsi, esc, sizeof(esc));
		cur = json_append(cur, start, space, "\"imsi\":\"%s\",", esc);
	}
	cur = json_append(cur, start, space, "\"nsapi\":%u,\"sapi\":%u,\"ti\":%u,",
			  pdp->nsapi, pdp->sapi, pdp->ti);
	if (pdp->lib && pdp->lib->apn_use.l > 0) {
		osmo_apn_to_str(apnbuf, pdp->lib->apn_use.v, pdp->lib->apn_use.l);
		json_escape(apnbuf, esc, sizeof(esc));
		cur = json_append(cur, start, space, "\"apn\":\"%s\",", esc);
		pdp_addr_str(pdp->lib->eua.v, pdp->lib->eua.l, addr, sizeof(addr));
		json_escape(addr, esc, sizeof(esc));
		cur = json_append(cur, start, space, "\"pdp_address\":\"%s\",", esc);
	} else {
		cur = json_append(cur, start, space, "\"apn\":\"\",\"pdp_address\":\"\",");
	}
	cur = api_append_pdp_gtp_json(cur, start, space, pdp);
	cur = json_append(cur, start, space, "}");
	return cur;
}

static char *api_append_mm_pdp_json(char *cur, char *start, size_t *space,
				    const struct sgsn_pdp_ctx *pdp)
{
	return api_append_pdp_entry_json(cur, start, space, pdp, false);
}

static char *api_append_pdp_json(char *cur, char *start, size_t *space,
				 const struct sgsn_pdp_ctx *pdp)
{
	return api_append_pdp_entry_json(cur, start, space, pdp, true);
}

static char *build_pdp_list_json(const struct api_pdp_list_query *query)
{
	struct sgsn_pdp_ctx *pdp;
	char *items, *cur, *result;
	size_t space;
	unsigned returned = 0, scanned = 0;
	bool first = true;
	char prefix_esc[32];

	if (!sgsn || !query)
		return NULL;

	items = talloc_zero_size(g_api_ctx, 256 * 1024);
	if (!items)
		return NULL;
	cur = items;
	space = 256 * 1024;

	llist_for_each_entry(pdp, &sgsn->pdp_list, g_list) {
		if (++scanned > SGSN_API_PDP_MAX_SCAN)
			break;
		if (!pdp->mm)
			continue;
		if (query->has_imsi_prefix && !api_pdp_imsi_matches(pdp, query->imsi_prefix))
			continue;
		if (returned >= query->limit)
			break;

		if (!first)
			cur = json_append(cur, items, &space, ",");
		first = false;
		cur = api_append_pdp_json(cur, items, &space, pdp);
		if (space == 0)
			break;
		returned++;
	}

	if (query->has_imsi_prefix) {
		json_escape(query->imsi_prefix, prefix_esc, sizeof(prefix_esc));
		result = talloc_asprintf(g_api_ctx,
					 "{\"count\":%u,\"limit\":%u,\"imsi_prefix\":\"%s\",\"pdp_contexts\":[%s]}",
					 returned, query->limit, prefix_esc, items);
	} else {
		result = talloc_asprintf(g_api_ctx,
					 "{\"count\":%u,\"limit\":%u,\"pdp_contexts\":[%s]}",
					 returned, query->limit, items);
	}
	talloc_free(items);
	return result;
}

static char *build_links_json(void)
{
	char *iu_json = NULL;
	char *result;
	char gtp_local[INET_ADDRSTRLEN + 1];
	char gsup_ip[256];
	int gsup_port = 0;
	bool gsup_up = false;
#if BUILD_IU
	unsigned iu_idx;
	struct iu_rnc_api_entry iu_ent;
	char iu_buf[512];
	char *iu_cur = iu_buf;
	size_t iu_space = sizeof(iu_buf);
	bool iu_first = true;
#endif

	if (!sgsn)
		return NULL;

	inet_ntop(AF_INET, &sgsn->cfg.gtp_listenaddr.sin_addr, gtp_local, sizeof(gtp_local));
	gsup_ip[0] = '\0';
	if (sgsn->gsup_client) {
		osmo_strlcpy(gsup_ip, osmo_gsup_client_get_rem_addr(sgsn->gsup_client), sizeof(gsup_ip));
		gsup_port = osmo_gsup_client_get_rem_port(sgsn->gsup_client);
		gsup_up = osmo_gsup_client_is_connected(sgsn->gsup_client);
	} else if (sgsn->cfg.gsup_server_addr.sin_addr.s_addr) {
		inet_ntop(AF_INET, &sgsn->cfg.gsup_server_addr.sin_addr, gsup_ip, sizeof(gsup_ip));
		gsup_port = sgsn->cfg.gsup_server_port;
	}

#if BUILD_IU
	iu_buf[0] = '\0';
	for (iu_idx = 0; iu_idx < iu_rnc_api_count(); iu_idx++) {
		char rnc_id[64], sccp_addr[64], state[32];

		if (!iu_rnc_api_get(iu_idx, &iu_ent))
			break;
		if (!iu_first)
			iu_cur = json_append(iu_cur, iu_buf, &iu_space, ",");
		iu_first = false;
		api_fmt_rnc_id(&iu_ent.rnc_id, rnc_id, sizeof(rnc_id));
		api_fmt_sccp_pc(&iu_ent.sccp_addr, sccp_addr, sizeof(sccp_addr));
		api_fmt_iu_rnc_state_cached(iu_ent.state, state, sizeof(state));
		iu_cur = json_append(iu_cur, iu_buf, &iu_space,
				     "{\"rnc_id\":\"%s\",\"sccp_addr\":\"%s\",\"state\":\"%s\"}",
				     rnc_id, sccp_addr, state);
	}
	iu_json = iu_buf;
#else
	iu_json = "";
#endif

	if (sgsn->gsn) {
		char gtp_sig[INET_ADDRSTRLEN + 1];
		char gtp_user[INET_ADDRSTRLEN + 1];

		inet_ntop(AF_INET, &sgsn->gsn->gsnc, gtp_sig, sizeof(gtp_sig));
		inet_ntop(AF_INET, &sgsn->gsn->gsnu, gtp_user, sizeof(gtp_user));
		result = talloc_asprintf(g_api_ctx,
					 "{\"network\":{\"gtp\":{\"signalling_ip\":\"%s\",\"user_ip\":\"%s\"},"
					 "\"gtp_local_ip\":\"%s\","
					 "\"ggsn\":[],\"mme\":[],"
					 "\"gsup\":{\"remote_ip\":\"%s\",\"remote_port\":%d,\"connected\":%s},"
					 "\"iu_rnc\":[%s]}}",
					 gtp_sig, gtp_user, gtp_local,
					 gsup_ip, gsup_port, gsup_up ? "true" : "false",
					 iu_json ? iu_json : "");
	} else {
		result = talloc_asprintf(g_api_ctx,
					 "{\"network\":{\"gtp\":null,"
					 "\"gtp_local_ip\":\"%s\","
					 "\"ggsn\":[],\"mme\":[],"
					 "\"gsup\":{\"remote_ip\":\"%s\",\"remote_port\":%d,\"connected\":%s},"
					 "\"iu_rnc\":[%s]}}",
					 gtp_local, gsup_ip, gsup_port, gsup_up ? "true" : "false",
					 iu_json ? iu_json : "");
	}
	return result;
}

static void api_client_close(struct api_conn *ac);
static int api_write_all(int fd, const char *data, size_t len);
static void handle_request(struct api_conn *ac, const char *req);

/* Runs in either thread: only stores the response, api_flush() writes it. */
static void api_send(struct api_conn *ac, int code, const char *status,
		     const char *content_type, const char *body)
{
	char *resp = NULL;
	size_t body_len = body ? strlen(body) : 0;
	int rc;

	if (content_type && body)
		rc = asprintf(&resp,
			      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
			      code, status, content_type, body_len, body);
	else
		rc = asprintf(&resp,
			      "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			      code, status);
	if (rc < 0)
		return;

	free(ac->resp);
	ac->resp = resp;
	ac->resp_len = rc;
}

static void api_flush(struct api_conn *ac)
{
	int rc;

	if (!ac->resp)
		return;
	rc = api_write_all(ac->fd, ac->resp, ac->resp_len);
	if (rc == -EAGAIN) {
		osmo_sock_set_nonblock(ac->fd, 0);
		rc = api_write_all(ac->fd, ac->resp, ac->resp_len);
	}
	if (rc < 0)
		fprintf(stderr, "HTTP API write failed: %s\n", strerror(-rc));
	free(ac->resp);
	ac->resp = NULL;
}

static int api_write_all(int fd, const char *data, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t rc = write(fd, data + off, len - off);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return -EAGAIN;
			return -errno;
		}
		if (rc == 0)
			return -EIO;
		off += rc;
	}
	return 0;
}

static int api_conn_slot(struct api_conn *ac)
{
	unsigned i;

	for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
		if (g_api_conns[i] == ac)
			return i;
	}
	return -1;
}

static void api_client_close(struct api_conn *ac)
{
	int slot = api_conn_slot(ac);

	if (slot < 0)
		return;
	close(ac->fd);
	free(ac->resp);
	free(ac);
	g_api_conns[slot] = NULL;
	if (g_api_client_count)
		g_api_client_count--;
}

static int api_conn_add(int cfd)
{
	struct api_conn *ac;
	unsigned i;

	for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
		if (g_api_conns[i])
			continue;
		struct timeval snd_to = { .tv_sec = SGSN_API_SND_TIMEOUT_SEC };

		ac = calloc(1, sizeof(*ac));
		if (!ac) {
			close(cfd);
			return -ENOMEM;
		}
		setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &snd_to, sizeof(snd_to));
		ac->fd = cfd;
		ac->last_activity = time(NULL);
		g_api_conns[i] = ac;
		g_api_client_count++;
		return 0;
	}
	return -EBUSY;
}

static void api_accept_all(void)
{
	while (g_api_thread_run && g_api_listen_fd >= 0) {
		int cfd = accept(g_api_listen_fd, NULL, NULL);

		if (cfd < 0) {
			if (errno == EAGAIN || errno == EINTR)
				break;
			fprintf(stderr, "HTTP API accept failed: %s\n", strerror(errno));
			break;
		}

		osmo_sock_set_nonblock(cfd, 1);

		if (g_api_client_count >= SGSN_API_MAX_CLIENTS) {
			static const char busy[] =
				"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

			osmo_sock_set_nonblock(cfd, 0);
			(void)api_write_all(cfd, busy, sizeof(busy) - 1);
			close(cfd);
			continue;
		}

		if (api_conn_add(cfd) < 0) {
			static const char busy[] =
				"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

			osmo_sock_set_nonblock(cfd, 0);
			(void)api_write_all(cfd, busy, sizeof(busy) - 1);
			close(cfd);
		}
	}
}

static void api_idle_sweep(void)
{
	time_t now = time(NULL);
	unsigned i;

	for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
		struct api_conn *ac = g_api_conns[i];

		if (!ac)
			continue;
		if (now - ac->last_activity >= SGSN_API_IDLE_SEC)
			api_client_close(ac);
	}
}

/* API thread: queue ac for handle_request() in the main loop and wait for
 * the response. A job the main loop has not picked up within
 * SGSN_API_MAIN_WAIT_SEC is withdrawn; a running one is always waited for,
 * since the main loop is using ac. */
static void api_run_in_main(struct api_conn *ac)
{
	struct timespec deadline;
	const char one = 1;
	bool done;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += SGSN_API_MAIN_WAIT_SEC;

	pthread_mutex_lock(&g_api_lock);
	g_api_job_conn = ac;
	g_api_job_state = API_JOB_PENDING;
	pthread_mutex_unlock(&g_api_lock);

	if (write(g_api_wake_pipe[1], &one, 1) < 0 && errno != EAGAIN)
		fprintf(stderr, "HTTP API wake failed: %s\n", strerror(errno));

	pthread_mutex_lock(&g_api_lock);
	while (g_api_job_state != API_JOB_DONE && g_api_thread_run) {
		int rc;

		if (g_api_job_state == API_JOB_PENDING)
			rc = pthread_cond_timedwait(&g_api_job_cond, &g_api_lock, &deadline);
		else
			rc = pthread_cond_wait(&g_api_job_cond, &g_api_lock);
		if (rc == ETIMEDOUT && g_api_job_state == API_JOB_PENDING)
			break;
	}
	done = g_api_job_state == API_JOB_DONE;
	g_api_job_conn = NULL;
	g_api_job_state = API_JOB_NONE;
	pthread_mutex_unlock(&g_api_lock);

	if (!done)
		api_send(ac, 503, "Service Unavailable", NULL, NULL);
}

/* Main loop: run the queued request. */
static int api_wake_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct api_conn *ac = NULL;
	char drain[16];

	while (read(ofd->fd, drain, sizeof(drain)) > 0)
		;

	pthread_mutex_lock(&g_api_lock);
	if (g_api_job_state == API_JOB_PENDING) {
		ac = g_api_job_conn;
		g_api_job_state = API_JOB_RUNNING;
	}
	pthread_mutex_unlock(&g_api_lock);
	if (!ac)
		return 0;

	handle_request(ac, ac->buf);

	pthread_mutex_lock(&g_api_lock);
	g_api_job_state = API_JOB_DONE;
	pthread_cond_broadcast(&g_api_job_cond);
	pthread_mutex_unlock(&g_api_lock);
	return 0;
}

static void api_client_read(struct api_conn *ac)
{
	char *hdr_end;
	ssize_t rc;

	if (ac->len >= sizeof(ac->buf) - 1) {
		api_send(ac, 413, "Payload Too Large", NULL, NULL);
		api_flush(ac);
		api_client_close(ac);
		return;
	}

	rc = read(ac->fd, ac->buf + ac->len, sizeof(ac->buf) - ac->len - 1);
	if (rc <= 0) {
		api_client_close(ac);
		return;
	}

	ac->len += rc;
	ac->buf[ac->len] = '\0';
	ac->last_activity = time(NULL);

	if (ac->len + 1 >= sizeof(ac->buf)) {
		api_send(ac, 413, "Payload Too Large", NULL, NULL);
		api_flush(ac);
		api_client_close(ac);
		return;
	}

	hdr_end = strstr(ac->buf, "\r\n\r\n");
	if (!hdr_end)
		return;

	*hdr_end = '\0';
	api_run_in_main(ac);
	api_flush(ac);
	api_client_close(ac);
}

static void *api_thread_main(void *arg)
{
	(void)arg;

	while (g_api_thread_run) {
		struct pollfd pfds[1 + SGSN_API_MAX_CLIENTS];
		nfds_t nfds = 0;
		unsigned i;
		int rc;

		if (g_api_listen_fd >= 0) {
			pfds[nfds].fd = g_api_listen_fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
			if (!g_api_conns[i])
				continue;
			pfds[nfds].fd = g_api_conns[i]->fd;
			pfds[nfds].events = POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}

		rc = poll(pfds, nfds, SGSN_API_POLL_MS);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "HTTP API poll failed: %s\n", strerror(errno));
			break;
		}

		if (rc == 0) {
			api_idle_sweep();
			continue;
		}

		if (g_api_listen_fd >= 0 && (pfds[0].revents & (POLLIN | POLLERR | POLLHUP)))
			api_accept_all();

		for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
			struct api_conn *ac = g_api_conns[i];
			nfds_t p;

			if (!ac)
				continue;
			for (p = 0; p < nfds; p++) {
				if (pfds[p].fd != ac->fd)
					continue;
				if (pfds[p].revents & (POLLIN | POLLERR | POLLHUP))
					api_client_read(ac);
				break;
			}
		}
	}

	return NULL;
}

static const char *find_header(const char *hdr, const char *name)
{
	size_t name_len = strlen(name);
	const char *p = hdr;

	while (p && *p) {
		const char *eol = strstr(p, "\r\n");
		size_t line_len = eol ? (size_t)(eol - p) : strlen(p);

		if (line_len > name_len + 2 &&
		    strncasecmp(p, name, name_len) == 0 &&
		    p[name_len] == ':' &&
		    p[name_len + 1] == ' ') {
			return p + name_len + 2;
		}
		if (!eol || eol == p)
			break;
		p = eol + 2;
	}
	return NULL;
}

static bool auth_ok(const char *hdr)
{
	const char *auth;
	char expect[512];
	size_t auth_len;

	if (!api_enabled())
		return false;

	auth = find_header(hdr, "Authorization");
	if (!auth)
		return false;

	auth_len = strcspn(auth, "\r\n");
	snprintf(expect, sizeof(expect), "Bearer %s", sgsn->cfg.api.token);
	if (strlen(expect) != auth_len)
		return false;
	return strncmp(auth, expect, auth_len) == 0;
}

static bool parse_path(const char *req, char *method, size_t method_len,
		       char *path, size_t path_len, char *query, size_t query_len)
{
	const char *sp1, *sp2, *eol, *qmark;
	size_t mlen, plen, path_only;

	eol = strstr(req, "\r\n");
	if (!eol)
		eol = strchr(req, '\n');
	if (!eol)
		return false;

	sp1 = strchr(req, ' ');
	if (!sp1 || sp1 >= eol)
		return false;
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2 || sp2 >= eol)
		return false;

	mlen = (size_t)(sp1 - req);
	if (mlen == 0 || mlen >= method_len)
		return false;
	memcpy(method, req, mlen);
	method[mlen] = '\0';

	plen = (size_t)(sp2 - (sp1 + 1));
	if (plen == 0 || plen >= path_len)
		return false;

	qmark = memchr(sp1 + 1, '?', plen);
	if (qmark) {
		path_only = (size_t)(qmark - (sp1 + 1));
		if (path_only == 0 || path_only >= path_len)
			return false;
		memcpy(path, sp1 + 1, path_only);
		path[path_only] = '\0';
		if (query && query_len > 0) {
			size_t qlen = plen - path_only - 1;

			if (qlen >= query_len)
				qlen = query_len - 1;
			memcpy(query, qmark + 1, qlen);
			query[qlen] = '\0';
		}
	} else {
		memcpy(path, sp1 + 1, plen);
		path[plen] = '\0';
		if (query && query_len > 0)
			query[0] = '\0';
	}
	return path[0] == '/';
}

/* ---- per-IMSI debug trace ----
 *
 * OsmoSGSN does not attach a per-message subscriber log context (it only writes
 * the IMSI into the log text, e.g. "MM(<imsi>/...)"), so the VLR-style context
 * filter that OsmoMSC uses is not available here. Instead we install a dedicated
 * libosmocore log target whose output callback keeps only the lines that mention
 * the traced IMSI, and appends them to a per-IMSI file. This is the OsmoSGSN
 * equivalent of the Open5GS IMSI trace and, unlike the MSC, it can be armed
 * before the subscriber attaches (it matches on text, not a live context).
 */

struct sgsn_api_trace {
	struct llist_head entry;
	char imsi[16];
	struct log_target *target;
};

static LLIST_HEAD(g_api_traces);

/* The SGSN's own Iu SCTP association goes to the local STP, so the real RNC
 * addresses are taken from the STP config: RNC point code -> AS -> ASP.
 * Re-read on every trace enable; only accessed from the main thread. */
#define SGSN_API_STP_CFG "/etc/osmocom/osmo-stp.cfg"
#define STP_MAX_ASP 32
#define STP_MAX_AS 32
#define STP_MAX_ADDR 4
#define STP_NAME_LEN 32

#if BUILD_IU
struct stp_asp {
	char name[STP_NAME_LEN];
	uint16_t remote_port;
	uint16_t local_port;
	char remote_ip[STP_MAX_ADDR][INET6_ADDRSTRLEN];
	unsigned n_remote_ip;
	char local_ip[STP_MAX_ADDR][INET6_ADDRSTRLEN];
	unsigned n_local_ip;
};

struct stp_as {
	char asp[STP_MAX_ADDR][STP_NAME_LEN];
	unsigned n_asp;
	char pc[STP_MAX_ADDR][32];
	unsigned n_pc;
};

static struct {
	struct stp_asp asp[STP_MAX_ASP];
	unsigned n_asp;
	struct stp_as as[STP_MAX_AS];
	unsigned n_as;
} g_stp_map;
#endif
static volatile bool g_stp_map_stale = true;

static struct sgsn_api_trace *api_trace_find_nolock(const char *imsi)
{
	struct sgsn_api_trace *t;

	llist_for_each_entry(t, &g_api_traces, entry) {
		if (!strcmp(t->imsi, imsi))
			return t;
	}
	return NULL;
}

static struct sgsn_api_trace *api_trace_find(const char *imsi)
{
	struct sgsn_api_trace *t;

	pthread_mutex_lock(&g_api_trace_lock);
	t = api_trace_find_nolock(imsi);
	pthread_mutex_unlock(&g_api_trace_lock);
	return t;
}

/* libosmocore log target output callback: keep only lines mentioning the traced
 * IMSI and write them to stderr, so the daemon's journald unit captures them. */
static void api_trace_log_output(struct log_target *tgt, unsigned int level, const char *line)
{
	struct sgsn_api_trace *t;

	pthread_mutex_lock(&g_api_trace_lock);
	llist_for_each_entry(t, &g_api_traces, entry) {
		if (t->target != tgt)
			continue;
		if (strstr(line, t->imsi)) {
			fputs(line, stderr);
			fflush(stderr);
		}
		break;
	}
	pthread_mutex_unlock(&g_api_trace_lock);
}

/* Returns 0 on success (*out set), negative errno otherwise. */
static int api_trace_enable(const char *imsi, struct sgsn_api_trace **out)
{
	struct sgsn_api_trace *t;
	struct log_target *tgt;

	pthread_mutex_lock(&g_api_trace_lock);
	t = api_trace_find_nolock(imsi);
	if (t) {
		*out = t;	/* idempotent */
		pthread_mutex_unlock(&g_api_trace_lock);
		return 0;
	}

	t = talloc_zero(g_api_ctx, struct sgsn_api_trace);
	if (!t) {
		pthread_mutex_unlock(&g_api_trace_lock);
		return -ENOMEM;
	}
	osmo_strlcpy(t->imsi, imsi, sizeof(t->imsi));

	tgt = log_target_create();
	if (!tgt) {
		talloc_free(t);
		pthread_mutex_unlock(&g_api_trace_lock);
		return -ENOMEM;
	}
	tgt->output = api_trace_log_output;
	/* gprs_log_filter_fn() would otherwise deny a target with no filters set;
	 * pass everything to our output callback and substring-filter by IMSI there. */
	log_set_all_filter(tgt, 1);
	log_set_log_level(tgt, LOGL_DEBUG);
	log_set_use_color(tgt, 0);
	log_set_print_category(tgt, 1);
	log_set_print_category_hex(tgt, 0);
	log_set_print_level(tgt, 1);
	log_set_print_extended_timestamp(tgt, 1);

	t->target = tgt;
	llist_add_tail(&t->entry, &g_api_traces);
	pthread_mutex_unlock(&g_api_trace_lock);
	log_add_target(tgt);
	g_stp_map_stale = true;

	LOGP(DGPRS, LOGL_NOTICE, "API enabled IMSI debug trace for %s (-> journal)\n", imsi);
	*out = t;
	return 0;
}

static int api_trace_disable(const char *imsi)
{
	struct sgsn_api_trace *t;

	pthread_mutex_lock(&g_api_trace_lock);
	t = api_trace_find_nolock(imsi);
	if (!t) {
		pthread_mutex_unlock(&g_api_trace_lock);
		return -ENOENT;
	}

	llist_del(&t->entry);
	pthread_mutex_unlock(&g_api_trace_lock);
	if (t->target)
		log_target_destroy(t->target);
	LOGP(DGPRS, LOGL_NOTICE, "API disabled IMSI debug trace for %s\n", imsi);
	talloc_free(t);
	return 0;
}

bool sgsn_api_trace_any_active(void)
{
	bool active;

	pthread_mutex_lock(&g_api_trace_lock);
	active = !llist_empty(&g_api_traces);
	pthread_mutex_unlock(&g_api_trace_lock);
	return active;
}

bool sgsn_api_trace_active(const char *imsi)
{
	if (!imsi || !imsi[0])
		return false;
	return api_trace_find(imsi) != NULL;
}

void sgsn_api_trace_packet(const char *imsi, const char *proto, bool tx,
			   const char *link, const uint8_t *data, size_t len)
{
	size_t cap_len, b64_len, olen;
	bool truncated = false;
	unsigned char *b64;
	char *line;
	int rc;

	if (!imsi || !imsi[0] || !proto || !data || !len)
		return;
	if (!sgsn_api_trace_active(imsi))
		return;

	cap_len = len;
	if (cap_len > SGSN_API_TRACE_PKT_MAX) {
		cap_len = SGSN_API_TRACE_PKT_MAX;
		truncated = true;
	}

	b64_len = ((cap_len + 2) / 3) * 4 + 1;
	b64 = malloc(b64_len);
	if (!b64)
		return;

	if (osmo_base64_encode(b64, b64_len, &olen, data, cap_len) < 0) {
		free(b64);
		return;
	}

	rc = asprintf(&line,
		      "[IMSI:%s] PACKET: proto=%s dir=%s%s len=%zu%s b64=%s\n",
		      imsi, proto, tx ? "tx" : "rx", link ? link : "", cap_len,
		      truncated ? " trunc=1" : "", b64);
	free(b64);
	if (rc < 0 || !line)
		return;
	fputs(line, stderr);
	fflush(stderr);
	free(line);
}

#if BUILD_IU
/* Join addresses as "ip:port,ip:port"; port 0 (dynamic) prints the IP only. */
static void api_fmt_endpoints(char *out, size_t out_len, const char (*ips)[INET6_ADDRSTRLEN],
			      unsigned n, uint16_t port)
{
	size_t off = 0;
	unsigned i;

	out[0] = '\0';
	if (!n) {
		osmo_strlcpy(out, "?", out_len);
		return;
	}
	for (i = 0; i < n && off < out_len; i++) {
		const char *ip = ips[i];
		bool v6 = strchr(ip, ':') != NULL;
		int rc;

		if (!strcmp(ip, "0.0.0.0") || !strcmp(ip, "::"))
			ip = "*";
		if (port)
			rc = snprintf(out + off, out_len - off, "%s%s%s%s:%u", i ? "," : "",
				      v6 ? "[" : "", ip, v6 ? "]" : "", port);
		else
			rc = snprintf(out + off, out_len - off, "%s%s", i ? "," : "", ip);
		if (rc < 0)
			break;
		off += rc;
	}
}
#endif

struct api_gb_link {
	char local[128];
	char remote[128];
	unsigned n;
};

static void api_gb_link_add(char *list, size_t list_len, const struct osmo_sockaddr *sa)
{
	char tmp[INET6_ADDRSTRLEN + 16];
	size_t off = strlen(list);

	if (!sa || !osmo_sockaddr_to_str_buf(tmp, sizeof(tmp), sa))
		return;
	if (strstr(list, tmp))
		return;
	snprintf(list + off, list_len - off, "%s%s", off ? "," : "", tmp);
}

static int api_gb_link_nsvc_cb(struct gprs_ns2_vc *nsvc, void *ctx)
{
	struct api_gb_link *g = ctx;
	const struct osmo_sockaddr *remote = gprs_ns2_ip_vc_remote(nsvc);

	if (!remote)
		return 0;
	api_gb_link_add(g->remote, sizeof(g->remote), remote);
	api_gb_link_add(g->local, sizeof(g->local), gprs_ns2_ip_vc_local(nsvc));
	g->n++;
	return 0;
}

/* NS2 load-shares across the NS-VCs of an NSE internally, so with more than
 * one IP NS-VC all candidate endpoints are listed. */
const char *sgsn_api_trace_link_gb(char *buf, size_t buf_len, uint16_t nsei, bool tx)
{
	struct gprs_ns2_nse *nse = NULL;
	struct api_gb_link g = {};

	if (sgsn && sgsn->cfg.nsi)
		nse = gprs_ns2_nse_by_nsei(sgsn->cfg.nsi, nsei);
	if (nse)
		gprs_ns2_nse_foreach_nsvc(nse, api_gb_link_nsvc_cb, &g);
	if (!g.n) {
		snprintf(buf, buf_len, " link=gb nsei=%u", nsei);
		return buf;
	}
	if (!g.local[0])
		osmo_strlcpy(g.local, "?", sizeof(g.local));
	snprintf(buf, buf_len, " link=gb nsei=%u src=%s dst=%s", nsei,
		 tx ? g.local : g.remote, tx ? g.remote : g.local);
	return buf;
}

#if BUILD_IU
static void stp_map_load(void)
{
	struct stp_asp *cur_asp = NULL;
	struct stp_as *cur_as = NULL;
	char line[256];
	FILE *f;

	memset(&g_stp_map, 0, sizeof(g_stp_map));
	f = fopen(SGSN_API_STP_CFG, "r");
	if (!f) {
		LOGP(DGPRS, LOGL_NOTICE, "IMSI trace: cannot read %s, Iu RNC IPs unavailable\n",
		     SGSN_API_STP_CFG);
		return;
	}

	while (fgets(line, sizeof(line), f)) {
		size_t indent = strspn(line, " ");
		const char *p = line + indent;
		char name[STP_NAME_LEN], addr[INET6_ADDRSTRLEN], pc[32];
		unsigned rport, lport;

		if (indent == 1) {
			cur_asp = NULL;
			cur_as = NULL;
			if (!strncmp(p, "asp ", 4) &&
			    sscanf(p, "asp %31s %u %u", name, &rport, &lport) == 3 &&
			    g_stp_map.n_asp < STP_MAX_ASP) {
				cur_asp = &g_stp_map.asp[g_stp_map.n_asp++];
				osmo_strlcpy(cur_asp->name, name, sizeof(cur_asp->name));
				cur_asp->remote_port = rport;
				cur_asp->local_port = lport;
			} else if (!strncmp(p, "as ", 3) && g_stp_map.n_as < STP_MAX_AS) {
				cur_as = &g_stp_map.as[g_stp_map.n_as++];
			}
		} else if (indent == 2 && cur_asp) {
			if (!strncmp(p, "remote-ip ", 10) && sscanf(p, "remote-ip %45s", addr) == 1 &&
			    cur_asp->n_remote_ip < STP_MAX_ADDR)
				osmo_strlcpy(cur_asp->remote_ip[cur_asp->n_remote_ip++], addr,
					     INET6_ADDRSTRLEN);
			else if (!strncmp(p, "local-ip ", 9) && sscanf(p, "local-ip %45s", addr) == 1 &&
				 cur_asp->n_local_ip < STP_MAX_ADDR)
				osmo_strlcpy(cur_asp->local_ip[cur_asp->n_local_ip++], addr,
					     INET6_ADDRSTRLEN);
		} else if (indent == 2 && cur_as) {
			if (!strncmp(p, "asp ", 4) && sscanf(p, "asp %31s", name) == 1 &&
			    cur_as->n_asp < STP_MAX_ADDR)
				osmo_strlcpy(cur_as->asp[cur_as->n_asp++], name, STP_NAME_LEN);
			else if (!strncmp(p, "routing-key ", 12) &&
				 sscanf(p, "routing-key %*u %31s", pc) == 1 &&
				 cur_as->n_pc < STP_MAX_ADDR)
				osmo_strlcpy(cur_as->pc[cur_as->n_pc++], pc, sizeof(cur_as->pc[0]));
		} else if (indent == 0) {
			cur_asp = NULL;
			cur_as = NULL;
		}
	}
	fclose(f);
}

static const struct stp_asp *stp_asp_find(const char *name)
{
	unsigned i;

	for (i = 0; i < g_stp_map.n_asp; i++) {
		if (!strcmp(g_stp_map.asp[i].name, name))
			return &g_stp_map.asp[i];
	}
	return NULL;
}

static const struct stp_asp *stp_asp_for_pc(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	unsigned i, j, k;

	if (g_stp_map_stale) {
		g_stp_map_stale = false;
		stp_map_load();
	}

	for (i = 0; i < g_stp_map.n_as; i++) {
		const struct stp_as *as = &g_stp_map.as[i];

		for (j = 0; j < as->n_pc; j++) {
			if (osmo_ss7_pointcode_parse(inst, as->pc[j]) != (int)pc)
				continue;
			for (k = 0; k < as->n_asp; k++) {
				const struct stp_asp *asp = stp_asp_find(as->asp[k]);
				if (asp)
					return asp;
			}
		}
	}
	return NULL;
}

const char *sgsn_api_trace_link_iu(char *buf, size_t buf_len,
				   const struct ranap_ue_conn_ctx *ue, bool tx)
{
	const struct osmo_ss7_instance *inst;
	const struct ranap_iu_rnc *rnc;
	const struct stp_asp *asp;
	char pc_str[32], rnc_id[64], stp_ep[160], rnc_ep[160];

	buf[0] = '\0';
	if (!ue)
		return buf;
	rnc = ue->rnc;
	if (!rnc) {
		snprintf(buf, buf_len, " link=iu conn_id=%u", ue->conn_id);
		return buf;
	}

	inst = osmo_ss7_instance_find(sgsn->cfg.iu.cs7_instance);
	api_fmt_rnc_id(&rnc->rnc_id, rnc_id, sizeof(rnc_id));
	if (!(rnc->sccp_addr.presence & OSMO_SCCP_ADDR_T_PC)) {
		snprintf(buf, buf_len, " link=iu conn_id=%u rnc_id=%s", ue->conn_id, rnc_id);
		return buf;
	}
	osmo_ss7_pointcode_print_buf(pc_str, sizeof(pc_str), inst, rnc->sccp_addr.pc);

	asp = stp_asp_for_pc(inst, rnc->sccp_addr.pc);
	if (!asp) {
		snprintf(buf, buf_len, " link=iu conn_id=%u rnc_id=%s rnc_pc=%s",
			 ue->conn_id, rnc_id, pc_str);
		return buf;
	}

	api_fmt_endpoints(stp_ep, sizeof(stp_ep), asp->local_ip, asp->n_local_ip, asp->local_port);
	api_fmt_endpoints(rnc_ep, sizeof(rnc_ep), asp->remote_ip, asp->n_remote_ip, asp->remote_port);
	snprintf(buf, buf_len, " link=iu conn_id=%u rnc_id=%s rnc_pc=%s asp=%s src=%s dst=%s",
		 ue->conn_id, rnc_id, pc_str, asp->name,
		 tx ? stp_ep : rnc_ep, tx ? rnc_ep : stp_ep);
	return buf;
}
#endif

static const char *api_trace_link_mm(char *buf, size_t buf_len,
				     const struct sgsn_mm_ctx *mm, bool tx)
{
	buf[0] = '\0';
	switch (mm->ran_type) {
	case MM_CTX_T_GERAN_Gb:
		return sgsn_api_trace_link_gb(buf, buf_len, mm->gb.nsei, tx);
#if BUILD_IU
	case MM_CTX_T_UTRAN_Iu:
		if (mm->iu.ue_ctx)
			return sgsn_api_trace_link_iu(buf, buf_len, mm->iu.ue_ctx, tx);
		break;
#endif
	default:
		break;
	}
	return buf;
}

void sgsn_api_trace_packet_mm(const struct sgsn_mm_ctx *mm, const char *proto,
			      bool tx, const uint8_t *data, size_t len)
{
	char link[SGSN_API_TRACE_LINK_MAX];

	if (!mm || !mm->imsi[0] || !data || !len)
		return;
	if (!sgsn_api_trace_active(mm->imsi))
		return;
	sgsn_api_trace_packet(mm->imsi, proto, tx,
			      api_trace_link_mm(link, sizeof(link), mm, tx), data, len);
}

void sgsn_api_trace_packet_gb(const struct sgsn_mm_ctx *mm, uint32_t tlli, uint16_t nsei,
			      const char *proto, bool tx, const uint8_t *data, size_t len)
{
	char link[SGSN_API_TRACE_LINK_MAX];

	if (!data || !len || !sgsn_api_trace_any_active())
		return;
	if ((!mm || !mm->imsi[0]) && tlli)
		mm = sgsn_mm_ctx_by_any_tlli(tlli);
	if (!mm || !mm->imsi[0] || !sgsn_api_trace_active(mm->imsi))
		return;
	sgsn_api_trace_packet(mm->imsi, proto, tx,
			      sgsn_api_trace_link_gb(link, sizeof(link), nsei, tx), data, len);
}

#if BUILD_IU
void sgsn_api_trace_packet_ue(const struct ranap_ue_conn_ctx *ue, const char *proto,
			      bool tx, const uint8_t *data, size_t len)
{
	char link[SGSN_API_TRACE_LINK_MAX];
	struct sgsn_mm_ctx *mm;

	if (!ue || !data || !len || !sgsn_api_trace_any_active())
		return;
	mm = sgsn_mm_ctx_by_ue_ctx(ue);
	if (!mm || !mm->imsi[0] || !sgsn_api_trace_active(mm->imsi))
		return;
	sgsn_api_trace_packet(mm->imsi, proto, tx,
			      sgsn_api_trace_link_iu(link, sizeof(link), ue, tx), data, len);
}
#endif

static char *build_trace_json(const struct sgsn_api_trace *t, const char *status)
{
	char eimsi[32];

	json_escape(t->imsi, eimsi, sizeof(eimsi));
	return talloc_asprintf(g_api_ctx,
		"{\"status\":\"%s\",\"imsi\":\"%s\",\"output\":\"journal\",\"level\":\"debug\"}",
		status, eimsi);
}

static char *build_trace_list_json(void)
{
	struct sgsn_api_trace *t;
	char *start, *cur;
	size_t space = 16 * 1024;
	bool first = true;

	start = talloc_zero_size(g_api_ctx, space);
	if (!start)
		return NULL;
	cur = start;
	cur = json_append(cur, start, &space, "{\"traces\":[");
	llist_for_each_entry(t, &g_api_traces, entry) {
		char eimsi[32];

		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;
		json_escape(t->imsi, eimsi, sizeof(eimsi));
		cur = json_append(cur, start, &space,
				  "{\"imsi\":\"%s\",\"output\":\"journal\",\"level\":\"debug\"}",
				  eimsi);
	}
	cur = json_append(cur, start, &space, "]}");
	return start;
}

/* Handle /v1/trace[...]. Returns true if it was a trace route. */
static bool handle_trace(struct api_conn *ac, const char *method, const char *path)
{
	char *body;
	const char *imsi;
	struct sgsn_api_trace *t;
	int rc;

	if (!strcmp(method, "GET") && !strcmp(path, "/v1/trace")) {
		body = build_trace_list_json();
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
		if (body)
			talloc_free(body);
		return true;
	}

	if (strncmp(path, "/v1/trace/", 10) != 0)
		return false;

	imsi = path + 10;
	if (!api_valid_imsi(imsi)) {
		api_send(ac, 400, "Bad Request", "application/json",
			 "{\"error\":\"invalid IMSI\"}");
		return true;
	}

	if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
		rc = api_trace_enable(imsi, &t);
		if (rc < 0) {
			api_send(ac, 500, "Error", "application/json",
				 "{\"error\":\"failed to enable trace\"}");
			return true;
		}
		body = build_trace_json(t, "enabled");
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
		if (body)
			talloc_free(body);
		return true;
	}

	if (!strcmp(method, "DELETE")) {
		rc = api_trace_disable(imsi);
		if (rc == -ENOENT) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"no active trace for this IMSI\"}");
			return true;
		}
		body = talloc_asprintf(g_api_ctx, "{\"status\":\"disabled\",\"imsi\":\"%s\"}", imsi);
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
		if (body)
			talloc_free(body);
		return true;
	}

	if (!strcmp(method, "GET")) {
		t = api_trace_find(imsi);
		if (!t) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"no active trace for this IMSI\"}");
			return true;
		}
		body = build_trace_json(t, "active");
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
		if (body)
			talloc_free(body);
		return true;
	}

	return false;
}

static void handle_request(struct api_conn *ac, const char *req)
{
	char method[16] = {};
	char path[256] = {};
	char query[512] = {};
	char *body = NULL;
	struct sgsn_mm_ctx *mm;

	if (!parse_path(req, method, sizeof(method), path, sizeof(path),
			query, sizeof(query))) {
		api_send(ac, 400, "Bad Request", NULL, NULL);
		return;
	}

	if (strcmp(path, "/health") == 0) {
		api_send(ac, 200, "OK", "application/json", "{\"status\":\"ok\"}");
		return;
	}

	if (!auth_ok(req)) {
		api_send(ac, 401, "Unauthorized", "application/json",
			 "{\"error\":\"invalid or missing token\"}");
		return;
	}

	if (handle_trace(ac, method, path))
		return;

	if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/counts")) {
		body = build_counts_json();
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/stats")) {
		body = build_stats_json();
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/links")) {
		body = build_links_json();
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/mm")) {
		api_send(ac, 503, "Service Unavailable", "application/json",
			 "{\"error\":\"disabled for stability; use /v1/contexts/counts\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/pdp")) {
		struct api_pdp_list_query pq;
		int qrc = api_parse_pdp_query(query, &pq);

		if (qrc < 0) {
			api_send(ac, 400, "Bad Request", "application/json",
				 "{\"error\":\"invalid query; use ?imsi_prefix=...&limit=N (limit 1-1000)\"}");
		} else {
			body = build_pdp_list_json(&pq);
			api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
				 "application/json", body ? body : "{\"error\":\"oom\"}");
		}
	} else if (!strcmp(method, "GET") && !strncmp(path, "/v1/contexts/mm/", 16)) {
		const char *imsi = path + 16;
		bool include_pdp = true;

		if (!imsi[0] || strchr(imsi, '/')) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"unknown endpoint\"}");
			return;
		}
		if (!api_valid_imsi(imsi)) {
			api_send(ac, 400, "Bad Request", "application/json",
				 "{\"error\":\"invalid IMSI\"}");
			return;
		}
		if (!api_parse_include_pdp_query(query, &include_pdp)) {
			api_send(ac, 400, "Bad Request", "application/json",
				 "{\"error\":\"invalid include_pdp query; use true or false\"}");
			return;
		}
		mm = sgsn_mm_ctx_by_imsi(imsi);
		if (!mm) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"mm context not found\"}");
			return;
		}
		body = build_mm_json(mm, include_pdp);
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strncmp(method, "POST", 4) && !strncmp(path, "/v1/subscribers/", 16)) {
		const char *suffix = path + 16;
		const char *action = strchr(suffix, '/');
		char imsi_buf[GSM23003_IMSI_MAX_DIGITS + 1];

		if (!action) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"unknown endpoint\"}");
			return;
		}
		if ((size_t)(action - suffix) >= sizeof(imsi_buf)) {
			api_send(ac, 400, "Bad Request", "application/json",
				 "{\"error\":\"imsi too long\"}");
			return;
		}
		memcpy(imsi_buf, suffix, action - suffix);
		imsi_buf[action - suffix] = '\0';
		mm = sgsn_mm_ctx_by_imsi(imsi_buf);
		if (!mm) {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"mm context not found\"}");
			return;
		}
		if (!strcmp(action, "/disconnect")) {
			gsm0408_gprs_access_cancelled(mm, SGSN_ERROR_CAUSE_NONE);
			api_send(ac, 200, "OK", "application/json",
				 "{\"ok\":true,\"action\":\"disconnect\"}");
		} else if (!strcmp(action, "/detach")) {
			gsm0408_gprs_access_denied(mm, GMM_CAUSE_IMPL_DETACHED);
			api_send(ac, 200, "OK", "application/json",
				 "{\"ok\":true,\"action\":\"detach\"}");
		} else {
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"unknown action\"}");
		}
	} else {
		api_send(ac, 404, "Not Found", "application/json",
			 "{\"error\":\"not found\"}");
	}

	if (body)
		talloc_free(body);
}

int sgsn_api_init(struct sgsn_instance *inst)
{
	const char *bind_addr;
	uint16_t port;
	int fd;

	g_api_ctx = tall_sgsn_ctx;

	if (!api_enabled()) {
		LOGP(DGPRS, LOGL_NOTICE, "HTTP API disabled (no api token configured)\n");
		return 0;
	}

	bind_addr = inet_ntoa(inst->cfg.api.bind_addr);
	port = inst->cfg.api.port ? inst->cfg.api.port : SGSN_API_DEFAULT_PORT;

	fd = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP, bind_addr, port,
			    OSMO_SOCK_F_BIND | OSMO_SOCK_F_NONBLOCK);
	if (fd < 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to open HTTP API on %s:%u\n", bind_addr, port);
		return -EIO;
	}
	if (listen(fd, 128) < 0)
		LOGP(DGPRS, LOGL_ERROR, "HTTP API listen(%s:%u) failed: %s\n",
		     bind_addr, port, strerror(errno));

	if (pipe(g_api_wake_pipe) < 0) {
		LOGP(DGPRS, LOGL_ERROR, "HTTP API pipe() failed: %s\n", strerror(errno));
		close(fd);
		return -EIO;
	}
	osmo_sock_set_nonblock(g_api_wake_pipe[0], 1);
	osmo_sock_set_nonblock(g_api_wake_pipe[1], 1);
	osmo_fd_setup(&g_api_wake_ofd, g_api_wake_pipe[0], OSMO_FD_READ, api_wake_cb, NULL, 0);
	if (osmo_fd_register(&g_api_wake_ofd) < 0) {
		LOGP(DGPRS, LOGL_ERROR, "HTTP API wake fd register failed\n");
		goto err_pipe;
	}

	g_api_listen_fd = fd;
	g_api_thread_run = true;
	if (pthread_create(&g_api_thread, NULL, api_thread_main, NULL) != 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to start HTTP API thread\n");
		g_api_thread_run = false;
		g_api_listen_fd = -1;
		osmo_fd_unregister(&g_api_wake_ofd);
		goto err_pipe;
	}

	LOGP(DGPRS, LOGL_NOTICE, "HTTP API listening on %s:%u (dedicated thread)\n", bind_addr, port);
	return 0;

err_pipe:
	close(g_api_wake_pipe[0]);
	close(g_api_wake_pipe[1]);
	g_api_wake_pipe[0] = g_api_wake_pipe[1] = -1;
	close(fd);
	return -EIO;
}

void sgsn_api_shutdown(void)
{
	struct sgsn_api_trace *t, *t2;
	unsigned i;

	pthread_mutex_lock(&g_api_trace_lock);
	llist_for_each_entry_safe(t, t2, &g_api_traces, entry) {
		llist_del(&t->entry);
		if (t->target)
			log_target_destroy(t->target);
		talloc_free(t);
	}
	pthread_mutex_unlock(&g_api_trace_lock);

	if (g_api_listen_fd < 0)
		return;

	pthread_mutex_lock(&g_api_lock);
	g_api_thread_run = false;
	pthread_cond_broadcast(&g_api_job_cond);
	pthread_mutex_unlock(&g_api_lock);
	shutdown(g_api_listen_fd, SHUT_RDWR);
	close(g_api_listen_fd);
	g_api_listen_fd = -1;
	pthread_join(g_api_thread, NULL);

	osmo_fd_unregister(&g_api_wake_ofd);
	close(g_api_wake_pipe[0]);
	close(g_api_wake_pipe[1]);
	g_api_wake_pipe[0] = g_api_wake_pipe[1] = -1;

	for (i = 0; i < SGSN_API_MAX_CLIENTS; i++) {
		if (g_api_conns[i])
			api_client_close(g_api_conns[i]);
	}
	g_api_client_count = 0;
}
