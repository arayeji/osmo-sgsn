/* Embedded HTTP REST API for OsmoSGSN */

#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stat_item.h>
#include <osmocom/core/base64.h>
#include <osmocom/gtp/gsn.h>
#include <osmocom/gtp/pdp.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

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
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/iu_rnc_fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/osmo_ss7.h>
#endif

#define API_CONN_BUF_SIZE (64 * 1024)
#define SGSN_API_TRACE_PKT_MAX 4096

struct api_conn {
	struct osmo_fd ofd;
	char buf[API_CONN_BUF_SIZE];
	size_t len;
};

static struct osmo_fd g_api_listen_fd;
static bool g_api_listen_registered;
static void *g_api_ctx;

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
/* PrettyNMS polls /v1/links and /v1/stats. Skip corrupt/stale RNC objects
 * instead of calling osmo_sccp_addr_dump() / walking bad list nodes. */
static bool api_iu_rnc_usable(const struct ranap_iu_rnc *rnc)
{
	if (!rnc)
		return false;
	if (!rnc->fi || rnc->fi->priv != rnc)
		return false;
	if (rnc->fi->fsm != &iu_rnc_fsm)
		return false;
	return true;
}

static void api_fmt_rnc_state(const struct ranap_iu_rnc *rnc, char *out, size_t out_len)
{
	if (!out || !out_len)
		return;
	if (!api_iu_rnc_usable(rnc)) {
		out[0] = '\0';
		return;
	}
	snprintf(out, out_len, "%s", osmo_fsm_inst_state_name(rnc->fi));
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

static unsigned api_iu_rnc_ra_count(const struct ranap_iu_rnc *rnc)
{
	unsigned count = 0;
	struct iu_lac_rac_entry *lre;

	if (!api_iu_rnc_usable(rnc))
		return 0;

	llist_for_each_entry(lre, &rnc->lac_rac_list, entry)
		count++;
	return count;
}
#endif

static const char *mm_state_name(const struct sgsn_mm_ctx *mm)
{
	switch (mm->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
#if BUILD_IU
		return osmo_fsm_inst_state_name(mm->iu.mm_state_fsm);
#endif
		break;
	case MM_CTX_T_GERAN_Gb:
		return osmo_fsm_inst_state_name(mm->gb.mm_state_fsm);
	default:
		break;
	}
	return "unknown";
}

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

static unsigned api_sgsn_pdp_count(void)
{
	unsigned count = 0;
	struct sgsn_pdp_ctx *pdp;

	if (!sgsn)
		return 0;
	llist_for_each_entry(pdp, &sgsn->pdp_list, g_list)
		count++;
	return count;
}

static unsigned api_ggsn_pdp_count(const struct sgsn_ggsn_ctx *ggsn)
{
	unsigned count = 0;
	struct sgsn_pdp_ctx *pdp;

	if (!ggsn)
		return 0;
	llist_for_each_entry(pdp, &ggsn->pdp_list, ggsn_list)
		count++;
	return count;
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

	mm_count = llist_count(&sgsn->mm_list);
	pdp_count = api_sgsn_pdp_count();

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

static char *build_mm_json(const struct sgsn_mm_ctx *mm, bool include_pdp)
{
	char *start, *cur;
	size_t space;
	char esc[256];
	char addr[INET6_ADDRSTRLEN + 8];
	char apnbuf[APN_MAXLEN + 1];
	struct sgsn_pdp_ctx *pdp;
	bool first_pdp;

	start = talloc_zero_size(g_api_ctx, 64 * 1024);
	if (!start)
		return NULL;
	cur = start;
	space = 64 * 1024;

	json_escape(mm->imsi, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "{\"imsi\":\"%s\",", esc);
	json_escape(mm->imei, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"imei\":\"%s\",", esc);
	json_escape(mm->msisdn, esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"msisdn\":\"%s\",", esc);
	cur = json_append(cur, start, &space, "\"p_tmsi\":\"%08x\",", mm->p_tmsi);
	cur = json_append(cur, start, &space, "\"tlli\":\"%08x\",", mm->gb.tlli);
	json_escape(osmo_fsm_inst_state_name(mm->gmm_fsm), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"gmm_state\":\"%s\",", esc);
	json_escape(osmo_rai_name2(&mm->ra), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"routing_area\":\"%s\",", esc);
	cur = json_append(cur, start, &space, "\"cell_id\":%u,", mm->gb.cell_id);
	json_escape(mm_state_name(mm), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"mm_state\":\"%s\",", esc);
	json_escape(get_value_string(sgsn_ran_type_names, mm->ran_type), esc, sizeof(esc));
	cur = json_append(cur, start, &space, "\"ran_type\":\"%s\",", esc);

	if (!include_pdp) {
		cur = json_append(cur, start, &space, "\"pdp_count\":%u}", llist_count(&mm->pdp_list));
		return start;
	}

	cur = json_append(cur, start, &space, "\"pdp_contexts\":[");
	first_pdp = true;
	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (!first_pdp)
			cur = json_append(cur, start, &space, ",");
		first_pdp = false;

		cur = json_append(cur, start, &space, "{\"nsapi\":%u,\"sapi\":%u,\"ti\":%u,",
				  pdp->nsapi, pdp->sapi, pdp->ti);
		if (pdp->lib) {
			osmo_apn_to_str(apnbuf, pdp->lib->apn_use.v, pdp->lib->apn_use.l);
			json_escape(apnbuf, esc, sizeof(esc));
			cur = json_append(cur, start, &space, "\"apn\":\"%s\",", esc);
			pdp_addr_str(pdp->lib->eua.v, pdp->lib->eua.l, addr, sizeof(addr));
			json_escape(addr, esc, sizeof(esc));
			cur = json_append(cur, start, &space, "\"pdp_address\":\"%s\"", esc);
		} else {
			cur = json_append(cur, start, &space, "\"apn\":\"\",\"pdp_address\":\"\"");
		}
		cur = json_append(cur, start, &space, "}");
	}
	cur = json_append(cur, start, &space, "]}");
	return start;
}

static char *build_counts_json(void)
{
	unsigned mm_count = 0, pdp_count = 0, active_pdp = 0;
	struct sgsn_mm_ctx *mm;
	struct sgsn_pdp_ctx *pdp;
	char *json;

	llist_for_each_entry(mm, &sgsn->mm_list, list)
		mm_count++;
	llist_for_each_entry(pdp, &sgsn->pdp_list, g_list)
		pdp_count++;
	llist_for_each_entry(mm, &sgsn->mm_list, list)
		active_pdp += llist_count(&mm->pdp_list);

	json = talloc_asprintf(g_api_ctx,
			       "{\"mm_context_count\":%u,\"pdp_context_count\":%u,\"active_pdp_count\":%u}",
			       mm_count, pdp_count, active_pdp);
	return json;
}

static char *build_mm_list_json(bool include_pdp)
{
	char *start, *cur, *entry;
	size_t space;
	bool first = true;
	struct sgsn_mm_ctx *mm;

	start = talloc_zero_size(g_api_ctx, 256 * 1024);
	if (!start)
		return NULL;
	cur = start;
	space = 256 * 1024;
	cur = json_append(cur, start, &space, "{\"count\":%u,\"mm_contexts\":[",
			   llist_count(&sgsn->mm_list));

	llist_for_each_entry(mm, &sgsn->mm_list, list) {
		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;
		entry = build_mm_json(mm, include_pdp);
		if (!entry)
			continue;
		cur = json_append(cur, start, &space, "%s", entry);
		talloc_free(entry);
	}
	cur = json_append(cur, start, &space, "]}");
	return start;
}

static char *build_pdp_list_json(void)
{
	char *start, *cur;
	size_t space;
	char esc[256];
	char addr[INET6_ADDRSTRLEN + 8];
	char apnbuf[APN_MAXLEN + 1];
	struct sgsn_pdp_ctx *pdp;
	bool first = true;

	start = talloc_zero_size(g_api_ctx, 256 * 1024);
	if (!start)
		return NULL;
	cur = start;
	space = 256 * 1024;
	cur = json_append(cur, start, &space, "{\"count\":%u,\"pdp_contexts\":[",
			   api_sgsn_pdp_count());

	llist_for_each_entry(pdp, &sgsn->pdp_list, g_list) {
		const char *imsi = pdp->mm ? pdp->mm->imsi : "";

		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;

		json_escape(imsi, esc, sizeof(esc));
		cur = json_append(cur, start, &space, "{\"imsi\":\"%s\",\"nsapi\":%u,\"sapi\":%u,\"ti\":%u,",
				  esc, pdp->nsapi, pdp->sapi, pdp->ti);
		if (pdp->lib) {
			osmo_apn_to_str(apnbuf, pdp->lib->apn_use.v, pdp->lib->apn_use.l);
			json_escape(apnbuf, esc, sizeof(esc));
			cur = json_append(cur, start, &space, "\"apn\":\"%s\",", esc);
			pdp_addr_str(pdp->lib->eua.v, pdp->lib->eua.l, addr, sizeof(addr));
			json_escape(addr, esc, sizeof(esc));
			cur = json_append(cur, start, &space, "\"pdp_address\":\"%s\"}", esc);
		} else {
			cur = json_append(cur, start, &space, "\"apn\":\"\",\"pdp_address\":\"\"}");
		}
	}
	cur = json_append(cur, start, &space, "]}");
	return start;
}

static char *build_links_json(void)
{
	char *start, *cur, *esc;
	size_t space;
	bool first;
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_mme_ctx *mme;
#if BUILD_IU
	struct ranap_iu_rnc *rnc;
#endif

	start = talloc_zero_size(g_api_ctx, 64 * 1024);
	if (!start)
		return NULL;
	cur = start;
	space = 64 * 1024;
	esc = talloc_size(g_api_ctx, 512);
	if (!esc)
		return NULL;

	cur = json_append(cur, start, &space, "{\"api\":[");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/health\",\"auth\":false,\"description\":\"Health check\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/stats\",\"auth\":true,\"description\":\"Operational stats snapshot\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/links\",\"auth\":true,\"description\":\"API and network links\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/contexts/counts\",\"auth\":true,\"description\":\"Context counts\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/contexts/mm\",\"auth\":true,\"description\":\"All MM contexts\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/contexts/pdp\",\"auth\":true,\"description\":\"All PDP contexts\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/contexts/mm/{imsi}\",\"auth\":true,\"description\":\"One MM context\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"POST\",\"path\":\"/v1/subscribers/{imsi}/disconnect\",\"auth\":true,\"description\":\"Disconnect subscriber PDP sessions\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"POST\",\"path\":\"/v1/subscribers/{imsi}/detach\",\"auth\":true,\"description\":\"Detach subscriber\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"GET\",\"path\":\"/v1/trace\",\"auth\":true,\"description\":\"List active IMSI debug traces\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"POST\",\"path\":\"/v1/trace/{imsi}\",\"auth\":true,\"description\":\"Enable IMSI debug trace\"},");
	cur = json_append(cur, start, &space,
			  "{\"method\":\"DELETE\",\"path\":\"/v1/trace/{imsi}\",\"auth\":true,\"description\":\"Disable IMSI debug trace\"}],");
	cur = json_append(cur, start, &space, "\"network\":{");

	if (sgsn->gsn) {
		cur = json_append(cur, start, &space, "\"gtp\":{");
		json_escape(inet_ntoa(sgsn->gsn->gsnc), esc, 512);
		cur = json_append(cur, start, &space, "\"signalling_ip\":\"%s\",", esc);
		json_escape(inet_ntoa(sgsn->gsn->gsnu), esc, 512);
		cur = json_append(cur, start, &space, "\"user_ip\":\"%s\"},", esc);
	} else {
		cur = json_append(cur, start, &space, "\"gtp\":null,");
	}

	json_escape(inet_ntoa(sgsn->cfg.gtp_listenaddr.sin_addr), esc, 512);
	cur = json_append(cur, start, &space, "\"gtp_local_ip\":\"%s\",", esc);

	cur = json_append(cur, start, &space, "\"ggsn\":[");
	first = true;
	llist_for_each_entry(ggsn, &sgsn->ggsn_list, list) {
		if (ggsn->id == UINT32_MAX)
			continue;
		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;
		json_escape(inet_ntoa(ggsn->remote_addr), esc, 512);
		cur = json_append(cur, start, &space,
				  "{\"id\":%u,\"remote_ip\":\"%s\",\"gtp_version\":%u,\"pdp_count\":%u,\"echo_interval\":%u}",
				  ggsn->id, esc, ggsn->gtp_version,
				  api_ggsn_pdp_count(ggsn), ggsn->echo_interval);
	}
	cur = json_append(cur, start, &space, "],");

	if (sgsn->gsup_client) {
		cur = json_append(cur, start, &space, "\"gsup\":{");
		json_escape(osmo_gsup_client_get_rem_addr(sgsn->gsup_client), esc, 512);
		cur = json_append(cur, start, &space, "\"remote_ip\":\"%s\",", esc);
		cur = json_append(cur, start, &space, "\"remote_port\":%d,",
				  osmo_gsup_client_get_rem_port(sgsn->gsup_client));
		cur = json_append(cur, start, &space, "\"connected\":%s},",
				  osmo_gsup_client_is_connected(sgsn->gsup_client) ? "true" : "false");
	} else if (sgsn->cfg.gsup_server_addr.sin_addr.s_addr) {
		cur = json_append(cur, start, &space, "\"gsup\":{");
		json_escape(inet_ntoa(sgsn->cfg.gsup_server_addr.sin_addr), esc, 512);
		cur = json_append(cur, start, &space, "\"remote_ip\":\"%s\",", esc);
		cur = json_append(cur, start, &space, "\"remote_port\":%d,",
				  sgsn->cfg.gsup_server_port);
		cur = json_append(cur, start, &space, "\"connected\":false},");
	} else {
		cur = json_append(cur, start, &space, "\"gsup\":null,");
	}

	cur = json_append(cur, start, &space, "\"mme\":[");
	first = true;
	llist_for_each_entry(mme, &sgsn->mme_list, list) {
		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;
		json_escape(mme->name ? mme->name : "", esc, 512);
		cur = json_append(cur, start, &space, "{\"name\":\"%s\",", esc);
		json_escape(inet_ntoa(mme->remote_addr), esc, 512);
		cur = json_append(cur, start, &space,
				  "\"remote_ip\":\"%s\",\"default_route\":%s}",
				  esc, mme->default_route ? "true" : "false");
	}

#if BUILD_IU
	/* Same safe walk as /v1/stats. */
	cur = json_append(cur, start, &space, "],\"iu_rnc\":[");
	first = true;
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		if (!api_iu_rnc_usable(rnc))
			continue;

		if (!first)
			cur = json_append(cur, start, &space, ",");
		first = false;
		api_fmt_rnc_id(&rnc->rnc_id, esc, 512);
		cur = json_append(cur, start, &space, "{\"rnc_id\":\"%s\",", esc);
		api_fmt_sccp_pc(&rnc->sccp_addr, esc, 512);
		cur = json_append(cur, start, &space, "\"sccp_addr\":\"%s\",", esc);
		api_fmt_rnc_state(rnc, esc, 512);
		cur = json_append(cur, start, &space,
				  "\"state\":\"%s\",\"routing_areas\":%u}",
				  esc, api_iu_rnc_ra_count(rnc));
	}
	cur = json_append(cur, start, &space, "]}}");
#else
	cur = json_append(cur, start, &space, "]}}");
#endif

	talloc_free(esc);
	return start;
}

static void api_send(struct api_conn *ac, int code, const char *status,
		     const char *content_type, const char *body)
{
	char *resp;
	size_t body_len = body ? strlen(body) : 0;
	ssize_t rc;

	if (content_type && body)
		resp = talloc_asprintf(g_api_ctx,
				       "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
				       code, status, content_type, body_len, body);
	else
		resp = talloc_asprintf(g_api_ctx,
				       "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
				       code, status);
	if (!resp)
		return;

	rc = write(ac->ofd.fd, resp, strlen(resp));
	if (rc < 0)
		LOGP(DGPRS, LOGL_ERROR, "HTTP API write failed: %s\n", strerror(errno));
	talloc_free(resp);
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
		       char *path, size_t path_len)
{
	const char *sp1, *sp2, *eol;
	size_t mlen, plen;

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
	memcpy(path, sp1 + 1, plen);
	path[plen] = '\0';
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

static struct sgsn_api_trace *api_trace_find(const char *imsi)
{
	struct sgsn_api_trace *t;

	llist_for_each_entry(t, &g_api_traces, entry) {
		if (!strcmp(t->imsi, imsi))
			return t;
	}
	return NULL;
}

/* libosmocore log target output callback: keep only lines mentioning the traced
 * IMSI and write them to stderr, so the daemon's journald unit captures them. */
static void api_trace_log_output(struct log_target *tgt, unsigned int level, const char *line)
{
	struct sgsn_api_trace *t;

	llist_for_each_entry(t, &g_api_traces, entry) {
		if (t->target != tgt)
			continue;
		if (strstr(line, t->imsi)) {
			fputs(line, stderr);
			fflush(stderr);
		}
		return;
	}
}

static bool api_valid_imsi(const char *imsi)
{
	const char *p;
	size_t n = 0;

	if (!imsi || !imsi[0])
		return false;
	for (p = imsi; *p; p++, n++) {
		if (*p < '0' || *p > '9')
			return false;
	}
	return n >= 5 && n <= 15;
}

/* Returns 0 on success (*out set), negative errno otherwise. */
static int api_trace_enable(const char *imsi, struct sgsn_api_trace **out)
{
	struct sgsn_api_trace *t;
	struct log_target *tgt;

	t = api_trace_find(imsi);
	if (t) {
		*out = t;	/* idempotent */
		return 0;
	}

	t = talloc_zero(g_api_ctx, struct sgsn_api_trace);
	if (!t)
		return -ENOMEM;
	osmo_strlcpy(t->imsi, imsi, sizeof(t->imsi));

	tgt = log_target_create();
	if (!tgt) {
		talloc_free(t);
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
	log_add_target(tgt);

	LOGP(DGPRS, LOGL_NOTICE, "API enabled IMSI debug trace for %s (-> journal)\n", imsi);
	*out = t;
	return 0;
}

static int api_trace_disable(const char *imsi)
{
	struct sgsn_api_trace *t = api_trace_find(imsi);

	if (!t)
		return -ENOENT;

	llist_del(&t->entry);
	if (t->target)
		log_target_destroy(t->target);
	LOGP(DGPRS, LOGL_NOTICE, "API disabled IMSI debug trace for %s\n", imsi);
	talloc_free(t);
	return 0;
}

bool sgsn_api_trace_active(const char *imsi)
{
	if (!imsi || !imsi[0])
		return false;
	return api_trace_find(imsi) != NULL;
}

void sgsn_api_trace_packet(const char *imsi, const char *proto, bool tx,
			   const uint8_t *data, size_t len)
{
	size_t cap_len, b64_len, olen;
	bool truncated = false;
	unsigned char *b64;
	char line[32 + 16 + 8 + 16 + SGSN_API_TRACE_PKT_MAX * 4 / 3 + 64];

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
	b64 = talloc_size(g_api_ctx, b64_len);
	if (!b64)
		return;

	if (osmo_base64_encode(b64, b64_len, &olen, data, cap_len) < 0) {
		talloc_free(b64);
		return;
	}

	snprintf(line, sizeof(line),
		 "[IMSI:%s] PACKET: proto=%s dir=%s len=%zu%s b64=%s\n",
		 imsi, proto, tx ? "tx" : "rx", cap_len,
		 truncated ? " trunc=1" : "", b64);
	fputs(line, stderr);
	fflush(stderr);
	talloc_free(b64);
}

void sgsn_api_trace_packet_mm(const struct sgsn_mm_ctx *mm, const char *proto,
			      bool tx, const uint8_t *data, size_t len)
{
	if (!mm || !mm->imsi[0])
		return;
	sgsn_api_trace_packet(mm->imsi, proto, tx, data, len);
}

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
	char *body = NULL;
	const char *imsi;
	struct sgsn_mm_ctx *mm;

	if (!parse_path(req, method, sizeof(method), path, sizeof(path))) {
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
		body = build_mm_list_json(true);
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/pdp")) {
		body = build_pdp_list_json();
		api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strncmp(method, "GET", 3) && !strncmp(path, "/v1/contexts/mm/", 16)) {
		imsi = path + 16;
		mm = sgsn_mm_ctx_by_imsi(imsi);
		if (!mm)
			api_send(ac, 404, "Not Found", "application/json",
				 "{\"error\":\"mm context not found\"}");
		else {
			body = build_mm_json(mm, true);
			api_send(ac, body ? 200 : 500, body ? "OK" : "Error",
				 "application/json", body ? body : "{\"error\":\"oom\"}");
		}
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

static void api_client_close(struct api_conn *ac)
{
	osmo_fd_unregister(&ac->ofd);
	close(ac->ofd.fd);
	talloc_free(ac);
}

static int api_client_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct api_conn *ac = ofd->data;
	char *hdr_end;
	ssize_t rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	rc = read(ofd->fd, ac->buf + ac->len, sizeof(ac->buf) - ac->len - 1);
	if (rc <= 0) {
		api_client_close(ac);
		return -1;
	}

	ac->len += rc;
	ac->buf[ac->len] = '\0';

	if (ac->len + 1 >= sizeof(ac->buf)) {
		api_send(ac, 413, "Payload Too Large", NULL, NULL);
		api_client_close(ac);
		return -1;
	}

	hdr_end = strstr(ac->buf, "\r\n\r\n");
	if (!hdr_end)
		return 0;

	*hdr_end = '\0';
	handle_request(ac, ac->buf);
	api_client_close(ac);
	return 0;
}

static int api_listen_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct api_conn *ac;
	int cfd;

	if (!(what & OSMO_FD_READ))
		return 0;

	cfd = accept(ofd->fd, NULL, NULL);
	if (cfd < 0) {
		if (errno != EAGAIN && errno != EINTR)
			LOGP(DGPRS, LOGL_ERROR, "HTTP API accept failed: %s\n", strerror(errno));
		return 0;
	}

	osmo_sock_set_nonblock(cfd, 1);

	ac = talloc_zero(g_api_ctx, struct api_conn);
	if (!ac) {
		close(cfd);
		return 0;
	}

	osmo_fd_setup(&ac->ofd, cfd, OSMO_FD_READ, api_client_cb, ac, 0);
	if (osmo_fd_register(&ac->ofd) != 0) {
		close(cfd);
		talloc_free(ac);
	}
	return 0;
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

	osmo_fd_setup(&g_api_listen_fd, fd, OSMO_FD_READ, api_listen_cb, NULL, 0);
	if (osmo_fd_register(&g_api_listen_fd) != 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to register HTTP API socket\n");
		close(fd);
		return -EIO;
	}

	g_api_listen_registered = true;
	LOGP(DGPRS, LOGL_NOTICE, "HTTP API listening on %s:%u\n", bind_addr, port);
	return 0;
}

void sgsn_api_shutdown(void)
{
	struct sgsn_api_trace *t, *t2;

	llist_for_each_entry_safe(t, t2, &g_api_traces, entry) {
		llist_del(&t->entry);
		if (t->target)
			log_target_destroy(t->target);
		talloc_free(t);
	}

	if (g_api_listen_registered) {
		osmo_fd_unregister(&g_api_listen_fd);
		close(g_api_listen_fd.fd);
		g_api_listen_registered = false;
	}
}
