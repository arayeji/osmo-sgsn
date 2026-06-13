/* Embedded HTTP REST API for OsmoSGSN */

#include <stdarg.h>
#include <strings.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/gtp/pdp.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/sgsn_api.h>

#define API_CONN_BUF_SIZE (64 * 1024)

struct api_conn {
	struct osmo_stream_srv *conn;
	char buf[API_CONN_BUF_SIZE];
	size_t len;
};

static struct osmo_stream_srv_link *g_api_link;
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
			   llist_count(&sgsn->pdp_list));

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

static void api_send(struct osmo_stream_srv *conn, int code, const char *status,
		     const char *content_type, const char *body)
{
	struct msgb *msg;
	size_t body_len = body ? strlen(body) : 0;

	msg = msgb_alloc(512 + body_len, "sgsn-api-resp");
	if (!msg)
		return;

	if (content_type && body)
		msgb_printf(msg, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
			    code, status, content_type, body_len, body);
	else
		msgb_printf(msg, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			    code, status);

	osmo_stream_srv_send(conn, msg);
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
	char expect[256];
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
	const char *sp1, *sp2, *sp3;
	size_t plen;

	sp1 = strchr(req, ' ');
	if (!sp1)
		return false;
	sp2 = strchr(sp1 + 1, ' ');
	if (!sp2)
		return false;

	osmo_strlcpy(method, sp1 + 1, method_len);
	sp3 = strchr(sp2 + 1, ' ');
	plen = sp3 ? (size_t)(sp3 - (sp2 + 1)) : strlen(sp2 + 1);
	if (plen >= path_len)
		return false;
	memcpy(path, sp2 + 1, plen);
	path[plen] = '\0';
	return path[0] == '/';
}

static void handle_request(struct osmo_stream_srv *conn, const char *req)
{
	char method[16] = {};
	char path[256] = {};
	char *body = NULL;
	const char *imsi;
	struct sgsn_mm_ctx *mm;

	if (!parse_path(req, method, sizeof(method), path, sizeof(path))) {
		api_send(conn, 400, "Bad Request", NULL, NULL);
		return;
	}

	if (strcmp(path, "/health") == 0) {
		api_send(conn, 200, "OK", "application/json", "{\"status\":\"ok\"}");
		return;
	}

	if (!auth_ok(req)) {
		api_send(conn, 401, "Unauthorized", "application/json",
			 "{\"error\":\"invalid or missing token\"}");
		return;
	}

	if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/counts")) {
		body = build_counts_json();
		api_send(conn, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/mm")) {
		body = build_mm_list_json(true);
		api_send(conn, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strcmp(method, "GET") && !strcmp(path, "/v1/contexts/pdp")) {
		body = build_pdp_list_json();
		api_send(conn, body ? 200 : 500, body ? "OK" : "Error",
			 "application/json", body ? body : "{\"error\":\"oom\"}");
	} else if (!strncmp(method, "GET", 3) && !strncmp(path, "/v1/contexts/mm/", 16)) {
		imsi = path + 16;
		mm = sgsn_mm_ctx_by_imsi(imsi);
		if (!mm)
			api_send(conn, 404, "Not Found", "application/json",
				 "{\"error\":\"mm context not found\"}");
		else {
			body = build_mm_json(mm, true);
			api_send(conn, body ? 200 : 500, body ? "OK" : "Error",
				 "application/json", body ? body : "{\"error\":\"oom\"}");
		}
	} else if (!strncmp(method, "POST", 4) && !strncmp(path, "/v1/subscribers/", 16)) {
		const char *suffix = path + 16;
		const char *action = strchr(suffix, '/');
		char imsi_buf[GSM23003_IMSI_MAX_DIGITS + 1];

		if (!action) {
			api_send(conn, 404, "Not Found", "application/json",
				 "{\"error\":\"unknown endpoint\"}");
			return;
		}
		if ((size_t)(action - suffix) >= sizeof(imsi_buf)) {
			api_send(conn, 400, "Bad Request", "application/json",
				 "{\"error\":\"imsi too long\"}");
			return;
		}
		memcpy(imsi_buf, suffix, action - suffix);
		imsi_buf[action - suffix] = '\0';
		mm = sgsn_mm_ctx_by_imsi(imsi_buf);
		if (!mm) {
			api_send(conn, 404, "Not Found", "application/json",
				 "{\"error\":\"mm context not found\"}");
			return;
		}
		if (!strcmp(action, "/disconnect")) {
			gsm0408_gprs_access_cancelled(mm, SGSN_ERROR_CAUSE_NONE);
			api_send(conn, 200, "OK", "application/json",
				 "{\"ok\":true,\"action\":\"disconnect\"}");
		} else if (!strcmp(action, "/detach")) {
			gsm0408_gprs_access_denied(mm, GMM_CAUSE_IMPL_DETACHED);
			api_send(conn, 200, "OK", "application/json",
				 "{\"ok\":true,\"action\":\"detach\"}");
		} else {
			api_send(conn, 404, "Not Found", "application/json",
				 "{\"error\":\"unknown action\"}");
		}
	} else {
		api_send(conn, 404, "Not Found", "application/json",
			 "{\"error\":\"not found\"}");
	}

	if (body)
		talloc_free(body);
}

static int api_conn_read_cb(struct osmo_stream_srv *conn)
{
	struct api_conn *ac = osmo_stream_srv_get_data(conn);
	struct msgb *msg = msgb_alloc(4096, "sgsn-api-rx");
	int rc;
	char *hdr_end;

	if (!ac || !msg)
		return -1;

	rc = osmo_stream_srv_recv(conn, msg);
	if (rc <= 0) {
		msgb_free(msg);
		return rc;
	}

	if (ac->len + msg->len >= sizeof(ac->buf)) {
		msgb_free(msg);
		api_send(conn, 413, "Payload Too Large", NULL, NULL);
		return -1;
	}

	memcpy(ac->buf + ac->len, msg->data, msg->len);
	ac->len += msg->len;
	ac->buf[ac->len] = '\0';
	msgb_free(msg);

	hdr_end = strstr(ac->buf, "\r\n\r\n");
	if (!hdr_end)
		return 0;

	*hdr_end = '\0';
	handle_request(conn, ac->buf);
	osmo_stream_srv_set_flush_and_destroy(conn);
	return 0;
}

static int api_link_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct api_conn *ac;

	ac = talloc_zero(g_api_ctx, struct api_conn);
	if (!ac)
		return -1;

	ac->conn = osmo_stream_srv_create(g_api_ctx, link, fd, api_conn_read_cb, NULL, ac);
	if (!ac->conn) {
		talloc_free(ac);
		return -1;
	}
	osmo_stream_srv_set_data(ac->conn, ac);
	osmo_stream_srv_set_name(ac->conn, "sgsn-api-client");
	return 0;
}

int sgsn_api_init(struct sgsn_instance *inst)
{
	const char *bind_addr;
	uint16_t port;

	g_api_ctx = tall_sgsn_ctx;

	if (!api_enabled()) {
		LOGP(DGPRS, LOGL_NOTICE, "HTTP API disabled (no api token configured)\n");
		return 0;
	}

	bind_addr = inet_ntoa(inst->cfg.api.bind_addr);
	port = inst->cfg.api.port ? inst->cfg.api.port : SGSN_API_DEFAULT_PORT;

	g_api_link = osmo_stream_srv_link_create(g_api_ctx);
	if (!g_api_link)
		return -ENOMEM;

	osmo_stream_srv_link_set_name(g_api_link, "sgsn-api");
	osmo_stream_srv_link_set_addr(g_api_link, bind_addr);
	osmo_stream_srv_link_set_port(g_api_link, port);
	osmo_stream_srv_link_set_accept_cb(g_api_link, api_link_accept_cb);

	if (osmo_stream_srv_link_open(g_api_link) != 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to open HTTP API on %s:%u\n", bind_addr, port);
		osmo_stream_srv_link_destroy(g_api_link);
		g_api_link = NULL;
		return -EIO;
	}

	LOGP(DGPRS, LOGL_NOTICE, "HTTP API listening on %s:%u\n", bind_addr, port);
	return 0;
}

void sgsn_api_shutdown(void)
{
	if (g_api_link) {
		osmo_stream_srv_link_close(g_api_link);
		osmo_stream_srv_link_destroy(g_api_link);
		g_api_link = NULL;
	}
}
