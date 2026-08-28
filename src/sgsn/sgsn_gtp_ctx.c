/* GTP-C SGSN Context Request/Response/Ack (TS 29.060 §7.5.3–7.5.5) */

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/gtpie.h>
#include <osmocom/gtp/gsn.h>
#include <osmocom/gtp/pdp.h>
#include <osmocom/gtp/version.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/signal.h>
#include <osmocom/core/signal.h>

#define SGSN_CTX_MAX_PDP_IE	16
#define SGSN_CTX_MM_BUF		512
#define SGSN_CTX_PDP_BUF	512

struct sgsn_ctx_xfer {
	struct llist_head	list;
	uint32_t		local_ref;
	struct sgsn_mm_ctx	*mm;
};

static LLIST_HEAD(sgsn_ctx_xfer_list);

static void ctx_xfer_purge_mm(struct sgsn_mm_ctx *mm)
{
	struct sgsn_ctx_xfer *xfer, *tmp;

	if (!mm)
		return;

	llist_for_each_entry_safe(xfer, tmp, &sgsn_ctx_xfer_list, list) {
		if (xfer->mm != mm)
			continue;
		llist_del(&xfer->list);
		talloc_free(xfer);
	}
}

static int sgsn_gtp_ctx_mm_signal(unsigned subsys, unsigned signal,
				  void *handler_data, void *_signal_data)
{
	struct sgsn_signal_data *sd = _signal_data;

	(void)handler_data;

	if (subsys != SS_SGSN)
		return 0;

	if (signal == S_SGSN_MM_FREE && sd && sd->mm)
		ctx_xfer_purge_mm(sd->mm);

	return 0;
}

static struct sgsn_subscriber_data *mm_subscr_data(struct sgsn_mm_ctx *mm)
{
	struct gprs_subscr *gsub;

	if (!mm || !mm->imsi[0])
		return NULL;
	if (mm->subscr && mm->subscr->sgsn_data)
		return mm->subscr->sgsn_data;
	gsub = gprs_subscr_get_by_imsi(mm->imsi);
	if (!gsub || !gsub->sgsn_data)
		return NULL;
	return gsub->sgsn_data;
}

static uint64_t imsi_str_to_gtp64(const char *imsi)
{
	uint64_t imsi64 = 0;
	unsigned int n;
	unsigned int imsi_len = strlen(imsi);

	for (n = 0; n < 16; n++) {
		uint64_t val;
		if (n < imsi_len)
			val = (imsi[n] - '0') & 0xf;
		else
			val = 0xf;
		imsi64 |= (val << (n * 4));
	}
	return imsi64;
}

static void imsi_gtp64_to_str(uint64_t imsi64, char *out, size_t out_len)
{
	unsigned int n;
	size_t o = 0;

	for (n = 0; n < 16 && o + 1 < out_len; n++) {
		uint8_t digit = (imsi64 >> (n * 4)) & 0xf;
		if (digit == 0xf)
			break;
		out[o++] = '0' + digit;
	}
	out[o] = '\0';
}

static struct sgsn_mm_ctx *mm_from_ctx_req_ie(union gtpie_member * const *ie)
{
	struct sgsn_mm_ctx *mm = NULL;
	uint64_t imsi64 = 0;
	uint32_t ptmsi = 0;
	uint8_t rai_buf[6];
	struct osmo_routing_area_id rai;

	if (!gtpie_gettv8(ie, GTPIE_IMSI, 0, &imsi64)) {
		char imsi[GSM23003_IMSI_MAX_DIGITS + 1];
		imsi_gtp64_to_str(imsi64, imsi, sizeof(imsi));
		return sgsn_mm_ctx_by_imsi(imsi);
	}

	if (gtpie_gettv4(ie, GTPIE_P_TMSI, 0, &ptmsi))
		return NULL;

	mm = sgsn_mm_ctx_by_ptmsi(ptmsi);
	if (!mm)
		return NULL;

	if (!gtpie_gettv0(ie, GTPIE_RAI, 0, rai_buf, sizeof(rai_buf))) {
		osmo_routing_area_id_decode(&rai, rai_buf, sizeof(rai_buf));
		if (osmo_rai_cmp(&rai, &mm->ra))
			return NULL;
	}

	return mm;
}

static bool ptmsi_sig_matches(struct sgsn_mm_ctx *mm, union gtpie_member * const *ie)
{
	uint8_t sig[3];

	if (gtpie_gettv0(ie, GTPIE_P_TMSI_S, 0, sig, sizeof(sig)))
		return true;
	if (!mm->p_tmsi_sig)
		return true;
	return mm->p_tmsi_sig == (sig[0] << 16 | sig[1] << 8 | sig[2]);
}

static bool mm_ctx_transferable(struct sgsn_mm_ctx *mm)
{
	if (!mm || !mm->gmm_fsm)
		return false;

	switch (mm->gmm_fsm->state) {
	case ST_GMM_REGISTERED_NORMAL:
	case ST_GMM_REGISTERED_SUSPENDED:
		return true;
	default:
		return false;
	}
}

static uint8_t gtp_cipher_from_mm(struct sgsn_mm_ctx *mm)
{
	if (mm->ciph_algo == GPRS_ALGO_GEA0)
		return 0;
	return (uint8_t)mm->ciph_algo;
}

static void triplet_encode(uint8_t *dst, const struct osmo_auth_vector *vec)
{
	memcpy(dst, vec->rand, 16);
	memcpy(dst + 16, vec->sres, 4);
	memcpy(dst + 20, vec->kc, 8);
}

static unsigned auth_triplet_count(struct sgsn_mm_ctx *mm)
{
	struct sgsn_subscriber_data *sd = mm_subscr_data(mm);
	unsigned int i, count = 0;

	if (!sd)
		return mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL ? 1 : 0;

	for (i = 0; i < ARRAY_SIZE(sd->auth_triplets); i++) {
		if (sd->auth_triplets[i].key_seq != GSM_KEY_SEQ_INVAL)
			count++;
	}
	if (!count && mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL)
		count = 1;
	return OSMO_MIN(count, 5);
}

static unsigned append_gsm_triplets(uint8_t *ptr, size_t space, struct sgsn_mm_ctx *mm)
{
	struct sgsn_subscriber_data *sd = mm_subscr_data(mm);
	unsigned int i, count = 0;

	if (sd) {
		for (i = 0; i < ARRAY_SIZE(sd->auth_triplets) && count < 5; i++) {
			if (sd->auth_triplets[i].key_seq == GSM_KEY_SEQ_INVAL)
				continue;
			if (space < 28)
				break;
			triplet_encode(ptr, &sd->auth_triplets[i].vec);
			ptr += 28;
			space -= 28;
			count++;
		}
	}
	if (!count && mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL && space >= 28) {
		triplet_encode(ptr, &mm->auth_triplet.vec);
		count = 1;
	}
	return count;
}

static const uint8_t *mm_kc(struct sgsn_mm_ctx *mm)
{
	if (mm->gb.llme && mm->gb.llme->cksn != GSM_KEY_SEQ_INVAL)
		return mm->gb.llme->kc;
	if (mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL)
		return mm->auth_triplet.vec.kc;
	return NULL;
}

/* TS 29.060 Figure 39/41: GSM key and triplets */
static int encode_gsm_mm_context(struct sgsn_mm_ctx *mm, uint8_t *buf, size_t buf_len)
{
	uint8_t *ptr = buf;
	uint8_t *end = buf + buf_len;
	const uint8_t *kc;
	uint8_t cksn;
	uint8_t cipher;
	unsigned num_vectors;
	uint16_t drx;

	if (end - ptr < 14)
		return -ENOSPC;

	drx = htons(mm->drx_parms);
	memcpy(ptr, &drx, 2);
	ptr += 2;

	kc = mm_kc(mm);
	cipher = gtp_cipher_from_mm(mm);
	cksn = mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL ?
		(mm->auth_triplet.key_seq & 0x07) : 7;
	num_vectors = auth_triplet_count(mm);

	if (cipher) {
		/* Figure 41: used cipher, GSM key and triplets */
		*ptr++ = (uint8_t)(5 << 5);
		*ptr++ = (cipher << 5) | (cksn & 0x07);
	} else {
		/* Figure 39: GSM key and triplets */
		*ptr++ = (uint8_t)((1 << 6) | ((num_vectors & 0x07) << 3));
	}

	if (!kc)
		memset(ptr, 0, 8);
	else
		memcpy(ptr, kc, 8);
	ptr += 8;

	if (!cipher) {
		unsigned n = append_gsm_triplets(ptr, end - ptr, mm);
		ptr += n * 28;
	}

	if (mm->ms_network_capa.len && end - ptr > 1 + mm->ms_network_capa.len) {
		*ptr++ = mm->ms_network_capa.len;
		memcpy(ptr, mm->ms_network_capa.buf, mm->ms_network_capa.len);
		ptr += mm->ms_network_capa.len;
	} else if (end - ptr >= 1) {
		*ptr++ = 0;
	}

	/* Container length = 0 (no IMEISV container) */
	if (end - ptr >= 2) {
		*ptr++ = 0;
		*ptr++ = 0;
	}

	/* Access restriction data length = 0 */
	if (end - ptr >= 1)
		*ptr++ = 0;

	return ptr - buf;
}

static int encode_quintuplet(uint8_t *dst, size_t space, const struct osmo_auth_vector *vec)
{
	uint8_t *ptr = dst;
	uint8_t xres_len = sizeof(vec->sres);
	uint8_t autn_len = sizeof(vec->autn);

	if (space < 16 + 1 + xres_len + 16 + 16 + 1 + autn_len)
		return -ENOSPC;

	memcpy(ptr, vec->rand, 16);
	ptr += 16;
	*ptr++ = xres_len;
	memcpy(ptr, vec->sres, xres_len);
	ptr += xres_len;
	memcpy(ptr, vec->ck, 16);
	ptr += 16;
	memcpy(ptr, vec->ik, 16);
	ptr += 16;
	*ptr++ = autn_len;
	memcpy(ptr, vec->autn, autn_len);
	ptr += autn_len;

	return ptr - dst;
}

/* TS 29.060 Figure 40: UMTS key and quintuplets */
static int encode_umts_mm_context(struct sgsn_mm_ctx *mm, uint8_t *buf, size_t buf_len)
{
	uint8_t *ptr = buf;
	uint8_t *end = buf + buf_len;
	uint8_t *quint_len_ptr;
	uint16_t drx;
	uint8_t ksi;
	unsigned num_vectors = 0;
	struct sgsn_subscriber_data *sd = mm_subscr_data(mm);
	unsigned int i;

	if (end - ptr < 40)
		return -ENOSPC;

	ksi = mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL ?
		(mm->auth_triplet.key_seq & 0x07) : 7;

	*ptr++ = (uint8_t)((1 << 7) | (1 << 6) | (0 << 3) | ksi);
	*ptr++ = (uint8_t)((2 << 6) | (0 << 3) | 0x07);

	memcpy(ptr, mm->auth_triplet.vec.ck, 16);
	ptr += 16;
	memcpy(ptr, mm->auth_triplet.vec.ik, 16);
	ptr += 16;

	quint_len_ptr = ptr;
	ptr += 2;

	if (sd) {
		for (i = 0; i < ARRAY_SIZE(sd->auth_triplets) && num_vectors < 5; i++) {
			int used;
			if (sd->auth_triplets[i].key_seq == GSM_KEY_SEQ_INVAL)
				continue;
			used = encode_quintuplet(ptr, end - ptr, &sd->auth_triplets[i].vec);
			if (used < 0)
				break;
			ptr += used;
			num_vectors++;
		}
	}
	buf[1] = (buf[1] & 0x1f) | ((num_vectors & 0x07) << 3);
	osmo_store16be(ptr - (quint_len_ptr + 2), quint_len_ptr);

	drx = htons(mm->drx_parms);
	memcpy(ptr, &drx, 2);
	ptr += 2;

	if (mm->ms_network_capa.len && end - ptr > 1 + mm->ms_network_capa.len) {
		*ptr++ = mm->ms_network_capa.len;
		memcpy(ptr, mm->ms_network_capa.buf, mm->ms_network_capa.len);
		ptr += mm->ms_network_capa.len;
	} else if (end - ptr >= 1) {
		*ptr++ = 0;
	}

	if (end - ptr >= 2) {
		*ptr++ = 0;
		*ptr++ = 0;
	}
	if (end - ptr >= 1)
		*ptr++ = 0;

	return ptr - buf;
}

static int encode_mm_context(struct sgsn_mm_ctx *mm, uint8_t *buf, size_t buf_len)
{
	if (mm->ran_type == MM_CTX_T_UTRAN_Iu || mm->sec_ctx == OSMO_AUTH_TYPE_UMTS)
		return encode_umts_mm_context(mm, buf, buf_len);
	return encode_gsm_mm_context(mm, buf, buf_len);
}

static int ie_slot_alloc(union gtpie_member *ie[GTPIE_SIZE])
{
	int i;
	for (i = 0; i < GTPIE_SIZE; i++) {
		if (!ie[i])
			return i;
	}
	return -1;
}

static void ctx_xfer_link(uint32_t local_ref, struct sgsn_mm_ctx *mm)
{
	struct sgsn_ctx_xfer *xfer;

	xfer = talloc_zero(sgsn, struct sgsn_ctx_xfer);
	if (!xfer)
		return;
	xfer->local_ref = local_ref;
	xfer->mm = mm;
	llist_add_tail(&xfer->list, &sgsn_ctx_xfer_list);
}

static struct sgsn_ctx_xfer *ctx_xfer_take(uint32_t local_ref)
{
	struct sgsn_ctx_xfer *xfer;

	llist_for_each_entry(xfer, &sgsn_ctx_xfer_list, list) {
		if (xfer->local_ref == local_ref) {
			llist_del(&xfer->list);
			return xfer;
		}
	}
	return NULL;
}

static int send_ctx_resp_error(struct gsn_t *gsn, uint32_t local_ref, uint8_t cause)
{
	return gtp_sgsn_context_resp_error(gsn, local_ref, cause);
}

static int send_ctx_resp_accept(struct gsn_t *gsn, uint32_t local_ref, struct sgsn_mm_ctx *mm)
{
	union gtpie_member *ie[GTPIE_SIZE] = { NULL };
	union gtpie_member cause_ie, imsi_ie, rai_ie, ptmsi_ie, ptmsi_sig_ie, recovery_ie, mm_ie;
	union gtpie_member pdp_ie[SGSN_CTX_MAX_PDP_IE];
	uint8_t mm_buf[SGSN_CTX_MM_BUF];
	uint8_t pdp_buf[SGSN_CTX_PDP_BUF];
	struct sgsn_pdp_ctx *pctx;
	int mm_len, rc, slot;
	unsigned pdp_count = 0;

	cause_ie.tv1.t = GTPIE_CAUSE;
	cause_ie.tv1.v = GTPCAUSE_ACC_REQ;
	ie[GTPIE_CAUSE] = &cause_ie;

	imsi_ie.tv8.t = GTPIE_IMSI;
	imsi_ie.tv8.v = imsi_str_to_gtp64(mm->imsi);
	ie[GTPIE_IMSI] = &imsi_ie;

	rai_ie.tv0.t = GTPIE_RAI;
	osmo_routing_area_id_encode_buf(rai_ie.tv0.v, sizeof(rai_ie.tv0.v), &mm->ra);
	ie[GTPIE_RAI] = &rai_ie;

	if (mm->p_tmsi) {
		ptmsi_ie.tv4.t = GTPIE_P_TMSI;
		ptmsi_ie.tv4.v = htonl(mm->p_tmsi);
		ie[GTPIE_P_TMSI] = &ptmsi_ie;
	}
	if (mm->p_tmsi_sig) {
		ptmsi_sig_ie.tv0.t = GTPIE_P_TMSI_S;
		ptmsi_sig_ie.tv0.v[0] = (mm->p_tmsi_sig >> 16) & 0xff;
		ptmsi_sig_ie.tv0.v[1] = (mm->p_tmsi_sig >> 8) & 0xff;
		ptmsi_sig_ie.tv0.v[2] = mm->p_tmsi_sig & 0xff;
		ie[GTPIE_P_TMSI_S] = &ptmsi_sig_ie;
	}

	recovery_ie.tv1.t = GTPIE_RECOVERY;
	recovery_ie.tv1.v = gsn->restart_counter;
	ie[GTPIE_RECOVERY] = &recovery_ie;

	mm_len = encode_mm_context(mm, mm_buf, sizeof(mm_buf));
	if (mm_len < 0)
		return send_ctx_resp_error(gsn, local_ref, GTPCAUSE_SYS_FAIL);

	mm_ie.tlv.t = GTPIE_MM_CONTEXT;
	mm_ie.tlv.l = htons(mm_len);
	memcpy(mm_ie.tlv.v, mm_buf, mm_len);
	ie[GTPIE_MM_CONTEXT] = &mm_ie;

	llist_for_each_entry(pctx, &mm->pdp_list, list) {
		int pdp_len;

		if (pctx->state != PDP_STATE_CR_CONF || !pctx->lib)
			continue;
		if (pdp_count >= SGSN_CTX_MAX_PDP_IE)
			break;

		pdp_len = gtp_encode_pdp_ctx(pdp_buf, sizeof(pdp_buf), pctx->lib, pctx->sapi);
		if (pdp_len < 0) {
			LOGMMCTXP(LOGL_ERROR, mm, "Failed to encode PDP context NSAPI=%u\n", pctx->nsapi);
			continue;
		}

		slot = ie_slot_alloc(ie);
		if (slot < 0)
			break;

		pdp_ie[pdp_count].tlv.t = GTPIE_PDP_CONTEXT;
		pdp_ie[pdp_count].tlv.l = htons(pdp_len);
		memcpy(pdp_ie[pdp_count].tlv.v, pdp_buf, pdp_len);
		ie[slot] = &pdp_ie[pdp_count];
		pdp_count++;
	}

	if (!pdp_count) {
		LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Response: no active PDP contexts\n");
		return send_ctx_resp_error(gsn, local_ref, GTPCAUSE_CONTEXT_NOT_FOUND);
	}

	rc = gtp_sgsn_context_resp(gsn, local_ref, ie);
	if (!rc)
		ctx_xfer_link(local_ref, mm);
	return rc;
}

static int cb_sgsn_context_request_ind(struct gsn_t *gsn, const struct sockaddr_in *peer,
				       uint32_t local_ref, union gtpie_member * const *ie,
				       unsigned int ie_size)
{
	struct sgsn_mm_ctx *mm;
	char addr[INET_ADDRSTRLEN];

	(void)ie_size;
	inet_ntop(AF_INET, &peer->sin_addr, addr, sizeof(addr));
	LOGP(DGTP, LOGL_NOTICE, "Rx SGSN Context Request from %s (local TEID-C 0x%x)\n",
	     addr, local_ref);

	mm = mm_from_ctx_req_ie(ie);
	if (!mm) {
		LOGP(DGTP, LOGL_NOTICE, "SGSN Context Request: subscriber not found\n");
		return send_ctx_resp_error(gsn, local_ref, GTPCAUSE_CONTEXT_NOT_FOUND);
	}

	if (!ptmsi_sig_matches(mm, ie)) {
		LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Request: P-TMSI signature mismatch\n");
		return send_ctx_resp_error(gsn, local_ref, GTPCAUSE_PTIMSI_MISMATCH);
	}

	if (!mm_ctx_transferable(mm)) {
		LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Request: MM state %s not transferable\n",
			  osmo_fsm_inst_state_name(mm->gmm_fsm));
		return send_ctx_resp_error(gsn, local_ref, GTPCAUSE_MS_DETACHED);
	}

	LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Request: sending context to %s\n", addr);
	return send_ctx_resp_accept(gsn, local_ref, mm);
}

static void ctx_xfer_finish(struct sgsn_ctx_xfer *xfer, uint8_t cause)
{
	struct sgsn_pdp_ctx *pctx, *pctx2;
	struct sgsn_mm_ctx *mm = xfer->mm;

	if (!mm)
		goto out;

	if (cause == GTPCAUSE_ACC_REQ) {
		LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Ack accepted: releasing local PS context\n");
		llist_for_each_entry_safe(pctx, pctx2, &mm->pdp_list, list)
			sgsn_delete_pdp_ctx(pctx);
		gsm0408_gprs_access_cancelled(mm, SGSN_ERROR_CAUSE_NONE);
	} else {
		LOGMMCTXP(LOGL_NOTICE, mm, "SGSN Context Ack with cause %u\n", cause);
	}

out:
	talloc_free(xfer);
}

static int cb_sgsn_context_ack_ind(struct gsn_t *gsn, const struct sockaddr_in *peer,
				   uint32_t local_ref, union gtpie_member * const *ie,
				   unsigned int ie_size)
{
	struct sgsn_ctx_xfer *xfer;
	uint8_t cause = GTPCAUSE_SYS_FAIL;
	char addr[INET_ADDRSTRLEN];

	(void)gsn;
	(void)ie_size;
	inet_ntop(AF_INET, &peer->sin_addr, addr, sizeof(addr));

	xfer = ctx_xfer_take(local_ref);
	if (!xfer) {
		LOGP(DGTP, LOGL_NOTICE, "Rx SGSN Context Ack from %s for unknown TEID-C 0x%x\n",
		     addr, local_ref);
		return 0;
	}

	if (!gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause))
		LOGP(DGTP, LOGL_NOTICE, "Rx SGSN Context Ack from %s (TEID-C 0x%x, cause %u)\n",
		     addr, local_ref, cause);

	ctx_xfer_finish(xfer, cause);
	return 0;
}

static int cb_sgsn_context_response_ind(struct gsn_t *gsn, const struct sockaddr_in *peer,
					uint32_t local_ref, union gtpie_member * const *ie,
					unsigned int ie_size)
{
	(void)gsn;
	(void)peer;
	(void)local_ref;
	(void)ie;
	(void)ie_size;
	/* Outgoing SGSN Context Request (new SGSN) is not implemented yet. */
	return 0;
}

int sgsn_gtp_ctx_init(struct sgsn_instance *sgi)
{
	struct gsn_t *gsn = sgi->gsn;
	int rc;

	if (!LIBGTP_VERSION_GREATER_EQUAL(1, 14, 0)) {
		LOGP(DGPRS, LOGL_ERROR, "libgtp >= 1.14.0 required for SGSN Context procedures\n");
		return -ENOTSUP;
	}

	rc = gtp_set_cb_sgsn_context_request_ind(gsn, cb_sgsn_context_request_ind);
	if (rc)
		return rc;
	rc = gtp_set_cb_sgsn_context_response_ind(gsn, cb_sgsn_context_response_ind);
	if (rc)
		return rc;
	rc = gtp_set_cb_sgsn_context_ack_ind(gsn, cb_sgsn_context_ack_ind);
	if (rc)
		return rc;

	LOGP(DGPRS, LOGL_NOTICE, "SGSN Context Request/Response/Ack handling enabled\n");

	osmo_signal_register_handler(SS_SGSN, sgsn_gtp_ctx_mm_signal, NULL);

	return 0;
}
