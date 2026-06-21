/* Gn PDP cleanup policies (Delete PDP Context toward GGSN) */

#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/sgsn_pdp_gn.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/sgsn.h>

#if BUILD_IU

#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/sccp.h>

static bool mm_has_active_gn_pdp(const struct sgsn_mm_ctx *mm)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->ggsn && pdp->lib)
			return true;
	}
	return false;
}

static void mm_iu_unreachable_pdp_timer_cb(void *data)
{
	struct sgsn_mm_ctx *mm = data;

	LOGMMCTXP(LOGL_NOTICE, mm,
		  "PMM-IDLE unreachable timer expired, deleting PDP contexts on Gn\n");
	sgsn_mm_ctx_delete_all_pdp_gn(mm);
}

void sgsn_mm_iu_unreachable_timer_stop(struct sgsn_mm_ctx *mm)
{
	if (!mm || mm->ran_type != MM_CTX_T_UTRAN_Iu)
		return;
	osmo_timer_del(&mm->iu.unreachable_gn_pdp_timer);
}

void sgsn_mm_iu_unreachable_timer_start(struct sgsn_mm_ctx *mm)
{
	unsigned int timeout;

	if (!mm || mm->ran_type != MM_CTX_T_UTRAN_Iu)
		return;

	timeout = sgsn->cfg.iu.unreachable_pdp_timer_sec;
	if (!timeout || !mm_has_active_gn_pdp(mm))
		return;

	if (mm->iu.mm_state_fsm->state != ST_PMM_IDLE)
		return;

	osmo_timer_schedule(&mm->iu.unreachable_gn_pdp_timer, timeout, 0);
	LOGMMCTXP(LOGL_INFO, mm,
		  "Started PMM-IDLE unreachable Gn PDP timer (%u s)\n", timeout);
}

bool sgsn_mm_ctx_on_rnc(const struct sgsn_mm_ctx *mm, const struct ranap_iu_rnc *rnc)
{
	struct iu_lac_rac_entry *e;

	if (!mm || !rnc || mm->ran_type != MM_CTX_T_UTRAN_Iu)
		return false;

	if (mm->iu.ue_ctx && mm->iu.ue_ctx->rnc == rnc)
		return true;

	llist_for_each_entry(e, &rnc->lac_rac_list, entry) {
		if (osmo_rai_cmp(&e->rai, &mm->ra) == 0)
			return true;
	}
	return false;
}

void sgsn_mm_ctx_delete_all_pdp_gn(struct sgsn_mm_ctx *mm)
{
	struct sgsn_pdp_ctx *pdp, *pdp2;

	if (!mm)
		return;

	sgsn_mm_iu_unreachable_timer_stop(mm);

	llist_for_each_entry_safe(pdp, pdp2, &mm->pdp_list, list) {
		if (!pdp->ggsn || !pdp->lib)
			continue;
		LOGPDPCTXP(LOGL_NOTICE, pdp, "Deleting PDP context on Gn\n");
		sgsn_delete_pdp_ctx(pdp);
	}
}

static void sgsn_mm_iu_handle_rnc_loss(struct sgsn_mm_ctx *mm)
{
	struct osmo_fsm_inst *fi;

	if (!mm || mm->ran_type != MM_CTX_T_UTRAN_Iu)
		return;

	sgsn_mm_iu_unreachable_timer_stop(mm);
	fi = mm->iu.mm_state_fsm;

	if (fi && fi->state == ST_PMM_CONNECTED) {
		/* Iu is gone: PMM-IDLE. iu_release policy may Update GTP; rnc_loss
		 * delete-gn below overrides that toward the GGSN (TS 23.060). */
		osmo_fsm_inst_dispatch(fi, E_PMM_PS_CONN_RELEASE, NULL);
	} else {
		sgsn_mm_ctx_iu_ranap_free(mm);
	}

	if (sgsn->cfg.iu.rnc_loss_pdp == SGSN_RNC_LOSS_PDP_DELETE_GN)
		sgsn_mm_ctx_delete_all_pdp_gn(mm);
}

void sgsn_rnc_handle_ps_loss(struct ranap_iu_rnc *rnc)
{
	struct ranap_ue_conn_ctx *ue, *ue2;
	struct sgsn_mm_ctx *mm, *mm2;

	if (!rnc)
		return;

	LOG_RNC(rnc, LOGL_NOTICE, "RNC unreachable, releasing PS sessions for served UEs\n");

	/* Connected UEs with active Iu on this RNC. PS_CONN_RELEASE may free ue. */
	llist_for_each_entry_safe(ue, ue2, &sgsn->sccp.scu_iups->ue_conn_ctx_list, list) {
		if (ue->rnc != rnc)
			continue;
		mm = sgsn_mm_ctx_by_ue_ctx(ue);
		if (mm)
			sgsn_mm_iu_handle_rnc_loss(mm);
	}

	/* PMM-IDLE UEs last served in this RNC's routing area(s). */
	llist_for_each_entry_safe(mm, mm2, &sgsn->mm_list, list) {
		if (!sgsn_mm_ctx_on_rnc(mm, rnc))
			continue;
		if (mm->iu.ue_ctx && mm->iu.ue_ctx->rnc == rnc)
			continue;
		sgsn_mm_iu_handle_rnc_loss(mm);
	}
}

void sgsn_mm_iu_unreachable_timer_init(struct sgsn_mm_ctx *mm)
{
	if (!mm)
		return;
	osmo_timer_setup(&mm->iu.unreachable_gn_pdp_timer,
			 mm_iu_unreachable_pdp_timer_cb, mm);
}

#endif /* BUILD_IU */
