#pragma once

#include "config.h"

#if BUILD_IU

struct ranap_iu_rnc;
struct sgsn_mm_ctx;

bool sgsn_mm_ctx_on_rnc(const struct sgsn_mm_ctx *mm, const struct ranap_iu_rnc *rnc);
void sgsn_mm_ctx_delete_all_pdp_gn(struct sgsn_mm_ctx *mm);
void sgsn_rnc_handle_ps_loss(struct ranap_iu_rnc *rnc);
void sgsn_mm_iu_unreachable_timer_stop(struct sgsn_mm_ctx *mm);
void sgsn_mm_iu_unreachable_timer_start(struct sgsn_mm_ctx *mm);
void sgsn_mm_iu_unreachable_timer_init(struct sgsn_mm_ctx *mm);

#endif /* BUILD_IU */
