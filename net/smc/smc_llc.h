/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Definitions for LLC (link layer control) message handling
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Klaus Wacker <Klaus.Wacker@de.ibm.com>
 *              Ursula Braun <ubraun@linux.vnet.ibm.com>
 */

#ifndef SMC_LLC_H
#define SMC_LLC_H

#include "smc_wr.h"

#define SMC_LLC_FLAG_RESP		0x80

#define SMC_LLC_WAIT_FIRST_TIME		(5 * HZ)
#define SMC_LLC_WAIT_TIME		(2 * HZ)

enum smc_llc_reqresp {
	SMC_LLC_REQ,
	SMC_LLC_RESP
};

enum smc_llc_msg_type {
	SMC_LLC_CONFIRM_LINK		= 0x01,
	SMC_LLC_ADD_LINK		= 0x02,
	SMC_LLC_DELETE_LINK		= 0x04,
	SMC_LLC_CONFIRM_RKEY		= 0x06,
	SMC_LLC_TEST_LINK		= 0x07,
	SMC_LLC_CONFIRM_RKEY_CONT	= 0x08,
	SMC_LLC_DELETE_RKEY		= 0x09,
};

/* returns a usable link of the link group, or NULL */
static inline struct smc_link *smc_llc_usable_link(struct smc_link_group *lgr)
{
	int i;

	for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++)
		if (smc_link_usable(&lgr->lnk[i]))
			return &lgr->lnk[i];
	return NULL;
}

/* transmit */
int smc_llc_send_confirm_link(struct smc_link *lnk,
			      enum smc_llc_reqresp reqresp);
int smc_llc_send_add_link(struct smc_link *link, u8 mac[], u8 gid[],
			  enum smc_llc_reqresp reqresp);
int smc_llc_send_delete_link(struct smc_link *link,
			     enum smc_llc_reqresp reqresp, bool orderly);
void smc_llc_lgr_init(struct smc_link_group *lgr, struct smc_sock *smc);
void smc_llc_lgr_clear(struct smc_link_group *lgr);
int smc_llc_link_init(struct smc_link *link);
void smc_llc_link_active(struct smc_link *link);
void smc_llc_link_clear(struct smc_link *link);
int smc_llc_do_confirm_rkey(struct smc_link *send_link,
			    struct smc_buf_desc *rmb_desc);
int smc_llc_do_delete_rkey(struct smc_link_group *lgr,
			   struct smc_buf_desc *rmb_desc);
int smc_llc_flow_initiate(struct smc_link_group *lgr,
			  enum smc_llc_flowtype type);
void smc_llc_flow_stop(struct smc_link_group *lgr, struct smc_llc_flow *flow);
int smc_llc_eval_conf_link(struct smc_llc_qentry *qentry,
			   enum smc_llc_reqresp type);
struct smc_llc_qentry *smc_llc_wait(struct smc_link_group *lgr,
				    struct smc_link *lnk,
				    int time_out, u8 exp_msg);
struct smc_llc_qentry *smc_llc_flow_qentry_clr(struct smc_llc_flow *flow);
void smc_llc_flow_qentry_del(struct smc_llc_flow *flow);
int smc_llc_init(void) __init;

#endif /* SMC_LLC_H */
