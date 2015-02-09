/* bnx2x_vfpf.h: Broadcom Everest network driver.
 *
 * Copyright (c) 2011-2013 Broadcom Corporation
 *
 * Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2, available
 * at http://www.gnu.org/licenses/old-licenses/gpl-2.0.html (the "GPL").
 *
 * Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a
 * license other than the GPL, without Broadcom's express prior written
 * consent.
 *
 * Maintained by: Ariel Elior <ariel.elior@qlogic.com>
 * Written by: Ariel Elior <ariel.elior@qlogic.com>
 */
#ifndef VF_PF_IF_H
#define VF_PF_IF_H

#ifdef CONFIG_BNX2X_SRIOV

/* Common definitions for all HVs */
struct vf_pf_resc_request {
	uint8_t  num_rxqs;
	uint8_t  num_txqs;
	uint8_t  num_sbs;
	uint8_t  num_mac_filters;
	uint8_t  num_vlan_filters;
	uint8_t  num_mc_filters; /* No limit  so superfluous */
};

struct hw_sb_info {
	uint8_t hw_sb_id;	/* aka absolute igu id, used to ack the sb */
	uint8_t sb_qid;	/* used to update DHC for sb */
};

/* HW VF-PF channel definitions
 * A.K.A VF-PF mailbox
 */
#define TLV_BUFFER_SIZE			1024
#define PF_VF_BULLETIN_SIZE		512

#define VFPF_QUEUE_FLG_TPA		0x0001
#define VFPF_QUEUE_FLG_TPA_IPV6		0x0002
#define VFPF_QUEUE_FLG_TPA_GRO		0x0004
#define VFPF_QUEUE_FLG_CACHE_ALIGN	0x0008
#define VFPF_QUEUE_FLG_STATS		0x0010
#define VFPF_QUEUE_FLG_OV		0x0020
#define VFPF_QUEUE_FLG_VLAN		0x0040
#define VFPF_QUEUE_FLG_COS		0x0080
#define VFPF_QUEUE_FLG_HC		0x0100
#define VFPF_QUEUE_FLG_DHC		0x0200
#define VFPF_QUEUE_FLG_LEADING_RSS	0x0400

#define VFPF_QUEUE_DROP_IP_CS_ERR	(1 << 0)
#define VFPF_QUEUE_DROP_TCP_CS_ERR	(1 << 1)
#define VFPF_QUEUE_DROP_TTL0		(1 << 2)
#define VFPF_QUEUE_DROP_UDP_CS_ERR	(1 << 3)

#define VFPF_RX_MASK_ACCEPT_NONE		0x00000000
#define VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST	0x00000001
#define VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST	0x00000002
#define VFPF_RX_MASK_ACCEPT_ALL_UNICAST		0x00000004
#define VFPF_RX_MASK_ACCEPT_ALL_MULTICAST	0x00000008
#define VFPF_RX_MASK_ACCEPT_BROADCAST		0x00000010
#define BULLETIN_CONTENT_SIZE		(sizeof(struct pf_vf_bulletin_content))
#define BULLETIN_CONTENT_LEGACY_SIZE	(32)
#define BULLETIN_ATTEMPTS	5 /* crc failures before throwing towel */
#define BULLETIN_CRC_SEED	0

enum {
	PFVF_STATUS_WAITING = 0,
	PFVF_STATUS_SUCCESS,
	PFVF_STATUS_FAILURE,
	PFVF_STATUS_NOT_SUPPORTED,
	PFVF_STATUS_NO_RESOURCE
};

/* vf pf channel tlvs */
/* general tlv header (used for both vf->pf request and pf->vf response) */
struct channel_tlv {
	uint16_t type;
	uint16_t length;
};

/* header of first vf->pf tlv carries the offset used to calculate response
 * buffer address
 */
struct vfpf_first_tlv {
	struct channel_tlv tl;
	uint32_t resp_msg_offset;
};

/* header of pf->vf tlvs, carries the status of handling the request */
struct pfvf_tlv {
	struct channel_tlv tl;
	uint8_t status;
	uint8_t padding[3];
};

/* response tlv used for most tlvs */
struct pfvf_general_resp_tlv {
	struct pfvf_tlv hdr;
};

/* used to terminate and pad a tlv list */
struct channel_list_end_tlv {
	struct channel_tlv tl;
	uint8_t padding[4];
};

/* Acquire */
struct vfpf_acquire_tlv {
	struct vfpf_first_tlv first_tlv;

	struct vf_pf_vfdev_info {
		/* the following fields are for debug purposes */
		uint8_t  vf_id;		/* ME register value */
		uint8_t  vf_os;		/* e.g. Linux, W2K8 */
#define VF_OS_SUBVERSION_MASK	(0x1f)
#define VF_OS_MASK		(0xe0)
#define VF_OS_SHIFT		(5)
#define VF_OS_UNDEFINED		(0 << VF_OS_SHIFT)
#define VF_OS_WINDOWS		(1 << VF_OS_SHIFT)

		uint8_t fp_hsi_ver;
		uint8_t caps;
#define VF_CAP_SUPPORT_EXT_BULLETIN	(1 << 0)
	} vfdev_info;

	struct vf_pf_resc_request resc_request;

	aligned_u64 bulletin_addr;
};

/* simple operation request on queue */
struct vfpf_q_op_tlv {
	struct vfpf_first_tlv	first_tlv;
	uint8_t vf_qid;
	uint8_t padding[3];
};

/* receive side scaling tlv */
struct vfpf_rss_tlv {
	struct vfpf_first_tlv	first_tlv;
	uint32_t			rss_flags;
#define VFPF_RSS_MODE_DISABLED	(1 << 0)
#define VFPF_RSS_MODE_REGULAR	(1 << 1)
#define VFPF_RSS_SET_SRCH	(1 << 2)
#define VFPF_RSS_IPV4		(1 << 3)
#define VFPF_RSS_IPV4_TCP	(1 << 4)
#define VFPF_RSS_IPV4_UDP	(1 << 5)
#define VFPF_RSS_IPV6		(1 << 6)
#define VFPF_RSS_IPV6_TCP	(1 << 7)
#define VFPF_RSS_IPV6_UDP	(1 << 8)
	uint8_t			rss_result_mask;
	uint8_t			ind_table_size;
	uint8_t			rss_key_size;
	uint8_t			padding;
	uint8_t			ind_table[T_ETH_INDIRECTION_TABLE_SIZE];
	uint32_t			rss_key[T_ETH_RSS_KEY];	/* hash values */
};

/* acquire response tlv - carries the allocated resources */
struct pfvf_acquire_resp_tlv {
	struct pfvf_tlv hdr;
	struct pf_vf_pfdev_info {
		uint32_t chip_num;
		uint32_t pf_cap;
#define PFVF_CAP_RSS		0x00000001
#define PFVF_CAP_DHC		0x00000002
#define PFVF_CAP_TPA		0x00000004
#define PFVF_CAP_TPA_UPDATE	0x00000008
		char fw_ver[32];
		uint16_t db_size;
		uint8_t  indices_per_sb;
		uint8_t  padding;
	} pfdev_info;
	struct pf_vf_resc {
		/* in case of status NO_RESOURCE in message hdr, pf will fill
		 * this struct with suggested amount of resources for next
		 * acquire request
		 */
#define PFVF_MAX_QUEUES_PER_VF         16
#define PFVF_MAX_SBS_PER_VF            16
		struct hw_sb_info hw_sbs[PFVF_MAX_SBS_PER_VF];
		uint8_t	hw_qid[PFVF_MAX_QUEUES_PER_VF];
		uint8_t	num_rxqs;
		uint8_t	num_txqs;
		uint8_t	num_sbs;
		uint8_t	num_mac_filters;
		uint8_t	num_vlan_filters;
		uint8_t	num_mc_filters;
		uint8_t	permanent_mac_addr[Eaddrlen];
		uint8_t	current_mac_addr[Eaddrlen];
		uint8_t	padding[2];
	} resc;
};

struct vfpf_port_phys_id_resp_tlv {
	struct channel_tlv tl;
	uint8_t id[Eaddrlen];
	uint8_t padding[2];
};

struct vfpf_fp_hsi_resp_tlv {
	struct channel_tlv tl;
	uint8_t is_supported;
	uint8_t padding[3];
};

#define VFPF_INIT_FLG_STATS_COALESCE	(1 << 0) /* when set the VFs queues
						  * stats will be coalesced on
						  * the leading RSS queue
						  */

/* Init VF */
struct vfpf_init_tlv {
	struct vfpf_first_tlv first_tlv;
	aligned_u64 sb_addr[PFVF_MAX_SBS_PER_VF]; /* vf_sb based */
	aligned_u64 spq_addr;
	aligned_u64 stats_addr;
	uint16_t stats_stride;
	uint32_t flags;
	uint32_t padding[2];
};

/* Setup Queue */
struct vfpf_setup_q_tlv {
	struct vfpf_first_tlv first_tlv;

	struct vf_pf_rxq_params {
		/* physical addresses */
		aligned_u64 rcq_addr;
		aligned_u64 rcq_np_addr;
		aligned_u64 rxq_addr;
		aligned_u64 sge_addr;

		/* sb + hc info */
		uint8_t  vf_sb;		/* index in hw_sbs[] */
		uint8_t  sb_index;		/* Index in the SB */
		uint16_t hc_rate;		/* desired interrupts per sec. */
					/* valid iff VFPF_QUEUE_FLG_HC */
		/* rx buffer info */
		uint16_t mtu;
		uint16_t buf_sz;
		uint16_t flags;		/* VFPF_QUEUE_FLG_X flags */
		uint16_t stat_id;		/* valid iff VFPF_QUEUE_FLG_STATS */

		/* valid iff VFPF_QUEUE_FLG_TPA */
		uint16_t sge_buf_sz;
		uint16_t tpa_agg_sz;
		uint8_t max_sge_pkt;

		uint8_t drop_flags;		/* VFPF_QUEUE_DROP_X, for Linux VMs
					 * all the flags are turned off
					 */

		uint8_t cache_line_log;	/* VFPF_QUEUE_FLG_CACHE_ALIGN */
		uint8_t padding;
	} rxq;

	struct vf_pf_txq_params {
		/* physical addresses */
		aligned_u64 txq_addr;

		/* sb + hc info */
		uint8_t  vf_sb;		/* index in hw_sbs[] */
		uint8_t  sb_index;		/* Index in the SB */
		uint16_t hc_rate;		/* desired interrupts per sec. */
					/* valid iff VFPF_QUEUE_FLG_HC */
		uint32_t flags;		/* VFPF_QUEUE_FLG_X flags */
		uint16_t stat_id;		/* valid iff VFPF_QUEUE_FLG_STATS */
		uint8_t  traffic_type;	/* see in setup_context() */
		uint8_t  padding;
	} txq;

	uint8_t vf_qid;			/* index in hw_qid[] */
	uint8_t param_valid;
#define VFPF_RXQ_VALID		0x01
#define VFPF_TXQ_VALID		0x02
	uint8_t padding[2];
};

/* Set Queue Filters */
struct vfpf_q_mac_vlan_filter {
	uint32_t flags;
#define VFPF_Q_FILTER_DEST_MAC_VALID	0x01
#define VFPF_Q_FILTER_VLAN_TAG_VALID	0x02
#define VFPF_Q_FILTER_SET_MAC		0x100	/* set/clear */
	uint8_t  mac[Eaddrlen];
	uint16_t vlan_tag;
};

/* configure queue filters */
struct vfpf_set_q_filters_tlv {
	struct vfpf_first_tlv first_tlv;

	uint32_t flags;
#define VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED	0x01
#define VFPF_SET_Q_FILTERS_MULTICAST_CHANGED	0x02
#define VFPF_SET_Q_FILTERS_RX_MASK_CHANGED	0x04

	uint8_t vf_qid;			/* index in hw_qid[] */
	uint8_t n_mac_vlan_filters;
	uint8_t n_multicast;
	uint8_t padding;

#define PFVF_MAX_MAC_FILTERS                   16
#define PFVF_MAX_VLAN_FILTERS                  16
#define PFVF_MAX_FILTERS               (PFVF_MAX_MAC_FILTERS +\
					 PFVF_MAX_VLAN_FILTERS)
	struct vfpf_q_mac_vlan_filter filters[PFVF_MAX_FILTERS];

#define PFVF_MAX_MULTICAST_PER_VF              32
	uint8_t  multicast[PFVF_MAX_MULTICAST_PER_VF][Eaddrlen];

	uint32_t rx_mask;	/* see mask constants at the top of the file */
};

struct vfpf_tpa_tlv {
	struct vfpf_first_tlv	first_tlv;

	struct vf_pf_tpa_client_info {
		aligned_u64 sge_addr[PFVF_MAX_QUEUES_PER_VF];
		uint8_t update_ipv4;
		uint8_t update_ipv6;
		uint8_t max_tpa_queues;
		uint8_t max_sges_for_packet;
		uint8_t complete_on_both_clients;
		uint8_t dont_verify_thr;
		uint8_t tpa_mode;
		uint16_t sge_buff_size;
		uint16_t max_agg_size;
		uint16_t sge_pause_thr_low;
		uint16_t sge_pause_thr_high;
	} tpa_client_info;
};

/* close VF (disable VF) */
struct vfpf_close_tlv {
	struct vfpf_first_tlv   first_tlv;
	uint16_t			vf_id;  /* for debug */
	uint8_t padding[2];
};

/* release the VF's acquired resources */
struct vfpf_release_tlv {
	struct vfpf_first_tlv	first_tlv;
	uint16_t			vf_id;
	uint8_t padding[2];
};

struct tlv_buffer_size {
	uint8_t tlv_buffer[TLV_BUFFER_SIZE];
};

union vfpf_tlvs {
	struct vfpf_first_tlv		first_tlv;
	struct vfpf_acquire_tlv		acquire;
	struct vfpf_init_tlv		init;
	struct vfpf_close_tlv		close;
	struct vfpf_q_op_tlv		q_op;
	struct vfpf_setup_q_tlv		setup_q;
	struct vfpf_set_q_filters_tlv	set_q_filters;
	struct vfpf_release_tlv		release;
	struct vfpf_rss_tlv		update_rss;
	struct vfpf_tpa_tlv		update_tpa;
	struct channel_list_end_tlv	list_end;
	struct tlv_buffer_size		tlv_buf_size;
};

union pfvf_tlvs {
	struct pfvf_general_resp_tlv	general_resp;
	struct pfvf_acquire_resp_tlv	acquire_resp;
	struct channel_list_end_tlv	list_end;
	struct tlv_buffer_size		tlv_buf_size;
};

/* This is a structure which is allocated in the VF, which the PF may update
 * when it deems it necessary to do so. The bulletin board is sampled
 * periodically by the VF. A copy per VF is maintained in the PF (to prevent
 * loss of data upon multiple updates (or the need for read modify write)).
 */
struct pf_vf_bulletin_size {
	uint8_t size[PF_VF_BULLETIN_SIZE];
};

struct pf_vf_bulletin_content {
	uint32_t crc;			/* crc of structure to ensure is not in
					 * mid-update
					 */
	uint16_t version;
	uint16_t length;

	aligned_u64 valid_bitmap;	/* bitmap indicating which fields
					 * hold valid values
					 */

#define MAC_ADDR_VALID		0	/* alert the vf that a new mac address
					 * is available for it
					 */
#define VLAN_VALID		1	/* when set, the vf should not access
					 * the vfpf channel
					 */
#define CHANNEL_DOWN		2	/* vfpf channel is disabled. VFs are not
					 * to attempt to send messages on the
					 * channel after this bit is set
					 */
#define LINK_VALID		3	/* alert the VF thet a new link status
					 * update is available for it
					 */
	uint8_t mac[Eaddrlen];
	uint8_t mac_padding[2];

	uint16_t vlan;
	uint8_t vlan_padding[6];

	uint16_t link_speed;			 /* Effective line speed */
	uint8_t link_speed_padding[6];
	uint32_t link_flags;			 /* VFPF_LINK_REPORT_XXX flags */
#define VFPF_LINK_REPORT_LINK_DOWN	 (1 << 0)
#define VFPF_LINK_REPORT_FULL_DUPLEX	 (1 << 1)
#define VFPF_LINK_REPORT_RX_FC_ON	 (1 << 2)
#define VFPF_LINK_REPORT_TX_FC_ON	 (1 << 3)
	uint8_t link_flags_padding[4];
};

union pf_vf_bulletin {
	struct pf_vf_bulletin_content content;
	struct pf_vf_bulletin_size size;
};

#define MAX_TLVS_IN_LIST 50

enum channel_tlvs {
	CHANNEL_TLV_NONE,
	CHANNEL_TLV_ACQUIRE,
	CHANNEL_TLV_INIT,
	CHANNEL_TLV_SETUP_Q,
	CHANNEL_TLV_SET_Q_FILTERS,
	CHANNEL_TLV_ACTIVATE_Q,
	CHANNEL_TLV_DEACTIVATE_Q,
	CHANNEL_TLV_TEARDOWN_Q,
	CHANNEL_TLV_CLOSE,
	CHANNEL_TLV_RELEASE,
	CHANNEL_TLV_UPDATE_RSS_DEPRECATED,
	CHANNEL_TLV_PF_RELEASE_VF,
	CHANNEL_TLV_LIST_END,
	CHANNEL_TLV_FLR,
	CHANNEL_TLV_PF_SET_MAC,
	CHANNEL_TLV_PF_SET_VLAN,
	CHANNEL_TLV_UPDATE_RSS,
	CHANNEL_TLV_PHYS_PORT_ID,
	CHANNEL_TLV_UPDATE_TPA,
	CHANNEL_TLV_FP_HSI_SUPPORT,
	CHANNEL_TLV_MAX
};

#endif /* CONFIG_BNX2X_SRIOV */
#endif /* VF_PF_IF_H */