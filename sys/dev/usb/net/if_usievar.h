/* $FreeBSD$ */

/*-
 * Copyright (c) 2011 Anybots Inc
 * written by Akinori Furukoshi <moonlightakkiy@yahoo.ca>
 *  - ucom part is based on u3g.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _IF_USEVAR_H_
#define	_IF_USEVAR_H_

#define	USIE_DCD		0x0001
#define	USIE_DSR		0x0002
#define	USIE_DTR		0x0004
#define	USIE_RI			0x0008
#define	USIE_CTS		0x0100
#define	USIE_RTS		0x0200

#define	USIE_HIP_FRM_CHR	0x7e
#define	USIE_HIP_ESC_CHR	0x7d
#define	USIE_HIP_IF		0

#define	USIE_HIPCNS_MIN		16	/* HIP + CnS + 2 framing char */
#define	USIE_HIPCNS_MAX		261	/* HIP + max CnS 255 + 2 framing char */

#define	USIE_CNFG_INDEX		0
#define	USIE_IFACE_INDEX	0
#define	USIE_IFACE_MAX		12
#define	USIE_BUFSIZE		2048
#define	USIE_MTU_MAX		1500
#define	USIE_RXSZ_MAX		4096

/* USB control pipe request */
#define	USIE_POWER		0x00
#define	USIE_FW_ATTR		0x06
#define	USIE_NMEA		0x07
#define	USIE_LINK_STATE		0x22

/* firmware attr flags */
#define	USIE_PM_AUTO		(1 << 1)
#define	USIE_FW_DHCP		(1 << 3)	/* DHCP capable */

/* line state flags */
#define	USIE_LS_DTR		(1 << 0)
#define	USIE_LS_RTS		(1 << 1)

/* Host Interface Porotocol Header */
struct usie_hip {
	uint16_t len;
#define	USIE_HIP_LEN_MASK	0x3fff
#define	USIE_HIP_IP_LEN_MASK	0x07ff

	uint8_t	id;
#define	USIE_HIP_PAD		(1 << 7)
#define	USIE_HIP_MASK		0x7f
#define	USIE_HIP_SYNC2M		0x20	/* host -> modem */
#define	USIE_HIP_DOWN		0x26
#define	USIE_HIP_CNS2M		0x2b	/* h -> m */
#define	USIE_HIP_CTX		0x3f
#define	USIE_HIP_SYNC2H		0x60	/* h <- m */
#define	USIE_HIP_RESTR		0x62
#define	USIE_HIP_RCGI		0x64
#define	USIE_HIP_CNS2H		0x6b	/* h <- m */
#define	USIE_HIP_UMTS		0x78
#define	USIE_HIP_IP		0x7f

	uint8_t	param;
} __packed __aligned(4);

/* Control and Status Header */
struct usie_cns {
	uint16_t obj;			/* object type */
#define	USIE_CNS_OB_RSSI	0x1001	/* read RSSI */
#define	USIE_CNS_OB_HW_DISABLE	0x1011	/* disable h/w */
#define	USIE_CNS_OB_PW_SW	0x1071	/* power on/off */
#define	USIE_CNS_OB_PROF_WRITE	0x7003	/* write profile */
#define	USIE_CNS_OB_LINK_UPDATE	0x7004	/* dis/connect */
#define	USIE_CNS_OB_PDP_READ	0x7006	/* read out IP addr */

	uint8_t	op;			/* operation type */
#define	USIE_CNS_OP_ERR		(1 << 7)/* | == error */
#define	USIE_CNS_OP_REQ		0x01	/* host -> modem */
#define	USIE_CNS_OP_RSP		0x02	/* h <- m */
#define	USIE_CNS_OP_SET		0x03	/* h -> m */
#define	USIE_CNS_OP_ACK		0x04	/* h <- m */
#define	USIE_CNS_OP_NOTIF_ON	0x05	/* h -> m */
#define	USIE_CNS_OP_RSP_ON	0x06	/* h <- m */
#define	USIE_CNS_OP_NOTIF	0x07	/* h <- m */
#define	USIE_CNS_OP_NOTIF_OFF	0x08	/* h -> m */
#define	USIE_CNS_OP_RSP_OFF	0x09	/* h <- m */
#define	USIE_CNS_OP_REQ_CHG	0x0a	/* h -> m */
#define	USIE_CNS_OP_RSP_CHG	0x0b	/* h <- m */

	uint8_t	rsv0;			/* reserved, always '0' */
	uint32_t id;			/* caller ID */
/*
 * .id is to identify calling functions
 * h/w responses with the same .id used in request. Only '0' is reserved
 * for notification (asynchronous message generated by h/w without any
 * request). All other values are user defineable.
 */
#define	USIE_CNS_ID_NOTIF	0x00000000	/* reserved */
#define	USIE_CNS_ID_INIT	0x00000001
#define	USIE_CNS_ID_STOP	0x00000002
#define	USIE_CNS_ID_DNS		0x00000003
#define	USIE_CNS_ID_RSSI	0x00000004

	uint8_t	rsv1;			/* reserved, always '0' */
	uint8_t	len;			/* length of param */
} __packed;

/*
 * CnS param attached to struct usie_cns
 * usie_cns.len is total size of this param
 * max 255
 */
#define	USIE_CNS_PM_UP		0x01
#define	USIE_CNS_PM_DOWN	0x00

/* Link Sense Indication data structure */
struct usie_lsi {
	uint8_t	proto;
#define	USIE_LSI_UMTS		0x01

	uint8_t	pad0;
	uint16_t len;
	uint8_t	area;
#define	USIE_LSI_AREA_NO	0x00
#define	USIE_LSI_AREA_NODATA	0x01

	uint8_t	pad1[41];
	uint8_t	state;
#define	USIE_LSI_STATE_IDLE	0x00

	uint8_t	pad2[33];
	uint8_t	type;
#define	USIE_LSI_IP4		0x00

	uint8_t	pdp_addr_len;		/* PDP addr */
	uint8_t	pdp_addr[16];
	uint8_t	pad3[23];
	uint8_t	dns1_addr_len;		/* DNS addr */
	uint8_t	dns1_addr[16];
	uint8_t	dns2_addr_len;
	uint8_t	dns2_addr[16];
	uint8_t	wins1_addr_len;		/* Wins addr */
	uint8_t	wins1_addr[16];
	uint8_t	wins2_addr_len;
	uint8_t	wins2_addr[16];
	uint8_t	pad4[4];
	uint8_t	gw_addr_len;		/* GW addr */
	uint8_t	gw_addr[16];
	uint8_t	rsv[8];
} __packed;

struct usie_net_info {
	uint8_t	addr_len;
	uint8_t	pdp_addr[16];
	uint8_t	dns1_addr[16];
	uint8_t	dns2_addr[16];
	uint8_t	gw_addr[16];
} __packed;

/* Tx/Rx IP packet descriptor */
struct usie_desc {
	struct usie_hip hip;
	uint16_t desc_type;
#define	USIE_TYPE_MASK	0x03ff
#define	USIE_IP_TX	0x0002
#define	USIE_IP_RX	0x0202

	struct ether_header ethhdr;
} __packed;

enum {
	USIE_UC_STATUS,
	USIE_UC_RX,
	USIE_UC_TX,
	USIE_UC_N_XFER
};

enum {
	USIE_IF_STATUS,
	USIE_IF_RX,
	USIE_IF_TX,
	USIE_IF_N_XFER
};

struct usie_softc {
	struct ucom_super_softc sc_super_ucom;

#define	USIE_UCOM_MAX	6
	struct ucom_softc sc_ucom[USIE_UCOM_MAX];
	uint8_t	sc_uc_ifnum[USIE_UCOM_MAX];

	struct mtx sc_mtx;

	struct task sc_if_status_task;
	struct task sc_if_sync_task;
	struct usb_callout sc_if_sync_ch;

	struct usie_net_info sc_net;

	struct usie_desc sc_txd;

	struct usb_xfer *sc_uc_xfer[USIE_UCOM_MAX][USIE_UC_N_XFER];
	struct usb_xfer *sc_if_xfer[USIE_IF_N_XFER];

	struct ifnet *sc_ifp;
	struct usb_device *sc_udev;
	device_t sc_dev;

	struct mbuf *sc_rxm;

	uint16_t sc_if_ifnum;

	int16_t	sc_rssi;

	uint8_t	sc_msr;
	uint8_t	sc_lsr;
	uint8_t	sc_nucom;

	uint8_t	sc_resp_temp[USIE_BUFSIZE] __aligned(4);
	uint8_t	sc_status_temp[USIE_BUFSIZE] __aligned(4);
};

/* Some code assumptions */

extern uint8_t usie_assert[((sizeof(struct usie_hip) +
    sizeof(struct usie_lsi) + 1) <= USIE_BUFSIZE) ? 1 : -1];

extern uint8_t ucdc_assert[(sizeof(struct usb_cdc_notification)
     >= 16) ? 1 : -1];

#endif					/* _IF_USEVAR_H_ */
