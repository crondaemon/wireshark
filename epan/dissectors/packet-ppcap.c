/* packet-ppcap.c
 * Copyright 2012, 2014, Ericsson AB
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/address_types.h>

#include <wsutil/ws_roundup.h>

#include "packet-mtp3.h"

#define INVALID_SSN	0xff

void proto_register_ppcap(void);

static uint8_t ssn;

static dissector_handle_t ppcap_handle;
static dissector_handle_t mtp3_handle;  /* MTP3 handle */
static dissector_handle_t tcap_handle;  /* TCAP handle */
static dissector_handle_t bssap_handle; /* BSSAP handle */
static dissector_handle_t ranap_handle; /* RANAP handle */
static dissector_handle_t h248_handle;  /* H248 handle */
static dissector_handle_t sip_handle;   /* SIP handle  */
static dissector_handle_t sccp_handle;  /* SCCP handle */
static dissector_handle_t sgsap_handle; /* SGSAP handle */
static dissector_handle_t gtpv2_handle; /* GTPv2 handle */

static dissector_table_t sccp_ssn_dissector_table;

static mtp3_addr_pc_t* mtp3_addr_opc;
static mtp3_addr_pc_t* mtp3_addr_dpc;

static int ss7pc_address_type = -1;

static int ett_ppcap;
static int ett_ppcap1;
static int ett_ppcap_new;

static const value_string payload_tag_values[] = {
	{  1,	"Payload Type"},
	{  2,	"Payload Data"},
	{  3,	"Source Address"},
	{  4,	"Destination Address"},
	{  5,	"Local Port"},
	{  6,	"Remote Port"},
	{  7,	"Transfer Protocol used for message"},
	{  8,	"SCTP association ID" },
	{256,	"Info String"},
	{0,	NULL},

};

static const value_string address_type_values[] = {
	{1,	"SSN+SPC"},
	{2,	"SPC"},
	{3,	"IP Address"},
	{4,	"Node Id"},
	{0,	NULL},

};

/* Initialise the header fields */

static int proto_ppcap;
static int hf_ppcap_length;
static int hf_ppcap_payload_type;
static int hf_ppcap_ssn;
static int hf_ppcap_spc;
static int hf_ppcap_ssn1;
static int hf_ppcap_spc1;
static int hf_ppcap_opc;
static int hf_ppcap_dpc;
static int hf_ppcap_source_nodeid;
static int hf_ppcap_destination_nodeid;
/*static int hf_ppcap_source_address_type; */
/*static int hf_ppcap_destination_address_type; */
static int hf_ppcap_address_type;
static int hf_ppcap_source_ip_address1;
static int hf_ppcap_source_ip_address2;
static int hf_ppcap_destination_ip_address1;
static int hf_ppcap_destination_ip_address2;
static int hf_ppcap_reserved;
static int hf_ppcap_destreserved;
static int hf_ppcap_info;
static int hf_ppcap_payload_data;
static int hf_ppcap_local_port;
static int hf_ppcap_remote_port;
static int hf_ppcap_transport_prot;
static int hf_ppcap_sctp_assoc;

/* Initialize the subtree pointers */

void proto_reg_handoff_ppcap(void);


/* PPCAP payload types */
typedef enum {
	PPCAP_UNKNOWN = 0,
	PPCAP_MTP3    = 1,
	PPCAP_TCAP    = 2,
	PPCAP_BSSAP   = 3,
	PPCAP_RANAP   = 4,
	PPCAP_H248    = 5,
	PPCAP_SIP     = 6,
	PPCAP_SCCP    = 7,
	PPCAP_SGSAP   = 8,
	PPCAP_GTPV2   = 9
} payload_type_type;

static int dissect_ppcap_payload_type(tvbuff_t *, packet_info *, proto_tree *, int, payload_type_type *);
static int dissect_ppcap_source_address(tvbuff_t *, packet_info *, proto_tree *, int);
static int dissect_ppcap_destination_address(tvbuff_t *, packet_info *, proto_tree *, int);
static int dissect_ppcap_info_string(tvbuff_t *, proto_tree *, int);
static int dissect_ppcap_local_port(tvbuff_t *, proto_tree *, int);
static int dissect_ppcap_remote_port(tvbuff_t *,proto_tree *, int);
static int dissect_ppcap_transport_protocol(tvbuff_t *,proto_tree *, int);
static int dissect_ppcap_sctp_assoc(tvbuff_t *, proto_tree *, int);
static int dissect_ppcap_payload_data(tvbuff_t *, packet_info *, proto_tree *, int, proto_tree *, payload_type_type);

/*Dissecting the function PPCAP */

static int
dissect_ppcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *ppcap_tree, *ppcap_tree1;
	uint16_t msg_type;
	int offset = 0;
	payload_type_type payload_type = PPCAP_UNKNOWN;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PPCAP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_ppcap, tvb, 0, -1, ENC_NA);
	ppcap_tree = proto_item_add_subtree(ti, ett_ppcap);

	while (tvb_reported_length_remaining(tvb, offset) > 0)
	{
		msg_type = tvb_get_ntohs(tvb, offset);
		ppcap_tree1 = proto_tree_add_subtree(ppcap_tree, tvb, offset, 2, ett_ppcap1, NULL,
					val_to_str(msg_type, payload_tag_values, "Unknown PPCAP message type (%u)"));
		offset  = offset + 2;
		switch (msg_type) {
		case 1:
			payload_type = PPCAP_UNKNOWN;
			offset = dissect_ppcap_payload_type(tvb, pinfo, ppcap_tree1, offset, &payload_type);
			break;
		case 2:
			offset = dissect_ppcap_payload_data(tvb, pinfo, ppcap_tree1, offset, tree, payload_type);
			break;
		case 3:
			offset = dissect_ppcap_source_address(tvb, pinfo, ppcap_tree1, offset);
			break;
		case 4:
			offset = dissect_ppcap_destination_address(tvb, pinfo, ppcap_tree1, offset);
			break;
		case 5:
			offset = dissect_ppcap_local_port(tvb,ppcap_tree1, offset);
			break;
		case 6:
			offset = dissect_ppcap_remote_port(tvb,ppcap_tree1, offset);
			break;
		case 7:
			offset = dissect_ppcap_transport_protocol(tvb,ppcap_tree1, offset);
			break;
		case 8:
			offset = dissect_ppcap_sctp_assoc(tvb, ppcap_tree1, offset);
			break;
		case 256:
			offset = dissect_ppcap_info_string(tvb, ppcap_tree1, offset);
			break;
		}
	}
	return tvb_captured_length(tvb);
}


/* Dissecting the function Payload type to compare the protocol type */

/*
  *******************************************************
  *               Payload Type                          *
  *                                                     *
  *******************************************************
*/



static int
dissect_ppcap_payload_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree * ppcap_tree1, int offset, payload_type_type *payload_type)
{
	char *string;
	uint16_t msg_len =0;
	msg_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item( ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset  = offset + 2;
	string = tvb_get_string_enc(pinfo->pool, tvb, offset, msg_len, ENC_UTF_8|ENC_NA);
	if (strcmp(string,"mtp3") == 0) {
		*payload_type = PPCAP_MTP3;
	}else if (strcmp(string,"tcap")  == 0) {
		*payload_type = PPCAP_TCAP;
	}else if (strcmp(string,"bssap") == 0) {
		*payload_type = PPCAP_BSSAP;
	}else if (strcmp(string,"ranap") == 0) {
		*payload_type = PPCAP_RANAP;
	}else if (strcmp(string,"h248")  == 0) {
		*payload_type = PPCAP_H248;
	}else if (strcmp(string,"sip")   == 0) {
		*payload_type = PPCAP_SIP;
	}else if (strcmp(string,"sccp")  == 0) {
		*payload_type = PPCAP_SCCP;
	}else if (strcmp(string, "sgsap") == 0) {
		*payload_type = PPCAP_SGSAP;
	}else if (strcmp(string, "gtpv2") == 0) {
		*payload_type = PPCAP_GTPV2;
	}

	proto_tree_add_item(ppcap_tree1, hf_ppcap_payload_type, tvb, offset, msg_len, ENC_UTF_8);

	msg_len = WS_ROUNDUP_4(msg_len);
	offset += msg_len;
	return offset;
}

/* Dissecting the function Source Address */

/*

  *******************************************************
  *	Reserved	*	Address Type		*
  *				*			*
  *******************************************************
  *	          Address Value				*
  *							*
  *******************************************************
*/

static int
dissect_ppcap_source_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree * ppcap_tree1, int offset)
{
	int key1;
	uint16_t msg_len;
	msg_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item( ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset  = offset + 2;
	proto_tree_add_item(ppcap_tree1, hf_ppcap_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	key1 = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ppcap_tree1, hf_ppcap_address_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (key1 == 1)
	{
		proto_tree_add_item(ppcap_tree1, hf_ppcap_ssn, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(ppcap_tree1, hf_ppcap_spc, tvb, offset, 3, ENC_BIG_ENDIAN);
		/*src_addr1 = (uint32_t )tvb_get_ntoh24(tvb, offset);*/
		mtp3_addr_opc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
		mtp3_addr_opc->pc = (uint32_t )tvb_get_ntoh24(tvb, offset);
		mtp3_addr_opc->type = ITU_STANDARD;
		mtp3_addr_opc->ni = 0;
		/*set_address(&pinfo->net_src, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (uint8_t *) mtp3_addr_opc);*/
		set_address(&pinfo->src, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (uint8_t *) mtp3_addr_opc);
		msg_len = WS_ROUNDUP_4(msg_len);

		offset += msg_len-1;
		return offset;
	}
	else if (key1 == 2)
	{
		proto_tree_add_item(ppcap_tree1, hf_ppcap_opc, tvb, offset, msg_len, ENC_BIG_ENDIAN);

		/*src_addr1 = (uint32_t )tvb_get_ntoh24(tvb, offset);*/
		mtp3_addr_opc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
		mtp3_addr_opc->pc = tvb_get_ntohl(tvb, offset);
		mtp3_addr_opc->type = ITU_STANDARD;
		mtp3_addr_opc->ni = 0;
		set_address(&pinfo->src, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (uint8_t *) mtp3_addr_opc);
	}
	else if (key1 == 3)
	{
		if (msg_len%16 != 0)
		{

			proto_tree_add_item(ppcap_tree1, hf_ppcap_source_ip_address1, tvb, offset, msg_len, ENC_BIG_ENDIAN);
			set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, offset);
			copy_address_shallow(&pinfo->src, &pinfo->net_src);
		}
		else
		{
			proto_tree_add_item(ppcap_tree1, hf_ppcap_source_ip_address2, tvb, offset, msg_len, ENC_NA);
			set_address_tvb(&pinfo->net_src, AT_IPv6, 6, tvb, offset);
			copy_address_shallow(&pinfo->src, &pinfo->net_src);
		}
	}

	else if (key1 == 4)

	{
		proto_tree_add_item(ppcap_tree1, hf_ppcap_source_nodeid, tvb, offset, msg_len, ENC_ASCII);
		set_address_tvb(&pinfo->net_src, AT_STRINGZ, msg_len, tvb, offset);
		copy_address_shallow(&pinfo->src, &pinfo->net_src);
	}
	msg_len = WS_ROUNDUP_4(msg_len);
	offset += msg_len;
	return offset;
}

/* Dissecting the function Destination Address */

/*
  *******************************************************
  *     Reserved        *       Address Type            *
  *                     *                               *
  *******************************************************
  *               Address Value                         *
  *                                                     *
  *******************************************************
*/


static int
dissect_ppcap_destination_address(tvbuff_t *tvb, packet_info * pinfo, proto_tree * ppcap_tree1, int offset)
{
	int key2;
	uint16_t msg_len;
	msg_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item( ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset  = offset + 2;
	proto_tree_add_item(ppcap_tree1, hf_ppcap_destreserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	key2 = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ppcap_tree1, hf_ppcap_address_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	if (key2 == 1)
	{
		ssn = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(ppcap_tree1, hf_ppcap_ssn1, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(ppcap_tree1, hf_ppcap_spc1, tvb, offset, 3, ENC_BIG_ENDIAN);

		/*dst_addr1 = (uint32_t )tvb_get_ntoh24(tvb, offset);*/
		mtp3_addr_dpc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
		mtp3_addr_dpc->pc = (uint32_t)tvb_get_ntoh24(tvb, offset);
		mtp3_addr_dpc->type = ITU_STANDARD;
		mtp3_addr_dpc->ni = 0;
		set_address(&pinfo->dst, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (uint8_t *) mtp3_addr_dpc);

		msg_len = WS_ROUNDUP_4(msg_len);

		offset += msg_len-1;
		return offset;

	}
	else if (key2 == 2)
	{
		proto_tree_add_item(ppcap_tree1, hf_ppcap_dpc, tvb, offset, 4, ENC_BIG_ENDIAN);

		/*dst_addr1 = (uint32_t )tvb_get_ntoh24(tvb, offset);*/
		mtp3_addr_dpc = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
		mtp3_addr_dpc->pc = tvb_get_ntohl(tvb, offset);
		mtp3_addr_dpc->type = ITU_STANDARD;
		mtp3_addr_dpc->ni = 0;
		set_address(&pinfo->dst, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (uint8_t *) mtp3_addr_dpc);
	}
	else if (key2 == 3)
	{
		if (msg_len%16 != 0)
		{
			proto_tree_add_item(ppcap_tree1, hf_ppcap_destination_ip_address1, tvb, offset, msg_len, ENC_BIG_ENDIAN);
			set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, offset);
			copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
		}
		else
		{
			proto_tree_add_item(ppcap_tree1, hf_ppcap_destination_ip_address2, tvb, offset, msg_len, ENC_NA);
			set_address_tvb(&pinfo->net_dst, AT_IPv6, 6, tvb, offset);
			copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
		}
	}

	else if (key2 == 4)
	{
		const uint8_t *string;
		proto_tree_add_item_ret_string(ppcap_tree1, hf_ppcap_destination_nodeid, tvb, offset, msg_len, ENC_UTF_8|ENC_NA, pinfo->pool, &string);
		set_address_tvb(&pinfo->net_dst, AT_STRINGZ, msg_len, tvb, offset);
		copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
	}

	msg_len = WS_ROUNDUP_4(msg_len);

	offset += msg_len;

	return offset;
}

/* Dissecting the function Info String */

/*
  *******************************************************
  *               Info                        		*
  *                                                     *
  *******************************************************
*/

static int
dissect_ppcap_info_string(tvbuff_t *tvb, proto_tree * ppcap_tree1, int offset)
{
	uint16_t msg_len;
	msg_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item( ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset  = offset + 2;
	proto_tree_add_item(ppcap_tree1, hf_ppcap_info, tvb, offset, msg_len, ENC_ASCII);

	msg_len = WS_ROUNDUP_4(msg_len);
	offset += msg_len;
	return offset;
}

/* Dissecting the function Local Port */

/*
  *******************************************************
  *               Local Port                            *
  *                                                     *
  *******************************************************
*/
static int
dissect_ppcap_local_port(tvbuff_t *tvb,proto_tree * ppcap_tree1, int offset)
{
	proto_tree_add_item(ppcap_tree1,hf_ppcap_local_port,tvb,offset,2,ENC_BIG_ENDIAN);
	offset = offset+6;      /*Adding offset of filler bytes without text*/
	return offset;
}

/* Dissecting the function Remote Port */

/*
  *******************************************************
  *               Remote Port                           *
  *                                                     *
  *******************************************************
*/

static int
dissect_ppcap_remote_port(tvbuff_t *tvb,proto_tree * ppcap_tree1, int offset)
{
	proto_tree_add_item(ppcap_tree1,hf_ppcap_remote_port,tvb,offset,2,ENC_BIG_ENDIAN);
	offset = offset+6;      /*Adding offset of filler bytes without text*/
	return offset;
}

/* Dissecting the function TCP SIP Message */

/*
  *******************************************************
  *               Transport protocol                    *
  *                                                     *
  *******************************************************
*/

static int
dissect_ppcap_transport_protocol(tvbuff_t *tvb,proto_tree * ppcap_tree1, int offset)
{
	proto_tree_add_item(ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset = offset + 2;
	proto_tree_add_item(ppcap_tree1, hf_ppcap_transport_prot, tvb, offset, 4, ENC_ASCII);
	offset += 4;

	return offset;
}

static int
dissect_ppcap_sctp_assoc(tvbuff_t *tvb _U_, proto_tree * tree _U_, int offset)
{
	uint16_t length;
	length = tvb_get_ntohs(tvb, offset);

	proto_tree_add_item(tree, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset = offset + 2;

	proto_tree_add_item(tree, hf_ppcap_sctp_assoc, tvb, offset, length, ENC_ASCII);

	/* The string can be 1 -15 characters long but the IE is padded to 16 bytes*/

	return offset + 16;
}

/* Dissecting the function Payload Data to call the protocol that based upon the type decided in the Payload Type */

/*
  *******************************************************
  *               Payload Data                          *
  *                                                     *
  *******************************************************
*/


static int
dissect_ppcap_payload_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree * ppcap_tree1, int offset, proto_tree *tree, payload_type_type payload_type)
{
	tvbuff_t        *next_tvb;
	uint16_t msg_len;
	msg_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item( ppcap_tree1, hf_ppcap_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset  = offset + 2;
	proto_tree_add_item(ppcap_tree1, hf_ppcap_payload_data, tvb, offset, msg_len, ENC_NA);

	msg_len = WS_ROUNDUP_4(msg_len);

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	switch (payload_type) {
	case PPCAP_MTP3:
		call_dissector(mtp3_handle, next_tvb, pinfo, tree);  /* calling the MTP3 handle */
		break;
	case PPCAP_TCAP:
		/*
		 * The protocol which runs on TCAP takes the SSN value from the SCCP layer which is missing in this case.
		 * So we have made code changes for TCAP handle as below for taking the SSN value from ppcap.
		 */
		if (ssn != INVALID_SSN && dissector_try_uint(sccp_ssn_dissector_table, ssn, next_tvb, pinfo, tree))	{
			return  offset+msg_len;
		}else{
			call_dissector(tcap_handle, next_tvb, pinfo, tree);  /* calling the TCAP handle */
		}
		break;
	case PPCAP_BSSAP:
		call_dissector(bssap_handle, next_tvb, pinfo, tree);  /* calling the BSSAP handle */
		break;
	case PPCAP_RANAP:
		call_dissector(ranap_handle, next_tvb, pinfo, tree);  /* calling the RANAP handle */
		break;
	case PPCAP_H248:
		call_dissector(h248_handle, next_tvb, pinfo, tree);   /* calling the H248 handle */
		break;
	case PPCAP_SIP:
		call_dissector(sip_handle, next_tvb, pinfo, tree);    /* calling the SIP handle */
		break;
	case PPCAP_SCCP:
		call_dissector(sccp_handle, next_tvb, pinfo, tree);   /* calling the SCCP handle */
		break;
	case PPCAP_SGSAP:
		call_dissector(sgsap_handle, next_tvb, pinfo, tree);   /* calling the SGSAP handle */
		break;
	case PPCAP_GTPV2:
		call_dissector(gtpv2_handle, next_tvb, pinfo, tree);   /* calling the GTPv2 handle */
		break;
	default:
		call_data_dissector(next_tvb, pinfo, tree);   /* calling the DATA handle */
		break;
	}

	offset += msg_len;
	return offset;
}

/* Registering the hf variables */

void proto_register_ppcap(void)
{

	static hf_register_info hf[] = {
	{ &hf_ppcap_length,
	{ "Length",         "ppcap.length",
		FT_UINT16, BASE_DEC, NULL,   0x00, NULL, HFILL}},
	{ &hf_ppcap_payload_type,
	{ "Payload Type", "ppcap.payload_type", FT_STRING,
		BASE_NONE, 	NULL, 	0x0    , NULL,    HFILL}},
	{ &hf_ppcap_reserved,
	{ "Reserved",         "ppcap.reserved",    FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_address_type,
	{ "Address Type",         "ppcap.address_type",    FT_UINT16,
		BASE_DEC,    VALS(address_type_values),         0x00 , NULL, HFILL}},
#if 0
	{ &hf_ppcap_source_address_type,
	{ "Source Address Type",         "ppcap.source_address_type",    FT_UINT16,
		BASE_DEC,    VALS(address_type_values),         0x00 , NULL, HFILL}},
#endif
	{ &hf_ppcap_ssn,
	{ "SSN",     "ppcap.ssn",   FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_spc,
	{"OPC",     "ppcap.spc",   FT_UINT24,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_opc,
	{ "OPC",     "ppcap.opc",   FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_source_ip_address1,
	{ "Source IP Address",     "ppcap.source_ip_address1",   FT_IPv4,
		BASE_NONE,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_source_ip_address2,
	{ "Source IP Address",     "ppcap.source_ip_address2",   FT_IPv6,
		BASE_NONE,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_destreserved,
	{ "Reserved",         "ppcap.destreserved",    FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
#if 0
	{ &hf_ppcap_destination_address_type,
	{ "Destination Address Type",         "ppcap.destination_address_type",    FT_UINT16,
		BASE_DEC,      VALS(address_type_values),   0x00,   NULL,     HFILL}},
#endif
	{ &hf_ppcap_ssn1,
	{ "SSN",     "ppcap.ssn1",   FT_UINT8,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_spc1,
	{ "DPC",     "ppcap.spc1",   FT_UINT24,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_dpc,
	{ "DPC",     "ppcap.dpc",   FT_UINT32,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_destination_ip_address1,
	{ "Destination IP Address",     "ppcap.destination_ip_address1",   FT_IPv4,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_destination_ip_address2,
	{ "Destination IP Address",     "ppcap.destination_ip_address2",   FT_IPv6,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_source_nodeid,
	{ "Source Node ID",         "ppcap.source_nodeid",    FT_STRING,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_destination_nodeid,
	{ "Destination Node ID",         "ppcap.destination_address",    FT_STRING,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_info,
	{ "Info",         "ppcap.info",    FT_STRING,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_payload_data,
	{ "Payload Data",         "ppcap.payload_data",    FT_BYTES,
		BASE_NONE,       NULL,   0x0,   NULL,     HFILL}},
	{ &hf_ppcap_local_port,
	{ "Local Port",         "ppcap.local_port",    FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_remote_port,
	{ "Remote Port",         "ppcap.remote_port",    FT_UINT16,
		BASE_DEC,       NULL,   0x00,   NULL,     HFILL}},
	{ &hf_ppcap_transport_prot,
	{ "Transport Protocol", "ppcap.transport_prot", FT_STRING,
		BASE_NONE,      NULL,   0x0    , NULL,    HFILL}},
	{ &hf_ppcap_sctp_assoc,
	{ "SCTP Association ID", "ppcap.sctp_assoc", FT_STRING,
		BASE_NONE,      NULL,   0x0    , NULL,    HFILL } },
	};

	static int *ett[]= {
		&ett_ppcap,
		&ett_ppcap1,
		&ett_ppcap_new,
	};
	proto_ppcap = proto_register_protocol("Proprietary PCAP", "PPCAP", "ppcap");
	proto_register_field_array(proto_ppcap , hf , array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("ppcap", dissect_ppcap, proto_ppcap);

}

void proto_reg_handoff_ppcap(void)
{
	ppcap_handle = find_dissector_add_dependency("ppcap", proto_ppcap);
	mtp3_handle  = find_dissector_add_dependency("mtp3", proto_ppcap);  /* calling the protocol MTP3 */
	tcap_handle  = find_dissector_add_dependency("tcap", proto_ppcap);  /* calling the protocol TCAP */
	bssap_handle = find_dissector_add_dependency("bssap", proto_ppcap); /* calling the protocol BSSAP */
	ranap_handle = find_dissector_add_dependency("ranap", proto_ppcap); /* calling the protocol RANAP */
	h248_handle  = find_dissector_add_dependency("h248", proto_ppcap);  /* calling the protocol H248 */
	sip_handle   = find_dissector_add_dependency("sip", proto_ppcap);   /* calling the protocol SIP */
	sccp_handle  = find_dissector_add_dependency("sccp", proto_ppcap);   /* calling the protocol SCCP */
	sgsap_handle = find_dissector_add_dependency("sgsap", proto_ppcap); /* calling the protocol SGSAP */
	gtpv2_handle = find_dissector_add_dependency("gtpv2", proto_ppcap); /* calling the protocol GTPv2 */

	sccp_ssn_dissector_table = find_dissector_table("sccp.ssn");

	ss7pc_address_type = address_type_get_by_name("AT_SS7PC");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
