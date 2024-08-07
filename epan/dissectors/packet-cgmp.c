/* packet-cgmp.c
 * Routines for the disassembly of the Cisco Group Management Protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/cisco_pid.h>

/*
 * See
 *
 * http://www.barnett.sk/software/bbooks/cisco_multicasting_routing/chap04.html
 *
 * for some information on CGMP.
 */
void proto_register_cgmp(void);
void proto_reg_handoff_cgmp(void);

static dissector_handle_t cgmp_handle;

static int proto_cgmp;
static int hf_cgmp_version;
static int hf_cgmp_type;
static int hf_cgmp_reserved;
static int hf_cgmp_count;
static int hf_cgmp_gda;
static int hf_cgmp_usa;

static int ett_cgmp;

static const value_string type_vals[] = {
	{ 0, "Join" },
	{ 1, "Leave" },
	{ 0, NULL },
};

static int
dissect_cgmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *cgmp_tree = NULL;
	int offset = 0;
	uint8_t count;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CGMP");
	col_set_str(pinfo->cinfo, COL_INFO, "Cisco Group Management Protocol");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_cgmp, tvb, offset, -1,
		    ENC_NA);
		cgmp_tree = proto_item_add_subtree(ti, ett_cgmp);

		proto_tree_add_item(cgmp_tree, hf_cgmp_version, tvb, offset, 1,
		    ENC_BIG_ENDIAN);
		proto_tree_add_item(cgmp_tree, hf_cgmp_type, tvb, offset, 1,
		    ENC_BIG_ENDIAN);
		offset += 1;

		proto_tree_add_item(cgmp_tree, hf_cgmp_reserved, tvb, offset, 2,
		    ENC_BIG_ENDIAN);
		offset += 2;

		count = tvb_get_uint8(tvb, offset);
		proto_tree_add_uint(cgmp_tree, hf_cgmp_count, tvb, offset, 1,
		    count);
		offset += 1;

		while (count != 0) {
			proto_tree_add_item(cgmp_tree, hf_cgmp_gda, tvb, offset, 6,
			    ENC_NA);
			offset += 6;

			proto_tree_add_item(cgmp_tree, hf_cgmp_usa, tvb, offset, 6,
			    ENC_NA);
			offset += 6;

			count--;
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_cgmp(void)
{
	static hf_register_info hf[] = {
		{ &hf_cgmp_version,
		{ "Version",	"cgmp.version",	FT_UINT8, BASE_DEC, NULL, 0xF0,
			NULL, HFILL }},

		{ &hf_cgmp_type,
		{ "Type",	"cgmp.type",	FT_UINT8, BASE_DEC, VALS(type_vals), 0x0F,
			NULL, HFILL }},

		{ &hf_cgmp_reserved,
		{ "Reserved",	"cgmp.reserved", FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_cgmp_count,
		{ "Count",	"cgmp.count", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_cgmp_gda,
		{ "Group Destination Address",	"cgmp.gda", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_cgmp_usa,
		{ "Unicast Source Address",	"cgmp.usa", FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
	};
	static int *ett[] = {
		&ett_cgmp,
	};

	proto_cgmp = proto_register_protocol("Cisco Group Management Protocol",
	    "CGMP", "cgmp");
	proto_register_field_array(proto_cgmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cgmp_handle = register_dissector("cgmp", dissect_cgmp, proto_cgmp);
}

void
proto_reg_handoff_cgmp(void)
{
	dissector_add_uint("llc.cisco_pid", CISCO_PID_CGMP, cgmp_handle);
	dissector_add_uint("ethertype", 0x2001, cgmp_handle);
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
