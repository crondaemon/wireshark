/*
 *  packet-h248_10.c
 *
 *  H.248.10
 *  Gateway control protocol: Media gateway
 *  resource congestion handling package
 *
 *  (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include "packet-h248.h"

void proto_register_h248_dot10(void);

#define PNAME  "H.248.10"
#define PSNAME "H248CHP"
#define PFNAME "h248.chp"

static int proto_h248_CHP;

static int hf_h248_CHP_mgcon;
static int hf_h248_CHP_mgcon_reduction;

static int ett_h248_CHP;
static int ett_h248_CHP_mgcon;

static const value_string h248_CHP_prop_vals[] = {
	{ 0, "chp (MG Congestion Handling)" },
	{ 0, NULL }
};

static const value_string h248_CHP_events_vals[] = {
	{1, "MGCon"},
	{ 0, NULL }
};

static const value_string h248_CHP_mgcon_params_vals[] = {
	{1, "reduction"},
	{ 0, NULL }
};


static const h248_pkg_param_t h248_CHP_mgcon_params[] = {
	{ 0x0001, &hf_h248_CHP_mgcon_reduction, h248_param_ber_integer, NULL },
	{ 0, NULL, NULL, NULL}
};


static const h248_pkg_evt_t h248_CHP_mgcon_events[] = {
	{ 0x0001, &hf_h248_CHP_mgcon, &ett_h248_CHP_mgcon, h248_CHP_mgcon_params, h248_CHP_mgcon_params_vals},
	{ 0, NULL, NULL, NULL, NULL}
};

static h248_package_t h248_pkg_CHP = {
	0x0029,
	&proto_h248_CHP,
	&ett_h248_CHP,

	h248_CHP_prop_vals,
	NULL,
	h248_CHP_events_vals,
	NULL,

	NULL,
	NULL,
	h248_CHP_mgcon_events,
	NULL
};

void proto_register_h248_dot10(void) {
	static hf_register_info hf[] = {
		/* H.248.1 E.1  Generic Package */
		{ &hf_h248_CHP_mgcon, { "MGCon", "h248.chp.mgcon", FT_BYTES, BASE_NONE, NULL, 0, "This event occurs when the MG requires that the MGC start or finish load reduction.", HFILL }},
		{ &hf_h248_CHP_mgcon_reduction, { "Reduction", "h248.chp.mgcon.reduction", FT_UINT32, BASE_DEC, NULL, 0, "Percentage of the load that the MGC is requested to block", HFILL }},
	};

	static int *ett[] = {
		&ett_h248_CHP,
		&ett_h248_CHP_mgcon,
	};

	proto_h248_CHP = proto_register_protocol(PNAME, PSNAME, PFNAME);

	proto_register_field_array(proto_h248_CHP, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	h248_register_package(&h248_pkg_CHP,REPLACE_PKG);
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
