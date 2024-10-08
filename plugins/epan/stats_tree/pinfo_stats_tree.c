/* pinfo_stats_tree.c
 * Stats tree for ethernet frames
 *
 *  (c) 2005, Luis E. G. Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/stats_tree.h>
#include <epan/prefs.h>
#include <epan/uat-int.h>
#include <epan/to_str.h>
#include <epan/dissectors/packet-ip.h>

#include "pinfo_stats_tree.h"

/*-------------------------------------
 * UAT for Packet Lengths
 *-------------------------------------
 */
typedef struct {
	range_t *packet_range;
} uat_plen_record_t;

static uat_plen_record_t *uat_plen_records;
static uat_t *plen_uat;
static unsigned num_plen_uat;

void register_tap_listener_pinfo_stat_tree(void);

static void *uat_plen_record_copy_cb(void *n, const void *o, size_t siz _U_) {
	const uat_plen_record_t *r = (const uat_plen_record_t *)o;
	uat_plen_record_t *rn = (uat_plen_record_t *)n;

	if (r->packet_range)
		rn->packet_range = range_copy(NULL, r->packet_range);

	return n;
}

static bool
uat_plen_record_update_cb(void *r, char **err)
{
	uat_plen_record_t *rec = (uat_plen_record_t*)r;
	if (rec->packet_range->nranges < 1) {
		*err = g_strdup("Invalid range string");
		return false;
	}

	*err = NULL;
	return true;
}

static void uat_plen_record_free_cb(void*r) {
	uat_plen_record_t *record = (uat_plen_record_t*)r;

	if (record->packet_range)
		wmem_free(NULL, record->packet_range);
}

static void uat_plen_record_post_update_cb(void) {
	/* If there are no records, create default list */
	if (num_plen_uat == 0) {
		static const char * const default_range[] = {
			"0-19",
			"20-39",
			"40-79",
			"80-159",
			"160-319",
			"320-639",
			"640-1279",
			"1280-2559",
			"2560-5119",
			"5120-0xFFFFFFFF"
		};
		unsigned i;

		/* default values for packet lengths */
		for (i = 0; i < array_length(default_range); i++)
		{
			uat_plen_record_t rec;

			/* When asserts are disabled, some compilers optimize the assertion
			 * out of existence, but then complain that result is not used. */
			_U_ convert_ret_t result = range_convert_str(NULL, &rec.packet_range, default_range[i], UINT32_MAX);
			ws_assert(result == CVT_NO_ERROR);
			uat_add_record(plen_uat, &rec, true);
			wmem_free(NULL, rec.packet_range);
		}
	}
}

UAT_RANGE_CB_DEF(uat_plen_records, packet_range, uat_plen_record_t)

/* ip host stats_tree -- basic test */
static int st_node_ipv4 = -1;
static int st_node_ipv6 = -1;
static const char *st_str_ipv4 = "IPv4 Statistics" STATS_TREE_MENU_SEPARATOR "All Addresses";
static const char *st_str_ipv6 = "IPv6 Statistics" STATS_TREE_MENU_SEPARATOR "All Addresses";

static void ipv4_hosts_stats_tree_init(stats_tree *st) {
	st_node_ipv4 = stats_tree_create_node(st, st_str_ipv4, 0, STAT_DT_INT, true);
}

static void ipv6_hosts_stats_tree_init(stats_tree *st) {
	st_node_ipv6 = stats_tree_create_node(st, st_str_ipv6, 0, STAT_DT_INT, true);
}

static tap_packet_status ip_hosts_stats_tree_packet(stats_tree *st, packet_info *pinfo, int st_node, const char *st_str) {
	tick_stat_node(st, st_str, 0, false);
	tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_src), st_node, false);
	tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_dst), st_node, false);
	return TAP_PACKET_REDRAW;
}

static tap_packet_status ipv4_hosts_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return ip_hosts_stats_tree_packet(st, pinfo, st_node_ipv4, st_str_ipv4);
}

static tap_packet_status ipv6_hosts_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return ip_hosts_stats_tree_packet(st, pinfo, st_node_ipv6, st_str_ipv6);
}

/* ip host stats_tree -- separate source and dest, test stats_tree flags */
static int st_node_ipv4_src = -1;
static int st_node_ipv4_dst = -1;
static int st_node_ipv6_src = -1;
static int st_node_ipv6_dst = -1;
static const char *st_str_ipv4_srcdst = "IPv4 Statistics" STATS_TREE_MENU_SEPARATOR "Source and Destination Addresses";
static const char *st_str_ipv6_srcdst = "IPv6 Statistics" STATS_TREE_MENU_SEPARATOR "Source and Destination Addresses";
static const char *st_str_ipv4_src = "Source IPv4 Addresses";
static const char *st_str_ipv4_dst = "Destination IPv4 Addresses";
static const char *st_str_ipv6_src = "Source IPv6 Addresses";
static const char *st_str_ipv6_dst = "Destination IPv6 Addresses";

static void ip_srcdst_stats_tree_init(stats_tree *st,
				const char *st_str_src, int *st_node_src_ptr,
				const char *st_str_dst, int *st_node_dst_ptr) {
	/* create one tree branch for source */
	*st_node_src_ptr = stats_tree_create_node(st, st_str_src, 0, STAT_DT_INT, true);
	/* set flag so this branch will always be sorted to top of tree */
	stat_node_set_flags(st, st_str_src, 0, false, ST_FLG_SORT_TOP);
	/* create another top level node for destination branch */
	*st_node_dst_ptr = stats_tree_create_node(st, st_str_dst, 0, STAT_DT_INT, true);
	/* set flag so this branch will not be expanded by default */
	stat_node_set_flags(st, st_str_dst, 0, false, ST_FLG_DEF_NOEXPAND);
}

static void ipv4_srcdst_stats_tree_init(stats_tree *st) {
	ip_srcdst_stats_tree_init(st, st_str_ipv4_src, &st_node_ipv4_src, st_str_ipv4_dst, &st_node_ipv4_dst);
}

static void ipv6_srcdst_stats_tree_init(stats_tree *st) {
	ip_srcdst_stats_tree_init(st, st_str_ipv6_src, &st_node_ipv6_src, st_str_ipv6_dst, &st_node_ipv6_dst);
}

static tap_packet_status ip_srcdst_stats_tree_packet(stats_tree *st,
						     packet_info *pinfo,
						     int st_node_src,
						     const char *st_str_src,
						     int st_node_dst,
						     const char *st_str_dst) {
	/* update source branch */
	tick_stat_node(st, st_str_src, 0, false);
	tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_src), st_node_src, false);
	/* update destination branch */
	tick_stat_node(st, st_str_dst, 0, false);
	tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_dst), st_node_dst, false);
	return TAP_PACKET_REDRAW;
}

static tap_packet_status ipv4_srcdst_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return ip_srcdst_stats_tree_packet(st, pinfo, st_node_ipv4_src, st_str_ipv4_src, st_node_ipv4_dst, st_str_ipv4_dst);
}

static tap_packet_status ipv6_srcdst_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return ip_srcdst_stats_tree_packet(st, pinfo, st_node_ipv6_src, st_str_ipv6_src, st_node_ipv6_dst, st_str_ipv6_dst);
}

/* packet type stats_tree -- test pivot node */
static int st_node_ipv4_ptype = -1;
static int st_node_ipv6_ptype = -1;
static const char *st_str_ipv4_ptype = "IPv4 Statistics" STATS_TREE_MENU_SEPARATOR "IP Protocol Types";
static const char *st_str_ipv6_ptype = "IPv6 Statistics" STATS_TREE_MENU_SEPARATOR "IP Protocol Types";

static void ipv4_ptype_stats_tree_init(stats_tree *st) {
	st_node_ipv4_ptype = stats_tree_create_pivot(st, st_str_ipv4_ptype, 0);
}

static void ipv6_ptype_stats_tree_init(stats_tree *st) {
	st_node_ipv6_ptype = stats_tree_create_pivot(st, st_str_ipv6_ptype, 0);
}

static tap_packet_status ipv4_ptype_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	stats_tree_tick_pivot(st, st_node_ipv4_ptype, port_type_to_str(pinfo->ptype));
	return TAP_PACKET_REDRAW;
}

static tap_packet_status ipv6_ptype_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	stats_tree_tick_pivot(st, st_node_ipv6_ptype, port_type_to_str(pinfo->ptype));
	return TAP_PACKET_REDRAW;
}

/* a tree example
 - IP
    - PROTO
       - PORT

*/
static int st_node_ipv4_dsts = -1;
static int st_node_ipv6_dsts = -1;
static const char *st_str_ipv4_dsts = "IPv4 Statistics" STATS_TREE_MENU_SEPARATOR "Destinations and Ports";
static const char *st_str_ipv6_dsts = "IPv6 Statistics" STATS_TREE_MENU_SEPARATOR "Destinations and Ports";

static void ipv4_dsts_stats_tree_init(stats_tree *st) {
	st_node_ipv4_dsts = stats_tree_create_node(st, st_str_ipv4_dsts, 0, STAT_DT_INT, true);
}

static void ipv6_dsts_stats_tree_init(stats_tree *st) {
	st_node_ipv6_dsts = stats_tree_create_node(st, st_str_ipv6_dsts, 0, STAT_DT_INT, true);
}

static tap_packet_status dsts_stats_tree_packet(stats_tree *st, packet_info *pinfo, int st_node, const char *st_str) {
	static char str[128];
	int ip_dst_node;
	int protocol_node;

	tick_stat_node(st, st_str, 0, false);
	ip_dst_node = tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_dst), st_node, true);
	protocol_node = tick_stat_node(st, port_type_to_str(pinfo->ptype), ip_dst_node, true);
	snprintf(str, sizeof(str) - 1, "%u", pinfo->destport);
	tick_stat_node(st, str, protocol_node, true);
	return TAP_PACKET_REDRAW;
}

static tap_packet_status ipv4_dsts_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return dsts_stats_tree_packet(st, pinfo, st_node_ipv4_dsts, st_str_ipv4_dsts);
}

static tap_packet_status ipv6_dsts_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	return dsts_stats_tree_packet(st, pinfo, st_node_ipv6_dsts, st_str_ipv6_dsts);
}

static int st_node_ipv4_src_ttls = -1;
static int st_node_ipv6_src_ttls = -1;
static const char* st_str_ipv4_src_ttls = "IPv4 Statistics" STATS_TREE_MENU_SEPARATOR "Source TTLs";
static const char* st_str_ipv6_src_ttls = "IPv6 Statistics" STATS_TREE_MENU_SEPARATOR "Source Hop Limits";

static void ipv4_src_ttl_stats_tree_init(stats_tree* st) {
	st_node_ipv4_src_ttls = stats_tree_create_node(st, st_str_ipv4_src_ttls, 0, STAT_DT_INT, true);
}

static void ipv6_src_ttl_stats_tree_init(stats_tree* st) {
	st_node_ipv6_src_ttls = stats_tree_create_node(st, st_str_ipv6_src_ttls, 0, STAT_DT_INT, true);
}

static tap_packet_status src_ttl_stats_tree_packet(stats_tree* st, packet_info* pinfo, int st_node, const char* st_str, uint8_t ttl) {
	static char str[128];
	int ip_src_node;
	int ttl_node;

	tick_stat_node(st, st_str, 0, false);
	ip_src_node = tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_src), st_node, true);
	snprintf(str, sizeof(str) - 1, "%u", ttl);
	ttl_node = tick_stat_node(st, str, ip_src_node, true);
	tick_stat_node(st, address_to_str(pinfo->pool, &pinfo->net_dst), ttl_node, true);
	return TAP_PACKET_REDRAW;
}

static tap_packet_status ipv4_src_ttl_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_) {
	ws_ip4* iph = (ws_ip4*)p;

	return src_ttl_stats_tree_packet(st, pinfo, st_node_ipv4_src_ttls, st_str_ipv4_src_ttls, iph->ip_ttl);
}

static tap_packet_status ipv6_src_ttl_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_) {
	ws_ip6* iph = (ws_ip6*)p;

	return src_ttl_stats_tree_packet(st, pinfo, st_node_ipv6_src_ttls, st_str_ipv6_src_ttls, iph->ip6_hop);
}

/* packet length stats_tree -- test range node */
static int st_node_plen = -1;
static const char *st_str_plen = "Packet Lengths";

static void plen_stats_tree_init(stats_tree *st) {
	unsigned i;
	char **str_range_array = (char **)wmem_alloc(NULL, num_plen_uat*sizeof(char*));

	/* Convert the ranges to strings for the stats tree API */
	for (i = 0; i < num_plen_uat - 1; i++) {
		str_range_array[i] = range_convert_range(NULL, uat_plen_records[i].packet_range);
	}
	str_range_array[num_plen_uat - 1] = ws_strdup_printf("%u and greater",
		uat_plen_records[num_plen_uat - 1].packet_range->ranges[0].low);

	st_node_plen = stats_tree_create_range_node_string(st, st_str_plen, 0, num_plen_uat, str_range_array);
	for (i = 0; i < num_plen_uat; i++) {
		wmem_free(NULL, str_range_array[i]);
	}
}

static tap_packet_status plen_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p _U_, tap_flags_t flags _U_) {
	tick_stat_node(st, st_str_plen, 0, false);

	stats_tree_tick_range(st, st_str_plen, 0, pinfo->fd->pkt_len);

	return TAP_PACKET_REDRAW;
}

/* register all pinfo trees */
void register_tap_listener_pinfo_stat_tree(void)
{
	module_t *stat_module;

	static uat_field_t plen_uat_flds[] = {
		UAT_FLD_RANGE(uat_plen_records, packet_range, "Packet Range", 0xFFFFFFFF, "Range of packet sizes to count"),
		UAT_END_FIELDS
	};

	stats_tree_register_plugin("ip", "ip_hosts", st_str_ipv4, 0, ipv4_hosts_stats_tree_packet, ipv4_hosts_stats_tree_init, NULL );
	stats_tree_register_plugin("ip", "ip_srcdst", st_str_ipv4_srcdst, 0, ipv4_srcdst_stats_tree_packet, ipv4_srcdst_stats_tree_init, NULL );
	stats_tree_register_plugin("ip", "ptype", st_str_ipv4_ptype, 0, ipv4_ptype_stats_tree_packet, ipv4_ptype_stats_tree_init, NULL );
	stats_tree_register_plugin("ip", "dests", st_str_ipv4_dsts, 0, ipv4_dsts_stats_tree_packet, ipv4_dsts_stats_tree_init, NULL );
	stats_tree_register_plugin("ip", "ip_ttl", st_str_ipv4_src_ttls, 0, ipv4_src_ttl_stats_tree_packet, ipv4_src_ttl_stats_tree_init, NULL);

	stats_tree_register_plugin("ipv6", "ipv6_hosts", st_str_ipv6, 0, ipv6_hosts_stats_tree_packet, ipv6_hosts_stats_tree_init, NULL );
	stats_tree_register_plugin("ipv6", "ipv6_srcdst", st_str_ipv6_srcdst, 0, ipv6_srcdst_stats_tree_packet, ipv6_srcdst_stats_tree_init, NULL );
	stats_tree_register_plugin("ipv6", "ipv6_ptype", st_str_ipv6_ptype, 0, ipv6_ptype_stats_tree_packet, ipv6_ptype_stats_tree_init, NULL );
	stats_tree_register_plugin("ipv6", "ipv6_dests", st_str_ipv6_dsts, 0, ipv6_dsts_stats_tree_packet, ipv6_dsts_stats_tree_init, NULL );
	stats_tree_register_plugin("ipv6", "ipv6_hop", st_str_ipv6_src_ttls, 0, ipv6_src_ttl_stats_tree_packet, ipv6_src_ttl_stats_tree_init, NULL);


	stats_tree_cfg *st_config = stats_tree_register("frame", "plen", st_str_plen, 0, plen_stats_tree_packet, plen_stats_tree_init, NULL);
	stats_tree_set_group(st_config, REGISTER_STAT_GROUP_GENERIC);

	stat_module = prefs_register_stat("stat_tree", "Stats Tree", "Stats Tree", NULL);

	plen_uat = uat_new("Packet Lengths",
			sizeof(uat_plen_record_t),  /* record size */
			"packet_lengths",           /* filename */
			true,                       /* from_profile */
			&uat_plen_records,          /* data_ptr */
			&num_plen_uat,              /* numitems_ptr */
			0,                          /* not a dissector, so affects neither dissection nor fields */
			NULL,                       /* help */
			uat_plen_record_copy_cb,    /* copy callback */
			uat_plen_record_update_cb,  /* update callback */
			uat_plen_record_free_cb,    /* free callback */
			uat_plen_record_post_update_cb, /* post update callback */
			NULL,                       /* reset callback */
			plen_uat_flds);             /* UAT field definitions */

	prefs_register_uat_preference(stat_module, "packet_lengths",
		"Packet Lengths", "Delineated packet sizes to count", plen_uat);
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
