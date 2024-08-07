/* guid-utils.c
 * GUID handling
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/epan.h>
#include <wsutil/unicode-utils.h>
#include <epan/wmem_scopes.h>
#include "guid-utils.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#endif

static wmem_tree_t *guid_to_name_tree;


#ifdef _WIN32
/* try to resolve an DCE/RPC interface name to its name using the Windows registry entries */
/* XXX - might be better to fill all interfaces into our database at startup instead of searching each time */
static int
ResolveWin32UUID(e_guid_t if_id, char *uuid_name, int uuid_name_max_len)
{
	TCHAR *reg_uuid_name;
	HKEY hKey = NULL;
	DWORD uuid_max_size = MAX_PATH;
	TCHAR *reg_uuid_str;

	reg_uuid_name=wmem_alloc(NULL, (MAX_PATH*sizeof(TCHAR))+1);
	reg_uuid_str=wmem_alloc(NULL, (MAX_PATH*sizeof(TCHAR))+1);

	if(uuid_name_max_len < 2){
		return 0;
	}
	reg_uuid_name[0] = '\0';
	StringCchPrintf(reg_uuid_str, MAX_PATH, _T("SOFTWARE\\Classes\\Interface\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}"),
			if_id.data1, if_id.data2, if_id.data3,
			if_id.data4[0], if_id.data4[1],
			if_id.data4[2], if_id.data4[3],
			if_id.data4[4], if_id.data4[5],
			if_id.data4[6], if_id.data4[7]);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_uuid_str, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
		if (RegQueryValueEx(hKey, NULL, NULL, NULL, (LPBYTE)reg_uuid_name, &uuid_max_size) == ERROR_SUCCESS && uuid_max_size <= MAX_PATH) {
			snprintf(uuid_name, uuid_name_max_len, "%s", utf_16to8(reg_uuid_name));
			RegCloseKey(hKey);
			wmem_free(NULL, reg_uuid_name);
			wmem_free(NULL, reg_uuid_str);
			return (int) strlen(uuid_name);
		}
		RegCloseKey(hKey);
	}
	wmem_free(NULL, reg_uuid_name);
	wmem_free(NULL, reg_uuid_str);
	return 0; /* we didn't find anything anyhow. Please don't use the string! */

}
#endif


/* store a guid to name mapping */
void
guids_add_guid(const e_guid_t *guid, const char *name)
{
	wmem_tree_key_t guidkey[2];
	uint32_t g[4];

	g[0]=guid->data1;

	g[1]=guid->data2;
	g[1]<<=16;
	g[1]|=guid->data3;

	g[2]=guid->data4[0];
	g[2]<<=8;
	g[2]|=guid->data4[1];
	g[2]<<=8;
	g[2]|=guid->data4[2];
	g[2]<<=8;
	g[2]|=guid->data4[3];

	g[3]=guid->data4[4];
	g[3]<<=8;
	g[3]|=guid->data4[5];
	g[3]<<=8;
	g[3]|=guid->data4[6];
	g[3]<<=8;
	g[3]|=guid->data4[7];

	guidkey[0].key=g;
	guidkey[0].length=4;
	guidkey[1].length=0;

	wmem_tree_insert32_array(guid_to_name_tree, &guidkey[0], (char *) name);
}

/* remove a guid to name mapping */
void
guids_delete_guid(const e_guid_t *guid)
{
	wmem_tree_key_t guidkey[2];
	uint32_t g[4];

	g[0] = guid->data1;

	g[1] = guid->data2;
	g[1] <<= 16;
	g[1] |= guid->data3;

	g[2] = guid->data4[0];
	g[2] <<= 8;
	g[2] |= guid->data4[1];
	g[2] <<= 8;
	g[2] |= guid->data4[2];
	g[2] <<= 8;
	g[2] |= guid->data4[3];

	g[3] = guid->data4[4];
	g[3] <<= 8;
	g[3] |= guid->data4[5];
	g[3] <<= 8;
	g[3] |= guid->data4[6];
	g[3] <<= 8;
	g[3] |= guid->data4[7];

	guidkey[0].key = g;
	guidkey[0].length = 4;
	guidkey[1].length = 0;

	void *data = wmem_tree_lookup32_array(guid_to_name_tree, &guidkey[0]);

	if (data != NULL) {
		// This will "remove" the entry by setting its data to NULL
		wmem_tree_insert32_array(guid_to_name_tree, &guidkey[0], NULL);
	}

}

/* retrieve the registered name for this GUID; uses the scope for the fallback case only */
const char *
guids_get_guid_name(const e_guid_t *guid, wmem_allocator_t *scope _U_)
{
	wmem_tree_key_t guidkey[2];
	uint32_t g[4];
	char *name;
#ifdef _WIN32
	static char *uuid_name;
#endif

	g[0]=guid->data1;

	g[1]=guid->data2;
	g[1]<<=16;
	g[1]|=guid->data3;

	g[2]=guid->data4[0];
	g[2]<<=8;
	g[2]|=guid->data4[1];
	g[2]<<=8;
	g[2]|=guid->data4[2];
	g[2]<<=8;
	g[2]|=guid->data4[3];

	g[3]=guid->data4[4];
	g[3]<<=8;
	g[3]|=guid->data4[5];
	g[3]<<=8;
	g[3]|=guid->data4[6];
	g[3]<<=8;
	g[3]|=guid->data4[7];

	guidkey[0].key=g;
	guidkey[0].length=4;
	guidkey[1].length=0;

	if((name = (char *)wmem_tree_lookup32_array(guid_to_name_tree, &guidkey[0]))){
		return name;
	}

#ifdef _WIN32
	/* try to resolve the mapping from the Windows registry */
	/* XXX - prefill the resolving database with all the Windows registry entries once at init only (instead of searching each time)? */
	uuid_name=wmem_alloc(scope, 128);
	if(ResolveWin32UUID(*guid, uuid_name, 128)) {
		return uuid_name;
	}
#endif

	return NULL;
}


void
guids_init(void)
{
	guid_to_name_tree=wmem_tree_new(wmem_epan_scope());
	/* XXX here is a good place to read a config file with wellknown guids */
}


/* Tries to match a guid against its name.
   Returns the associated string ptr on a match.
   Formats uuid number and returns the resulting string via wmem scope, if name is unknown.
   (derived from val_to_str) */
const char *
guids_resolve_guid_to_str(const e_guid_t *guid, wmem_allocator_t *scope)
{
	const char *name;

	name=guids_get_guid_name(guid, scope);
	if(name){
		return name;
	}

	return wmem_strdup_printf(scope, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				guid->data1, guid->data2, guid->data3,
				guid->data4[0], guid->data4[1],
				guid->data4[2], guid->data4[3],
				guid->data4[4], guid->data4[5],
				guid->data4[6], guid->data4[7]);
}

int guid_cmp(const e_guid_t *g1, const e_guid_t *g2)
{
	if (g1->data1 != g2->data1) {
		return (g1->data1 < g2->data1) ? -1 : 1;
	}

	if (g1->data2 != g2->data2) {
		return (g1->data2 < g2->data2) ? -1 : 1;
	}

	if (g1->data3 != g2->data3) {
		return (g1->data3 < g2->data3) ? -1 : 1;
	}

	return memcmp(&g1->data4[0], &g2->data4[0], 8);
}

unsigned guid_hash(const e_guid_t *guid)
{
	return g_int64_hash((const int64_t *)guid);
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
