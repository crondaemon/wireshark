/* pgp.c
 *
 * Copyright 2019, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include "pgp.h"

static gboolean valid_packet_tag(guint8 packet_tag _U_)
{
	guint8 tag;

	if (packet_tag >> 7 != 1)
		return FALSE;

	if (packet_tag & 0x4 >> 6) {
		tag = (packet_tag & 0x3c) >> 2;
	} else {
		tag = packet_tag & 0xC0;
	}

	if (tag > 19 && tag < 60)
		return FALSE;

	return TRUE;
}

wtap_open_return_val pgp_open(wtap *wth, int *err, gchar **err_info)
{
	guint8 packet_tag;
    int bytes_read;

	bytes_read = file_read(&packet_tag, 1, wth->fh);

	if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(wth->fh, err_info);
        return WTAP_OPEN_ERROR;
    }
    if (bytes_read == 0) {
        return WTAP_OPEN_NOT_MINE;
    }

    if (!valid_packet_tag(packet_tag)) {
		return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PGP;
    wth->file_encap = WTAP_ENCAP_PGP;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;
    wth->snapshot_length = 0;

	return WTAP_OPEN_MINE;
}
