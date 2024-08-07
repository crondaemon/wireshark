/* packet-ubertooth.h
 * Headers for Ubertooth USB dissection
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_UBERTOOTH_H__
#define __PACKET_UBERTOOTH_H__


typedef struct _ubertooth_data_t {
    uint16_t bus_id;
    uint16_t device_address;

    uint32_t     clock_100ns;
    uint8_t      channel;
} ubertooth_data_t;


#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
