/* packet-btl2cap.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTL2CAP_H__
#define __PACKET_BTL2CAP_H__

#define BTL2CAP_PSM_SDP               0x0001
#define BTL2CAP_PSM_RFCOMM            0x0003
#define BTL2CAP_PSM_TCS_BIN           0x0005
#define BTL2CAP_PSM_TCS_BIN_CORDLESS  0x0007
#define BTL2CAP_PSM_BNEP              0x000f
#define BTL2CAP_PSM_HID_CTRL          0x0011
#define BTL2CAP_PSM_HID_INTR          0x0013
#define BTL2CAP_PSM_UPNP              0x0015
#define BTL2CAP_PSM_AVCTP_CTRL        0x0017
#define BTL2CAP_PSM_AVDTP             0x0019
#define BTL2CAP_PSM_AVCTP_BRWS        0x001b
#define BTL2CAP_PSM_UDI_C_PLANE       0x001d
#define BTL2CAP_PSM_ATT               0x001f
#define BTL2CAP_PSM_3DS               0x0021
#define BTL2CAP_PSM_LE_IPSP           0x0023
#define BTL2CAP_PSM_EATT              0x0027

#define BTL2CAP_DYNAMIC_PSM_START   0x1000

#define BTL2CAP_FIXED_CID_NULL      0x0000
#define BTL2CAP_FIXED_CID_SIGNAL    0x0001
#define BTL2CAP_FIXED_CID_CONNLESS  0x0002
#define BTL2CAP_FIXED_CID_AMP_MAN   0x0003
#define BTL2CAP_FIXED_CID_ATT       0x0004
#define BTL2CAP_FIXED_CID_LE_SIGNAL 0x0005
#define BTL2CAP_FIXED_CID_SMP       0x0006
#define BTL2CAP_FIXED_CID_BR_EDR_SM 0x0007
#define BTL2CAP_FIXED_CID_AMP_TEST  0x003F
#define BTL2CAP_FIXED_CID_LAST      0x003F

#define BTL2CAP_UNKNOWN_CID 0xFFFFFFFF

typedef struct _btl2cap_data_t {
    uint32_t  interface_id;
    uint32_t  adapter_id;
    uint32_t *adapter_disconnect_in_frame;
    uint16_t  chandle;  /* only low 12 bits used */
    uint32_t *hci_disconnect_in_frame;
    uint16_t  psm;
    uint32_t *disconnect_in_frame;
    uint16_t  cid;
    uint32_t  local_cid;
    uint32_t  remote_cid;

    bool      is_local_psm; /* otherwise it is PSM in remote device */
    uint32_t  remote_bd_addr_oui;
    uint32_t  remote_bd_addr_id;
} btl2cap_data_t;

extern int proto_btl2cap;

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
