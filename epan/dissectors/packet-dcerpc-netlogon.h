/* packet-dcerpc-netlogon.h
 * Routines for SMB \PIPE\NETLOGON packet disassembly
 * Copyright 2001,2003 Tim Potter <tpot@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DCERPC_NETLOGON_H
#define __PACKET_DCERPC_NETLOGON_H

#define NETLOGON_NETRLOGONUASLOGON			0x00
#define NETLOGON_NETRLOGONUASLOGOFF			0x01
#define NETLOGON_NETRLOGONSAMLOGON			0x02
#define NETLOGON_NETRLOGONSAMLOGOFF			0x03
#define NETLOGON_NETRSERVERREQCHALLENGE			0x04
#define NETLOGON_NETRSERVERAUTHENTICATE			0x05
#define NETLOGON_NETRSERVERPASSWORDSET			0x06
#define NETLOGON_NETRDATABASEDELTAS			0x07
#define NETLOGON_NETRDATABASESYNC			0x08
#define NETLOGON_NETRACCOUNTDELTAS			0x09
#define NETLOGON_NETRACCOUNTSYNC			0x0a
#define NETLOGON_NETRGETDCNAME				0x0b
#define NETLOGON_NETRLOGONCONTROL			0x0c
#define NETLOGON_NETRGETANYDCNAME			0x0d
#define NETLOGON_NETRLOGONCONTROL2			0x0e
#define NETLOGON_NETRSERVERAUTHENTICATE2		0x0f
#define NETLOGON_NETRDATABASESYNC2			0x10
#define NETLOGON_NETRDATABASEREDO			0x11
#define NETLOGON_NETRLOGONCONTROL2EX			0x12
#define NETLOGON_NETRENUMERATETRUSTEDDOMAINS		0x13
#define NETLOGON_DSRGETDCNAME				0x14
#define NETLOGON_NETRLOGONDUMMYROUTINE1			0x15
#define NETLOGON_NETRLOGONSETSERVICEBITS		0x16
#define NETLOGON_NETRLOGONGETTRUSTRID			0x17
#define NETLOGON_NETRLOGONCOMPUTESERVERDIGEST		0x18
#define NETLOGON_NETRLOGONCOMPUTECLIENTDIGEST		0x19
#define NETLOGON_NETRSERVERAUTHENTICATE3		0x1a
#define NETLOGON_DSRGETDCNAMEX				0x1b
#define NETLOGON_DSRGETSITENAME				0x1c
#define NETLOGON_NETRLOGONGETDOMAININFO			0x1d
#define NETLOGON_NETRSERVERPASSWORDSET2			0x1e
#define NETLOGON_NETRSERVERPASSWORDGET			0x1f
#define NETLOGON_NETRLOGONSENDTOSAM			0x20
#define NETLOGON_DSRADDRESSTOSITENAMESW			0x21
#define NETLOGON_DSRGETDCNAMEEX2			0x22
#define NETLOGON_NETRLOGONGETTIMESERVICEPARENTDOMAIN	0x23
#define NETLOGON_NETRENUMERATETRUSTEDDOMAINSEX		0x24
#define NETLOGON_DSRADDRESSTOSITENAMESEXW		0x25
#define NETLOGON_DSRGETDCSITECOVERAGEW			0x26
#define NETLOGON_NETRLOGONSAMLOGONEX			0x27
#define NETLOGON_DSRENUMERATEDOMAINTRUSTS		0x28
#define NETLOGON_DSRDEREGISTERDNSHOSTRECORDS		0x29
#define NETLOGON_NETRSERVERTRUSTPASSWORDSGET		0x2a
#define NETLOGON_DSRGETFORESTTRUSTINFORMATION		0x2b
#define NETLOGON_NETRGETFORESTTRUSTINFORMATION		0x2c
#define NETLOGON_NETRLOGONSAMLOGONWITHFLAGS		0x2d
#define NETLOGON_NETRSERVERGETTRUSTINFO			0x2e
#define NETLOGON_DSRUPDATEREADONLYSERVERDNSRECORDS	0x30
#define NETLOGON_NETRCHAINSETCLIENTATTRIBUTES		0x36 /* This is documented as 49 (0x31) but it's 54) */
#define NETLOGON_NETRSERVERAUTHENTICATEKERBEROS		0x3B


/* needed to decrypt PAC_LOGON_INFO in kerberos */
int
netlogon_dissect_PAC_LOGON_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep);

/* needed to decrypt PAC_S4U_DELEGATION_INFO in kerberos */
int
netlogon_dissect_PAC_S4U_DELEGATION_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep);

/* needed to decrypt PAC_DEVICE_INFO in kerberos */
int
netlogon_dissect_PAC_DEVICE_INFO(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep);

/* needed to dissect PAC_CLAIMS_INFO in kerberos */
int
netlogon_dissect_CLAIMS_SET_METADATA_BLOB(tvbuff_t *tvb,
                                          int offset,
                                          int length,
                                          packet_info *pinfo,
                                          proto_tree *parent_tree,
                                          int hf_index,
                                          int ett_index,
                                          const char *info_str);

#endif /* packet-dcerpc-netlogon.h */
