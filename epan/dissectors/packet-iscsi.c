/* TODO for the cases where one just can not autodetect whether header digest
   is used or not we might need a new preference
   HeaderDigest :
       Automatic (default)
       None
       CRC32
*/

/* packet-iscsi.c
 * Routines for iSCSI dissection
 * Copyright 2001, Eurologic and Mark Burton <markb@ordern.com>
 *  2004 Request/Response matching and Service Response Time: ronnie sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include "packet-scsi.h"
#include "packet-ppp.h"
#include <epan/crc32-tvb.h>
#include <wsutil/crc32.h>
#include <wsutil/inet_addr.h>
#include <wsutil/strtoi.h>
#include <wsutil/array.h>
#include <wsutil/ws_roundup.h>

void proto_register_iscsi(void);
void proto_reg_handoff_iscsi(void);

/* the absolute values of these constants don't matter as long as
 * latter revisions of the protocol are assigned a larger number */
#define ISCSI_PROTOCOL_DRAFT08 1
#define ISCSI_PROTOCOL_DRAFT09 2
#define ISCSI_PROTOCOL_DRAFT11 3
#define ISCSI_PROTOCOL_DRAFT12 4
#define ISCSI_PROTOCOL_DRAFT13 5

static const enum_val_t iscsi_protocol_versions[] = {
    { "draft-08", "Draft 08", ISCSI_PROTOCOL_DRAFT08 },
    { "draft-09", "Draft 09", ISCSI_PROTOCOL_DRAFT09 },
    { "draft-11", "Draft 11", ISCSI_PROTOCOL_DRAFT11 },
    { "draft-12", "Draft 12", ISCSI_PROTOCOL_DRAFT12 },
    { "draft-13", "Draft 13", ISCSI_PROTOCOL_DRAFT13 },
    { NULL, NULL, 0 }
};

static const value_string ahs_type_vals[] = {
    {1, "Extended CDB"},
    {2, "Expected Bidirection Read Data Length"},
    {0, NULL}
};

static dissector_handle_t iscsi_handle;

static int iscsi_protocol_version = ISCSI_PROTOCOL_DRAFT13;

static bool iscsi_desegment = true;

static bool demand_good_f_bit;
static bool enable_bogosity_filter = true;
static uint32_t bogus_pdu_data_length_threshold = 256 * 1024;

#define TCP_PORT_ISCSI_RANGE    "3260"

static range_t *global_iscsi_port_range;
static unsigned iscsi_system_port = 860;

/* Initialize the protocol and registered fields */
static int proto_iscsi;
static int hf_iscsi_time;
static int hf_iscsi_r2t_time;
static int hf_iscsi_request_frame;
static int hf_iscsi_r2t_frame;
static int hf_iscsi_data_in_frame;
static int hf_iscsi_data_out_frame;
static int hf_iscsi_response_frame;
static int hf_iscsi_AHS_length;
static int hf_iscsi_AHS_type;
static int hf_iscsi_AHS_blob;
static int hf_iscsi_AHS_read_data_length;
static int hf_iscsi_AHS_extended_cdb;
static int hf_iscsi_Padding;
static int hf_iscsi_ping_data;
static int hf_iscsi_immediate_data;
static int hf_iscsi_async_event_data;
static int hf_iscsi_vendor_specific_data;
static int hf_iscsi_Opcode;
static int hf_iscsi_Flags;
static int hf_iscsi_HeaderDigest32;
static int hf_iscsi_DataDigest32;
/* #ifdef DRAFT08 */
static int hf_iscsi_X;
/* #endif */
static int hf_iscsi_I;
static int hf_iscsi_SCSICommand_F;
static int hf_iscsi_SCSICommand_R;
static int hf_iscsi_SCSICommand_W;
static int hf_iscsi_SCSICommand_Attr;
static int hf_iscsi_SCSICommand_CRN;
static int hf_iscsi_DataSegmentLength;
static int hf_iscsi_TotalAHSLength;
static int hf_iscsi_InitiatorTaskTag;
static int hf_iscsi_ExpectedDataTransferLength;
static int hf_iscsi_CmdSN;
static int hf_iscsi_ExpStatSN;
static int hf_iscsi_StatSN;
static int hf_iscsi_ExpCmdSN;
static int hf_iscsi_MaxCmdSN;
static int hf_iscsi_SCSIResponse_o;
static int hf_iscsi_SCSIResponse_u;
static int hf_iscsi_SCSIResponse_O;
static int hf_iscsi_SCSIResponse_U;
static int hf_iscsi_SCSIResponse_BidiReadResidualCount;
static int hf_iscsi_SCSIResponse_ResidualCount;
static int hf_iscsi_SCSIResponse_Response;
static int hf_iscsi_SCSIResponse_Status;
static int hf_iscsi_SenseLength;
static int hf_iscsi_SCSIData_F;
static int hf_iscsi_SCSIData_A;
static int hf_iscsi_SCSIData_S;
static int hf_iscsi_SCSIData_O;
static int hf_iscsi_SCSIData_U;
static int hf_iscsi_TargetTransferTag;
static int hf_iscsi_DataSN;
static int hf_iscsi_BufferOffset;
static int hf_iscsi_SCSIData_ResidualCount;
static int hf_iscsi_VersionMin;
static int hf_iscsi_VersionMax;
static int hf_iscsi_VersionActive;
static int hf_iscsi_CID;
static int hf_iscsi_ISID8;
static int hf_iscsi_ISID;
/* #if defined(DRAFT09) */
static int hf_iscsi_ISID_Type;
static int hf_iscsi_ISID_NamingAuthority;
static int hf_iscsi_ISID_Qualifier;
/* #elif !defined(DRAFT08) */
static int hf_iscsi_ISID_t;
static int hf_iscsi_ISID_a;
static int hf_iscsi_ISID_b;
static int hf_iscsi_ISID_c;
static int hf_iscsi_ISID_d;
/* #endif */
static int hf_iscsi_TSID;
static int hf_iscsi_TSIH;
/* #ifdef DRAFT09 */
static int hf_iscsi_Login_X;
/* #endif */
static int hf_iscsi_Login_C;
static int hf_iscsi_Login_T;
static int hf_iscsi_Login_CSG;
static int hf_iscsi_Login_NSG;
static int hf_iscsi_Login_Status;
static int hf_iscsi_Login_SendTargets;
static int hf_iscsi_Login_Chap_A;
static int hf_iscsi_Login_Chap_C;
static int hf_iscsi_Login_Chap_I;
static int hf_iscsi_Login_Chap_N;
static int hf_iscsi_Login_Chap_R;
static int hf_iscsi_Login_SessionType;
static int hf_iscsi_Login_AuthMethod;
static int hf_iscsi_Login_InitiatorName;
static int hf_iscsi_Login_TargetName;
static int hf_iscsi_Login_TargetAddress;
static int hf_iscsi_Login_TargetAlias;
static int hf_iscsi_Login_TargetPortalGroupTag;
static int hf_iscsi_Login_HeaderDigest;
static int hf_iscsi_Login_DataDigest;
static int hf_iscsi_Login_InitialR2T;
static int hf_iscsi_Login_ImmediateData;
static int hf_iscsi_Login_IFMarker;
static int hf_iscsi_Login_OFMarker;
static int hf_iscsi_Login_DataPDUInOrder;
static int hf_iscsi_Login_DataSequenceInOrder;
static int hf_iscsi_Login_MaxBurstLength;
static int hf_iscsi_Login_FirstBurstLength;
static int hf_iscsi_Login_DefaultTime2Wait;
static int hf_iscsi_Login_DefaultTime2Retain;
static int hf_iscsi_Login_MaxOutstandingR2T;
static int hf_iscsi_Login_ErrorRecoveryLevel;
static int hf_iscsi_Login_MaxConnections;
static int hf_iscsi_Login_MaxRecvDataSegmentLength;
static int hf_iscsi_KeyValue;
static int hf_iscsi_Text_C;
static int hf_iscsi_Text_F;
static int hf_iscsi_ExpDataSN;
static int hf_iscsi_R2TSN;
static int hf_iscsi_TaskManagementFunction_ReferencedTaskTag;
static int hf_iscsi_RefCmdSN;
static int hf_iscsi_TaskManagementFunction_Function;
static int hf_iscsi_TaskManagementFunction_Response;
static int hf_iscsi_Logout_Reason;
static int hf_iscsi_Logout_Response;
static int hf_iscsi_Time2Wait;
static int hf_iscsi_Time2Retain;
static int hf_iscsi_DesiredDataLength;
static int hf_iscsi_AsyncEvent;
static int hf_iscsi_EventVendorCode;
static int hf_iscsi_Parameter1;
static int hf_iscsi_Parameter2;
static int hf_iscsi_Parameter3;
static int hf_iscsi_Reject_Reason;
static int hf_iscsi_snack_type;
static int hf_iscsi_BegRun;
static int hf_iscsi_RunLength;

/* Initialize the subtree pointers */
static int ett_iscsi;
static int ett_iscsi_KeyValue;
static int ett_iscsi_KeyValues;
static int ett_iscsi_CDB;
static int ett_iscsi_Flags;
static int ett_iscsi_RejectHeader;
static int ett_iscsi_lun;
/* #ifndef DRAFT08 */
static int ett_iscsi_ISID;
/* #endif */

static expert_field ei_iscsi_keyvalue_invalid;
static expert_field ei_iscsi_opcode_invalid;

enum iscsi_digest {
    ISCSI_DIGEST_AUTO,
    ISCSI_DIGEST_NONE,
    ISCSI_DIGEST_CRC32
};
/* this structure contains session wide state for a specific tcp conversation */
typedef struct _iscsi_session_t {
    enum iscsi_digest header_digest;
    enum iscsi_digest data_digest;
    wmem_tree_t *itlq;  /* indexed by ITT */
    wmem_map_t *itl;   /* indexed by LUN */
} iscsi_session_t;



/* #ifdef DRAFT08 */
#define X_BIT 0x80
/* #endif */

#define I_BIT 0x40

#define OPCODE_MASK 0x3f

#define TARGET_OPCODE_BIT 0x20

#define ISCSI_OPCODE_NOP_OUT                  0x00
#define ISCSI_OPCODE_SCSI_COMMAND             0x01
#define ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION 0x02
#define ISCSI_OPCODE_LOGIN_COMMAND            0x03
#define ISCSI_OPCODE_TEXT_COMMAND             0x04
#define ISCSI_OPCODE_SCSI_DATA_OUT            0x05
#define ISCSI_OPCODE_LOGOUT_COMMAND           0x06
#define ISCSI_OPCODE_SNACK_REQUEST            0x10
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I0       0x1c
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I1       0x1d
#define ISCSI_OPCODE_VENDOR_SPECIFIC_I2       0x1e

#define ISCSI_OPCODE_NOP_IN                            0x20
#define ISCSI_OPCODE_SCSI_RESPONSE                     0x21
#define ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE 0x22
#define ISCSI_OPCODE_LOGIN_RESPONSE                    0x23
#define ISCSI_OPCODE_TEXT_RESPONSE                     0x24
#define ISCSI_OPCODE_SCSI_DATA_IN                      0x25
#define ISCSI_OPCODE_LOGOUT_RESPONSE                   0x26
#define ISCSI_OPCODE_R2T                               0x31
#define ISCSI_OPCODE_ASYNC_MESSAGE                     0x32
#define ISCSI_OPCODE_REJECT                            0x3f
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T0                0x3c
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T1                0x3d
#define ISCSI_OPCODE_VENDOR_SPECIFIC_T2                0x3e

#define CSG_SHIFT 2
#define CSG_MASK  (0x03 << CSG_SHIFT)
#define NSG_MASK  0x03

#define ISCSI_CSG_SECURITY_NEGOTIATION    (0 << CSG_SHIFT)
#define ISCSI_CSG_OPERATIONAL_NEGOTIATION (1 << CSG_SHIFT)
#define ISCSI_CSG_FULL_FEATURE_PHASE      (3 << CSG_SHIFT)

#define ISCSI_SCSI_DATA_FLAG_S 0x01
#define ISCSI_SCSI_DATA_FLAG_U 0x02
#define ISCSI_SCSI_DATA_FLAG_O 0x04
#define ISCSI_SCSI_DATA_FLAG_A 0x40
#define ISCSI_SCSI_DATA_FLAG_F 0x80

static const value_string iscsi_opcodes[] = {
  { ISCSI_OPCODE_NOP_OUT,                           "NOP Out" },
  { ISCSI_OPCODE_SCSI_COMMAND,                      "SCSI Command" },
  { ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION,          "Task Management Function" },
  { ISCSI_OPCODE_LOGIN_COMMAND,                     "Login Command" },
  { ISCSI_OPCODE_TEXT_COMMAND,                      "Text Command" },
  { ISCSI_OPCODE_SCSI_DATA_OUT,                     "SCSI Data Out" },
  { ISCSI_OPCODE_LOGOUT_COMMAND,                    "Logout Command" },
  { ISCSI_OPCODE_SNACK_REQUEST,                     "SNACK Request" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I0,                "Vendor Specific I0" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I1,                "Vendor Specific I1" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_I2,                "Vendor Specific I2" },

  { ISCSI_OPCODE_NOP_IN,                            "NOP In" },
  { ISCSI_OPCODE_SCSI_RESPONSE,                     "SCSI Response" },
  { ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE, "Task Management Function Response" },
  { ISCSI_OPCODE_LOGIN_RESPONSE,                    "Login Response" },
  { ISCSI_OPCODE_TEXT_RESPONSE,                     "Text Response" },
  { ISCSI_OPCODE_SCSI_DATA_IN,                      "SCSI Data In" },
  { ISCSI_OPCODE_LOGOUT_RESPONSE,                   "Logout Response" },
  { ISCSI_OPCODE_R2T,                               "Ready To Transfer" },
  { ISCSI_OPCODE_ASYNC_MESSAGE,                     "Asynchronous Message" },
  { ISCSI_OPCODE_REJECT,                            "Reject"},
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T0,                "Vendor Specific T0" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T1,                "Vendor Specific T1" },
  { ISCSI_OPCODE_VENDOR_SPECIFIC_T2,                "Vendor Specific T2" },
  {0, NULL},
};

static const value_string error_recovery_level_vals[] = {
  { 0,                           "Session recovery class" },
  { 1,                           "Digest failure recovery" },
  { 2,                           "Connection recovery class" },
  {0, NULL},
};

/* #ifdef DRAFT08 */
static const true_false_string iscsi_meaning_X = {
    "Retry",
    "Not retry"
};
/* #endif */

/* #ifdef DRAFT09 */
static const true_false_string iscsi_meaning_login_X = {
    "Reinstate failed connection",
    "New connection"
};
/* #endif */

static const true_false_string iscsi_meaning_I = {
    "Immediate delivery",
    "Queued delivery"
};

static const true_false_string iscsi_meaning_F = {
    "Final PDU in sequence",
    "Not final PDU in sequence"
};

static const true_false_string iscsi_meaning_A = {
    "Acknowledge requested",
    "Acknowledge not requested"
};

static const true_false_string iscsi_meaning_T = {
    "Transit to next login stage",
    "Stay in current login stage"
};

static const true_false_string iscsi_meaning_C = {
    "Text is incomplete",
    "Text is complete"
};

static const true_false_string iscsi_meaning_S = {
    "Response contains SCSI status",
    "Response does not contain SCSI status"
};

static const true_false_string iscsi_meaning_R = {
    "Data will be read from target",
    "No data will be read from target"
};

static const true_false_string iscsi_meaning_W = {
    "Data will be written to target",
    "No data will be written to target"
};

static const true_false_string iscsi_meaning_o = {
    "Read part of bi-directional command overflowed",
    "No overflow of read part of bi-directional command",
};

static const true_false_string iscsi_meaning_u = {
    "Read part of bi-directional command underflowed",
    "No underflow of read part of bi-directional command",
};

static const true_false_string iscsi_meaning_O = {
    "Residual overflow occurred",
    "No residual overflow occurred",
};

static const true_false_string iscsi_meaning_U = {
    "Residual underflow occurred",
    "No residual underflow occurred",
};

static const value_string iscsi_scsi_responses[] = {
    { 0, "Command completed at target" },
    { 1, "Response does not contain SCSI status"},
    { 0, NULL }
};

static const value_string iscsi_scsicommand_taskattrs[] = {
    {0, "Untagged"},
    {1, "Simple"},
    {2, "Ordered"},
    {3, "Head of Queue"},
    {4, "ACA"},
    {0, NULL},
};

static const value_string iscsi_task_management_responses[] = {
    {0, "Function complete"},
    {1, "Task not in task set"},
    {2, "LUN does not exist"},
    {3, "Task still allegiant"},
    {4, "Task failover not supported"},
    {5, "Task management function not supported"},
    {6, "Authorisation failed"},
    {255, "Function rejected"},
    {0, NULL},
};

static const value_string iscsi_task_management_functions[] = {
    {1, "Abort Task"},
    {2, "Abort Task Set"},
    {3, "Clear ACA"},
    {4, "Clear Task Set"},
    {5, "Logical Unit Reset"},
    {6, "Target Warm Reset"},
    {7, "Target Cold Reset"},
    {8, "Target Reassign"},
    {0, NULL},
};

static const value_string iscsi_login_status[] = {
    {0x0000, "Success"},
    {0x0101, "Target moved temporarily"},
    {0x0102, "Target moved permanently"},
    {0x0200, "Initiator error (miscellaneous error)"},
    {0x0201, "Authentication failed"},
    {0x0202, "Authorisation failure"},
    {0x0203, "Target not found"},
    {0x0204, "Target removed"},
    {0x0205, "Unsupported version"},
    {0x0206, "Too many connections"},
    {0x0207, "Missing parameter"},
    {0x0208, "Can't include in session"},
    {0x0209, "Session type not supported"},
    {0x020a, "Session does not exist"},
    {0x020b, "Invalid request during login"},
    {0x0300, "Target error (miscellaneous error)"},
    {0x0301, "Service unavailable"},
    {0x0302, "Out of resources"},
    {0, NULL},
};

static const value_string iscsi_login_stage[] = {
    {0, "Security negotiation"},
    {1, "Operational negotiation"},
    {3, "Full feature phase"},
    {0, NULL},
};

/* #ifndef DRAFT08 */
static const value_string iscsi_isid_type[] = {
    {0x00, "IEEE OUI"},
    {0x01, "IANA Enterprise Number"},
    {0x02, "Random"},
    {0, NULL},
};
/* #endif */

static const value_string iscsi_logout_reasons[] = {
    {0, "Close session"},
    {1, "Close connection"},
    {2, "Remove connection for recovery"},
    {0, NULL},
};

static const value_string iscsi_logout_response[] = {
    {0, "Connection closed successfully"},
    {1, "CID not found"},
    {2, "Connection recovery not supported"},
    {3, "Cleanup failed for various reasons"},
    {0, NULL},
};

static const value_string iscsi_asyncevents[] = {
    {0, "A SCSI asynchronous event is reported in the sense data"},
    {1, "Target requests logout"},
    {2, "Target will/has dropped connection"},
    {3, "Target will/has dropped all connections"},
    {4, "Target requests parameter negotiation"},
    {0, NULL},
};

static const value_string iscsi_snack_types[] = {
    {0, "Data/R2T"},
    {1, "Status"},
/* #ifndef DRAFT08 */
    {2, "Data ACK"},
/* #endif */
    {3, "R-Data"},
    {0, NULL}
};

static const value_string iscsi_reject_reasons[] = {
/* #ifdef DRAFT08 */
    {0x01, "Full feature phase command before login"},
/* #endif */
    {0x02, "Data (payload) digest error"},
    {0x03, "Data SNACK reject"},
    {0x04, "Protocol error"},
    {0x05, "Command not supported in this session type"},
    {0x06, "Immediate command reject (too many immediate commands)"},
    {0x07, "Task in progress"},
    {0x08, "Invalid Data Ack"},
    {0x09, "Invalid PDU field"},
    {0x0a, "Long operation reject"},
    {0x0b, "Negotiation reset"},
    {0x0c, "Waiting for logout"},
    {0, NULL},
};

/* structure and functions to keep track of
 * COMMAND/DATA_IN/DATA_OUT/RESPONSE matching
 */
typedef struct _iscsi_conv_data {
    uint32_t data_in_frame;
    uint32_t data_out_frame;
    uint32_t r2t_frame;
    uint32_t itt;
    itlq_nexus_t itlq;
} iscsi_conv_data_t;

/* TargetAddress describes a iscsi port, possibly using a non-standard port
   so we can use this to set up a conversation dissector to that port.

   TargetAddress is of the form :
   TargetAddress=domainname[:port][,portal-group-tag]

   where domainname is either a dns-name, an ipv4 address is dotted-decimal
   form or a bracketed ipv6 address.
   so treat this as signalling, parse the value and register iscis as a conversation
   dissector for the address/port that TargetAddress points to.
   (it starts to be common to use redirectors to point to non-3260 ports)
*/
static address null_address = ADDRESS_INIT_NONE;

static void
iscsi_dissect_TargetAddress(packet_info *pinfo, tvbuff_t* tvb, proto_tree *tree, unsigned offset)
{
    address addr = ADDRESS_INIT_NONE;
    uint16_t port;
    int colon_offset;
    int end_offset;
    char *ip_str, *port_str;

    colon_offset = tvb_find_uint8(tvb, offset, -1, ':');
    if (colon_offset == -1) {
        /* RFC 7143 13.8 TargetAddress "If the TCP port is not specified,
         * it is assumed to be the IANA-assigned default port for iSCSI",
         * so nothing to do here.
         */
        return;
    }

    /* We found a colon, so there's at least one byte and this won't fail. */
    if (tvb_get_uint8(tvb, offset) == '[') {
        offset++;
        /* could be an ipv6 address */
        end_offset = tvb_find_uint8(tvb, offset, -1, ']');
        if (end_offset == -1) {
            return;
        }

        /* look for the colon before the port, if any */
        colon_offset = tvb_find_uint8(tvb, end_offset, -1, ':');
        if (colon_offset == -1) {
            return;
        }

        ws_in6_addr *ip6_addr = wmem_new(pinfo->pool, ws_in6_addr);
        ip_str = tvb_get_string_enc(pinfo->pool, tvb, offset, end_offset - offset, ENC_ASCII);
        if (ws_inet_pton6(ip_str, ip6_addr)) {
            /* looks like a ipv6 address */
            set_address(&addr, AT_IPv6, sizeof(ws_in6_addr), ip6_addr);
        }

    } else {
        /* This is either a ipv4 address or a dns name */
        ip_str = tvb_get_string_enc(pinfo->pool, tvb, offset, colon_offset - offset, ENC_ASCII);
        ws_in4_addr *ip4_addr = wmem_new(pinfo->pool, ws_in4_addr);
        if (ws_inet_pton4(ip_str, ip4_addr)) {
            /* looks like a ipv4 address */
            set_address(&addr, AT_IPv4, 4, ip4_addr);
        }
        /* else a DNS host name; we could, theoretically, try to use
         * name resolution information in the capture to lookup the address.
         */
    }

    /* Extract the port */
    end_offset = tvb_find_uint8(tvb, colon_offset, -1, ',');
    int port_len;
    if (end_offset == -1) {
        port_len = tvb_reported_length_remaining(tvb, colon_offset + 1);
    } else {
        port_len = end_offset - (colon_offset + 1);
    }
    port_str = tvb_get_string_enc(pinfo->pool, tvb, colon_offset + 1, port_len, ENC_ASCII);
    if (!ws_strtou16(port_str, NULL, &port)) {
        proto_tree_add_expert_format(tree, pinfo, &ei_iscsi_keyvalue_invalid,
            tvb, colon_offset + 1, port_len, "Invalid port: %s", port_str);
        return;
    }

    /* attach a conversation dissector to this address/port tuple */
    if (!addresses_equal(&addr, &null_address) && !pinfo->fd->visited) {
        conversation_t *conv;

        conv = conversation_new(pinfo->num, &addr, &null_address, CONVERSATION_TCP, port, 0, NO_ADDR2|NO_PORT2);
        if (conv == NULL) {
            return;
        }
        conversation_set_dissector(conv, iscsi_handle);
    }

}

static int
addTextKeys(packet_info *pinfo, proto_tree *tt, tvbuff_t *tvb, int offset, uint32_t text_len) {
    const int limit = offset + text_len;
    tvbuff_t *keyvalue_tvb;
    int len, value_offset;
    const char *value;

    while(offset < limit) {
        /* RFC 7143 6.1 Text Format: "Every key=value pair, including the
         * last or only pair in a LTDS, MUST be followed by one null (0x00)
         * delimiter.
         */
        len = tvb_strnlen(tvb, offset, -1) + 1; /* +1 to include the '\0' */
        keyvalue_tvb = tvb_new_subset_length(tvb, offset, len);
        value_offset = tvb_find_uint8(keyvalue_tvb, 0, len, '=');

        if (value_offset == -1) {
            break;
        }
        value_offset++;
        value = tvb_get_string_enc(pinfo->pool, keyvalue_tvb, value_offset, len - value_offset, ENC_ASCII);

        if (tvb_strneql(keyvalue_tvb, 0, "AuthMethod=", strlen("AuthMethod=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_AuthMethod, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "CHAP_A=", strlen("CHAP_A=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_Chap_A, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "CHAP_C=", strlen("CHAP_C=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_Chap_C, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "CHAP_I=", strlen("CHAP_I=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_Chap_I, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "CHAP_N=", strlen("CHAP_N=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_Chap_N, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "CHAP_R=", strlen("CHAP_R=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_Chap_R, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "DataDigest=", strlen("DataDigest=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_DataDigest, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "DataPDUInOrder=", strlen("DataPDUInOrder=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_DataPDUInOrder, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "DataSequenceInOrder=", strlen("DataSequenceInOrder=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_DataSequenceInOrder, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "DefaultTime2Retain=", strlen("DefaultTime2Retain=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_DefaultTime2Retain, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "DefaultTime2Wait=", strlen("DefaultTime2Wait=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_DefaultTime2Wait, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "ErrorRecoveryLevel=", strlen("ErrorRecoveryLevel=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_ErrorRecoveryLevel, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "FirstBurstLength=", strlen("FirstBurstLength=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_FirstBurstLength, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "HeaderDigest=", strlen("HeaderDigest=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_HeaderDigest, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "IFMarker=", strlen("IFMarker=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_IFMarker, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "ImmediateData=", strlen("ImmediateData=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_ImmediateData, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "InitialR2T=", strlen("InitialR2T=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_InitialR2T, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "InitiatorName=", strlen("InitiatorName=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_InitiatorName, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "MaxBurstLength=", strlen("MaxBurstLength=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_MaxBurstLength, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "MaxConnections=", strlen("MaxConnections=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_MaxConnections, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "MaxOutstandingR2T=", strlen("MaxOutstandingR2T=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_MaxOutstandingR2T, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "MaxRecvDataSegmentLength=", strlen("MaxRecvDataSegmentLength=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_MaxRecvDataSegmentLength, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else if (tvb_strneql(keyvalue_tvb, 0, "OFMarker=", strlen("IFMarker=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_OFMarker, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "SendTargets=", strlen("SendTargets=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_SendTargets, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "SessionType=", strlen("SessionType=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_SessionType, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "TargetAddress=", strlen("TargetAddress=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_TargetAddress, keyvalue_tvb, 0, len, value);
            iscsi_dissect_TargetAddress(pinfo, keyvalue_tvb, tt, value_offset);
        } else if (tvb_strneql(keyvalue_tvb, 0, "TargetAlias=", strlen("TargetAlias=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_TargetAlias, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "TargetName=", strlen("TargetName=")) == 0) {
            proto_tree_add_string(tt, hf_iscsi_Login_TargetName, keyvalue_tvb, 0, len, value);
        } else if (tvb_strneql(keyvalue_tvb, 0, "TargetPortalGroupTag=", strlen("TargetPortalGroupTag=")) == 0) {
            proto_tree_add_uint(tt, hf_iscsi_Login_TargetPortalGroupTag, keyvalue_tvb, 0, len,
                                (int)strtol(value, NULL, 0));
        } else {
            proto_tree_add_item(tt, hf_iscsi_KeyValue, keyvalue_tvb, 0, len, ENC_ASCII);
        }

        offset += len;
    }
    return offset;
}

static int
handleHeaderDigest(iscsi_session_t *iscsi_session, proto_item *ti, tvbuff_t *tvb, unsigned offset, int headerLen) {
    int available_bytes = tvb_captured_length_remaining(tvb, offset);

    switch(iscsi_session->header_digest){
    case ISCSI_DIGEST_CRC32:
        if(available_bytes >= (headerLen + 4)) {
            uint32_t crc = ~crc32c_tvb_offset_calculate(tvb, offset, headerLen, CRC32C_PRELOAD);
            uint32_t sent = tvb_get_ntohl(tvb, offset + headerLen);
            if(crc == sent) {
                proto_tree_add_uint_format_value(ti, hf_iscsi_HeaderDigest32, tvb, offset + headerLen, 4, sent, "0x%08x (Good CRC32)", sent);
            } else {
                proto_tree_add_uint_format_value(ti, hf_iscsi_HeaderDigest32, tvb, offset + headerLen, 4, sent, "0x%08x (Bad CRC32, should be 0x%08x)", sent, crc);
            }
        }
        return offset + headerLen + 4;
    default:
        break;
    }
    return offset + headerLen;
}

static int
handleDataDigest(iscsi_session_t *iscsi_session, proto_item *ti, tvbuff_t *tvb, unsigned offset, int dataLen) {
    int available_bytes = tvb_captured_length_remaining(tvb, offset);

    if (dataLen > 0) {
        switch (iscsi_session->data_digest){
        case ISCSI_DIGEST_CRC32:
            if(available_bytes >= (dataLen + 4)) {
                uint32_t crc = ~crc32c_tvb_offset_calculate(tvb, offset, dataLen, CRC32C_PRELOAD);
                uint32_t sent = tvb_get_ntohl(tvb, offset + dataLen);
                if(crc == sent) {
                    proto_tree_add_uint_format_value(ti, hf_iscsi_DataDigest32, tvb, offset + dataLen, 4, sent, "0x%08x (Good CRC32)", sent);
                }
                else {
                    proto_tree_add_uint_format_value(ti, hf_iscsi_DataDigest32, tvb, offset + dataLen, 4, sent, "0x%08x (Bad CRC32, should be 0x%08x)", sent, crc);
                }
            }
            return offset + dataLen + 4;
        default:
            break;
        }
    }
    return offset + dataLen;
}

static int
handleDataSegment(iscsi_session_t *iscsi_session, proto_item *ti, tvbuff_t *tvb, unsigned offset, unsigned dataSegmentLen, unsigned endOffset, int hf_id) {
    if(endOffset > offset) {
        int dataOffset = offset;
        int dataLen = MIN(dataSegmentLen, endOffset - offset);
        if(dataLen > 0) {
            proto_tree_add_item(ti, hf_id, tvb, offset, dataLen, ENC_NA);
            offset += dataLen;
        }
        if(offset < endOffset && (offset & 3) != 0) {
            int padding = 4 - (offset & 3);
            proto_tree_add_item(ti, hf_iscsi_Padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
        if(dataSegmentLen > 0 && offset < endOffset)
            offset = handleDataDigest(iscsi_session, ti, tvb, dataOffset, offset - dataOffset);
    }

    return offset;
}

static int
handleDataSegmentAsTextKeys(iscsi_session_t *iscsi_session, packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, unsigned offset, unsigned dataSegmentLen, unsigned endOffset, int digestsActive) {
    if(endOffset > offset) {
        int dataOffset = offset;
        int textLen = MIN(dataSegmentLen, endOffset - offset);
        if(textLen > 0) {
            proto_tree *tt = proto_tree_add_subtree(ti, tvb, offset, textLen,
                                          ett_iscsi_KeyValues, NULL, "Key/Value Pairs");
            offset = addTextKeys(pinfo, tt, tvb, offset, textLen);
        }
        if(offset < endOffset && (offset & 3) != 0) {
            int padding = 4 - (offset & 3);
            proto_tree_add_item(ti, hf_iscsi_Padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
        if(digestsActive && dataSegmentLen > 0 && offset < endOffset)
            offset = handleDataDigest(iscsi_session, ti, tvb, dataOffset, offset - dataOffset);
    }
    return offset;
}

/* Code to actually dissect the packets */
static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_iscsi_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint8_t opcode, uint32_t data_segment_len, iscsi_session_t *iscsi_session, conversation_t *conversation) {

    unsigned original_offset = offset;
    proto_tree *ti = NULL, *opcode_item = NULL, *itm = NULL;
    uint8_t scsi_status = 0;
    bool S_bit=false;
    bool A_bit=false;
    unsigned cdb_offset = offset + 32; /* offset of CDB from start of PDU */
    unsigned end_offset = offset + tvb_captured_length_remaining(tvb, offset);
    iscsi_conv_data_t *cdata = NULL;
    int paddedDataSegmentLength = data_segment_len;
    uint16_t lun=0xffff;
    unsigned immediate_data_length=0;
    unsigned immediate_data_offset=0;
    itl_nexus_t *itl=NULL;
    unsigned ahs_cdb_length=0;
    unsigned ahs_cdb_offset=0;
    uint32_t data_offset=0;
    wmem_tree_key_t key[3];
    uint32_t itt;
    const char* opcode_str = val_to_str_const(opcode, iscsi_opcodes, "Unknown");

    if(paddedDataSegmentLength & 3)
        paddedDataSegmentLength += 4 - (paddedDataSegmentLength & 3);
    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "iSCSI");

    itt = tvb_get_ntohl(tvb, offset+16);
    key[0].length = 1;
    key[0].key = &itt;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (opcode == ISCSI_OPCODE_SCSI_COMMAND) {
            cdata = wmem_new(wmem_file_scope(), iscsi_conv_data_t);
            cdata->itlq.lun = 0xffff;
            cdata->itlq.scsi_opcode = 0xffff;
            cdata->itlq.task_flags = 0;
            cdata->itlq.data_length = 0;
            cdata->itlq.bidir_data_length = 0;
            cdata->itlq.fc_time = pinfo->abs_ts;
            cdata->itlq.r2t_time = pinfo->abs_ts;
            cdata->itlq.first_exchange_frame = 0;
            cdata->itlq.last_exchange_frame = 0;
            cdata->itlq.flags = 0;
            cdata->itlq.alloc_len = 0;
            cdata->itlq.extra_data = NULL;
            cdata->r2t_frame = 0;
            cdata->data_in_frame = 0;
            cdata->data_out_frame = 0;
            cdata->itt = itt;
            wmem_tree_insert32_array(iscsi_session->itlq, key, (void *)cdata);
        } else {
            cdata = (iscsi_conv_data_t *)wmem_tree_lookup32_array_le(iscsi_session->itlq, key);
            if (cdata && (cdata->itt != itt)) {
                cdata = NULL;
            }
        }
    } else {
        cdata = (iscsi_conv_data_t *)wmem_tree_lookup32_array_le(iscsi_session->itlq, key);
        if (cdata && (cdata->itt != itt)) {
            cdata = NULL;
        }
    }

    if(!cdata) {
        /* Create a fake temporary structure */
        cdata = wmem_new(pinfo->pool, iscsi_conv_data_t);
        cdata->itlq.lun = 0xffff;
        cdata->itlq.scsi_opcode = 0xffff;
        cdata->itlq.task_flags = 0;
        cdata->itlq.data_length = 0;
        cdata->itlq.bidir_data_length = 0;
        cdata->itlq.fc_time = pinfo->abs_ts;
        cdata->itlq.first_exchange_frame = 0;
        cdata->itlq.last_exchange_frame = 0;
        cdata->itlq.flags = 0;
        cdata->itlq.alloc_len = 0;
        cdata->itlq.extra_data = NULL;
        cdata->data_in_frame = 0;
        cdata->data_out_frame = 0;
        cdata->r2t_frame = 0;
        cdata->itt = itt;
    }

    if (opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
        opcode == ISCSI_OPCODE_SCSI_DATA_IN) {
        scsi_status = tvb_get_uint8 (tvb, offset+3);
    }

    if ((opcode == ISCSI_OPCODE_SCSI_RESPONSE) ||
        (opcode == ISCSI_OPCODE_SCSI_DATA_IN) ||
        (opcode == ISCSI_OPCODE_SCSI_DATA_OUT) ||
        (opcode == ISCSI_OPCODE_R2T)) {
        /* first time we see this packet. check if we can find the request */
        switch(opcode){
        case ISCSI_OPCODE_SCSI_RESPONSE:
            cdata->itlq.last_exchange_frame=pinfo->num;
            break;
        case ISCSI_OPCODE_R2T:
            cdata->r2t_frame=pinfo->num;
            break;
        case ISCSI_OPCODE_SCSI_DATA_IN:
            /* a bit ugly but we need to check the S bit here */
            if(tvb_get_uint8(tvb, offset+1)&ISCSI_SCSI_DATA_FLAG_S){
                cdata->itlq.last_exchange_frame=pinfo->num;
            }
            cdata->data_in_frame=pinfo->num;
            break;
        case ISCSI_OPCODE_SCSI_DATA_OUT:
            cdata->data_out_frame=pinfo->num;
            break;
        }

    } else if (opcode == ISCSI_OPCODE_SCSI_COMMAND) {
        /*we need the LUN value for some of the commands so we can pass it
          across to the SCSI dissector.
          Not correct but simple  and probably accurate enough :
          If bit 6 of first bit is 0   then just take second byte as the LUN
          If bit 6 of first bit is 1, then take 6 bits from first byte
          and all of second byte and pretend it is the lun value
          people that care can add host specific dissection of vsa later.

          We need to keep track of this on a per transaction basis since
          for error recoverylevel 0 and when the A bit is clear in a
          Data-In PDU, there will not be a LUN field in the iscsi layer.
        */
        if(tvb_get_uint8(tvb, offset+8)&0x40){
            /* volume set addressing */
            lun=tvb_get_uint8(tvb,offset+8)&0x3f;
            lun<<=8;
            lun|=tvb_get_uint8(tvb,offset+9);
        } else {
            lun=tvb_get_uint8(tvb,offset+9);
        }

        cdata->itlq.lun=lun;
        cdata->itlq.first_exchange_frame=pinfo->num;

        itl=(itl_nexus_t *)wmem_map_lookup(iscsi_session->itl, GUINT_TO_POINTER((unsigned long)lun));
        if(!itl){
            itl=wmem_new(wmem_file_scope(), itl_nexus_t);
            itl->cmdset=0xff;
            itl->conversation=conversation;
            wmem_map_insert(iscsi_session->itl, GUINT_TO_POINTER((unsigned long)lun), itl);
        }

    }

    if(!itl){
        itl=(itl_nexus_t *)wmem_map_lookup(iscsi_session->itl, GUINT_TO_POINTER((unsigned long)cdata->itlq.lun));
    }



    if (opcode != ISCSI_OPCODE_SCSI_COMMAND) {

        col_append_str(pinfo->cinfo, COL_INFO, opcode_str);

        if (opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
            (opcode == ISCSI_OPCODE_SCSI_DATA_IN &&
                (tvb_get_uint8(tvb, offset + 1) & ISCSI_SCSI_DATA_FLAG_S))) {
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (scsi_status, scsi_status_val, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
            uint16_t login_status = tvb_get_ntohs(tvb, offset+36);
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (login_status, iscsi_login_status, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_LOGOUT_COMMAND) {
            uint8_t logoutReason;
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
                logoutReason = tvb_get_uint8(tvb, offset+11);
            } else if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
                logoutReason = tvb_get_uint8(tvb, offset+1) & 0x7f;
            }
            else {
                logoutReason = tvb_get_uint8(tvb, offset+23);
            }
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (logoutReason, iscsi_logout_reasons, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION) {
            uint8_t tmf = tvb_get_uint8(tvb, offset + 1) & 0x7f;
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (tmf, iscsi_task_management_functions, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE) {
            uint8_t resp = tvb_get_uint8(tvb, offset + 2);
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (resp, iscsi_task_management_responses, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_REJECT) {
            uint8_t reason = tvb_get_uint8(tvb, offset + 2);
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (reason, iscsi_reject_reasons, "0x%x"));
        }
        else if (opcode == ISCSI_OPCODE_ASYNC_MESSAGE) {
            uint8_t asyncEvent = tvb_get_uint8(tvb, offset + 36);
            col_append_fstr (pinfo->cinfo, COL_INFO, " (%s) ",
                                val_to_str (asyncEvent, iscsi_asyncevents, "0x%x"));
        }
    }

    /* In the interest of speed, if "tree" is NULL, don't do any
       work not necessary to generate protocol tree items. */
    if (tree) {
        proto_item *tp;
        /* create display subtree for the protocol */
        tp = proto_tree_add_protocol_format(tree, proto_iscsi, tvb,
                                            offset, -1, "iSCSI (%s) ",
                                            opcode_str);
        ti = proto_item_add_subtree(tp, ett_iscsi);
    }
    opcode_item = proto_tree_add_item(ti, hf_iscsi_Opcode, tvb,
                        offset + 0, 1, ENC_NA);
    if (!try_val_to_str(opcode, iscsi_opcodes)) {
        expert_add_info(pinfo, opcode_item, &ei_iscsi_opcode_invalid);
    }
    if((opcode & TARGET_OPCODE_BIT) == 0) {
        /* initiator -> target */
        int b = tvb_get_uint8(tvb, offset + 0);
        if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
            if(opcode != ISCSI_OPCODE_SCSI_DATA_OUT &&
               opcode != ISCSI_OPCODE_LOGOUT_COMMAND &&
               opcode != ISCSI_OPCODE_SNACK_REQUEST)
                proto_tree_add_boolean(ti, hf_iscsi_X, tvb, offset + 0, 1, b);
        }
        if(opcode != ISCSI_OPCODE_SCSI_DATA_OUT &&
           opcode != ISCSI_OPCODE_LOGIN_COMMAND &&
           opcode != ISCSI_OPCODE_SNACK_REQUEST)
            proto_tree_add_boolean(ti, hf_iscsi_I, tvb, offset + 0, 1, b);
    }

    if(opcode == ISCSI_OPCODE_NOP_OUT) {
        /* NOP Out */
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        offset = handleDataSegment(iscsi_session, ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_ping_data);
    } else if(opcode == ISCSI_OPCODE_NOP_IN) {
        /* NOP In */
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        offset = handleDataSegment(iscsi_session, ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_ping_data);
    } else if(opcode == ISCSI_OPCODE_SCSI_COMMAND) {
        /* SCSI Command */
        uint32_t ahsLen = tvb_get_uint8(tvb, offset + 4) * 4;
        {
            int b = tvb_get_uint8(tvb, offset + 1);
            static int * const flags[] = {
                &hf_iscsi_SCSICommand_F,
                &hf_iscsi_SCSICommand_R,
                &hf_iscsi_SCSICommand_W,
                &hf_iscsi_SCSICommand_Attr,
                NULL
            };

            proto_tree_add_bitmask(tree, tvb, offset + 1, hf_iscsi_Flags, ett_iscsi_Flags, flags, ENC_NA);

            if(b&0x40){
                cdata->itlq.task_flags|=SCSI_DATA_READ;
            }
            if(b&0x20){
                cdata->itlq.task_flags|=SCSI_DATA_WRITE;
            }
        }
        if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
            proto_tree_add_item(ti, hf_iscsi_SCSICommand_CRN, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpectedDataTransferLength, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        cdata->itlq.data_length=tvb_get_ntohl(tvb, offset+20);
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        if(ahsLen > 0) {
            unsigned ahs_offset=offset+48;
            uint16_t ahs_length=0;
            uint8_t ahs_type=0;

            while(ahs_offset<(offset+48+ahsLen)){

                ahs_length=tvb_get_ntohs(tvb, ahs_offset);
                proto_tree_add_item(ti, hf_iscsi_AHS_length, tvb, ahs_offset, 2, ENC_BIG_ENDIAN);
                ahs_offset+=2;

                ahs_type=tvb_get_uint8(tvb, ahs_offset);
                proto_tree_add_item(ti, hf_iscsi_AHS_type, tvb, ahs_offset, 1, ENC_BIG_ENDIAN);
                ahs_offset++;

                switch(ahs_type){
                case 0x01: /* extended CDB */
                    /* additional cdb */
                    ahs_cdb_offset=ahs_offset+1;
                    ahs_cdb_length=ahs_length-1;
                    proto_tree_add_item(ti, hf_iscsi_AHS_extended_cdb, tvb, ahs_cdb_offset, ahs_cdb_length, ENC_NA);
                    ahs_offset+=ahs_length;
                    break;
                case 0x02: /* bidirectional read data length */
                    /* skip reserved byte */
                    ahs_offset++;
                    /* read data length */
                    proto_tree_add_item(ti, hf_iscsi_AHS_read_data_length, tvb, ahs_offset, 4, ENC_BIG_ENDIAN);
                    cdata->itlq.bidir_data_length=tvb_get_ntohl(tvb, ahs_offset);
                    ahs_offset+=4;
                    break;
                default:
                    proto_tree_add_item(ti, hf_iscsi_AHS_blob, tvb, ahs_offset, ahs_length, ENC_NA);
                    ahs_offset+=ahs_length;
                }

                /* strip off padding bytes */
                if(ahs_offset & 3){
                    ahs_offset=WS_ROUNDUP_4(ahs_offset);
                }

            }

        }
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48 + ahsLen);

        immediate_data_offset=offset;
        offset = handleDataSegment(iscsi_session, ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_immediate_data);
        immediate_data_length=offset-immediate_data_offset;
    } else if(opcode == ISCSI_OPCODE_SCSI_RESPONSE) {
        /* SCSI Response */
        static int * const flags[] = {
            &hf_iscsi_SCSIResponse_o,
            &hf_iscsi_SCSIResponse_u,
            &hf_iscsi_SCSIResponse_O,
            &hf_iscsi_SCSIResponse_U,
            NULL
        };

        proto_tree_add_bitmask(tree, tvb, offset + 1, hf_iscsi_Flags, ett_iscsi_Flags, flags, ENC_NA);
        proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Status, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_SCSIResponse_ResidualCount, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpDataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_SCSIResponse_BidiReadResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(ti, hf_iscsi_SCSIResponse_BidiReadResidualCount, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_SCSIResponse_ResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
        }
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        /* do not update offset here because the data segment is
         * dissected below */
        handleDataDigest(iscsi_session, ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION) {
        /* Task Management Function */
        proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_Function, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        }
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_ReferencedTaskTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_RefCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE) {
        /* Task Management Function Response */
        proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
            proto_tree_add_item(ti, hf_iscsi_TaskManagementFunction_ReferencedTaskTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_LOGIN_COMMAND) {
        /* Login Command */
        int digestsActive = 0;
        {
            int b = tvb_get_uint8(tvb, offset + 1);
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
                if((b & CSG_MASK) >= ISCSI_CSG_OPERATIONAL_NEGOTIATION)
                    digestsActive = 1;
            }
#if 0
            proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

            proto_tree_add_boolean(ti, hf_iscsi_Login_T, tvb, offset + 1, 1, b);
            if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
                proto_tree_add_boolean(ti, hf_iscsi_Login_C, tvb, offset + 1, 1, b);
            }
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
                proto_tree_add_boolean(ti, hf_iscsi_Login_X, tvb, offset + 1, 1, b);
            }
            proto_tree_add_item(ti, hf_iscsi_Login_CSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

            /* NSG is undefined unless T is set */
            if(b&0x80){
                proto_tree_add_item(ti, hf_iscsi_Login_NSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            }
        }
        proto_tree_add_item(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_VersionMin, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
            proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_ISID8, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_item *tf = proto_tree_add_item(ti, hf_iscsi_ISID, tvb, offset + 8, 6, ENC_NA);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_ISID);
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT09) {
                proto_tree_add_item(tt, hf_iscsi_ISID_Type, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_NamingAuthority, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_Qualifier, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_item(tt, hf_iscsi_ISID_t, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_a, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_b, tvb, offset + 9, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_c, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_d, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
            }
        }
        if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
            proto_tree_add_item(ti, hf_iscsi_TSID, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(ti, hf_iscsi_TSIH, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
            proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 20, 2, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        if(digestsActive){
            offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        } else {
            offset += 48;
        }
        offset = handleDataSegmentAsTextKeys(iscsi_session, pinfo, ti, tvb, offset, data_segment_len, end_offset, digestsActive);
    } else if(opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
        /* Login Response */
        int digestsActive = 0;
        {
            int b = tvb_get_uint8(tvb, offset + 1);
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
                if((b & CSG_MASK) >= ISCSI_CSG_OPERATIONAL_NEGOTIATION)
                    digestsActive = 1;
            }
#if 0
            proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

            proto_tree_add_boolean(ti, hf_iscsi_Login_T, tvb, offset + 1, 1, b);
            if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
                proto_tree_add_boolean(ti, hf_iscsi_Login_C, tvb, offset + 1, 1, b);
            }
            proto_tree_add_item(ti, hf_iscsi_Login_CSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            /* NSG is undefined unless T is set */
            if(b&0x80){
                proto_tree_add_item(ti, hf_iscsi_Login_NSG, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
            }
        }

        proto_tree_add_item(ti, hf_iscsi_VersionMax, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_VersionActive, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
            proto_tree_add_item(ti, hf_iscsi_ISID8, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_item *tf = proto_tree_add_item(ti, hf_iscsi_ISID, tvb, offset + 8, 6, ENC_NA);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_ISID);
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT09) {
                proto_tree_add_item(tt, hf_iscsi_ISID_Type, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_NamingAuthority, tvb, offset + 9, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_Qualifier, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
            }
            else {
                proto_tree_add_item(tt, hf_iscsi_ISID_t, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_a, tvb, offset + 8, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_b, tvb, offset + 9, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_c, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tt, hf_iscsi_ISID_d, tvb, offset + 12, 2, ENC_BIG_ENDIAN);
            }
        }
        if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT12) {
            proto_tree_add_item(ti, hf_iscsi_TSID, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(ti, hf_iscsi_TSIH, tvb, offset + 14, 2, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Login_Status, tvb, offset + 36, 2, ENC_BIG_ENDIAN);
        if(digestsActive){
            offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        } else {
            offset += 48;
        }
        offset = handleDataSegmentAsTextKeys(iscsi_session, pinfo, ti, tvb, offset, data_segment_len, end_offset, digestsActive);
    } else if(opcode == ISCSI_OPCODE_TEXT_COMMAND) {
        /* Text Command */
        {
            int b = tvb_get_uint8(tvb, offset + 1);
            proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

            proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
            if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
                proto_tree_add_boolean(tt, hf_iscsi_Text_C, tvb, offset + 1, 1, b);
            }
        }
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            dissect_scsi_lun(ti, tvb, offset + 8);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        offset = handleDataSegmentAsTextKeys(iscsi_session, pinfo, ti, tvb, offset, data_segment_len, end_offset, true);
    } else if(opcode == ISCSI_OPCODE_TEXT_RESPONSE) {
        /* Text Response */
        {
            int b = tvb_get_uint8(tvb, offset + 1);
            proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);

            proto_tree_add_boolean(tt, hf_iscsi_Text_F, tvb, offset + 1, 1, b);
            if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
                proto_tree_add_boolean(tt, hf_iscsi_Text_C, tvb, offset + 1, 1, b);
            }
        }
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            dissect_scsi_lun(ti, tvb, offset + 8);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        offset = handleDataSegmentAsTextKeys(iscsi_session, pinfo, ti, tvb, offset, data_segment_len, end_offset, true);
    } else if(opcode == ISCSI_OPCODE_SCSI_DATA_OUT) {
        /* SCSI Data Out (write) */
        static int * const flags[] = {
            &hf_iscsi_SCSIData_F,
            NULL
        };

        proto_tree_add_bitmask(tree, tvb, offset + 1, hf_iscsi_Flags, ett_iscsi_Flags, flags, ENC_NA);

        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
        data_offset=tvb_get_ntohl(tvb, offset+40);

        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        /* do not update offset here because the data segment is
         * dissected below */
        handleDataDigest(iscsi_session, ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_SCSI_DATA_IN) {
        /* SCSI Data In (read) */
        {
            static int * const scsi_data_in[] = {
                &hf_iscsi_SCSIData_F,
                &hf_iscsi_SCSIData_O,
                &hf_iscsi_SCSIData_U,
                &hf_iscsi_SCSIData_S,
                NULL
            };

            static int * const scsi_data_in_draft08[] = {
                &hf_iscsi_SCSIData_F,
                &hf_iscsi_SCSIData_A,
                &hf_iscsi_SCSIData_O,
                &hf_iscsi_SCSIData_U,
                &hf_iscsi_SCSIData_S,
                NULL
            };
            int b;

            if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
                proto_tree_add_bitmask_with_flags(ti, tvb, offset+1, hf_iscsi_Flags,
                                   ett_iscsi_Flags, scsi_data_in_draft08, ENC_NA, BMT_NO_APPEND);
            } else {
                proto_tree_add_bitmask_with_flags(ti, tvb, offset+1, hf_iscsi_Flags,
                                   ett_iscsi_Flags, scsi_data_in, ENC_NA, BMT_NO_APPEND);
            }

            b = tvb_get_uint8(tvb, offset + 1);
            if(b&ISCSI_SCSI_DATA_FLAG_S){
                S_bit=true;
            }

            if(b&ISCSI_SCSI_DATA_FLAG_A){
                A_bit=true;
            }

        }
        if(S_bit){
            proto_tree_add_item(ti, hf_iscsi_SCSIResponse_Status, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        }
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        cdata->itlq.data_length=tvb_get_ntoh24(tvb, offset + 5);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            if (A_bit) {
                dissect_scsi_lun(ti, tvb, offset + 8);
            }
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_SCSIData_ResidualCount, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        }
        else {
            if (A_bit) {
                proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
            }
        }
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
        data_offset=tvb_get_ntohl(tvb, offset+40);

        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_SCSIData_ResidualCount, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
        }
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        /* do not update offset here because the data segment is
         * dissected below */
        handleDataDigest(iscsi_session, ti, tvb, offset, paddedDataSegmentLength);
    } else if(opcode == ISCSI_OPCODE_LOGOUT_COMMAND) {
        /* Logout Command */
        if(iscsi_protocol_version >= ISCSI_PROTOCOL_DRAFT13) {
            proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        }
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        }
        if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
            proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 8, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 11, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT08) {
            proto_tree_add_item(ti, hf_iscsi_CID, tvb, offset + 20, 2, ENC_BIG_ENDIAN);
            if(iscsi_protocol_version < ISCSI_PROTOCOL_DRAFT13) {
                proto_tree_add_item(ti, hf_iscsi_Logout_Reason, tvb, offset + 23, 1, ENC_BIG_ENDIAN);
            }
        }
        proto_tree_add_item(ti, hf_iscsi_CmdSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_LOGOUT_RESPONSE) {
        /* Logout Response */
        proto_tree_add_item(ti, hf_iscsi_Logout_Response, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Time2Wait, tvb, offset + 40, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Time2Retain, tvb, offset + 42, 2, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_SNACK_REQUEST) {
        /* SNACK Request */
        {
#if 0
            int b = tvb_get_uint8(tvb, offset + 1);
            proto_item *tf = proto_tree_add_uint(ti, hf_iscsi_Flags, tvb, offset + 1, 1, b);
            proto_tree *tt = proto_item_add_subtree(tf, ett_iscsi_Flags);
#endif

            proto_tree_add_item(ti, hf_iscsi_snack_type, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        }
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            dissect_scsi_lun(ti, tvb, offset + 8);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version <= ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_BegRun, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_RunLength, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_ExpDataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_ExpStatSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_BegRun, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_RunLength, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
        }
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_R2T) {
        /* R2T */
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
            dissect_scsi_lun(ti, tvb, offset + 8);
        }
        proto_tree_add_item(ti, hf_iscsi_InitiatorTaskTag, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_TargetTransferTag, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_R2TSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_BufferOffset, tvb, offset + 40, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_DesiredDataLength, tvb, offset + 44, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
    } else if(opcode == ISCSI_OPCODE_ASYNC_MESSAGE) {
        int dsl, snsl;

        /* Asynchronous Message */
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        dsl=tvb_get_ntoh24(tvb, offset+5);
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        dissect_scsi_lun(ti, tvb, offset + 8);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_AsyncEvent, tvb, offset + 36, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_EventVendorCode, tvb, offset + 37, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Parameter1, tvb, offset + 38, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Parameter2, tvb, offset + 40, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_Parameter3, tvb, offset + 42, 2, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);

        /* If we have a datasegment this contains scsi sense info followed
         * by iscsi event data. (rfc3720 10.9.4)
         */
        if(dsl){
            snsl=tvb_get_ntohs(tvb, offset);
            offset+=2;
            if(snsl){
                tvbuff_t *data_tvb;
                int tvb_len, tvb_rlen;

                tvb_len=tvb_captured_length_remaining(tvb, offset);
                if(tvb_len>snsl)
                    tvb_len=snsl;
                tvb_rlen=tvb_reported_length_remaining(tvb, offset);
                if(tvb_rlen>snsl)
                    tvb_rlen=snsl;
                data_tvb=tvb_new_subset_length_caplen(tvb, offset, tvb_len, tvb_rlen);
                dissect_scsi_snsinfo (data_tvb, pinfo, tree, 0,
                                      tvb_len,
                                      &cdata->itlq, itl);

                offset+=snsl;
            }
            if((end_offset-offset)>0){
                proto_tree_add_item(ti, hf_iscsi_async_event_data, tvb, offset, end_offset-offset, ENC_NA);
            }
        }
        offset=end_offset;
    } else if(opcode == ISCSI_OPCODE_REJECT) {
        proto_tree *tt;
        uint8_t next_opcode;

        /* Reject */
        proto_tree_add_item(ti, hf_iscsi_Reject_Reason, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_StatSN, tvb, offset + 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_ExpCmdSN, tvb, offset + 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_MaxCmdSN, tvb, offset + 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ti, hf_iscsi_DataSN, tvb, offset + 36, 4, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);

        next_opcode = tvb_get_uint8(tvb, offset) & OPCODE_MASK;

        tt = proto_tree_add_subtree(ti, tvb, offset, -1, ett_iscsi_RejectHeader, NULL, "Rejected Header");

        increment_dissection_depth(pinfo);
        dissect_iscsi_pdu(tvb, pinfo, tt, offset, next_opcode, 0, iscsi_session, conversation);
        decrement_dissection_depth(pinfo);
    } else if(opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I0 ||
              opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I1 ||
              opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_I2 ||
              opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T0 ||
              opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T1 ||
              opcode == ISCSI_OPCODE_VENDOR_SPECIFIC_T2) {
        /* Vendor specific opcodes */
        if(iscsi_protocol_version > ISCSI_PROTOCOL_DRAFT09) {
            proto_tree_add_item(ti, hf_iscsi_TotalAHSLength, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(ti, hf_iscsi_DataSegmentLength, tvb, offset + 5, 3, ENC_BIG_ENDIAN);
        offset = handleHeaderDigest(iscsi_session, ti, tvb, offset, 48);
        offset = handleDataSegment(iscsi_session, ti, tvb, offset, data_segment_len, end_offset, hf_iscsi_vendor_specific_data);
    }



    /* handle request/response matching */
    switch(opcode){
    case ISCSI_OPCODE_SCSI_RESPONSE:
        if (cdata->itlq.first_exchange_frame){
            nstime_t delta_time;
            itm = proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
            proto_item_set_generated(itm);
            nstime_delta(&delta_time, &pinfo->abs_ts, &cdata->itlq.fc_time);
            itm = proto_tree_add_time(ti, hf_iscsi_time, tvb, 0, 0, &delta_time);
            proto_item_set_generated(itm);
        }
        if (cdata->r2t_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_r2t_frame, tvb, 0, 0, cdata->r2t_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->data_in_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->data_out_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
            proto_item_set_generated(itm);
        }
        break;

    case ISCSI_OPCODE_R2T:
        if (cdata->itlq.first_exchange_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->itlq.first_exchange_frame && (cdata->itlq.first_exchange_frame < pinfo->num)) {
            nstime_t delta_time;
            nstime_delta(&delta_time, &pinfo->abs_ts, &cdata->itlq.r2t_time);
            itm = proto_tree_add_time(ti, hf_iscsi_r2t_time, tvb, 0, 0, &delta_time);
            proto_item_set_generated(itm);
        }
        if (cdata->data_out_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->itlq.last_exchange_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
            proto_item_set_generated(itm);
        }

        if (cdata->itlq.lun == 0xffff)
            col_append_str (pinfo->cinfo, COL_INFO,
                " <missing request> "
            );
        else
            col_append_fstr (pinfo->cinfo, COL_INFO,
                " LUN: 0x0%x, OK to write %u bytes (%u blocks) ",
                cdata->itlq.lun,
                cdata->itlq.data_length,
                cdata->itlq.data_length>=512 ? cdata->itlq.data_length/512 : 0
            );
        break;
    case ISCSI_OPCODE_SCSI_DATA_IN:
        /* if we have phase collaps then we might have the
           response embedded in the last DataIn segment */
        if(!S_bit){
            if (cdata->itlq.first_exchange_frame) {
                itm = proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
                proto_item_set_generated(itm);
            }
        } else {
            if (cdata->itlq.first_exchange_frame){
                nstime_t delta_time;
                itm = proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
                proto_item_set_generated(itm);
                nstime_delta(&delta_time, &pinfo->abs_ts, &cdata->itlq.fc_time);
                itm = proto_tree_add_time(ti, hf_iscsi_time, tvb, 0, 0, &delta_time);
                proto_item_set_generated(itm);
            }
        }
        if (cdata->data_out_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
            proto_item_set_generated(itm);
        }

        col_set_fence(pinfo->cinfo, COL_INFO);
        col_append_fstr (pinfo->cinfo, COL_INFO,
            " LUN: %u, read %u bytes (%u blocks) ",
            cdata->itlq.lun,
            data_segment_len,
            data_segment_len>=512 ? data_segment_len/512 : 0
        );
        break;
    case ISCSI_OPCODE_SCSI_DATA_OUT:
        if (cdata->itlq.first_exchange_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_request_frame, tvb, 0, 0, cdata->itlq.first_exchange_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->r2t_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_r2t_frame, tvb, 0, 0, cdata->r2t_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->data_in_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->itlq.last_exchange_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
            proto_item_set_generated(itm);
        }

        col_set_fence(pinfo->cinfo, COL_INFO);
        col_append_fstr (pinfo->cinfo, COL_INFO,
            " LUN: 0x0%x, wrote %u bytes (%u blocks) ",
            cdata->itlq.lun,
            data_segment_len,
            data_segment_len>=512 ? data_segment_len/512 : 0
        );
        break;
    case ISCSI_OPCODE_SCSI_COMMAND:
        if (cdata->r2t_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_r2t_frame, tvb, 0, 0, cdata->r2t_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->data_in_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_in_frame, tvb, 0, 0, cdata->data_in_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->data_out_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_data_out_frame, tvb, 0, 0, cdata->data_out_frame);
            proto_item_set_generated(itm);
        }
        if (cdata->itlq.last_exchange_frame) {
            itm = proto_tree_add_uint(ti, hf_iscsi_response_frame, tvb, 0, 0, cdata->itlq.last_exchange_frame);
            proto_item_set_generated(itm);
        }
        break;
    }



    proto_item_set_len(ti, offset - original_offset);

    if((opcode & ((iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08)?
                  ~(X_BIT | I_BIT) :
                  ~I_BIT)) == ISCSI_OPCODE_SCSI_COMMAND) {
        tvbuff_t *cdb_tvb, *data_tvb;
        int tvb_len, tvb_rlen;

        /* SCSI Command */
        tvb_len=tvb_captured_length_remaining(tvb, cdb_offset);
        tvb_rlen=tvb_reported_length_remaining(tvb, cdb_offset);
        if(ahs_cdb_length && ahs_cdb_length<1024){
            uint8_t *cdb_buf;

            /* We have a variable length CDB where bytes >16 is transported
             * in the AHS.
             */
            cdb_buf=(uint8_t *)wmem_alloc(pinfo->pool, 16+ahs_cdb_length);
            /* the 16 first bytes of the cdb */
            tvb_memcpy(tvb, cdb_buf, cdb_offset, 16);
            /* the remainder of the cdb from the ahs */
            tvb_memcpy(tvb, cdb_buf+16, ahs_cdb_offset, ahs_cdb_length);

            cdb_tvb = tvb_new_child_real_data(tvb, cdb_buf,
                                              ahs_cdb_length+16,
                                              ahs_cdb_length+16);

            add_new_data_source(pinfo, cdb_tvb, "CDB+AHS");
        } else {
            if(tvb_len>16){
                tvb_len=16;
            }
            if(tvb_rlen>16){
                tvb_rlen=16;
            }
            cdb_tvb=tvb_new_subset_length_caplen(tvb, cdb_offset, tvb_len, tvb_rlen);
        }
        dissect_scsi_cdb(cdb_tvb, pinfo, tree, SCSI_DEV_UNKNOWN, &cdata->itlq, itl);
        /* we don't want the immediate below to overwrite our CDB info */
        col_set_fence(pinfo->cinfo, COL_INFO);

        /* where there any ImmediateData ? */
        if(immediate_data_length){
            /* Immediate Data TVB */
            tvb_len=tvb_captured_length_remaining(tvb, immediate_data_offset);
            if(tvb_len>(int)immediate_data_length)
                tvb_len=immediate_data_length;
            tvb_rlen=tvb_reported_length_remaining(tvb, immediate_data_offset);
            if(tvb_rlen>(int)immediate_data_length)
                tvb_rlen=immediate_data_length;
            data_tvb=tvb_new_subset_length_caplen(tvb, immediate_data_offset, tvb_len, tvb_rlen);
            dissect_scsi_payload (data_tvb, pinfo, tree,
                                  true,
                                  &cdata->itlq, itl,
                                  0);
        }
    }
    else if (opcode == ISCSI_OPCODE_SCSI_RESPONSE) {
        if (scsi_status == 0x2) {
            /* A SCSI response with Check Condition contains sense data */
            /* offset is setup correctly by the iscsi code for response above */
            if((end_offset - offset) >= 2) {
                int senseLen = tvb_get_ntohs(tvb, offset);
                if(ti != NULL)
                    proto_tree_add_item(ti, hf_iscsi_SenseLength, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                if(senseLen > 0){
                    tvbuff_t *data_tvb;
                    int tvb_len, tvb_rlen;

                    tvb_len=tvb_captured_length_remaining(tvb, offset);
                    if(tvb_len>senseLen)
                        tvb_len=senseLen;
                    tvb_rlen=tvb_reported_length_remaining(tvb, offset);
                    if(tvb_rlen>senseLen)
                        tvb_rlen=senseLen;
                    data_tvb=tvb_new_subset_length_caplen(tvb, offset, tvb_len, tvb_rlen);
                    dissect_scsi_snsinfo (data_tvb, pinfo, tree, 0,
                                          tvb_len,
                                          &cdata->itlq, itl);
                }
            }
        }
        else {
            dissect_scsi_rsp(tvb, pinfo, tree, &cdata->itlq, itl, scsi_status);
        }
    }
    else if ((opcode == ISCSI_OPCODE_SCSI_DATA_IN) ||
             (opcode == ISCSI_OPCODE_SCSI_DATA_OUT)) {
        tvbuff_t *data_tvb;
        int tvb_len, tvb_rlen;

        /* offset is setup correctly by the iscsi code for response above */
        tvb_len=tvb_captured_length_remaining(tvb, offset);
        if(tvb_len>(int)data_segment_len)
            tvb_len=data_segment_len;
        tvb_rlen=tvb_reported_length_remaining(tvb, offset);
        if(tvb_rlen>(int)data_segment_len)
            tvb_rlen=data_segment_len;
        data_tvb=tvb_new_subset_length_caplen(tvb, offset, tvb_len, tvb_rlen);
        dissect_scsi_payload (data_tvb, pinfo, tree,
                              (opcode==ISCSI_OPCODE_SCSI_DATA_OUT),
                              &cdata->itlq, itl,
                              data_offset);
    }

    if(S_bit){
        dissect_scsi_rsp(tvb, pinfo, tree, &cdata->itlq, itl, scsi_status);
    }
}

static int
dissect_iscsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool check_port) {
    /* Set up structures needed to add the protocol subtree and manage it */
    unsigned offset = 0;
    uint32_t available_bytes = tvb_captured_length(tvb);
    int digestsActive = 1;
    conversation_t *conversation = NULL;
    iscsi_session_t *iscsi_session=NULL;
    uint8_t opcode, tmpbyte;

    if (available_bytes < 48) {
        /* heuristic already rejected the packet if size < 48,
           assume it's an iscsi packet with a segmented header */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return -1;
    }

    opcode = tvb_get_uint8(tvb, offset + 0);
    opcode &= OPCODE_MASK;

    /* heuristics to verify that the packet looks sane.   the heuristics
     * are based on the RFC version of iscsi.
     * (we should retire support for older iscsi versions in wireshark)
     *      -- ronnie s
     */
    /* opcode must be any of the ones from the standard
     * also check the header that it looks "sane"
     * all reserved or undefined bits in iscsi must be set to zero.
     */
    switch(opcode){
    case ISCSI_OPCODE_NOP_IN:
        /* top two bits of byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* bytes 2 and 3 must be 0 */
        if(tvb_get_uint8(tvb, offset+2)||tvb_get_uint8(tvb, offset+3)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_NOP_OUT:
        /* top bit of byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0x80){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* bytes 2 and 3 must be 0 */
        if(tvb_get_uint8(tvb, offset+2)||tvb_get_uint8(tvb, offset+3)){
            return 0;
        }
        /* assume ITT and TTT must always be non NULL (ok they can be NULL
         * from time to time but it usually means we are in the middle
         * of a zeroed datablock).
         */
        if(!tvb_get_letohl(tvb,offset+16) || !tvb_get_letohl(tvb,offset+20)){
            return 0;
        }
        /* all reserved bytes between 32 - 47 must be null */
        if(tvb_get_letohl(tvb,offset+32)
           || tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_LOGIN_COMMAND:
        /* top two bits in byte 0 must be 0x40 */
        if((tvb_get_uint8(tvb, offset+0)&0xc0)!=0x40){

            return 0;
        }
        /* both the T and C bits can not be set
         * and the two reserved bits in byte 1 must be 0
         */
        tmpbyte=tvb_get_uint8(tvb, offset+1);
        switch(tmpbyte&0xf0){
        case 0x80:
        case 0x40:
        case 0x00:
            break;
        default:
            return 0;
        }
        /* CSG and NSG must not be 2 */
        if(((tmpbyte & 0x03) == 0x02)
           || ((tmpbyte & 0x0c) == 0x08)) {
            return 0;
        }
        /* if T bit is set NSG must not be 0 */
        if(tmpbyte&0x80){
            if(!(tmpbyte&0x03)){
                return 0;
            }
        }
        /* should we test that datasegmentlen is non zero? */
        break;
    case ISCSI_OPCODE_LOGIN_RESPONSE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){

            return 0;
        }
        /* both the T and C bits can not be set
         * and the two reserved bits in byte 1 must be 0
         */
        tmpbyte=tvb_get_uint8(tvb, offset+1);
        switch(tmpbyte&0xf0){
        case 0x80:
        case 0x40:
        case 0x00:
            break;
        default:
            return 0;
        }
        /* CSG and NSG must not be 2 */
        if(((tmpbyte & 0x03) == 0x02)
           || ((tmpbyte & 0x0c) == 0x08)) {
            return 0;
        }
        /* if T bit is set NSG must not be 0 */
        if(tmpbyte&0x80){
            if(!(tmpbyte&0x03)){
                return 0;
            }
        }
        /* the 32bit words at offsets 20, 40, 44 must be zero */
        if(tvb_get_letohl(tvb,offset+20)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        /* the two bytes at offset 38 must be zero */
        if(tvb_get_letohs(tvb,offset+38)){
            return 0;
        }
        /* should we test that datasegmentlen is non zero unless we just
         * entered full featured phase?
         */
        break;
    case ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION:
        /* top bit in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0x80){
            return 0;
        }
        /* top bit in byte 1 must be set */
        tmpbyte=tvb_get_uint8(tvb, offset+1);
        if(!(tmpbyte&0x80)){
            return 0;
        }
        /* Function must be known */
        if(!try_val_to_str(tmpbyte&0x7f, iscsi_task_management_functions)){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* ahs and dsl must be null */
        if(tvb_get_letohl(tvb,offset+4)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* response must be 0-6 or 255 */
        tmpbyte=tvb_get_uint8(tvb,offset+2);
        if(tmpbyte>6 && tmpbyte<255){
            return 0;
        }
        /* byte 3 must be 0 */
        if(tvb_get_uint8(tvb,offset+3)){
            return 0;
        }
        /* ahs and dsl  as well as the 32bit words at offsets 8, 12, 20, 36
         * 40, 44 must all be 0
         */
        if(tvb_get_letohl(tvb,offset+4)
           || tvb_get_letohl(tvb,offset+8)
           || tvb_get_letohl(tvb,offset+12)
           || tvb_get_letohl(tvb,offset+20)
           || tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_LOGOUT_COMMAND:
        /* top bit in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0x80){
            return 0;
        }
        /* top bit in byte 1 must be set */
        tmpbyte=tvb_get_uint8(tvb, offset+1);
        if(!(tmpbyte&0x80)){
            return 0;
        }
        /* Reason code must be known */
        if(!try_val_to_str(tmpbyte&0x7f, iscsi_logout_reasons)){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* ahs and dsl  as well as the 32bit words at offsets 8, 12, 32, 36
         * 40, 44 must all be 0
         */
        if(tvb_get_letohl(tvb,offset+4)
           || tvb_get_letohl(tvb,offset+8)
           || tvb_get_letohl(tvb,offset+12)
           || tvb_get_letohl(tvb,offset+32)
           || tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_SNACK_REQUEST:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* top 4 bits in byte 1 must be 0x80 */
        tmpbyte=tvb_get_uint8(tvb, offset+1);
        if((tmpbyte&0xf0)!=0x80){
            return 0;
        }
        /* type must be known */
        if(!try_val_to_str(tmpbyte&0x0f, iscsi_snack_types)){
            return 0;
        }
        /* for status/snack and datack itt must be 0xffffffff
         * for rdata/snack ttt must not be 0 or 0xffffffff
         */
        switch(tmpbyte&0x0f){
        case 1:
        case 2:
            if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
                return 0;
            }
            break;
        case 3:
            if(tvb_get_letohl(tvb,offset+20)==0xffffffff){
                return 0;
            }
            if(tvb_get_letohl(tvb,offset+20)==0){
                return 0;
            }
            break;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* the 32bit words at offsets 24, 32, 36
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+24)
           || tvb_get_letohl(tvb,offset+32)
           || tvb_get_letohl(tvb,offset+36)){
            return 0;
        }

        break;
    case ISCSI_OPCODE_R2T:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* ahs and dsl must be null */
        if(tvb_get_letohl(tvb,offset+4)){
            return 0;
        }
        /* desired data transfer length must not be null */
        if(!tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_REJECT:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* reason must be known */
        if(!try_val_to_str(tvb_get_uint8(tvb,offset+2), iscsi_reject_reasons)){
            return 0;
        }
        /* byte 3 must be 0 */
        if(tvb_get_uint8(tvb, offset+3)){
            return 0;
        }
        /* the 32bit words at offsets 8, 12, 20, 40, 44
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+8)
           || tvb_get_letohl(tvb,offset+12)
           || tvb_get_letohl(tvb,offset+20)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        /* the 32bit word at 16 must be 0xffffffff */
        if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
            return 0;
        }
        break;
    case ISCSI_OPCODE_TEXT_COMMAND:
        /* top bit in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0x80){
            return 0;
        }
        /* one of the F and C bits must be set but not both
         * low 6 bits in byte 1 must be 0
         */
        switch(tvb_get_uint8(tvb,offset+1)){
        case 0x80:
        case 0x40:
            break;
        default:
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* the 32bit words at offsets 32, 36, 40, 44
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+32)
           || tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_TEXT_RESPONSE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* one of the F and C bits must be set but not both
         * low 6 bits in byte 1 must be 0
         */
        switch(tvb_get_uint8(tvb,offset+1)){
        case 0x80:
        case 0x40:
            break;
        default:
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* the 32bit words at offsets 36, 40, 44
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+40)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_SCSI_COMMAND:
        /* top bit in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0x80){
            return 0;
        }
        /* reserved bits in byte 1 must be 0 */
        if(tvb_get_uint8(tvb, offset+1)&0x18){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* if expected data transfer length is set, W and/or R have to be set */
        if(tvb_get_ntohl(tvb,offset+20)){
            if(!(tvb_get_uint8(tvb, offset+1)&0x60)){
                return 0;
            }
        }
        break;
    case ISCSI_OPCODE_SCSI_RESPONSE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* top bit in byte 1 must be 1 */
        tmpbyte=tvb_get_uint8(tvb,offset+1);
        if(!(tmpbyte&0x80)){
            return 0;
        }
        /* the reserved bits in byte 1 must be 0 */
        if(tmpbyte&0x61){
            return 0;
        }
        /* status must be known */
        if(!try_val_to_str(tvb_get_uint8(tvb,offset+3), scsi_status_val)){
            return 0;
        }
        /* the 32bit words at offsets 8, 12
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+8)
           || tvb_get_letohl(tvb,offset+12)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_ASYNC_MESSAGE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* the 32bit words at offsets 20, 44
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+20)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        /* the 32bit word at 16 must be 0xffffffff */
        if(tvb_get_letohl(tvb,offset+16)!=0xffffffff){
            return 0;
        }
        break;
    case ISCSI_OPCODE_LOGOUT_RESPONSE:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* byte 1 must be 0x80 */
        if(tvb_get_uint8(tvb, offset+1)!=0x80){
            return 0;
        }
        /* response must be known */
        if(!try_val_to_str(tvb_get_uint8(tvb,offset+2), iscsi_logout_response)){
            return 0;
        }
        /* byte 3 must be 0 */
        if(tvb_get_uint8(tvb,offset+3)){
            return 0;
        }
        /* ahs and dsl  as well as the 32bit words at offsets 8, 12, 20, 36
         * 44 must all be 0
         */
        if(tvb_get_letohl(tvb,offset+4)
           || tvb_get_letohl(tvb,offset+8)
           || tvb_get_letohl(tvb,offset+12)
           || tvb_get_letohl(tvb,offset+20)
           || tvb_get_letohl(tvb,offset+36)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_SCSI_DATA_OUT:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* low 7 bits in byte 1 must be 0 */
        if(tvb_get_uint8(tvb,offset+1)&0x7f){
            return 0;
        }
        /* bytes 2,3 must be null */
        if(tvb_get_letohs(tvb,offset+2)){
            return 0;
        }
        /* the 32bit words at offsets 24, 32, 44
         * must all be 0
         */
        if(tvb_get_letohl(tvb,offset+24)
           || tvb_get_letohl(tvb,offset+32)
           || tvb_get_letohl(tvb,offset+44)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_SCSI_DATA_IN:
        /* top two bits in byte 0 must be 0 */
        if(tvb_get_uint8(tvb, offset+0)&0xc0){
            return 0;
        }
        /* reserved bits in byte 1 must be 0 */
        if(tvb_get_uint8(tvb,offset+1)&0x38){
            return 0;
        }
        /* byte 2 must be reserved */
        if(tvb_get_uint8(tvb,offset+2)){
            return 0;
        }
        break;
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I0:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I1:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_I2:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T0:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T1:
    case ISCSI_OPCODE_VENDOR_SPECIFIC_T2:
        break;
    default:
        return 0;
    } /* end of heuristics check */


    /* process multiple iSCSI PDUs per packet */
    while(available_bytes >= 48 || (iscsi_desegment && available_bytes >= 8)) {
        uint32_t data_segment_len;
        uint32_t pduLen = 48;
        uint8_t secondPduByte = tvb_get_uint8(tvb, offset + 1);
        bool badPdu = false;
        uint8_t ahsLen=0;
        uint32_t data_segment_offset, data_segment_len_padded;

        /* mask out any extra bits in the opcode byte */
        opcode = tvb_get_uint8(tvb, offset + 0);
        opcode &= OPCODE_MASK;

        if(opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION ||
           opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE ||
           opcode == ISCSI_OPCODE_R2T ||
           opcode == ISCSI_OPCODE_LOGOUT_COMMAND ||
           opcode == ISCSI_OPCODE_LOGOUT_RESPONSE ||
           opcode == ISCSI_OPCODE_SNACK_REQUEST)
            data_segment_len = 0;
        else
            data_segment_len = tvb_get_ntohl(tvb, offset + 4) & 0x00ffffff;

        if (!try_val_to_str(opcode, iscsi_opcodes)) {
            badPdu = true;
        }


        if(!badPdu && check_port) {
            badPdu = true;
            if ((opcode & TARGET_OPCODE_BIT) && value_is_in_range(global_iscsi_port_range, pinfo->srcport)) {
                badPdu = false;
            }
            if (!(opcode & TARGET_OPCODE_BIT) && value_is_in_range(global_iscsi_port_range, pinfo->destport)) {
                badPdu = false;
            }
            if ((opcode & TARGET_OPCODE_BIT) && pinfo->srcport == iscsi_system_port) {
                badPdu = false;
            }
            if (!(opcode & TARGET_OPCODE_BIT) && pinfo->destport == iscsi_system_port) {
                badPdu = false;
            }
        }

        if(!badPdu && enable_bogosity_filter) {
            /* try and distinguish between data and real headers */
            if(data_segment_len > bogus_pdu_data_length_threshold) {
                badPdu = true;
            }
            else if(demand_good_f_bit &&
                    !(secondPduByte & 0x80) &&
                    (opcode == ISCSI_OPCODE_NOP_OUT ||
                     opcode == ISCSI_OPCODE_NOP_IN ||
                     opcode == ISCSI_OPCODE_LOGOUT_COMMAND ||
                     opcode == ISCSI_OPCODE_LOGOUT_RESPONSE ||
                     opcode == ISCSI_OPCODE_SCSI_RESPONSE ||
                     opcode == ISCSI_OPCODE_TASK_MANAGEMENT_FUNCTION_RESPONSE ||
                     opcode == ISCSI_OPCODE_R2T ||
                     opcode == ISCSI_OPCODE_ASYNC_MESSAGE ||
                     opcode == ISCSI_OPCODE_SNACK_REQUEST ||
                     opcode == ISCSI_OPCODE_REJECT)) {
                badPdu = true;
            } else if(opcode==ISCSI_OPCODE_NOP_OUT) {
                /* TransferTag for NOP-Out should either be -1 or
                   the tag value we want for a response.
                   Assume 0 means we are just inside a big all zero
                   datablock.
                */
                if(tvb_get_ntohl(tvb, offset+20)==0){
                    badPdu = true;
                }
            }
        }

        if(badPdu) {
            return offset;
        }

        if(opcode == ISCSI_OPCODE_LOGIN_COMMAND ||
           opcode == ISCSI_OPCODE_LOGIN_RESPONSE) {
            if(iscsi_protocol_version == ISCSI_PROTOCOL_DRAFT08) {
                if((secondPduByte & CSG_MASK) < ISCSI_CSG_OPERATIONAL_NEGOTIATION) {
                    /* digests are not yet turned on */
                    digestsActive = 0;
                }
            } else {
                digestsActive = 0;
            }
        }

        if(opcode == ISCSI_OPCODE_SCSI_COMMAND) {
            /* ahsLen */
            ahsLen = tvb_get_uint8(tvb, offset + 4);
            pduLen += ahsLen * 4;
        }

        data_segment_offset = pduLen;
        data_segment_len_padded = data_segment_len;
        if((data_segment_len_padded & 3) != 0)
            data_segment_len_padded += 4 - (data_segment_len_padded & 3);
        pduLen += data_segment_len_padded;


        /* make sure we have a conversation for this session */
        conversation = find_or_create_conversation(pinfo);

        iscsi_session=(iscsi_session_t *)conversation_get_proto_data(conversation, proto_iscsi);
        if(!iscsi_session){
            iscsi_session = wmem_new(wmem_file_scope(), iscsi_session_t);
            iscsi_session->header_digest = ISCSI_DIGEST_AUTO;
            iscsi_session->data_digest = ISCSI_DIGEST_AUTO;
            iscsi_session->itlq = wmem_tree_new(wmem_file_scope());
            iscsi_session->itl  = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
            conversation_add_proto_data(conversation, proto_iscsi, iscsi_session);

            /* DataOut PDUs are often mistaken by DCERPC heuristics to be
             * that protocol. Now that we know this is iscsi, set a
             * dissector for this conversation to block other heuristic
             * dissectors.
             */
            conversation_set_dissector(conversation, iscsi_handle);
        }
        /* try to autodetect if header digest is used or not */
        if (digestsActive && (available_bytes >= (uint32_t) (48+4+ahsLen*4)) &&
            (iscsi_session->header_digest == ISCSI_DIGEST_AUTO)) {
            uint32_t crc;
            /* we have enough data to test if HeaderDigest is enabled */
            crc= ~crc32c_tvb_offset_calculate(tvb, offset, 48+ahsLen*4, CRC32C_PRELOAD);
            if(crc==tvb_get_ntohl(tvb,48+ahsLen*4)){
                iscsi_session->header_digest = ISCSI_DIGEST_CRC32;
            } else {
                iscsi_session->header_digest = ISCSI_DIGEST_NONE;
            }
        }


        /* Add header digest length to pdulen */
        if(digestsActive){
            switch(iscsi_session->header_digest){
            case ISCSI_DIGEST_CRC32:
                pduLen += 4;
                data_segment_offset += 4;
                break;
            case ISCSI_DIGEST_NONE:
                break;
            case ISCSI_DIGEST_AUTO:
                /* oops we don't yet know what digest is used */
                /* here we should use some default */
                break;
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
            }
        }

        /* try to autodetect whether data digest is used */
        if (digestsActive &&
            (available_bytes >= data_segment_offset + data_segment_len_padded + 4) &&
            (iscsi_session->data_digest == ISCSI_DIGEST_AUTO)) {
            uint32_t crc;
            /* we have enough data to test if DataDigest is enabled */
            crc = ~crc32c_tvb_offset_calculate(tvb, data_segment_offset, data_segment_len_padded, CRC32C_PRELOAD);
            if (crc == tvb_get_ntohl(tvb, data_segment_offset + data_segment_len_padded)) {
                iscsi_session->data_digest = ISCSI_DIGEST_CRC32;
            } else {
                iscsi_session->data_digest = ISCSI_DIGEST_NONE;
            }
        }

        /* Add data digest length to pdulen */
        if (digestsActive && data_segment_len > 0) {
            switch (iscsi_session->data_digest) {
            case ISCSI_DIGEST_CRC32:
                pduLen += 4;
                break;
            case ISCSI_DIGEST_NONE:
                break;
            case ISCSI_DIGEST_AUTO:
                /* unknown digest, perhaps a new field was introduced? */
                break;
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
            }
        }

        /*
         * Desegmentation check.
         */
        if(iscsi_desegment && pinfo->can_desegment) {
            if(pduLen > available_bytes) {
                /*
                 * This frame doesn't have all of the data for
                 * this message, but we can do reassembly on it.
                 *
                 * Tell the TCP dissector where the data for this
                 * message starts in the data it handed us, and
                 * how many more bytes we need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = pduLen - available_bytes;
                return -1;
            }
        }

        /* This is to help TCP keep track of PDU boundaries
           and allows it to find PDUs that are not aligned to
           the start of a TCP segments.
           Since it also allows TCP to know what is in the middle
           of a large PDU, it reduces the probability of a segment
           in the middle of a large PDU transfer being misdissected as
           a PDU.
        */
        if(!pinfo->fd->visited){
            if(pduLen>(uint32_t)tvb_reported_length_remaining(tvb, offset)){
                pinfo->want_pdu_tracking=2;
                pinfo->bytes_until_next_pdu=pduLen-tvb_reported_length_remaining(tvb, offset);
            }
        }

        if (offset == 0)
            col_clear(pinfo->cinfo, COL_INFO);
        else
            col_append_str(pinfo->cinfo, COL_INFO, ", ");

        dissect_iscsi_pdu(tvb, pinfo, tree, offset, opcode, data_segment_len, iscsi_session, conversation);
        if(pduLen > available_bytes)
            pduLen = available_bytes;
        offset += pduLen;
        available_bytes -= pduLen;
    }

    return offset;
}

/* This is called for those sessions where we have explicitly said
   this to be iSCSI using "Decode As..."
   In this case we will not check the port number for sanity and just
   do as the user said.
   We still check that the PDU header looks sane though.
*/
static int
dissect_iscsi_handle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    return dissect_iscsi(tvb, pinfo, tree, false);
}

/* This is called through the heuristic handler.
   In this case we also want to check that the port matches the preference
   setting for iSCSI in order to reduce the number of
   false positives.
*/
static bool
dissect_iscsi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t available_bytes = tvb_captured_length(tvb);

    /* quick check to see if the packet is long enough to contain the
     * minimum amount of information we need */
    if (available_bytes < 48 ){
        /* no, so give up */
        return false;
    }

    return dissect_iscsi(tvb, pinfo, tree, true) != 0;
}


/* Register the protocol with Wireshark */

/*
 * this format is require because a script is used to build the C
 * function that calls all the protocol registration.
*/

void
proto_register_iscsi(void)
{
    module_t *iscsi_module;
    expert_module_t* expert_iscsi;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_iscsi_request_frame,
          { "Request in", "iscsi.request_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
            "Frame number of the request", HFILL }},

        { &hf_iscsi_time,
          { "Time from request", "iscsi.time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "Time between the Command and the Response", HFILL }},

        { &hf_iscsi_r2t_frame,
          { "Ready To Transfer", "iscsi.r2t_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame number of the R2T", HFILL }},

         { &hf_iscsi_r2t_time,
          { "Time from request to R2T", "iscsi.r2t_time",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
            "Time from the client's request to the server's R2T", HFILL }},

        { &hf_iscsi_data_in_frame,
          { "Data In in", "iscsi.data_in_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame number of the final Data In (could be multiple)", HFILL }},

        { &hf_iscsi_data_out_frame,
          { "Final Data Out in", "iscsi.data_out_frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Frame number of the final Data Out (could be multiple)", HFILL }},

        { &hf_iscsi_response_frame,
          { "Response in", "iscsi.response_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
            "Frame number of the response", HFILL }},
        { &hf_iscsi_AHS_length,
          { "AHS Length", "iscsi.ahs.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Length of Additional header segment", HFILL }
        },
        { &hf_iscsi_AHS_read_data_length,
          { "Bidirectional Read Data Length", "iscsi.ahs.bidir.length",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_iscsi_AHS_type,
          { "AHS Type", "iscsi.ahs.type",
            FT_UINT8, BASE_DEC, VALS(ahs_type_vals), 0,
            "Type of Additional header segment", HFILL }
        },
        { &hf_iscsi_AHS_extended_cdb,
          { "AHS Extended CDB", "iscsi.ahs.extended_cdb",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_iscsi_AHS_blob,
          { "Unknown AHS blob", "iscsi.ahs.unknown_blob",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_iscsi_Padding,
          { "Padding", "iscsi.padding",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Padding to 4 byte boundary", HFILL }
        },
        { &hf_iscsi_ping_data,
          { "PingData", "iscsi.pingdata",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Ping Data", HFILL }
        },
        { &hf_iscsi_immediate_data,
          { "ImmediateData", "iscsi.immediatedata",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Immediate Data", HFILL }
        },
        { &hf_iscsi_async_event_data,
          { "AsyncEventData", "iscsi.asynceventdata",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Async Event Data", HFILL }
        },
        { &hf_iscsi_vendor_specific_data,
          { "VendorSpecificData", "iscsi.vendorspecificdata",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Vendor Specific Data", HFILL }
        },
        { &hf_iscsi_HeaderDigest32,
          { "HeaderDigest", "iscsi.headerdigest32",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Header Digest", HFILL }
        },
        { &hf_iscsi_DataDigest32,
          { "DataDigest", "iscsi.datadigest32",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Data Digest", HFILL }
        },
        { &hf_iscsi_Opcode,
          { "Opcode", "iscsi.opcode",
            FT_UINT8, BASE_HEX, VALS(iscsi_opcodes), OPCODE_MASK,
            NULL, HFILL }
        },
/* #ifdef DRAFT08 */
        { &hf_iscsi_X,
          { "X", "iscsi.X",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_X), 0x80,
            "Command Retry", HFILL }
        },
/* #endif */
        { &hf_iscsi_I,
          { "I", "iscsi.I",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_I), 0x40,
            "Immediate delivery", HFILL }
        },
        { &hf_iscsi_Flags,
          { "Flags", "iscsi.flags",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Opcode specific flags", HFILL }
        },
        { &hf_iscsi_SCSICommand_F,
          { "F", "iscsi.scsicommand.F",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,
            "PDU completes command", HFILL }
        },
        { &hf_iscsi_SCSICommand_R,
          { "R", "iscsi.scsicommand.R",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_R), 0x40,
            "Command reads from SCSI target", HFILL }
        },
        { &hf_iscsi_SCSICommand_W,
          { "W", "iscsi.scsicommand.W",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_W), 0x20,
            "Command writes to SCSI target", HFILL }
        },
        { &hf_iscsi_SCSICommand_Attr,
          { "Attr", "iscsi.scsicommand.attr",
            FT_UINT8, BASE_HEX, VALS(iscsi_scsicommand_taskattrs), 0x07,
            "SCSI task attributes", HFILL }
        },
        { &hf_iscsi_SCSICommand_CRN,
          { "CRN", "iscsi.scsicommand.crn",
            FT_UINT8, BASE_HEX, NULL, 0,
            "SCSI command reference number", HFILL }
        },
        { &hf_iscsi_DataSegmentLength,
          { "DataSegmentLength", "iscsi.datasegmentlength",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Data segment length (bytes)", HFILL }
        },
        { &hf_iscsi_TotalAHSLength,
          { "TotalAHSLength", "iscsi.totalahslength",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            "Total additional header segment length (4 byte words)", HFILL }
        },
        { &hf_iscsi_InitiatorTaskTag,
          { "InitiatorTaskTag", "iscsi.initiatortasktag",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Initiator's task tag", HFILL }
        },
        { &hf_iscsi_ExpectedDataTransferLength,
          { "ExpectedDataTransferLength", "iscsi.scsicommand.expecteddatatransferlength",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Expected length of data transfer", HFILL }
        },
        { &hf_iscsi_CmdSN,
          { "CmdSN", "iscsi.cmdsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Sequence number for this command", HFILL }
        },
        { &hf_iscsi_ExpStatSN,
          { "ExpStatSN", "iscsi.expstatsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Next expected status sequence number", HFILL }
        },
        { &hf_iscsi_SCSIResponse_ResidualCount,
          { "ResidualCount", "iscsi.scsiresponse.residualcount",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Residual count", HFILL }
        },
        { &hf_iscsi_StatSN,
          { "StatSN", "iscsi.statsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Status sequence number", HFILL }
        },
        { &hf_iscsi_ExpCmdSN,
          { "ExpCmdSN", "iscsi.expcmdsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Next expected command sequence number", HFILL }
        },
        { &hf_iscsi_MaxCmdSN,
          { "MaxCmdSN", "iscsi.maxcmdsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Maximum acceptable command sequence number", HFILL }
        },
        { &hf_iscsi_SCSIResponse_o,
          { "o", "iscsi.scsiresponse.o",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_o), 0x10,
            "Bi-directional read residual overflow", HFILL }
        },
        { &hf_iscsi_SCSIResponse_u,
          { "u", "iscsi.scsiresponse.u",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_u), 0x08,
            "Bi-directional read residual underflow", HFILL }
        },
        { &hf_iscsi_SCSIResponse_O,
          { "O", "iscsi.scsiresponse.O",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_O), 0x04,
            "Residual overflow", HFILL }
        },
        { &hf_iscsi_SCSIResponse_U,
          { "U", "iscsi.scsiresponse.U",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_U), 0x02,
            "Residual underflow", HFILL }
        },
        { &hf_iscsi_SCSIResponse_Status,
          { "Status", "iscsi.scsiresponse.status",
            FT_UINT8, BASE_HEX, VALS(scsi_status_val), 0,
            "SCSI command status value", HFILL }
        },
        { &hf_iscsi_SCSIResponse_Response,
          { "Response", "iscsi.scsiresponse.response",
            FT_UINT8, BASE_HEX, VALS(iscsi_scsi_responses), 0,
            "SCSI command response value", HFILL }
        },
        { &hf_iscsi_SCSIResponse_BidiReadResidualCount,
          { "BidiReadResidualCount", "iscsi.scsiresponse.bidireadresidualcount",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Bi-directional read residual count", HFILL }
        },
        { &hf_iscsi_SenseLength,
          { "SenseLength", "iscsi.scsiresponse.senselength",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            "Sense data length", HFILL }
        },
        { &hf_iscsi_SCSIData_F,
          { "F", "iscsi.scsidata.F",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), ISCSI_SCSI_DATA_FLAG_F,
            "Final PDU", HFILL }
        },
        { &hf_iscsi_SCSIData_A,
          { "A", "iscsi.scsidata.A",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_A), ISCSI_SCSI_DATA_FLAG_A,
            "Acknowledge Requested", HFILL }
        },
        { &hf_iscsi_SCSIData_S,
          { "S", "iscsi.scsidata.S",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_S), ISCSI_SCSI_DATA_FLAG_S,
            "PDU Contains SCSI command status", HFILL }
        },
        { &hf_iscsi_SCSIData_U,
          { "U", "iscsi.scsidata.U",
            FT_BOOLEAN, 8,  TFS(&iscsi_meaning_U), ISCSI_SCSI_DATA_FLAG_U,
            "Residual underflow", HFILL }
        },
        { &hf_iscsi_SCSIData_O,
          { "O", "iscsi.scsidata.O",
            FT_BOOLEAN, 8,  TFS(&iscsi_meaning_O), ISCSI_SCSI_DATA_FLAG_O,
            "Residual overflow", HFILL }
        },
        { &hf_iscsi_TargetTransferTag,
          { "TargetTransferTag", "iscsi.targettransfertag",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Target transfer tag", HFILL }
        },
        { &hf_iscsi_BufferOffset,
          { "BufferOffset", "iscsi.bufferOffset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Buffer offset", HFILL }
        },
        { &hf_iscsi_SCSIData_ResidualCount,
          { "ResidualCount", "iscsi.scsidata.readresidualcount",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Residual count", HFILL }
        },
        { &hf_iscsi_DataSN,
          { "DataSN", "iscsi.datasn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Data sequence number", HFILL }
        },
        { &hf_iscsi_VersionMax,
          { "VersionMax", "iscsi.versionmax",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Maximum supported protocol version", HFILL }
        },
        { &hf_iscsi_VersionMin,
          { "VersionMin", "iscsi.versionmin",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Minimum supported protocol version", HFILL }
        },
        { &hf_iscsi_VersionActive,
          { "VersionActive", "iscsi.versionactive",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Negotiated protocol version", HFILL }
        },
        { &hf_iscsi_CID,
          { "CID", "iscsi.cid",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Connection identifier", HFILL }
        },
/* #ifdef DRAFT08 */
        { &hf_iscsi_ISID8,
          { "ISID", "iscsi.isid8",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Initiator part of session identifier", HFILL }
        },
/* #else */
        { &hf_iscsi_ISID,
          { "ISID", "iscsi.isid",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Initiator part of session identifier", HFILL }
        },
/* #ifdef DRAFT09 */
        { &hf_iscsi_ISID_Type,
          { "ISID_Type", "iscsi.isid.type",
            FT_UINT8, BASE_HEX, VALS(iscsi_isid_type), 0,
            "Initiator part of session identifier - type", HFILL }
        },
        { &hf_iscsi_ISID_NamingAuthority,
          { "ISID_NamingAuthority", "iscsi.isid.namingauthority",
            FT_UINT24, BASE_HEX, NULL, 0,
            "Initiator part of session identifier - naming authority", HFILL }
        },
        { &hf_iscsi_ISID_Qualifier,
          { "ISID_Qualifier", "iscsi.isid.qualifier",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Initiator part of session identifier - qualifier", HFILL }
        },
/* #else */
        { &hf_iscsi_ISID_t,
          { "ISID_t", "iscsi.isid.t",
            FT_UINT8, BASE_HEX, VALS(iscsi_isid_type), 0xc0,
            "Initiator part of session identifier - t", HFILL }
        },
        { &hf_iscsi_ISID_a,
          { "ISID_a", "iscsi.isid.a",
            FT_UINT8, BASE_HEX, NULL, 0x3f,
            "Initiator part of session identifier - a", HFILL }
        },
        { &hf_iscsi_ISID_b,
          { "ISID_b", "iscsi.isid.b",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Initiator part of session identifier - b", HFILL }
        },
        { &hf_iscsi_ISID_c,
          { "ISID_c", "iscsi.isid.c",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Initiator part of session identifier - c", HFILL }
        },
        { &hf_iscsi_ISID_d,
          { "ISID_d", "iscsi.isid.d",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Initiator part of session identifier - d", HFILL }
        },
/* #endif */
/* #endif */
        { &hf_iscsi_TSID,
          { "TSID", "iscsi.tsid",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Target part of session identifier", HFILL }
        },
        { &hf_iscsi_TSIH,
          { "TSIH", "iscsi.tsih",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Target session identifying handle", HFILL }
        },
        { &hf_iscsi_Login_T,
          { "T", "iscsi.login.T",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_T), 0x80,
            "Transit to next login stage",  HFILL }
        },
        { &hf_iscsi_Login_C,
          { "C", "iscsi.login.C",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_C), 0x40,
            "Text incomplete",  HFILL }
        },
/* #ifdef DRAFT09 */
        { &hf_iscsi_Login_X,
          { "X", "iscsi.login.X",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_login_X), 0x40,
            "Restart Connection",  HFILL }
        },
/* #endif */
        { &hf_iscsi_Login_CSG,
          { "CSG", "iscsi.login.csg",
            FT_UINT8, BASE_HEX, VALS(iscsi_login_stage), CSG_MASK,
            "Current stage",  HFILL }
        },
        { &hf_iscsi_Login_NSG,
          { "NSG", "iscsi.login.nsg",
            FT_UINT8, BASE_HEX, VALS(iscsi_login_stage), NSG_MASK,
            "Next stage",  HFILL }
        },
        { &hf_iscsi_Login_Status,
          { "Status", "iscsi.login.status",
            FT_UINT16, BASE_HEX, VALS(iscsi_login_status), 0,
            "Status class and detail", HFILL }
        },
        { &hf_iscsi_Login_Chap_A,
          { "CHAP_A", "iscsi.login.chap_a",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(chap_alg_rvals),
                0x0, "Authentication algorithm", HFILL }},
        { &hf_iscsi_Login_Chap_C,
          { "CHAP_C", "iscsi.login.chap_c",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Challenge", HFILL }},
        { &hf_iscsi_Login_Chap_I,
          { "CHAP_I", "iscsi.login.chap_i",
            FT_UINT8, BASE_DEC, NULL,
                0x0, "Identifier", HFILL }},
        { &hf_iscsi_Login_Chap_N,
          { "CHAP_N", "iscsi.login.chap_n",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Name", HFILL }},
        { &hf_iscsi_Login_Chap_R,
          { "CHAP_R", "iscsi.login.chap_r",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Response", HFILL }},
        { &hf_iscsi_Login_SessionType,
          { "Session Type", "iscsi.login.session_type",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_AuthMethod,
          { "Auth Method", "iscsi.login.auth_method",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Authentication methods offered/accepted", HFILL }},
        { &hf_iscsi_Login_InitiatorName,
          { "Initiator Name", "iscsi.login.initiator_name",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_SendTargets,
          { "Send Targets", "iscsi.login.send_targets",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_TargetAlias,
          { "Target Alias", "iscsi.login.target_alias",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_TargetName,
          { "Target Name", "iscsi.login.target_name",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_TargetAddress,
          { "Target Address", "iscsi.login.target_address",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_HeaderDigest,
          { "Header Digest", "iscsi.login.header_digest",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_DataDigest,
          { "Data Digest", "iscsi.login.data_digest",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_InitialR2T,
          { "Initial R2T", "iscsi.login.initialr2t",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_ImmediateData,
          { "Immediate Data", "iscsi.login.immediate_data",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_IFMarker,
          { "IF Marker", "iscsi.login.if_marker",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Target to Initiator Marker", HFILL }},
        { &hf_iscsi_Login_OFMarker,
          { "OF Marker", "iscsi.login.of_marker",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, "Initiator to Target Marker", HFILL }},
        { &hf_iscsi_Login_DataPDUInOrder,
          { "Data Pdu In Order", "iscsi.login.data_pdu_in_order",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_DataSequenceInOrder,
          { "Data Sequence In Order", "iscsi.login.data_sequence_in_order",
            FT_STRINGZ, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_TargetPortalGroupTag,
          { "Target Portal Group Tag", "iscsi.login.target_portal_group_tag",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_MaxBurstLength,
          { "Max Burst Length", "iscsi.login.max_burst_length",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_FirstBurstLength,
          { "First Burst Length", "iscsi.login.first_burst_length",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_DefaultTime2Wait,
          { "Default Time To Wait", "iscsi.login.default_time_to_wait",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_DefaultTime2Retain,
          { "Default Time To Retain", "iscsi.login.default_time_to_retain",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_MaxOutstandingR2T,
          { "Max Outstanding R2T", "iscsi.login.max_outstanding_r2t",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_ErrorRecoveryLevel,
          { "Error Recovery Level", "iscsi.error_recovery_level",
            FT_UINT8, BASE_DEC, VALS(error_recovery_level_vals),
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_MaxConnections,
          { "Max Connections", "iscsi.login.max_connections",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_Login_MaxRecvDataSegmentLength,
          { "Max Recv Data Segment Length", "iscsi.login.max_recv_data_segment_length",
            FT_UINT8, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_iscsi_KeyValue,
          { "KeyValue", "iscsi.keyvalue",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Key/value pair", HFILL }
        },
        { &hf_iscsi_Text_F,
          { "F", "iscsi.text.F",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_F), 0x80,
            "Final PDU in text sequence", HFILL }
        },
        { &hf_iscsi_Text_C,
          { "C", "iscsi.text.C",
            FT_BOOLEAN, 8, TFS(&iscsi_meaning_C), 0x40,
            "Text incomplete", HFILL }
        },
        { &hf_iscsi_ExpDataSN,
          { "ExpDataSN", "iscsi.expdatasn",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Next expected data sequence number", HFILL }
        },
        { &hf_iscsi_R2TSN,
          { "R2TSN", "iscsi.r2tsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "R2T PDU Number", HFILL }
        },
        { &hf_iscsi_TaskManagementFunction_Response,
          { "Response", "iscsi.taskmanfun.response",
            FT_UINT8, BASE_HEX, VALS(iscsi_task_management_responses), 0,
            NULL, HFILL }
        },
        { &hf_iscsi_TaskManagementFunction_ReferencedTaskTag,
          { "ReferencedTaskTag", "iscsi.taskmanfun.referencedtasktag",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Referenced task tag", HFILL }
        },
        { &hf_iscsi_RefCmdSN,
          { "RefCmdSN", "iscsi.refcmdsn",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Command sequence number for command to be aborted", HFILL }
        },
        { &hf_iscsi_TaskManagementFunction_Function,
          { "Function", "iscsi.taskmanfun.function",
            FT_UINT8, BASE_HEX, VALS(iscsi_task_management_functions), 0x7F,
            "Requested task function", HFILL }
        },
        { &hf_iscsi_Logout_Reason,
          { "Reason", "iscsi.logout.reason",
            FT_UINT8, BASE_HEX, VALS(iscsi_logout_reasons), 0x7F,
            "Reason for logout", HFILL }
        },
        { &hf_iscsi_Logout_Response,
          { "Response", "iscsi.logout.response",
            FT_UINT8, BASE_HEX, VALS(iscsi_logout_response), 0,
            "Logout response", HFILL }
        },
        { &hf_iscsi_Time2Wait,
          { "Time2Wait", "iscsi.time2wait",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_iscsi_Time2Retain,
          { "Time2Retain", "iscsi.time2retain",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_iscsi_DesiredDataLength,
          { "DesiredDataLength", "iscsi.desireddatalength",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Desired data length (bytes)", HFILL }
        },
        { &hf_iscsi_AsyncEvent,
          { "AsyncEvent", "iscsi.asyncevent",
            FT_UINT8, BASE_HEX, VALS(iscsi_asyncevents), 0,
            "Async event type", HFILL }
        },
        { &hf_iscsi_EventVendorCode,
          { "EventVendorCode", "iscsi.eventvendorcode",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Event vendor code", HFILL }
        },
        { &hf_iscsi_Parameter1,
          { "Parameter1", "iscsi.parameter1",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Parameter 1", HFILL }
        },
        { &hf_iscsi_Parameter2,
          { "Parameter2", "iscsi.parameter2",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Parameter 2", HFILL }
        },
        { &hf_iscsi_Parameter3,
          { "Parameter3", "iscsi.parameter3",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Parameter 3", HFILL }
        },
        { &hf_iscsi_Reject_Reason,
          { "Reason", "iscsi.reject.reason",
            FT_UINT8, BASE_HEX, VALS(iscsi_reject_reasons), 0,
            "Reason for command rejection", HFILL }
        },
        { &hf_iscsi_snack_type,
          { "S", "iscsi.snack.type",
            FT_UINT8, BASE_DEC, VALS(iscsi_snack_types), 0x0f,
            "Type of SNACK requested", HFILL }
        },
        { &hf_iscsi_BegRun,
          { "BegRun", "iscsi.snack.begrun",
            FT_UINT32, BASE_HEX, NULL, 0,
            "First missed DataSN or StatSN", HFILL }
        },
        { &hf_iscsi_RunLength,
          { "RunLength", "iscsi.snack.runlength",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "Number of additional missing status PDUs in this run", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_iscsi,
        &ett_iscsi_KeyValue,
        &ett_iscsi_KeyValues,
        &ett_iscsi_CDB,
        &ett_iscsi_Flags,
        &ett_iscsi_RejectHeader,
        &ett_iscsi_lun,
/* #ifndef DRAFT08 */
        &ett_iscsi_ISID,
/* #endif */
    };

    static ei_register_info ei[] = {
        { &ei_iscsi_keyvalue_invalid, { "iscsi.keyvalue.invalid", PI_MALFORMED, PI_ERROR,
            "Invalid key/value pair", EXPFILL }},
        { &ei_iscsi_opcode_invalid, { "iscsi.opcode.invalid", PI_MALFORMED, PI_ERROR,
            "Invalid opcode", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_iscsi = proto_register_protocol("iSCSI", "iSCSI", "iscsi");
    iscsi_handle = register_dissector("iscsi", dissect_iscsi_handle, proto_iscsi);

    /* Required function calls to register the header fields and
     * subtrees used */
    proto_register_field_array(proto_iscsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    iscsi_module = prefs_register_protocol(proto_iscsi, NULL);

    prefs_register_enum_preference(iscsi_module,
                                   "protocol_version",
                                   "Protocol version",
                                   "The iSCSI protocol version",
                                   &iscsi_protocol_version,
                                   iscsi_protocol_versions,
                                   false);

    prefs_register_bool_preference(iscsi_module,
                                   "desegment_iscsi_messages",
                                   "Reassemble iSCSI messages spanning multiple TCP segments",
                                   "Whether the iSCSI dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &iscsi_desegment);

    prefs_register_bool_preference(iscsi_module,
                                   "bogus_pdu_filter",
                                   "Enable bogus pdu filter",
                                   "When enabled, packets that appear bogus are ignored",
                                   &enable_bogosity_filter);

    prefs_register_bool_preference(iscsi_module,
                                   "demand_good_f_bit",
                                   "Ignore packets with bad F bit",
                                   "Ignore packets that haven't set the F bit when they should have",
                                   &demand_good_f_bit);

    prefs_register_uint_preference(iscsi_module,
                                   "bogus_pdu_max_data_len",
                                   "Bogus pdu max data length threshold",
                                   "Treat packets whose data segment length is greater than this value as bogus",
                                   10,
                                   &bogus_pdu_data_length_threshold);

    range_convert_str(wmem_epan_scope(), &global_iscsi_port_range, TCP_PORT_ISCSI_RANGE, MAX_TCP_PORT);
    prefs_register_range_preference(iscsi_module,
                                    "target_ports",
                                    "Target Ports Range",
                                    "Range of iSCSI target ports"
                                    "(default " TCP_PORT_ISCSI_RANGE ")",
                                    &global_iscsi_port_range, MAX_TCP_PORT);

    prefs_register_uint_preference(iscsi_module,
                                   "target_system_port",
                                   "Target system port",
                                   "System port number of iSCSI target",
                                   10,
                                   &iscsi_system_port);

    /* Preference supported in older versions.
       Register them as obsolete. */
    prefs_register_obsolete_preference(iscsi_module,
                                       "version_03_compatible");
    prefs_register_obsolete_preference(iscsi_module,
                                       "bogus_pdu_max_digest_padding");
    prefs_register_obsolete_preference(iscsi_module,
                                       "header_digest_is_crc32c");
    prefs_register_obsolete_preference(iscsi_module,
                                       "header_digest_size");
    prefs_register_obsolete_preference(iscsi_module,
                                       "enable_header_digests");
    prefs_register_obsolete_preference(iscsi_module,
                                       "data_digest_is_crc32c");
    prefs_register_obsolete_preference(iscsi_module,
                                       "data_digest_size");
    prefs_register_obsolete_preference(iscsi_module,
                                       "enable_data_digests");

    expert_iscsi = expert_register_protocol(proto_iscsi);
    expert_register_field_array(expert_iscsi, ei, array_length(ei));
}


/*
 * If this dissector uses sub-dissector registration add a
 * registration routine.
 */

/*
 * This format is required because a script is used to find these
 * routines and create the code that calls these routines.
 */
void
proto_reg_handoff_iscsi(void)
{
    heur_dissector_add("tcp", dissect_iscsi_heur, "iSCSI over TCP", "iscsi_tcp", proto_iscsi, HEURISTIC_ENABLE);

    dissector_add_for_decode_as_with_preference("tcp.port", iscsi_handle);
}

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
