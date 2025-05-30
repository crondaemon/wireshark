/* Do not modify this file. Changes will be overwritten */
/* Generated Automatically                              */
/* packet-skinny.c                                      */

/* packet-skinny.c
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 *
 * Author: Diederik de Groot <ddegroot@user.sf.net>, Copyright 2014
 * Rewritten to support newer skinny protocolversions (V0-V22)
 * Based on previous versions/contributions:
 *  - Joerg Mayer <jmayer@loplof.de>, Copyright 2001
 *  - Paul E. Erkkila (pee@erkkila.org) - fleshed out the decode
 *    skeleton to report values for most message/message fields.
 *    Much help from Guy Harris on figuring out the wireshark api.
 *  - packet-aim.c by Ralf Hoelzer <ralf@well.com>, Copyright 2000
 *  - Wireshark - Network traffic analyzer,
 *    By Gerald Combs <gerald@wireshark.org>, Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Generated automatically Using (from wireshark base directory):
 *   cog.py -D xmlfile=tools/SkinnyProtocolOptimized.xml -d -c -o epan/dissectors/packet-skinny.c epan/dissectors/packet-skinny.c.in
 */

/* c-basic-offset: 2; tab-width: 8; indent-tabs-mode: nil
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include <epan/ptvcursor.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-rtp.h"
#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-skinny.h"

/* un-comment the following as well as this line in conversation.c, to enable debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

void proto_register_skinny(void);
void proto_reg_handoff_skinny(void);

#define TCP_PORT_SKINNY 2000 /* Not IANA registered */
#define SSL_PORT_SKINNY 2443 /* IANA assigned to PowerClient Central Storage Facility */

#define BASIC_MSG_TYPE 0x00
#define V10_MSG_TYPE 0x0A
#define V11_MSG_TYPE 0x0B
#define V15_MSG_TYPE 0x0F
#define V16_MSG_TYPE 0x10
#define V17_MSG_TYPE 0x11
#define V18_MSG_TYPE 0x12
#define V19_MSG_TYPE 0x13
#define V20_MSG_TYPE 0x14
#define V21_MSG_TYPE 0x15
#define V22_MSG_TYPE 0x16

static const value_string header_version[] = {
  { BASIC_MSG_TYPE, "Basic" },
  { V10_MSG_TYPE,   "V10" },
  { V11_MSG_TYPE,   "V11" },
  { V15_MSG_TYPE,   "V15" },
  { V16_MSG_TYPE,   "V16" },
  { V17_MSG_TYPE,   "V17" },
  { V18_MSG_TYPE,   "V18" },
  { V19_MSG_TYPE,   "V19" },
  { V20_MSG_TYPE,   "V20" },
  { V21_MSG_TYPE,   "V21" },
  { V22_MSG_TYPE,   "V22" },
  { 0             , NULL }
};

/* Declare MessageId */
static const value_string message_id[] = {
  { 0x0000, "KeepAliveReq" },
  { 0x0001, "RegisterReq" },
  { 0x0002, "IpPort" },
  { 0x0003, "KeypadButton" },
  { 0x0004, "EnblocCall" },
  { 0x0005, "Stimulus" },
  { 0x0006, "OffHook" },
  { 0x0007, "OnHook" },
  { 0x0008, "HookFlash" },
  { 0x0009, "ForwardStatReq" },
  { 0x000a, "SpeedDialStatReq" },
  { 0x000b, "LineStatReq" },
  { 0x000c, "ConfigStatReq" },
  { 0x000d, "TimeDateReq" },
  { 0x000e, "ButtonTemplateReq" },
  { 0x000f, "VersionReq" },
  { 0x0010, "CapabilitiesRes" },
  { 0x0012, "ServerReq" },
  { 0x0020, "Alarm" },
  { 0x0021, "MulticastMediaReceptionAck" },
  { 0x0022, "OpenReceiveChannelAck" },
  { 0x0023, "ConnectionStatisticsRes" },
  { 0x0024, "OffHookWithCallingPartyNumber" },
  { 0x0025, "SoftKeySetReq" },
  { 0x0026, "SoftKeyEvent" },
  { 0x0027, "UnregisterReq" },
  { 0x0028, "SoftKeyTemplateReq" },
  { 0x0029, "RegisterTokenReq" },
  { 0x002a, "MediaTransmissionFailure" },
  { 0x002b, "HeadsetStatus" },
  { 0x002c, "MediaResourceNotification" },
  { 0x002d, "RegisterAvailableLines" },
  { 0x002e, "DeviceToUserData" },
  { 0x002f, "DeviceToUserDataResponse" },
  { 0x0030, "UpdateCapabilities" },
  { 0x0031, "OpenMultiMediaReceiveChannelAck" },
  { 0x0032, "ClearConference" },
  { 0x0033, "ServiceURLStatReq" },
  { 0x0034, "FeatureStatReq" },
  { 0x0035, "CreateConferenceRes" },
  { 0x0036, "DeleteConferenceRes" },
  { 0x0037, "ModifyConferenceRes" },
  { 0x0038, "AddParticipantRes" },
  { 0x0039, "AuditConferenceRes" },
  { 0x0040, "AuditParticipantRes" },
  { 0x0041, "DeviceToUserDataVersion1" },
  { 0x0042, "DeviceToUserDataResponseVersion1" },
  { 0x0043, "CapabilitiesV2Res" },
  { 0x0044, "CapabilitiesV3Res" },
  { 0x0045, "PortRes" },
  { 0x0046, "QoSResvNotify" },
  { 0x0047, "QoSErrorNotify" },
  { 0x0048, "SubscriptionStatReq" },
  { 0x0049, "MediaPathEvent" },
  { 0x004a, "MediaPathCapability" },
  { 0x004c, "MwiNotification" },
  { 0x0081, "RegisterAck" },
  { 0x0082, "StartTone" },
  { 0x0083, "StopTone" },
  { 0x0085, "SetRinger" },
  { 0x0086, "SetLamp" },
  { 0x0087, "SetHookFlashDetect" },
  { 0x0088, "SetSpeakerMode" },
  { 0x0089, "SetMicroMode" },
  { 0x008a, "StartMediaTransmission" },
  { 0x008b, "StopMediaTransmission" },
  { 0x008f, "CallInfo" },
  { 0x0090, "ForwardStatRes" },
  { 0x0091, "SpeedDialStatRes" },
  { 0x0092, "LineStatRes" },
  { 0x0093, "ConfigStatRes" },
  { 0x0094, "TimeDateRes" },
  { 0x0095, "StartSessionTransmission" },
  { 0x0096, "StopSessionTransmission" },
  { 0x0097, "ButtonTemplateRes" },
  { 0x0098, "VersionRes" },
  { 0x0099, "DisplayText" },
  { 0x009a, "ClearDisplay" },
  { 0x009b, "CapabilitiesReq" },
  { 0x009d, "RegisterReject" },
  { 0x009e, "ServerRes" },
  { 0x009f, "Reset" },
  { 0x0100, "KeepAliveAck" },
  { 0x0101, "StartMulticastMediaReception" },
  { 0x0102, "StartMulticastMediaTransmission" },
  { 0x0103, "StopMulticastMediaReception" },
  { 0x0104, "StopMulticastMediaTransmission" },
  { 0x0105, "OpenReceiveChannel" },
  { 0x0106, "CloseReceiveChannel" },
  { 0x0107, "ConnectionStatisticsReq" },
  { 0x0108, "SoftKeyTemplateRes" },
  { 0x0109, "SoftKeySetRes" },
  { 0x0110, "SelectSoftKeys" },
  { 0x0111, "CallState" },
  { 0x0112, "DisplayPromptStatus" },
  { 0x0113, "ClearPromptStatus" },
  { 0x0114, "DisplayNotify" },
  { 0x0115, "ClearNotify" },
  { 0x0116, "ActivateCallPlane" },
  { 0x0117, "DeactivateCallPlane" },
  { 0x0118, "UnregisterAck" },
  { 0x0119, "BackSpaceRes" },
  { 0x011a, "RegisterTokenAck" },
  { 0x011b, "RegisterTokenReject" },
  { 0x011c, "StartMediaFailureDetection" },
  { 0x011d, "DialedNumber" },
  { 0x011e, "UserToDeviceData" },
  { 0x011f, "FeatureStatRes" },
  { 0x0120, "DisplayPriNotify" },
  { 0x0121, "ClearPriNotify" },
  { 0x0122, "StartAnnouncement" },
  { 0x0123, "StopAnnouncement" },
  { 0x0124, "AnnouncementFinish" },
  { 0x0127, "NotifyDtmfTone" },
  { 0x0128, "SendDtmfTone" },
  { 0x0129, "SubscribeDtmfPayloadReq" },
  { 0x012a, "SubscribeDtmfPayloadRes" },
  { 0x012b, "SubscribeDtmfPayloadErr" },
  { 0x012c, "UnSubscribeDtmfPayloadReq" },
  { 0x012d, "UnSubscribeDtmfPayloadRes" },
  { 0x012e, "UnSubscribeDtmfPayloadErr" },
  { 0x012f, "ServiceURLStatRes" },
  { 0x0130, "CallSelectStatRes" },
  { 0x0131, "OpenMultiMediaReceiveChannel" },
  { 0x0132, "StartMultiMediaTransmission" },
  { 0x0133, "StopMultiMediaTransmission" },
  { 0x0134, "MiscellaneousCommand" },
  { 0x0135, "FlowControlCommand" },
  { 0x0136, "CloseMultiMediaReceiveChannel" },
  { 0x0137, "CreateConferenceReq" },
  { 0x0138, "DeleteConferenceReq" },
  { 0x0139, "ModifyConferenceReq" },
  { 0x013a, "AddParticipantReq" },
  { 0x013b, "DropParticipantReq" },
  { 0x013c, "AuditConferenceReq" },
  { 0x013d, "AuditParticipantReq" },
  { 0x013e, "ChangeParticipantReq" },
  { 0x013f, "UserToDeviceDataVersion1" },
  { 0x0140, "VideoDisplayCommand" },
  { 0x0141, "FlowControlNotify" },
  { 0x0142, "ConfigStatV2Res" },
  { 0x0143, "DisplayNotifyV2" },
  { 0x0144, "DisplayPriNotifyV2" },
  { 0x0145, "DisplayPromptStatusV2" },
  { 0x0146, "FeatureStatV2Res" },
  { 0x0147, "LineStatV2Res" },
  { 0x0148, "ServiceURLStatV2Res" },
  { 0x0149, "SpeedDialStatV2Res" },
  { 0x014a, "CallInfoV2" },
  { 0x014b, "PortReq" },
  { 0x014c, "PortClose" },
  { 0x014d, "QoSListen" },
  { 0x014e, "QoSPath" },
  { 0x014f, "QoSTeardown" },
  { 0x0150, "UpdateDSCP" },
  { 0x0151, "QoSModify" },
  { 0x0152, "SubscriptionStatRes" },
  { 0x0153, "Notification" },
  { 0x0154, "StartMediaTransmissionAck" },
  { 0x0155, "StartMultiMediaTransmissionAck" },
  { 0x0156, "CallHistoryInfo" },
  { 0x0157, "LocationInfo" },
  { 0x0158, "MwiRes" },
  { 0x0159, "AddOnDeviceCapabilities" },
  { 0x015a, "EnhancedAlarm" },
  { 0x015e, "CallCountReq" },
  { 0x015f, "CallCountResp" },
  { 0x0160, "RecordingStatus" },
  { 0x8000, "SPCPRegisterTokenReq" },
  { 0x8100, "SPCPRegisterTokenAck" },
  { 0x8101, "SPCPRegisterTokenReject" },
  {0     , NULL}
};
static value_string_ext message_id_ext = VALUE_STRING_EXT_INIT(message_id);

/* Declare Enums and Defines */
static const value_string DisplayLabels_36[] = {
  { 0x00000, "Empty" },
  { 0x00002, "Acct" },
  { 0x00003, "Flash" },
  { 0x00004, "Login" },
  { 0x00005, "Device In Home Location" },
  { 0x00006, "Device In Roaming Location" },
  { 0x00007, "Enter Authorization Code" },
  { 0x00008, "Enter Client Matter Code" },
  { 0x00009, "Calls Available For Pickup" },
  { 0x0000a, "Cm Fallback Service Operating" },
  { 0x0000b, "Max Phones Exceeded" },
  { 0x0000c, "Waiting To Rehome" },
  { 0x0000d, "Please End Call" },
  { 0x0000e, "Paging" },
  { 0x0000f, "Select Line" },
  { 0x00010, "Transfer Destination Is Busy" },
  { 0x00011, "Select A Service" },
  { 0x00012, "Local Services" },
  { 0x00013, "Enter Search Criteria" },
  { 0x00014, "Night Service" },
  { 0x00015, "Night Service Active" },
  { 0x00016, "Night Service Disabled" },
  { 0x00017, "Login Successful" },
  { 0x00018, "Wrong Pin" },
  { 0x00019, "Please Enter Pin" },
  { 0x0001a, "Of" },
  { 0x0001b, "Records 1 To" },
  { 0x0001c, "No Record Found" },
  { 0x0001d, "Search Results" },
  { 0x0001e, "Calls In Queue" },
  { 0x0001f, "Join To Hunt Group" },
  { 0x00020, "Ready" },
  { 0x00021, "Notready" },
  { 0x00022, "Call On Hold" },
  { 0x00023, "Hold Reversion" },
  { 0x00024, "Setup Failed" },
  { 0x00025, "No Resources" },
  { 0x00026, "Device Not Authorized" },
  { 0x00027, "Monitoring" },
  { 0x00028, "Recording Awaiting Call To Be Active" },
  { 0x00029, "Recording Already In Progress" },
  { 0x0002a, "Inactive Recording Session" },
  { 0x0002b, "Mobility" },
  { 0x0002c, "Whisper" },
  { 0x0002d, "Forward All" },
  { 0x0002e, "Malicious Call Id" },
  { 0x0002f, "Group Pickup" },
  { 0x00030, "Remove Last Participant" },
  { 0x00031, "Other Pickup" },
  { 0x00032, "Video" },
  { 0x00033, "End Call" },
  { 0x00034, "Conference List" },
  { 0x00035, "Quality Reporting Tool" },
  { 0x00036, "Hunt Group" },
  { 0x00037, "Use Line Or Join To Complete" },
  { 0x00038, "Do Not Disturb" },
  { 0x00039, "Do Not Disturb Is Active" },
  { 0x0003a, "Cfwdall Loop Detected" },
  { 0x0003b, "Cfwdall Hops Exceeded" },
  { 0x0003c, "Abbrdial" },
  { 0x0003d, "Pickup Is Unavailable" },
  { 0x0003e, "Conference Is Unavailable" },
  { 0x0003f, "Meetme Is Unavailable" },
  { 0x00040, "Cannot Retrieve Parked Call" },
  { 0x00041, "Cannot Send Call To Mobile" },
  { 0x00043, "Record" },
  { 0x00044, "Cannot Move Conversation" },
  { 0x00045, "Cw Off" },
  { 0x00046, "Coaching" },
  { 0x0004f, "Recording" },
  { 0x00050, "Recording Failed" },
  { 0x00051, "Connecting" },
  { 0x00000, NULL }
};
static value_string_ext DisplayLabels_36_ext = VALUE_STRING_EXT_INIT(DisplayLabels_36);

static const value_string DisplayLabels_200[] = {
  { 0x00001, "Redial" },
  { 0x00002, "Newcall" },
  { 0x00003, "Hold" },
  { 0x00004, "Transfer" },
  { 0x00005, "Cfwdall" },
  { 0x00006, "Cfwdbusy" },
  { 0x00007, "Cfwdnoanswer" },
  { 0x00008, "Backspace" },
  { 0x00009, "Endcall" },
  { 0x0000a, "Resume" },
  { 0x0000b, "Answer" },
  { 0x0000c, "Info" },
  { 0x0000d, "Confrn" },
  { 0x0000e, "Park" },
  { 0x0000f, "Join" },
  { 0x00010, "Meetme" },
  { 0x00011, "Pickup" },
  { 0x00012, "Gpickup" },
  { 0x00013, "Your Current Options" },
  { 0x00014, "Off Hook" },
  { 0x00015, "On Hook" },
  { 0x00016, "Ring Out" },
  { 0x00017, "From " },
  { 0x00018, "Connected" },
  { 0x00019, "Busy" },
  { 0x0001a, "Line In Use" },
  { 0x0001b, "Call Waiting" },
  { 0x0001c, "Call Transfer" },
  { 0x0001d, "Call Park" },
  { 0x0001e, "Call Proceed" },
  { 0x0001f, "In Use Remote" },
  { 0x00020, "Enter Number" },
  { 0x00021, "Call Park At" },
  { 0x00022, "Primary Only" },
  { 0x00023, "Temp Fail" },
  { 0x00024, "You Have Voicemail" },
  { 0x00025, "Forwarded To" },
  { 0x00026, "Can Not Complete Conference" },
  { 0x00027, "No Conference Bridge" },
  { 0x00028, "Can Not Hold Primary Control" },
  { 0x00029, "Invalid Conference Participant" },
  { 0x0002a, "In Conference Already" },
  { 0x0002b, "No Participant Info" },
  { 0x0002c, "Exceed Maximum Parties" },
  { 0x0002d, "Key Is Not Active" },
  { 0x0002e, "Error No License" },
  { 0x0002f, "Error Dbconfig" },
  { 0x00030, "Error Database" },
  { 0x00031, "Error Pass Limit" },
  { 0x00032, "Error Unknown" },
  { 0x00033, "Error Mismatch" },
  { 0x00034, "Conference" },
  { 0x00035, "Park Number" },
  { 0x00036, "Private" },
  { 0x00037, "Not Enough Bandwidth" },
  { 0x00038, "Unknown Number" },
  { 0x00039, "Rmlstc" },
  { 0x0003a, "Voicemail" },
  { 0x0003b, "Immdiv" },
  { 0x0003c, "Intrcpt" },
  { 0x0003d, "Setwtch" },
  { 0x0003e, "Trnsfvm" },
  { 0x0003f, "Dnd" },
  { 0x00040, "Divall" },
  { 0x00041, "Callback" },
  { 0x00042, "Network Congestion Rerouting" },
  { 0x00043, "Barge" },
  { 0x00044, "Failed To Setup Barge" },
  { 0x00045, "Another Barge Exists" },
  { 0x00046, "Incompatible Device Type" },
  { 0x00047, "No Park Number Available" },
  { 0x00048, "Callpark Reversion" },
  { 0x00049, "Service Is Not Active" },
  { 0x0004a, "High Traffic Try Again Later" },
  { 0x0004b, "Qrt" },
  { 0x0004c, "Mcid" },
  { 0x0004d, "Dirtrfr" },
  { 0x0004e, "Select" },
  { 0x0004f, "Conflist" },
  { 0x00050, "Idivert" },
  { 0x00051, "Cbarge" },
  { 0x00052, "Can Not Complete Transfer" },
  { 0x00053, "Can Not Join Calls" },
  { 0x00054, "Mcid Successful" },
  { 0x00055, "Number Not Configured" },
  { 0x00056, "Security Error" },
  { 0x00057, "Video Bandwidth Unavailable" },
  { 0x00058, "Vidmode" },
  { 0x00059, "Max Call Duration Timeout" },
  { 0x0005a, "Max Hold Duration Timeout" },
  { 0x0005b, "Opickup" },
  { 0x0005c, "Hlog" },
  { 0x0005d, "Logged Out Of Hunt Group" },
  { 0x0005e, "Park Slot Unavailable" },
  { 0x0005f, "No Call Available For Pickup" },
  { 0x00061, "External Transfer Restricted" },
  { 0x00062, "No Line Available For Pickup" },
  { 0x00063, "Path Replacement In Progress" },
  { 0x00064, "Unknown 2" },
  { 0x00065, "Mac Address" },
  { 0x00066, "Host Name" },
  { 0x00067, "Domain Name" },
  { 0x00068, "Ip Address" },
  { 0x00069, "Subnet Mask" },
  { 0x0006a, "Tftp Server 1" },
  { 0x0006b, "Default Router 1" },
  { 0x0006c, "Default Router 2" },
  { 0x0006d, "Default Router 3" },
  { 0x0006e, "Default Router 4" },
  { 0x0006f, "Default Router 5" },
  { 0x00070, "Dns Server 1" },
  { 0x00071, "Dns Server 2" },
  { 0x00072, "Dns Server 3" },
  { 0x00073, "Dns Server 4" },
  { 0x00074, "Dns Server 5" },
  { 0x00075, "Operational Vlan Id" },
  { 0x00076, "Admin Vlan Id" },
  { 0x00077, "Call Manager 1" },
  { 0x00078, "Call Manager 2" },
  { 0x00079, "Call Manager 3" },
  { 0x0007a, "Call Manager 4" },
  { 0x0007b, "Call Manager 5" },
  { 0x0007c, "Information Url" },
  { 0x0007d, "Directories Url" },
  { 0x0007e, "Messages Url" },
  { 0x0007f, "Services Url" },
  { 0x00000, NULL }
};
static value_string_ext DisplayLabels_200_ext = VALUE_STRING_EXT_INIT(DisplayLabels_200);

static const value_string DeviceType[] = {
  { 0x00001, "Station30SPplus" },
  { 0x00002, "Station12SPplus" },
  { 0x00003, "Station12SP" },
  { 0x00004, "Station12" },
  { 0x00005, "Station30VIP" },
  { 0x00006, "Cisco 7910" },
  { 0x00007, "StationTelecasterMgr" },
  { 0x00008, "Cisco 7940" },
  { 0x00009, "Cisco 7935" },
  { 0x0000a, "StationVGC" },
  { 0x0000b, "VGCVirtualPhone" },
  { 0x0000c, "StationATA186" },
  { 0x0000d, "StationATA188" },
  { 0x0000f, "EmccBase" },
  { 0x00014, "Virtual30SPplus" },
  { 0x00015, "StationPhoneApplication" },
  { 0x0001e, "AnalogAccess" },
  { 0x00028, "DigitalAccessTitan1" },
  { 0x00029, "Digital Access T1" },
  { 0x0002a, "DigitalAccessTitan2" },
  { 0x0002b, "DigitalAccessLennon" },
  { 0x0002f, "AnalogAccessElvis" },
  { 0x00030, "VGCGateway" },
  { 0x00032, "ConferenceBridge" },
  { 0x00033, "ConferenceBridgeYoko" },
  { 0x00034, "ConferenceBridgeDixieLand" },
  { 0x00035, "ConferenceBridgeSummit" },
  { 0x0003c, "H225" },
  { 0x0003d, "H323Phone" },
  { 0x0003e, "H323Gateway" },
  { 0x00046, "MusicOnHold" },
  { 0x00047, "Pilot" },
  { 0x00048, "TapiPort" },
  { 0x00049, "TapiRoutePoint" },
  { 0x00050, "VoiceInBox" },
  { 0x00051, "VoiceInboxAdmin" },
  { 0x00052, "LineAnnunciator" },
  { 0x00053, "SoftwareMtpDixieLand" },
  { 0x00054, "CiscoMediaServer" },
  { 0x00055, "ConferenceBridgeFlint" },
  { 0x00056, "ConferenceBridgeHetroGen" },
  { 0x00057, "ConferenceBridgeAudVid" },
  { 0x00058, "ConferenceHVideoBridge" },
  { 0x0005a, "RouteList" },
  { 0x00064, "LoadSimulator" },
  { 0x0006e, "MediaTerminationPoint" },
  { 0x0006f, "MediaTerminationPointYoko" },
  { 0x00070, "MediaTerminationPointDixieLand" },
  { 0x00071, "MediaTerminationPointSummit" },
  { 0x00073, "7941G" },
  { 0x00077, "7971" },
  { 0x00078, "MGCPStation" },
  { 0x00079, "MGCPTrunk" },
  { 0x0007a, "RASProxy" },
  { 0x0007c, "Cisco 7914 AddOn" },
  { 0x0007d, "Trunk" },
  { 0x0007e, "Annunciator" },
  { 0x0007f, "MonitorBridge" },
  { 0x00080, "Recorder" },
  { 0x00081, "MonitorBridgeYoko" },
  { 0x00083, "SipTrunk" },
  { 0x00084, "SipGateway" },
  { 0x00085, "WsmTrunk" },
  { 0x00086, "RemoteDestination" },
  { 0x000e3, "Cisco 7915 AddOn" },
  { 0x000e4, "Cisco 7915 AddOn 24" },
  { 0x000e5, "Cisco 7916 AddOn" },
  { 0x000e6, "Cisco 7916 AddOn 24" },
  { 0x000fd, "GenericDevice" },
  { 0x000fe, "UnknownMGCPGateway" },
  { 0x000ff, "NotDefined" },
  { 0x00113, "Nokia E Series" },
  { 0x0012e, "Cisco 7985" },
  { 0x00133, "7911" },
  { 0x00134, "Cisco 7961 GE" },
  { 0x00135, "7961G_GE" },
  { 0x0014f, "MotorolaCN622" },
  { 0x00150, "3rdPartySipBasic" },
  { 0x0015c, "Cisco 7931" },
  { 0x00166, "UnifiedCommunicator" },
  { 0x0016d, "7921" },
  { 0x00171, "7906" },
  { 0x00176, "3rdPartySipAdv" },
  { 0x00177, "Telepresence" },
  { 0x00178, "Nokia ICC client" },
  { 0x00194, "7962" },
  { 0x0019c, "3951" },
  { 0x001af, "7937" },
  { 0x001b2, "7942" },
  { 0x001b3, "7945" },
  { 0x001b4, "7965" },
  { 0x001b5, "7975" },
  { 0x001d4, "UnifiedMobileCommunicator" },
  { 0x001e4, "Cisco 7925" },
  { 0x001ed, "9971_CE" },
  { 0x001ef, "Cisco 6921" },
  { 0x001f0, "Cisco 6941" },
  { 0x001f1, "Cisco 6961" },
  { 0x001f7, "CSF" },
  { 0x00223, "Cisco 6901" },
  { 0x00224, "Cisco 6911" },
  { 0x00234, "Cisco 6945" },
  { 0x00249, "Cisco 8945" },
  { 0x0024a, "Cisco 8941" },
  { 0x00255, "CiscoTelepresenceMcu" },
  { 0x00257, "CiscoTelePresenceExchange" },
  { 0x00258, "CiscoTelePresenceSoftwareConferenceBridge" },
  { 0x00277, "ASSip" },
  { 0x0027b, "CtiRemoteDevice" },
  { 0x04e20, "7905" },
  { 0x07532, "7920" },
  { 0x07536, "7970" },
  { 0x07537, "7912" },
  { 0x07538, "7902" },
  { 0x07540, "Cisco IP Communicator" },
  { 0x07542, "7961G" },
  { 0x07543, "7936" },
  { 0x0754b, "AnalogPhone" },
  { 0x0754c, "ISDNBRIPhone" },
  { 0x07550, "SCCPGwVirtualPhone" },
  { 0x07553, "IP_STE" },
  { 0x08cc9, "CiscoTelePresenceConductor" },
  { 0x08d7b, "InteractiveVoiceResponse" },
  { 0x13880, "Cisco SPA 521S" },
  { 0x13883, "Cisco SPA 502G" },
  { 0x13884, "Cisco SPA 504G" },
  { 0x13885, "Cisco SPA 525G" },
  { 0x13887, "Cisco SPA 509G" },
  { 0x13889, "Cisco SPA 525G2" },
  { 0x1388b, "Cisco SPA 303G" },
  { 0x00000, NULL }
};
static value_string_ext DeviceType_ext = VALUE_STRING_EXT_INIT(DeviceType);

static const value_string KeyPadButton[] = {
  { 0x00000, "Zero" },
  { 0x00001, "One" },
  { 0x00002, "Two" },
  { 0x00003, "Three" },
  { 0x00004, "Four" },
  { 0x00005, "Five" },
  { 0x00006, "Six" },
  { 0x00007, "Seven" },
  { 0x00008, "Eight" },
  { 0x00009, "Nine" },
  { 0x0000a, "A" },
  { 0x0000b, "B" },
  { 0x0000c, "C" },
  { 0x0000d, "D" },
  { 0x0000e, "Star" },
  { 0x0000f, "Pound" },
  { 0x00010, "Plus" },
  { 0x00000, NULL }
};
static value_string_ext KeyPadButton_ext = VALUE_STRING_EXT_INIT(KeyPadButton);

static const value_string KeyPadButton_short[] = {
  { 0x00000, "0" },
  { 0x00001, "1" },
  { 0x00002, "2" },
  { 0x00003, "3" },
  { 0x00004, "4" },
  { 0x00005, "5" },
  { 0x00006, "6" },
  { 0x00007, "7" },
  { 0x00008, "8" },
  { 0x00009, "9" },
  { 0x0000a, "A" },
  { 0x0000b, "B" },
  { 0x0000c, "C" },
  { 0x0000d, "D" },
  { 0x0000e, "*" },
  { 0x0000f, "#" },
  { 0x00010, "+" },
  { 0x00000, NULL }
};
static value_string_ext KeyPadButton_short_ext = VALUE_STRING_EXT_INIT(KeyPadButton_short);

static const value_string DeviceStimulus[] = {
  { 0x00001, "LastNumberRedial" },
  { 0x00002, "SpeedDial" },
  { 0x00003, "Hold" },
  { 0x00004, "Transfer" },
  { 0x00005, "ForwardAll" },
  { 0x00006, "ForwardBusy" },
  { 0x00007, "ForwardNoAnswer" },
  { 0x00008, "Display" },
  { 0x00009, "Line" },
  { 0x0000a, "T120Chat" },
  { 0x0000b, "T120Whiteboard" },
  { 0x0000c, "T120ApplicationSharing" },
  { 0x0000d, "T120FileTransfer" },
  { 0x0000e, "Video" },
  { 0x0000f, "VoiceMail" },
  { 0x00010, "AnswerRelease" },
  { 0x00011, "AutoAnswer" },
  { 0x00012, "Select" },
  { 0x00013, "Privacy" },
  { 0x00014, "ServiceURL" },
  { 0x00015, "BLFSpeedDial" },
  { 0x00016, "DPark" },
  { 0x00017, "Intercom" },
  { 0x0001b, "MaliciousCall" },
  { 0x00021, "GenericAppB1" },
  { 0x00022, "GenericAppB2" },
  { 0x00023, "GenericAppB3" },
  { 0x00024, "GenericAppB4" },
  { 0x00025, "GenericAppB5" },
  { 0x0007b, "MeetMeConference" },
  { 0x0007d, "Conference" },
  { 0x0007e, "CallPark" },
  { 0x0007f, "CallPickUp" },
  { 0x00080, "GroupCallPickUp" },
  { 0x00081, "Mobility" },
  { 0x00082, "DoNotDisturb" },
  { 0x00083, "ConfList" },
  { 0x00084, "RemoveLastParticipant" },
  { 0x00085, "QRT" },
  { 0x00086, "CallBack" },
  { 0x00087, "OtherPickup" },
  { 0x00088, "VideoMode" },
  { 0x00089, "NewCall" },
  { 0x0008a, "EndCall" },
  { 0x0008b, "HLog" },
  { 0x0008f, "Queuing" },
  { 0x000ff, "MaxStimulusValue" },
  { 0x00000, NULL }
};
static value_string_ext DeviceStimulus_ext = VALUE_STRING_EXT_INIT(DeviceStimulus);

#define MEDIA_PAYLOAD_G711ALAW64K              0x00002 /* audio */
#define MEDIA_PAYLOAD_G711ALAW56K              0x00003 /* audio */
#define MEDIA_PAYLOAD_G711ULAW64K              0x00004 /* audio */
#define MEDIA_PAYLOAD_G711ULAW56K              0x00005 /* audio */
#define MEDIA_PAYLOAD_G722_64K                 0x00006 /* audio */
#define MEDIA_PAYLOAD_G722_56K                 0x00007 /* audio */
#define MEDIA_PAYLOAD_G722_48K                 0x00008 /* audio */
#define MEDIA_PAYLOAD_G7231                    0x00009 /* audio */
#define MEDIA_PAYLOAD_G728                     0x0000a /* audio */
#define MEDIA_PAYLOAD_G729                     0x0000b /* audio */
#define MEDIA_PAYLOAD_G729ANNEXA               0x0000c /* audio */
#define MEDIA_PAYLOAD_G729ANNEXB               0x0000f /* audio */
#define MEDIA_PAYLOAD_G729ANNEXAWANNEXB        0x00010 /* audio */
#define MEDIA_PAYLOAD_GSM_FULL_RATE            0x00012 /* audio */
#define MEDIA_PAYLOAD_GSM_HALF_RATE            0x00013 /* audio */
#define MEDIA_PAYLOAD_GSM_ENHANCED_FULL_RATE   0x00014 /* audio */
#define MEDIA_PAYLOAD_WIDE_BAND_256K           0x00019 /* audio */
#define MEDIA_PAYLOAD_DATA64                   0x00020 /* audio */
#define MEDIA_PAYLOAD_DATA56                   0x00021 /* audio */
#define MEDIA_PAYLOAD_G7221_32K                0x00028 /* audio */
#define MEDIA_PAYLOAD_G7221_24K                0x00029 /* audio */
#define MEDIA_PAYLOAD_AAC                      0x0002a /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_128             0x0002b /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_64              0x0002c /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_56              0x0002d /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_48              0x0002e /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_32              0x0002f /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_24              0x00030 /* audio */
#define MEDIA_PAYLOAD_MP4ALATM_NA              0x00031 /* audio */
#define MEDIA_PAYLOAD_GSM                      0x00050 /* audio */
#define MEDIA_PAYLOAD_G726_32K                 0x00052 /* audio */
#define MEDIA_PAYLOAD_G726_24K                 0x00053 /* audio */
#define MEDIA_PAYLOAD_G726_16K                 0x00054 /* audio */
#define MEDIA_PAYLOAD_ILBC                     0x00056 /* audio */
#define MEDIA_PAYLOAD_ISAC                     0x00059 /* audio */
#define MEDIA_PAYLOAD_OPUS                     0x0005a /* audio */
#define MEDIA_PAYLOAD_AMR                      0x00061 /* audio */
#define MEDIA_PAYLOAD_AMR_WB                   0x00062 /* audio */
#define MEDIA_PAYLOAD_H261                     0x00064 /* video */
#define MEDIA_PAYLOAD_H263                     0x00065 /* video */
#define MEDIA_PAYLOAD_VIEO                     0x00066 /* video */
#define MEDIA_PAYLOAD_H264                     0x00067 /* video */
#define MEDIA_PAYLOAD_H264_SVC                 0x00068 /* video */
#define MEDIA_PAYLOAD_T120                     0x00069 /* video */
#define MEDIA_PAYLOAD_H224                     0x0006a /* video */
#define MEDIA_PAYLOAD_T38FAX                   0x0006b /* video */
#define MEDIA_PAYLOAD_TOTE                     0x0006c /* video */
#define MEDIA_PAYLOAD_H265                     0x0006d /* video */
#define MEDIA_PAYLOAD_H264_UC                  0x0006e /* video */
#define MEDIA_PAYLOAD_XV150_MR_711U            0x0006f /* video */
#define MEDIA_PAYLOAD_NSE_VBD_711U             0x00070 /* video */
#define MEDIA_PAYLOAD_XV150_MR_729A            0x00071 /* video */
#define MEDIA_PAYLOAD_NSE_VBD_729A             0x00072 /* video */
#define MEDIA_PAYLOAD_H264_FEC                 0x00073 /* video */
#define MEDIA_PAYLOAD_CLEAR_CHAN               0x00078 /* data */
#define MEDIA_PAYLOAD_UNIVERSAL_XCODER         0x000de /* data */
#define MEDIA_PAYLOAD_RFC2833_DYNPAYLOAD       0x00101 /* data */
#define MEDIA_PAYLOAD_PASSTHROUGH              0x00102 /* data */
#define MEDIA_PAYLOAD_DYNAMIC_PAYLOAD_PASSTHRU 0x00103 /* data */
#define MEDIA_PAYLOAD_DTMF_OOB                 0x00104 /* data */
#define MEDIA_PAYLOAD_INBAND_DTMF_RFC2833      0x00105 /* data */
#define MEDIA_PAYLOAD_CFB_TONES                0x00106 /* data */
#define MEDIA_PAYLOAD_NOAUDIO                  0x0012b /* data */
#define MEDIA_PAYLOAD_V150_LC_MODEMRELAY       0x0012c /* data */
#define MEDIA_PAYLOAD_V150_LC_SPRT             0x0012d /* data */
#define MEDIA_PAYLOAD_V150_LC_SSE              0x0012e /* data */
#define MEDIA_PAYLOAD_MAX                      0x0012f /* data */

static const value_string Media_PayloadType[] = {
  { MEDIA_PAYLOAD_G711ALAW64K, "Media_Payload_G711Alaw64k" },
  { MEDIA_PAYLOAD_G711ALAW56K, "Media_Payload_G711Alaw56k" },
  { MEDIA_PAYLOAD_G711ULAW64K, "Media_Payload_G711Ulaw64k" },
  { MEDIA_PAYLOAD_G711ULAW56K, "Media_Payload_G711Ulaw56k" },
  { MEDIA_PAYLOAD_G722_64K, "Media_Payload_G722_64k" },
  { MEDIA_PAYLOAD_G722_56K, "Media_Payload_G722_56k" },
  { MEDIA_PAYLOAD_G722_48K, "Media_Payload_G722_48k" },
  { MEDIA_PAYLOAD_G7231, "Media_Payload_G7231" },
  { MEDIA_PAYLOAD_G728, "Media_Payload_G728" },
  { MEDIA_PAYLOAD_G729, "Media_Payload_G729" },
  { MEDIA_PAYLOAD_G729ANNEXA, "Media_Payload_G729AnnexA" },
  { MEDIA_PAYLOAD_G729ANNEXB, "Media_Payload_G729AnnexB" },
  { MEDIA_PAYLOAD_G729ANNEXAWANNEXB, "Media_Payload_G729AnnexAwAnnexB" },
  { MEDIA_PAYLOAD_GSM_FULL_RATE, "Media_Payload_GSM_Full_Rate" },
  { MEDIA_PAYLOAD_GSM_HALF_RATE, "Media_Payload_GSM_Half_Rate" },
  { MEDIA_PAYLOAD_GSM_ENHANCED_FULL_RATE, "Media_Payload_GSM_Enhanced_Full_Rate" },
  { MEDIA_PAYLOAD_WIDE_BAND_256K, "Media_Payload_Wide_Band_256k" },
  { MEDIA_PAYLOAD_DATA64, "Media_Payload_Data64" },
  { MEDIA_PAYLOAD_DATA56, "Media_Payload_Data56" },
  { MEDIA_PAYLOAD_G7221_32K, "Media_Payload_G7221_32K" },
  { MEDIA_PAYLOAD_G7221_24K, "Media_Payload_G7221_24K" },
  { MEDIA_PAYLOAD_AAC, "Media_Payload_AAC" },
  { MEDIA_PAYLOAD_MP4ALATM_128, "Media_Payload_MP4ALATM_128" },
  { MEDIA_PAYLOAD_MP4ALATM_64, "Media_Payload_MP4ALATM_64" },
  { MEDIA_PAYLOAD_MP4ALATM_56, "Media_Payload_MP4ALATM_56" },
  { MEDIA_PAYLOAD_MP4ALATM_48, "Media_Payload_MP4ALATM_48" },
  { MEDIA_PAYLOAD_MP4ALATM_32, "Media_Payload_MP4ALATM_32" },
  { MEDIA_PAYLOAD_MP4ALATM_24, "Media_Payload_MP4ALATM_24" },
  { MEDIA_PAYLOAD_MP4ALATM_NA, "Media_Payload_MP4ALATM_NA" },
  { MEDIA_PAYLOAD_GSM, "Media_Payload_GSM" },
  { MEDIA_PAYLOAD_G726_32K, "Media_Payload_G726_32K" },
  { MEDIA_PAYLOAD_G726_24K, "Media_Payload_G726_24K" },
  { MEDIA_PAYLOAD_G726_16K, "Media_Payload_G726_16K" },
  { MEDIA_PAYLOAD_ILBC, "Media_Payload_ILBC" },
  { MEDIA_PAYLOAD_ISAC, "Media_Payload_ISAC" },
  { MEDIA_PAYLOAD_OPUS, "Media_Payload_OPUS" },
  { MEDIA_PAYLOAD_AMR, "Media_Payload_AMR" },
  { MEDIA_PAYLOAD_AMR_WB, "Media_Payload_AMR_WB" },
  { MEDIA_PAYLOAD_H261, "Media_Payload_H261" },
  { MEDIA_PAYLOAD_H263, "Media_Payload_H263" },
  { MEDIA_PAYLOAD_VIEO, "Media_Payload_Vieo" },
  { MEDIA_PAYLOAD_H264, "Media_Payload_H264" },
  { MEDIA_PAYLOAD_H264_SVC, "Media_Payload_H264_SVC" },
  { MEDIA_PAYLOAD_T120, "Media_Payload_T120" },
  { MEDIA_PAYLOAD_H224, "Media_Payload_H224" },
  { MEDIA_PAYLOAD_T38FAX, "Media_Payload_T38Fax" },
  { MEDIA_PAYLOAD_TOTE, "Media_Payload_TOTE" },
  { MEDIA_PAYLOAD_H265, "Media_Payload_H265" },
  { MEDIA_PAYLOAD_H264_UC, "Media_Payload_H264_UC" },
  { MEDIA_PAYLOAD_XV150_MR_711U, "Media_Payload_XV150_MR_711U" },
  { MEDIA_PAYLOAD_NSE_VBD_711U, "Media_Payload_NSE_VBD_711U" },
  { MEDIA_PAYLOAD_XV150_MR_729A, "Media_Payload_XV150_MR_729A" },
  { MEDIA_PAYLOAD_NSE_VBD_729A, "Media_Payload_NSE_VBD_729A" },
  { MEDIA_PAYLOAD_H264_FEC, "Media_Payload_H264_FEC" },
  { MEDIA_PAYLOAD_CLEAR_CHAN, "Media_Payload_Clear_Chan" },
  { MEDIA_PAYLOAD_UNIVERSAL_XCODER, "Media_Payload_Universal_Xcoder" },
  { MEDIA_PAYLOAD_RFC2833_DYNPAYLOAD, "Media_Payload_RFC2833_DynPayload" },
  { MEDIA_PAYLOAD_PASSTHROUGH, "Media_Payload_PassThrough" },
  { MEDIA_PAYLOAD_DYNAMIC_PAYLOAD_PASSTHRU, "Media_Payload_Dynamic_Payload_PassThru" },
  { MEDIA_PAYLOAD_DTMF_OOB, "Media_Payload_DTMF_OOB" },
  { MEDIA_PAYLOAD_INBAND_DTMF_RFC2833, "Media_Payload_Inband_DTMF_RFC2833" },
  { MEDIA_PAYLOAD_CFB_TONES, "Media_Payload_CFB_Tones" },
  { MEDIA_PAYLOAD_NOAUDIO, "Media_Payload_NoAudio" },
  { MEDIA_PAYLOAD_V150_LC_MODEMRELAY, "Media_Payload_v150_LC_ModemRelay" },
  { MEDIA_PAYLOAD_V150_LC_SPRT, "Media_Payload_v150_LC_SPRT" },
  { MEDIA_PAYLOAD_V150_LC_SSE, "Media_Payload_v150_LC_SSE" },
  { MEDIA_PAYLOAD_MAX, "Media_Payload_Max" },
  { 0x00000, NULL }
};
static value_string_ext Media_PayloadType_ext = VALUE_STRING_EXT_INIT(Media_PayloadType);

static const value_string Media_G723BitRate[] = {
  { 0x00001, "Media_G723BRate_5_3" },
  { 0x00002, "Media_G723BRate_6_3" },
  { 0x00000, NULL }
};
static value_string_ext Media_G723BitRate_ext = VALUE_STRING_EXT_INIT(Media_G723BitRate);

static const value_string DeviceAlarmSeverity[] = {
  { 0x00000, "Critical" },
  { 0x00001, "Warning" },
  { 0x00002, "Informational" },
  { 0x00004, "Unknown" },
  { 0x00007, "Major" },
  { 0x00008, "Minor" },
  { 0x0000a, "Marginal" },
  { 0x00014, "TraceInfo" },
  { 0x00000, NULL }
};
static value_string_ext DeviceAlarmSeverity_ext = VALUE_STRING_EXT_INIT(DeviceAlarmSeverity);

static const value_string MulticastMediaReceptionStatus[] = {
  { 0x00000, "Ok" },
  { 0x00001, "Error" },
  { 0x00000, NULL }
};
static value_string_ext MulticastMediaReceptionStatus_ext = VALUE_STRING_EXT_INIT(MulticastMediaReceptionStatus);

static const value_string MediaStatus[] = {
  { 0x00000, "Ok" },
  { 0x00001, "Unknown" },
  { 0x00002, "NotEnoughChannels" },
  { 0x00003, "CodecTooComplex" },
  { 0x00004, "InvalidPartyID" },
  { 0x00005, "InvalidCallRef" },
  { 0x00006, "InvalidCodec" },
  { 0x00007, "InvalidPacketSize" },
  { 0x00008, "OutOfSockets" },
  { 0x00009, "EncoderOrDecoderFailed" },
  { 0x0000a, "InvalidDynamicPayloadType" },
  { 0x0000b, "RequestedIpAddrTypeUnAvailable" },
  { 0x000ff, "DeviceOnHook" },
  { 0x00000, NULL }
};
static value_string_ext MediaStatus_ext = VALUE_STRING_EXT_INIT(MediaStatus);

#define IPADDRTYPE_IPV4                        0x00000
#define IPADDRTYPE_IPV6                        0x00001
#define IPADDRTYPE_IPV4_V6                     0x00002
#define IPADDRTYPE_IP_INVALID                  0x00003

static const value_string IpAddrType[] = {
  { IPADDRTYPE_IPV4, "v4" },
  { IPADDRTYPE_IPV6, "v6" },
  { IPADDRTYPE_IPV4_V6, "v4_v6" },
  { IPADDRTYPE_IP_INVALID, "_Invalid" },
  { 0x00000, NULL }
};
static value_string_ext IpAddrType_ext = VALUE_STRING_EXT_INIT(IpAddrType);

static const value_string StatsProcessingType[] = {
  { 0x00000, "clearStats" },
  { 0x00001, "doNotClearStats" },
  { 0x00000, NULL }
};
static value_string_ext StatsProcessingType_ext = VALUE_STRING_EXT_INIT(StatsProcessingType);

static const value_string SoftKeySet[] = {
  { 0x00000, "On Hook" },
  { 0x00001, "Connected" },
  { 0x00002, "On Hold" },
  { 0x00003, "Ring In" },
  { 0x00004, "Off Hook" },
  { 0x00005, "Connected Transferable" },
  { 0x00006, "Digits Following" },
  { 0x00007, "Connected Conference" },
  { 0x00008, "Ring Out" },
  { 0x00009, "OffHook with Features" },
  { 0x0000a, "In Use Hint" },
  { 0x0000b, "On Hook with Stealable Call" },
  { 0x00000, NULL }
};
static value_string_ext SoftKeySet_ext = VALUE_STRING_EXT_INIT(SoftKeySet);

static const value_string SoftKeyEvent[] = {
  { 0x00001, "Redial" },
  { 0x00002, "NewCall" },
  { 0x00003, "Hold" },
  { 0x00004, "Transfer" },
  { 0x00005, "CfwdAll" },
  { 0x00006, "CfwdBusy" },
  { 0x00007, "CfwdNoAnswer" },
  { 0x00008, "BackSpace" },
  { 0x00009, "EndCall" },
  { 0x0000a, "Resume" },
  { 0x0000b, "Answer" },
  { 0x0000c, "Info" },
  { 0x0000d, "Confrn" },
  { 0x0000e, "Park" },
  { 0x0000f, "Join" },
  { 0x00010, "MeetMe" },
  { 0x00011, "PickUp" },
  { 0x00012, "GrpPickup" },
  { 0x00013, "Your current options" },
  { 0x00014, "Off Hook" },
  { 0x00015, "On Hook" },
  { 0x00016, "Ring out" },
  { 0x00017, "From " },
  { 0x00018, "Connected" },
  { 0x00019, "Busy" },
  { 0x0001a, "Line In Use" },
  { 0x0001b, "Call Waiting" },
  { 0x0001c, "Call Transfer" },
  { 0x0001d, "Call Park" },
  { 0x0001e, "Call Proceed" },
  { 0x0001f, "In Use Remote" },
  { 0x00020, "Enter number" },
  { 0x00021, "Call park At" },
  { 0x00022, "Primary Only" },
  { 0x00023, "Temp Fail" },
  { 0x00024, "You Have a VoiceMail" },
  { 0x00025, "Forwarded to" },
  { 0x00026, "Can Not Complete Conference" },
  { 0x00027, "No Conference Bridge" },
  { 0x00028, "Can Not Hold Primary Control" },
  { 0x00029, "Invalid Conference Participant" },
  { 0x0002a, "In Conference Already" },
  { 0x0002b, "No Participant Info" },
  { 0x0002c, "Exceed Maximum Parties" },
  { 0x0002d, "Key Is Not Active" },
  { 0x0002e, "Error No License" },
  { 0x0002f, "Error DBConfig" },
  { 0x00030, "Error Database" },
  { 0x00031, "Error Pass Limit" },
  { 0x00032, "Error Unknown" },
  { 0x00033, "Error Mismatch" },
  { 0x00034, "Conference" },
  { 0x00035, "Park Number" },
  { 0x00036, "Private" },
  { 0x00037, "Not Enough Bandwidth" },
  { 0x00038, "Unknown Number" },
  { 0x00039, "RmLstC" },
  { 0x0003a, "Voicemail" },
  { 0x0003b, "ImmDiv" },
  { 0x0003c, "Intrcpt" },
  { 0x0003d, "SetWtch" },
  { 0x0003e, "TrnsfVM" },
  { 0x0003f, "DND" },
  { 0x00040, "DivAll" },
  { 0x00041, "CallBack" },
  { 0x00042, "Network congestion,rerouting" },
  { 0x00043, "Barge" },
  { 0x00044, "Failed to setup Barge" },
  { 0x00045, "Another Barge exists" },
  { 0x00046, "Incompatible device type" },
  { 0x00047, "No Park Number Available" },
  { 0x00048, "CallPark Reversion" },
  { 0x00049, "Service is not Active" },
  { 0x0004a, "High Traffic Try Again Later" },
  { 0x0004b, "QRT" },
  { 0x0004c, "MCID" },
  { 0x0004d, "DirTrfr" },
  { 0x0004e, "Select" },
  { 0x0004f, "ConfList" },
  { 0x00050, "iDivert" },
  { 0x00051, "cBarge" },
  { 0x00052, "Can Not Complete Transfer" },
  { 0x00053, "Can Not Join Calls" },
  { 0x00054, "Mcid Successful" },
  { 0x00055, "Number Not Configured" },
  { 0x00056, "Security Error" },
  { 0x00057, "Video Bandwidth Unavailable" },
  { 0x00058, "Video Mode" },
  { 0x000c9, "Dial" },
  { 0x000ca, "Record" },
  { 0x00000, NULL }
};
static value_string_ext SoftKeyEvent_ext = VALUE_STRING_EXT_INIT(SoftKeyEvent);

static const value_string UnRegReasonCode[] = {
  { 0x00000, "Unknown" },
  { 0x00001, "PowerSaveMode" },
  { 0x00000, NULL }
};
static value_string_ext UnRegReasonCode_ext = VALUE_STRING_EXT_INIT(UnRegReasonCode);

static const value_string HeadsetMode[] = {
  { 0x00001, "On" },
  { 0x00002, "Off" },
  { 0x00000, NULL }
};
static value_string_ext HeadsetMode_ext = VALUE_STRING_EXT_INIT(HeadsetMode);

static const value_string SequenceFlag[] = {
  { 0x00000, "First" },
  { 0x00001, "More" },
  { 0x00002, "Last" },
  { 0x00000, NULL }
};
static value_string_ext SequenceFlag_ext = VALUE_STRING_EXT_INIT(SequenceFlag);

static const value_string Layout[] = {
  { 0x00000, "NoLayout" },
  { 0x00001, "OneByOne" },
  { 0x00002, "OneByTwo" },
  { 0x00003, "TwoByTwo" },
  { 0x00004, "TwoByTwo3Alt1" },
  { 0x00005, "TwoByTwo3Alt2" },
  { 0x00006, "ThreeByThree" },
  { 0x00007, "ThreeByThree6Alt1" },
  { 0x00008, "ThreeByThree6Alt2" },
  { 0x00009, "ThreeByThree4Alt1" },
  { 0x0000a, "ThreeByThree4Alt2" },
  { 0x00000, NULL }
};
static value_string_ext Layout_ext = VALUE_STRING_EXT_INIT(Layout);

static const value_string TransmitOrReceive[] = {
  { 0x00000, "None" },
  { 0x00001, "ReceiveOnly" },
  { 0x00002, "TransmitOnly" },
  { 0x00003, "Both" },
  { 0x00000, NULL }
};
static value_string_ext TransmitOrReceive_ext = VALUE_STRING_EXT_INIT(TransmitOrReceive);

static const value_string OpenReceiveChanStatus[] = {
  { 0x00000, "Ok" },
  { 0x00001, "Error" },
  { 0x00000, NULL }
};
static value_string_ext OpenReceiveChanStatus_ext = VALUE_STRING_EXT_INIT(OpenReceiveChanStatus);

static const value_string CreateConfResult[] = {
  { 0x00000, "OK" },
  { 0x00001, "ResourceNotAvailable" },
  { 0x00002, "ConferenceAlreadyExist" },
  { 0x00003, "SystemErr" },
  { 0x00000, NULL }
};
static value_string_ext CreateConfResult_ext = VALUE_STRING_EXT_INIT(CreateConfResult);

static const value_string DeleteConfResult[] = {
  { 0x00000, "OK" },
  { 0x00001, "ConferenceNotExist" },
  { 0x00002, "SystemErr" },
  { 0x00000, NULL }
};
static value_string_ext DeleteConfResult_ext = VALUE_STRING_EXT_INIT(DeleteConfResult);

static const value_string ModifyConfResult[] = {
  { 0x00000, "OK" },
  { 0x00001, "ResourceNotAvailable" },
  { 0x00002, "ConferenceNotExist" },
  { 0x00003, "InvalidParameter" },
  { 0x00004, "MoreActiveCallsThanReserved" },
  { 0x00005, "InvalidResourceType" },
  { 0x00006, "SystemErr" },
  { 0x00000, NULL }
};
static value_string_ext ModifyConfResult_ext = VALUE_STRING_EXT_INIT(ModifyConfResult);

static const value_string AddParticipantResult[] = {
  { 0x00000, "OK" },
  { 0x00001, "ResourceNotAvailable" },
  { 0x00002, "ConferenceNotExist" },
  { 0x00003, "DuplicateCallRef" },
  { 0x00004, "SystemErr" },
  { 0x00000, NULL }
};
static value_string_ext AddParticipantResult_ext = VALUE_STRING_EXT_INIT(AddParticipantResult);

static const value_string ResourceType[] = {
  { 0x00000, "Conference" },
  { 0x00001, "IVR" },
  { 0x00000, NULL }
};
static value_string_ext ResourceType_ext = VALUE_STRING_EXT_INIT(ResourceType);

static const value_string AuditParticipantResult[] = {
  { 0x00000, "OK" },
  { 0x00001, "ConferenceNotExist" },
  { 0x00000, NULL }
};
static value_string_ext AuditParticipantResult_ext = VALUE_STRING_EXT_INIT(AuditParticipantResult);

static const value_string Media_Encryption_Capability[] = {
  { 0x00000, "NotEncryptionCapable" },
  { 0x00001, "EncryptionCapable" },
  { 0x00000, NULL }
};
static value_string_ext Media_Encryption_Capability_ext = VALUE_STRING_EXT_INIT(Media_Encryption_Capability);

static const value_string IpAddrMode[] = {
  { 0x00000, "ModeIpv4" },
  { 0x00001, "ModeIpv6" },
  { 0x00002, "ModeIpv4AndIpv6" },
  { 0x00000, NULL }
};
static value_string_ext IpAddrMode_ext = VALUE_STRING_EXT_INIT(IpAddrMode);

static const value_string MediaType[] = {
  { 0x00000, "MediaType_Invalid" },
  { 0x00001, "MediaType_Audio" },
  { 0x00002, "MediaType_Main_Video" },
  { 0x00003, "MediaType_FECC" },
  { 0x00004, "MediaType_Presentation_Video" },
  { 0x00005, "MediaType_DataApp_BFCP" },
  { 0x00006, "MediaType_DataApp_IXChannel" },
  { 0x00007, "MediaType_T38" },
  { 0x00008, "MediaType_Max" },
  { 0x00000, NULL }
};
static value_string_ext MediaType_ext = VALUE_STRING_EXT_INIT(MediaType);

static const value_string RSVPDirection[] = {
  { 0x00001, "SEND" },
  { 0x00002, "RECV" },
  { 0x00003, "SENDRECV" },
  { 0x00000, NULL }
};
static value_string_ext RSVPDirection_ext = VALUE_STRING_EXT_INIT(RSVPDirection);

static const value_string QoSErrorCode[] = {
  { 0x00000, "QOS_CAUSE_RESERVATION_TIMEOUT" },
  { 0x00001, "QOS_CAUSE_PATH_FAIL" },
  { 0x00002, "QOS_CAUSE_RESV_FAIL" },
  { 0x00003, "QOS_CAUSE_LISTEN_FAIL" },
  { 0x00004, "QOS_CAUSE_RESOURCE_UNAVAILABLE" },
  { 0x00005, "QOS_CAUSE_LISTEN_TIMEOUT" },
  { 0x00006, "QOS_CAUSE_RESV_RETRIES_FAIL" },
  { 0x00007, "QOS_CAUSE_PATH_RETRIES_FAIL" },
  { 0x00008, "QOS_CAUSE_RESV_PREEMPTION" },
  { 0x00009, "QOS_CAUSE_PATH_PREEMPTION" },
  { 0x0000a, "QOS_CAUSE_RESV_MODIFY_FAIL" },
  { 0x0000b, "QOS_CAUSE_PATH_MODIFY_FAIL" },
  { 0x0000c, "QOS_CAUSE_RESV_TEAR" },
  { 0x00000, NULL }
};
static value_string_ext QoSErrorCode_ext = VALUE_STRING_EXT_INIT(QoSErrorCode);

static const value_string RSVPErrorCode[] = {
  { 0x00000, "CONFIRM" },
  { 0x00001, "ADMISSION" },
  { 0x00002, "ADMINISTRATIVE" },
  { 0x00003, "NO_PATH_INFORMATION" },
  { 0x00004, "NO_SENDER_INFORMATION" },
  { 0x00005, "CONFLICTING_STYLE" },
  { 0x00006, "UNKNOWN_STYLE" },
  { 0x00007, "CONFLICTING_DST_PORTS" },
  { 0x00008, "CONFLICTING_SRC_PORTS" },
  { 0x0000c, "SERVICE_PREEMPTED" },
  { 0x0000d, "UNKNOWN_OBJECT_CLASS" },
  { 0x0000e, "UNKNOWN_CLASS_TYPE" },
  { 0x00014, "API" },
  { 0x00015, "TRAFFIC" },
  { 0x00016, "TRAFFIC_SYSTEM" },
  { 0x00017, "SYSTEM" },
  { 0x00018, "ROUTING_PROBLEM" },
  { 0x00000, NULL }
};
static value_string_ext RSVPErrorCode_ext = VALUE_STRING_EXT_INIT(RSVPErrorCode);

static const value_string SubscriptionFeatureID[] = {
  { 0x00001, "BLF" },
  { 0x00000, NULL }
};
static value_string_ext SubscriptionFeatureID_ext = VALUE_STRING_EXT_INIT(SubscriptionFeatureID);

static const value_string MediaPathID[] = {
  { 0x00001, "Headset" },
  { 0x00002, "Handset" },
  { 0x00003, "Speaker" },
  { 0x00000, NULL }
};
static value_string_ext MediaPathID_ext = VALUE_STRING_EXT_INIT(MediaPathID);

static const value_string MediaPathEvent[] = {
  { 0x00001, "On" },
  { 0x00002, "Off" },
  { 0x00000, NULL }
};
static value_string_ext MediaPathEvent_ext = VALUE_STRING_EXT_INIT(MediaPathEvent);

static const value_string MediaPathCapabilities[] = {
  { 0x00001, "Enable" },
  { 0x00002, "Disable" },
  { 0x00003, "Monitor" },
  { 0x00000, NULL }
};
static value_string_ext MediaPathCapabilities_ext = VALUE_STRING_EXT_INIT(MediaPathCapabilities);

static const value_string DeviceTone[] = {
  { 0x00000, "Silence" },
  { 0x00001, "Dtmf1" },
  { 0x00002, "Dtmf2" },
  { 0x00003, "Dtmf3" },
  { 0x00004, "Dtmf4" },
  { 0x00005, "Dtmf5" },
  { 0x00006, "Dtmf6" },
  { 0x00007, "Dtmf7" },
  { 0x00008, "Dtmf8" },
  { 0x00009, "Dtmf9" },
  { 0x0000a, "Dtmf0" },
  { 0x0000e, "DtmfStar" },
  { 0x0000f, "DtmfPound" },
  { 0x00010, "DtmfA" },
  { 0x00011, "DtmfB" },
  { 0x00012, "DtmfC" },
  { 0x00013, "DtmfD" },
  { 0x00021, "InsideDialTone" },
  { 0x00022, "OutsideDialTone" },
  { 0x00023, "LineBusyTone" },
  { 0x00024, "AlertingTone" },
  { 0x00025, "ReorderTone" },
  { 0x00026, "RecorderWarningTone" },
  { 0x00027, "RecorderDetectedTone" },
  { 0x00028, "RevertingTone" },
  { 0x00029, "ReceiverOffHookTone" },
  { 0x0002a, "MessageWaitingIndicatorTone" },
  { 0x0002b, "NoSuchNumberTone" },
  { 0x0002c, "BusyVerificationTone" },
  { 0x0002d, "CallWaitingTone" },
  { 0x0002e, "ConfirmationTone" },
  { 0x0002f, "CampOnIndicationTone" },
  { 0x00030, "RecallDialTone" },
  { 0x00031, "ZipZip" },
  { 0x00032, "Zip" },
  { 0x00033, "BeepBonk" },
  { 0x00034, "MusicTone" },
  { 0x00035, "HoldTone" },
  { 0x00036, "TestTone" },
  { 0x00038, "MonitorWarningTone" },
  { 0x00039, "SecureWarningTone" },
  { 0x00040, "AddCallWaiting" },
  { 0x00041, "PriorityCallWait" },
  { 0x00042, "RecallDial" },
  { 0x00043, "BargIn" },
  { 0x00044, "DistinctAlert" },
  { 0x00045, "PriorityAlert" },
  { 0x00046, "ReminderRing" },
  { 0x00047, "PrecedenceRingBack" },
  { 0x00048, "PreemptionTone" },
  { 0x00049, "NonSecureWarningTone" },
  { 0x00050, "MF1" },
  { 0x00051, "MF2" },
  { 0x00052, "MF3" },
  { 0x00053, "MF4" },
  { 0x00054, "MF5" },
  { 0x00055, "MF6" },
  { 0x00056, "MF7" },
  { 0x00057, "MF8" },
  { 0x00058, "MF9" },
  { 0x00059, "MF0" },
  { 0x0005a, "MFKP1" },
  { 0x0005b, "MFST" },
  { 0x0005c, "MFKP2" },
  { 0x0005d, "MFSTP" },
  { 0x0005e, "MFST3P" },
  { 0x0005f, "MILLIWATT" },
  { 0x00060, "MILLIWATTTEST" },
  { 0x00061, "HIGHTONE" },
  { 0x00062, "FLASHOVERRIDE" },
  { 0x00063, "FLASH" },
  { 0x00064, "PRIORITY" },
  { 0x00065, "IMMEDIATE" },
  { 0x00066, "PREAMPWARN" },
  { 0x00067, "2105HZ" },
  { 0x00068, "2600HZ" },
  { 0x00069, "440HZ" },
  { 0x0006a, "300HZ" },
  { 0x0006b, "Mobility_WP" },
  { 0x0006c, "Mobility_UAC" },
  { 0x0006d, "Mobility_WTDN" },
  { 0x0006e, "Mobility_MON" },
  { 0x0006f, "Mobility_MOFF" },
  { 0x00070, "Mobility_UKC" },
  { 0x00071, "Mobility_VMA" },
  { 0x00072, "Mobility_FAC" },
  { 0x00073, "Mobility_CMC" },
  { 0x00077, "MLPP_PALA" },
  { 0x00078, "MLPP_ICA" },
  { 0x00079, "MLPP_VCA" },
  { 0x0007a, "MLPP_BPA" },
  { 0x0007b, "MLPP_BNEA" },
  { 0x0007c, "MLPP_UPA" },
  { 0x0007d, "TUA" },
  { 0x0007e, "GONE" },
  { 0x0007f, "NoTone" },
  { 0x00080, "MeetMe_Greeting" },
  { 0x00081, "MeetMe_NumberInvalid" },
  { 0x00082, "MeetMe_NumberFailed" },
  { 0x00083, "MeetMe_EnterPIN" },
  { 0x00084, "MeetMe_InvalidPIN" },
  { 0x00085, "MeetMe_FailedPIN" },
  { 0x00086, "MeetMe_CFB_Failed" },
  { 0x00087, "MeetMe_EnterAccessCode" },
  { 0x00088, "MeetMe_AccessCodeInvalid" },
  { 0x00089, "MeetMe_AccessCodeFailed" },
  { 0x0008a, "MAX" },
  { 0x00000, NULL }
};
static value_string_ext DeviceTone_ext = VALUE_STRING_EXT_INIT(DeviceTone);

static const value_string ToneOutputDirection[] = {
  { 0x00000, "User" },
  { 0x00001, "Network" },
  { 0x00002, "All" },
  { 0x00000, NULL }
};
static value_string_ext ToneOutputDirection_ext = VALUE_STRING_EXT_INIT(ToneOutputDirection);

static const value_string RingMode[] = {
  { 0x00001, "RingOff" },
  { 0x00002, "InsideRing" },
  { 0x00003, "OutsideRing" },
  { 0x00004, "FeatureRing" },
  { 0x00005, "FlashOnly" },
  { 0x00006, "PrecedenceRing" },
  { 0x00000, NULL }
};
static value_string_ext RingMode_ext = VALUE_STRING_EXT_INIT(RingMode);

static const value_string RingDuration[] = {
  { 0x00001, "NormalRing" },
  { 0x00002, "SingleRing" },
  { 0x00000, NULL }
};
static value_string_ext RingDuration_ext = VALUE_STRING_EXT_INIT(RingDuration);

static const value_string LampMode[] = {
  { 0x00001, "Off" },
  { 0x00002, "On" },
  { 0x00003, "Wink" },
  { 0x00004, "Flash" },
  { 0x00005, "Blink" },
  { 0x00000, NULL }
};
static value_string_ext LampMode_ext = VALUE_STRING_EXT_INIT(LampMode);

static const value_string SpeakerMode[] = {
  { 0x00001, "On" },
  { 0x00002, "Off" },
  { 0x00000, NULL }
};
static value_string_ext SpeakerMode_ext = VALUE_STRING_EXT_INIT(SpeakerMode);

static const value_string MicrophoneMode[] = {
  { 0x00001, "On" },
  { 0x00002, "Off" },
  { 0x00000, NULL }
};
static value_string_ext MicrophoneMode_ext = VALUE_STRING_EXT_INIT(MicrophoneMode);

static const value_string Media_SilenceSuppression[] = {
  { 0x00000, "Media_SilenceSuppression_Off" },
  { 0x00001, "Media_SilenceSuppression_On" },
  { 0x00000, NULL }
};
static value_string_ext Media_SilenceSuppression_ext = VALUE_STRING_EXT_INIT(Media_SilenceSuppression);

static const value_string MediaEncryptionAlgorithmType[] = {
  { 0x00000, "NO_ENCRYPTION" },
  { 0x00001, "CCM_AES_CM_128_HMAC_SHA1_32" },
  { 0x00002, "CCM_AES_CM_128_HMAC_SHA1_80" },
  { 0x00003, "CCM_F8_128_HMAC_SHA1_32" },
  { 0x00004, "CCM_F8_128_HMAC_SHA1_80" },
  { 0x00005, "CCM_AEAD_AES_128_GCM" },
  { 0x00006, "CCM_AEAD_AES_256_GCM" },
  { 0x00000, NULL }
};
static value_string_ext MediaEncryptionAlgorithmType_ext = VALUE_STRING_EXT_INIT(MediaEncryptionAlgorithmType);

static const value_string PortHandling[] = {
  { 0x00000, "CLOSE_PORT" },
  { 0x00001, "KEEP_PORT" },
  { 0x00000, NULL }
};
static value_string_ext PortHandling_ext = VALUE_STRING_EXT_INIT(PortHandling);

static const value_string CallType[] = {
  { 0x00001, "InBoundCall" },
  { 0x00002, "OutBoundCall" },
  { 0x00003, "ForwardCall" },
  { 0x00000, NULL }
};
static value_string_ext CallType_ext = VALUE_STRING_EXT_INIT(CallType);

static const value_string CallSecurityStatusType[] = {
  { 0x00000, "Unknown" },
  { 0x00001, "NotAuthenticated" },
  { 0x00002, "Authenticated" },
  { 0x00003, "Encrypted" },
  { 0x00004, "Max" },
  { 0x00000, NULL }
};
static value_string_ext CallSecurityStatusType_ext = VALUE_STRING_EXT_INIT(CallSecurityStatusType);

static const value_string SessionType[] = {
  { 0x00001, "Chat" },
  { 0x00002, "Whiteboard" },
  { 0x00004, "ApplicationSharing" },
  { 0x00008, "FileTransfer" },
  { 0x00010, "Video" },
  { 0x00000, NULL }
};
static value_string_ext SessionType_ext = VALUE_STRING_EXT_INIT(SessionType);

static const value_string ButtonType[] = {
  { 0x00000, "Unused" },
  { 0x00001, "Last Number Redial" },
  { 0x00002, "SpeedDial" },
  { 0x00003, "Hold" },
  { 0x00004, "Transfer" },
  { 0x00005, "Forward All" },
  { 0x00006, "Forward Busy" },
  { 0x00007, "Forward No Answer" },
  { 0x00008, "Display" },
  { 0x00009, "Line" },
  { 0x0000a, "T120 Chat" },
  { 0x0000b, "T120 Whiteboard" },
  { 0x0000c, "T120 Application Sharing" },
  { 0x0000d, "T120 File Transfer" },
  { 0x0000e, "Video" },
  { 0x0000f, "Voicemail" },
  { 0x00010, "Answer Release" },
  { 0x00011, "Auto Answer" },
  { 0x00012, "Select" },
  { 0x00013, "Feature" },
  { 0x00014, "ServiceURL" },
  { 0x00015, "BusyLampField Speeddial" },
  { 0x0001b, "Malicious Call" },
  { 0x00021, "Generic App B1" },
  { 0x00022, "Generic App B2" },
  { 0x00023, "Generic App B3" },
  { 0x00024, "Generic App B4" },
  { 0x00025, "Generic App B5" },
  { 0x00026, "Monitor/Multiblink" },
  { 0x0007b, "Meet Me Conference" },
  { 0x0007d, "Conference" },
  { 0x0007e, "Call Park" },
  { 0x0007f, "Call Pickup" },
  { 0x00080, "Group Call Pickup" },
  { 0x00081, "Mobility" },
  { 0x00082, "DoNotDisturb" },
  { 0x00083, "ConfList" },
  { 0x00084, "RemoveLastParticipant" },
  { 0x00085, "QRT" },
  { 0x00086, "CallBack" },
  { 0x00087, "OtherPickup" },
  { 0x00088, "VideoMode" },
  { 0x00089, "NewCall" },
  { 0x0008a, "EndCall" },
  { 0x0008b, "HLog" },
  { 0x0008f, "Queuing" },
  { 0x000c0, "Test E" },
  { 0x000c1, "Test F" },
  { 0x000c2, "Messages" },
  { 0x000c3, "Directory" },
  { 0x000c4, "Test I" },
  { 0x000c5, "Application" },
  { 0x000c6, "Headset" },
  { 0x000f0, "Keypad" },
  { 0x000fd, "Aec" },
  { 0x000ff, "Undefined" },
  { 0x00000, NULL }
};
static value_string_ext ButtonType_ext = VALUE_STRING_EXT_INIT(ButtonType);

static const value_string DeviceResetType[] = {
  { 0x00001, "RESET" },
  { 0x00002, "RESTART" },
  { 0x00003, "APPLY_CONFIG" },
  { 0x00000, NULL }
};
static value_string_ext DeviceResetType_ext = VALUE_STRING_EXT_INIT(DeviceResetType);

static const value_string Media_EchoCancellation[] = {
  { 0x00000, "Media_EchoCancellation_Off" },
  { 0x00001, "Media_EchoCancellation_On" },
  { 0x00000, NULL }
};
static value_string_ext Media_EchoCancellation_ext = VALUE_STRING_EXT_INIT(Media_EchoCancellation);

static const value_string SoftKeyTemplateIndex[] = {
  { 0x00001, "Redial" },
  { 0x00002, "NewCall" },
  { 0x00003, "Hold" },
  { 0x00004, "Transfer" },
  { 0x00005, "CfwdAll" },
  { 0x00006, "CfwdBusy" },
  { 0x00007, "CfwdNoAnswer" },
  { 0x00008, "BackSpace" },
  { 0x00009, "EndCall" },
  { 0x0000a, "Resume" },
  { 0x0000b, "Answer" },
  { 0x0000c, "Info" },
  { 0x0000d, "Confrn" },
  { 0x0000e, "Park" },
  { 0x0000f, "Join" },
  { 0x00010, "MeetMe" },
  { 0x00011, "PickUp" },
  { 0x00012, "GrpPickup" },
  { 0x00013, "Monitor" },
  { 0x00014, "CallBack" },
  { 0x00015, "Barge" },
  { 0x00016, "DND" },
  { 0x00017, "ConfList" },
  { 0x00018, "Select" },
  { 0x00019, "Private" },
  { 0x0001a, "Transfer Voicemail" },
  { 0x0001b, "Direct Transfer" },
  { 0x0001c, "Immediate Divert" },
  { 0x0001d, "Video Mode" },
  { 0x0001e, "Intercept" },
  { 0x0001f, "Empty" },
  { 0x00020, "Dial" },
  { 0x00021, "Conference Barge" },
  { 0x00000, NULL }
};
static value_string_ext SoftKeyTemplateIndex_ext = VALUE_STRING_EXT_INIT(SoftKeyTemplateIndex);

static const value_string SoftKeyInfoIndex[] = {
  { 0x0012d, "Redial" },
  { 0x0012e, "NewCall" },
  { 0x0012f, "Hold" },
  { 0x00130, "Transfer" },
  { 0x00131, "CfwdAll" },
  { 0x00132, "CfwdBusy" },
  { 0x00133, "CfwdNoAnswer" },
  { 0x00134, "BackSpace" },
  { 0x00135, "EndCall" },
  { 0x00136, "Resume" },
  { 0x00137, "Answer" },
  { 0x00138, "Info" },
  { 0x00139, "Confrn" },
  { 0x0013a, "Park" },
  { 0x0013b, "Join" },
  { 0x0013c, "MeetMe" },
  { 0x0013d, "PickUp" },
  { 0x0013e, "GrpPickup" },
  { 0x0013f, "Monitor" },
  { 0x00140, "CallBack" },
  { 0x00141, "Barge" },
  { 0x00142, "DND" },
  { 0x00143, "ConfList" },
  { 0x00144, "Select" },
  { 0x00145, "Private" },
  { 0x00146, "Transfer Voicemail" },
  { 0x00147, "Direct Transfer" },
  { 0x00148, "Immediate Divert" },
  { 0x00149, "Video Mode" },
  { 0x0014a, "Intercept" },
  { 0x0014b, "Empty" },
  { 0x0014c, "Dial" },
  { 0x0014d, "Conference Barge" },
  { 0x00000, NULL }
};
static value_string_ext SoftKeyInfoIndex_ext = VALUE_STRING_EXT_INIT(SoftKeyInfoIndex);

static const value_string DCallState[] = {
  { 0x00000, "Idle" },
  { 0x00001, "OffHook" },
  { 0x00002, "OnHook" },
  { 0x00003, "RingOut" },
  { 0x00004, "RingIn" },
  { 0x00005, "Connected" },
  { 0x00006, "Busy" },
  { 0x00007, "Congestion" },
  { 0x00008, "Hold" },
  { 0x00009, "CallWaiting" },
  { 0x0000a, "CallTransfer" },
  { 0x0000b, "CallPark" },
  { 0x0000c, "Proceed" },
  { 0x0000d, "CallRemoteMultiline" },
  { 0x0000e, "InvalidNumber" },
  { 0x0000f, "HoldRevert" },
  { 0x00010, "Whisper" },
  { 0x00011, "RemoteHold" },
  { 0x00012, "MaxState" },
  { 0x00000, NULL }
};
static value_string_ext DCallState_ext = VALUE_STRING_EXT_INIT(DCallState);

static const value_string CallPrivacy[] = {
  { 0x00000, "None" },
  { 0x00001, "Limited" },
  { 0x00002, "Full" },
  { 0x00000, NULL }
};
static value_string_ext CallPrivacy_ext = VALUE_STRING_EXT_INIT(CallPrivacy);

static const value_string DeviceUnregisterStatus[] = {
  { 0x00000, "Ok" },
  { 0x00001, "Error" },
  { 0x00002, "NAK" },
  { 0x00000, NULL }
};
static value_string_ext DeviceUnregisterStatus_ext = VALUE_STRING_EXT_INIT(DeviceUnregisterStatus);

static const value_string EndOfAnnAck[] = {
  { 0x00000, "NoAnnAckRequired" },
  { 0x00001, "AnnAckRequired" },
  { 0x00000, NULL }
};
static value_string_ext EndOfAnnAck_ext = VALUE_STRING_EXT_INIT(EndOfAnnAck);

static const value_string AnnPlayMode[] = {
  { 0x00000, "XmlConfigMode" },
  { 0x00001, "OneShotMode" },
  { 0x00002, "ContinuousMode" },
  { 0x00000, NULL }
};
static value_string_ext AnnPlayMode_ext = VALUE_STRING_EXT_INIT(AnnPlayMode);

static const value_string PlayAnnStatus[] = {
  { 0x00000, "OK" },
  { 0x00001, "Err" },
  { 0x00000, NULL }
};
static value_string_ext PlayAnnStatus_ext = VALUE_STRING_EXT_INIT(PlayAnnStatus);

#define MISCCOMMANDTYPE_VIDEOFREEZEPICTURE     0x00000
#define MISCCOMMANDTYPE_VIDEOFASTUPDATEPICTURE 0x00001
#define MISCCOMMANDTYPE_VIDEOFASTUPDATEGOB     0x00002
#define MISCCOMMANDTYPE_VIDEOFASTUPDATEMB      0x00003
#define MISCCOMMANDTYPE_LOSTPICTURE            0x00004
#define MISCCOMMANDTYPE_LOSTPARTIALPICTURE     0x00005
#define MISCCOMMANDTYPE_RECOVERYREFERENCEPICTURE 0x00006
#define MISCCOMMANDTYPE_TEMPORALSPATIALTRADEOFF 0x00007

static const value_string MiscCommandType[] = {
  { MISCCOMMANDTYPE_VIDEOFREEZEPICTURE, "videoFreezePicture" },
  { MISCCOMMANDTYPE_VIDEOFASTUPDATEPICTURE, "videoFastUpdatePicture" },
  { MISCCOMMANDTYPE_VIDEOFASTUPDATEGOB, "videoFastUpdateGOB" },
  { MISCCOMMANDTYPE_VIDEOFASTUPDATEMB, "videoFastUpdateMB" },
  { MISCCOMMANDTYPE_LOSTPICTURE, "lostPicture" },
  { MISCCOMMANDTYPE_LOSTPARTIALPICTURE, "lostPartialPicture" },
  { MISCCOMMANDTYPE_RECOVERYREFERENCEPICTURE, "recoveryReferencePicture" },
  { MISCCOMMANDTYPE_TEMPORALSPATIALTRADEOFF, "temporalSpatialTradeOff" },
  { 0x00000, NULL }
};
static value_string_ext MiscCommandType_ext = VALUE_STRING_EXT_INIT(MiscCommandType);

static const value_string MediaTransportType[] = {
  { 0x00001, "RTP" },
  { 0x00002, "UDP" },
  { 0x00003, "TCP" },
  { 0x00000, NULL }
};
static value_string_ext MediaTransportType_ext = VALUE_STRING_EXT_INIT(MediaTransportType);

static const value_string ResvStyle[] = {
  { 0x00001, "FF" },
  { 0x00002, "SE" },
  { 0x00003, "WF" },
  { 0x00000, NULL }
};
static value_string_ext ResvStyle_ext = VALUE_STRING_EXT_INIT(ResvStyle);

static const value_string SubscribeCause[] = {
  { 0x00000, "OK" },
  { 0x00001, "RouteFail" },
  { 0x00002, "AuthFail" },
  { 0x00003, "Timeout" },
  { 0x00004, "TrunkTerm" },
  { 0x00005, "TrunkForbidden" },
  { 0x00006, "Throttle" },
  { 0x00000, NULL }
};
static value_string_ext SubscribeCause_ext = VALUE_STRING_EXT_INIT(SubscribeCause);

static const value_string CallHistoryDisposition[] = {
  { 0x00000, "Ignore" },
  { 0x00001, "PlacedCalls" },
  { 0x00002, "ReceivedCalls" },
  { 0x00003, "MissedCalls" },
  { 0x0ffff, "UnknownDisp" },
  { 0x00000, NULL }
};
static value_string_ext CallHistoryDisposition_ext = VALUE_STRING_EXT_INIT(CallHistoryDisposition);

static const value_string MwiNotificationResult[] = {
  { 0x00000, "Ok" },
  { 0x00001, "GeneralError" },
  { 0x00002, "RequestRejected" },
  { 0x00003, "VmCountOutOfBounds" },
  { 0x00004, "FaxCountOutOfBounds" },
  { 0x00005, "InvalidPriorityVmCount" },
  { 0x00006, "InvalidPriorityFaxCount" },
  { 0x00000, NULL }
};
static value_string_ext MwiNotificationResult_ext = VALUE_STRING_EXT_INIT(MwiNotificationResult);

static const value_string RecordingStatus[] = {
  { 0x00000, "_OFF" },
  { 0x00001, "_ON" },
  { 0x00000, NULL }
};
static value_string_ext RecordingStatus_ext = VALUE_STRING_EXT_INIT(RecordingStatus);


/* Staticly Declared Variables */
static int proto_skinny;
static int hf_skinny_messageId;
static int hf_skinny_data_length;
static int hf_skinny_hdr_version;
static int hf_skinny_xmlData;
static int hf_skinny_ipv4or6;
static int hf_skinny_response_in;
static int hf_skinny_response_to;
static int hf_skinny_response_time;

static int hf_skinny_AlternateCallingParty;
static int hf_skinny_CallingPartyName;
static int hf_skinny_CallingPartyNumber;
static int hf_skinny_DSCPValue;
static int hf_skinny_DeviceName;
static int hf_skinny_FutureUse1;
static int hf_skinny_FutureUse2;
static int hf_skinny_FutureUse3;
static int hf_skinny_Generic_Bitfield_Bit1;
static int hf_skinny_Generic_Bitfield_Bit10;
static int hf_skinny_Generic_Bitfield_Bit11;
static int hf_skinny_Generic_Bitfield_Bit12;
static int hf_skinny_Generic_Bitfield_Bit13;
static int hf_skinny_Generic_Bitfield_Bit14;
static int hf_skinny_Generic_Bitfield_Bit15;
static int hf_skinny_Generic_Bitfield_Bit16;
static int hf_skinny_Generic_Bitfield_Bit17;
static int hf_skinny_Generic_Bitfield_Bit18;
static int hf_skinny_Generic_Bitfield_Bit19;
static int hf_skinny_Generic_Bitfield_Bit2;
static int hf_skinny_Generic_Bitfield_Bit20;
static int hf_skinny_Generic_Bitfield_Bit21;
static int hf_skinny_Generic_Bitfield_Bit22;
static int hf_skinny_Generic_Bitfield_Bit23;
static int hf_skinny_Generic_Bitfield_Bit24;
static int hf_skinny_Generic_Bitfield_Bit25;
static int hf_skinny_Generic_Bitfield_Bit26;
static int hf_skinny_Generic_Bitfield_Bit27;
static int hf_skinny_Generic_Bitfield_Bit28;
static int hf_skinny_Generic_Bitfield_Bit29;
static int hf_skinny_Generic_Bitfield_Bit3;
static int hf_skinny_Generic_Bitfield_Bit30;
static int hf_skinny_Generic_Bitfield_Bit31;
static int hf_skinny_Generic_Bitfield_Bit32;
static int hf_skinny_Generic_Bitfield_Bit4;
static int hf_skinny_Generic_Bitfield_Bit5;
static int hf_skinny_Generic_Bitfield_Bit6;
static int hf_skinny_Generic_Bitfield_Bit7;
static int hf_skinny_Generic_Bitfield_Bit8;
static int hf_skinny_Generic_Bitfield_Bit9;
static int hf_skinny_HuntPilotName;
static int hf_skinny_HuntPilotNumber;
static int hf_skinny_MPI;
static int hf_skinny_OrigDialed;
static int hf_skinny_PhoneFeatures_Abbreviated_Dial;
static int hf_skinny_PhoneFeatures_Bit1;
static int hf_skinny_PhoneFeatures_Bit11;
static int hf_skinny_PhoneFeatures_Bit12;
static int hf_skinny_PhoneFeatures_Bit13;
static int hf_skinny_PhoneFeatures_Bit14;
static int hf_skinny_PhoneFeatures_Bit15;
static int hf_skinny_PhoneFeatures_Bit2;
static int hf_skinny_PhoneFeatures_Bit3;
static int hf_skinny_PhoneFeatures_Bit4;
static int hf_skinny_PhoneFeatures_Bit6;
static int hf_skinny_PhoneFeatures_Bit7;
static int hf_skinny_PhoneFeatures_Bit9;
static int hf_skinny_PhoneFeatures_DynamicMessages;
static int hf_skinny_PhoneFeatures_RFC2833;
static int hf_skinny_PhoneFeatures_UTF8;
static int hf_skinny_RFC2833PayloadType;
static int hf_skinny_RTCPPortNumber;
static int hf_skinny_RedirDialed;
static int hf_skinny_RestrictInformationType_BitsReserved;
static int hf_skinny_RestrictInformationType_CalledParty;
static int hf_skinny_RestrictInformationType_CalledPartyName;
static int hf_skinny_RestrictInformationType_CalledPartyNumber;
static int hf_skinny_RestrictInformationType_CallingParty;
static int hf_skinny_RestrictInformationType_CallingPartyName;
static int hf_skinny_RestrictInformationType_CallingPartyNumber;
static int hf_skinny_RestrictInformationType_LastRedirectParty;
static int hf_skinny_RestrictInformationType_LastRedirectPartyName;
static int hf_skinny_RestrictInformationType_LastRedirectPartyNumber;
static int hf_skinny_RestrictInformationType_OriginalCalledParty;
static int hf_skinny_RestrictInformationType_OriginalCalledPartyName;
static int hf_skinny_RestrictInformationType_OriginalCalledPartyNumber;
static int hf_skinny_ServerName;
static int hf_skinny_SoftKeyMask_SoftKey1;
static int hf_skinny_SoftKeyMask_SoftKey10;
static int hf_skinny_SoftKeyMask_SoftKey11;
static int hf_skinny_SoftKeyMask_SoftKey12;
static int hf_skinny_SoftKeyMask_SoftKey13;
static int hf_skinny_SoftKeyMask_SoftKey14;
static int hf_skinny_SoftKeyMask_SoftKey15;
static int hf_skinny_SoftKeyMask_SoftKey16;
static int hf_skinny_SoftKeyMask_SoftKey2;
static int hf_skinny_SoftKeyMask_SoftKey3;
static int hf_skinny_SoftKeyMask_SoftKey4;
static int hf_skinny_SoftKeyMask_SoftKey5;
static int hf_skinny_SoftKeyMask_SoftKey6;
static int hf_skinny_SoftKeyMask_SoftKey7;
static int hf_skinny_SoftKeyMask_SoftKey8;
static int hf_skinny_SoftKeyMask_SoftKey9;
static int hf_skinny_active;
static int hf_skinny_activeConferenceOnRegistration;
static int hf_skinny_activeConferences;
static int hf_skinny_activeForward;
static int hf_skinny_activeStreams;
static int hf_skinny_activeStreamsOnRegistration;
static int hf_skinny_add_participant_result;
static int hf_skinny_alarmInfo;
static int hf_skinny_alarmSeverity;
static int hf_skinny_algorithmID;
static int hf_skinny_alignmentPadding;
static int hf_skinny_annAckReq;
static int hf_skinny_annPlayMode;
static int hf_skinny_annStatus;
static int hf_skinny_annexNandWFutureUse;
static int hf_skinny_appConfID;
static int hf_skinny_appData;
static int hf_skinny_appInstanceID;
static int hf_skinny_appName;
static int hf_skinny_applicationId;
static int hf_skinny_areMessagesWaiting;
static int hf_skinny_associatedStreamId;
static int hf_skinny_audioCapCount;
static int hf_skinny_audioLevelAdjustment;
static int hf_skinny_audit_participant_result;
static int hf_skinny_averageBitRate;
static int hf_skinny_bandwidth;
static int hf_skinny_bitRate;
static int hf_skinny_bridgeParticipantId;
static int hf_skinny_burstSize;
static int hf_skinny_busyTrigger;
static int hf_skinny_buttonCount;
static int hf_skinny_buttonDefinition;
static int hf_skinny_buttonOffset;
static int hf_skinny_callHistoryDisposition;
static int hf_skinny_callInstance;
static int hf_skinny_callReference;
static int hf_skinny_callSecurityStatus;
static int hf_skinny_callSelectStat;
static int hf_skinny_callState;
static int hf_skinny_callType;
static int hf_skinny_calledParty;
static int hf_skinny_calledPartyName;
static int hf_skinny_callingParty;
static int hf_skinny_callingPartyName;
static int hf_skinny_callingPartyNumber;
static int hf_skinny_capAndVer;
static int hf_skinny_capCount;
static int hf_skinny_cause;
static int hf_skinny_cdpnVoiceMailbox;
static int hf_skinny_cgpnVoiceMailbox;
static int hf_skinny_chan0MaxPayload;
static int hf_skinny_chan2MaxPayload;
static int hf_skinny_chan2MaxWindow;
static int hf_skinny_chan3MaxPayload;
static int hf_skinny_clockConversionCode;
static int hf_skinny_clockDivisor;
static int hf_skinny_codecMode;
static int hf_skinny_codecParam1;
static int hf_skinny_codecParam2;
static int hf_skinny_command;
static int hf_skinny_compressionType;
static int hf_skinny_confServiceNum;
static int hf_skinny_conferenceId;
static int hf_skinny_conferenceName;
static int hf_skinny_configVersionStamp;
static int hf_skinny_confirmRequired;
static int hf_skinny_country;
static int hf_skinny_customMaxBRandCPB;
static int hf_skinny_customMaxDPB;
static int hf_skinny_customMaxFS;
static int hf_skinny_customMaxMBPS;
static int hf_skinny_customPictureFormatCount;
static int hf_skinny_data;
static int hf_skinny_dataCapCount;
static int hf_skinny_dataCapabilityDirection;
static int hf_skinny_dataLength;
static int hf_skinny_dataSize;
static int hf_skinny_dateTemplate;
static int hf_skinny_defendingPriority;
static int hf_skinny_delete_conf_result;
static int hf_skinny_deviceType;
static int hf_skinny_dialedNumber;
static int hf_skinny_direction;
static int hf_skinny_directoryNum;
static int hf_skinny_displayPriority;
static int hf_skinny_dtmfType;
static int hf_skinny_dynamicPayload;
static int hf_skinny_ecValue;
static int hf_skinny_encryptionCapability;
static int hf_skinny_errorCode;
static int hf_skinny_failureNodeIpAddr;
static int hf_skinny_featureCapabilities;
static int hf_skinny_featureID;
static int hf_skinny_featureIndex;
static int hf_skinny_featureStatus;
static int hf_skinny_featureTextLabel;
static int hf_skinny_features;
static int hf_skinny_firmwareLoadName;
static int hf_skinny_firstGOB;
static int hf_skinny_firstMB;
static int hf_skinny_format;
static int hf_skinny_forwardAllActive;
static int hf_skinny_forwardAllDirnum;
static int hf_skinny_forwardBusyActive;
static int hf_skinny_forwardBusyDirnum;
static int hf_skinny_forwardNoAnswerActive;
static int hf_skinny_forwardNoAnswerlDirnum;
static int hf_skinny_g723BitRate;
static int hf_skinny_headsetStatus;
static int hf_skinny_hearingConfPartyMask;
static int hf_skinny_instance;
static int hf_skinny_instanceNumber;
static int hf_skinny_ipAddr_ipv4;
static int hf_skinny_ipAddr_ipv6;
static int hf_skinny_ipAddressType;
static int hf_skinny_ipAddressingMode;
static int hf_skinny_ipV4AddressScope;
static int hf_skinny_ipV6AddressScope;
static int hf_skinny_isConferenceCreator;
static int hf_skinny_isMKIPresent;
static int hf_skinny_jitter;
static int hf_skinny_keepAliveInterval;
static int hf_skinny_key;
static int hf_skinny_keyDerivationRate;
static int hf_skinny_keylen;
static int hf_skinny_kpButton;
static int hf_skinny_lampMode;
static int hf_skinny_last;
static int hf_skinny_lastRedirectingParty;
static int hf_skinny_lastRedirectingPartyName;
static int hf_skinny_lastRedirectingReason;
static int hf_skinny_lastRedirectingVoiceMailbox;
static int hf_skinny_latency;
static int hf_skinny_layoutCount;
static int hf_skinny_layoutID;
static int hf_skinny_layouts;
static int hf_skinny_level;
static int hf_skinny_levelPreferenceCount;
static int hf_skinny_lineDataEntries;
static int hf_skinny_lineDirNumber;
static int hf_skinny_lineDisplayOptions;
static int hf_skinny_lineFullyQualifiedDisplayName;
static int hf_skinny_lineInstance;
static int hf_skinny_lineNumber;
static int hf_skinny_lineTextLabel;
static int hf_skinny_locale;
static int hf_skinny_locationInfo;
static int hf_skinny_longTermPictureIndex;
static int hf_skinny_macAddress;
static int hf_skinny_matrixConfPartyID;
static int hf_skinny_maxBW;
static int hf_skinny_maxBitRate;
static int hf_skinny_maxConferences;
static int hf_skinny_maxFramesPerPacket;
static int hf_skinny_maxNumCalls;
static int hf_skinny_maxNumOfAvailLines;
static int hf_skinny_maxNumberOfLines;
static int hf_skinny_maxProtocolVer;
static int hf_skinny_maxRetryNumber;
static int hf_skinny_maxStreams;
static int hf_skinny_maxStreamsPerConf;
static int hf_skinny_maximumBitRate;
static int hf_skinny_mediaPathCapabilities;
static int hf_skinny_mediaPathEvent;
static int hf_skinny_mediaPathID;
static int hf_skinny_mediaReceptionStatus;
static int hf_skinny_mediaTransmissionStatus;
static int hf_skinny_mediaTransportType;
static int hf_skinny_mediaType;
static int hf_skinny_micMode;
static int hf_skinny_milliSecondPacketSize;
static int hf_skinny_minBitRate;
static int hf_skinny_mixingMode;
static int hf_skinny_modAnd2833;
static int hf_skinny_modelNumber;
static int hf_skinny_modify_conf_result;
static int hf_skinny_multicastIpAddr_ipv4;
static int hf_skinny_multicastIpAddr_ipv6;
static int hf_skinny_multicastPortNumber;
static int hf_skinny_multicastReceptionStatus;
static int hf_skinny_multimediaReceptionStatus;
static int hf_skinny_multimediaTransmissionStatus;
static int hf_skinny_mwiControlNumber;
static int hf_skinny_mwiTargetNumber;
static int hf_skinny_mwi_notification_result;
static int hf_skinny_noaudio;
static int hf_skinny_none;
static int hf_skinny_notificationStatus;
static int hf_skinny_notify;
static int hf_skinny_nse;
static int hf_skinny_numNewMsgs;
static int hf_skinny_numOldMsgs;
static int hf_skinny_numberOctetsReceived;
static int hf_skinny_numberOctetsSent;
static int hf_skinny_numberOfActiveParticipants;
static int hf_skinny_numberOfEntries;
static int hf_skinny_numberOfGOBs;
static int hf_skinny_numberOfInServiceStreams;
static int hf_skinny_numberOfLines;
static int hf_skinny_numberOfMBs;
static int hf_skinny_numberOfOutOfServiceStreams;
static int hf_skinny_numberOfReservedParticipants;
static int hf_skinny_numberOfSpeedDials;
static int hf_skinny_numberPacketsLost;
static int hf_skinny_numberPacketsReceived;
static int hf_skinny_numberPacketsSent;
static int hf_skinny_originalCalledParty;
static int hf_skinny_originalCalledPartyName;
static int hf_skinny_originalCdpnRedirectReason;
static int hf_skinny_originalCdpnVoiceMailbox;
static int hf_skinny_padding;
static int hf_skinny_parm1;
static int hf_skinny_parm2;
static int hf_skinny_participantEntry;
static int hf_skinny_participantName;
static int hf_skinny_participantNumber;
static int hf_skinny_partyDirection;
static int hf_skinny_passThroughPartyId;
static int hf_skinny_passThruData;
static int hf_skinny_passthruPartyID;
static int hf_skinny_payloadCapability;
static int hf_skinny_payloadDtmf;
static int hf_skinny_payloadType;
static int hf_skinny_payload_rfc_number;
static int hf_skinny_peakRate;
static int hf_skinny_pictureFormatCount;
static int hf_skinny_pictureHeight;
static int hf_skinny_pictureNumber;
static int hf_skinny_pictureWidth;
static int hf_skinny_pixelAspectRatio;
static int hf_skinny_portHandlingFlag;
static int hf_skinny_portNumber;
static int hf_skinny_precedenceDomain;
static int hf_skinny_precedenceLevel;
static int hf_skinny_precedenceValue;
static int hf_skinny_preemptionPriority;
static int hf_skinny_priority;
static int hf_skinny_privacy;
static int hf_skinny_profile;
static int hf_skinny_promptStatus;
static int hf_skinny_protocolDependentData;
static int hf_skinny_protocolVer;
static int hf_skinny_recording_status;
static int hf_skinny_recoveryReferencePictureCount;
static int hf_skinny_remoteIpAddr_ipv4;
static int hf_skinny_remoteIpAddr_ipv6;
static int hf_skinny_remotePortNumber;
static int hf_skinny_requestedIpAddrType;
static int hf_skinny_reserved_for_future_use;
static int hf_skinny_resetType;
static int hf_skinny_resourceType;
static int hf_skinny_result;
static int hf_skinny_resvStyle;
static int hf_skinny_retryTimer;
static int hf_skinny_rfc2833;
static int hf_skinny_ringDuration;
static int hf_skinny_ringMode;
static int hf_skinny_routingID;
static int hf_skinny_rsvpErrorCode;
static int hf_skinny_rsvpErrorFlag;
static int hf_skinny_rsvpErrorSubCodeVal;
static int hf_skinny_rtpMediaPort;
static int hf_skinny_rtpPayloadFormat;
static int hf_skinny_salt;
static int hf_skinny_saltlen;
static int hf_skinny_secondaryKeepAliveInterval;
static int hf_skinny_sequenceFlag;
static int hf_skinny_serverName;
static int hf_skinny_serverTcpListenPort;
static int hf_skinny_serviceNum;
static int hf_skinny_serviceNumber;
static int hf_skinny_serviceResourceCount;
static int hf_skinny_serviceURL;
static int hf_skinny_serviceURLDisplayName;
static int hf_skinny_serviceURLIndex;
static int hf_skinny_sessionType;
static int hf_skinny_softKeyCount;
static int hf_skinny_softKeyEvent;
static int hf_skinny_softKeyInfoIndex;
static int hf_skinny_softKeyLabel;
static int hf_skinny_softKeyOffset;
static int hf_skinny_softKeySetCount;
static int hf_skinny_softKeySetIndex;
static int hf_skinny_softKeySetOffset;
static int hf_skinny_softKeyTemplateIndex;
static int hf_skinny_sourceIpAddr_ipv4;
static int hf_skinny_sourceIpAddr_ipv6;
static int hf_skinny_sourcePortNumber;
static int hf_skinny_speakerMode;
static int hf_skinny_speedDialDirNumber;
static int hf_skinny_speedDialDisplayName;
static int hf_skinny_speedDialNumber;
static int hf_skinny_ssValue;
static int hf_skinny_sse;
static int hf_skinny_standard;
static int hf_skinny_startingLineInstance;
static int hf_skinny_stationIpAddr;
static int hf_skinny_stationIpAddr_ipv4;
static int hf_skinny_stationIpAddr_ipv6;
static int hf_skinny_stationIpV6Addr;
static int hf_skinny_stationIpV6Addr_ipv4;
static int hf_skinny_stationIpV6Addr_ipv6;
static int hf_skinny_statsProcessingMode;
static int hf_skinny_status;
static int hf_skinny_stillImageTransmission;
static int hf_skinny_stimulus;
static int hf_skinny_stimulusInstance;
static int hf_skinny_stimulusStatus;
static int hf_skinny_streamPassThroughId;
static int hf_skinny_subAppID;
static int hf_skinny_subscriptionFeatureID;
static int hf_skinny_subscriptionID;
static int hf_skinny_systemTime;
static int hf_skinny_temporalSpatialTradeOff;
static int hf_skinny_temporalSpatialTradeOffCapability;
static int hf_skinny_text;
static int hf_skinny_timeOutValue;
static int hf_skinny_timer;
static int hf_skinny_tone;
static int hf_skinny_toneAnnouncement;
static int hf_skinny_tone_output_direction;
static int hf_skinny_totalButtonCount;
static int hf_skinny_totalNumOfConfiguredLines;
static int hf_skinny_totalSoftKeyCount;
static int hf_skinny_totalSoftKeySetCount;
static int hf_skinny_transactionId;
static int hf_skinny_transmitIpAddr_ipv4;
static int hf_skinny_transmitIpAddr_ipv6;
static int hf_skinny_transmitPreference;
static int hf_skinny_unRegReasonCode;
static int hf_skinny_unknown;
static int hf_skinny_unknown1_0159;
static int hf_skinny_unknown2_0159;
static int hf_skinny_unknown3_0159;
static int hf_skinny_unknownString_0159;
static int hf_skinny_userName;
static int hf_skinny_v150sprt;
static int hf_skinny_vendor;
static int hf_skinny_vendorID;
static int hf_skinny_version;
static int hf_skinny_versionStr;
static int hf_skinny_videoCapCount;
static int hf_skinny_videoCapabilityDirection;
static int hf_skinny_wDay;
static int hf_skinny_wDayOfWeek;
static int hf_skinny_wHour;
static int hf_skinny_wMilliseconds;
static int hf_skinny_wMinute;
static int hf_skinny_wMonth;
static int hf_skinny_wSecond;
static int hf_skinny_wYear;
static int hf_skinny_waitTimeBeforeNextReq;
static int hf_skinny_xmldata;

static dissector_handle_t xml_handle;

/* Initialize the subtree pointers */
static int ett_skinny;
static int ett_skinny_tree;

/* preference globals */
static bool global_skinny_desegment = true;

/* tap register id */
static int skinny_tap;

/* skinny protocol tap info */
#define MAX_SKINNY_MESSAGES_IN_PACKET 10
static skinny_info_t pi_arr[MAX_SKINNY_MESSAGES_IN_PACKET];
static int pi_current;
static skinny_info_t *si;

dissector_handle_t skinny_handle;

/* Get the length of a single SKINNY PDU */
static unsigned
get_skinny_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  uint32_t hdr_data_length;

  /* Get the length of the SKINNY packet. */
  hdr_data_length = tvb_get_letohl(tvb, offset);

  /* That length doesn't include the length of the header itself. */
  return hdr_data_length + 8;
}

static void
dissect_skinny_xml(ptvcursor_t *cursor, int hfindex, packet_info *pinfo, uint32_t length, uint32_t maxlength)
{
  proto_item         *item       = NULL;
  proto_tree         *subtree    = NULL;
  proto_tree         *tree       = ptvcursor_tree(cursor);
  uint32_t           offset      = ptvcursor_current_offset(cursor);
  tvbuff_t           *tvb        = ptvcursor_tvbuff(cursor);
  tvbuff_t           *next_tvb;

  if (length == 0) {
    length = tvb_strnlen(tvb, offset, -1);
  }
  if (length >= maxlength) {
    length = maxlength;
  }

  ptvcursor_add_no_advance(cursor, hfindex, length, ENC_ASCII);

  item = proto_tree_add_item(tree, hf_skinny_xmlData, tvb, offset, length, ENC_ASCII);
  subtree = proto_item_add_subtree(item, 0);
  next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, -1);
  if (xml_handle != NULL) {
    call_dissector(xml_handle, next_tvb, pinfo, subtree);
  }
  ptvcursor_advance(cursor, maxlength);
}

static void
dissect_skinny_ipv4or6(ptvcursor_t *cursor, int hfindex_ipv4, int hfindex_ipv6)
{
  uint32_t           ipversion   = 0;
  uint32_t           offset      = ptvcursor_current_offset(cursor);
  tvbuff_t           *tvb        = ptvcursor_tvbuff(cursor);
  uint32_t           hdr_version = tvb_get_letohl(tvb, 4);

  /* ProtocolVersion > 18 include and extra field to declare IPv4 (0) / IPv6 (1) */
  if (hdr_version >= V17_MSG_TYPE) {
    ipversion = tvb_get_letohl(tvb, offset);
    ptvcursor_add(cursor, hf_skinny_ipv4or6, 4, ENC_LITTLE_ENDIAN);
  }
  if (ipversion == IPADDRTYPE_IPV4) {
    ptvcursor_add(cursor, hfindex_ipv4, 4, ENC_BIG_ENDIAN);
    if (hdr_version >= V17_MSG_TYPE) {
      /* skip over the extra room for ipv6 addresses */
      ptvcursor_advance(cursor, 12);
    }
  } else if (ipversion == IPADDRTYPE_IPV6 || ipversion == IPADDRTYPE_IPV4_V6) {
    ptvcursor_add(cursor, hfindex_ipv6, 16, ENC_NA);
  } else {
    /* Invalid : skip over ipv6 space completely */
    ptvcursor_advance(cursor, 16);
  }
}

/* Reads address to provided variable */
static void
read_skinny_ipv4or6(ptvcursor_t *cursor, address *media_addr)
{
  uint32_t           ipversion   = IPADDRTYPE_IPV4;
  uint32_t           offset      = ptvcursor_current_offset(cursor);
  uint32_t           offset2     = 0;
  tvbuff_t           *tvb        = ptvcursor_tvbuff(cursor);
  uint32_t           hdr_version = tvb_get_letohl(tvb, 4);

  /* ProtocolVersion > 18 include and extra field to declare IPv4 (0) / IPv6 (1) */
  if (hdr_version >= V17_MSG_TYPE) {
    ipversion = tvb_get_letohl(tvb, offset);
    offset2 = 4;
  }
  if (ipversion == IPADDRTYPE_IPV4) {
    set_address_tvb(media_addr, AT_IPv4, 4, tvb, offset+offset2);
  } else if (ipversion == IPADDRTYPE_IPV6 || ipversion == IPADDRTYPE_IPV4_V6) {
    set_address_tvb(media_addr, AT_IPv6, 16, tvb, offset+offset2);
  } else {
    clear_address(media_addr);
  }
}

/**
 * Parse a displayLabel string and check if it is using any embedded labels, if so lookup the label and add a user readable translation to the item_tree
 */
static void
dissect_skinny_displayLabel(ptvcursor_t *cursor, packet_info *pinfo, int hfindex, int length)
{
  proto_item    *item             = NULL;
  proto_tree    *tree             = ptvcursor_tree(cursor);
  uint32_t      offset            = ptvcursor_current_offset(cursor);
  tvbuff_t      *tvb              = ptvcursor_tvbuff(cursor);
  wmem_strbuf_t *wmem_new         = NULL;
  char          *disp_string      = NULL;
  const char    *replacestr       = NULL;
  bool          show_replaced_str = false;
  int           x                 = 0;

  if (length == 0) {
    length = tvb_strnlen(tvb, offset, -1);
    if (length == -1) {
      /* did not find end of string */
      length = tvb_captured_length_remaining(tvb, offset);
    }
  }

  item = proto_tree_add_item(tree, hfindex, tvb, offset, length, ENC_ASCII);

  wmem_new = wmem_strbuf_new_sized(pinfo->pool, length + 1);
  disp_string = (char*) wmem_alloc(pinfo->pool, length + 1);
  disp_string[length] = '\0';
  tvb_memcpy(tvb, (void*)disp_string, offset, length);

  for (x = 0; x < length && disp_string[x] != '\0'; x++) {
    replacestr = NULL;
    if (x + 1 < length) {
      if (disp_string[x] == '\36') {
        replacestr = try_val_to_str_ext(disp_string[x + 1], &DisplayLabels_36_ext);
      } else if (disp_string[x] == '\200') {
        replacestr = try_val_to_str_ext(disp_string[x + 1], &DisplayLabels_200_ext);
      }
    }
    if (replacestr) {
      x++;        /* swallow replaced characters */
      wmem_strbuf_append(wmem_new, replacestr);
      show_replaced_str = true;
    } else if (disp_string[x] & 0x80) {
      wmem_strbuf_append_unichar_repl(wmem_new);
    } else {
      wmem_strbuf_append_c(wmem_new, disp_string[x]);
    }
  }
  if (show_replaced_str) {
    si->additionalInfo = ws_strdup_printf("\"%s\"", wmem_strbuf_get_str(wmem_new));
    proto_item_append_text(item, " => \"%s\"" , wmem_strbuf_get_str(wmem_new));
  }
  ptvcursor_advance(cursor, length);
}

/*** Request / Response helper functions */
static void skinny_reqrep_add_request(ptvcursor_t *cursor, packet_info * pinfo, skinny_conv_info_t * skinny_conv, const int request_key)
{
  proto_tree *tree = ptvcursor_tree(cursor);
  tvbuff_t *tvb = ptvcursor_tvbuff(cursor);
  skinny_req_resp_t *req_resp = NULL;

  if (!PINFO_FD_VISITED(pinfo)) {
    req_resp = wmem_new0(wmem_file_scope(), skinny_req_resp_t);
    req_resp->request_frame = pinfo->num;
    req_resp->response_frame = 0;
    req_resp->request_time = pinfo->abs_ts;
    wmem_map_insert(skinny_conv->pending_req_resp, GINT_TO_POINTER(request_key), (void *)req_resp);
    DPRINT(("SKINNY: setup_request: frame=%d add key=%d to map\n", pinfo->num, request_key));
  }

  req_resp = (skinny_req_resp_t *) wmem_map_lookup(skinny_conv->requests, GUINT_TO_POINTER(pinfo->num));
  if (req_resp && req_resp->response_frame) {
    DPRINT(("SKINNY: show request in tree: frame/key=%d\n", pinfo->num));
    proto_item *it;
    it = proto_tree_add_uint(tree, hf_skinny_response_in, tvb, 0, 0, req_resp->response_frame);
    proto_item_set_generated(it);
  } else {
    DPRINT(("SKINNY: no request found for frame/key=%d\n", pinfo->num));
  }
}


static void skinny_reqrep_add_response(ptvcursor_t *cursor, packet_info * pinfo, skinny_conv_info_t * skinny_conv, const int request_key)
{
  proto_tree *tree = ptvcursor_tree(cursor);
  tvbuff_t *tvb = ptvcursor_tvbuff(cursor);
  skinny_req_resp_t *req_resp = NULL;

  if (!PINFO_FD_VISITED(pinfo)) {
    req_resp = (skinny_req_resp_t *) wmem_map_remove(skinny_conv->pending_req_resp, GINT_TO_POINTER(request_key));
    if (req_resp) {
      DPRINT(("SKINNY: match request:%d with response:%d for key=%d\n", req_resp->request_frame, pinfo->num, request_key));
      req_resp->response_frame = pinfo->num;
      wmem_map_insert(skinny_conv->requests, GUINT_TO_POINTER(req_resp->request_frame), (void *)req_resp);
      wmem_map_insert(skinny_conv->responses, GUINT_TO_POINTER(pinfo->num), (void *)req_resp);
    } else {
      DPRINT(("SKINNY: no match found for response frame=%d and key=%d\n", pinfo->num, request_key));
    }
  }

  req_resp = (skinny_req_resp_t *) wmem_map_lookup(skinny_conv->responses, GUINT_TO_POINTER(pinfo->num));
  if (req_resp && req_resp->request_frame) {
    DPRINT(("SKINNY: show response in tree: frame/key=%d\n", pinfo->num));
    proto_item *it;
    nstime_t ns;
    it = proto_tree_add_uint(tree, hf_skinny_response_to, tvb, 0, 0, req_resp->request_frame);
    proto_item_set_generated(it);

    nstime_delta(&ns, &pinfo->abs_ts, &req_resp->request_time);
    it = proto_tree_add_time(tree, hf_skinny_response_time, tvb, 0, 0, &ns);
    proto_item_set_generated(it);
  } else {
    DPRINT(("SKINNY: no response found for frame/key=%d\n", pinfo->num));
  }
}

/*** Messages Handlers ***/
/*
 * Message:   RegisterReqMessage
 * Opcode:    0x0001
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_RegisterReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sid");
    ptvcursor_add(cursor, hf_skinny_DeviceName, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_reserved_for_future_use, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_instance, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_stationIpAddr, 4, ENC_BIG_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_deviceType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxStreams, 4, ENC_LITTLE_ENDIAN);
  if (hdr_data_length > 52) {
    ptvcursor_add(cursor, hf_skinny_activeStreams, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_protocolVer, 1, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_unknown, 1, ENC_LITTLE_ENDIAN);
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "phoneFeatures");
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit1, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit2, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit3, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit4, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_UTF8, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit6, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit7, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_DynamicMessages, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit9, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_RFC2833, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit11, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit12, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit13, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit14, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit15, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Abbreviated_Dial, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_advance(cursor, 2);
    ptvcursor_pop_subtree(cursor); /* end bitfield: phoneFeatures */
    ptvcursor_add(cursor, hf_skinny_maxConferences, 4, ENC_LITTLE_ENDIAN);
  }
  if (hdr_data_length > 100) {
    ptvcursor_add(cursor, hf_skinny_activeConferences, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_macAddress, 6, ENC_NA);
    ptvcursor_advance(cursor, 12 - 6);
    ptvcursor_add(cursor, hf_skinny_ipV4AddressScope, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxNumberOfLines, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_stationIpV6Addr, 16, ENC_NA);
    ptvcursor_add(cursor, hf_skinny_ipV6AddressScope, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_firmwareLoadName, 32, ENC_ASCII);
  }
  if (hdr_data_length > 191) {
    ptvcursor_add(cursor, hf_skinny_configVersionStamp, 48, ENC_ASCII);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0001);
}

/*
 * Message:   IpPortMessage
 * Opcode:    0x0002
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_IpPortMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_rtpMediaPort, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   KeypadButtonMessage
 * Opcode:    0x0003
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_KeypadButtonMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  si->additionalInfo = ws_strdup_printf("\"%s\"",
    try_val_to_str_ext(
      tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)),
      &KeyPadButton_short_ext
    )
  );
  ptvcursor_add(cursor, hf_skinny_kpButton, 4, ENC_LITTLE_ENDIAN);
  if (hdr_data_length > 8) {
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   EnblocCallMessage
 * Opcode:    0x0004
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_EnblocCallMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t VariableDirnumSize = (hdr_version >= V18_MSG_TYPE) ? 25 : 24;

  si->calledParty = g_strdup(tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), VariableDirnumSize));
  ptvcursor_add(cursor, hf_skinny_calledParty, VariableDirnumSize, ENC_ASCII);
  if (hdr_data_length > 28) {
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   StimulusMessage
 * Opcode:    0x0005
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StimulusMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_stimulus, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_stimulusStatus, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   OffHookMessage
 * Opcode:    0x0006
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_OffHookMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  if (hdr_data_length > 4) {
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   OnHookMessage
 * Opcode:    0x0007
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_OnHookMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  if (hdr_data_length > 4) {
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   HookFlashMessage
 * Opcode:    0x0008
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_HookFlashMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ForwardStatReqMessage
 * Opcode:    0x0009
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_ForwardStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineNumber = 0;
  lineNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineNumber, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0009 ^ lineNumber);
}

/*
 * Message:   SpeedDialStatReqMessage
 * Opcode:    0x000a
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_SpeedDialStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t speedDialNumber = 0;
  speedDialNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_speedDialNumber, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x000a ^ speedDialNumber);
}

/*
 * Message:   LineStatReqMessage
 * Opcode:    0x000b
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_LineStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineNumber = 0;
  lineNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineNumber, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x000b ^ lineNumber);
}

/*
 * Message:   CapabilitiesResMessage
 * Opcode:    0x0010
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_CapabilitiesResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t capCount = 0;
  uint32_t payloadCapability = 0;
  capCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_capCount, 4, ENC_LITTLE_ENDIAN);
  if (capCount <= 18) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "caps [ref:capCount = %d, max:18]", capCount);
    if (capCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (capCount * 16) && capCount <= 18) {
      for (counter_1 = 0; counter_1 < 18; counter_1++) {
        if (counter_1 < capCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "caps [%d / %d]", counter_1 + 1, capCount);
          payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 4, ENC_LITTLE_ENDIAN);
          if (payloadCapability == MEDIA_PAYLOAD_G7231)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_G7231");
            ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_MODEMRELAY)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_ModemRelay");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
              ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SPRT)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SPRT");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
              ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SSE)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SSE");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
              ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any payloadCapability");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
              ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          }
        } else {
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (capCount * 16));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x009b);
}

/*
 * Message:   AlarmMessage
 * Opcode:    0x0020
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_AlarmMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_alarmSeverity, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_text, 80, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_parm1, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_parm2, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   MulticastMediaReceptionAckMessage
 * Opcode:    0x0021
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_MulticastMediaReceptionAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  si->multicastReceptionStatus = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_multicastReceptionStatus, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0101 ^ passThroughPartyId);
}

/*
 * Message:   OpenReceiveChannelAckMessage
 * Opcode:    0x0022
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_OpenReceiveChannelAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);
  address ipAddr;
  char *ipAddr_str = NULL;
  uint32_t portNumber = 0;
  uint32_t passThroughPartyId = 0;

  si->mediaReceptionStatus = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_mediaReceptionStatus, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &ipAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_ipAddr_ipv4, hf_skinny_ipAddr_ipv6);
  portNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_portNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &ipAddr, portNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  ipAddr_str = address_to_display(NULL, &ipAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", ipAddr_str, portNumber);
  wmem_free(NULL, ipAddr_str);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  if (hdr_data_length > 20) {
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0105 ^ passThroughPartyId);
}

/*
 * Message:   ConnectionStatisticsResMessage
 * Opcode:    0x0023
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ConnectionStatisticsResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t callReference = 0;
  uint32_t dataSize = 0;

  if (hdr_version <= V17_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_directoryNum, 24, ENC_ASCII);
    callReference = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_statsProcessingMode, 4, ENC_LITTLE_ENDIAN);
  }
  if (hdr_version >= V18_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_directoryNum, 28, ENC_ASCII);
    callReference = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_statsProcessingMode, 1, ENC_LITTLE_ENDIAN);
  }
  ptvcursor_add(cursor, hf_skinny_numberPacketsSent, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOctetsSent, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberPacketsReceived, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOctetsReceived, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberPacketsLost, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_jitter, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_latency, 4, ENC_LITTLE_ENDIAN);
  if (hdr_data_length > 64) {
    dataSize = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataSize, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_data, dataSize, ENC_ASCII);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0107 ^ callReference);
}

/*
 * Message:   OffHookWithCallingPartyNumberMessage
 * Opcode:    0x0024
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_OffHookWithCallingPartyNumberMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t VariableDirnumSize = (hdr_version >= V18_MSG_TYPE) ? 25 : 24;
  ptvcursor_add(cursor, hf_skinny_callingPartyNumber, VariableDirnumSize, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_cgpnVoiceMailbox, VariableDirnumSize, ENC_ASCII);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SoftKeyEventMessage
 * Opcode:    0x0026
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SoftKeyEventMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_softKeyEvent, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   UnregisterReqMessage
 * Opcode:    0x0027
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_UnregisterReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  if (hdr_data_length > 12) {
    ptvcursor_add(cursor, hf_skinny_unRegReasonCode, 4, ENC_LITTLE_ENDIAN);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0027);
}

/*
 * Message:   RegisterTokenReq
 * Opcode:    0x0029
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_RegisterTokenReq(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sid");
    ptvcursor_add(cursor, hf_skinny_DeviceName, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_reserved_for_future_use, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_instance, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_stationIpAddr, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_deviceType, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_ipv4or6(cursor, hf_skinny_stationIpV6Addr_ipv4, hf_skinny_stationIpV6Addr_ipv6);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0029);
}

/*
 * Message:   MediaTransmissionFailureMessage
 * Opcode:    0x002a
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_MediaTransmissionFailureMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x008a ^ passThroughPartyId);
}

/*
 * Message:   HeadsetStatusMessage
 * Opcode:    0x002b
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_HeadsetStatusMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_headsetStatus, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   MediaResourceNotificationMessage
 * Opcode:    0x002c
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_MediaResourceNotificationMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_deviceType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfInServiceStreams, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxStreamsPerConf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfOutOfServiceStreams, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   RegisterAvailableLinesMessage
 * Opcode:    0x002d
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_RegisterAvailableLinesMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_maxNumOfAvailLines, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   DeviceToUserDataMessage
 * Opcode:    0x002e
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_DeviceToUserDataMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "deviceToUserData");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x002e);
}

/*
 * Message:   DeviceToUserDataResponseMessage
 * Opcode:    0x002f
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_DeviceToUserDataResponseMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "deviceToUserData");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x002e);
}

/*
 * Message:   UpdateCapabilitiesMessage
 * Opcode:    0x0030
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_UpdateCapabilitiesMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t audioCapCount = 0;
  uint32_t videoCapCount = 0;
  uint32_t dataCapCount = 0;
  uint32_t customPictureFormatCount = 0;
  uint32_t serviceResourceCount = 0;
  uint32_t layoutCount = 0;
  uint32_t payloadCapability = 0;
  uint32_t levelPreferenceCount = 0;
  audioCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_audioCapCount, 4, ENC_LITTLE_ENDIAN);
  videoCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_videoCapCount, 4, ENC_LITTLE_ENDIAN);
  dataCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataCapCount, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rtpPayloadFormat, 4, ENC_LITTLE_ENDIAN);
  customPictureFormatCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_customPictureFormatCount, 4, ENC_LITTLE_ENDIAN);
  if (customPictureFormatCount <= 6) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [ref:customPictureFormatCount = %d, max:6]", customPictureFormatCount);
    if (customPictureFormatCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (customPictureFormatCount * 20) && customPictureFormatCount <= 6) {
      for (counter_1 = 0; counter_1 < 6; counter_1++) {
        if (counter_1 < customPictureFormatCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [%d / %d]", counter_1 + 1, customPictureFormatCount);
          ptvcursor_add(cursor, hf_skinny_pictureWidth, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_pictureHeight, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_pixelAspectRatio, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_clockConversionCode, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_clockDivisor, 4, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 20);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (customPictureFormatCount * 20));
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "confResources");
    ptvcursor_add(cursor, hf_skinny_activeStreamsOnRegistration, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxBW, 4, ENC_LITTLE_ENDIAN);
    serviceResourceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_serviceResourceCount, 4, ENC_LITTLE_ENDIAN);
    if (serviceResourceCount <= 4) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [ref:serviceResourceCount = %d, max:4]", serviceResourceCount);
      if (serviceResourceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (serviceResourceCount * 24) && serviceResourceCount <= 4) {
        for (counter_2 = 0; counter_2 < 4; counter_2++) {
          if (counter_2 < serviceResourceCount) {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [%d / %d]", counter_2 + 1, serviceResourceCount);
            layoutCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_skinny_layoutCount, 4, ENC_LITTLE_ENDIAN);
            if (layoutCount <= 5) { /* tvb enum size guard */
              uint32_t counter_7 = 0;
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "layouts [ref: layoutCount = %d, max:5]", layoutCount);
              for (counter_7 = 0; counter_7 < 5; counter_7++) {
                if (counter_7 < layoutCount) {
                  ptvcursor_add(cursor, hf_skinny_layouts, 4, ENC_LITTLE_ENDIAN);
                } else {
                  ptvcursor_advance(cursor, 4);
                }
              }
              ptvcursor_pop_subtree(cursor);
            } else {
              ptvcursor_advance(cursor, (5 * 4)); /* guard kicked in -> skip the rest */;
            }
            ptvcursor_add(cursor, hf_skinny_serviceNum, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_maxStreams, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_maxConferences, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_activeConferenceOnRegistration, 4, ENC_LITTLE_ENDIAN);
          } else {
            ptvcursor_advance(cursor, 24);
          }
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (serviceResourceCount * 24));
    }
    ptvcursor_pop_subtree(cursor);
  }
  if (audioCapCount <= 18) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [ref:audioCapCount = %d, max:18]", audioCapCount);
    if (audioCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (audioCapCount * 16) && audioCapCount <= 18) {
      for (counter_1 = 0; counter_1 < 18; counter_1++) {
        if (counter_1 < audioCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [%d / %d]", counter_1 + 1, audioCapCount);
          payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 4, ENC_LITTLE_ENDIAN);
          if (payloadCapability == MEDIA_PAYLOAD_G7231)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_G7231");
            ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_MODEMRELAY)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_ModemRelay");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
              ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SPRT)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SPRT");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
              ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SSE)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SSE");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
              ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any payloadCapability");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
              ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          }
        } else {
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (audioCapCount * 16));
  }
  if (videoCapCount <= 10) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [ref:videoCapCount = %d, max:10]", videoCapCount);
    if (videoCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (videoCapCount * 44) && videoCapCount <= 10) {
      for (counter_1 = 0; counter_1 < 10; counter_1++) {
        if (counter_1 < videoCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [%d / %d]", counter_1 + 1, videoCapCount);
          payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_videoCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
          levelPreferenceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_levelPreferenceCount, 4, ENC_LITTLE_ENDIAN);
          if (levelPreferenceCount <= 4) {
            uint32_t counter_5 = 0;
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [ref:levelPreferenceCount = %d, max:4]", levelPreferenceCount);
            if (levelPreferenceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (levelPreferenceCount * 24) && levelPreferenceCount <= 4) {
              for (counter_5 = 0; counter_5 < 4; counter_5++) {
                if (counter_5 < levelPreferenceCount) {
                  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [%d / %d]", counter_5 + 1, levelPreferenceCount);
                  ptvcursor_add(cursor, hf_skinny_transmitPreference, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_format, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_minBitRate, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_MPI, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_serviceNumber, 4, ENC_LITTLE_ENDIAN);
                } else {
                  ptvcursor_advance(cursor, 24);
                }
                ptvcursor_pop_subtree(cursor);
              }
            }
            ptvcursor_pop_subtree(cursor);
          } else {
            ptvcursor_advance(cursor, (levelPreferenceCount * 24));
          }
          if (payloadCapability == MEDIA_PAYLOAD_H261)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H261");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h261VideoCapability");
              ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOffCapability, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_stillImageTransmission, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_H263)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H263");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263VideoCapability");
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263_capability_bitfield");
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit1, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit2, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit3, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit4, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit5, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit6, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit7, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit8, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit9, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit10, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit11, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit12, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit13, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit14, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit15, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit16, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit17, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit18, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit19, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit20, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit21, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit22, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit23, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit24, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit25, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit26, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit27, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit28, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit29, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit30, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit31, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit32, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_advance(cursor, 4);
              ptvcursor_pop_subtree(cursor); /* end bitfield: h263_capability_bitfield */
              ptvcursor_add(cursor, hf_skinny_annexNandWFutureUse, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_VIEO)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_Vieo");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vieoVideoCapability");
              ptvcursor_add(cursor, hf_skinny_modelNumber, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_bandwidth, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          }
        } else {
          ptvcursor_advance(cursor, 44);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (videoCapCount * 44));
  }
  if (dataCapCount <= 5) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [ref:dataCapCount = %d, max:5]", dataCapCount);
    if (dataCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (dataCapCount * 16) && dataCapCount <= 5) {
      for (counter_1 = 0; counter_1 < 5; counter_1++) {
        if (counter_1 < dataCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [%d / %d]", counter_1 + 1, dataCapCount);
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dataCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_protocolDependentData, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (dataCapCount * 16));
  }
}

/*
 * Message:   OpenMultiMediaReceiveChannelAckMessage
 * Opcode:    0x0031
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_OpenMultiMediaReceiveChannelAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address ipAddr;
  char *ipAddr_str = NULL;
  uint32_t portNumber = 0;
  uint32_t passThroughPartyId = 0;
  si->multimediaReceptionStatus = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_multimediaReceptionStatus, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &ipAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_ipAddr_ipv4, hf_skinny_ipAddr_ipv6);
  portNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_portNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &ipAddr, portNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  ipAddr_str = address_to_display(NULL, &ipAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", ipAddr_str, portNumber);
  wmem_free(NULL, ipAddr_str);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0131 ^ passThroughPartyId);
}

/*
 * Message:   ClearConferenceMessage
 * Opcode:    0x0032
 * Type:      Conference
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_ClearConferenceMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_serviceNum, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ServiceURLStatReqMessage
 * Opcode:    0x0033
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_ServiceURLStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t serviceURLIndex = 0;
  serviceURLIndex = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_serviceURLIndex, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0033 ^ serviceURLIndex);
}

/*
 * Message:   FeatureStatReqMessage
 * Opcode:    0x0034
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_FeatureStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);
  uint32_t featureIndex = 0;

  featureIndex = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_featureIndex, 4, ENC_LITTLE_ENDIAN);
  if (hdr_data_length > 16) {
    ptvcursor_add(cursor, hf_skinny_featureCapabilities, 4, ENC_LITTLE_ENDIAN);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0034 ^ featureIndex);
}

/*
 * Message:   CreateConferenceResMessage
 * Opcode:    0x0035
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_CreateConferenceResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  uint32_t dataLength = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_result, 4, ENC_LITTLE_ENDIAN);
  dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passThruData, dataLength, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0137 ^ conferenceId);
}

/*
 * Message:   DeleteConferenceResMessage
 * Opcode:    0x0036
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_DeleteConferenceResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_delete_conf_result, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0138 ^ conferenceId);
}

/*
 * Message:   ModifyConferenceResMessage
 * Opcode:    0x0037
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ModifyConferenceResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  uint32_t dataLength = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_modify_conf_result, 4, ENC_LITTLE_ENDIAN);
  dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passThruData, dataLength, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0139 ^ conferenceId);
}

/*
 * Message:   AddParticipantResMessage
 * Opcode:    0x0038
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_AddParticipantResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_add_participant_result, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_bridgeParticipantId, 257, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x013a ^ conferenceId);
}

/*
 * Message:   AuditConferenceResMessage
 * Opcode:    0x0039
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_AuditConferenceResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t numberOfEntries = 0;
  ptvcursor_add(cursor, hf_skinny_last, 4, ENC_LITTLE_ENDIAN);
  numberOfEntries = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_numberOfEntries, 4, ENC_LITTLE_ENDIAN);
  if (numberOfEntries <= 32) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "conferenceEntry [ref:numberOfEntries = %d, max:32]", numberOfEntries);
    if (numberOfEntries && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (numberOfEntries * 76) && numberOfEntries <= 32) {
      for (counter_1 = 0; counter_1 < 32; counter_1++) {
        if (counter_1 < numberOfEntries) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "conferenceEntry [%d / %d]", counter_1 + 1, numberOfEntries);
          ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_resourceType, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_numberOfReservedParticipants, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_numberOfActiveParticipants, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_appConfID, 32, ENC_ASCII);
          ptvcursor_add(cursor, hf_skinny_appData, 24, ENC_ASCII);
        } else {
          ptvcursor_advance(cursor, 76);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (numberOfEntries * 76));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x013c);
}

/*
 * Message:   AuditParticipantResMessage
 * Opcode:    0x0040
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_AuditParticipantResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  uint32_t numberOfEntries = 0;
  ptvcursor_add(cursor, hf_skinny_audit_participant_result, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_last, 4, ENC_LITTLE_ENDIAN);
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  numberOfEntries = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_numberOfEntries, 4, ENC_LITTLE_ENDIAN);
  if (numberOfEntries <= 256) {
    uint32_t counter_2 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "participantEntry [ref:numberOfEntries = %d, max:256]", numberOfEntries);
    for (counter_2 = 0; counter_2 < 256; counter_2++) {
      if (counter_2 < numberOfEntries) {
        ptvcursor_add(cursor, hf_skinny_participantEntry, 4, ENC_LITTLE_ENDIAN);
      } else {
        ptvcursor_advance(cursor, 4);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (256 * 4));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x013d ^ conferenceId);
}

/*
 * Message:   DeviceToUserDataMessageVersion1
 * Opcode:    0x0041
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_DeviceToUserDataMessageVersion1(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "deviceToUserDataVersion1");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_sequenceFlag, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_displayPriority, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_appInstanceID, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_routingID, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0041);
}

/*
 * Message:   DeviceToUserDataResponseMessageVersion1
 * Opcode:    0x0042
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_DeviceToUserDataResponseMessageVersion1(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "deviceToUserDataVersion1");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_sequenceFlag, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_displayPriority, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_appInstanceID, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_routingID, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0041);
}

/*
 * Message:   CapabilitiesV2ResMessage
 * Opcode:    0x0043
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_CapabilitiesV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t audioCapCount = 0;
  uint32_t videoCapCount = 0;
  uint32_t dataCapCount = 0;
  uint32_t customPictureFormatCount = 0;
  uint32_t serviceResourceCount = 0;
  uint32_t layoutCount = 0;
  uint32_t payloadCapability = 0;
  uint32_t levelPreferenceCount = 0;
  audioCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_audioCapCount, 4, ENC_LITTLE_ENDIAN);
  videoCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_videoCapCount, 4, ENC_LITTLE_ENDIAN);
  dataCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataCapCount, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rtpPayloadFormat, 4, ENC_LITTLE_ENDIAN);
  customPictureFormatCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_customPictureFormatCount, 4, ENC_LITTLE_ENDIAN);
  if (customPictureFormatCount <= 6) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [ref:customPictureFormatCount = %d, max:6]", customPictureFormatCount);
    if (customPictureFormatCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (customPictureFormatCount * 20) && customPictureFormatCount <= 6) {
      for (counter_1 = 0; counter_1 < 6; counter_1++) {
        if (counter_1 < customPictureFormatCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [%d / %d]", counter_1 + 1, customPictureFormatCount);
          ptvcursor_add(cursor, hf_skinny_pictureWidth, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_pictureHeight, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_pixelAspectRatio, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_clockConversionCode, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_clockDivisor, 4, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 20);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (customPictureFormatCount * 20));
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "confResources");
    ptvcursor_add(cursor, hf_skinny_activeStreamsOnRegistration, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxBW, 4, ENC_LITTLE_ENDIAN);
    serviceResourceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_serviceResourceCount, 4, ENC_LITTLE_ENDIAN);
    if (serviceResourceCount <= 4) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [ref:serviceResourceCount = %d, max:4]", serviceResourceCount);
      if (serviceResourceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (serviceResourceCount * 24) && serviceResourceCount <= 4) {
        for (counter_2 = 0; counter_2 < 4; counter_2++) {
          if (counter_2 < serviceResourceCount) {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [%d / %d]", counter_2 + 1, serviceResourceCount);
            layoutCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
            ptvcursor_add(cursor, hf_skinny_layoutCount, 4, ENC_LITTLE_ENDIAN);
            if (layoutCount <= 5) { /* tvb enum size guard */
              uint32_t counter_7 = 0;
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "layouts [ref: layoutCount = %d, max:5]", layoutCount);
              for (counter_7 = 0; counter_7 < 5; counter_7++) {
                if (counter_7 < layoutCount) {
                  ptvcursor_add(cursor, hf_skinny_layouts, 4, ENC_LITTLE_ENDIAN);
                } else {
                  ptvcursor_advance(cursor, 4);
                }
              }
              ptvcursor_pop_subtree(cursor);
            } else {
              ptvcursor_advance(cursor, (5 * 4)); /* guard kicked in -> skip the rest */;
            }
            ptvcursor_add(cursor, hf_skinny_serviceNum, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_maxStreams, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_maxConferences, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_activeConferenceOnRegistration, 4, ENC_LITTLE_ENDIAN);
          } else {
            ptvcursor_advance(cursor, 24);
          }
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (serviceResourceCount * 24));
    }
    ptvcursor_pop_subtree(cursor);
  }
  if (audioCapCount <= 18) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [ref:audioCapCount = %d, max:18]", audioCapCount);
    if (audioCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (audioCapCount * 16) && audioCapCount <= 18) {
      for (counter_1 = 0; counter_1 < 18; counter_1++) {
        if (counter_1 < audioCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [%d / %d]", counter_1 + 1, audioCapCount);
          payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 4, ENC_LITTLE_ENDIAN);
          if (payloadCapability == MEDIA_PAYLOAD_G7231)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_G7231");
            ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_MODEMRELAY)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_ModemRelay");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
              ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SPRT)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SPRT");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
              ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SSE)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SSE");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
              ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any payloadCapability");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
              ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 4);
          }
        } else {
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (audioCapCount * 16));
  }
  if (videoCapCount <= 10) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [ref:videoCapCount = %d, max:10]", videoCapCount);
    if (videoCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (videoCapCount * 60) && videoCapCount <= 10) {
      for (counter_1 = 0; counter_1 < 10; counter_1++) {
        if (counter_1 < videoCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [%d / %d]", counter_1 + 1, videoCapCount);
          payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_videoCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
          levelPreferenceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_levelPreferenceCount, 4, ENC_LITTLE_ENDIAN);
          if (levelPreferenceCount <= 4) {
            uint32_t counter_5 = 0;
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [ref:levelPreferenceCount = %d, max:4]", levelPreferenceCount);
            if (levelPreferenceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (levelPreferenceCount * 24) && levelPreferenceCount <= 4) {
              for (counter_5 = 0; counter_5 < 4; counter_5++) {
                if (counter_5 < levelPreferenceCount) {
                  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [%d / %d]", counter_5 + 1, levelPreferenceCount);
                  ptvcursor_add(cursor, hf_skinny_transmitPreference, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_format, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_minBitRate, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_MPI, 4, ENC_LITTLE_ENDIAN);
                  ptvcursor_add(cursor, hf_skinny_serviceNumber, 4, ENC_LITTLE_ENDIAN);
                } else {
                  ptvcursor_advance(cursor, 24);
                }
                ptvcursor_pop_subtree(cursor);
              }
            }
            ptvcursor_pop_subtree(cursor);
          } else {
            ptvcursor_advance(cursor, (levelPreferenceCount * 24));
          }
          if (payloadCapability == MEDIA_PAYLOAD_H261)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H261");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h261VideoCapability");
              ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOffCapability, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_stillImageTransmission, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 16);
          } else if (payloadCapability == MEDIA_PAYLOAD_H263)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H263");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263VideoCapability");
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263_capability_bitfield");
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit1, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit2, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit3, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit4, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit5, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit6, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit7, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit8, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit9, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit10, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit11, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit12, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit13, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit14, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit15, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit16, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit17, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit18, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit19, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit20, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit21, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit22, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit23, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit24, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit25, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit26, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit27, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit28, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit29, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit30, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit31, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit32, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_advance(cursor, 4);
              ptvcursor_pop_subtree(cursor); /* end bitfield: h263_capability_bitfield */
              ptvcursor_add(cursor, hf_skinny_annexNandWFutureUse, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 16);
          } else if (payloadCapability == MEDIA_PAYLOAD_H264)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H264");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h264VideoCapability");
              ptvcursor_add(cursor, hf_skinny_profile, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_level, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_customMaxMBPS, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_customMaxFS, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_customMaxDPB, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_customMaxBRandCPB, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          } else if (payloadCapability == MEDIA_PAYLOAD_VIEO)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_Vieo");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vieoVideoCapability");
              ptvcursor_add(cursor, hf_skinny_modelNumber, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_bandwidth, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
            ptvcursor_advance(cursor, 16);
          }
        } else {
          ptvcursor_advance(cursor, 60);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (videoCapCount * 60));
  }
  if (dataCapCount <= 5) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [ref:dataCapCount = %d, max:5]", dataCapCount);
    if (dataCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (dataCapCount * 16) && dataCapCount <= 5) {
      for (counter_1 = 0; counter_1 < 5; counter_1++) {
        if (counter_1 < dataCapCount) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [%d / %d]", counter_1 + 1, dataCapCount);
          ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dataCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_protocolDependentData, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (dataCapCount * 16));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x009b);
}

/*
 * Message:   CapabilitiesV3ResMessage
 * Opcode:    0x0044
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_CapabilitiesV3ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t audioCapCount = 0;
  uint32_t videoCapCount = 0;
  uint32_t dataCapCount = 0;
  uint32_t customPictureFormatCount = 0;
  uint32_t serviceResourceCount = 0;
  uint32_t layoutCount = 0;
  uint32_t payloadCapability = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t levelPreferenceCount = 0;
  audioCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_audioCapCount, 4, ENC_LITTLE_ENDIAN);
  videoCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_videoCapCount, 4, ENC_LITTLE_ENDIAN);
  dataCapCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataCapCount, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rtpPayloadFormat, 4, ENC_LITTLE_ENDIAN);
  customPictureFormatCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_customPictureFormatCount, 4, ENC_LITTLE_ENDIAN);
  if (customPictureFormatCount <= 6) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [ref:customPictureFormatCount = %d, max:6]", customPictureFormatCount);
    if (customPictureFormatCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (customPictureFormatCount * 20) && customPictureFormatCount <= 6) {
      for (counter_1 = 0; counter_1 < 6; counter_1++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "customPictureFormat [%d / %d]", counter_1 + 1, customPictureFormatCount);
        ptvcursor_add(cursor, hf_skinny_pictureWidth, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_pictureHeight, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_pixelAspectRatio, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_clockConversionCode, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_clockDivisor, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (customPictureFormatCount * 20));
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "confResources");
    ptvcursor_add(cursor, hf_skinny_activeStreamsOnRegistration, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxBW, 4, ENC_LITTLE_ENDIAN);
    serviceResourceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_serviceResourceCount, 4, ENC_LITTLE_ENDIAN);
    if (serviceResourceCount <= 4) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [ref:serviceResourceCount = %d, max:4]", serviceResourceCount);
      if (serviceResourceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (serviceResourceCount * 24) && serviceResourceCount <= 4) {
        for (counter_2 = 0; counter_2 < 4; counter_2++) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serviceResource [%d / %d]", counter_2 + 1, serviceResourceCount);
          layoutCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
          ptvcursor_add(cursor, hf_skinny_layoutCount, 4, ENC_LITTLE_ENDIAN);
          if (layoutCount <= 5) { /* tvb enum size guard */
            uint32_t counter_6 = 0;
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "layouts [ref: layoutCount = %d, max:layoutCount]", layoutCount);
            for (counter_6 = 0; counter_6 < layoutCount; counter_6++) {
              ptvcursor_add(cursor, hf_skinny_layouts, 4, ENC_LITTLE_ENDIAN);
            }
            ptvcursor_pop_subtree(cursor);
          } else {
            ptvcursor_advance(cursor, (layoutCount * 4)); /* guard kicked in -> skip the rest */;
          }
          ptvcursor_add(cursor, hf_skinny_serviceNum, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxStreams, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_maxConferences, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_activeConferenceOnRegistration, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (serviceResourceCount * 24));
    }
    ptvcursor_pop_subtree(cursor);
  }
  if (audioCapCount <= 18) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [ref:audioCapCount = %d, max:18]", audioCapCount);
    if (audioCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (audioCapCount * 16) && audioCapCount <= 18) {
      for (counter_1 = 0; counter_1 < 18; counter_1++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audiocaps [%d / %d]", counter_1 + 1, audioCapCount);
        payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 4, ENC_LITTLE_ENDIAN);
        if (payloadCapability == MEDIA_PAYLOAD_G7231)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_G7231");
          ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
          ptvcursor_advance(cursor, 4);
        } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_MODEMRELAY)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_ModemRelay");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
            ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
        } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SPRT)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SPRT");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
            ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
        } else if (payloadCapability == MEDIA_PAYLOAD_V150_LC_SSE)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_v150_LC_SSE");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
            ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
        } else         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any payloadCapability");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
            ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
          ptvcursor_advance(cursor, 4);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (audioCapCount * 16));
  }
  if (videoCapCount <= 10) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [ref:videoCapCount = %d, max:10]", videoCapCount);
    if (videoCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (videoCapCount * 4) && videoCapCount <= 10) {
      for (counter_1 = 0; counter_1 < 10; counter_1++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidCaps [%d / %d]", counter_1 + 1, videoCapCount);
        payloadCapability = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_videoCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
        levelPreferenceCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
        ptvcursor_add(cursor, hf_skinny_levelPreferenceCount, 4, ENC_LITTLE_ENDIAN);
        if (levelPreferenceCount <= 4) {
          uint32_t counter_4 = 0;
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [ref:levelPreferenceCount = %d, max:4]", levelPreferenceCount);
          if (levelPreferenceCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (levelPreferenceCount * 24) && levelPreferenceCount <= 4) {
            for (counter_4 = 0; counter_4 < 4; counter_4++) {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "levelPreference [%d / %d]", counter_4 + 1, levelPreferenceCount);
              ptvcursor_add(cursor, hf_skinny_transmitPreference, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_format, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_minBitRate, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_MPI, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_serviceNumber, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
          }
          ptvcursor_pop_subtree(cursor);
        } else {
          ptvcursor_advance(cursor, (levelPreferenceCount * 24));
        }
        ptvcursor_add(cursor, hf_skinny_encryptionCapability, 4, ENC_LITTLE_ENDIAN);
        if (payloadCapability == MEDIA_PAYLOAD_H261)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H261");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h261VideoCapability");
            ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOffCapability, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_stillImageTransmission, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
          ptvcursor_advance(cursor, 16);
        } else if (payloadCapability == MEDIA_PAYLOAD_H263)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H263");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263VideoCapability");
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263_capability_bitfield");
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit1, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit2, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit3, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit4, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit5, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit6, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit7, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit8, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit9, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit10, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit11, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit12, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit13, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit14, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit15, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit16, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit17, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit18, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit19, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit20, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit21, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit22, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit23, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit24, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit25, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit26, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit27, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit28, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit29, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit30, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit31, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit32, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_advance(cursor, 4);
            ptvcursor_pop_subtree(cursor); /* end bitfield: h263_capability_bitfield */
            ptvcursor_add(cursor, hf_skinny_annexNandWFutureUse, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
          ptvcursor_advance(cursor, 16);
        } else if (payloadCapability == MEDIA_PAYLOAD_H264)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_H264");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h264VideoCapability");
            ptvcursor_add(cursor, hf_skinny_profile, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_level, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_customMaxMBPS, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_customMaxFS, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_customMaxDPB, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_customMaxBRandCPB, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
        } else if (payloadCapability == MEDIA_PAYLOAD_VIEO)         {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadCapability is Media_Payload_Vieo");
          {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vieoVideoCapability");
            ptvcursor_add(cursor, hf_skinny_modelNumber, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_bandwidth, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          }
          ptvcursor_pop_subtree(cursor);
          ptvcursor_advance(cursor, 16);
        }
        ptvcursor_add(cursor, hf_skinny_ipAddressingMode, 4, ENC_LITTLE_ENDIAN);
        if (hdr_version >= V16_MSG_TYPE) {
          ptvcursor_add(cursor, hf_skinny_ipAddressingMode, 4, ENC_LITTLE_ENDIAN);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (videoCapCount * 4));
  }
  if (dataCapCount <= 5) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [ref:dataCapCount = %d, max:5]", dataCapCount);
    if (dataCapCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (dataCapCount * 20) && dataCapCount <= 5) {
      for (counter_1 = 0; counter_1 < 5; counter_1++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataCaps [%d / %d]", counter_1 + 1, dataCapCount);
        ptvcursor_add(cursor, hf_skinny_payloadCapability, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_dataCapabilityDirection, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_protocolDependentData, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_encryptionCapability, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (dataCapCount * 20));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x009b);
}

/*
 * Message:   PortResMessage
 * Opcode:    0x0045
 * Type:      MediaControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_PortResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t callReference = 0;
  address ipAddr;
  char *ipAddr_str = NULL;
  uint32_t portNumber = 0;

  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  callReference = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &ipAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_ipAddr_ipv4, hf_skinny_ipAddr_ipv6);
  portNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_portNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &ipAddr, portNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  ipAddr_str = address_to_display(NULL, &ipAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", ipAddr_str, portNumber);
  wmem_free(NULL, ipAddr_str);
  ptvcursor_add(cursor, hf_skinny_RTCPPortNumber, 4, ENC_LITTLE_ENDIAN);
  if (hdr_version >= V19_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_mediaType, 4, ENC_LITTLE_ENDIAN);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x014b ^ callReference);
}

/*
 * Message:   QoSResvNotifyMessage
 * Opcode:    0x0046
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSResvNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_direction, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   QoSErrorNotifyMessage
 * Opcode:    0x0047
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSErrorNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_direction, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_errorCode, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_failureNodeIpAddr, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rsvpErrorCode, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rsvpErrorSubCodeVal, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_rsvpErrorFlag, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SubscriptionStatReqMessage
 * Opcode:    0x0048
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_SubscriptionStatReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t transactionId = 0;
  transactionId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_subscriptionFeatureID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_timer, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_subscriptionID, 64, ENC_ASCII);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0048 ^ transactionId);
}

/*
 * Message:   MediaPathEventMessage
 * Opcode:    0x0049
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_MediaPathEventMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_mediaPathID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mediaPathEvent, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   MediaPathCapabilityMessage
 * Opcode:    0x004a
 * Type:      CallControl
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_MediaPathCapabilityMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_mediaPathID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mediaPathCapabilities, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   MwiNotificationMessage
 * Opcode:    0x004c
 * Type:      RegistrationAndManagement
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_MwiNotificationMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_mwiTargetNumber, 25, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_mwiControlNumber, 25, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_areMessagesWaiting, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "totalVmCounts");
    ptvcursor_add(cursor, hf_skinny_numNewMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_numOldMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "priorityVmCounts");
    ptvcursor_add(cursor, hf_skinny_numNewMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_numOldMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "totalFaxCounts");
    ptvcursor_add(cursor, hf_skinny_numNewMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_numOldMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "priorityFaxCounts");
    ptvcursor_add(cursor, hf_skinny_numNewMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_numOldMsgs, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x004c);
}

/*
 * Message:   RegisterAckMessage
 * Opcode:    0x0081
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_RegisterAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_keepAliveInterval, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_dateTemplate, 6, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_alignmentPadding, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_secondaryKeepAliveInterval, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxProtocolVer, 1, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_unknown, 1, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "phoneFeatures");
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit1, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit2, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit3, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit4, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_UTF8, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit6, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit7, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_DynamicMessages, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit9, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_RFC2833, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit11, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit12, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit13, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit14, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Bit15, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_PhoneFeatures_Abbreviated_Dial, 2, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 2);
  ptvcursor_pop_subtree(cursor); /* end bitfield: phoneFeatures */
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0001);
}

/*
 * Message:   StartToneMessage
 * Opcode:    0x0082
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StartToneMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->additionalInfo = ws_strdup_printf("\"%s\"",
    try_val_to_str_ext(
      tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)),
      &DeviceTone_ext
    )
  );
  ptvcursor_add(cursor, hf_skinny_tone, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_tone_output_direction, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StopToneMessage
 * Opcode:    0x0083
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopToneMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);

  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  if (hdr_version >= V11_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_tone, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   SetRingerMessage
 * Opcode:    0x0085
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SetRingerMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_ringMode, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_ringDuration, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SetLampMessage
 * Opcode:    0x0086
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SetLampMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_stimulus, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_stimulusInstance, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_lampMode, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SetSpeakerModeMessage
 * Opcode:    0x0088
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SetSpeakerModeMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_speakerMode, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SetMicroModeMessage
 * Opcode:    0x0089
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SetMicroModeMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_micMode, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StartMediaTransmissionMessage
 * Opcode:    0x008a
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_StartMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t passThroughPartyId = 0;
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  uint32_t compressionType = 0;
  uint16_t keylen = 0;
  uint16_t saltlen = 0;

  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierOut");
    ptvcursor_add(cursor, hf_skinny_precedenceValue, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_ssValue, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_padding, 2, ENC_LITTLE_ENDIAN);
    if (hdr_version <= V10_MSG_TYPE) {
      ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
    }
    if (hdr_version >= V11_MSG_TYPE) {
      if (compressionType == MEDIA_PAYLOAD_G7231)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
        ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      } else       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
          ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  }
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "mTxMediaEncryptionKeyInfo");
    ptvcursor_add(cursor, hf_skinny_algorithmID, 4, ENC_LITTLE_ENDIAN);
    keylen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_keylen, 2, ENC_LITTLE_ENDIAN);
    saltlen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_saltlen, 2, ENC_LITTLE_ENDIAN);
    if (keylen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "key [ref:keylen = %d, max:16]", keylen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < keylen) {
          ptvcursor_add(cursor, hf_skinny_key, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    if (saltlen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "salt [ref:saltlen = %d, max:16]", saltlen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < saltlen) {
          ptvcursor_add(cursor, hf_skinny_salt, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    ptvcursor_add(cursor, hf_skinny_isMKIPresent, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_keyDerivationRate, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_streamPassThroughId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_associatedStreamId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_RFC2833PayloadType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_dtmfType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mixingMode, 4, ENC_LITTLE_ENDIAN);
  if (hdr_version >= V15_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_partyDirection, 4, ENC_LITTLE_ENDIAN);
  }
  if (hdr_version >= V21_MSG_TYPE) {
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "latentCapsInfo");
      ptvcursor_add(cursor, hf_skinny_active, 4, ENC_LITTLE_ENDIAN);
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
        ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
        ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
        ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadParam");
        ptvcursor_add(cursor, hf_skinny_nse, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_rfc2833, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_sse, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_v150sprt, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_noaudio, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_FutureUse1, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_FutureUse2, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_FutureUse3, 1, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_pop_subtree(cursor);
    }
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x008a ^ passThroughPartyId);
}

/*
 * Message:   StopMediaTransmissionMessage
 * Opcode:    0x008b
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_portHandlingFlag, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   CallInfoMessage
 * Opcode:    0x008f
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CallInfoMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_callingPartyName, 40, ENC_ASCII);
  si->callingParty = g_strdup(tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), 24));
  ptvcursor_add(cursor, hf_skinny_callingParty, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_calledPartyName, 40, ENC_ASCII);
  si->calledParty = g_strdup(tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), 24));
  ptvcursor_add(cursor, hf_skinny_calledParty, 24, ENC_ASCII);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_callType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_originalCalledPartyName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_originalCalledParty, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lastRedirectingPartyName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lastRedirectingParty, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_originalCdpnRedirectReason, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_lastRedirectingReason, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_cgpnVoiceMailbox, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_cdpnVoiceMailbox, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_originalCdpnVoiceMailbox, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lastRedirectingVoiceMailbox, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_callInstance, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_callSecurityStatus, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "partyPIRestrictionBits");
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_BitsReserved, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: partyPIRestrictionBits */
  if (si->callingParty && si->calledParty) {
    si->additionalInfo = ws_strdup_printf("\"%s -> %s\"", si->callingParty, si->calledParty);
  }
}

/*
 * Message:   ForwardStatResMessage
 * Opcode:    0x0090
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ForwardStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineNumber = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t VariableDirnumSize = (hdr_version >= V18_MSG_TYPE) ? 25 : 24;
  ptvcursor_add(cursor, hf_skinny_activeForward, 4, ENC_LITTLE_ENDIAN);
  lineNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_forwardAllActive, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_forwardAllDirnum, VariableDirnumSize, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_forwardBusyActive, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_forwardBusyDirnum, VariableDirnumSize, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_forwardNoAnswerActive, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_forwardNoAnswerlDirnum, VariableDirnumSize, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0009 ^ lineNumber);
}

/*
 * Message:   SpeedDialStatResMessage
 * Opcode:    0x0091
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SpeedDialStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t speedDialNumber = 0;
  speedDialNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_speedDialNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_speedDialDirNumber, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_speedDialDisplayName, 40, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000a ^ speedDialNumber);
}

/*
 * Message:   LineStatResMessage
 * Opcode:    0x0092
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_LineStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineNumber = 0;
  lineNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_lineDirNumber, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lineFullyQualifiedDisplayName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lineTextLabel, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_lineDisplayOptions, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000b ^ lineNumber);
}

/*
 * Message:   ConfigStatResMessage
 * Opcode:    0x0093
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ConfigStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sid");
    ptvcursor_add(cursor, hf_skinny_DeviceName, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_reserved_for_future_use, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_instance, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_userName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_serverName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_numberOfLines, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfSpeedDials, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000c);
}

/*
 * Message:   TimeDateResMessage
 * Opcode:    0x0094
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_TimeDateResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "timeDataInfo");
    ptvcursor_add(cursor, hf_skinny_wYear, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wMonth, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wDayOfWeek, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wDay, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wHour, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wMinute, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wSecond, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_wMilliseconds, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_systemTime, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000d);
}

/*
 * Message:   StartSessionTransmissionMessage
 * Opcode:    0x0095
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StartSessionTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  ptvcursor_add(cursor, hf_skinny_sessionType, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StopSessionTransmissionMessage
 * Opcode:    0x0096
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopSessionTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  ptvcursor_add(cursor, hf_skinny_sessionType, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ButtonTemplateResMessage
 * Opcode:    0x0097
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ButtonTemplateResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t totalButtonCount = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "buttonTemplate");
    ptvcursor_add(cursor, hf_skinny_buttonOffset, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_buttonCount, 4, ENC_LITTLE_ENDIAN);
    totalButtonCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_totalButtonCount, 4, ENC_LITTLE_ENDIAN);
    if (totalButtonCount <= 42) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [ref:totalButtonCount = %d, max:42]", totalButtonCount);
      if (totalButtonCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (totalButtonCount * 2) && totalButtonCount <= 42) {
        for (counter_2 = 0; counter_2 < 42; counter_2++) {
          if (counter_2 < totalButtonCount) {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [%d / %d]", counter_2 + 1, totalButtonCount);
            ptvcursor_add(cursor, hf_skinny_instanceNumber, 1, ENC_LITTLE_ENDIAN);
            ptvcursor_add(cursor, hf_skinny_buttonDefinition, 1, ENC_LITTLE_ENDIAN);
          } else {
            ptvcursor_advance(cursor, 2);
          }
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (totalButtonCount * 2));
    }
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000e);
}

/*
 * Message:   VersionResMessage
 * Opcode:    0x0098
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_VersionResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_versionStr, 16, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000f);
}

/*
 * Message:   DisplayTextMessage
 * Opcode:    0x0099
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_DisplayTextMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_text, 32, ENC_ASCII);
}

/*
 * Message:   RegisterRejectMessage
 * Opcode:    0x009d
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_RegisterRejectMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_text, 32, ENC_ASCII);
}

/*
 * Message:   ServerResMessage
 * Opcode:    0x009e
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ServerResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);

  {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "server [max:5]");
    for (counter_1 = 0; counter_1 < 5; counter_1++) {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "server [%d / %d]", counter_1 + 1, 5);
      ptvcursor_add(cursor, hf_skinny_ServerName, 48, ENC_ASCII);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
  }
  {
    uint32_t counter_2 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serverTcpListenPort [max:5]");
    for (counter_2 = 0; counter_2 < 5; counter_2++) {
      ptvcursor_add(cursor, hf_skinny_serverTcpListenPort, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
  }
  if (hdr_data_length < 293) {
    {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serverIpAddr [max:5]");
      for (counter_2 = 0; counter_2 < 5; counter_2++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serverIpAddr [%d / %d]", counter_2 + 1, 5);
        ptvcursor_add(cursor, hf_skinny_stationIpAddr, 4, ENC_BIG_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_pop_subtree(cursor);
    }
  }
  if (hdr_data_length > 292) {
    {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serverIpAddr [max:5]");
      for (counter_2 = 0; counter_2 < 5; counter_2++) {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "serverIpAddr [%d / %d]", counter_2 + 1, 5);
        dissect_skinny_ipv4or6(cursor, hf_skinny_stationIpAddr_ipv4, hf_skinny_stationIpAddr_ipv6);
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_pop_subtree(cursor);
    }
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0012);
}

/*
 * Message:   Reset
 * Opcode:    0x009f
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_Reset(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_resetType, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StartMulticastMediaReceptionMessage
 * Opcode:    0x0101
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_StartMulticastMediaReceptionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  address multicastIpAddr;
  char *multicastIpAddr_str = NULL;
  uint32_t multicastPortNumber = 0;
  uint32_t compressionType = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &multicastIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_multicastIpAddr_ipv4, hf_skinny_multicastIpAddr_ipv6);
  multicastPortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_multicastPortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &multicastIpAddr, multicastPortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  multicastIpAddr_str = address_to_display(NULL, &multicastIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", multicastIpAddr_str, multicastPortNumber);
  wmem_free(NULL, multicastIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierIn");
    ptvcursor_add(cursor, hf_skinny_ecValue, 4, ENC_LITTLE_ENDIAN);
    if (hdr_version <= V10_MSG_TYPE) {
      ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
    }
    if (hdr_version >= V11_MSG_TYPE) {
      if (compressionType == MEDIA_PAYLOAD_G7231)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
        ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      } else       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
          ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  }
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0101 ^ passThroughPartyId);
}

/*
 * Message:   StartMulticastMediaTransmissionMessage
 * Opcode:    0x0102
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_StartMulticastMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  address multicastIpAddr;
  char *multicastIpAddr_str = NULL;
  uint32_t multicastPortNumber = 0;
  uint32_t compressionType = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &multicastIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_multicastIpAddr_ipv4, hf_skinny_multicastIpAddr_ipv6);
  multicastPortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_multicastPortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &multicastIpAddr, multicastPortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  multicastIpAddr_str = address_to_display(NULL, &multicastIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", multicastIpAddr_str, multicastPortNumber);
  wmem_free(NULL, multicastIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierOut");
    ptvcursor_add(cursor, hf_skinny_precedenceValue, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_ssValue, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_maxFramesPerPacket, 2, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_padding, 2, ENC_LITTLE_ENDIAN);
    if (hdr_version <= V10_MSG_TYPE) {
      ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
    }
    if (hdr_version >= V11_MSG_TYPE) {
      if (compressionType == MEDIA_PAYLOAD_G7231)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
        ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      } else       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
          ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  }
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0102 ^ passThroughPartyId);
}

/*
 * Message:   StopMulticastMediaReceptionMessage
 * Opcode:    0x0103
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopMulticastMediaReceptionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StopMulticastMediaTransmissionMessage
 * Opcode:    0x0104
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopMulticastMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   OpenReceiveChannelMessage
 * Opcode:    0x0105
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_OpenReceiveChannelMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_data_length = tvb_get_letohl(ptvcursor_tvbuff(cursor), 0);
  uint32_t passThroughPartyId = 0;
  uint32_t compressionType = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint16_t keylen = 0;
  uint16_t saltlen = 0;
  address sourceIpAddr;
  char *sourceIpAddr_str = NULL;
  uint32_t sourcePortNumber = 0;

  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierIn");
    ptvcursor_add(cursor, hf_skinny_ecValue, 4, ENC_LITTLE_ENDIAN);
    if (hdr_version <= V10_MSG_TYPE) {
      ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
    }
    if (hdr_version >= V11_MSG_TYPE) {
      if (compressionType == MEDIA_PAYLOAD_G7231)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
        ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      } else       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
          ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  }
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "mRxMediaEncryptionKeyInfo");
    ptvcursor_add(cursor, hf_skinny_algorithmID, 4, ENC_LITTLE_ENDIAN);
    keylen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_keylen, 2, ENC_LITTLE_ENDIAN);
    saltlen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_saltlen, 2, ENC_LITTLE_ENDIAN);
    if (keylen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "key [ref:keylen = %d, max:16]", keylen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < keylen) {
          ptvcursor_add(cursor, hf_skinny_key, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    if (saltlen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "salt [ref:saltlen = %d, max:16]", saltlen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < saltlen) {
          ptvcursor_add(cursor, hf_skinny_salt, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    ptvcursor_add(cursor, hf_skinny_isMKIPresent, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_keyDerivationRate, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_streamPassThroughId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_associatedStreamId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_RFC2833PayloadType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_dtmfType, 4, ENC_LITTLE_ENDIAN);
  if (hdr_version >= V11_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_mixingMode, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_partyDirection, 4, ENC_LITTLE_ENDIAN);
    read_skinny_ipv4or6(cursor, &sourceIpAddr);
    dissect_skinny_ipv4or6(cursor, hf_skinny_sourceIpAddr_ipv4, hf_skinny_sourceIpAddr_ipv6);
    sourcePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_sourcePortNumber, 4, ENC_LITTLE_ENDIAN);
    srtp_add_address(pinfo, PT_UDP, &sourceIpAddr, sourcePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
    sourceIpAddr_str = address_to_display(NULL, &sourceIpAddr);
    si->additionalInfo = ws_strdup_printf("%s:%d", sourceIpAddr_str, sourcePortNumber);
    wmem_free(NULL, sourceIpAddr_str);
  }
  if (hdr_version >= V16_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_requestedIpAddrType, 4, ENC_LITTLE_ENDIAN);
  }
  if (hdr_version >= V17_MSG_TYPE) {
    if (hdr_data_length > 132) {
      ptvcursor_add(cursor, hf_skinny_audioLevelAdjustment, 4, ENC_LITTLE_ENDIAN);
    }
  }
  if (hdr_version >= V21_MSG_TYPE) {
    if (hdr_data_length > 132) {
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "latentCapsInfo");
        ptvcursor_add(cursor, hf_skinny_active, 4, ENC_LITTLE_ENDIAN);
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "modemRelay");
          ptvcursor_add(cursor, hf_skinny_capAndVer, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_modAnd2833, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sprtPayload");
          ptvcursor_add(cursor, hf_skinny_chan0MaxPayload, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_chan2MaxPayload, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_chan3MaxPayload, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_chan2MaxWindow, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sse");
          ptvcursor_add(cursor, hf_skinny_standard, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_vendor, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadParam");
          ptvcursor_add(cursor, hf_skinny_nse, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_rfc2833, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_sse, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_v150sprt, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_noaudio, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_FutureUse1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_FutureUse2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_FutureUse3, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0105 ^ passThroughPartyId);
}

/*
 * Message:   CloseReceiveChannelMessage
 * Opcode:    0x0106
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CloseReceiveChannelMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_portHandlingFlag, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ConnectionStatisticsReqMessage
 * Opcode:    0x0107
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_ConnectionStatisticsReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t callReference = 0;

  if (hdr_version <= V17_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_directoryNum, 24, ENC_ASCII);
  }
  if (hdr_version >= V18_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_directoryNum, 28, ENC_ASCII);
  }
  callReference = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_statsProcessingMode, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0107 ^ callReference);
}

/*
 * Message:   SoftKeyTemplateResMessage
 * Opcode:    0x0108
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SoftKeyTemplateResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t totalSoftKeyCount = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "softKeyTemplate");
    ptvcursor_add(cursor, hf_skinny_softKeyOffset, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_softKeyCount, 4, ENC_LITTLE_ENDIAN);
    totalSoftKeyCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_totalSoftKeyCount, 4, ENC_LITTLE_ENDIAN);
    if (totalSoftKeyCount <= 32) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [ref:totalSoftKeyCount = %d, max:32]", totalSoftKeyCount);
      if (totalSoftKeyCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (totalSoftKeyCount * 20) && totalSoftKeyCount <= 32) {
        for (counter_2 = 0; counter_2 < 32; counter_2++) {
          if (counter_2 < totalSoftKeyCount) {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [%d / %d]", counter_2 + 1, totalSoftKeyCount);
            dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_softKeyLabel, 16);
            ptvcursor_add(cursor, hf_skinny_softKeyEvent, 4, ENC_LITTLE_ENDIAN);
          } else {
            ptvcursor_advance(cursor, 20);
          }
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (totalSoftKeyCount * 20));
    }
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0028);
}

/*
 * Message:   SoftKeySetResMessage
 * Opcode:    0x0109
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SoftKeySetResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t totalSoftKeySetCount = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "softKeySets");
    ptvcursor_add(cursor, hf_skinny_softKeySetOffset, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_softKeySetCount, 4, ENC_LITTLE_ENDIAN);
    totalSoftKeySetCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_totalSoftKeySetCount, 4, ENC_LITTLE_ENDIAN);
    if (totalSoftKeySetCount <= 16) {
      uint32_t counter_2 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [ref:totalSoftKeySetCount = %d, max:16]", totalSoftKeySetCount);
      if (totalSoftKeySetCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (totalSoftKeySetCount * 3) && totalSoftKeySetCount <= 16) {
        for (counter_2 = 0; counter_2 < 16; counter_2++) {
          if (counter_2 < totalSoftKeySetCount) {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "definition [%d / %d]", counter_2 + 1, totalSoftKeySetCount);
            {
              uint32_t counter_7 = 0;
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "softKeyTemplateIndex [max:16]");
              for (counter_7 = 0; counter_7 < 16; counter_7++) {
                ptvcursor_add(cursor, hf_skinny_softKeyTemplateIndex, 1, ENC_LITTLE_ENDIAN);
              }
              ptvcursor_pop_subtree(cursor);
            }
            {
              uint32_t counter_7 = 0;
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "softKeyInfoIndex [max:16]");
              for (counter_7 = 0; counter_7 < 16; counter_7++) {
                ptvcursor_add(cursor, hf_skinny_softKeyInfoIndex, 2, ENC_LITTLE_ENDIAN);
              }
              ptvcursor_pop_subtree(cursor);
            }
          } else {
            ptvcursor_advance(cursor, 3);
          }
          ptvcursor_pop_subtree(cursor);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (totalSoftKeySetCount * 3));
    }
    ptvcursor_pop_subtree(cursor);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0025);
}

/*
 * Message:   SelectSoftKeysMessage
 * Opcode:    0x0110
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SelectSoftKeysMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_softKeySetIndex, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "validKeyMask");
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey1, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey2, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey3, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey4, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey5, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey6, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey7, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey8, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey9, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey10, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey11, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey12, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey13, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey14, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey15, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_SoftKeyMask_SoftKey16, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: validKeyMask */
}

/*
 * Message:   CallStateMessage
 * Opcode:    0x0111
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CallStateMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->additionalInfo = ws_strdup_printf("\"%s\"",
    try_val_to_str_ext(
      tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)),
      &DCallState_ext
    )
  );
  si->callState = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callState, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_privacy, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "precedence");
    ptvcursor_add(cursor, hf_skinny_precedenceLevel, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_precedenceDomain, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   DisplayPromptStatusMessage
 * Opcode:    0x0112
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_DisplayPromptStatusMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_promptStatus, 32);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ClearPromptStatusMessage
 * Opcode:    0x0113
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_ClearPromptStatusMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   DisplayNotifyMessage
 * Opcode:    0x0114
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_DisplayNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_notify, 32);
}

/*
 * Message:   ActivateCallPlaneMessage
 * Opcode:    0x0116
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_ActivateCallPlaneMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   UnregisterAckMessage
 * Opcode:    0x0118
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_UnregisterAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_status, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0027);
}

/*
 * Message:   BackSpaceResMessage
 * Opcode:    0x0119
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_BackSpaceResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   RegisterTokenReject
 * Opcode:    0x011b
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_RegisterTokenReject(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_waitTimeBeforeNextReq, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0029);
}

/*
 * Message:   StartMediaFailureDetectionMessage
 * Opcode:    0x011c
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StartMediaFailureDetectionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t compressionType = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierIn");
    ptvcursor_add(cursor, hf_skinny_ecValue, 4, ENC_LITTLE_ENDIAN);
    if (hdr_version <= V10_MSG_TYPE) {
      ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
    }
    if (hdr_version >= V11_MSG_TYPE) {
      if (compressionType == MEDIA_PAYLOAD_G7231)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
        ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      } else       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
          ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  }
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   DialedNumberMessage
 * Opcode:    0x011d
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_DialedNumberMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t VariableDirnumSize = (hdr_version >= V18_MSG_TYPE) ? 25 : 24;

  if (hdr_version <= V17_MSG_TYPE) {
    uint32_t dialedNumber_len;
    dialedNumber_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), 24)+1;
    if (dialedNumber_len > 1) {
      si->additionalInfo = ws_strdup_printf("\"%s\"", tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), dialedNumber_len));
    }
    ptvcursor_add(cursor, hf_skinny_dialedNumber, 24, ENC_ASCII);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
  if (hdr_version >= V18_MSG_TYPE) {
    uint32_t dialedNumber_len;
    dialedNumber_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), VariableDirnumSize)+1;
    if (dialedNumber_len > 1) {
      si->additionalInfo = ws_strdup_printf("\"%s\"", tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), dialedNumber_len));
    }
    ptvcursor_add(cursor, hf_skinny_dialedNumber, VariableDirnumSize, ENC_ASCII);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  }
}

/*
 * Message:   UserToDeviceDataMessage
 * Opcode:    0x011e
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_UserToDeviceDataMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "userToDeviceData");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   FeatureStatResMessage
 * Opcode:    0x011f
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_FeatureStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t featureIndex = 0;
  featureIndex = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_featureIndex, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_featureID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_featureTextLabel, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_featureStatus, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0034 ^ featureIndex);
}

/*
 * Message:   DisplayPriNotifyMessage
 * Opcode:    0x0120
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_DisplayPriNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_priority, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_notify, 32);
}

/*
 * Message:   ClearPriNotifyMessage
 * Opcode:    0x0121
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_ClearPriNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_priority, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StartAnnouncementMessage
 * Opcode:    0x0122
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StartAnnouncementMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "AnnList [max:32]");
    for (counter_1 = 0; counter_1 < 32; counter_1++) {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "AnnList [%d / %d]", counter_1 + 1, 32);
      ptvcursor_add(cursor, hf_skinny_locale, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_country, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_toneAnnouncement, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_annAckReq, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  {
    uint32_t counter_2 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "matrixConfPartyID [max:16]");
    for (counter_2 = 0; counter_2 < 16; counter_2++) {
      ptvcursor_add(cursor, hf_skinny_matrixConfPartyID, 4, ENC_LITTLE_ENDIAN);
    }
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_hearingConfPartyMask, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_annPlayMode, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   StopAnnouncementMessage
 * Opcode:    0x0123
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopAnnouncementMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   AnnouncementFinishMessage
 * Opcode:    0x0124
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_AnnouncementFinishMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_annStatus, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   NotifyDtmfToneMessage
 * Opcode:    0x0127
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_NotifyDtmfToneMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_tone, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SendDtmfToneMessage
 * Opcode:    0x0128
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_SendDtmfToneMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_tone, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SubscribeDtmfPayloadReqMessage
 * Opcode:    0x0129
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_SubscribeDtmfPayloadReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_dtmfType, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0129);
}

/*
 * Message:   SubscribeDtmfPayloadResMessage
 * Opcode:    0x012a
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SubscribeDtmfPayloadResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0129 ^ passthruPartyID);
}

/*
 * Message:   SubscribeDtmfPayloadErrMessage
 * Opcode:    0x012b
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SubscribeDtmfPayloadErrMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0129 ^ passthruPartyID);
}

/*
 * Message:   UnSubscribeDtmfPayloadReqMessage
 * Opcode:    0x012c
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_UnSubscribeDtmfPayloadReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_dtmfType, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x012c ^ passthruPartyID);
}

/*
 * Message:   UnSubscribeDtmfPayloadResMessage
 * Opcode:    0x012d
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_UnSubscribeDtmfPayloadResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x012d ^ passthruPartyID);
}

/*
 * Message:   UnSubscribeDtmfPayloadErrMessage
 * Opcode:    0x012e
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_UnSubscribeDtmfPayloadErrMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  ptvcursor_add(cursor, hf_skinny_payloadDtmf, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x012d ^ passthruPartyID);
}

/*
 * Message:   ServiceURLStatResMessage
 * Opcode:    0x012f
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_ServiceURLStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t serviceURLIndex = 0;
  serviceURLIndex = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_serviceURLIndex, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_serviceURL, 256, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_serviceURLDisplayName, 40, ENC_ASCII);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0033 ^ serviceURLIndex);
}

/*
 * Message:   CallSelectStatResMessage
 * Opcode:    0x0130
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CallSelectStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_callSelectStat, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   OpenMultiMediaReceiveChannelMessage
 * Opcode:    0x0131
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_OpenMultiMediaReceiveChannelMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t passThroughPartyId = 0;
  uint32_t compressionType = 0;
  uint32_t payloadType = 0;
  uint32_t pictureFormatCount = 0;
  uint16_t keylen = 0;
  uint16_t saltlen = 0;
  address sourceIpAddr;
  char *sourceIpAddr_str = NULL;
  uint32_t sourcePortNumber = 0;

  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType");
    ptvcursor_add(cursor, hf_skinny_payload_rfc_number, 4, ENC_LITTLE_ENDIAN);
    payloadType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_payloadType, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_isConferenceCreator, 4, ENC_LITTLE_ENDIAN);
  if (payloadType <= MEDIA_PAYLOAD_AMR_WB)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType <= Media_Payload_AMR_WB");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audioParameters");
      ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierIn");
        ptvcursor_add(cursor, hf_skinny_ecValue, 4, ENC_LITTLE_ENDIAN);
        if (hdr_version <= V10_MSG_TYPE) {
          ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        }
        if (hdr_version >= V11_MSG_TYPE) {
          if (compressionType == MEDIA_PAYLOAD_G7231)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
            ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          } else           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
              ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          }
        }
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 36);
  } else if (payloadType >= MEDIA_PAYLOAD_H261 && payloadType <= MEDIA_PAYLOAD_H264_FEC)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "Media_Payload_H261 <= payloadType <= Media_Payload_H264_FEC");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidParameters");
      ptvcursor_add(cursor, hf_skinny_bitRate, 4, ENC_LITTLE_ENDIAN);
      pictureFormatCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_skinny_pictureFormatCount, 4, ENC_LITTLE_ENDIAN);
      if (pictureFormatCount <= 5) {
        uint32_t counter_3 = 0;
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "pictureFormat [ref:pictureFormatCount = %d, max:5]", pictureFormatCount);
        if (pictureFormatCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (pictureFormatCount * 8) && pictureFormatCount <= 5) {
          for (counter_3 = 0; counter_3 < 5; counter_3++) {
            if (counter_3 < pictureFormatCount) {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "pictureFormat [%d / %d]", counter_3 + 1, pictureFormatCount);
              ptvcursor_add(cursor, hf_skinny_format, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_MPI, 4, ENC_LITTLE_ENDIAN);
            } else {
              ptvcursor_advance(cursor, 8);
            }
            ptvcursor_pop_subtree(cursor);
          }
        }
        ptvcursor_pop_subtree(cursor);
      } else {
        ptvcursor_advance(cursor, (pictureFormatCount * 8));
      }
      ptvcursor_add(cursor, hf_skinny_confServiceNum, 4, ENC_LITTLE_ENDIAN);
      if (payloadType == MEDIA_PAYLOAD_H261)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H261");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h261VideoCapability");
          ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOffCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_stillImageTransmission, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      } else if (payloadType == MEDIA_PAYLOAD_H263)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H263");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263VideoCapability");
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263_capability_bitfield");
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit1, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit2, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit3, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit4, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit5, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit6, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit7, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit8, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit9, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit10, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit11, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit12, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit13, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit14, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit15, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit16, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit17, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit18, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit19, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit20, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit21, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit22, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit23, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit24, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit25, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit26, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit27, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit28, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit29, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit30, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit31, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit32, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_advance(cursor, 4);
          ptvcursor_pop_subtree(cursor); /* end bitfield: h263_capability_bitfield */
          ptvcursor_add(cursor, hf_skinny_annexNandWFutureUse, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      } else if (payloadType == MEDIA_PAYLOAD_H264)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H264");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h264VideoCapability");
          ptvcursor_add(cursor, hf_skinny_profile, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_level, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxMBPS, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxFS, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxDPB, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxBRandCPB, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      } else if (payloadType == MEDIA_PAYLOAD_VIEO)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_Vieo");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vieoVideoCapability");
          ptvcursor_add(cursor, hf_skinny_modelNumber, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_bandwidth, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      }
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
  } else if (payloadType >= MEDIA_PAYLOAD_CLEAR_CHAN)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType >= Media_Payload_Clear_Chan");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataParameters");
      ptvcursor_add(cursor, hf_skinny_protocolDependentData, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 36);
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "mRxMediaEncryptionKeyInfo");
    ptvcursor_add(cursor, hf_skinny_algorithmID, 4, ENC_LITTLE_ENDIAN);
    keylen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_keylen, 2, ENC_LITTLE_ENDIAN);
    saltlen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_saltlen, 2, ENC_LITTLE_ENDIAN);
    if (keylen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "key [ref:keylen = %d, max:16]", keylen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < keylen) {
          ptvcursor_add(cursor, hf_skinny_key, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    if (saltlen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "salt [ref:saltlen = %d, max:16]", saltlen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < saltlen) {
          ptvcursor_add(cursor, hf_skinny_salt, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    ptvcursor_add(cursor, hf_skinny_isMKIPresent, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_keyDerivationRate, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_streamPassThroughId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_associatedStreamId, 4, ENC_LITTLE_ENDIAN);
  if (hdr_version >= V11_MSG_TYPE) {
    read_skinny_ipv4or6(cursor, &sourceIpAddr);
    dissect_skinny_ipv4or6(cursor, hf_skinny_sourceIpAddr_ipv4, hf_skinny_sourceIpAddr_ipv6);
    sourcePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_sourcePortNumber, 4, ENC_LITTLE_ENDIAN);
    srtp_add_address(pinfo, PT_UDP, &sourceIpAddr, sourcePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
    sourceIpAddr_str = address_to_display(NULL, &sourceIpAddr);
    si->additionalInfo = ws_strdup_printf("%s:%d", sourceIpAddr_str, sourcePortNumber);
    wmem_free(NULL, sourceIpAddr_str);
  }
  if (hdr_version >= V16_MSG_TYPE) {
    ptvcursor_add(cursor, hf_skinny_requestedIpAddrType, 4, ENC_LITTLE_ENDIAN);
  }
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0131 ^ passThroughPartyId);
}

/*
 * Message:   StartMultiMediaTransmissionMessage
 * Opcode:    0x0132
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_StartMultiMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passthruPartyID = 0;
  uint32_t compressionType = 0;
  uint32_t payloadType = 0;
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t pictureFormatCount = 0;
  uint16_t keylen = 0;
  uint16_t saltlen = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passthruPartyID = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  compressionType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType");
    ptvcursor_add(cursor, hf_skinny_payload_rfc_number, 4, ENC_LITTLE_ENDIAN);
    payloadType = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_payloadType, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_DSCPValue, 4, ENC_LITTLE_ENDIAN);
  if (payloadType <= MEDIA_PAYLOAD_AMR_WB)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType <= Media_Payload_AMR_WB");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "audioParameters");
      ptvcursor_add(cursor, hf_skinny_milliSecondPacketSize, 4, ENC_LITTLE_ENDIAN);
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "qualifierIn");
        ptvcursor_add(cursor, hf_skinny_ecValue, 4, ENC_LITTLE_ENDIAN);
        if (hdr_version <= V10_MSG_TYPE) {
          ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
        }
        if (hdr_version >= V11_MSG_TYPE) {
          if (compressionType == MEDIA_PAYLOAD_G7231)           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "compressionType is Media_Payload_G7231");
            ptvcursor_add(cursor, hf_skinny_g723BitRate, 4, ENC_LITTLE_ENDIAN);
            ptvcursor_pop_subtree(cursor);
          } else           {
            ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any compressionType");
            {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "codecParams");
              ptvcursor_add(cursor, hf_skinny_codecMode, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_dynamicPayload, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam1, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_codecParam2, 1, ENC_LITTLE_ENDIAN);
              ptvcursor_pop_subtree(cursor);
            }
            ptvcursor_pop_subtree(cursor);
          }
        }
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 36);
  } else if (payloadType >= MEDIA_PAYLOAD_H261 && payloadType <= MEDIA_PAYLOAD_H264_FEC)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "Media_Payload_H261 <= payloadType <= Media_Payload_H264_FEC");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vidParameters");
      ptvcursor_add(cursor, hf_skinny_bitRate, 4, ENC_LITTLE_ENDIAN);
      pictureFormatCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_skinny_pictureFormatCount, 4, ENC_LITTLE_ENDIAN);
      if (pictureFormatCount <= 5) {
        uint32_t counter_3 = 0;
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "pictureFormat [ref:pictureFormatCount = %d, max:5]", pictureFormatCount);
        if (pictureFormatCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (pictureFormatCount * 8) && pictureFormatCount <= 5) {
          for (counter_3 = 0; counter_3 < 5; counter_3++) {
            if (counter_3 < pictureFormatCount) {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "pictureFormat [%d / %d]", counter_3 + 1, pictureFormatCount);
              ptvcursor_add(cursor, hf_skinny_format, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_MPI, 4, ENC_LITTLE_ENDIAN);
            } else {
              ptvcursor_advance(cursor, 8);
            }
            ptvcursor_pop_subtree(cursor);
          }
        }
        ptvcursor_pop_subtree(cursor);
      } else {
        ptvcursor_advance(cursor, (pictureFormatCount * 8));
      }
      ptvcursor_add(cursor, hf_skinny_confServiceNum, 4, ENC_LITTLE_ENDIAN);
      if (payloadType == MEDIA_PAYLOAD_H261)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H261");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h261VideoCapability");
          ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOffCapability, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_stillImageTransmission, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      } else if (payloadType == MEDIA_PAYLOAD_H263)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H263");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263VideoCapability");
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h263_capability_bitfield");
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit1, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit2, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit3, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit4, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit5, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit6, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit7, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit8, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit9, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit10, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit11, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit12, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit13, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit14, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit15, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit16, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit17, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit18, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit19, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit20, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit21, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit22, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit23, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit24, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit25, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit26, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit27, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit28, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit29, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit30, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit31, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add_no_advance(cursor, hf_skinny_Generic_Bitfield_Bit32, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_advance(cursor, 4);
          ptvcursor_pop_subtree(cursor); /* end bitfield: h263_capability_bitfield */
          ptvcursor_add(cursor, hf_skinny_annexNandWFutureUse, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      } else if (payloadType == MEDIA_PAYLOAD_H264)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_H264");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "h264VideoCapability");
          ptvcursor_add(cursor, hf_skinny_profile, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_level, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxMBPS, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxFS, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxDPB, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_customMaxBRandCPB, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
      } else if (payloadType == MEDIA_PAYLOAD_VIEO)       {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType is Media_Payload_Vieo");
        {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "vieoVideoCapability");
          ptvcursor_add(cursor, hf_skinny_modelNumber, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_bandwidth, 4, ENC_LITTLE_ENDIAN);
          ptvcursor_pop_subtree(cursor);
        }
        ptvcursor_pop_subtree(cursor);
        ptvcursor_advance(cursor, 16);
      }
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
  } else if (payloadType >= MEDIA_PAYLOAD_CLEAR_CHAN)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "payloadType >= Media_Payload_Clear_Chan");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "dataParameters");
      ptvcursor_add(cursor, hf_skinny_protocolDependentData, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_maxBitRate, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 36);
  }
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "mTxMediaEncryptionKeyInfo");
    ptvcursor_add(cursor, hf_skinny_algorithmID, 4, ENC_LITTLE_ENDIAN);
    keylen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_keylen, 2, ENC_LITTLE_ENDIAN);
    saltlen = tvb_get_letohs(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_saltlen, 2, ENC_LITTLE_ENDIAN);
    if (keylen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "key [ref:keylen = %d, max:16]", keylen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < keylen) {
          ptvcursor_add(cursor, hf_skinny_key, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    if (saltlen <= 16) {
      uint32_t counter_3 = 0;
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "salt [ref:saltlen = %d, max:16]", saltlen);
      for (counter_3 = 0; counter_3 < 16; counter_3++) {
        if (counter_3 < saltlen) {
          ptvcursor_add(cursor, hf_skinny_salt, 1, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 1);
        }
      }
      ptvcursor_pop_subtree(cursor);
    } else {
      ptvcursor_advance(cursor, (16 * 1));
    }
    ptvcursor_add(cursor, hf_skinny_isMKIPresent, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_keyDerivationRate, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_streamPassThroughId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_associatedStreamId, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0132 ^ passthruPartyID);
}

/*
 * Message:   StopMultiMediaTransmissionMessage
 * Opcode:    0x0133
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_StopMultiMediaTransmissionMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_portHandlingFlag, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   MiscellaneousCommandMessage
 * Opcode:    0x0134
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_MiscellaneousCommandMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t command = 0;
  uint32_t recoveryReferencePictureCount = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  command = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_command, 4, ENC_LITTLE_ENDIAN);
  if (command == MISCCOMMANDTYPE_VIDEOFASTUPDATEPICTURE)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_videoFastUpdatePicture");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "videoFastUpdatePicture");
      ptvcursor_add(cursor, hf_skinny_firstGOB, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_numberOfGOBs, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 8);
  } else if (command == MISCCOMMANDTYPE_VIDEOFASTUPDATEGOB)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_videoFastUpdateGOB");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "videoFastUpdateGOB");
      ptvcursor_add(cursor, hf_skinny_firstGOB, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_numberOfGOBs, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 8);
  } else if (command == MISCCOMMANDTYPE_VIDEOFASTUPDATEMB)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_videoFastUpdateMB");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "videoFastUpdateMB");
      ptvcursor_add(cursor, hf_skinny_firstGOB, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_firstMB, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_numberOfMBs, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 4);
  } else if (command == MISCCOMMANDTYPE_LOSTPICTURE)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_lostPicture");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "lostPicture");
      ptvcursor_add(cursor, hf_skinny_pictureNumber, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_longTermPictureIndex, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 8);
  } else if (command == MISCCOMMANDTYPE_LOSTPARTIALPICTURE)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_lostPartialPicture");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "lostPartialPicture");
      {
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "pictureReference");
        ptvcursor_add(cursor, hf_skinny_pictureNumber, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_add(cursor, hf_skinny_longTermPictureIndex, 4, ENC_LITTLE_ENDIAN);
        ptvcursor_pop_subtree(cursor);
      }
      ptvcursor_add(cursor, hf_skinny_firstMB, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_add(cursor, hf_skinny_numberOfMBs, 4, ENC_LITTLE_ENDIAN);
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
  } else if (command == MISCCOMMANDTYPE_RECOVERYREFERENCEPICTURE)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_recoveryReferencePicture");
    {
      ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "recoveryReferencePictureValue");
      recoveryReferencePictureCount = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
      ptvcursor_add(cursor, hf_skinny_recoveryReferencePictureCount, 4, ENC_LITTLE_ENDIAN);
      if (recoveryReferencePictureCount <= 4) {
        uint32_t counter_3 = 0;
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "recoveryReferencePicture [ref:recoveryReferencePictureCount = %d, max:4]", recoveryReferencePictureCount);
        if (recoveryReferencePictureCount && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (recoveryReferencePictureCount * 8) && recoveryReferencePictureCount <= 4) {
          for (counter_3 = 0; counter_3 < 4; counter_3++) {
            if (counter_3 < recoveryReferencePictureCount) {
              ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "recoveryReferencePicture [%d / %d]", counter_3 + 1, recoveryReferencePictureCount);
              ptvcursor_add(cursor, hf_skinny_pictureNumber, 4, ENC_LITTLE_ENDIAN);
              ptvcursor_add(cursor, hf_skinny_longTermPictureIndex, 4, ENC_LITTLE_ENDIAN);
            } else {
              ptvcursor_advance(cursor, 8);
            }
            ptvcursor_pop_subtree(cursor);
          }
        }
        ptvcursor_pop_subtree(cursor);
      } else {
        ptvcursor_advance(cursor, (recoveryReferencePictureCount * 8));
      }
      ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 4);
  } else if (command == MISCCOMMANDTYPE_TEMPORALSPATIALTRADEOFF)   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "command is MiscCommandType_temporalSpatialTradeOff");
    ptvcursor_add(cursor, hf_skinny_temporalSpatialTradeOff, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 12);
  } else   {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "any command");
    ptvcursor_add(cursor, hf_skinny_none, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
    ptvcursor_advance(cursor, 12);
  }
}

/*
 * Message:   FlowControlCommandMessage
 * Opcode:    0x0135
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_FlowControlCommandMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maximumBitRate, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   CloseMultiMediaReceiveChannelMessage
 * Opcode:    0x0136
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CloseMultiMediaReceiveChannelMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_portHandlingFlag, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   CreateConferenceReqMessage
 * Opcode:    0x0137
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_CreateConferenceReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  uint32_t dataLength = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfReservedParticipants, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_resourceType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_appConfID, 32, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_appData, 24, ENC_ASCII);
  dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passThruData, dataLength, ENC_ASCII);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0137 ^ conferenceId);
}

/*
 * Message:   DeleteConferenceReqMessage
 * Opcode:    0x0138
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_DeleteConferenceReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0138 ^ conferenceId);
}

/*
 * Message:   ModifyConferenceReqMessage
 * Opcode:    0x0139
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_ModifyConferenceReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  uint32_t dataLength = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfReservedParticipants, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_appConfID, 32, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_appData, 24, ENC_ASCII);
  dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passThruData, dataLength, ENC_ASCII);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x0139 ^ conferenceId);
}

/*
 * Message:   AddParticipantReqMessage
 * Opcode:    0x013a
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_AddParticipantReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "partyPIRestrictionBits");
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_BitsReserved, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: partyPIRestrictionBits */
  ptvcursor_add(cursor, hf_skinny_participantName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_participantNumber, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_conferenceName, 32, ENC_ASCII);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x013a ^ conferenceId);
}

/*
 * Message:   DropParticipantReqMessage
 * Opcode:    0x013b
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_DropParticipantReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x013b ^ conferenceId);
}

/*
 * Message:   AuditParticipantReqMessage
 * Opcode:    0x013d
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_AuditParticipantReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x013d ^ conferenceId);
}

/*
 * Message:   ChangeParticipantReqMessage
 * Opcode:    0x013e
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_ChangeParticipantReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t conferenceId = 0;
  conferenceId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "partyPIRestrictionBits");
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_BitsReserved, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: partyPIRestrictionBits */
  ptvcursor_add(cursor, hf_skinny_participantName, 40, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_participantNumber, 24, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_conferenceName, 32, ENC_ASCII);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x013e ^ conferenceId);
}

/*
 * Message:   UserToDeviceDataMessageVersion1
 * Opcode:    0x013f
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_UserToDeviceDataMessageVersion1(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t dataLength = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "userToDeviceDataVersion1");
    ptvcursor_add(cursor, hf_skinny_applicationId, 4, ENC_LITTLE_ENDIAN);
    si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
    si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
    dataLength = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
    ptvcursor_add(cursor, hf_skinny_dataLength, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_sequenceFlag, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_displayPriority, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_appInstanceID, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_routingID, 4, ENC_LITTLE_ENDIAN);
    dissect_skinny_xml(cursor, hf_skinny_xmldata, pinfo, dataLength, 2000);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   VideoDisplayCommandMessage
 * Opcode:    0x0140
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_VideoDisplayCommandMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_layoutID, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   FlowControlNotifyMessage
 * Opcode:    0x0141
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_FlowControlNotifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_passthruPartyID, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maximumBitRate, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   ConfigStatV2ResMessage
 * Opcode:    0x0142
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_ConfigStatV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t DeviceName_len = 0;
  uint32_t userName_len = 0;
  uint32_t serverName_len = 0;
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sid");
    DeviceName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
    if (DeviceName_len > 1) {
      ptvcursor_add(cursor, hf_skinny_DeviceName, DeviceName_len, ENC_ASCII);
    } else {
      ptvcursor_advance(cursor, 1);
    }
    ptvcursor_add(cursor, hf_skinny_reserved_for_future_use, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_instance, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_numberOfLines, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_numberOfSpeedDials, 4, ENC_LITTLE_ENDIAN);
  userName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (userName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_userName, userName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  serverName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (serverName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_serverName, serverName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000c);
}

/*
 * Message:   DisplayNotifyV2Message
 * Opcode:    0x0143
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   event
 */
static void
handle_DisplayNotifyV2Message(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_notify, 0);
}

/*
 * Message:   DisplayPriNotifyV2Message
 * Opcode:    0x0144
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   event
 */
static void
handle_DisplayPriNotifyV2Message(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_priority, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_notify, 0);
}

/*
 * Message:   DisplayPromptStatusV2Message
 * Opcode:    0x0145
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   event
 */
static void
handle_DisplayPromptStatusV2Message(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_timeOutValue, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  dissect_skinny_displayLabel(cursor, pinfo, hf_skinny_promptStatus, 0);
}

/*
 * Message:   FeatureStatV2ResMessage
 * Opcode:    0x0146
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_FeatureStatV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t featureTextLabel_len = 0;
  ptvcursor_add(cursor, hf_skinny_featureIndex, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_featureID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_featureStatus, 4, ENC_LITTLE_ENDIAN);
  featureTextLabel_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (featureTextLabel_len > 1) {
    ptvcursor_add(cursor, hf_skinny_featureTextLabel, featureTextLabel_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0034);
}

/*
 * Message:   LineStatV2ResMessage
 * Opcode:    0x0147
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_LineStatV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineNumber = 0;
  uint32_t lineDirNumber_len = 0;
  uint32_t lineFullyQualifiedDisplayName_len = 0;
  uint32_t lineTextLabel_len = 0;
  lineNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "lineType");
  ptvcursor_add_no_advance(cursor, hf_skinny_OrigDialed, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RedirDialed, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_CallingPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_CallingPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: lineType */
  lineDirNumber_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lineDirNumber_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lineDirNumber, lineDirNumber_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  lineFullyQualifiedDisplayName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lineFullyQualifiedDisplayName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lineFullyQualifiedDisplayName, lineFullyQualifiedDisplayName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  lineTextLabel_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lineTextLabel_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lineTextLabel, lineTextLabel_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000b ^ lineNumber);
}

/*
 * Message:   ServiceURLStatV2ResMessage
 * Opcode:    0x0148
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_ServiceURLStatV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t serviceURLIndex = 0;
  serviceURLIndex = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_serviceURLIndex, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0033 ^ serviceURLIndex);
}

/*
 * Message:   SpeedDialStatV2ResMessage
 * Opcode:    0x0149
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   response
 */
static void
handle_SpeedDialStatV2ResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t speedDialNumber = 0;
  uint32_t speedDialDirNumber_len = 0;
  uint32_t speedDialDisplayName_len = 0;
  speedDialNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_speedDialNumber, 4, ENC_LITTLE_ENDIAN);
  speedDialDirNumber_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (speedDialDirNumber_len > 1) {
    ptvcursor_add(cursor, hf_skinny_speedDialDirNumber, speedDialDirNumber_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  speedDialDisplayName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (speedDialDisplayName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_speedDialDisplayName, speedDialDisplayName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x000a ^ speedDialNumber);
}

/*
 * Message:   CallInfoV2Message
 * Opcode:    0x014a
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: yes
 * MsgType:   event
 */
static void
handle_CallInfoV2Message(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t hdr_version = tvb_get_letohl(ptvcursor_tvbuff(cursor), 4);
  uint32_t callingParty_len = 0;
  uint32_t AlternateCallingParty_len = 0;
  uint32_t calledParty_len = 0;
  uint32_t originalCalledParty_len = 0;
  uint32_t lastRedirectingParty_len = 0;
  uint32_t cgpnVoiceMailbox_len = 0;
  uint32_t cdpnVoiceMailbox_len = 0;
  uint32_t originalCdpnVoiceMailbox_len = 0;
  uint32_t lastRedirectingVoiceMailbox_len = 0;
  uint32_t callingPartyName_len = 0;
  uint32_t calledPartyName_len = 0;
  uint32_t originalCalledPartyName_len = 0;
  uint32_t lastRedirectingPartyName_len = 0;
  uint32_t HuntPilotNumber_len = 0;
  uint32_t HuntPilotName_len = 0;

  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_callType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_originalCdpnRedirectReason, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_lastRedirectingReason, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_callInstance, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_callSecurityStatus, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "partyPIRestrictionBits");
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CallingParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_CalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_OriginalCalledParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyName, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectPartyNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_LastRedirectParty, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add_no_advance(cursor, hf_skinny_RestrictInformationType_BitsReserved, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_advance(cursor, 4);
  ptvcursor_pop_subtree(cursor); /* end bitfield: partyPIRestrictionBits */
  callingParty_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (callingParty_len > 1) {
    si->callingParty = g_strdup(tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), callingParty_len));
    ptvcursor_add(cursor, hf_skinny_callingParty, callingParty_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  AlternateCallingParty_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (AlternateCallingParty_len > 1) {
    ptvcursor_add(cursor, hf_skinny_AlternateCallingParty, AlternateCallingParty_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  calledParty_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (calledParty_len > 1) {
    si->calledParty = g_strdup(tvb_format_stringzpad(pinfo->pool, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), calledParty_len));
    ptvcursor_add(cursor, hf_skinny_calledParty, calledParty_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  originalCalledParty_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (originalCalledParty_len > 1) {
    ptvcursor_add(cursor, hf_skinny_originalCalledParty, originalCalledParty_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  lastRedirectingParty_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lastRedirectingParty_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lastRedirectingParty, lastRedirectingParty_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  cgpnVoiceMailbox_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (cgpnVoiceMailbox_len > 1) {
    ptvcursor_add(cursor, hf_skinny_cgpnVoiceMailbox, cgpnVoiceMailbox_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  cdpnVoiceMailbox_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (cdpnVoiceMailbox_len > 1) {
    ptvcursor_add(cursor, hf_skinny_cdpnVoiceMailbox, cdpnVoiceMailbox_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  originalCdpnVoiceMailbox_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (originalCdpnVoiceMailbox_len > 1) {
    ptvcursor_add(cursor, hf_skinny_originalCdpnVoiceMailbox, originalCdpnVoiceMailbox_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  lastRedirectingVoiceMailbox_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lastRedirectingVoiceMailbox_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lastRedirectingVoiceMailbox, lastRedirectingVoiceMailbox_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  callingPartyName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (callingPartyName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_callingPartyName, callingPartyName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  calledPartyName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (calledPartyName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_calledPartyName, calledPartyName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  originalCalledPartyName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (originalCalledPartyName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_originalCalledPartyName, originalCalledPartyName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  lastRedirectingPartyName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
  if (lastRedirectingPartyName_len > 1) {
    ptvcursor_add(cursor, hf_skinny_lastRedirectingPartyName, lastRedirectingPartyName_len, ENC_ASCII);
  } else {
    ptvcursor_advance(cursor, 1);
  }
  if (hdr_version >= V17_MSG_TYPE) {
    HuntPilotNumber_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
    if (HuntPilotNumber_len > 1) {
      ptvcursor_add(cursor, hf_skinny_HuntPilotNumber, HuntPilotNumber_len, ENC_ASCII);
    } else {
      ptvcursor_advance(cursor, 1);
    }
    HuntPilotName_len = tvb_strnlen(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), -1)+1;
    if (HuntPilotName_len > 1) {
      ptvcursor_add(cursor, hf_skinny_HuntPilotName, HuntPilotName_len, ENC_ASCII);
    } else {
      ptvcursor_advance(cursor, 1);
    }
  }
  if (si->callingParty && si->calledParty) {
    si->additionalInfo = ws_strdup_printf("\"%s -> %s\"", si->callingParty, si->calledParty);
  }
}

/*
 * Message:   PortReqMessage
 * Opcode:    0x014b
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   request
 */
static void
handle_PortReqMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mediaTransportType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_ipAddressType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mediaType, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x014b);
}

/*
 * Message:   PortCloseMessage
 * Opcode:    0x014c
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_PortCloseMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_mediaType, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   QoSListenMessage
 * Opcode:    0x014d
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSListenMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_resvStyle, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxRetryNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_retryTimer, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_confirmRequired, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_preemptionPriority, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_defendingPriority, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_averageBitRate, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_burstSize, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_peakRate, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "applicationID");
    ptvcursor_add(cursor, hf_skinny_vendorID, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_version, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_appName, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_subAppID, 32, ENC_ASCII);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   QoSPathMessage
 * Opcode:    0x014e
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSPathMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_resvStyle, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxRetryNumber, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_retryTimer, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_preemptionPriority, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_defendingPriority, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_averageBitRate, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_burstSize, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_peakRate, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "applicationID");
    ptvcursor_add(cursor, hf_skinny_vendorID, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_version, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_appName, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_subAppID, 32, ENC_ASCII);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   QoSTeardownMessage
 * Opcode:    0x014f
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSTeardownMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_direction, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   UpdateDSCPMessage
 * Opcode:    0x0150
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_UpdateDSCPMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_DSCPValue, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   QoSModifyMessage
 * Opcode:    0x0151
 * Type:      IntraCCM
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_QoSModifyMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  address remoteIpAddr;
  char *remoteIpAddr_str = NULL;
  uint32_t remotePortNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &remoteIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_remoteIpAddr_ipv4, hf_skinny_remoteIpAddr_ipv6);
  remotePortNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_remotePortNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &remoteIpAddr, remotePortNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  remoteIpAddr_str = address_to_display(NULL, &remoteIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", remoteIpAddr_str, remotePortNumber);
  wmem_free(NULL, remoteIpAddr_str);
  ptvcursor_add(cursor, hf_skinny_direction, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_compressionType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_averageBitRate, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_burstSize, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_peakRate, 4, ENC_LITTLE_ENDIAN);
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "applicationID");
    ptvcursor_add(cursor, hf_skinny_vendorID, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_version, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_appName, 32, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_subAppID, 32, ENC_ASCII);
    ptvcursor_pop_subtree(cursor);
  }
}

/*
 * Message:   SubscriptionStatResMessage
 * Opcode:    0x0152
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SubscriptionStatResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t transactionId = 0;
  transactionId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_subscriptionFeatureID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_timer, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_cause, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0048 ^ transactionId);
}

/*
 * Message:   NotificationMessage
 * Opcode:    0x0153
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_NotificationMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_transactionId, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_subscriptionFeatureID, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_notificationStatus, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_text, 97, ENC_ASCII);
}

/*
 * Message:   StartMediaTransmissionAckMessage
 * Opcode:    0x0154
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_StartMediaTransmissionAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  address transmitIpAddr;
  char *transmitIpAddr_str = NULL;
  uint32_t portNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &transmitIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_transmitIpAddr_ipv4, hf_skinny_transmitIpAddr_ipv6);
  portNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_portNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &transmitIpAddr, portNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  transmitIpAddr_str = address_to_display(NULL, &transmitIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", transmitIpAddr_str, portNumber);
  wmem_free(NULL, transmitIpAddr_str);
  si->mediaTransmissionStatus = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_mediaTransmissionStatus, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x008a ^ passThroughPartyId);
}

/*
 * Message:   StartMultiMediaTransmissionAckMessage
 * Opcode:    0x0155
 * Type:      MediaControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_StartMultiMediaTransmissionAckMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t passThroughPartyId = 0;
  address transmitIpAddr;
  char *transmitIpAddr_str = NULL;
  uint32_t portNumber = 0;
  ptvcursor_add(cursor, hf_skinny_conferenceId, 4, ENC_LITTLE_ENDIAN);
  passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  si->passThroughPartyId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_passThroughPartyId, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  read_skinny_ipv4or6(cursor, &transmitIpAddr);
  dissect_skinny_ipv4or6(cursor, hf_skinny_transmitIpAddr_ipv4, hf_skinny_transmitIpAddr_ipv6);
  portNumber = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_portNumber, 4, ENC_LITTLE_ENDIAN);
  srtp_add_address(pinfo, PT_UDP, &transmitIpAddr, portNumber, 0, "SKINNY", pinfo->num, false, NULL, NULL, NULL);
  transmitIpAddr_str = address_to_display(NULL, &transmitIpAddr);
  si->additionalInfo = ws_strdup_printf("%s:%d", transmitIpAddr_str, portNumber);
  wmem_free(NULL, transmitIpAddr_str);
  si->multimediaTransmissionStatus = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_multimediaTransmissionStatus, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x0132 ^ passThroughPartyId);
}

/*
 * Message:   CallHistoryInfoMessage
 * Opcode:    0x0156
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_CallHistoryInfoMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_callHistoryDisposition, 4, ENC_LITTLE_ENDIAN);
  si->lineId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineInstance, 4, ENC_LITTLE_ENDIAN);
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   LocationInfoMessage
 * Opcode:    0x0157
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 * Comment: Sent by wifi devices, contains xml information about connected SSID
 */
static void
handle_LocationInfoMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_locationInfo, 2401, ENC_ASCII);
}

/*
 * Message:   MwiResMessage
 * Opcode:    0x0158
 * Type:      RegistrationAndManagement
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_MwiResMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_mwiTargetNumber, 25, ENC_ASCII);
  ptvcursor_add(cursor, hf_skinny_mwi_notification_result, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x004c);
}

/*
 * Message:   AddOnDeviceCapabilitiesMessage
 * Opcode:    0x0159
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   event
 */
static void
handle_AddOnDeviceCapabilitiesMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_unknown1_0159, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_unknown2_0159, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_unknown3_0159, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_unknownString_0159, 152, ENC_ASCII);
}

/*
 * Message:   EnhancedAlarmMessage
 * Opcode:    0x015a
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_EnhancedAlarmMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  dissect_skinny_xml(cursor, hf_skinny_alarmInfo, pinfo, 0, 2048);
}

/*
 * Message:   CallCountRespMessage
 * Opcode:    0x015f
 * Type:      CallControl
 * Direction: pbx2pbx
 * VarLength: no
 * MsgType:   response
 */
static void
handle_CallCountRespMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  uint32_t lineDataEntries = 0;
  ptvcursor_add(cursor, hf_skinny_totalNumOfConfiguredLines, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_startingLineInstance, 4, ENC_LITTLE_ENDIAN);
  lineDataEntries = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_lineDataEntries, 4, ENC_LITTLE_ENDIAN);
  if (lineDataEntries <= 42) {
    uint32_t counter_1 = 0;
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "lineData [ref:lineDataEntries = %d, max:42]", lineDataEntries);
    if (lineDataEntries && tvb_get_letohl(ptvcursor_tvbuff(cursor), 0) + 8 >= ptvcursor_current_offset(cursor) + (lineDataEntries * 4) && lineDataEntries <= 42) {
      for (counter_1 = 0; counter_1 < 42; counter_1++) {
        if (counter_1 < lineDataEntries) {
          ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "lineData [%d / %d]", counter_1 + 1, lineDataEntries);
          ptvcursor_add(cursor, hf_skinny_maxNumCalls, 2, ENC_LITTLE_ENDIAN);
          ptvcursor_add(cursor, hf_skinny_busyTrigger, 2, ENC_LITTLE_ENDIAN);
        } else {
          ptvcursor_advance(cursor, 4);
        }
        ptvcursor_pop_subtree(cursor);
      }
    }
    ptvcursor_pop_subtree(cursor);
  } else {
    ptvcursor_advance(cursor, (lineDataEntries * 4));
  }
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x015e);
}

/*
 * Message:   RecordingStatusMessage
 * Opcode:    0x0160
 * Type:      CallControl
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   event
 */
static void
handle_RecordingStatusMessage(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  si->callId = tvb_get_letohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
  ptvcursor_add(cursor, hf_skinny_callReference, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_recording_status, 4, ENC_LITTLE_ENDIAN);
}

/*
 * Message:   SPCPRegisterTokenReq
 * Opcode:    0x8000
 * Type:      RegistrationAndManagement
 * Direction: dev2pbx
 * VarLength: no
 * MsgType:   request
 */
static void
handle_SPCPRegisterTokenReq(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  {
    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_skinny_tree, "sid");
    ptvcursor_add(cursor, hf_skinny_DeviceName, 16, ENC_ASCII);
    ptvcursor_add(cursor, hf_skinny_reserved_for_future_use, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_add(cursor, hf_skinny_instance, 4, ENC_LITTLE_ENDIAN);
    ptvcursor_pop_subtree(cursor);
  }
  ptvcursor_add(cursor, hf_skinny_stationIpAddr, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_deviceType, 4, ENC_LITTLE_ENDIAN);
  ptvcursor_add(cursor, hf_skinny_maxStreams, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_request(cursor, pinfo, skinny_conv, 0x8000);
}

/*
 * Message:   SPCPRegisterTokenAck
 * Opcode:    0x8100
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SPCPRegisterTokenAck(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_features, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x8000);
}

/*
 * Message:   SPCPRegisterTokenReject
 * Opcode:    0x8101
 * Type:      RegistrationAndManagement
 * Direction: pbx2dev
 * VarLength: no
 * MsgType:   response
 */
static void
handle_SPCPRegisterTokenReject(ptvcursor_t *cursor, packet_info * pinfo _U_, skinny_conv_info_t * skinny_conv _U_)
{
  ptvcursor_add(cursor, hf_skinny_waitTimeBeforeNextReq, 4, ENC_LITTLE_ENDIAN);
  skinny_reqrep_add_response(cursor, pinfo, skinny_conv, 0x8000);
}


typedef void (*message_handler) (ptvcursor_t * cursor, packet_info *pinfo, skinny_conv_info_t * skinny_conv);

typedef struct _skinny_opcode_map_t {
  uint32_t opcode;
  message_handler handler;
  skinny_message_type_t type;
  const char *name;
} skinny_opcode_map_t;

/* Messages Handler Array */
static const skinny_opcode_map_t skinny_opcode_map[] = {
  {0x0000, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "KeepAliveReqMessage"},
  {0x0001, handle_RegisterReqMessage                      , SKINNY_MSGTYPE_REQUEST  , "RegisterReqMessage"},
  {0x0002, handle_IpPortMessage                           , SKINNY_MSGTYPE_EVENT    , "IpPortMessage"},
  {0x0003, handle_KeypadButtonMessage                     , SKINNY_MSGTYPE_EVENT    , "KeypadButtonMessage"},
  {0x0004, handle_EnblocCallMessage                       , SKINNY_MSGTYPE_EVENT    , "EnblocCallMessage"},
  {0x0005, handle_StimulusMessage                         , SKINNY_MSGTYPE_EVENT    , "StimulusMessage"},
  {0x0006, handle_OffHookMessage                          , SKINNY_MSGTYPE_EVENT    , "OffHookMessage"},
  {0x0007, handle_OnHookMessage                           , SKINNY_MSGTYPE_EVENT    , "OnHookMessage"},
  {0x0008, handle_HookFlashMessage                        , SKINNY_MSGTYPE_EVENT    , "HookFlashMessage"},
  {0x0009, handle_ForwardStatReqMessage                   , SKINNY_MSGTYPE_REQUEST  , "ForwardStatReqMessage"},
  {0x000a, handle_SpeedDialStatReqMessage                 , SKINNY_MSGTYPE_REQUEST  , "SpeedDialStatReqMessage"},
  {0x000b, handle_LineStatReqMessage                      , SKINNY_MSGTYPE_REQUEST  , "LineStatReqMessage"},
  {0x000c, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "ConfigStatReqMessage"},
  {0x000d, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "TimeDateReqMessage"},
  {0x000e, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "ButtonTemplateReqMessage"},
  {0x000f, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "VersionReqMessage"},
  {0x0010, handle_CapabilitiesResMessage                  , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesResMessage"},
  {0x0012, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "ServerReqMessage"},
  {0x0020, handle_AlarmMessage                            , SKINNY_MSGTYPE_EVENT    , "AlarmMessage"},
  {0x0021, handle_MulticastMediaReceptionAckMessage       , SKINNY_MSGTYPE_RESPONSE , "MulticastMediaReceptionAckMessage"},
  {0x0022, handle_OpenReceiveChannelAckMessage            , SKINNY_MSGTYPE_RESPONSE , "OpenReceiveChannelAckMessage"},
  {0x0023, handle_ConnectionStatisticsResMessage          , SKINNY_MSGTYPE_RESPONSE , "ConnectionStatisticsResMessage"},
  {0x0024, handle_OffHookWithCallingPartyNumberMessage    , SKINNY_MSGTYPE_EVENT    , "OffHookWithCallingPartyNumberMessage"},
  {0x0025, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "SoftKeySetReqMessage"},
  {0x0026, handle_SoftKeyEventMessage                     , SKINNY_MSGTYPE_EVENT    , "SoftKeyEventMessage"},
  {0x0027, handle_UnregisterReqMessage                    , SKINNY_MSGTYPE_REQUEST  , "UnregisterReqMessage"},
  {0x0028, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "SoftKeyTemplateReqMessage"},
  {0x0029, handle_RegisterTokenReq                        , SKINNY_MSGTYPE_REQUEST  , "RegisterTokenReq"},
  {0x002a, handle_MediaTransmissionFailureMessage         , SKINNY_MSGTYPE_RESPONSE , "MediaTransmissionFailureMessage"},
  {0x002b, handle_HeadsetStatusMessage                    , SKINNY_MSGTYPE_EVENT    , "HeadsetStatusMessage"},
  {0x002c, handle_MediaResourceNotificationMessage        , SKINNY_MSGTYPE_EVENT    , "MediaResourceNotificationMessage"},
  {0x002d, handle_RegisterAvailableLinesMessage           , SKINNY_MSGTYPE_EVENT    , "RegisterAvailableLinesMessage"},
  {0x002e, handle_DeviceToUserDataMessage                 , SKINNY_MSGTYPE_REQUEST  , "DeviceToUserDataMessage"},
  {0x002f, handle_DeviceToUserDataResponseMessage         , SKINNY_MSGTYPE_RESPONSE , "DeviceToUserDataResponseMessage"},
  {0x0030, handle_UpdateCapabilitiesMessage               , SKINNY_MSGTYPE_EVENT    , "UpdateCapabilitiesMessage"},
  {0x0031, handle_OpenMultiMediaReceiveChannelAckMessage  , SKINNY_MSGTYPE_RESPONSE , "OpenMultiMediaReceiveChannelAckMessage"},
  {0x0032, handle_ClearConferenceMessage                  , SKINNY_MSGTYPE_EVENT    , "ClearConferenceMessage"},
  {0x0033, handle_ServiceURLStatReqMessage                , SKINNY_MSGTYPE_REQUEST  , "ServiceURLStatReqMessage"},
  {0x0034, handle_FeatureStatReqMessage                   , SKINNY_MSGTYPE_REQUEST  , "FeatureStatReqMessage"},
  {0x0035, handle_CreateConferenceResMessage              , SKINNY_MSGTYPE_RESPONSE , "CreateConferenceResMessage"},
  {0x0036, handle_DeleteConferenceResMessage              , SKINNY_MSGTYPE_RESPONSE , "DeleteConferenceResMessage"},
  {0x0037, handle_ModifyConferenceResMessage              , SKINNY_MSGTYPE_RESPONSE , "ModifyConferenceResMessage"},
  {0x0038, handle_AddParticipantResMessage                , SKINNY_MSGTYPE_RESPONSE , "AddParticipantResMessage"},
  {0x0039, handle_AuditConferenceResMessage               , SKINNY_MSGTYPE_RESPONSE , "AuditConferenceResMessage"},
  {0x0040, handle_AuditParticipantResMessage              , SKINNY_MSGTYPE_RESPONSE , "AuditParticipantResMessage"},
  {0x0041, handle_DeviceToUserDataMessageVersion1         , SKINNY_MSGTYPE_REQUEST  , "DeviceToUserDataMessageVersion1"},
  {0x0042, handle_DeviceToUserDataResponseMessageVersion1 , SKINNY_MSGTYPE_RESPONSE , "DeviceToUserDataResponseMessageVersion1"},
  {0x0043, handle_CapabilitiesV2ResMessage                , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesV2ResMessage"},
  {0x0044, handle_CapabilitiesV3ResMessage                , SKINNY_MSGTYPE_RESPONSE , "CapabilitiesV3ResMessage"},
  {0x0045, handle_PortResMessage                          , SKINNY_MSGTYPE_RESPONSE , "PortResMessage"},
  {0x0046, handle_QoSResvNotifyMessage                    , SKINNY_MSGTYPE_EVENT    , "QoSResvNotifyMessage"},
  {0x0047, handle_QoSErrorNotifyMessage                   , SKINNY_MSGTYPE_EVENT    , "QoSErrorNotifyMessage"},
  {0x0048, handle_SubscriptionStatReqMessage              , SKINNY_MSGTYPE_REQUEST  , "SubscriptionStatReqMessage"},
  {0x0049, handle_MediaPathEventMessage                   , SKINNY_MSGTYPE_EVENT    , "MediaPathEventMessage"},
  {0x004a, handle_MediaPathCapabilityMessage              , SKINNY_MSGTYPE_EVENT    , "MediaPathCapabilityMessage"},
  {0x004c, handle_MwiNotificationMessage                  , SKINNY_MSGTYPE_REQUEST  , "MwiNotificationMessage"},
  {0x0081, handle_RegisterAckMessage                      , SKINNY_MSGTYPE_RESPONSE , "RegisterAckMessage"},
  {0x0082, handle_StartToneMessage                        , SKINNY_MSGTYPE_EVENT    , "StartToneMessage"},
  {0x0083, handle_StopToneMessage                         , SKINNY_MSGTYPE_EVENT    , "StopToneMessage"},
  {0x0085, handle_SetRingerMessage                        , SKINNY_MSGTYPE_EVENT    , "SetRingerMessage"},
  {0x0086, handle_SetLampMessage                          , SKINNY_MSGTYPE_EVENT    , "SetLampMessage"},
  {0x0087, NULL                                           , SKINNY_MSGTYPE_EVENT    , "SetHookFlashDetectMessage"},
  {0x0088, handle_SetSpeakerModeMessage                   , SKINNY_MSGTYPE_EVENT    , "SetSpeakerModeMessage"},
  {0x0089, handle_SetMicroModeMessage                     , SKINNY_MSGTYPE_EVENT    , "SetMicroModeMessage"},
  {0x008a, handle_StartMediaTransmissionMessage           , SKINNY_MSGTYPE_REQUEST  , "StartMediaTransmissionMessage"},
  {0x008b, handle_StopMediaTransmissionMessage            , SKINNY_MSGTYPE_EVENT    , "StopMediaTransmissionMessage"},
  {0x008f, handle_CallInfoMessage                         , SKINNY_MSGTYPE_EVENT    , "CallInfoMessage"},
  {0x0090, handle_ForwardStatResMessage                   , SKINNY_MSGTYPE_RESPONSE , "ForwardStatResMessage"},
  {0x0091, handle_SpeedDialStatResMessage                 , SKINNY_MSGTYPE_RESPONSE , "SpeedDialStatResMessage"},
  {0x0092, handle_LineStatResMessage                      , SKINNY_MSGTYPE_RESPONSE , "LineStatResMessage"},
  {0x0093, handle_ConfigStatResMessage                    , SKINNY_MSGTYPE_RESPONSE , "ConfigStatResMessage"},
  {0x0094, handle_TimeDateResMessage                      , SKINNY_MSGTYPE_RESPONSE , "TimeDateResMessage"},
  {0x0095, handle_StartSessionTransmissionMessage         , SKINNY_MSGTYPE_EVENT    , "StartSessionTransmissionMessage"},
  {0x0096, handle_StopSessionTransmissionMessage          , SKINNY_MSGTYPE_EVENT    , "StopSessionTransmissionMessage"},
  {0x0097, handle_ButtonTemplateResMessage                , SKINNY_MSGTYPE_RESPONSE , "ButtonTemplateResMessage"},
  {0x0098, handle_VersionResMessage                       , SKINNY_MSGTYPE_RESPONSE , "VersionResMessage"},
  {0x0099, handle_DisplayTextMessage                      , SKINNY_MSGTYPE_EVENT    , "DisplayTextMessage"},
  {0x009a, NULL                                           , SKINNY_MSGTYPE_EVENT    , "ClearDisplay"},
  {0x009b, NULL                                           , SKINNY_MSGTYPE_EVENT    , "CapabilitiesReq"},
  {0x009d, handle_RegisterRejectMessage                   , SKINNY_MSGTYPE_EVENT    , "RegisterRejectMessage"},
  {0x009e, handle_ServerResMessage                        , SKINNY_MSGTYPE_RESPONSE , "ServerResMessage"},
  {0x009f, handle_Reset                                   , SKINNY_MSGTYPE_EVENT    , "Reset"},
  {0x0100, NULL                                           , SKINNY_MSGTYPE_RESPONSE , "KeepAliveAckMessage"},
  {0x0101, handle_StartMulticastMediaReceptionMessage     , SKINNY_MSGTYPE_REQUEST  , "StartMulticastMediaReceptionMessage"},
  {0x0102, handle_StartMulticastMediaTransmissionMessage  , SKINNY_MSGTYPE_REQUEST  , "StartMulticastMediaTransmissionMessage"},
  {0x0103, handle_StopMulticastMediaReceptionMessage      , SKINNY_MSGTYPE_EVENT    , "StopMulticastMediaReceptionMessage"},
  {0x0104, handle_StopMulticastMediaTransmissionMessage   , SKINNY_MSGTYPE_EVENT    , "StopMulticastMediaTransmissionMessage"},
  {0x0105, handle_OpenReceiveChannelMessage               , SKINNY_MSGTYPE_REQUEST  , "OpenReceiveChannelMessage"},
  {0x0106, handle_CloseReceiveChannelMessage              , SKINNY_MSGTYPE_EVENT    , "CloseReceiveChannelMessage"},
  {0x0107, handle_ConnectionStatisticsReqMessage          , SKINNY_MSGTYPE_REQUEST  , "ConnectionStatisticsReqMessage"},
  {0x0108, handle_SoftKeyTemplateResMessage               , SKINNY_MSGTYPE_RESPONSE , "SoftKeyTemplateResMessage"},
  {0x0109, handle_SoftKeySetResMessage                    , SKINNY_MSGTYPE_RESPONSE , "SoftKeySetResMessage"},
  {0x0110, handle_SelectSoftKeysMessage                   , SKINNY_MSGTYPE_EVENT    , "SelectSoftKeysMessage"},
  {0x0111, handle_CallStateMessage                        , SKINNY_MSGTYPE_EVENT    , "CallStateMessage"},
  {0x0112, handle_DisplayPromptStatusMessage              , SKINNY_MSGTYPE_EVENT    , "DisplayPromptStatusMessage"},
  {0x0113, handle_ClearPromptStatusMessage                , SKINNY_MSGTYPE_EVENT    , "ClearPromptStatusMessage"},
  {0x0114, handle_DisplayNotifyMessage                    , SKINNY_MSGTYPE_EVENT    , "DisplayNotifyMessage"},
  {0x0115, NULL                                           , SKINNY_MSGTYPE_EVENT    , "ClearNotifyMessage"},
  {0x0116, handle_ActivateCallPlaneMessage                , SKINNY_MSGTYPE_EVENT    , "ActivateCallPlaneMessage"},
  {0x0117, NULL                                           , SKINNY_MSGTYPE_EVENT    , "DeactivateCallPlaneMessage"},
  {0x0118, handle_UnregisterAckMessage                    , SKINNY_MSGTYPE_RESPONSE , "UnregisterAckMessage"},
  {0x0119, handle_BackSpaceResMessage                     , SKINNY_MSGTYPE_EVENT    , "BackSpaceResMessage"},
  {0x011a, NULL                                           , SKINNY_MSGTYPE_RESPONSE , "RegisterTokenAck"},
  {0x011b, handle_RegisterTokenReject                     , SKINNY_MSGTYPE_RESPONSE , "RegisterTokenReject"},
  {0x011c, handle_StartMediaFailureDetectionMessage       , SKINNY_MSGTYPE_EVENT    , "StartMediaFailureDetectionMessage"},
  {0x011d, handle_DialedNumberMessage                     , SKINNY_MSGTYPE_EVENT    , "DialedNumberMessage"},
  {0x011e, handle_UserToDeviceDataMessage                 , SKINNY_MSGTYPE_EVENT    , "UserToDeviceDataMessage"},
  {0x011f, handle_FeatureStatResMessage                   , SKINNY_MSGTYPE_RESPONSE , "FeatureStatResMessage"},
  {0x0120, handle_DisplayPriNotifyMessage                 , SKINNY_MSGTYPE_EVENT    , "DisplayPriNotifyMessage"},
  {0x0121, handle_ClearPriNotifyMessage                   , SKINNY_MSGTYPE_EVENT    , "ClearPriNotifyMessage"},
  {0x0122, handle_StartAnnouncementMessage                , SKINNY_MSGTYPE_EVENT    , "StartAnnouncementMessage"},
  {0x0123, handle_StopAnnouncementMessage                 , SKINNY_MSGTYPE_EVENT    , "StopAnnouncementMessage"},
  {0x0124, handle_AnnouncementFinishMessage               , SKINNY_MSGTYPE_EVENT    , "AnnouncementFinishMessage"},
  {0x0127, handle_NotifyDtmfToneMessage                   , SKINNY_MSGTYPE_EVENT    , "NotifyDtmfToneMessage"},
  {0x0128, handle_SendDtmfToneMessage                     , SKINNY_MSGTYPE_EVENT    , "SendDtmfToneMessage"},
  {0x0129, handle_SubscribeDtmfPayloadReqMessage          , SKINNY_MSGTYPE_REQUEST  , "SubscribeDtmfPayloadReqMessage"},
  {0x012a, handle_SubscribeDtmfPayloadResMessage          , SKINNY_MSGTYPE_RESPONSE , "SubscribeDtmfPayloadResMessage"},
  {0x012b, handle_SubscribeDtmfPayloadErrMessage          , SKINNY_MSGTYPE_RESPONSE , "SubscribeDtmfPayloadErrMessage"},
  {0x012c, handle_UnSubscribeDtmfPayloadReqMessage        , SKINNY_MSGTYPE_REQUEST  , "UnSubscribeDtmfPayloadReqMessage"},
  {0x012d, handle_UnSubscribeDtmfPayloadResMessage        , SKINNY_MSGTYPE_RESPONSE , "UnSubscribeDtmfPayloadResMessage"},
  {0x012e, handle_UnSubscribeDtmfPayloadErrMessage        , SKINNY_MSGTYPE_RESPONSE , "UnSubscribeDtmfPayloadErrMessage"},
  {0x012f, handle_ServiceURLStatResMessage                , SKINNY_MSGTYPE_RESPONSE , "ServiceURLStatResMessage"},
  {0x0130, handle_CallSelectStatResMessage                , SKINNY_MSGTYPE_EVENT    , "CallSelectStatResMessage"},
  {0x0131, handle_OpenMultiMediaReceiveChannelMessage     , SKINNY_MSGTYPE_REQUEST  , "OpenMultiMediaReceiveChannelMessage"},
  {0x0132, handle_StartMultiMediaTransmissionMessage      , SKINNY_MSGTYPE_REQUEST  , "StartMultiMediaTransmissionMessage"},
  {0x0133, handle_StopMultiMediaTransmissionMessage       , SKINNY_MSGTYPE_EVENT    , "StopMultiMediaTransmissionMessage"},
  {0x0134, handle_MiscellaneousCommandMessage             , SKINNY_MSGTYPE_EVENT    , "MiscellaneousCommandMessage"},
  {0x0135, handle_FlowControlCommandMessage               , SKINNY_MSGTYPE_EVENT    , "FlowControlCommandMessage"},
  {0x0136, handle_CloseMultiMediaReceiveChannelMessage    , SKINNY_MSGTYPE_EVENT    , "CloseMultiMediaReceiveChannelMessage"},
  {0x0137, handle_CreateConferenceReqMessage              , SKINNY_MSGTYPE_REQUEST  , "CreateConferenceReqMessage"},
  {0x0138, handle_DeleteConferenceReqMessage              , SKINNY_MSGTYPE_REQUEST  , "DeleteConferenceReqMessage"},
  {0x0139, handle_ModifyConferenceReqMessage              , SKINNY_MSGTYPE_REQUEST  , "ModifyConferenceReqMessage"},
  {0x013a, handle_AddParticipantReqMessage                , SKINNY_MSGTYPE_REQUEST  , "AddParticipantReqMessage"},
  {0x013b, handle_DropParticipantReqMessage               , SKINNY_MSGTYPE_REQUEST  , "DropParticipantReqMessage"},
  {0x013c, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "AuditConferenceReqMessage"},
  {0x013d, handle_AuditParticipantReqMessage              , SKINNY_MSGTYPE_REQUEST  , "AuditParticipantReqMessage"},
  {0x013e, handle_ChangeParticipantReqMessage             , SKINNY_MSGTYPE_REQUEST  , "ChangeParticipantReqMessage"},
  {0x013f, handle_UserToDeviceDataMessageVersion1         , SKINNY_MSGTYPE_EVENT    , "UserToDeviceDataMessageVersion1"},
  {0x0140, handle_VideoDisplayCommandMessage              , SKINNY_MSGTYPE_EVENT    , "VideoDisplayCommandMessage"},
  {0x0141, handle_FlowControlNotifyMessage                , SKINNY_MSGTYPE_EVENT    , "FlowControlNotifyMessage"},
  {0x0142, handle_ConfigStatV2ResMessage                  , SKINNY_MSGTYPE_RESPONSE , "ConfigStatV2ResMessage"},
  {0x0143, handle_DisplayNotifyV2Message                  , SKINNY_MSGTYPE_EVENT    , "DisplayNotifyV2Message"},
  {0x0144, handle_DisplayPriNotifyV2Message               , SKINNY_MSGTYPE_EVENT    , "DisplayPriNotifyV2Message"},
  {0x0145, handle_DisplayPromptStatusV2Message            , SKINNY_MSGTYPE_EVENT    , "DisplayPromptStatusV2Message"},
  {0x0146, handle_FeatureStatV2ResMessage                 , SKINNY_MSGTYPE_RESPONSE , "FeatureStatV2ResMessage"},
  {0x0147, handle_LineStatV2ResMessage                    , SKINNY_MSGTYPE_RESPONSE , "LineStatV2ResMessage"},
  {0x0148, handle_ServiceURLStatV2ResMessage              , SKINNY_MSGTYPE_RESPONSE , "ServiceURLStatV2ResMessage"},
  {0x0149, handle_SpeedDialStatV2ResMessage               , SKINNY_MSGTYPE_RESPONSE , "SpeedDialStatV2ResMessage"},
  {0x014a, handle_CallInfoV2Message                       , SKINNY_MSGTYPE_EVENT    , "CallInfoV2Message"},
  {0x014b, handle_PortReqMessage                          , SKINNY_MSGTYPE_REQUEST  , "PortReqMessage"},
  {0x014c, handle_PortCloseMessage                        , SKINNY_MSGTYPE_EVENT    , "PortCloseMessage"},
  {0x014d, handle_QoSListenMessage                        , SKINNY_MSGTYPE_EVENT    , "QoSListenMessage"},
  {0x014e, handle_QoSPathMessage                          , SKINNY_MSGTYPE_EVENT    , "QoSPathMessage"},
  {0x014f, handle_QoSTeardownMessage                      , SKINNY_MSGTYPE_EVENT    , "QoSTeardownMessage"},
  {0x0150, handle_UpdateDSCPMessage                       , SKINNY_MSGTYPE_EVENT    , "UpdateDSCPMessage"},
  {0x0151, handle_QoSModifyMessage                        , SKINNY_MSGTYPE_EVENT    , "QoSModifyMessage"},
  {0x0152, handle_SubscriptionStatResMessage              , SKINNY_MSGTYPE_RESPONSE , "SubscriptionStatResMessage"},
  {0x0153, handle_NotificationMessage                     , SKINNY_MSGTYPE_EVENT    , "NotificationMessage"},
  {0x0154, handle_StartMediaTransmissionAckMessage        , SKINNY_MSGTYPE_RESPONSE , "StartMediaTransmissionAckMessage"},
  {0x0155, handle_StartMultiMediaTransmissionAckMessage   , SKINNY_MSGTYPE_RESPONSE , "StartMultiMediaTransmissionAckMessage"},
  {0x0156, handle_CallHistoryInfoMessage                  , SKINNY_MSGTYPE_EVENT    , "CallHistoryInfoMessage"},
  {0x0157, handle_LocationInfoMessage                     , SKINNY_MSGTYPE_EVENT    , "LocationInfoMessage"},
  {0x0158, handle_MwiResMessage                           , SKINNY_MSGTYPE_RESPONSE , "MwiResMessage"},
  {0x0159, handle_AddOnDeviceCapabilitiesMessage          , SKINNY_MSGTYPE_EVENT    , "AddOnDeviceCapabilitiesMessage"},
  {0x015a, handle_EnhancedAlarmMessage                    , SKINNY_MSGTYPE_EVENT    , "EnhancedAlarmMessage"},
  {0x015e, NULL                                           , SKINNY_MSGTYPE_REQUEST  , "CallCountReqMessage"},
  {0x015f, handle_CallCountRespMessage                    , SKINNY_MSGTYPE_RESPONSE , "CallCountRespMessage"},
  {0x0160, handle_RecordingStatusMessage                  , SKINNY_MSGTYPE_EVENT    , "RecordingStatusMessage"},
  {0x8000, handle_SPCPRegisterTokenReq                    , SKINNY_MSGTYPE_REQUEST  , "SPCPRegisterTokenReq"},
  {0x8100, handle_SPCPRegisterTokenAck                    , SKINNY_MSGTYPE_RESPONSE , "SPCPRegisterTokenAck"},
  {0x8101, handle_SPCPRegisterTokenReject                 , SKINNY_MSGTYPE_RESPONSE , "SPCPRegisterTokenReject"},
};

/* Dissect a single SKINNY PDU */
static int dissect_skinny_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  unsigned offset   = 0;
  /*bool is_video = false;*/    /* FIX ME: need to indicate video or not */
  ptvcursor_t* cursor;
  conversation_t *conversation;
  skinny_conv_info_t *skinny_conv;
  const skinny_opcode_map_t *opcode_entry = NULL;

  /* Header fields */
  uint32_t hdr_data_length;
  uint32_t hdr_version;
  uint32_t hdr_opcode;

  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_tree *skinny_tree = NULL;
  proto_item *ti = NULL;

  /* Initialization */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_version     = tvb_get_letohl(tvb, 4);
  hdr_opcode      = tvb_get_letohl(tvb, 8);

  for (size_t i = 0; i < array_length(skinny_opcode_map); i++) {
    if (skinny_opcode_map[i].opcode == hdr_opcode) {
      opcode_entry = &skinny_opcode_map[i];
    }
  }

  conversation = find_or_create_conversation(pinfo);
  skinny_conv = (skinny_conv_info_t *)conversation_get_proto_data(conversation, proto_skinny);
  if (!skinny_conv) {
    skinny_conv = wmem_new0(wmem_file_scope(), skinny_conv_info_t);
    //skinny_conv->pending_req_resp = wmem_map_new(wmem_file_scope(), wmem_str_hash, g_str_equal);
    skinny_conv->pending_req_resp = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    skinny_conv->requests = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    skinny_conv->responses = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    skinny_conv->lineId = -1;
    skinny_conv->mtype = SKINNY_MSGTYPE_EVENT;
    conversation_add_proto_data(conversation, proto_skinny, skinny_conv);
  }

  /* Initialise stat info for passing to tap */
  /* WIP: will be (partially) replaced in favor of conversionation, dependents: ui/voip_calls.c */
  pi_current++;
  if (pi_current == MAX_SKINNY_MESSAGES_IN_PACKET)
  {
    /* Overwrite info in first struct if run out of space... */
    pi_current = 0;
  }
  si = &pi_arr[pi_current];
  si->messId = hdr_opcode;
  si->messageName = val_to_str_ext(hdr_opcode, &message_id_ext, "0x%08X (Unknown)");
  si->callId = 0;
  si->lineId = 0;
  si->passThroughPartyId = 0;
  si->callState = 0;
  g_free(si->callingParty);
  si->callingParty = NULL;
  g_free(si->calledParty);
  si->calledParty = NULL;
  si->mediaReceptionStatus = -1;
  si->mediaTransmissionStatus = -1;
  si->multimediaReceptionStatus = -1;
  si->multimediaTransmissionStatus = -1;
  si->multicastReceptionStatus = -1;
  g_free(si->additionalInfo);
  si->additionalInfo = NULL;

  col_add_fstr(pinfo->cinfo, COL_INFO,"%s ", si->messageName);
  col_set_fence(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_skinny, tvb, offset, hdr_data_length+8, ENC_NA);
    skinny_tree = proto_item_add_subtree(ti, ett_skinny);
  }

  if (opcode_entry && opcode_entry->type != SKINNY_MSGTYPE_EVENT) {
    skinny_conv->mtype = opcode_entry->type;
    if (opcode_entry->type == SKINNY_MSGTYPE_REQUEST) {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY/REQ");
    } else {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY/RESP");
    }
  }

  if (skinny_tree) {
    proto_tree_add_uint(skinny_tree, hf_skinny_data_length, tvb, offset  , 4, hdr_data_length);
    proto_tree_add_uint(skinny_tree, hf_skinny_hdr_version, tvb, offset+4, 4, hdr_version);
    proto_tree_add_uint(skinny_tree, hf_skinny_messageId,   tvb, offset+8, 4, hdr_opcode );
  }
  offset += 12;

  cursor = ptvcursor_new(pinfo->pool, skinny_tree, tvb, offset);
  if (opcode_entry && opcode_entry->handler) {
    opcode_entry->handler(cursor, pinfo, skinny_conv);
  }
  ptvcursor_free(cursor);

  tap_queue_packet(skinny_tap, pinfo, si);

  return tvb_captured_length(tvb);
}

/* Code to actually dissect the packets */
static int
dissect_skinny(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  /* The general structure of a packet: {IP-Header|TCP-Header|n*SKINNY}
   * SKINNY-Packet: {Header(Size, Reserved)|Data(MessageID, Message-Data)}
   */
  /* Header fields */
  uint32_t hdr_data_length;
  uint32_t hdr_version;

  /* check, if this is really an SKINNY packet, they start with a length + 0 */

  if (tvb_captured_length(tvb) < 8)
  {
    return 0;
  }
  /* get relevant header information */
  hdr_data_length = tvb_get_letohl(tvb, 0);
  hdr_version     = tvb_get_letohl(tvb, 4);

  /*  data_size       = MIN(8+hdr_data_length, tvb_length(tvb)) - 0xC; */

  if (
      (hdr_data_length < 4) ||
      ((hdr_version != BASIC_MSG_TYPE) &&
       (hdr_version != V10_MSG_TYPE) &&
       (hdr_version != V11_MSG_TYPE) &&
       (hdr_version != V15_MSG_TYPE) &&
       (hdr_version != V16_MSG_TYPE) &&
       (hdr_version != V17_MSG_TYPE) &&
       (hdr_version != V18_MSG_TYPE) &&
       (hdr_version != V19_MSG_TYPE) &&
       (hdr_version != V20_MSG_TYPE) &&
       (hdr_version != V21_MSG_TYPE) &&
       (hdr_version != V22_MSG_TYPE))
     )
  {
      /* Not an SKINNY packet, just happened to use the same port */
      return 0;
  }

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SKINNY");

  col_set_str(pinfo->cinfo, COL_INFO, "Skinny Client Control Protocol");

  tcp_dissect_pdus(tvb, pinfo, tree, global_skinny_desegment, 4, get_skinny_pdu_len, dissect_skinny_pdu, data);

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_skinny(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_skinny_data_length,
      {
        "Data length", "skinny.data_length", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of bytes in the data portion.", HFILL }},
    { &hf_skinny_hdr_version,
      {
        "Header version", "skinny.hdr_version", FT_UINT32, BASE_HEX, VALS(header_version), 0x0,
        NULL, HFILL }},
    { &hf_skinny_messageId,
      {
        "Message ID", "skinny.messageId", FT_UINT32, BASE_DEC|BASE_EXT_STRING, &message_id_ext, 0x0,
        NULL, HFILL }},
    { &hf_skinny_xmlData,
      {
        "XML data", "skinny.xmlData", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL,  HFILL }},
    { &hf_skinny_ipv4or6,
      {
        "IPv4or6", "skinny.ipv4or6", FT_UINT32, BASE_DEC|BASE_EXT_STRING, &IpAddrType_ext, 0x0,
        NULL, HFILL }},
    { &hf_skinny_response_in,
      {
        "Response In", "skinny.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "The response to this SKINNY request is in this frame", HFILL }},
    { &hf_skinny_response_to,
      {
        "Request In", "skinny.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
        "This is a response to the SKINNY request in this frame", HFILL }},
    { &hf_skinny_response_time,
      {
        "Response Time", "skinny.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "The time between the Call and the Reply", HFILL }},
    { &hf_skinny_CallingPartyName,
      {
        "CallingName", "skinny.CallingPartyName", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
        NULL, HFILL }},
    { &hf_skinny_CallingPartyNumber,
      {
        "CallingNum", "skinny.CallingPartyNumber", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
        NULL, HFILL }},
    { &hf_skinny_DSCPValue,
      {
        "DSCPValue", "skinny.DSCPValue", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_FutureUse1,
      {
        "FutureUse1", "skinny.FutureUse1", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_FutureUse2,
      {
        "FutureUse2", "skinny.FutureUse2", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_FutureUse3,
      {
        "FutureUse3", "skinny.FutureUse3", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit1,
      {
        "Bit1", "skinny.Generic.Bitfield.Bit1", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit10,
      {
        "Bit10", "skinny.Generic.Bitfield.Bit10", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000200,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit11,
      {
        "Bit11", "skinny.Generic.Bitfield.Bit11", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000400,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit12,
      {
        "Bit12", "skinny.Generic.Bitfield.Bit12", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000800,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit13,
      {
        "Bit13", "skinny.Generic.Bitfield.Bit13", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00001000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit14,
      {
        "Bit14", "skinny.Generic.Bitfield.Bit14", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00002000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit15,
      {
        "Bit15", "skinny.Generic.Bitfield.Bit15", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00004000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit16,
      {
        "Bit16", "skinny.Generic.Bitfield.Bit16", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00008000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit17,
      {
        "Bit17", "skinny.Generic.Bitfield.Bit17", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00010000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit18,
      {
        "Bit18", "skinny.Generic.Bitfield.Bit18", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00020000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit19,
      {
        "Bit19", "skinny.Generic.Bitfield.Bit19", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00040000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit2,
      {
        "Bit2", "skinny.Generic.Bitfield.Bit2", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit20,
      {
        "Bit20", "skinny.Generic.Bitfield.Bit20", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00080000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit21,
      {
        "Bit21", "skinny.Generic.Bitfield.Bit21", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00100000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit22,
      {
        "Bit22", "skinny.Generic.Bitfield.Bit22", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00200000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit23,
      {
        "Bit23", "skinny.Generic.Bitfield.Bit23", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00400000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit24,
      {
        "Bit24", "skinny.Generic.Bitfield.Bit24", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00800000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit25,
      {
        "Bit25", "skinny.Generic.Bitfield.Bit25", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x01000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit26,
      {
        "Bit26", "skinny.Generic.Bitfield.Bit26", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x02000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit27,
      {
        "Bit27", "skinny.Generic.Bitfield.Bit27", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x04000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit28,
      {
        "Bit28", "skinny.Generic.Bitfield.Bit28", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x08000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit29,
      {
        "Bit29", "skinny.Generic.Bitfield.Bit29", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x10000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit3,
      {
        "Bit3", "skinny.Generic.Bitfield.Bit3", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit30,
      {
        "Bit30", "skinny.Generic.Bitfield.Bit30", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x20000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit31,
      {
        "Bit31", "skinny.Generic.Bitfield.Bit31", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x40000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit32,
      {
        "Bit32", "skinny.Generic.Bitfield.Bit32", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x80000000,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit4,
      {
        "Bit4", "skinny.Generic.Bitfield.Bit4", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit5,
      {
        "Bit5", "skinny.Generic.Bitfield.Bit5", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit6,
      {
        "Bit6", "skinny.Generic.Bitfield.Bit6", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit7,
      {
        "Bit7", "skinny.Generic.Bitfield.Bit7", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit8,
      {
        "Bit8", "skinny.Generic.Bitfield.Bit8", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000080,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_Generic_Bitfield_Bit9,
      {
        "Bit9", "skinny.Generic.Bitfield.Bit9", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000100,
        "H263 Capability BitField", HFILL }},
    { &hf_skinny_MPI,
      {
        "MPI", "skinny.MPI", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_OrigDialed,
      {
        "Originally Dialed", "skinny.OrigDialed", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
        NULL, HFILL }},
    { &hf_skinny_PhoneFeatures_Abbreviated_Dial,
      {
        "AbbrevDial", "skinny.PhoneFeatures.Abbreviated.Dial", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit1,
      {
        "Bit1", "skinny.PhoneFeatures.Bit1", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit11,
      {
        "Bit11", "skinny.PhoneFeatures.Bit11", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit12,
      {
        "Bit12", "skinny.PhoneFeatures.Bit12", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit13,
      {
        "Bit13", "skinny.PhoneFeatures.Bit13", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit14,
      {
        "Bit14", "skinny.PhoneFeatures.Bit14", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit15,
      {
        "Bit15", "skinny.PhoneFeatures.Bit15", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit2,
      {
        "Bit2", "skinny.PhoneFeatures.Bit2", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit3,
      {
        "Bit3", "skinny.PhoneFeatures.Bit3", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit4,
      {
        "Bit4", "skinny.PhoneFeatures.Bit4", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit6,
      {
        "Bit6", "skinny.PhoneFeatures.Bit6", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit7,
      {
        "Bit7", "skinny.PhoneFeatures.Bit7", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_Bit9,
      {
        "Bit9", "skinny.PhoneFeatures.Bit9", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_DynamicMessages,
      {
        "DynamicMessages", "skinny.PhoneFeatures.DynamicMessages", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_RFC2833,
      {
        "RFC2833", "skinny.PhoneFeatures.RFC2833", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
        "Features this device supports", HFILL }},
    { &hf_skinny_PhoneFeatures_UTF8,
      {
        "UTF8Bit5", "skinny.PhoneFeatures.UTF8", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010,
        "Features this device supports", HFILL }},
    { &hf_skinny_RFC2833PayloadType,
      {
        "RFC2833PayloadType", "skinny.RFC2833PayloadType", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_RTCPPortNumber,
      {
        "RTCPPortNumber", "skinny.RTCPPortNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_RedirDialed,
      {
        "Redirected Dialed", "skinny.RedirDialed", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_BitsReserved,
      {
        "BitsReserved", "skinny.RestrictInformationType.BitsReserved", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0xffffff00,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CalledParty,
      {
        "CalledParty", "skinny.RestrictInformationType.CalledParty", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x0000000c,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CalledPartyName,
      {
        "CalledPartyName", "skinny.RestrictInformationType.CalledPartyName", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CalledPartyNumber,
      {
        "CalledPartyNumber", "skinny.RestrictInformationType.CalledPartyNumber", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CallingParty,
      {
        "CallingParty", "skinny.RestrictInformationType.CallingParty", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000003,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CallingPartyName,
      {
        "CallingPartyName", "skinny.RestrictInformationType.CallingPartyName", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_CallingPartyNumber,
      {
        "CallingPartyNumber", "skinny.RestrictInformationType.CallingPartyNumber", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_LastRedirectParty,
      {
        "LastRedirectParty", "skinny.RestrictInformationType.LastRedirectParty", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x000000c0,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_LastRedirectPartyName,
      {
        "LastRedirectPartyName", "skinny.RestrictInformationType.LastRedirectPartyName", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_LastRedirectPartyNumber,
      {
        "LastRedirectPartyNumber", "skinny.RestrictInformationType.LastRedirectPartyNumber", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000080,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_OriginalCalledParty,
      {
        "OriginalCalledParty", "skinny.RestrictInformationType.OriginalCalledParty", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000030,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_OriginalCalledPartyName,
      {
        "OriginalCalledPartyName", "skinny.RestrictInformationType.OriginalCalledPartyName", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
        NULL, HFILL }},
    { &hf_skinny_RestrictInformationType_OriginalCalledPartyNumber,
      {
        "OriginalCalledPartyNumber", "skinny.RestrictInformationType.OriginalCalledPartyNumber", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey1,
      {
        "SoftKey1", "skinny.SoftKeyMask.SoftKey1", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000001,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey10,
      {
        "SoftKey10", "skinny.SoftKeyMask.SoftKey10", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000200,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey11,
      {
        "SoftKey11", "skinny.SoftKeyMask.SoftKey11", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000400,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey12,
      {
        "SoftKey12", "skinny.SoftKeyMask.SoftKey12", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000800,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey13,
      {
        "SoftKey13", "skinny.SoftKeyMask.SoftKey13", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00001000,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey14,
      {
        "SoftKey14", "skinny.SoftKeyMask.SoftKey14", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00002000,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey15,
      {
        "SoftKey15", "skinny.SoftKeyMask.SoftKey15", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00004000,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey16,
      {
        "SoftKey16", "skinny.SoftKeyMask.SoftKey16", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00008000,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey2,
      {
        "SoftKey2", "skinny.SoftKeyMask.SoftKey2", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000002,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey3,
      {
        "SoftKey3", "skinny.SoftKeyMask.SoftKey3", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000004,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey4,
      {
        "SoftKey4", "skinny.SoftKeyMask.SoftKey4", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000008,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey5,
      {
        "SoftKey5", "skinny.SoftKeyMask.SoftKey5", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000010,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey6,
      {
        "SoftKey6", "skinny.SoftKeyMask.SoftKey6", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000020,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey7,
      {
        "SoftKey7", "skinny.SoftKeyMask.SoftKey7", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000040,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey8,
      {
        "SoftKey8", "skinny.SoftKeyMask.SoftKey8", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000080,
        NULL, HFILL }},
    { &hf_skinny_SoftKeyMask_SoftKey9,
      {
        "SoftKey9", "skinny.SoftKeyMask.SoftKey9", FT_BOOLEAN, 32, TFS(&tfs_yes_no), 0x00000100,
        NULL, HFILL }},
    { &hf_skinny_active,
      {
        "active", "skinny.active", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_activeConferenceOnRegistration,
      {
        "Active Conference", "skinny.activeConferenceOnRegistration", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Active conference at Registration", HFILL }},
    { &hf_skinny_activeConferences,
      {
        "Active Conferences", "skinny.activeConferences", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Active Conferences at Registration", HFILL }},
    { &hf_skinny_activeForward,
      {
        "activeForward", "skinny.activeForward", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_activeStreams,
      {
        "Active RTP Streams", "skinny.activeStreams", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Active RTP Streams at Registration", HFILL }},
    { &hf_skinny_activeStreamsOnRegistration,
      {
        "activeStreamsOnRegistration", "skinny.activeStreamsOnRegistration", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_alarmInfo,
      {
        "alarmInfo", "skinny.alarmInfo", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_alignmentPadding,
      {
        "alignmentPadding", "skinny.alignmentPadding", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_annexNandWFutureUse,
      {
        "annexNandWFutureUse", "skinny.annexNandWFutureUse", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_appInstanceID,
      {
        "appInstanceID", "skinny.appInstanceID", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_applicationId,
      {
        "applicationId", "skinny.applicationId", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_areMessagesWaiting,
      {
        "areMessagesWaiting", "skinny.areMessagesWaiting", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_associatedStreamId,
      {
        "associatedStreamId", "skinny.associatedStreamId", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_audioCapCount,
      {
        "audioCapCount", "skinny.audioCapCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_audioLevelAdjustment,
      {
        "audioLevelAdjustment", "skinny.audioLevelAdjustment", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_averageBitRate,
      {
        "averageBitRate", "skinny.averageBitRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_bandwidth,
      {
        "bandwidth", "skinny.bandwidth", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_bitRate,
      {
        "bitRate", "skinny.bitRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_burstSize,
      {
        "burstSize", "skinny.burstSize", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_busyTrigger,
      {
        "busyTrigger", "skinny.busyTrigger", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_buttonCount,
      {
        "buttonCount", "skinny.buttonCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_buttonOffset,
      {
        "buttonOffset", "skinny.buttonOffset", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_callInstance,
      {
        "callInstance", "skinny.callInstance", FT_UINT32, BASE_DEC, NULL, 0x0,
        "CallId", HFILL }},
    { &hf_skinny_callReference,
      {
        "callReference", "skinny.callReference", FT_UINT32, BASE_DEC, NULL, 0x0,
        "CallId", HFILL }},
    { &hf_skinny_callSelectStat,
      {
        "callSelectStat", "skinny.callSelectStat", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_capAndVer,
      {
        "capAndVer", "skinny.capAndVer", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_capCount,
      {
        "capCount", "skinny.capCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_chan0MaxPayload,
      {
        "chan0MaxPayload", "skinny.chan0MaxPayload", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_chan2MaxPayload,
      {
        "chan2MaxPayload", "skinny.chan2MaxPayload", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_chan2MaxWindow,
      {
        "chan2MaxWindow", "skinny.chan2MaxWindow", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_chan3MaxPayload,
      {
        "chan3MaxPayload", "skinny.chan3MaxPayload", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_clockConversionCode,
      {
        "clockConversionCode", "skinny.clockConversionCode", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_clockDivisor,
      {
        "clockDivisor", "skinny.clockDivisor", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_codecMode,
      {
        "codecMode", "skinny.codecMode", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_codecParam1,
      {
        "codecParam1", "skinny.codecParam1", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_codecParam2,
      {
        "codecParam2", "skinny.codecParam2", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_confServiceNum,
      {
        "confServiceNum", "skinny.confServiceNum", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_conferenceId,
      {
        "conferenceId", "skinny.conferenceId", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Conference ID", HFILL }},
    { &hf_skinny_confirmRequired,
      {
        "confirmRequired", "skinny.confirmRequired", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_country,
      {
        "country", "skinny.country", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_customMaxBRandCPB,
      {
        "customMaxBRandCPB", "skinny.customMaxBRandCPB", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_customMaxDPB,
      {
        "customMaxDPB", "skinny.customMaxDPB", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_customMaxFS,
      {
        "customMaxFS", "skinny.customMaxFS", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_customMaxMBPS,
      {
        "customMaxMBPS", "skinny.customMaxMBPS", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_customPictureFormatCount,
      {
        "customPictureFormatCount", "skinny.customPictureFormatCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_dataCapCount,
      {
        "dataCapCount", "skinny.dataCapCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_dataLength,
      {
        "dataLength", "skinny.dataLength", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_dataSize,
      {
        "dataSize", "skinny.dataSize", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Data Size", HFILL }},
    { &hf_skinny_defendingPriority,
      {
        "defendingPriority", "skinny.defendingPriority", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_displayPriority,
      {
        "displayPriority", "skinny.displayPriority", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_dtmfType,
      {
        "dtmfType", "skinny.dtmfType", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_dynamicPayload,
      {
        "dynamicPayload", "skinny.dynamicPayload", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_failureNodeIpAddr,
      {
        "failureNodeIpAddr", "skinny.failureNodeIpAddr", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_featureCapabilities,
      {
        "featureCapabilities", "skinny.featureCapabilities", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_featureIndex,
      {
        "featureIndex", "skinny.featureIndex", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_featureStatus,
      {
        "featureStatus", "skinny.featureStatus", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_features,
      {
        "features", "skinny.features", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_firstGOB,
      {
        "firstGOB", "skinny.firstGOB", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_firstMB,
      {
        "firstMB", "skinny.firstMB", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_format,
      {
        "format", "skinny.format", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_forwardAllActive,
      {
        "forwardAllActive", "skinny.forwardAllActive", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_forwardBusyActive,
      {
        "forwardBusyActive", "skinny.forwardBusyActive", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_forwardNoAnswerActive,
      {
        "forwardNoAnswerActive", "skinny.forwardNoAnswerActive", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_hearingConfPartyMask,
      {
        "hearingConfPartyMask", "skinny.hearingConfPartyMask", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_instance,
      {
        "instance", "skinny.instance", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Device Instance", HFILL }},
    { &hf_skinny_instanceNumber,
      {
        "instanceNumber", "skinny.instanceNumber", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_ipAddr_ipv4,
     {
        "ipAddr IPv4 Address", "skinny.ipAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_ipAddr_ipv6,
     {
        "ipAddr IPv6 Address", "skinny.ipAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_ipV4AddressScope,
      {
        "ipV4AddressScope", "skinny.ipV4AddressScope", FT_UINT32, BASE_DEC, NULL, 0x0,
        "IPv4 Address Scope", HFILL }},
    { &hf_skinny_ipV6AddressScope,
      {
        "ipV6AddressScope", "skinny.ipV6AddressScope", FT_UINT32, BASE_DEC, NULL, 0x0,
        "IPv6 Address Scope", HFILL }},
    { &hf_skinny_isConferenceCreator,
      {
        "isConferenceCreator", "skinny.isConferenceCreator", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_isMKIPresent,
      {
        "isMKIPresent", "skinny.isMKIPresent", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_jitter,
      {
        "jitter", "skinny.jitter", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Amount of Jitter", HFILL }},
    { &hf_skinny_keepAliveInterval,
      {
        "keepAliveInterval", "skinny.keepAliveInterval", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_key,
      {
        "key", "skinny.key", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_keyDerivationRate,
      {
        "keyDerivationRate", "skinny.keyDerivationRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_keylen,
      {
        "keylen", "skinny.keylen", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_last,
      {
        "last", "skinny.last", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_lastRedirectingReason,
      {
        "lastRedirectingReason", "skinny.lastRedirectingReason", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Last Redirecting Reason", HFILL }},
    { &hf_skinny_latency,
      {
        "latency", "skinny.latency", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Amount of Latency", HFILL }},
    { &hf_skinny_layoutCount,
      {
        "layoutCount", "skinny.layoutCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_layoutID,
      {
        "layoutID", "skinny.layoutID", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_level,
      {
        "level", "skinny.level", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_levelPreferenceCount,
      {
        "levelPreferenceCount", "skinny.levelPreferenceCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_lineDataEntries,
      {
        "lineDataEntries", "skinny.lineDataEntries", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Line Data Entries", HFILL }},
    { &hf_skinny_lineDisplayOptions,
      {
        "lineDisplayOptions", "skinny.lineDisplayOptions", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_lineInstance,
      {
        "lineInstance", "skinny.lineInstance", FT_UINT32, BASE_DEC, NULL, 0x0,
        "LineId", HFILL }},
    { &hf_skinny_lineNumber,
      {
        "lineNumber", "skinny.lineNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_locale,
      {
        "locale", "skinny.locale", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_longTermPictureIndex,
      {
        "longTermPictureIndex", "skinny.longTermPictureIndex", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_macAddress,
      {
        "Mac Address", "skinny.macAddress", FT_ETHER, BASE_NONE, NULL, 0x0,
        "Ethernet/Mac Address", HFILL }},
    { &hf_skinny_matrixConfPartyID,
      {
        "matrixConfPartyID", "skinny.matrixConfPartyID", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxBW,
      {
        "maxBW", "skinny.maxBW", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxBitRate,
      {
        "maxBitRate", "skinny.maxBitRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxConferences,
      {
        "Maximum Number of Concurrent Conferences", "skinny.maxConferences", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Indicates the maximum number of simultaneous Conferences, which this client/appliance can handle", HFILL }},
    { &hf_skinny_maxFramesPerPacket,
      {
        "maxFramesPerPacket", "skinny.maxFramesPerPacket", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxNumCalls,
      {
        "maxNumCalls", "skinny.maxNumCalls", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxNumOfAvailLines,
      {
        "maxNumOfAvailLines", "skinny.maxNumOfAvailLines", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxNumberOfLines,
      {
        "maxNumberOfLines", "skinny.maxNumberOfLines", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Maximum number of lines", HFILL }},
    { &hf_skinny_maxProtocolVer,
      {
        "maxProtocolVer", "skinny.maxProtocolVer", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxRetryNumber,
      {
        "maxRetryNumber", "skinny.maxRetryNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maxStreams,
      {
        "Maximum Number of Concurrent RTP Streams", "skinny.maxStreams", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Indicates the maximum number of simultaneous RTP duplex streams, which this client/appliance can handle.", HFILL }},
    { &hf_skinny_maxStreamsPerConf,
      {
        "maxStreamsPerConf", "skinny.maxStreamsPerConf", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_maximumBitRate,
      {
        "maximumBitRate", "skinny.maximumBitRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_milliSecondPacketSize,
      {
        "milliSecondPacketSize", "skinny.milliSecondPacketSize", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_minBitRate,
      {
        "minBitRate", "skinny.minBitRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_mixingMode,
      {
        "mixingMode", "skinny.mixingMode", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_modAnd2833,
      {
        "modAnd2833", "skinny.modAnd2833", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_modelNumber,
      {
        "modelNumber", "skinny.modelNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_multicastIpAddr_ipv4,
     {
        "multicastIpAddr IPv4 Address", "skinny.multicastIpAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_multicastIpAddr_ipv6,
     {
        "multicastIpAddr IPv6 Address", "skinny.multicastIpAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_multicastPortNumber,
      {
        "multicastPortNumber", "skinny.multicastPortNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_noaudio,
      {
        "noaudio", "skinny.noaudio", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_none,
      {
        "none", "skinny.none", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_notificationStatus,
      {
        "notificationStatus", "skinny.notificationStatus", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_nse,
      {
        "nse", "skinny.nse", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numNewMsgs,
      {
        "numNewMsgs", "skinny.numNewMsgs", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numOldMsgs,
      {
        "numOldMsgs", "skinny.numOldMsgs", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOctetsReceived,
      {
        "numberOctetsReceived", "skinny.numberOctetsReceived", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Octets Received", HFILL }},
    { &hf_skinny_numberOctetsSent,
      {
        "numberOctetsSent", "skinny.numberOctetsSent", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Octets Sent", HFILL }},
    { &hf_skinny_numberOfActiveParticipants,
      {
        "numberOfActiveParticipants", "skinny.numberOfActiveParticipants", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfEntries,
      {
        "numberOfEntries", "skinny.numberOfEntries", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfGOBs,
      {
        "numberOfGOBs", "skinny.numberOfGOBs", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfInServiceStreams,
      {
        "numberOfInServiceStreams", "skinny.numberOfInServiceStreams", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfLines,
      {
        "numberOfLines", "skinny.numberOfLines", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfMBs,
      {
        "numberOfMBs", "skinny.numberOfMBs", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfOutOfServiceStreams,
      {
        "numberOfOutOfServiceStreams", "skinny.numberOfOutOfServiceStreams", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfReservedParticipants,
      {
        "numberOfReservedParticipants", "skinny.numberOfReservedParticipants", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberOfSpeedDials,
      {
        "numberOfSpeedDials", "skinny.numberOfSpeedDials", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_numberPacketsLost,
      {
        "numberPacketsLost", "skinny.numberPacketsLost", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Packets Lost", HFILL }},
    { &hf_skinny_numberPacketsReceived,
      {
        "numberPacketsReceived", "skinny.numberPacketsReceived", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Packets Received", HFILL }},
    { &hf_skinny_numberPacketsSent,
      {
        "numberPacketsSent", "skinny.numberPacketsSent", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Number of Packets Sent", HFILL }},
    { &hf_skinny_originalCdpnRedirectReason,
      {
        "originalCdpnRedirectReason", "skinny.originalCdpnRedirectReason", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Original Called Party Redirect Reason", HFILL }},
    { &hf_skinny_padding,
      {
        "padding", "skinny.padding", FT_UINT16, BASE_DEC, NULL, 0x0,
        "Unused/Padding", HFILL }},
    { &hf_skinny_parm1,
      {
        "parm1", "skinny.parm1", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_parm2,
      {
        "parm2", "skinny.parm2", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_participantEntry,
      {
        "participantEntry", "skinny.participantEntry", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_partyDirection,
      {
        "partyDirection", "skinny.partyDirection", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_passThroughPartyId,
      {
        "passThroughPartyId", "skinny.passThroughPartyId", FT_UINT32, BASE_DEC, NULL, 0x0,
        "PassThrough PartyId", HFILL }},
    { &hf_skinny_passthruPartyID,
      {
        "passthruPartyID", "skinny.passthruPartyID", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_payloadDtmf,
      {
        "payloadDtmf", "skinny.payloadDtmf", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_payloadType,
      {
        "payloadType", "skinny.payloadType", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_payload_rfc_number,
      {
        "payload_rfc_number", "skinny.payload.rfc.number", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_peakRate,
      {
        "peakRate", "skinny.peakRate", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_pictureFormatCount,
      {
        "pictureFormatCount", "skinny.pictureFormatCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_pictureHeight,
      {
        "pictureHeight", "skinny.pictureHeight", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_pictureNumber,
      {
        "pictureNumber", "skinny.pictureNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_pictureWidth,
      {
        "pictureWidth", "skinny.pictureWidth", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_pixelAspectRatio,
      {
        "pixelAspectRatio", "skinny.pixelAspectRatio", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_portNumber,
      {
        "portNumber", "skinny.portNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_precedenceDomain,
      {
        "precedenceDomain", "skinny.precedenceDomain", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Precedence Domain", HFILL }},
    { &hf_skinny_precedenceLevel,
      {
        "precedenceLevel", "skinny.precedenceLevel", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Precedence Level, MLPP priorities", HFILL }},
    { &hf_skinny_precedenceValue,
      {
        "precedenceValue", "skinny.precedenceValue", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_preemptionPriority,
      {
        "preemptionPriority", "skinny.preemptionPriority", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_priority,
      {
        "priority", "skinny.priority", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_profile,
      {
        "profile", "skinny.profile", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_protocolDependentData,
      {
        "protocolDependentData", "skinny.protocolDependentData", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_protocolVer,
      {
        "Protocol Version", "skinny.protocolVer", FT_UINT8, BASE_DEC, NULL, 0x0,
        "Maximum Supported Protocol Version", HFILL }},
    { &hf_skinny_recoveryReferencePictureCount,
      {
        "recoveryReferencePictureCount", "skinny.recoveryReferencePictureCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_remoteIpAddr_ipv4,
     {
        "remoteIpAddr IPv4 Address", "skinny.remoteIpAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_remoteIpAddr_ipv6,
     {
        "remoteIpAddr IPv6 Address", "skinny.remoteIpAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_remotePortNumber,
      {
        "remotePortNumber", "skinny.remotePortNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_reserved_for_future_use,
      {
        "reserved_for_future_use", "skinny.reserved.for.future.use", FT_UINT32, BASE_DEC, NULL, 0x0,
        "User Id", HFILL }},
    { &hf_skinny_retryTimer,
      {
        "retryTimer", "skinny.retryTimer", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_rfc2833,
      {
        "rfc2833", "skinny.rfc2833", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_routingID,
      {
        "routingID", "skinny.routingID", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_rsvpErrorFlag,
      {
        "rsvpErrorFlag", "skinny.rsvpErrorFlag", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_rsvpErrorSubCodeVal,
      {
        "rsvpErrorSubCodeVal", "skinny.rsvpErrorSubCodeVal", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_rtpMediaPort,
      {
        "rtpMediaPort", "skinny.rtpMediaPort", FT_UINT32, BASE_DEC, NULL, 0x0,
        "RTP Media Port", HFILL }},
    { &hf_skinny_rtpPayloadFormat,
      {
        "rtpPayloadFormat", "skinny.rtpPayloadFormat", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_salt,
      {
        "salt", "skinny.salt", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_saltlen,
      {
        "saltlen", "skinny.saltlen", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_secondaryKeepAliveInterval,
      {
        "secondaryKeepAliveInterval", "skinny.secondaryKeepAliveInterval", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_serverTcpListenPort,
      {
        "serverTcpListenPort", "skinny.serverTcpListenPort", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_serviceNum,
      {
        "serviceNum", "skinny.serviceNum", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_serviceNumber,
      {
        "serviceNumber", "skinny.serviceNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_serviceResourceCount,
      {
        "serviceResourceCount", "skinny.serviceResourceCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_serviceURLIndex,
      {
        "serviceURLIndex", "skinny.serviceURLIndex", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_softKeyCount,
      {
        "softKeyCount", "skinny.softKeyCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_softKeyOffset,
      {
        "softKeyOffset", "skinny.softKeyOffset", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_softKeySetCount,
      {
        "softKeySetCount", "skinny.softKeySetCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_softKeySetOffset,
      {
        "softKeySetOffset", "skinny.softKeySetOffset", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_sourceIpAddr_ipv4,
     {
        "sourceIpAddr IPv4 Address", "skinny.sourceIpAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_sourceIpAddr_ipv6,
     {
        "sourceIpAddr IPv6 Address", "skinny.sourceIpAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_sourcePortNumber,
      {
        "sourcePortNumber", "skinny.sourcePortNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_speedDialNumber,
      {
        "speedDialNumber", "skinny.speedDialNumber", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_sse,
      {
        "sse", "skinny.sse", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_standard,
      {
        "standard", "skinny.standard", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_startingLineInstance,
      {
        "startingLineInstance", "skinny.startingLineInstance", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Starting Line Instance", HFILL }},
    { &hf_skinny_stationIpAddr,
      {
        "stationIpAddr", "skinny.stationIpAddr", FT_IPv4, BASE_NONE, NULL, 0x0,
        "IPv4 Address", HFILL }},
    { &hf_skinny_stationIpAddr_ipv4,
     {
        "stationIpAddr IPv4 Address", "skinny.stationIpAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_stationIpAddr_ipv6,
     {
        "stationIpAddr IPv6 Address", "skinny.stationIpAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_stationIpV6Addr,
      {
        "stationIpV6Addr", "skinny.stationIpV6Addr", FT_IPv6, BASE_NONE, NULL, 0x0,
        "IPv6 Address", HFILL }},
    { &hf_skinny_stationIpV6Addr_ipv4,
     {
        "stationIpV6Addr IPv4 Address", "skinny.stationIpV6Addr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_stationIpV6Addr_ipv6,
     {
        "stationIpV6Addr IPv6 Address", "skinny.stationIpV6Addr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_stillImageTransmission,
      {
        "stillImageTransmission", "skinny.stillImageTransmission", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Still Image Transmission", HFILL }},
    { &hf_skinny_stimulusInstance,
      {
        "stimulusInstance", "skinny.stimulusInstance", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_stimulusStatus,
      {
        "stimulusStatus", "skinny.stimulusStatus", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Stimulus Status", HFILL }},
    { &hf_skinny_streamPassThroughId,
      {
        "streamPassThroughId", "skinny.streamPassThroughId", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_systemTime,
      {
        "systemTime", "skinny.systemTime", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_temporalSpatialTradeOff,
      {
        "temporalSpatialTradeOff", "skinny.temporalSpatialTradeOff", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_temporalSpatialTradeOffCapability,
      {
        "temporalSpatialTradeOffCapability", "skinny.temporalSpatialTradeOffCapability", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Temporal spatial trade off capability", HFILL }},
    { &hf_skinny_timeOutValue,
      {
        "timeOutValue", "skinny.timeOutValue", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_timer,
      {
        "timer", "skinny.timer", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_totalButtonCount,
      {
        "totalButtonCount", "skinny.totalButtonCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_totalNumOfConfiguredLines,
      {
        "totalNumOfConfiguredLines", "skinny.totalNumOfConfiguredLines", FT_UINT32, BASE_DEC, NULL, 0x0,
        "Total Number of Configured Lines", HFILL }},
    { &hf_skinny_totalSoftKeyCount,
      {
        "totalSoftKeyCount", "skinny.totalSoftKeyCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_totalSoftKeySetCount,
      {
        "totalSoftKeySetCount", "skinny.totalSoftKeySetCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_transactionId,
      {
        "transactionId", "skinny.transactionId", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_transmitIpAddr_ipv4,
     {
        "transmitIpAddr IPv4 Address", "skinny.transmitIpAddr.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_transmitIpAddr_ipv6,
     {
        "transmitIpAddr IPv6 Address", "skinny.transmitIpAddr.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
        "ipaddress in big endian", HFILL }},
    { &hf_skinny_transmitPreference,
      {
        "transmitPreference", "skinny.transmitPreference", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_unknown,
      {
        "unknown", "skinny.unknown", FT_UINT8, BASE_DEC, NULL, 0x0,
        "unknown (Part of ProtocolVer)", HFILL }},
    { &hf_skinny_unknown1_0159,
      {
        "unknown1_0159", "skinny.unknown1.0159", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_unknown2_0159,
      {
        "unknown2_0159", "skinny.unknown2.0159", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_unknown3_0159,
      {
        "unknown3_0159", "skinny.unknown3.0159", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_v150sprt,
      {
        "v150sprt", "skinny.v150sprt", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_vendor,
      {
        "vendor", "skinny.vendor", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_videoCapCount,
      {
        "videoCapCount", "skinny.videoCapCount", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wDay,
      {
        "wDay", "skinny.wDay", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wDayOfWeek,
      {
        "wDayOfWeek", "skinny.wDayOfWeek", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wHour,
      {
        "wHour", "skinny.wHour", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wMilliseconds,
      {
        "wMilliseconds", "skinny.wMilliseconds", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wMinute,
      {
        "wMinute", "skinny.wMinute", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wMonth,
      {
        "wMonth", "skinny.wMonth", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wSecond,
      {
        "wSecond", "skinny.wSecond", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_wYear,
      {
        "wYear", "skinny.wYear", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_waitTimeBeforeNextReq,
      {
        "waitTimeBeforeNextReq", "skinny.waitTimeBeforeNextReq", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_skinny_xmldata,
      {
        "xmldata", "skinny.xmldata", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_AlternateCallingParty,
      {
        "AlternateCallingParty", "skinny.AlternateCallingParty", FT_STRING, BASE_NONE, NULL, 0x0,
        "Alternate Calling Party Number", HFILL }},
    {&hf_skinny_DeviceName,
      {
        "DeviceName", "skinny.DeviceName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Device Name", HFILL }},
    {&hf_skinny_HuntPilotName,
      {
        "HuntPilotName", "skinny.HuntPilotName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_HuntPilotNumber,
      {
        "HuntPilotNumber", "skinny.HuntPilotNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ServerName,
      {
        "ServerName", "skinny.ServerName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_add_participant_result,
      {
        "add_participant_result", "skinny.add.participant.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &AddParticipantResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_alarmSeverity,
      {
        "alarmSeverity", "skinny.alarmSeverity", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceAlarmSeverity_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_algorithmID,
      {
        "algorithmID", "skinny.algorithmID", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaEncryptionAlgorithmType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_annAckReq,
      {
        "annAckReq", "skinny.annAckReq", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &EndOfAnnAck_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_annPlayMode,
      {
        "annPlayMode", "skinny.annPlayMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &AnnPlayMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_annStatus,
      {
        "annStatus", "skinny.annStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &PlayAnnStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_appConfID,
      {
        "appConfID", "skinny.appConfID", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_appData,
      {
        "appData", "skinny.appData", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_appName,
      {
        "appName", "skinny.appName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_audit_participant_result,
      {
        "audit_participant_result", "skinny.audit.participant.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &AuditParticipantResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_bridgeParticipantId,
      {
        "bridgeParticipantId", "skinny.bridgeParticipantId", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_buttonDefinition,
      {
        "buttonDefinition", "skinny.buttonDefinition", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ButtonType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_callHistoryDisposition,
      {
        "callHistoryDisposition", "skinny.callHistoryDisposition", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &CallHistoryDisposition_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_callSecurityStatus,
      {
        "callSecurityStatus", "skinny.callSecurityStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &CallSecurityStatusType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_callState,
      {
        "callState", "skinny.callState", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DCallState_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_callType,
      {
        "callType", "skinny.callType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &CallType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_calledParty,
      {
        "calledParty", "skinny.calledParty", FT_STRING, BASE_NONE, NULL, 0x0,
        "CalledPartyNumber", HFILL }},
    {&hf_skinny_calledPartyName,
      {
        "calledPartyName", "skinny.calledPartyName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Called Party Name", HFILL }},
    {&hf_skinny_callingParty,
      {
        "callingParty", "skinny.callingParty", FT_STRING, BASE_NONE, NULL, 0x0,
        "Calling Party Number", HFILL }},
    {&hf_skinny_callingPartyName,
      {
        "callingPartyName", "skinny.callingPartyName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Calling Party Name", HFILL }},
    {&hf_skinny_callingPartyNumber,
      {
        "callingPartyNumber", "skinny.callingPartyNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        "Calling Party Number", HFILL }},
    {&hf_skinny_cause,
      {
        "cause", "skinny.cause", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SubscribeCause_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_cdpnVoiceMailbox,
      {
        "cdpnVoiceMailbox", "skinny.cdpnVoiceMailbox", FT_STRING, BASE_NONE, NULL, 0x0,
        "Called Party Voicemail Box Number", HFILL }},
    {&hf_skinny_cgpnVoiceMailbox,
      {
        "cgpnVoiceMailbox", "skinny.cgpnVoiceMailbox", FT_STRING, BASE_NONE, NULL, 0x0,
        "Calling Party Voicemail Box Number", HFILL }},
    {&hf_skinny_command,
      {
        "command", "skinny.command", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MiscCommandType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_compressionType,
      {
        "compressionType", "skinny.compressionType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_PayloadType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_conferenceName,
      {
        "conferenceName", "skinny.conferenceName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_configVersionStamp,
      {
        "configVersionStamp", "skinny.configVersionStamp", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_data,
      {
        "Statistics", "skinny.data", FT_STRING, BASE_NONE, NULL, 0x0,
        "variable field size (max: 600]", HFILL }},
    {&hf_skinny_dataCapabilityDirection,
      {
        "dataCapabilityDirection", "skinny.dataCapabilityDirection", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &TransmitOrReceive_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_dateTemplate,
      {
        "dateTemplate", "skinny.dateTemplate", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_delete_conf_result,
      {
        "delete_conf_result", "skinny.delete.conf.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeleteConfResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_deviceType,
      {
        "Device Type", "skinny.deviceType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceType_ext, 0x0,
        "Device Type of this phone / appliance", HFILL }},
    {&hf_skinny_dialedNumber,
      {
        "dialedNumber", "skinny.dialedNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_direction,
      {
        "direction", "skinny.direction", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &RSVPDirection_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_directoryNum,
      {
        "directoryNum", "skinny.directoryNum", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ecValue,
      {
        "ecValue", "skinny.ecValue", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_EchoCancellation_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_encryptionCapability,
      {
        "encryptionCapability", "skinny.encryptionCapability", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_Encryption_Capability_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_errorCode,
      {
        "errorCode", "skinny.errorCode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &QoSErrorCode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_featureID,
      {
        "featureID", "skinny.featureID", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ButtonType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_featureTextLabel,
      {
        "featureTextLabel", "skinny.featureTextLabel", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_firmwareLoadName,
      {
        "firmwareLoadName", "skinny.firmwareLoadName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Firmware Load Name", HFILL }},
    {&hf_skinny_forwardAllDirnum,
      {
        "forwardAllDirnum", "skinny.forwardAllDirnum", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_forwardBusyDirnum,
      {
        "forwardBusyDirnum", "skinny.forwardBusyDirnum", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_forwardNoAnswerlDirnum,
      {
        "forwardNoAnswerlDirnum", "skinny.forwardNoAnswerlDirnum", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_g723BitRate,
      {
        "g723BitRate", "skinny.g723BitRate", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_G723BitRate_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_headsetStatus,
      {
        "headsetStatus", "skinny.headsetStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &HeadsetMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ipAddressType,
      {
        "ipAddressType", "skinny.ipAddressType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &IpAddrType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ipAddressingMode,
      {
        "ipAddressingMode", "skinny.ipAddressingMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &IpAddrMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_kpButton,
      {
        "kpButton", "skinny.kpButton", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &KeyPadButton_ext, 0x0,
        "KeyPad Button which was Pressed", HFILL }},
    {&hf_skinny_lampMode,
      {
        "lampMode", "skinny.lampMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &LampMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_lastRedirectingParty,
      {
        "lastRedirectingParty", "skinny.lastRedirectingParty", FT_STRING, BASE_NONE, NULL, 0x0,
        "Last Redirecting Party Number", HFILL }},
    {&hf_skinny_lastRedirectingPartyName,
      {
        "lastRedirectingPartyName", "skinny.lastRedirectingPartyName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Last Redirecting Party Name", HFILL }},
    {&hf_skinny_lastRedirectingVoiceMailbox,
      {
        "lastRedirectingVoiceMailbox", "skinny.lastRedirectingVoiceMailbox", FT_STRING, BASE_NONE, NULL, 0x0,
        "Last Redirecting Parties Voicemail Box Number", HFILL }},
    {&hf_skinny_layouts,
      {
        "layouts", "skinny.layouts", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Layout_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_lineDirNumber,
      {
        "lineDirNumber", "skinny.lineDirNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_lineFullyQualifiedDisplayName,
      {
        "lineFullyQualifiedDisplayName", "skinny.lineFullyQualifiedDisplayName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_lineTextLabel,
      {
        "lineTextLabel", "skinny.lineTextLabel", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_locationInfo,
      {
        "locationInfo", "skinny.locationInfo", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaPathCapabilities,
      {
        "mediaPathCapabilities", "skinny.mediaPathCapabilities", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaPathCapabilities_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaPathEvent,
      {
        "mediaPathEvent", "skinny.mediaPathEvent", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaPathEvent_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaPathID,
      {
        "mediaPathID", "skinny.mediaPathID", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaPathID_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaReceptionStatus,
      {
        "mediaReceptionStatus", "skinny.mediaReceptionStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaTransmissionStatus,
      {
        "mediaTransmissionStatus", "skinny.mediaTransmissionStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaTransportType,
      {
        "mediaTransportType", "skinny.mediaTransportType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaTransportType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mediaType,
      {
        "mediaType", "skinny.mediaType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_micMode,
      {
        "micMode", "skinny.micMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MicrophoneMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_modify_conf_result,
      {
        "modify_conf_result", "skinny.modify.conf.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ModifyConfResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_multicastReceptionStatus,
      {
        "multicastReceptionStatus", "skinny.multicastReceptionStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MulticastMediaReceptionStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_multimediaReceptionStatus,
      {
        "multimediaReceptionStatus", "skinny.multimediaReceptionStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &OpenReceiveChanStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_multimediaTransmissionStatus,
      {
        "multimediaTransmissionStatus", "skinny.multimediaTransmissionStatus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MediaStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mwiControlNumber,
      {
        "mwiControlNumber", "skinny.mwiControlNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mwiTargetNumber,
      {
        "mwiTargetNumber", "skinny.mwiTargetNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_mwi_notification_result,
      {
        "mwi_notification_result", "skinny.mwi.notification.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &MwiNotificationResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_notify,
      {
        "notify", "skinny.notify", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_originalCalledParty,
      {
        "originalCalledParty", "skinny.originalCalledParty", FT_STRING, BASE_NONE, NULL, 0x0,
        "Original Called Party Number", HFILL }},
    {&hf_skinny_originalCalledPartyName,
      {
        "originalCalledPartyName", "skinny.originalCalledPartyName", FT_STRING, BASE_NONE, NULL, 0x0,
        "Original Called Party Name", HFILL }},
    {&hf_skinny_originalCdpnVoiceMailbox,
      {
        "originalCdpnVoiceMailbox", "skinny.originalCdpnVoiceMailbox", FT_STRING, BASE_NONE, NULL, 0x0,
        "Original Called Party Voicemail Box Number", HFILL }},
    {&hf_skinny_participantName,
      {
        "participantName", "skinny.participantName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_participantNumber,
      {
        "participantNumber", "skinny.participantNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_passThruData,
      {
        "passThruData", "skinny.passThruData", FT_STRING, BASE_NONE, NULL, 0x0,
        "variable field size (max: 2000]", HFILL }},
    {&hf_skinny_payloadCapability,
      {
        "payloadCapability", "skinny.payloadCapability", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_PayloadType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_portHandlingFlag,
      {
        "portHandlingFlag", "skinny.portHandlingFlag", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &PortHandling_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_privacy,
      {
        "privacy", "skinny.privacy", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &CallPrivacy_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_promptStatus,
      {
        "promptStatus", "skinny.promptStatus", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_recording_status,
      {
        "recording_status", "skinny.recording.status", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &RecordingStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_requestedIpAddrType,
      {
        "requestedIpAddrType", "skinny.requestedIpAddrType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &IpAddrType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_resetType,
      {
        "resetType", "skinny.resetType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceResetType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_resourceType,
      {
        "resourceType", "skinny.resourceType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ResourceType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_result,
      {
        "result", "skinny.result", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &CreateConfResult_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_resvStyle,
      {
        "resvStyle", "skinny.resvStyle", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ResvStyle_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ringDuration,
      {
        "ringDuration", "skinny.ringDuration", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &RingDuration_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ringMode,
      {
        "ringMode", "skinny.ringMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &RingMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_rsvpErrorCode,
      {
        "rsvpErrorCode", "skinny.rsvpErrorCode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &RSVPErrorCode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_sequenceFlag,
      {
        "sequenceFlag", "skinny.sequenceFlag", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SequenceFlag_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_serverName,
      {
        "serverName", "skinny.serverName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_serviceURL,
      {
        "serviceURL", "skinny.serviceURL", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_serviceURLDisplayName,
      {
        "serviceURLDisplayName", "skinny.serviceURLDisplayName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_sessionType,
      {
        "sessionType", "skinny.sessionType", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SessionType_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_softKeyEvent,
      {
        "softKeyEvent", "skinny.softKeyEvent", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SoftKeyEvent_ext, 0x0,
        "SoftKey Event", HFILL }},
    {&hf_skinny_softKeyInfoIndex,
      {
        "softKeyInfoIndex", "skinny.softKeyInfoIndex", FT_UINT16, BASE_HEX | BASE_EXT_STRING, &SoftKeyInfoIndex_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_softKeyLabel,
      {
        "softKeyLabel", "skinny.softKeyLabel", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_softKeySetIndex,
      {
        "softKeySetIndex", "skinny.softKeySetIndex", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SoftKeySet_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_softKeyTemplateIndex,
      {
        "softKeyTemplateIndex", "skinny.softKeyTemplateIndex", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &SoftKeyTemplateIndex_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_speakerMode,
      {
        "speakerMode", "skinny.speakerMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SpeakerMode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_speedDialDirNumber,
      {
        "speedDialDirNumber", "skinny.speedDialDirNumber", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_speedDialDisplayName,
      {
        "speedDialDisplayName", "skinny.speedDialDisplayName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_ssValue,
      {
        "ssValue", "skinny.ssValue", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &Media_SilenceSuppression_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_statsProcessingMode,
      {
        "Stats Processing Mode", "skinny.statsProcessingMode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &StatsProcessingType_ext, 0x0,
        "What to do after you send the stats", HFILL }},
    {&hf_skinny_status,
      {
        "status", "skinny.status", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceUnregisterStatus_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_stimulus,
      {
        "stimulus", "skinny.stimulus", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceStimulus_ext, 0x0,
        "Device Stimulus", HFILL }},
    {&hf_skinny_subAppID,
      {
        "subAppID", "skinny.subAppID", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_subscriptionFeatureID,
      {
        "subscriptionFeatureID", "skinny.subscriptionFeatureID", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &SubscriptionFeatureID_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_subscriptionID,
      {
        "subscriptionID", "skinny.subscriptionID", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_text,
      {
        "text", "skinny.text", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_tone,
      {
        "tone", "skinny.tone", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceTone_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_toneAnnouncement,
      {
        "toneAnnouncement", "skinny.toneAnnouncement", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &DeviceTone_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_tone_output_direction,
      {
        "tone_output_direction", "skinny.tone.output.direction", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &ToneOutputDirection_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_unRegReasonCode,
      {
        "unRegReasonCode", "skinny.unRegReasonCode", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &UnRegReasonCode_ext, 0x0,
        NULL, HFILL }},
    {&hf_skinny_unknownString_0159,
      {
        "unknownString_0159", "skinny.unknownString.0159", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_userName,
      {
        "userName", "skinny.userName", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_vendorID,
      {
        "vendorID", "skinny.vendorID", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_version,
      {
        "version", "skinny.version", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_versionStr,
      {
        "versionStr", "skinny.versionStr", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    {&hf_skinny_videoCapabilityDirection,
      {
        "videoCapabilityDirection", "skinny.videoCapabilityDirection", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &TransmitOrReceive_ext, 0x0,
        NULL, HFILL }},
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_skinny,
    &ett_skinny_tree,
  };

  module_t *skinny_module;

  /* Register the protocol name and description */
  proto_skinny = proto_register_protocol("Skinny Client Control Protocol",
                                         "SKINNY", "skinny");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_skinny, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  skinny_module = prefs_register_protocol(proto_skinny, NULL);
  prefs_register_bool_preference(skinny_module, "desegment",
    "Reassemble SKINNY messages spanning multiple TCP segments",
    "Whether the SKINNY dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable"
    " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &global_skinny_desegment);

  skinny_handle = register_dissector("skinny", dissect_skinny, proto_skinny);

  skinny_tap = register_tap("skinny");
}

void
proto_reg_handoff_skinny(void)
{
  /* Skinny content type and internet media type used by other dissectors are the same */
  xml_handle = find_dissector_add_dependency("xml", proto_skinny);
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_SKINNY, skinny_handle);
  ssl_dissector_add(SSL_PORT_SKINNY, skinny_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
