/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ranap.c                                                             */
/* asn2wrs.py -q -L -p ranap -c ./ranap.cnf -s ./packet-ranap-template -D . -O ../.. RANAP-CommonDataTypes.asn RANAP-Constants.asn RANAP-Containers.asn RANAP-IEs.asn RANAP-PDU-Contents.asn RANAP-PDU-Descriptions.asn */

/* packet-ranap.c
 * Routines for UMTS Node B Application Part(RANAP) packet dissection
 * Copyright 2005 - 2010, Anders Broman <anders.broman[AT]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 25.413 version 10.4.0 Release 10
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"
#include "packet-ranap.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-isup.h"
#include "packet-s1ap.h"
#include "packet-rtp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define SCCP_SSN_RANAP 142

#define PNAME  "Radio Access Network Application Part"
#define PSNAME "RANAP"
#define PFNAME "ranap"

/* Highest Ranap_ProcedureCode_value, use in heuristics */
#define RANAP_MAX_PC  49 /* id_RerouteNASRequest =  49 */

#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfDTs                     15
#define maxNrOfErrors                  256
#define maxNrOfIuSigConIds             250
#define maxNrOfPDPDirections           2
#define maxNrOfPoints                  15
#define maxNrOfRABs                    256
#define maxNrOfSeparateTrafficDirections 2
#define maxNrOfSRBs                    8
#define maxNrOfVol                     2
#define maxNrOfLevels                  256
#define maxNrOfAltValues               16
#define maxNrOfPLMNsSN                 32
#define maxNrOfLAs                     65536
#define maxNrOfSNAs                    65536
#define maxNrOfUEsToBeTraced           64
#define maxNrOfInterfaces              16
#define maxRAB_Subflows                7
#define maxRAB_SubflowCombination      64
#define maxSet                         9
#define maxNrOfHSDSCHMACdFlows_1       7
#define maxnoofMulticastServicesPerUE  128
#define maxnoofMulticastServicesPerRNC 512
#define maxMBMSSA                      256
#define maxMBMSRA                      65536
#define maxNrOfEDCHMACdFlows_1         7
#define maxGANSSSet                    9
#define maxNrOfCSGs                    256
#define maxNrOfEUTRAFreqs              8
#define maxNrOfCellIds                 32
#define maxNrOfRAIs                    8
#define maxNrOfLAIs                    8
#define maxSizeOfIMSInfo               32
#define maxnoofMDTPLMNs                16
#define maxAddPosSet                   8
#define maxnoofPLMNs                   16

typedef enum _ProcedureCode_enum {
  id_RAB_Assignment =   0,
  id_Iu_Release =   1,
  id_RelocationPreparation =   2,
  id_RelocationResourceAllocation =   3,
  id_RelocationCancel =   4,
  id_SRNS_ContextTransfer =   5,
  id_SecurityModeControl =   6,
  id_DataVolumeReport =   7,
  id_Not_Used_8 =   8,
  id_Reset     =   9,
  id_RAB_ReleaseRequest =  10,
  id_Iu_ReleaseRequest =  11,
  id_RelocationDetect =  12,
  id_RelocationComplete =  13,
  id_Paging    =  14,
  id_CommonID  =  15,
  id_CN_InvokeTrace =  16,
  id_LocationReportingControl =  17,
  id_LocationReport =  18,
  id_InitialUE_Message =  19,
  id_DirectTransfer =  20,
  id_OverloadControl =  21,
  id_ErrorIndication =  22,
  id_SRNS_DataForward =  23,
  id_ForwardSRNS_Context =  24,
  id_privateMessage =  25,
  id_CN_DeactivateTrace =  26,
  id_ResetResource =  27,
  id_RANAP_Relocation =  28,
  id_RAB_ModifyRequest =  29,
  id_LocationRelatedData =  30,
  id_InformationTransfer =  31,
  id_UESpecificInformation =  32,
  id_UplinkInformationExchange =  33,
  id_DirectInformationTransfer =  34,
  id_MBMSSessionStart =  35,
  id_MBMSSessionUpdate =  36,
  id_MBMSSessionStop =  37,
  id_MBMSUELinking =  38,
  id_MBMSRegistration =  39,
  id_MBMSCNDe_Registration_Procedure =  40,
  id_MBMSRABEstablishmentIndication =  41,
  id_MBMSRABRelease =  42,
  id_enhancedRelocationComplete =  43,
  id_enhancedRelocationCompleteConfirm =  44,
  id_RANAPenhancedRelocation =  45,
  id_SRVCCPreparation =  46,
  id_UeRadioCapabilityMatch =  47,
  id_UeRegistrationQuery =  48,
  id_RerouteNASRequest =  49
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_AreaIdentity =   0,
  id_Not_Used_1 =   1,
  id_Not_Used_2 =   2,
  id_CN_DomainIndicator =   3,
  id_Cause     =   4,
  id_ChosenEncryptionAlgorithm =   5,
  id_ChosenIntegrityProtectionAlgorithm =   6,
  id_ClassmarkInformation2 =   7,
  id_ClassmarkInformation3 =   8,
  id_CriticalityDiagnostics =   9,
  id_DL_GTP_PDU_SequenceNumber =  10,
  id_EncryptionInformation =  11,
  id_IntegrityProtectionInformation =  12,
  id_IuTransportAssociation =  13,
  id_L3_Information =  14,
  id_LAI       =  15,
  id_NAS_PDU   =  16,
  id_NonSearchingIndication =  17,
  id_NumberOfSteps =  18,
  id_OMC_ID    =  19,
  id_OldBSS_ToNewBSS_Information =  20,
  id_PagingAreaID =  21,
  id_PagingCause =  22,
  id_PermanentNAS_UE_ID =  23,
  id_RAB_ContextItem =  24,
  id_RAB_ContextList =  25,
  id_RAB_DataForwardingItem =  26,
  id_RAB_DataForwardingItem_SRNS_CtxReq =  27,
  id_RAB_DataForwardingList =  28,
  id_RAB_DataForwardingList_SRNS_CtxReq =  29,
  id_RAB_DataVolumeReportItem =  30,
  id_RAB_DataVolumeReportList =  31,
  id_RAB_DataVolumeReportRequestItem =  32,
  id_RAB_DataVolumeReportRequestList =  33,
  id_RAB_FailedItem =  34,
  id_RAB_FailedList =  35,
  id_RAB_ID    =  36,
  id_RAB_QueuedItem =  37,
  id_RAB_QueuedList =  38,
  id_RAB_ReleaseFailedList =  39,
  id_RAB_ReleaseItem =  40,
  id_RAB_ReleaseList =  41,
  id_RAB_ReleasedItem =  42,
  id_RAB_ReleasedList =  43,
  id_RAB_ReleasedList_IuRelComp =  44,
  id_RAB_RelocationReleaseItem =  45,
  id_RAB_RelocationReleaseList =  46,
  id_RAB_SetupItem_RelocReq =  47,
  id_RAB_SetupItem_RelocReqAck =  48,
  id_RAB_SetupList_RelocReq =  49,
  id_RAB_SetupList_RelocReqAck =  50,
  id_RAB_SetupOrModifiedItem =  51,
  id_RAB_SetupOrModifiedList =  52,
  id_RAB_SetupOrModifyItem =  53,
  id_RAB_SetupOrModifyList =  54,
  id_RAC       =  55,
  id_RelocationType =  56,
  id_RequestType =  57,
  id_SAI       =  58,
  id_SAPI      =  59,
  id_SourceID  =  60,
  id_Source_ToTarget_TransparentContainer =  61,
  id_TargetID  =  62,
  id_Target_ToSource_TransparentContainer =  63,
  id_TemporaryUE_ID =  64,
  id_TraceReference =  65,
  id_TraceType =  66,
  id_TransportLayerAddress =  67,
  id_TriggerID =  68,
  id_UE_ID     =  69,
  id_UL_GTP_PDU_SequenceNumber =  70,
  id_RAB_FailedtoReportItem =  71,
  id_RAB_FailedtoReportList =  72,
  id_Not_Used_73 =  73,
  id_Not_Used_74 =  74,
  id_KeyStatus =  75,
  id_DRX_CycleLengthCoefficient =  76,
  id_IuSigConIdList =  77,
  id_IuSigConIdItem =  78,
  id_IuSigConId =  79,
  id_DirectTransferInformationItem_RANAP_RelocInf =  80,
  id_DirectTransferInformationList_RANAP_RelocInf =  81,
  id_RAB_ContextItem_RANAP_RelocInf =  82,
  id_RAB_ContextList_RANAP_RelocInf =  83,
  id_RAB_ContextFailedtoTransferItem =  84,
  id_RAB_ContextFailedtoTransferList =  85,
  id_GlobalRNC_ID =  86,
  id_RAB_ReleasedItem_IuRelComp =  87,
  id_MessageStructure =  88,
  id_Alt_RAB_Parameters =  89,
  id_Ass_RAB_Parameters =  90,
  id_RAB_ModifyList =  91,
  id_RAB_ModifyItem =  92,
  id_TypeOfError =  93,
  id_BroadcastAssistanceDataDecipheringKeys =  94,
  id_LocationRelatedDataRequestType =  95,
  id_GlobalCN_ID =  96,
  id_LastKnownServiceArea =  97,
  id_SRB_TrCH_Mapping =  98,
  id_InterSystemInformation_TransparentContainer =  99,
  id_NewBSS_To_OldBSS_Information = 100,
  id_Not_Used_101 = 101,
  id_Not_Used_102 = 102,
  id_SourceRNC_PDCP_context_info = 103,
  id_InformationTransferID = 104,
  id_SNA_Access_Information = 105,
  id_ProvidedData = 106,
  id_GERAN_BSC_Container = 107,
  id_GERAN_Classmark = 108,
  id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item = 109,
  id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse = 110,
  id_VerticalAccuracyCode = 111,
  id_ResponseTime = 112,
  id_PositioningPriority = 113,
  id_ClientType = 114,
  id_LocationRelatedDataRequestTypeSpecificToGERANIuMode = 115,
  id_SignallingIndication = 116,
  id_hS_DSCH_MAC_d_Flow_ID = 117,
  id_UESBI_Iu  = 118,
  id_PositionData = 119,
  id_PositionDataSpecificToGERANIuMode = 120,
  id_CellLoadInformationGroup = 121,
  id_AccuracyFulfilmentIndicator = 122,
  id_InformationTransferType = 123,
  id_TraceRecordingSessionInformation = 124,
  id_TracePropagationParameters = 125,
  id_InterSystemInformationTransferType = 126,
  id_SelectedPLMN_ID = 127,
  id_RedirectionCompleted = 128,
  id_RedirectionIndication = 129,
  id_NAS_SequenceNumber = 130,
  id_RejectCauseValue = 131,
  id_APN       = 132,
  id_CNMBMSLinkingInformation = 133,
  id_DeltaRAListofIdleModeUEs = 134,
  id_FrequenceLayerConvergenceFlag = 135,
  id_InformationExchangeID = 136,
  id_InformationExchangeType = 137,
  id_InformationRequested = 138,
  id_InformationRequestType = 139,
  id_IPMulticastAddress = 140,
  id_JoinedMBMSBearerServicesList = 141,
  id_LeftMBMSBearerServicesList = 142,
  id_MBMSBearerServiceType = 143,
  id_MBMSCNDe_Registration = 144,
  id_MBMSServiceArea = 145,
  id_MBMSSessionDuration = 146,
  id_MBMSSessionIdentity = 147,
  id_PDP_TypeInformation = 148,
  id_RAB_Parameters = 149,
  id_RAListofIdleModeUEs = 150,
  id_MBMSRegistrationRequestType = 151,
  id_SessionUpdateID = 152,
  id_TMGI      = 153,
  id_TransportLayerInformation = 154,
  id_UnsuccessfulLinkingList = 155,
  id_MBMSLinkingInformation = 156,
  id_MBMSSessionRepetitionNumber = 157,
  id_AlternativeRABConfiguration = 158,
  id_AlternativeRABConfigurationRequest = 159,
  id_E_DCH_MAC_d_Flow_ID = 160,
  id_SourceBSS_ToTargetBSS_TransparentContainer = 161,
  id_TargetBSS_ToSourceBSS_TransparentContainer = 162,
  id_TimeToMBMSDataTransfer = 163,
  id_IncludeVelocity = 164,
  id_VelocityEstimate = 165,
  id_RedirectAttemptFlag = 166,
  id_RAT_Type  = 167,
  id_PeriodicLocationInfo = 168,
  id_MBMSCountingInformation = 169,
  id_170_not_to_be_used_for_IE_ids = 170,
  id_ExtendedRNC_ID = 171,
  id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf = 172,
  id_Alt_RAB_Parameter_ExtendedMaxBitrateInf = 173,
  id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList = 174,
  id_Ass_RAB_Parameter_ExtendedMaxBitrateList = 175,
  id_RAB_Parameter_ExtendedGuaranteedBitrateList = 176,
  id_RAB_Parameter_ExtendedMaxBitrateList = 177,
  id_Requested_RAB_Parameter_ExtendedMaxBitrateList = 178,
  id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList = 179,
  id_LAofIdleModeUEs = 180,
  id_newLAListofIdleModeUEs = 181,
  id_LAListwithNoIdleModeUEsAnyMore = 182,
  id_183_not_to_be_used_for_IE_ids = 183,
  id_GANSS_PositioningDataSet = 184,
  id_RequestedGANSSAssistanceData = 185,
  id_BroadcastGANSSAssistanceDataDecipheringKeys = 186,
  id_d_RNTI_for_NoIuCSUP = 187,
  id_RAB_SetupList_EnhancedRelocCompleteReq = 188,
  id_RAB_SetupItem_EnhancedRelocCompleteReq = 189,
  id_RAB_SetupList_EnhancedRelocCompleteRes = 190,
  id_RAB_SetupItem_EnhancedRelocCompleteRes = 191,
  id_RAB_SetupList_EnhRelocInfoReq = 192,
  id_RAB_SetupItem_EnhRelocInfoReq = 193,
  id_RAB_SetupList_EnhRelocInfoRes = 194,
  id_RAB_SetupItem_EnhRelocInfoRes = 195,
  id_OldIuSigConId = 196,
  id_RAB_FailedList_EnhRelocInfoRes = 197,
  id_RAB_FailedItem_EnhRelocInfoRes = 198,
  id_Global_ENB_ID = 199,
  id_UE_History_Information = 200,
  id_MBMSSynchronisationInformation = 201,
  id_SubscriberProfileIDforRFP = 202,
  id_CSG_Id    = 203,
  id_OldIuSigConIdCS = 204,
  id_OldIuSigConIdPS = 205,
  id_GlobalCN_IDCS = 206,
  id_GlobalCN_IDPS = 207,
  id_SourceExtendedRNC_ID = 208,
  id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes = 209,
  id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes = 210,
  id_SourceRNC_ID = 211,
  id_Relocation_TargetRNC_ID = 212,
  id_Relocation_TargetExtendedRNC_ID = 213,
  id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf = 214,
  id_Alt_RAB_Parameter_SupportedMaxBitrateInf = 215,
  id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList = 216,
  id_Ass_RAB_Parameter_SupportedMaxBitrateList = 217,
  id_RAB_Parameter_SupportedGuaranteedBitrateList = 218,
  id_RAB_Parameter_SupportedMaxBitrateList = 219,
  id_Requested_RAB_Parameter_SupportedMaxBitrateList = 220,
  id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList = 221,
  id_Relocation_SourceRNC_ID = 222,
  id_Relocation_SourceExtendedRNC_ID = 223,
  id_EncryptionKey = 224,
  id_IntegrityProtectionKey = 225,
  id_SRVCC_HO_Indication = 226,
  id_SRVCC_Information = 227,
  id_SRVCC_Operation_Possible = 228,
  id_CSG_Id_List = 229,
  id_PSRABtobeReplaced = 230,
  id_E_UTRAN_Service_Handover = 231,
  id_Not_Used_232 = 232,
  id_UE_AggregateMaximumBitRate = 233,
  id_CSG_Membership_Status = 234,
  id_Cell_Access_Mode = 235,
  id_IP_Source_Address = 236,
  id_CSFB_Information = 237,
  id_PDP_TypeInformation_extension = 238,
  id_MSISDN    = 239,
  id_Offload_RAB_Parameters = 240,
  id_LGW_TransportLayerAddress = 241,
  id_Correlation_ID = 242,
  id_IRAT_Measurement_Configuration = 243,
  id_MDT_Configuration = 244,
  id_Priority_Class_Indicator = 245,
  id_RNSAPRelocationParameters = 247,
  id_RABParametersList = 248,
  id_Management_Based_MDT_Allowed = 249,
  id_HigherBitratesThan16MbpsFlag = 250,
  id_Trace_Collection_Entity_IP_Addess = 251,
  id_End_Of_CSFB = 252,
  id_Time_UE_StayedInCell_EnhancedGranularity = 253,
  id_Out_Of_UTRAN = 254,
  id_TraceRecordingSessionReference = 255,
  id_IMSI      = 256,
  id_HO_Cause  = 257,
  id_VoiceSupportMatchIndicator = 258,
  id_RSRVCC_HO_Indication = 259,
  id_RSRVCC_Information = 260,
  id_AnchorPLMN_ID = 261,
  id_Tunnel_Information_for_BBF = 262,
  id_Management_Based_MDT_PLMN_List = 263,
  id_SignallingBasedMDTPLMNList = 264,
  id_M4Report  = 265,
  id_M5Report  = 266,
  id_M6Report  = 267,
  id_M7Report  = 268,
  id_TimingDifferenceULDL = 269,
  id_Serving_Cell_Identifier = 270,
  id_EARFCN_Extended = 271,
  id_RSRVCC_Operation_Possible = 272,
  id_SIPTO_LGW_TransportLayerAddress = 273,
  id_SIPTO_Correlation_ID = 274,
  id_LHN_ID    = 275,
  id_Session_Re_establishment_Indicator = 276,
  id_LastE_UTRANPLMNIdentity = 277,
  id_RSRQ_Type = 278,
  id_RSRQ_Extension = 279,
  id_Additional_CSPS_coordination_information = 280,
  id_UERegistrationQueryResult = 281,
  id_IuSigConIdRangeEnd = 282,
  id_BarometricPressure = 283,
  id_Additional_PositioningDataSet = 284,
  id_CivicAddress = 285,
  id_SGSN_Group_Identity = 286,
  id_P_TMSI    = 287,
  id_RANAP_Message = 288,
  id_PowerSavingIndicator = 289,
  id_UE_Usage_Type = 290,
  id_DCN_ID    = 291,
  id_UE_Application_Layer_Measurement_Configuration = 292,
  id_UE_Application_Layer_Measurement_Configuration_For_Relocation = 293
} ProtocolIE_ID_enum;

void proto_register_ranap(void);
void proto_reg_handoff_ranap(void);

/* Initialize the protocol and registered fields */
static int proto_ranap;

/* initialise sub-dissector handles */
static dissector_handle_t rrc_s_to_trnc_handle;
static dissector_handle_t rrc_t_to_srnc_handle;
static dissector_handle_t rrc_ho_to_utran_cmd;
static dissector_handle_t bssgp_handle;

static int hf_ranap_transportLayerAddress_ipv4;
static int hf_ranap_transportLayerAddress_ipv6;
static int hf_ranap_transportLayerAddress_nsap;

static int hf_ranap_AccuracyFulfilmentIndicator_PDU;  /* AccuracyFulfilmentIndicator */
static int hf_ranap_Additional_CSPS_coordination_information_PDU;  /* Additional_CSPS_coordination_information */
static int hf_ranap_Additional_PositioningDataSet_PDU;  /* Additional_PositioningDataSet */
static int hf_ranap_Alt_RAB_Parameters_PDU;       /* Alt_RAB_Parameters */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU;  /* Alt_RAB_Parameter_SupportedGuaranteedBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU;  /* Alt_RAB_Parameter_ExtendedMaxBitrateInf */
static int hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU;  /* Alt_RAB_Parameter_SupportedMaxBitrateInf */
static int hf_ranap_AlternativeRABConfigurationRequest_PDU;  /* AlternativeRABConfigurationRequest */
static int hf_ranap_UE_Application_Layer_Measurement_Configuration_PDU;  /* UE_Application_Layer_Measurement_Configuration */
static int hf_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation_PDU;  /* UE_Application_Layer_Measurement_Configuration_For_Relocation */
static int hf_ranap_APN_PDU;                      /* APN */
static int hf_ranap_AreaIdentity_PDU;             /* AreaIdentity */
static int hf_ranap_Ass_RAB_Parameters_PDU;       /* Ass_RAB_Parameters */
static int hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU;  /* Ass_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU;  /* Ass_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_BarometricPressure_PDU;       /* BarometricPressure */
static int hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU;  /* BroadcastAssistanceDataDecipheringKeys */
static int hf_ranap_ranap_Cause_PDU;              /* Cause */
static int hf_ranap_Cell_Access_Mode_PDU;         /* Cell_Access_Mode */
static int hf_ranap_CellLoadInformationGroup_PDU;  /* CellLoadInformationGroup */
static int hf_ranap_CivicAddress_PDU;             /* CivicAddress */
static int hf_ranap_ClientType_PDU;               /* ClientType */
static int hf_ranap_CriticalityDiagnostics_PDU;   /* CriticalityDiagnostics */
static int hf_ranap_MessageStructure_PDU;         /* MessageStructure */
static int hf_ranap_ChosenEncryptionAlgorithm_PDU;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_ranap_ClassmarkInformation2_PDU;    /* ClassmarkInformation2 */
static int hf_ranap_ClassmarkInformation3_PDU;    /* ClassmarkInformation3 */
static int hf_ranap_CN_DomainIndicator_PDU;       /* CN_DomainIndicator */
static int hf_ranap_Correlation_ID_PDU;           /* Correlation_ID */
static int hf_ranap_CSFB_Information_PDU;         /* CSFB_Information */
static int hf_ranap_CSG_Id_PDU;                   /* CSG_Id */
static int hf_ranap_CSG_Id_List_PDU;              /* CSG_Id_List */
static int hf_ranap_CSG_Membership_Status_PDU;    /* CSG_Membership_Status */
static int hf_ranap_DCN_ID_PDU;                   /* DCN_ID */
static int hf_ranap_DeltaRAListofIdleModeUEs_PDU;  /* DeltaRAListofIdleModeUEs */
static int hf_ranap_DRX_CycleLengthCoefficient_PDU;  /* DRX_CycleLengthCoefficient */
static int hf_ranap_EARFCN_Extended_PDU;          /* EARFCN_Extended */
static int hf_ranap_E_DCH_MAC_d_Flow_ID_PDU;      /* E_DCH_MAC_d_Flow_ID */
static int hf_ranap_EncryptionInformation_PDU;    /* EncryptionInformation */
static int hf_ranap_EncryptionKey_PDU;            /* EncryptionKey */
static int hf_ranap_End_Of_CSFB_PDU;              /* End_Of_CSFB */
static int hf_ranap_E_UTRAN_Service_Handover_PDU;  /* E_UTRAN_Service_Handover */
static int hf_ranap_ExtendedRNC_ID_PDU;           /* ExtendedRNC_ID */
static int hf_ranap_FrequenceLayerConvergenceFlag_PDU;  /* FrequenceLayerConvergenceFlag */
static int hf_ranap_GANSS_PositioningDataSet_PDU;  /* GANSS_PositioningDataSet */
static int hf_ranap_GERAN_BSC_Container_PDU;      /* GERAN_BSC_Container */
static int hf_ranap_GERAN_Classmark_PDU;          /* GERAN_Classmark */
static int hf_ranap_GlobalCN_ID_PDU;              /* GlobalCN_ID */
static int hf_ranap_GlobalRNC_ID_PDU;             /* GlobalRNC_ID */
static int hf_ranap_HigherBitratesThan16MbpsFlag_PDU;  /* HigherBitratesThan16MbpsFlag */
static int hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU;    /* HS_DSCH_MAC_d_Flow_ID */
static int hf_ranap_IMSI_PDU;                     /* IMSI */
static int hf_ranap_IncludeVelocity_PDU;          /* IncludeVelocity */
static int hf_ranap_InformationExchangeID_PDU;    /* InformationExchangeID */
static int hf_ranap_InformationExchangeType_PDU;  /* InformationExchangeType */
static int hf_ranap_InformationRequested_PDU;     /* InformationRequested */
static int hf_ranap_InformationRequestType_PDU;   /* InformationRequestType */
static int hf_ranap_InformationTransferID_PDU;    /* InformationTransferID */
static int hf_ranap_InformationTransferType_PDU;  /* InformationTransferType */
static int hf_ranap_IntegrityProtectionInformation_PDU;  /* IntegrityProtectionInformation */
static int hf_ranap_IntegrityProtectionKey_PDU;   /* IntegrityProtectionKey */
static int hf_ranap_InterSystemInformationTransferType_PDU;  /* InterSystemInformationTransferType */
static int hf_ranap_ranap_InterSystemInformation_TransparentContainer_PDU;  /* InterSystemInformation_TransparentContainer */
static int hf_ranap_IPMulticastAddress_PDU;       /* IPMulticastAddress */
static int hf_ranap_IuSignallingConnectionIdentifier_PDU;  /* IuSignallingConnectionIdentifier */
static int hf_ranap_IuTransportAssociation_PDU;   /* IuTransportAssociation */
static int hf_ranap_KeyStatus_PDU;                /* KeyStatus */
static int hf_ranap_LAI_PDU;                      /* LAI */
static int hf_ranap_LastKnownServiceArea_PDU;     /* LastKnownServiceArea */
static int hf_ranap_ranap_LastVisitedUTRANCell_Item_PDU;  /* LastVisitedUTRANCell_Item */
static int hf_ranap_LHN_ID_PDU;                   /* LHN_ID */
static int hf_ranap_LocationRelatedDataRequestType_PDU;  /* LocationRelatedDataRequestType */
static int hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU;  /* LocationRelatedDataRequestTypeSpecificToGERANIuMode */
static int hf_ranap_L3_Information_PDU;           /* L3_Information */
static int hf_ranap_M4Report_PDU;                 /* M4Report */
static int hf_ranap_M5Report_PDU;                 /* M5Report */
static int hf_ranap_M6Report_PDU;                 /* M6Report */
static int hf_ranap_M7Report_PDU;                 /* M7Report */
static int hf_ranap_Management_Based_MDT_Allowed_PDU;  /* Management_Based_MDT_Allowed */
static int hf_ranap_MBMSBearerServiceType_PDU;    /* MBMSBearerServiceType */
static int hf_ranap_MBMSCNDe_Registration_PDU;    /* MBMSCNDe_Registration */
static int hf_ranap_MBMSCountingInformation_PDU;  /* MBMSCountingInformation */
static int hf_ranap_MBMSLinkingInformation_PDU;   /* MBMSLinkingInformation */
static int hf_ranap_MBMSRegistrationRequestType_PDU;  /* MBMSRegistrationRequestType */
static int hf_ranap_MBMSServiceArea_PDU;          /* MBMSServiceArea */
static int hf_ranap_MBMSSessionDuration_PDU;      /* MBMSSessionDuration */
static int hf_ranap_MBMSSessionIdentity_PDU;      /* MBMSSessionIdentity */
static int hf_ranap_MBMSSessionRepetitionNumber_PDU;  /* MBMSSessionRepetitionNumber */
static int hf_ranap_MDT_Configuration_PDU;        /* MDT_Configuration */
static int hf_ranap_MDT_PLMN_List_PDU;            /* MDT_PLMN_List */
static int hf_ranap_MSISDN_PDU;                   /* MSISDN */
static int hf_ranap_NAS_PDU_PDU;                  /* NAS_PDU */
static int hf_ranap_NAS_SequenceNumber_PDU;       /* NAS_SequenceNumber */
static int hf_ranap_NewBSS_To_OldBSS_Information_PDU;  /* NewBSS_To_OldBSS_Information */
static int hf_ranap_NonSearchingIndication_PDU;   /* NonSearchingIndication */
static int hf_ranap_NumberOfSteps_PDU;            /* NumberOfSteps */
static int hf_ranap_Offload_RAB_Parameters_PDU;   /* Offload_RAB_Parameters */
static int hf_ranap_OldBSS_ToNewBSS_Information_PDU;  /* OldBSS_ToNewBSS_Information */
static int hf_ranap_OMC_ID_PDU;                   /* OMC_ID */
static int hf_ranap_Out_Of_UTRAN_PDU;             /* Out_Of_UTRAN */
static int hf_ranap_PagingAreaID_PDU;             /* PagingAreaID */
static int hf_ranap_PagingCause_PDU;              /* PagingCause */
static int hf_ranap_PDP_TypeInformation_PDU;      /* PDP_TypeInformation */
static int hf_ranap_PDP_TypeInformation_extension_PDU;  /* PDP_TypeInformation_extension */
static int hf_ranap_PeriodicLocationInfo_PDU;     /* PeriodicLocationInfo */
static int hf_ranap_PermanentNAS_UE_ID_PDU;       /* PermanentNAS_UE_ID */
static int hf_ranap_PLMNidentity_PDU;             /* PLMNidentity */
static int hf_ranap_PositioningPriority_PDU;      /* PositioningPriority */
static int hf_ranap_PositionData_PDU;             /* PositionData */
static int hf_ranap_PositionDataSpecificToGERANIuMode_PDU;  /* PositionDataSpecificToGERANIuMode */
static int hf_ranap_Priority_Class_Indicator_PDU;  /* Priority_Class_Indicator */
static int hf_ranap_ProvidedData_PDU;             /* ProvidedData */
static int hf_ranap_PowerSavingIndicator_PDU;     /* PowerSavingIndicator */
static int hf_ranap_P_TMSI_PDU;                   /* P_TMSI */
static int hf_ranap_RAB_ID_PDU;                   /* RAB_ID */
static int hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU;  /* RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU;  /* RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_RAB_Parameters_PDU;           /* RAB_Parameters */
static int hf_ranap_RABParametersList_PDU;        /* RABParametersList */
static int hf_ranap_RAC_PDU;                      /* RAC */
static int hf_ranap_RAListofIdleModeUEs_PDU;      /* RAListofIdleModeUEs */
static int hf_ranap_LAListofIdleModeUEs_PDU;      /* LAListofIdleModeUEs */
static int hf_ranap_RAT_Type_PDU;                 /* RAT_Type */
static int hf_ranap_RedirectAttemptFlag_PDU;      /* RedirectAttemptFlag */
static int hf_ranap_RedirectionCompleted_PDU;     /* RedirectionCompleted */
static int hf_ranap_RejectCauseValue_PDU;         /* RejectCauseValue */
static int hf_ranap_RelocationType_PDU;           /* RelocationType */
static int hf_ranap_RequestedGANSSAssistanceData_PDU;  /* RequestedGANSSAssistanceData */
static int hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU;  /* Requested_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU;  /* Requested_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_RequestType_PDU;              /* RequestType */
static int hf_ranap_ResponseTime_PDU;             /* ResponseTime */
static int hf_ranap_RNSAPRelocationParameters_PDU;  /* RNSAPRelocationParameters */
static int hf_ranap_RRC_Container_PDU;            /* RRC_Container */
static int hf_ranap_RSRVCC_HO_Indication_PDU;     /* RSRVCC_HO_Indication */
static int hf_ranap_RSRVCC_Information_PDU;       /* RSRVCC_Information */
static int hf_ranap_RSRVCC_Operation_Possible_PDU;  /* RSRVCC_Operation_Possible */
static int hf_ranap_SAI_PDU;                      /* SAI */
static int hf_ranap_SAPI_PDU;                     /* SAPI */
static int hf_ranap_SessionUpdateID_PDU;          /* SessionUpdateID */
static int hf_ranap_Session_Re_establishment_Indicator_PDU;  /* Session_Re_establishment_Indicator */
static int hf_ranap_SignallingIndication_PDU;     /* SignallingIndication */
static int hf_ranap_SGSN_Group_Identity_PDU;      /* SGSN_Group_Identity */
static int hf_ranap_SNA_Access_Information_PDU;   /* SNA_Access_Information */
static int hf_ranap_ranap_Source_ToTarget_TransparentContainer_PDU;  /* Source_ToTarget_TransparentContainer */
static int hf_ranap_ranap_SourceCellID_PDU;       /* SourceCellID */
static int hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU;  /* SourceBSS_ToTargetBSS_TransparentContainer */
static int hf_ranap_SourceID_PDU;                 /* SourceID */
static int hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU;  /* SourceRNC_ToTargetRNC_TransparentContainer */
static int hf_ranap_IRAT_Measurement_Configuration_PDU;  /* IRAT_Measurement_Configuration */
static int hf_ranap_RSRQ_Type_PDU;                /* RSRQ_Type */
static int hf_ranap_RSRQ_Extension_PDU;           /* RSRQ_Extension */
static int hf_ranap_SubscriberProfileIDforRFP_PDU;  /* SubscriberProfileIDforRFP */
static int hf_ranap_SupportedRAB_ParameterBitrateList_PDU;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_SRB_TrCH_Mapping_PDU;         /* SRB_TrCH_Mapping */
static int hf_ranap_SRVCC_HO_Indication_PDU;      /* SRVCC_HO_Indication */
static int hf_ranap_SRVCC_Information_PDU;        /* SRVCC_Information */
static int hf_ranap_SRVCC_Operation_Possible_PDU;  /* SRVCC_Operation_Possible */
static int hf_ranap_Target_ToSource_TransparentContainer_PDU;  /* Target_ToSource_TransparentContainer */
static int hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU;  /* TargetBSS_ToSourceBSS_TransparentContainer */
static int hf_ranap_TargetID_PDU;                 /* TargetID */
static int hf_ranap_ranap_TargetRNC_ID_PDU;       /* TargetRNC_ID */
static int hf_ranap_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU;  /* TargetRNC_ToSourceRNC_TransparentContainer */
static int hf_ranap_TemporaryUE_ID_PDU;           /* TemporaryUE_ID */
static int hf_ranap_Time_UE_StayedInCell_EnhancedGranularity_PDU;  /* Time_UE_StayedInCell_EnhancedGranularity */
static int hf_ranap_TimeToMBMSDataTransfer_PDU;   /* TimeToMBMSDataTransfer */
static int hf_ranap_TimingDifferenceULDL_PDU;     /* TimingDifferenceULDL */
static int hf_ranap_TMGI_PDU;                     /* TMGI */
static int hf_ranap_TracePropagationParameters_PDU;  /* TracePropagationParameters */
static int hf_ranap_TraceRecordingSessionInformation_PDU;  /* TraceRecordingSessionInformation */
static int hf_ranap_TraceRecordingSessionReference_PDU;  /* TraceRecordingSessionReference */
static int hf_ranap_TraceReference_PDU;           /* TraceReference */
static int hf_ranap_TraceType_PDU;                /* TraceType */
static int hf_ranap_TransportLayerAddress_PDU;    /* TransportLayerAddress */
static int hf_ranap_TriggerID_PDU;                /* TriggerID */
static int hf_ranap_TunnelInformation_PDU;        /* TunnelInformation */
static int hf_ranap_TypeOfError_PDU;              /* TypeOfError */
static int hf_ranap_UE_AggregateMaximumBitRate_PDU;  /* UE_AggregateMaximumBitRate */
static int hf_ranap_UE_History_Information_PDU;   /* UE_History_Information */
static int hf_ranap_UE_ID_PDU;                    /* UE_ID */
static int hf_ranap_UE_Usage_Type_PDU;            /* UE_Usage_Type */
static int hf_ranap_UERegistrationQueryResult_PDU;  /* UERegistrationQueryResult */
static int hf_ranap_UESBI_Iu_PDU;                 /* UESBI_Iu */
static int hf_ranap_UTRAN_CellID_PDU;             /* UTRAN_CellID */
static int hf_ranap_VelocityEstimate_PDU;         /* VelocityEstimate */
static int hf_ranap_VerticalAccuracyCode_PDU;     /* VerticalAccuracyCode */
static int hf_ranap_VoiceSupportMatchIndicator_PDU;  /* VoiceSupportMatchIndicator */
static int hf_ranap_Iu_ReleaseCommand_PDU;        /* Iu_ReleaseCommand */
static int hf_ranap_Iu_ReleaseComplete_PDU;       /* Iu_ReleaseComplete */
static int hf_ranap_RAB_DataVolumeReportList_PDU;  /* RAB_DataVolumeReportList */
static int hf_ranap_RAB_DataVolumeReportItem_PDU;  /* RAB_DataVolumeReportItem */
static int hf_ranap_RAB_ReleasedList_IuRelComp_PDU;  /* RAB_ReleasedList_IuRelComp */
static int hf_ranap_RAB_ReleasedItem_IuRelComp_PDU;  /* RAB_ReleasedItem_IuRelComp */
static int hf_ranap_RelocationRequired_PDU;       /* RelocationRequired */
static int hf_ranap_RelocationCommand_PDU;        /* RelocationCommand */
static int hf_ranap_RAB_RelocationReleaseList_PDU;  /* RAB_RelocationReleaseList */
static int hf_ranap_RAB_RelocationReleaseItem_PDU;  /* RAB_RelocationReleaseItem */
static int hf_ranap_RAB_DataForwardingList_PDU;   /* RAB_DataForwardingList */
static int hf_ranap_RAB_DataForwardingItem_PDU;   /* RAB_DataForwardingItem */
static int hf_ranap_RelocationPreparationFailure_PDU;  /* RelocationPreparationFailure */
static int hf_ranap_RelocationRequest_PDU;        /* RelocationRequest */
static int hf_ranap_RAB_SetupList_RelocReq_PDU;   /* RAB_SetupList_RelocReq */
static int hf_ranap_RAB_SetupItem_RelocReq_PDU;   /* RAB_SetupItem_RelocReq */
static int hf_ranap_CNMBMSLinkingInformation_PDU;  /* CNMBMSLinkingInformation */
static int hf_ranap_JoinedMBMSBearerService_IEs_PDU;  /* JoinedMBMSBearerService_IEs */
static int hf_ranap_RelocationRequestAcknowledge_PDU;  /* RelocationRequestAcknowledge */
static int hf_ranap_RAB_SetupList_RelocReqAck_PDU;  /* RAB_SetupList_RelocReqAck */
static int hf_ranap_RAB_SetupItem_RelocReqAck_PDU;  /* RAB_SetupItem_RelocReqAck */
static int hf_ranap_RAB_FailedList_PDU;           /* RAB_FailedList */
static int hf_ranap_RAB_FailedItem_PDU;           /* RAB_FailedItem */
static int hf_ranap_RelocationFailure_PDU;        /* RelocationFailure */
static int hf_ranap_RelocationCancel_PDU;         /* RelocationCancel */
static int hf_ranap_RelocationCancelAcknowledge_PDU;  /* RelocationCancelAcknowledge */
static int hf_ranap_SRNS_ContextRequest_PDU;      /* SRNS_ContextRequest */
static int hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU;  /* RAB_DataForwardingList_SRNS_CtxReq */
static int hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU;  /* RAB_DataForwardingItem_SRNS_CtxReq */
static int hf_ranap_SRNS_ContextResponse_PDU;     /* SRNS_ContextResponse */
static int hf_ranap_RAB_ContextList_PDU;          /* RAB_ContextList */
static int hf_ranap_RAB_ContextItem_PDU;          /* RAB_ContextItem */
static int hf_ranap_RAB_ContextFailedtoTransferList_PDU;  /* RAB_ContextFailedtoTransferList */
static int hf_ranap_RABs_ContextFailedtoTransferItem_PDU;  /* RABs_ContextFailedtoTransferItem */
static int hf_ranap_SecurityModeCommand_PDU;      /* SecurityModeCommand */
static int hf_ranap_SecurityModeComplete_PDU;     /* SecurityModeComplete */
static int hf_ranap_SecurityModeReject_PDU;       /* SecurityModeReject */
static int hf_ranap_DataVolumeReportRequest_PDU;  /* DataVolumeReportRequest */
static int hf_ranap_RAB_DataVolumeReportRequestList_PDU;  /* RAB_DataVolumeReportRequestList */
static int hf_ranap_RAB_DataVolumeReportRequestItem_PDU;  /* RAB_DataVolumeReportRequestItem */
static int hf_ranap_DataVolumeReport_PDU;         /* DataVolumeReport */
static int hf_ranap_RAB_FailedtoReportList_PDU;   /* RAB_FailedtoReportList */
static int hf_ranap_RABs_failed_to_reportItem_PDU;  /* RABs_failed_to_reportItem */
static int hf_ranap_Reset_PDU;                    /* Reset */
static int hf_ranap_ResetAcknowledge_PDU;         /* ResetAcknowledge */
static int hf_ranap_ResetResource_PDU;            /* ResetResource */
static int hf_ranap_ResetResourceList_PDU;        /* ResetResourceList */
static int hf_ranap_ResetResourceItem_PDU;        /* ResetResourceItem */
static int hf_ranap_ResetResourceAcknowledge_PDU;  /* ResetResourceAcknowledge */
static int hf_ranap_ResetResourceAckList_PDU;     /* ResetResourceAckList */
static int hf_ranap_ResetResourceAckItem_PDU;     /* ResetResourceAckItem */
static int hf_ranap_RAB_ReleaseRequest_PDU;       /* RAB_ReleaseRequest */
static int hf_ranap_RAB_ReleaseList_PDU;          /* RAB_ReleaseList */
static int hf_ranap_RAB_ReleaseItem_PDU;          /* RAB_ReleaseItem */
static int hf_ranap_Iu_ReleaseRequest_PDU;        /* Iu_ReleaseRequest */
static int hf_ranap_RelocationDetect_PDU;         /* RelocationDetect */
static int hf_ranap_RelocationComplete_PDU;       /* RelocationComplete */
static int hf_ranap_EnhancedRelocationCompleteRequest_PDU;  /* EnhancedRelocationCompleteRequest */
static int hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU;  /* RAB_SetupList_EnhancedRelocCompleteReq */
static int hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU;  /* RAB_SetupItem_EnhancedRelocCompleteReq */
static int hf_ranap_EnhancedRelocationCompleteResponse_PDU;  /* EnhancedRelocationCompleteResponse */
static int hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU;  /* RAB_SetupList_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU;  /* RAB_SetupItem_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU;  /* RAB_ToBeReleasedList_EnhancedRelocCompleteRes */
static int hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU;  /* RAB_ToBeReleasedItem_EnhancedRelocCompleteRes */
static int hf_ranap_EnhancedRelocationCompleteFailure_PDU;  /* EnhancedRelocationCompleteFailure */
static int hf_ranap_EnhancedRelocationCompleteConfirm_PDU;  /* EnhancedRelocationCompleteConfirm */
static int hf_ranap_Paging_PDU;                   /* Paging */
static int hf_ranap_CommonID_PDU;                 /* CommonID */
static int hf_ranap_CN_InvokeTrace_PDU;           /* CN_InvokeTrace */
static int hf_ranap_CN_DeactivateTrace_PDU;       /* CN_DeactivateTrace */
static int hf_ranap_LocationReportingControl_PDU;  /* LocationReportingControl */
static int hf_ranap_LocationReport_PDU;           /* LocationReport */
static int hf_ranap_InitialUE_Message_PDU;        /* InitialUE_Message */
static int hf_ranap_DirectTransfer_PDU;           /* DirectTransfer */
static int hf_ranap_RedirectionIndication_PDU;    /* RedirectionIndication */
static int hf_ranap_Overload_PDU;                 /* Overload */
static int hf_ranap_ErrorIndication_PDU;          /* ErrorIndication */
static int hf_ranap_SRNS_DataForwardCommand_PDU;  /* SRNS_DataForwardCommand */
static int hf_ranap_ForwardSRNS_Context_PDU;      /* ForwardSRNS_Context */
static int hf_ranap_RAB_AssignmentRequest_PDU;    /* RAB_AssignmentRequest */
static int hf_ranap_RAB_SetupOrModifyList_PDU;    /* RAB_SetupOrModifyList */
static int hf_ranap_RAB_SetupOrModifyItemFirst_PDU;  /* RAB_SetupOrModifyItemFirst */
static int hf_ranap_TransportLayerInformation_PDU;  /* TransportLayerInformation */
static int hf_ranap_RAB_SetupOrModifyItemSecond_PDU;  /* RAB_SetupOrModifyItemSecond */
static int hf_ranap_RAB_AssignmentResponse_PDU;   /* RAB_AssignmentResponse */
static int hf_ranap_RAB_SetupOrModifiedList_PDU;  /* RAB_SetupOrModifiedList */
static int hf_ranap_RAB_SetupOrModifiedItem_PDU;  /* RAB_SetupOrModifiedItem */
static int hf_ranap_RAB_ReleasedList_PDU;         /* RAB_ReleasedList */
static int hf_ranap_RAB_ReleasedItem_PDU;         /* RAB_ReleasedItem */
static int hf_ranap_RAB_QueuedList_PDU;           /* RAB_QueuedList */
static int hf_ranap_RAB_QueuedItem_PDU;           /* RAB_QueuedItem */
static int hf_ranap_RAB_ReleaseFailedList_PDU;    /* RAB_ReleaseFailedList */
static int hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU;  /* GERAN_Iumode_RAB_FailedList_RABAssgntResponse */
static int hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU;  /* GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item */
static int hf_ranap_PrivateMessage_PDU;           /* PrivateMessage */
static int hf_ranap_RANAP_RelocationInformation_PDU;  /* RANAP_RelocationInformation */
static int hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU;  /* DirectTransferInformationList_RANAP_RelocInf */
static int hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU;  /* DirectTransferInformationItem_RANAP_RelocInf */
static int hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU;  /* RAB_ContextList_RANAP_RelocInf */
static int hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU;  /* RAB_ContextItem_RANAP_RelocInf */
static int hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU;  /* RANAP_EnhancedRelocationInformationRequest */
static int hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU;  /* RAB_SetupList_EnhRelocInfoReq */
static int hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU;  /* RAB_SetupItem_EnhRelocInfoReq */
static int hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU;  /* RANAP_EnhancedRelocationInformationResponse */
static int hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU;  /* RAB_SetupList_EnhRelocInfoRes */
static int hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU;  /* RAB_SetupItem_EnhRelocInfoRes */
static int hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU;  /* RAB_FailedList_EnhRelocInfoRes */
static int hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU;  /* RAB_FailedItem_EnhRelocInfoRes */
static int hf_ranap_RAB_ModifyRequest_PDU;        /* RAB_ModifyRequest */
static int hf_ranap_RAB_ModifyList_PDU;           /* RAB_ModifyList */
static int hf_ranap_RAB_ModifyItem_PDU;           /* RAB_ModifyItem */
static int hf_ranap_LocationRelatedDataRequest_PDU;  /* LocationRelatedDataRequest */
static int hf_ranap_LocationRelatedDataResponse_PDU;  /* LocationRelatedDataResponse */
static int hf_ranap_LocationRelatedDataFailure_PDU;  /* LocationRelatedDataFailure */
static int hf_ranap_InformationTransferIndication_PDU;  /* InformationTransferIndication */
static int hf_ranap_InformationTransferConfirmation_PDU;  /* InformationTransferConfirmation */
static int hf_ranap_InformationTransferFailure_PDU;  /* InformationTransferFailure */
static int hf_ranap_UESpecificInformationIndication_PDU;  /* UESpecificInformationIndication */
static int hf_ranap_DirectInformationTransfer_PDU;  /* DirectInformationTransfer */
static int hf_ranap_UplinkInformationExchangeRequest_PDU;  /* UplinkInformationExchangeRequest */
static int hf_ranap_UplinkInformationExchangeResponse_PDU;  /* UplinkInformationExchangeResponse */
static int hf_ranap_UplinkInformationExchangeFailure_PDU;  /* UplinkInformationExchangeFailure */
static int hf_ranap_MBMSSessionStart_PDU;         /* MBMSSessionStart */
static int hf_ranap_MBMSSynchronisationInformation_PDU;  /* MBMSSynchronisationInformation */
static int hf_ranap_MBMSSessionStartResponse_PDU;  /* MBMSSessionStartResponse */
static int hf_ranap_MBMSSessionStartFailure_PDU;  /* MBMSSessionStartFailure */
static int hf_ranap_MBMSSessionUpdate_PDU;        /* MBMSSessionUpdate */
static int hf_ranap_MBMSSessionUpdateResponse_PDU;  /* MBMSSessionUpdateResponse */
static int hf_ranap_MBMSSessionUpdateFailure_PDU;  /* MBMSSessionUpdateFailure */
static int hf_ranap_MBMSSessionStop_PDU;          /* MBMSSessionStop */
static int hf_ranap_MBMSSessionStopResponse_PDU;  /* MBMSSessionStopResponse */
static int hf_ranap_MBMSUELinkingRequest_PDU;     /* MBMSUELinkingRequest */
static int hf_ranap_LeftMBMSBearerService_IEs_PDU;  /* LeftMBMSBearerService_IEs */
static int hf_ranap_MBMSUELinkingResponse_PDU;    /* MBMSUELinkingResponse */
static int hf_ranap_UnsuccessfulLinking_IEs_PDU;  /* UnsuccessfulLinking_IEs */
static int hf_ranap_MBMSRegistrationRequest_PDU;  /* MBMSRegistrationRequest */
static int hf_ranap_MBMSRegistrationResponse_PDU;  /* MBMSRegistrationResponse */
static int hf_ranap_MBMSRegistrationFailure_PDU;  /* MBMSRegistrationFailure */
static int hf_ranap_MBMSCNDe_RegistrationRequest_PDU;  /* MBMSCNDe_RegistrationRequest */
static int hf_ranap_MBMSCNDe_RegistrationResponse_PDU;  /* MBMSCNDe_RegistrationResponse */
static int hf_ranap_MBMSRABEstablishmentIndication_PDU;  /* MBMSRABEstablishmentIndication */
static int hf_ranap_MBMSRABReleaseRequest_PDU;    /* MBMSRABReleaseRequest */
static int hf_ranap_MBMSRABRelease_PDU;           /* MBMSRABRelease */
static int hf_ranap_MBMSRABReleaseFailure_PDU;    /* MBMSRABReleaseFailure */
static int hf_ranap_SRVCC_CSKeysRequest_PDU;      /* SRVCC_CSKeysRequest */
static int hf_ranap_SRVCC_CSKeysResponse_PDU;     /* SRVCC_CSKeysResponse */
static int hf_ranap_UeRadioCapabilityMatchRequest_PDU;  /* UeRadioCapabilityMatchRequest */
static int hf_ranap_UeRadioCapabilityMatchResponse_PDU;  /* UeRadioCapabilityMatchResponse */
static int hf_ranap_UeRegistrationQueryRequest_PDU;  /* UeRegistrationQueryRequest */
static int hf_ranap_UeRegistrationQueryResponse_PDU;  /* UeRegistrationQueryResponse */
static int hf_ranap_RerouteNASRequest_PDU;        /* RerouteNASRequest */
static int hf_ranap_RANAP_PDU_PDU;                /* RANAP_PDU */
static int hf_ranap_local;                        /* INTEGER_0_65535 */
static int hf_ranap_global;                       /* OBJECT_IDENTIFIER */
static int hf_ranap_ProtocolIE_Container_item;    /* ProtocolIE_Field */
static int hf_ranap_id;                           /* ProtocolIE_ID */
static int hf_ranap_criticality;                  /* Criticality */
static int hf_ranap_ie_field_value;               /* T_ie_field_value */
static int hf_ranap_ProtocolIE_ContainerPair_item;  /* ProtocolIE_FieldPair */
static int hf_ranap_firstCriticality;             /* Criticality */
static int hf_ranap_firstValue;                   /* T_firstValue */
static int hf_ranap_secondCriticality;            /* Criticality */
static int hf_ranap_secondValue;                  /* T_secondValue */
static int hf_ranap_ProtocolIE_ContainerList_item;  /* ProtocolIE_Container */
static int hf_ranap_ProtocolIE_ContainerPairList_item;  /* ProtocolIE_ContainerPair */
static int hf_ranap_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_ranap_ext_id;                       /* ProtocolExtensionID */
static int hf_ranap_extensionValue;               /* T_extensionValue */
static int hf_ranap_PrivateIE_Container_item;     /* PrivateIE_Field */
static int hf_ranap_private_id;                   /* PrivateIE_ID */
static int hf_ranap_private_value;                /* T_private_value */
static int hf_ranap_old_LAI;                      /* LAI */
static int hf_ranap_old_RAC;                      /* RAC */
static int hf_ranap_nRI;                          /* BIT_STRING_SIZE_10 */
static int hf_ranap_uE_is_Attaching;              /* NULL */
static int hf_ranap_iE_Extensions;                /* ProtocolExtensionContainer */
static int hf_ranap_Additional_PositioningDataSet_item;  /* Additional_PositioningMethodAndUsage */
static int hf_ranap_priorityLevel;                /* PriorityLevel */
static int hf_ranap_pre_emptionCapability;        /* Pre_emptionCapability */
static int hf_ranap_pre_emptionVulnerability;     /* Pre_emptionVulnerability */
static int hf_ranap_queuingAllowed;               /* QueuingAllowed */
static int hf_ranap_altMaxBitrateInf;             /* Alt_RAB_Parameter_MaxBitrateInf */
static int hf_ranap_altGuaranteedBitRateInf;      /* Alt_RAB_Parameter_GuaranteedBitrateInf */
static int hf_ranap_altExtendedGuaranteedBitrateType;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altExtendedGuaranteedBitrates;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item;  /* Alt_RAB_Parameter_ExtendedGuaranteedBitrateList */
static int hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_altGuaranteedBitrateType;     /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altGuaranteedBitrates;        /* Alt_RAB_Parameter_GuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item;  /* Alt_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item;  /* GuaranteedBitrate */
static int hf_ranap_altSupportedGuaranteedBitrateType;  /* Alt_RAB_Parameter_GuaranteedBitrateType */
static int hf_ranap_altSupportedGuaranteedBitrates;  /* Alt_RAB_Parameter_SupportedGuaranteedBitrates */
static int hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_altExtendedMaxBitrateType;    /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altExtendedMaxBitrates;       /* Alt_RAB_Parameter_ExtendedMaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item;  /* Alt_RAB_Parameter_ExtendedMaxBitrateList */
static int hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item;  /* ExtendedMaxBitrate */
static int hf_ranap_altMaxBitrateType;            /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altMaxBitrates;               /* Alt_RAB_Parameter_MaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrates_item;  /* Alt_RAB_Parameter_MaxBitrateList */
static int hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item;  /* MaxBitrate */
static int hf_ranap_altSupportedMaxBitrateType;   /* Alt_RAB_Parameter_MaxBitrateType */
static int hf_ranap_altSupportedMaxBitrates;      /* Alt_RAB_Parameter_SupportedMaxBitrates */
static int hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item;  /* SupportedRAB_ParameterBitrateList */
static int hf_ranap_applicationLayerContainerForMeasurementConfiguration;  /* OCTET_STRING_SIZE_1_1000 */
static int hf_ranap_areaScopeForUEApplicationLayerMeasurementConfiguration;  /* AreaScopeForUEApplicationLayerMeasurementConfiguration */
static int hf_ranap_traceReference;               /* TraceReference */
static int hf_ranap_tracePropagationParameters;   /* TracePropagationParameters */
static int hf_ranap_traceCollectionEntityIPAddress;  /* TransportLayerAddress */
static int hf_ranap_cellbased;                    /* CellBased */
static int hf_ranap_labased;                      /* LABased */
static int hf_ranap_rabased;                      /* RABased */
static int hf_ranap_plmn_area_based;              /* PLMNBased */
static int hf_ranap_sAI;                          /* SAI */
static int hf_ranap_geographicalArea;             /* GeographicalArea */
static int hf_ranap_assMaxBitrateInf;             /* Ass_RAB_Parameter_MaxBitrateList */
static int hf_ranap_assGuaranteedBitRateInf;      /* Ass_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item;  /* ExtendedMaxBitrate */
static int hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item;  /* GuaranteedBitrate */
static int hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item;  /* MaxBitrate */
static int hf_ranap_AuthorisedPLMNs_item;         /* AuthorisedPLMNs_item */
static int hf_ranap_pLMNidentity;                 /* PLMNidentity */
static int hf_ranap_authorisedSNAsList;           /* AuthorisedSNAs */
static int hf_ranap_AuthorisedSNAs_item;          /* SNAC */
static int hf_ranap_cipheringKeyFlag;             /* BIT_STRING_SIZE_1 */
static int hf_ranap_currentDecipheringKey;        /* BIT_STRING_SIZE_56 */
static int hf_ranap_nextDecipheringKey;           /* BIT_STRING_SIZE_56 */
static int hf_ranap_radioNetwork;                 /* CauseRadioNetwork */
static int hf_ranap_transmissionNetwork;          /* CauseTransmissionNetwork */
static int hf_ranap_nAS;                          /* CauseNAS */
static int hf_ranap_protocol;                     /* CauseProtocol */
static int hf_ranap_misc;                         /* CauseMisc */
static int hf_ranap_non_Standard;                 /* CauseNon_Standard */
static int hf_ranap_radioNetworkExtension;        /* CauseRadioNetworkExtension */
static int hf_ranap_cellIdList;                   /* CellIdList */
static int hf_ranap_CellIdList_item;              /* Cell_Id */
static int hf_ranap_cell_Capacity_Class_Value;    /* Cell_Capacity_Class_Value */
static int hf_ranap_loadValue;                    /* LoadValue */
static int hf_ranap_rTLoadValue;                  /* RTLoadValue */
static int hf_ranap_nRTLoadInformationValue;      /* NRTLoadInformationValue */
static int hf_ranap_sourceCellID;                 /* SourceCellID */
static int hf_ranap_uplinkCellLoadInformation;    /* CellLoadInformation */
static int hf_ranap_downlinkCellLoadInformation;  /* CellLoadInformation */
static int hf_ranap_procedureCode;                /* ProcedureCode */
static int hf_ranap_triggeringMessage;            /* TriggeringMessage */
static int hf_ranap_procedureCriticality;         /* Criticality */
static int hf_ranap_iEsCriticalityDiagnostics;    /* CriticalityDiagnostics_IE_List */
static int hf_ranap_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_ranap_iECriticality;                /* Criticality */
static int hf_ranap_iE_ID;                        /* ProtocolIE_ID */
static int hf_ranap_repetitionNumber;             /* RepetitionNumber0 */
static int hf_ranap_MessageStructure_item;        /* MessageStructure_item */
static int hf_ranap_item_repetitionNumber;        /* RepetitionNumber1 */
static int hf_ranap_lAC;                          /* LAC */
static int hf_ranap_cI;                           /* CI */
static int hf_ranap_CSG_Id_List_item;             /* CSG_Id */
static int hf_ranap_newRAListofIdleModeUEs;       /* NewRAListofIdleModeUEs */
static int hf_ranap_rAListwithNoIdleModeUEsAnyMore;  /* RAListwithNoIdleModeUEsAnyMore */
static int hf_ranap_NewRAListofIdleModeUEs_item;  /* RAC */
static int hf_ranap_RAListwithNoIdleModeUEsAnyMore_item;  /* RAC */
static int hf_ranap_macroENB_ID;                  /* BIT_STRING_SIZE_20 */
static int hf_ranap_homeENB_ID;                   /* BIT_STRING_SIZE_28 */
static int hf_ranap_short_macroENB_ID;            /* BIT_STRING_SIZE_18 */
static int hf_ranap_long_macroENB_ID;             /* BIT_STRING_SIZE_21 */
static int hf_ranap_permittedAlgorithms;          /* PermittedEncryptionAlgorithms */
static int hf_ranap_key;                          /* EncryptionKey */
static int hf_ranap_iMEIlist;                     /* IMEIList */
static int hf_ranap_iMEISVlist;                   /* IMEISVList */
static int hf_ranap_iMEIgroup;                    /* IMEIGroup */
static int hf_ranap_iMEISVgroup;                  /* IMEISVGroup */
static int hf_ranap_measurementQuantity;          /* MeasurementQuantity */
static int hf_ranap_threshold;                    /* INTEGER_M120_165 */
static int hf_ranap_threshold_01;                 /* INTEGER_M120_M25 */
static int hf_ranap_GANSS_PositioningDataSet_item;  /* GANSS_PositioningMethodAndUsage */
static int hf_ranap_point;                        /* GA_Point */
static int hf_ranap_pointWithUnCertainty;         /* GA_PointWithUnCertainty */
static int hf_ranap_polygon;                      /* GA_Polygon */
static int hf_ranap_pointWithUncertaintyEllipse;  /* GA_PointWithUnCertaintyEllipse */
static int hf_ranap_pointWithAltitude;            /* GA_PointWithAltitude */
static int hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid;  /* GA_PointWithAltitudeAndUncertaintyEllipsoid */
static int hf_ranap_ellipsoidArc;                 /* GA_EllipsoidArc */
static int hf_ranap_latitudeSign;                 /* T_latitudeSign */
static int hf_ranap_latitude;                     /* INTEGER_0_8388607 */
static int hf_ranap_longitude;                    /* INTEGER_M8388608_8388607 */
static int hf_ranap_directionOfAltitude;          /* T_directionOfAltitude */
static int hf_ranap_altitude;                     /* INTEGER_0_32767 */
static int hf_ranap_geographicalCoordinates;      /* GeographicalCoordinates */
static int hf_ranap_innerRadius;                  /* INTEGER_0_65535 */
static int hf_ranap_uncertaintyRadius;            /* INTEGER_0_127 */
static int hf_ranap_offsetAngle;                  /* INTEGER_0_179 */
static int hf_ranap_includedAngle;                /* INTEGER_0_179 */
static int hf_ranap_confidence;                   /* INTEGER_0_127 */
static int hf_ranap_altitudeAndDirection;         /* GA_AltitudeAndDirection */
static int hf_ranap_uncertaintyEllipse;           /* GA_UncertaintyEllipse */
static int hf_ranap_uncertaintyAltitude;          /* INTEGER_0_127 */
static int hf_ranap_uncertaintyCode;              /* INTEGER_0_127 */
static int hf_ranap_GA_Polygon_item;              /* GA_Polygon_item */
static int hf_ranap_uncertaintySemi_major;        /* INTEGER_0_127 */
static int hf_ranap_uncertaintySemi_minor;        /* INTEGER_0_127 */
static int hf_ranap_orientationOfMajorAxis;       /* INTEGER_0_179 */
static int hf_ranap_lAI;                          /* LAI */
static int hf_ranap_rAC;                          /* RAC */
static int hf_ranap_cN_ID;                        /* CN_ID */
static int hf_ranap_rNC_ID;                       /* RNC_ID */
static int hf_ranap_iMEI;                         /* IMEI */
static int hf_ranap_iMEIMask;                     /* BIT_STRING_SIZE_7 */
static int hf_ranap_IMEIList_item;                /* IMEI */
static int hf_ranap_iMEISV;                       /* IMEISV */
static int hf_ranap_iMEISVMask;                   /* BIT_STRING_SIZE_7 */
static int hf_ranap_IMEISVList_item;              /* IMEISV */
static int hf_ranap_measurementsToActivate;       /* MeasurementsToActivate */
static int hf_ranap_m1report;                     /* M1Report */
static int hf_ranap_m2report;                     /* M2Report */
static int hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest;  /* RequestedMBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_requestedMulticastServiceList;  /* RequestedMulticastServiceList */
static int hf_ranap_mBMSIPMulticastAddressandAPNRequest;  /* MBMSIPMulticastAddressandAPNRequest */
static int hf_ranap_permanentNAS_UE_ID;           /* PermanentNAS_UE_ID */
static int hf_ranap_rNCTraceInformation;          /* RNCTraceInformation */
static int hf_ranap_permittedAlgorithms_01;       /* PermittedIntegrityProtectionAlgorithms */
static int hf_ranap_key_01;                       /* IntegrityProtectionKey */
static int hf_ranap_rIM_Transfer;                 /* RIM_Transfer */
static int hf_ranap_gTP_TEI;                      /* GTP_TEI */
static int hf_ranap_bindingID;                    /* BindingID */
static int hf_ranap_LA_LIST_item;                 /* LA_LIST_item */
static int hf_ranap_listOF_SNAs;                  /* ListOF_SNAs */
static int hf_ranap_ageOfSAI;                     /* INTEGER_0_32767 */
static int hf_ranap_uTRAN_CellID;                 /* UTRAN_CellID */
static int hf_ranap_cellType;                     /* CellType */
static int hf_ranap_time_UE_StayedInCell;         /* Time_UE_StayedInCell */
static int hf_ranap_ListOF_SNAs_item;             /* SNAC */
static int hf_ranap_ListOfInterfacesToTrace_item;  /* InterfacesToTraceItem */
static int hf_ranap_interface;                    /* T_interface */
static int hf_ranap_requestedLocationRelatedDataType;  /* RequestedLocationRelatedDataType */
static int hf_ranap_requestedGPSAssistanceData;   /* RequestedGPSAssistanceData */
static int hf_ranap_reportChangeOfSAI;            /* ReportChangeOfSAI */
static int hf_ranap_periodicReportingIndicator;   /* PeriodicReportingIndicator */
static int hf_ranap_directReportingIndicator;     /* DirectReportingIndicator */
static int hf_ranap_verticalAccuracyCode;         /* VerticalAccuracyCode */
static int hf_ranap_positioningPriorityChangeSAI;  /* PositioningPriority */
static int hf_ranap_positioningPriorityDirect;    /* PositioningPriority */
static int hf_ranap_clientTypePeriodic;           /* ClientType */
static int hf_ranap_clientTypeDirect;             /* ClientType */
static int hf_ranap_responseTime;                 /* ResponseTime */
static int hf_ranap_includeVelocity;              /* IncludeVelocity */
static int hf_ranap_periodicLocationInfo;         /* PeriodicLocationInfo */
static int hf_ranap_periodic;                     /* MDT_Report_Parameters */
static int hf_ranap_event1F;                      /* Event1F_Parameters */
static int hf_ranap_event1I;                      /* Event1I_Parameters */
static int hf_ranap_all;                          /* NULL */
static int hf_ranap_m4_collection_parameters;     /* M4_Collection_Parameters */
static int hf_ranap_m4_period;                    /* M4_Period */
static int hf_ranap_m4_threshold;                 /* M4_Threshold */
static int hf_ranap_when_available;               /* NULL */
static int hf_ranap_m5_period;                    /* M5_Period */
static int hf_ranap_m6_period;                    /* M6_Period */
static int hf_ranap_m6_links_to_log;              /* Links_to_log */
static int hf_ranap_m7_period;                    /* M7_Period */
static int hf_ranap_m7_links_to_log;              /* Links_to_log */
static int hf_ranap_MBMSIPMulticastAddressandAPNRequest_item;  /* TMGI */
static int hf_ranap_plmn_area_based_01;           /* NULL */
static int hf_ranap_mdtActivation;                /* MDT_Activation */
static int hf_ranap_mdtAreaScope;                 /* MDTAreaScope */
static int hf_ranap_mdtMode;                      /* MDTMode */
static int hf_ranap_immediateMDT;                 /* ImmediateMDT */
static int hf_ranap_loggedMDT;                    /* LoggedMDT */
static int hf_ranap_MDT_PLMN_List_item;           /* PLMNidentity */
static int hf_ranap_reportInterval;               /* ReportInterval */
static int hf_ranap_reportAmount;                 /* ReportAmount */
static int hf_ranap_accessPointName;              /* Offload_RAB_Parameters_APN */
static int hf_ranap_chargingCharacteristics;      /* Offload_RAB_Parameters_ChargingCharacteristics */
static int hf_ranap_rAI;                          /* RAI */
static int hf_ranap_PDP_TypeInformation_item;     /* PDP_Type */
static int hf_ranap_PDP_TypeInformation_extension_item;  /* PDP_Type_extension */
static int hf_ranap_reportingAmount;              /* INTEGER_1_8639999_ */
static int hf_ranap_reportingInterval;            /* INTEGER_1_8639999_ */
static int hf_ranap_iMSI;                         /* IMSI */
static int hf_ranap_PermittedEncryptionAlgorithms_item;  /* EncryptionAlgorithm */
static int hf_ranap_PermittedIntegrityProtectionAlgorithms_item;  /* IntegrityProtectionAlgorithm */
static int hf_ranap_laiList;                      /* LAI_List */
static int hf_ranap_LAI_List_item;                /* LAI */
static int hf_ranap_loggingInterval;              /* LoggingInterval */
static int hf_ranap_loggingDuration;              /* LoggingDuration */
static int hf_ranap_plmnList;                     /* PLMNList */
static int hf_ranap_PLMNList_item;                /* PLMNidentity */
static int hf_ranap_PLMNs_in_shared_network_item;  /* PLMNs_in_shared_network_item */
static int hf_ranap_lA_LIST;                      /* LA_LIST */
static int hf_ranap_PositioningDataSet_item;      /* PositioningMethodAndUsage */
static int hf_ranap_positioningDataDiscriminator;  /* PositioningDataDiscriminator */
static int hf_ranap_positioningDataSet;           /* PositioningDataSet */
static int hf_ranap_shared_network_information;   /* Shared_Network_Information */
static int hf_ranap_raiList;                      /* RAI_List */
static int hf_ranap_RAI_List_item;                /* RAI */
static int hf_ranap_RABDataVolumeReport_item;     /* RABDataVolumeReport_item */
static int hf_ranap_dl_UnsuccessfullyTransmittedDataVolume;  /* UnsuccessfullyTransmittedDataVolume */
static int hf_ranap_dataVolumeReference;          /* DataVolumeReference */
static int hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item;  /* ExtendedMaxBitrate */
static int hf_ranap_RAB_Parameter_GuaranteedBitrateList_item;  /* GuaranteedBitrate */
static int hf_ranap_RAB_Parameter_MaxBitrateList_item;  /* MaxBitrate */
static int hf_ranap_trafficClass;                 /* TrafficClass */
static int hf_ranap_rAB_AsymmetryIndicator;       /* RAB_AsymmetryIndicator */
static int hf_ranap_maxBitrate;                   /* RAB_Parameter_MaxBitrateList */
static int hf_ranap_guaranteedBitRate;            /* RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_deliveryOrder;                /* DeliveryOrder */
static int hf_ranap_maxSDU_Size;                  /* MaxSDU_Size */
static int hf_ranap_sDU_Parameters;               /* SDU_Parameters */
static int hf_ranap_transferDelay;                /* TransferDelay */
static int hf_ranap_trafficHandlingPriority;      /* TrafficHandlingPriority */
static int hf_ranap_allocationOrRetentionPriority;  /* AllocationOrRetentionPriority */
static int hf_ranap_sourceStatisticsDescriptor;   /* SourceStatisticsDescriptor */
static int hf_ranap_relocationRequirement;        /* RelocationRequirement */
static int hf_ranap_RABParametersList_item;       /* RABParametersList_item */
static int hf_ranap_rab_Id;                       /* RAB_ID */
static int hf_ranap_cn_domain;                    /* CN_DomainIndicator */
static int hf_ranap_rabDataVolumeReport;          /* RABDataVolumeReport */
static int hf_ranap_upInformation;                /* UPInformation */
static int hf_ranap_RAB_TrCH_Mapping_item;        /* RAB_TrCH_MappingItem */
static int hf_ranap_rAB_ID;                       /* RAB_ID */
static int hf_ranap_trCH_ID_List;                 /* TrCH_ID_List */
static int hf_ranap_notEmptyRAListofIdleModeUEs;  /* NotEmptyRAListofIdleModeUEs */
static int hf_ranap_emptyFullRAListofIdleModeUEs;  /* T_emptyFullRAListofIdleModeUEs */
static int hf_ranap_rAofIdleModeUEs;              /* RAofIdleModeUEs */
static int hf_ranap_RAofIdleModeUEs_item;         /* RAC */
static int hf_ranap_LAListofIdleModeUEs_item;     /* LAI */
static int hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item;  /* MBMSIPMulticastAddressandAPNlist */
static int hf_ranap_tMGI;                         /* TMGI */
static int hf_ranap_iPMulticastAddress;           /* IPMulticastAddress */
static int hf_ranap_aPN;                          /* APN */
static int hf_ranap_RequestedMulticastServiceList_item;  /* TMGI */
static int hf_ranap_requestedMaxBitrates;         /* Requested_RAB_Parameter_MaxBitrateList */
static int hf_ranap_requestedGuaranteedBitrates;  /* Requested_RAB_Parameter_GuaranteedBitrateList */
static int hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item;  /* ExtendedMaxBitrate */
static int hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item;  /* ExtendedGuaranteedBitrate */
static int hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item;  /* MaxBitrate */
static int hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item;  /* GuaranteedBitrate */
static int hf_ranap_event;                        /* Event */
static int hf_ranap_reportArea;                   /* ReportArea */
static int hf_ranap_accuracyCode;                 /* INTEGER_0_127 */
static int hf_ranap_mantissa;                     /* INTEGER_1_9 */
static int hf_ranap_exponent;                     /* INTEGER_1_8 */
static int hf_ranap_rIMInformation;               /* RIMInformation */
static int hf_ranap_rIMRoutingAddress;            /* RIMRoutingAddress */
static int hf_ranap_targetRNC_ID;                 /* TargetRNC_ID */
static int hf_ranap_gERAN_Cell_ID;                /* GERAN_Cell_ID */
static int hf_ranap_targeteNB_ID;                 /* TargetENB_ID */
static int hf_ranap_traceActivationIndicator;     /* T_traceActivationIndicator */
static int hf_ranap_equipmentsToBeTraced;         /* EquipmentsToBeTraced */
static int hf_ranap_rabParmetersList;             /* RABParametersList */
static int hf_ranap_locationReporting;            /* LocationReportingTransferInformation */
static int hf_ranap_traceInformation;             /* TraceInformation */
static int hf_ranap_sourceSAI;                    /* SAI */
static int hf_ranap_nonce;                        /* BIT_STRING_SIZE_128 */
static int hf_ranap_iMSInformation;               /* OCTET_STRING_SIZE_1_maxSizeOfIMSInfo */
static int hf_ranap_sAC;                          /* SAC */
static int hf_ranap_pLMNs_in_shared_network;      /* PLMNs_in_shared_network */
static int hf_ranap_exponent_1_8;                 /* INTEGER_1_6 */
static int hf_ranap_SDU_FormatInformationParameters_item;  /* SDU_FormatInformationParameters_item */
static int hf_ranap_subflowSDU_Size;              /* SubflowSDU_Size */
static int hf_ranap_rAB_SubflowCombinationBitRate;  /* RAB_SubflowCombinationBitRate */
static int hf_ranap_SDU_Parameters_item;          /* SDU_Parameters_item */
static int hf_ranap_sDU_ErrorRatio;               /* SDU_ErrorRatio */
static int hf_ranap_residualBitErrorRatio;        /* ResidualBitErrorRatio */
static int hf_ranap_deliveryOfErroneousSDU;       /* DeliveryOfErroneousSDU */
static int hf_ranap_sDU_FormatInformationParameters;  /* SDU_FormatInformationParameters */
static int hf_ranap_null_NRI;                     /* Null_NRI */
static int hf_ranap_sGSN_Group_ID;                /* SGSN_Group_ID */
static int hf_ranap_authorisedPLMNs;              /* AuthorisedPLMNs */
static int hf_ranap_sourceUTRANCellID;            /* SourceUTRANCellID */
static int hf_ranap_sourceGERANCellID;            /* CGI */
static int hf_ranap_sourceRNC_ID;                 /* SourceRNC_ID */
static int hf_ranap_rRC_Container;                /* RRC_Container */
static int hf_ranap_numberOfIuInstances;          /* NumberOfIuInstances */
static int hf_ranap_relocationType;               /* RelocationType */
static int hf_ranap_chosenIntegrityProtectionAlgorithm;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_ranap_integrityProtectionKey;       /* IntegrityProtectionKey */
static int hf_ranap_chosenEncryptionAlgorithForSignalling;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_cipheringKey;                 /* EncryptionKey */
static int hf_ranap_chosenEncryptionAlgorithForCS;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_chosenEncryptionAlgorithForPS;  /* ChosenEncryptionAlgorithm */
static int hf_ranap_d_RNTI;                       /* D_RNTI */
static int hf_ranap_targetCellId;                 /* TargetCellId */
static int hf_ranap_rAB_TrCH_Mapping;             /* RAB_TrCH_Mapping */
static int hf_ranap_rSRP;                         /* INTEGER_0_97 */
static int hf_ranap_rSRQ;                         /* INTEGER_0_34 */
static int hf_ranap_iRATmeasurementParameters;    /* IRATmeasurementParameters */
static int hf_ranap_measurementDuration;          /* INTEGER_1_100 */
static int hf_ranap_eUTRANFrequencies;            /* EUTRANFrequencies */
static int hf_ranap_allSymbols;                   /* BOOLEAN */
static int hf_ranap_wideBand;                     /* BOOLEAN */
static int hf_ranap_EUTRANFrequencies_item;       /* EUTRANFrequencies_item */
static int hf_ranap_earfcn;                       /* INTEGER_0_65535 */
static int hf_ranap_measBand;                     /* MeasBand */
static int hf_ranap_SupportedRAB_ParameterBitrateList_item;  /* SupportedBitrate */
static int hf_ranap_uTRANcellID;                  /* TargetCellId */
static int hf_ranap_SRB_TrCH_Mapping_item;        /* SRB_TrCH_MappingItem */
static int hf_ranap_sRB_ID;                       /* SRB_ID */
static int hf_ranap_trCH_ID;                      /* TrCH_ID */
static int hf_ranap_tAC;                          /* TAC */
static int hf_ranap_cGI;                          /* CGI */
static int hf_ranap_eNB_ID;                       /* ENB_ID */
static int hf_ranap_selectedTAI;                  /* TAI */
static int hf_ranap_tMSI;                         /* TMSI */
static int hf_ranap_p_TMSI;                       /* P_TMSI */
static int hf_ranap_serviceID;                    /* OCTET_STRING_SIZE_3 */
static int hf_ranap_ue_identity;                  /* UE_ID */
static int hf_ranap_traceRecordingSessionReference;  /* TraceRecordingSessionReference */
static int hf_ranap_traceDepth;                   /* TraceDepth */
static int hf_ranap_listOfInterfacesToTrace;      /* ListOfInterfacesToTrace */
static int hf_ranap_dCH_ID;                       /* DCH_ID */
static int hf_ranap_dSCH_ID;                      /* DSCH_ID */
static int hf_ranap_uSCH_ID;                      /* USCH_ID */
static int hf_ranap_TrCH_ID_List_item;            /* TrCH_ID */
static int hf_ranap_transportLayerAddress;        /* TransportLayerAddress */
static int hf_ranap_uDP_Port_Number;              /* Port_Number */
static int hf_ranap_uE_AggregateMaximumBitRateDownlink;  /* UE_AggregateMaximumBitRateDownlink */
static int hf_ranap_uE_AggregateMaximumBitRateUplink;  /* UE_AggregateMaximumBitRateUplink */
static int hf_ranap_imsi;                         /* IMSI */
static int hf_ranap_imei;                         /* IMEI */
static int hf_ranap_imeisv;                       /* IMEISV */
static int hf_ranap_uE_IsServed;                  /* UE_IsServed */
static int hf_ranap_uE_IsNotServed;               /* UE_IsNotServed */
static int hf_ranap_uESBI_IuA;                    /* UESBI_IuA */
static int hf_ranap_uESBI_IuB;                    /* UESBI_IuB */
static int hf_ranap_frameSeqNoUL;                 /* FrameSequenceNumber */
static int hf_ranap_frameSeqNoDL;                 /* FrameSequenceNumber */
static int hf_ranap_pdu14FrameSeqNoUL;            /* PDUType14FrameSequenceNumber */
static int hf_ranap_pdu14FrameSeqNoDL;            /* PDUType14FrameSequenceNumber */
static int hf_ranap_dataPDUType;                  /* DataPDUType */
static int hf_ranap_upinitialisationFrame;        /* UPInitialisationFrame */
static int hf_ranap_cellID;                       /* TargetCellId */
static int hf_ranap_horizontalVelocity;           /* HorizontalVelocity */
static int hf_ranap_horizontalWithVerticalVelocity;  /* HorizontalWithVerticalVelocity */
static int hf_ranap_horizontalVelocityWithUncertainty;  /* HorizontalVelocityWithUncertainty */
static int hf_ranap_horizontalWithVeritcalVelocityAndUncertainty;  /* HorizontalWithVerticalVelocityAndUncertainty */
static int hf_ranap_horizontalSpeedAndBearing;    /* HorizontalSpeedAndBearing */
static int hf_ranap_veritcalVelocity;             /* VerticalVelocity */
static int hf_ranap_uncertaintySpeed;             /* INTEGER_0_255 */
static int hf_ranap_horizontalUncertaintySpeed;   /* INTEGER_0_255 */
static int hf_ranap_verticalUncertaintySpeed;     /* INTEGER_0_255 */
static int hf_ranap_bearing;                      /* INTEGER_0_359 */
static int hf_ranap_horizontalSpeed;              /* INTEGER_0_2047 */
static int hf_ranap_veritcalSpeed;                /* INTEGER_0_255 */
static int hf_ranap_veritcalSpeedDirection;       /* VerticalSpeedDirection */
static int hf_ranap_protocolIEs;                  /* ProtocolIE_Container */
static int hf_ranap_protocolExtensions;           /* ProtocolExtensionContainer */
static int hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume;  /* DataVolumeList */
static int hf_ranap_dL_GTP_PDU_SequenceNumber;    /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_uL_GTP_PDU_SequenceNumber;    /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_iuTransportAssociation;       /* IuTransportAssociation */
static int hf_ranap_nAS_SynchronisationIndicator;  /* NAS_SynchronisationIndicator */
static int hf_ranap_rAB_Parameters;               /* RAB_Parameters */
static int hf_ranap_dataVolumeReportingIndication;  /* DataVolumeReportingIndication */
static int hf_ranap_pDP_TypeInformation;          /* PDP_TypeInformation */
static int hf_ranap_userPlaneInformation;         /* UserPlaneInformation */
static int hf_ranap_service_Handover;             /* Service_Handover */
static int hf_ranap_userPlaneMode;                /* UserPlaneMode */
static int hf_ranap_uP_ModeVersions;              /* UP_ModeVersions */
static int hf_ranap_joinedMBMSBearerService_IEs;  /* JoinedMBMSBearerService_IEs */
static int hf_ranap_JoinedMBMSBearerService_IEs_item;  /* JoinedMBMSBearerService_IEs_item */
static int hf_ranap_mBMS_PTP_RAB_ID;              /* MBMS_PTP_RAB_ID */
static int hf_ranap_cause;                        /* Cause */
static int hf_ranap_dl_GTP_PDU_SequenceNumber;    /* DL_GTP_PDU_SequenceNumber */
static int hf_ranap_ul_GTP_PDU_SequenceNumber;    /* UL_GTP_PDU_SequenceNumber */
static int hf_ranap_dl_N_PDU_SequenceNumber;      /* DL_N_PDU_SequenceNumber */
static int hf_ranap_ul_N_PDU_SequenceNumber;      /* UL_N_PDU_SequenceNumber */
static int hf_ranap_iuSigConId;                   /* IuSignallingConnectionIdentifier */
static int hf_ranap_transportLayerAddressReq1;    /* TransportLayerAddress */
static int hf_ranap_iuTransportAssociationReq1;   /* IuTransportAssociation */
static int hf_ranap_ass_RAB_Parameters;           /* Ass_RAB_Parameters */
static int hf_ranap_transportLayerAddressRes1;    /* TransportLayerAddress */
static int hf_ranap_iuTransportAssociationRes1;   /* IuTransportAssociation */
static int hf_ranap_rab2beReleasedList;           /* RAB_ToBeReleasedList_EnhancedRelocCompleteRes */
static int hf_ranap_transportLayerInformation;    /* TransportLayerInformation */
static int hf_ranap_dl_dataVolumes;               /* DataVolumeList */
static int hf_ranap_DataVolumeList_item;          /* DataVolumeList_item */
static int hf_ranap_gERAN_Classmark;              /* GERAN_Classmark */
static int hf_ranap_privateIEs;                   /* PrivateIE_Container */
static int hf_ranap_nAS_PDU;                      /* NAS_PDU */
static int hf_ranap_sAPI;                         /* SAPI */
static int hf_ranap_cN_DomainIndicator;           /* CN_DomainIndicator */
static int hf_ranap_dataForwardingInformation;    /* TNLInformationEnhRelInfoReq */
static int hf_ranap_sourceSideIuULTNLInfo;        /* TNLInformationEnhRelInfoReq */
static int hf_ranap_alt_RAB_Parameters;           /* Alt_RAB_Parameters */
static int hf_ranap_dataForwardingInformation_01;  /* TNLInformationEnhRelInfoRes */
static int hf_ranap_dl_forwardingTransportLayerAddress;  /* TransportLayerAddress */
static int hf_ranap_dl_forwardingTransportAssociation;  /* IuTransportAssociation */
static int hf_ranap_requested_RAB_Parameter_Values;  /* Requested_RAB_Parameter_Values */
static int hf_ranap_mBMSHCIndicator;              /* MBMSHCIndicator */
static int hf_ranap_gTPDLTEID;                    /* GTP_TEI */
static int hf_ranap_LeftMBMSBearerService_IEs_item;  /* LeftMBMSBearerService_IEs_item */
static int hf_ranap_UnsuccessfulLinking_IEs_item;  /* UnsuccessfulLinking_IEs_item */
static int hf_ranap_initiatingMessage;            /* InitiatingMessage */
static int hf_ranap_successfulOutcome;            /* SuccessfulOutcome */
static int hf_ranap_unsuccessfulOutcome;          /* UnsuccessfulOutcome */
static int hf_ranap_outcome;                      /* Outcome */
static int hf_ranap_initiatingMessagevalue;       /* InitiatingMessage_value */
static int hf_ranap_successfulOutcome_value;      /* SuccessfulOutcome_value */
static int hf_ranap_unsuccessfulOutcome_value;    /* UnsuccessfulOutcome_value */
static int hf_ranap_value;                        /* T_value */

/* Initialize the subtree pointers */
static int ett_ranap;
static int ett_ranap_transportLayerAddress;
static int ett_ranap_transportLayerAddress_nsap;

static int ett_ranap_PrivateIE_ID;
static int ett_ranap_ProtocolIE_Container;
static int ett_ranap_ProtocolIE_Field;
static int ett_ranap_ProtocolIE_ContainerPair;
static int ett_ranap_ProtocolIE_FieldPair;
static int ett_ranap_ProtocolIE_ContainerList;
static int ett_ranap_ProtocolIE_ContainerPairList;
static int ett_ranap_ProtocolExtensionContainer;
static int ett_ranap_ProtocolExtensionField;
static int ett_ranap_PrivateIE_Container;
static int ett_ranap_PrivateIE_Field;
static int ett_ranap_Additional_CSPS_coordination_information;
static int ett_ranap_Additional_PositioningDataSet;
static int ett_ranap_AllocationOrRetentionPriority;
static int ett_ranap_Alt_RAB_Parameters;
static int ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates;
static int ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList;
static int ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates;
static int ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList;
static int ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates;
static int ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates;
static int ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList;
static int ett_ranap_Alt_RAB_Parameter_MaxBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_MaxBitrates;
static int ett_ranap_Alt_RAB_Parameter_MaxBitrateList;
static int ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf;
static int ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates;
static int ett_ranap_UE_Application_Layer_Measurement_Configuration;
static int ett_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation;
static int ett_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration;
static int ett_ranap_AreaIdentity;
static int ett_ranap_Ass_RAB_Parameters;
static int ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList;
static int ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList;
static int ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList;
static int ett_ranap_Ass_RAB_Parameter_MaxBitrateList;
static int ett_ranap_AuthorisedPLMNs;
static int ett_ranap_AuthorisedPLMNs_item;
static int ett_ranap_AuthorisedSNAs;
static int ett_ranap_BroadcastAssistanceDataDecipheringKeys;
static int ett_ranap_Cause;
static int ett_ranap_CellBased;
static int ett_ranap_CellIdList;
static int ett_ranap_CellLoadInformation;
static int ett_ranap_CellLoadInformationGroup;
static int ett_ranap_CriticalityDiagnostics;
static int ett_ranap_CriticalityDiagnostics_IE_List;
static int ett_ranap_CriticalityDiagnostics_IE_List_item;
static int ett_ranap_MessageStructure;
static int ett_ranap_MessageStructure_item;
static int ett_ranap_CGI;
static int ett_ranap_CSG_Id_List;
static int ett_ranap_DeltaRAListofIdleModeUEs;
static int ett_ranap_NewRAListofIdleModeUEs;
static int ett_ranap_RAListwithNoIdleModeUEsAnyMore;
static int ett_ranap_ENB_ID;
static int ett_ranap_EncryptionInformation;
static int ett_ranap_EquipmentsToBeTraced;
static int ett_ranap_Event1F_Parameters;
static int ett_ranap_Event1I_Parameters;
static int ett_ranap_GANSS_PositioningDataSet;
static int ett_ranap_GeographicalArea;
static int ett_ranap_GeographicalCoordinates;
static int ett_ranap_GA_AltitudeAndDirection;
static int ett_ranap_GA_EllipsoidArc;
static int ett_ranap_GA_Point;
static int ett_ranap_GA_PointWithAltitude;
static int ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid;
static int ett_ranap_GA_PointWithUnCertainty;
static int ett_ranap_GA_PointWithUnCertaintyEllipse;
static int ett_ranap_GA_Polygon;
static int ett_ranap_GA_Polygon_item;
static int ett_ranap_GA_UncertaintyEllipse;
static int ett_ranap_GERAN_Cell_ID;
static int ett_ranap_GlobalCN_ID;
static int ett_ranap_GlobalRNC_ID;
static int ett_ranap_IMEIGroup;
static int ett_ranap_IMEIList;
static int ett_ranap_IMEISVGroup;
static int ett_ranap_IMEISVList;
static int ett_ranap_ImmediateMDT;
static int ett_ranap_InformationRequested;
static int ett_ranap_InformationRequestType;
static int ett_ranap_InformationTransferType;
static int ett_ranap_IntegrityProtectionInformation;
static int ett_ranap_InterSystemInformationTransferType;
static int ett_ranap_InterSystemInformation_TransparentContainer;
static int ett_ranap_IuTransportAssociation;
static int ett_ranap_LA_LIST;
static int ett_ranap_LA_LIST_item;
static int ett_ranap_LAI;
static int ett_ranap_LastKnownServiceArea;
static int ett_ranap_LastVisitedUTRANCell_Item;
static int ett_ranap_ListOF_SNAs;
static int ett_ranap_ListOfInterfacesToTrace;
static int ett_ranap_InterfacesToTraceItem;
static int ett_ranap_LocationRelatedDataRequestType;
static int ett_ranap_LocationReportingTransferInformation;
static int ett_ranap_M1Report;
static int ett_ranap_M2Report;
static int ett_ranap_M4Report;
static int ett_ranap_M4_Collection_Parameters;
static int ett_ranap_M5Report;
static int ett_ranap_M6Report;
static int ett_ranap_M7Report;
static int ett_ranap_MBMSIPMulticastAddressandAPNRequest;
static int ett_ranap_MDTAreaScope;
static int ett_ranap_MDT_Configuration;
static int ett_ranap_MDTMode;
static int ett_ranap_MDT_PLMN_List;
static int ett_ranap_MDT_Report_Parameters;
static int ett_ranap_Offload_RAB_Parameters;
static int ett_ranap_PagingAreaID;
static int ett_ranap_PDP_TypeInformation;
static int ett_ranap_PDP_TypeInformation_extension;
static int ett_ranap_PeriodicLocationInfo;
static int ett_ranap_PermanentNAS_UE_ID;
static int ett_ranap_PermittedEncryptionAlgorithms;
static int ett_ranap_PermittedIntegrityProtectionAlgorithms;
static int ett_ranap_LABased;
static int ett_ranap_LAI_List;
static int ett_ranap_LoggedMDT;
static int ett_ranap_PLMNBased;
static int ett_ranap_PLMNList;
static int ett_ranap_PLMNs_in_shared_network;
static int ett_ranap_PLMNs_in_shared_network_item;
static int ett_ranap_PositioningDataSet;
static int ett_ranap_PositionData;
static int ett_ranap_ProvidedData;
static int ett_ranap_RABased;
static int ett_ranap_RAI_List;
static int ett_ranap_RABDataVolumeReport;
static int ett_ranap_RABDataVolumeReport_item;
static int ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList;
static int ett_ranap_RAB_Parameter_ExtendedMaxBitrateList;
static int ett_ranap_RAB_Parameter_GuaranteedBitrateList;
static int ett_ranap_RAB_Parameter_MaxBitrateList;
static int ett_ranap_RAB_Parameters;
static int ett_ranap_RABParametersList;
static int ett_ranap_RABParametersList_item;
static int ett_ranap_RAB_TrCH_Mapping;
static int ett_ranap_RAB_TrCH_MappingItem;
static int ett_ranap_RAI;
static int ett_ranap_RAListofIdleModeUEs;
static int ett_ranap_NotEmptyRAListofIdleModeUEs;
static int ett_ranap_RAofIdleModeUEs;
static int ett_ranap_LAListofIdleModeUEs;
static int ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest;
static int ett_ranap_MBMSIPMulticastAddressandAPNlist;
static int ett_ranap_RequestedMulticastServiceList;
static int ett_ranap_Requested_RAB_Parameter_Values;
static int ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList;
static int ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList;
static int ett_ranap_Requested_RAB_Parameter_MaxBitrateList;
static int ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList;
static int ett_ranap_RequestType;
static int ett_ranap_ResidualBitErrorRatio;
static int ett_ranap_RIM_Transfer;
static int ett_ranap_RIMRoutingAddress;
static int ett_ranap_RNCTraceInformation;
static int ett_ranap_RNSAPRelocationParameters;
static int ett_ranap_RSRVCC_Information;
static int ett_ranap_SAI;
static int ett_ranap_Shared_Network_Information;
static int ett_ranap_SDU_ErrorRatio;
static int ett_ranap_SDU_FormatInformationParameters;
static int ett_ranap_SDU_FormatInformationParameters_item;
static int ett_ranap_SDU_Parameters;
static int ett_ranap_SDU_Parameters_item;
static int ett_ranap_SGSN_Group_Identity;
static int ett_ranap_SNA_Access_Information;
static int ett_ranap_SourceCellID;
static int ett_ranap_SourceID;
static int ett_ranap_SourceRNC_ID;
static int ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer;
static int ett_ranap_IRAT_Measurement_Configuration;
static int ett_ranap_IRATmeasurementParameters;
static int ett_ranap_RSRQ_Type;
static int ett_ranap_EUTRANFrequencies;
static int ett_ranap_EUTRANFrequencies_item;
static int ett_ranap_SupportedRAB_ParameterBitrateList;
static int ett_ranap_SourceUTRANCellID;
static int ett_ranap_SRB_TrCH_Mapping;
static int ett_ranap_SRB_TrCH_MappingItem;
static int ett_ranap_SRVCC_Information;
static int ett_ranap_TAI;
static int ett_ranap_TargetID;
static int ett_ranap_TargetENB_ID;
static int ett_ranap_TargetRNC_ID;
static int ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer;
static int ett_ranap_TemporaryUE_ID;
static int ett_ranap_TMGI;
static int ett_ranap_TraceInformation;
static int ett_ranap_TracePropagationParameters;
static int ett_ranap_TraceRecordingSessionInformation;
static int ett_ranap_TrCH_ID;
static int ett_ranap_TrCH_ID_List;
static int ett_ranap_TunnelInformation;
static int ett_ranap_UE_AggregateMaximumBitRate;
static int ett_ranap_UE_ID;
static int ett_ranap_UE_IsNotServed;
static int ett_ranap_UE_IsServed;
static int ett_ranap_UERegistrationQueryResult;
static int ett_ranap_UESBI_Iu;
static int ett_ranap_UPInformation;
static int ett_ranap_UTRAN_CellID;
static int ett_ranap_VelocityEstimate;
static int ett_ranap_HorizontalVelocity;
static int ett_ranap_HorizontalWithVerticalVelocity;
static int ett_ranap_HorizontalVelocityWithUncertainty;
static int ett_ranap_HorizontalWithVerticalVelocityAndUncertainty;
static int ett_ranap_HorizontalSpeedAndBearing;
static int ett_ranap_VerticalVelocity;
static int ett_ranap_Iu_ReleaseCommand;
static int ett_ranap_Iu_ReleaseComplete;
static int ett_ranap_RAB_DataVolumeReportItem;
static int ett_ranap_RAB_ReleasedItem_IuRelComp;
static int ett_ranap_RelocationRequired;
static int ett_ranap_RelocationCommand;
static int ett_ranap_RAB_RelocationReleaseItem;
static int ett_ranap_RAB_DataForwardingItem;
static int ett_ranap_RelocationPreparationFailure;
static int ett_ranap_RelocationRequest;
static int ett_ranap_RAB_SetupItem_RelocReq;
static int ett_ranap_UserPlaneInformation;
static int ett_ranap_CNMBMSLinkingInformation;
static int ett_ranap_JoinedMBMSBearerService_IEs;
static int ett_ranap_JoinedMBMSBearerService_IEs_item;
static int ett_ranap_RelocationRequestAcknowledge;
static int ett_ranap_RAB_SetupItem_RelocReqAck;
static int ett_ranap_RAB_FailedItem;
static int ett_ranap_RelocationFailure;
static int ett_ranap_RelocationCancel;
static int ett_ranap_RelocationCancelAcknowledge;
static int ett_ranap_SRNS_ContextRequest;
static int ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq;
static int ett_ranap_SRNS_ContextResponse;
static int ett_ranap_RAB_ContextItem;
static int ett_ranap_RABs_ContextFailedtoTransferItem;
static int ett_ranap_SecurityModeCommand;
static int ett_ranap_SecurityModeComplete;
static int ett_ranap_SecurityModeReject;
static int ett_ranap_DataVolumeReportRequest;
static int ett_ranap_RAB_DataVolumeReportRequestItem;
static int ett_ranap_DataVolumeReport;
static int ett_ranap_RABs_failed_to_reportItem;
static int ett_ranap_Reset;
static int ett_ranap_ResetAcknowledge;
static int ett_ranap_ResetResource;
static int ett_ranap_ResetResourceItem;
static int ett_ranap_ResetResourceAcknowledge;
static int ett_ranap_ResetResourceAckItem;
static int ett_ranap_RAB_ReleaseRequest;
static int ett_ranap_RAB_ReleaseItem;
static int ett_ranap_Iu_ReleaseRequest;
static int ett_ranap_RelocationDetect;
static int ett_ranap_RelocationComplete;
static int ett_ranap_EnhancedRelocationCompleteRequest;
static int ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq;
static int ett_ranap_EnhancedRelocationCompleteResponse;
static int ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes;
static int ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes;
static int ett_ranap_EnhancedRelocationCompleteFailure;
static int ett_ranap_EnhancedRelocationCompleteConfirm;
static int ett_ranap_Paging;
static int ett_ranap_CommonID;
static int ett_ranap_CN_InvokeTrace;
static int ett_ranap_CN_DeactivateTrace;
static int ett_ranap_LocationReportingControl;
static int ett_ranap_LocationReport;
static int ett_ranap_InitialUE_Message;
static int ett_ranap_DirectTransfer;
static int ett_ranap_Overload;
static int ett_ranap_ErrorIndication;
static int ett_ranap_SRNS_DataForwardCommand;
static int ett_ranap_ForwardSRNS_Context;
static int ett_ranap_RAB_AssignmentRequest;
static int ett_ranap_RAB_SetupOrModifyItemFirst;
static int ett_ranap_TransportLayerInformation;
static int ett_ranap_RAB_SetupOrModifyItemSecond;
static int ett_ranap_RAB_AssignmentResponse;
static int ett_ranap_RAB_SetupOrModifiedItem;
static int ett_ranap_RAB_ReleasedItem;
static int ett_ranap_DataVolumeList;
static int ett_ranap_DataVolumeList_item;
static int ett_ranap_RAB_QueuedItem;
static int ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item;
static int ett_ranap_PrivateMessage;
static int ett_ranap_RANAP_RelocationInformation;
static int ett_ranap_DirectTransferInformationItem_RANAP_RelocInf;
static int ett_ranap_RAB_ContextItem_RANAP_RelocInf;
static int ett_ranap_RANAP_EnhancedRelocationInformationRequest;
static int ett_ranap_RAB_SetupItem_EnhRelocInfoReq;
static int ett_ranap_TNLInformationEnhRelInfoReq;
static int ett_ranap_RANAP_EnhancedRelocationInformationResponse;
static int ett_ranap_RAB_SetupItem_EnhRelocInfoRes;
static int ett_ranap_RAB_FailedItem_EnhRelocInfoRes;
static int ett_ranap_TNLInformationEnhRelInfoRes;
static int ett_ranap_RAB_ModifyRequest;
static int ett_ranap_RAB_ModifyItem;
static int ett_ranap_LocationRelatedDataRequest;
static int ett_ranap_LocationRelatedDataResponse;
static int ett_ranap_LocationRelatedDataFailure;
static int ett_ranap_InformationTransferIndication;
static int ett_ranap_InformationTransferConfirmation;
static int ett_ranap_InformationTransferFailure;
static int ett_ranap_UESpecificInformationIndication;
static int ett_ranap_DirectInformationTransfer;
static int ett_ranap_UplinkInformationExchangeRequest;
static int ett_ranap_UplinkInformationExchangeResponse;
static int ett_ranap_UplinkInformationExchangeFailure;
static int ett_ranap_MBMSSessionStart;
static int ett_ranap_MBMSSynchronisationInformation;
static int ett_ranap_MBMSSessionStartResponse;
static int ett_ranap_MBMSSessionStartFailure;
static int ett_ranap_MBMSSessionUpdate;
static int ett_ranap_MBMSSessionUpdateResponse;
static int ett_ranap_MBMSSessionUpdateFailure;
static int ett_ranap_MBMSSessionStop;
static int ett_ranap_MBMSSessionStopResponse;
static int ett_ranap_MBMSUELinkingRequest;
static int ett_ranap_LeftMBMSBearerService_IEs;
static int ett_ranap_LeftMBMSBearerService_IEs_item;
static int ett_ranap_MBMSUELinkingResponse;
static int ett_ranap_UnsuccessfulLinking_IEs;
static int ett_ranap_UnsuccessfulLinking_IEs_item;
static int ett_ranap_MBMSRegistrationRequest;
static int ett_ranap_MBMSRegistrationResponse;
static int ett_ranap_MBMSRegistrationFailure;
static int ett_ranap_MBMSCNDe_RegistrationRequest;
static int ett_ranap_MBMSCNDe_RegistrationResponse;
static int ett_ranap_MBMSRABEstablishmentIndication;
static int ett_ranap_MBMSRABReleaseRequest;
static int ett_ranap_MBMSRABRelease;
static int ett_ranap_MBMSRABReleaseFailure;
static int ett_ranap_SRVCC_CSKeysRequest;
static int ett_ranap_SRVCC_CSKeysResponse;
static int ett_ranap_UeRadioCapabilityMatchRequest;
static int ett_ranap_UeRadioCapabilityMatchResponse;
static int ett_ranap_UeRegistrationQueryRequest;
static int ett_ranap_UeRegistrationQueryResponse;
static int ett_ranap_RerouteNASRequest;
static int ett_ranap_RANAP_PDU;
static int ett_ranap_InitiatingMessage;
static int ett_ranap_SuccessfulOutcome;
static int ett_ranap_UnsuccessfulOutcome;
static int ett_ranap_Outcome;

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/


typedef struct ranap_private_data_t
{
  uint32_t transportLayerAddress_ipv4;
  uint16_t binding_id_port;
  e212_number_type_t number_type;
} ranap_private_data_t;


/* Helper function to get or create the private data struct */
static ranap_private_data_t* ranap_get_private_data(asn1_ctx_t *actx)
{
  packet_info *pinfo = actx->pinfo;
  ranap_private_data_t *private_data = (ranap_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ranap, 0);
  if(private_data == NULL ) {
    private_data = wmem_new0(pinfo->pool, ranap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_ranap, 0, private_data);
  }
  return private_data;
}

/* Helper function to reset the private data struct */
static void ranap_reset_private_data(packet_info *pinfo)
{
  p_remove_proto_data(pinfo->pool, pinfo, proto_ranap, 0);
}

static uint32_t private_data_get_transportLayerAddress_ipv4(asn1_ctx_t *actx)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  return private_data->transportLayerAddress_ipv4;
}

static void private_data_set_transportLayerAddress_ipv4(asn1_ctx_t *actx, uint32_t transportLayerAddress_ipv4)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->transportLayerAddress_ipv4 = transportLayerAddress_ipv4;
}

static uint16_t private_data_get_binding_id_port(asn1_ctx_t *actx)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  return private_data->binding_id_port;
}

static void private_data_set_binding_id_port(asn1_ctx_t *actx, uint16_t binding_id_port)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->binding_id_port = binding_id_port;
}

/*****************************************************************************/


/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
static uint32_t ProtocolExtensionID;
static bool glbl_dissect_container;

static dissector_handle_t ranap_handle;

/* Some IE:s identities uses the same value for different IE:s
 * depending on PDU type:
 * InitiatingMessage
 * SuccessfulOutcome
 * UnsuccessfulOutcome
 * Outcome
 * As a workarond a value is added to the IE:id in the .cnf file.
 * Example:
 * ResetResourceList                N rnsap.ies IMSG||id-IuSigConIdList  # no spaces are allowed in value as a space is delimiter
 * PDU type is stored in a global variable and can is used in the IE decoding section.
 */
/*
 *  &InitiatingMessage        ,
 *  &SuccessfulOutcome        OPTIONAL,
 *  &UnsuccessfulOutcome      OPTIONAL,
 *  &Outcome                  OPTIONAL,
 *
 * Only these two needed currently
 */
#define IMSG (1U<<16)
#define SOUT (2U<<16)
#define SPECIAL (4U<<16)

int pdu_type; /* 0 means wildcard */

/* Dissector tables */
static dissector_table_t ranap_ies_dissector_table;
static dissector_table_t ranap_ies_p1_dissector_table;
static dissector_table_t ranap_ies_p2_dissector_table;
static dissector_table_t ranap_extension_dissector_table;
static dissector_table_t ranap_proc_imsg_dissector_table;
static dissector_table_t ranap_proc_sout_dissector_table;
static dissector_table_t ranap_proc_uout_dissector_table;
static dissector_table_t ranap_proc_out_dissector_table;
static dissector_table_t nas_pdu_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);



static const value_string ranap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_ranap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string ranap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_ranap_local         , ASN1_NO_EXTENSIONS     , dissect_ranap_INTEGER_0_65535 },
  {   1, &hf_ranap_global        , ASN1_NO_EXTENSIONS     , dissect_ranap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_ProcedureCode_vals[] = {
  { id_RAB_Assignment, "id-RAB-Assignment" },
  { id_Iu_Release, "id-Iu-Release" },
  { id_RelocationPreparation, "id-RelocationPreparation" },
  { id_RelocationResourceAllocation, "id-RelocationResourceAllocation" },
  { id_RelocationCancel, "id-RelocationCancel" },
  { id_SRNS_ContextTransfer, "id-SRNS-ContextTransfer" },
  { id_SecurityModeControl, "id-SecurityModeControl" },
  { id_DataVolumeReport, "id-DataVolumeReport" },
  { id_Not_Used_8, "id-Not-Used-8" },
  { id_Reset, "id-Reset" },
  { id_RAB_ReleaseRequest, "id-RAB-ReleaseRequest" },
  { id_Iu_ReleaseRequest, "id-Iu-ReleaseRequest" },
  { id_RelocationDetect, "id-RelocationDetect" },
  { id_RelocationComplete, "id-RelocationComplete" },
  { id_Paging, "id-Paging" },
  { id_CommonID, "id-CommonID" },
  { id_CN_InvokeTrace, "id-CN-InvokeTrace" },
  { id_LocationReportingControl, "id-LocationReportingControl" },
  { id_LocationReport, "id-LocationReport" },
  { id_InitialUE_Message, "id-InitialUE-Message" },
  { id_DirectTransfer, "id-DirectTransfer" },
  { id_OverloadControl, "id-OverloadControl" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_SRNS_DataForward, "id-SRNS-DataForward" },
  { id_ForwardSRNS_Context, "id-ForwardSRNS-Context" },
  { id_privateMessage, "id-privateMessage" },
  { id_CN_DeactivateTrace, "id-CN-DeactivateTrace" },
  { id_ResetResource, "id-ResetResource" },
  { id_RANAP_Relocation, "id-RANAP-Relocation" },
  { id_RAB_ModifyRequest, "id-RAB-ModifyRequest" },
  { id_LocationRelatedData, "id-LocationRelatedData" },
  { id_InformationTransfer, "id-InformationTransfer" },
  { id_UESpecificInformation, "id-UESpecificInformation" },
  { id_UplinkInformationExchange, "id-UplinkInformationExchange" },
  { id_DirectInformationTransfer, "id-DirectInformationTransfer" },
  { id_MBMSSessionStart, "id-MBMSSessionStart" },
  { id_MBMSSessionUpdate, "id-MBMSSessionUpdate" },
  { id_MBMSSessionStop, "id-MBMSSessionStop" },
  { id_MBMSUELinking, "id-MBMSUELinking" },
  { id_MBMSRegistration, "id-MBMSRegistration" },
  { id_MBMSCNDe_Registration_Procedure, "id-MBMSCNDe-Registration-Procedure" },
  { id_MBMSRABEstablishmentIndication, "id-MBMSRABEstablishmentIndication" },
  { id_MBMSRABRelease, "id-MBMSRABRelease" },
  { id_enhancedRelocationComplete, "id-enhancedRelocationComplete" },
  { id_enhancedRelocationCompleteConfirm, "id-enhancedRelocationCompleteConfirm" },
  { id_RANAPenhancedRelocation, "id-RANAPenhancedRelocation" },
  { id_SRVCCPreparation, "id-SRVCCPreparation" },
  { id_UeRadioCapabilityMatch, "id-UeRadioCapabilityMatch" },
  { id_UeRegistrationQuery, "id-UeRegistrationQuery" },
  { id_RerouteNASRequest, "id-RerouteNASRequest" },
  { 0, NULL }
};

static value_string_ext ranap_ProcedureCode_vals_ext = VALUE_STRING_EXT_INIT(ranap_ProcedureCode_vals);


static int
dissect_ranap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);

     col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                 val_to_str_ext_const(ProcedureCode, &ranap_ProcedureCode_vals_ext,
                            "unknown message"));
  return offset;
}



static int
dissect_ranap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, false);

  return offset;
}


static const value_string ranap_ProtocolIE_ID_vals[] = {
  { id_AreaIdentity, "id-AreaIdentity" },
  { id_Not_Used_1, "id-Not-Used-1" },
  { id_Not_Used_2, "id-Not-Used-2" },
  { id_CN_DomainIndicator, "id-CN-DomainIndicator" },
  { id_Cause, "id-Cause" },
  { id_ChosenEncryptionAlgorithm, "id-ChosenEncryptionAlgorithm" },
  { id_ChosenIntegrityProtectionAlgorithm, "id-ChosenIntegrityProtectionAlgorithm" },
  { id_ClassmarkInformation2, "id-ClassmarkInformation2" },
  { id_ClassmarkInformation3, "id-ClassmarkInformation3" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_DL_GTP_PDU_SequenceNumber, "id-DL-GTP-PDU-SequenceNumber" },
  { id_EncryptionInformation, "id-EncryptionInformation" },
  { id_IntegrityProtectionInformation, "id-IntegrityProtectionInformation" },
  { id_IuTransportAssociation, "id-IuTransportAssociation" },
  { id_L3_Information, "id-L3-Information" },
  { id_LAI, "id-LAI" },
  { id_NAS_PDU, "id-NAS-PDU" },
  { id_NonSearchingIndication, "id-NonSearchingIndication" },
  { id_NumberOfSteps, "id-NumberOfSteps" },
  { id_OMC_ID, "id-OMC-ID" },
  { id_OldBSS_ToNewBSS_Information, "id-OldBSS-ToNewBSS-Information" },
  { id_PagingAreaID, "id-PagingAreaID" },
  { id_PagingCause, "id-PagingCause" },
  { id_PermanentNAS_UE_ID, "id-PermanentNAS-UE-ID" },
  { id_RAB_ContextItem, "id-RAB-ContextItem" },
  { id_RAB_ContextList, "id-RAB-ContextList" },
  { id_RAB_DataForwardingItem, "id-RAB-DataForwardingItem" },
  { id_RAB_DataForwardingItem_SRNS_CtxReq, "id-RAB-DataForwardingItem-SRNS-CtxReq" },
  { id_RAB_DataForwardingList, "id-RAB-DataForwardingList" },
  { id_RAB_DataForwardingList_SRNS_CtxReq, "id-RAB-DataForwardingList-SRNS-CtxReq" },
  { id_RAB_DataVolumeReportItem, "id-RAB-DataVolumeReportItem" },
  { id_RAB_DataVolumeReportList, "id-RAB-DataVolumeReportList" },
  { id_RAB_DataVolumeReportRequestItem, "id-RAB-DataVolumeReportRequestItem" },
  { id_RAB_DataVolumeReportRequestList, "id-RAB-DataVolumeReportRequestList" },
  { id_RAB_FailedItem, "id-RAB-FailedItem" },
  { id_RAB_FailedList, "id-RAB-FailedList" },
  { id_RAB_ID, "id-RAB-ID" },
  { id_RAB_QueuedItem, "id-RAB-QueuedItem" },
  { id_RAB_QueuedList, "id-RAB-QueuedList" },
  { id_RAB_ReleaseFailedList, "id-RAB-ReleaseFailedList" },
  { id_RAB_ReleaseItem, "id-RAB-ReleaseItem" },
  { id_RAB_ReleaseList, "id-RAB-ReleaseList" },
  { id_RAB_ReleasedItem, "id-RAB-ReleasedItem" },
  { id_RAB_ReleasedList, "id-RAB-ReleasedList" },
  { id_RAB_ReleasedList_IuRelComp, "id-RAB-ReleasedList-IuRelComp" },
  { id_RAB_RelocationReleaseItem, "id-RAB-RelocationReleaseItem" },
  { id_RAB_RelocationReleaseList, "id-RAB-RelocationReleaseList" },
  { id_RAB_SetupItem_RelocReq, "id-RAB-SetupItem-RelocReq" },
  { id_RAB_SetupItem_RelocReqAck, "id-RAB-SetupItem-RelocReqAck" },
  { id_RAB_SetupList_RelocReq, "id-RAB-SetupList-RelocReq" },
  { id_RAB_SetupList_RelocReqAck, "id-RAB-SetupList-RelocReqAck" },
  { id_RAB_SetupOrModifiedItem, "id-RAB-SetupOrModifiedItem" },
  { id_RAB_SetupOrModifiedList, "id-RAB-SetupOrModifiedList" },
  { id_RAB_SetupOrModifyItem, "id-RAB-SetupOrModifyItem" },
  { id_RAB_SetupOrModifyList, "id-RAB-SetupOrModifyList" },
  { id_RAC, "id-RAC" },
  { id_RelocationType, "id-RelocationType" },
  { id_RequestType, "id-RequestType" },
  { id_SAI, "id-SAI" },
  { id_SAPI, "id-SAPI" },
  { id_SourceID, "id-SourceID" },
  { id_Source_ToTarget_TransparentContainer, "id-Source-ToTarget-TransparentContainer" },
  { id_TargetID, "id-TargetID" },
  { id_Target_ToSource_TransparentContainer, "id-Target-ToSource-TransparentContainer" },
  { id_TemporaryUE_ID, "id-TemporaryUE-ID" },
  { id_TraceReference, "id-TraceReference" },
  { id_TraceType, "id-TraceType" },
  { id_TransportLayerAddress, "id-TransportLayerAddress" },
  { id_TriggerID, "id-TriggerID" },
  { id_UE_ID, "id-UE-ID" },
  { id_UL_GTP_PDU_SequenceNumber, "id-UL-GTP-PDU-SequenceNumber" },
  { id_RAB_FailedtoReportItem, "id-RAB-FailedtoReportItem" },
  { id_RAB_FailedtoReportList, "id-RAB-FailedtoReportList" },
  { id_Not_Used_73, "id-Not-Used-73" },
  { id_Not_Used_74, "id-Not-Used-74" },
  { id_KeyStatus, "id-KeyStatus" },
  { id_DRX_CycleLengthCoefficient, "id-DRX-CycleLengthCoefficient" },
  { id_IuSigConIdList, "id-IuSigConIdList" },
  { id_IuSigConIdItem, "id-IuSigConIdItem" },
  { id_IuSigConId, "id-IuSigConId" },
  { id_DirectTransferInformationItem_RANAP_RelocInf, "id-DirectTransferInformationItem-RANAP-RelocInf" },
  { id_DirectTransferInformationList_RANAP_RelocInf, "id-DirectTransferInformationList-RANAP-RelocInf" },
  { id_RAB_ContextItem_RANAP_RelocInf, "id-RAB-ContextItem-RANAP-RelocInf" },
  { id_RAB_ContextList_RANAP_RelocInf, "id-RAB-ContextList-RANAP-RelocInf" },
  { id_RAB_ContextFailedtoTransferItem, "id-RAB-ContextFailedtoTransferItem" },
  { id_RAB_ContextFailedtoTransferList, "id-RAB-ContextFailedtoTransferList" },
  { id_GlobalRNC_ID, "id-GlobalRNC-ID" },
  { id_RAB_ReleasedItem_IuRelComp, "id-RAB-ReleasedItem-IuRelComp" },
  { id_MessageStructure, "id-MessageStructure" },
  { id_Alt_RAB_Parameters, "id-Alt-RAB-Parameters" },
  { id_Ass_RAB_Parameters, "id-Ass-RAB-Parameters" },
  { id_RAB_ModifyList, "id-RAB-ModifyList" },
  { id_RAB_ModifyItem, "id-RAB-ModifyItem" },
  { id_TypeOfError, "id-TypeOfError" },
  { id_BroadcastAssistanceDataDecipheringKeys, "id-BroadcastAssistanceDataDecipheringKeys" },
  { id_LocationRelatedDataRequestType, "id-LocationRelatedDataRequestType" },
  { id_GlobalCN_ID, "id-GlobalCN-ID" },
  { id_LastKnownServiceArea, "id-LastKnownServiceArea" },
  { id_SRB_TrCH_Mapping, "id-SRB-TrCH-Mapping" },
  { id_InterSystemInformation_TransparentContainer, "id-InterSystemInformation-TransparentContainer" },
  { id_NewBSS_To_OldBSS_Information, "id-NewBSS-To-OldBSS-Information" },
  { id_Not_Used_101, "id-Not-Used-101" },
  { id_Not_Used_102, "id-Not-Used-102" },
  { id_SourceRNC_PDCP_context_info, "id-SourceRNC-PDCP-context-info" },
  { id_InformationTransferID, "id-InformationTransferID" },
  { id_SNA_Access_Information, "id-SNA-Access-Information" },
  { id_ProvidedData, "id-ProvidedData" },
  { id_GERAN_BSC_Container, "id-GERAN-BSC-Container" },
  { id_GERAN_Classmark, "id-GERAN-Classmark" },
  { id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, "id-GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item" },
  { id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse, "id-GERAN-Iumode-RAB-FailedList-RABAssgntResponse" },
  { id_VerticalAccuracyCode, "id-VerticalAccuracyCode" },
  { id_ResponseTime, "id-ResponseTime" },
  { id_PositioningPriority, "id-PositioningPriority" },
  { id_ClientType, "id-ClientType" },
  { id_LocationRelatedDataRequestTypeSpecificToGERANIuMode, "id-LocationRelatedDataRequestTypeSpecificToGERANIuMode" },
  { id_SignallingIndication, "id-SignallingIndication" },
  { id_hS_DSCH_MAC_d_Flow_ID, "id-hS-DSCH-MAC-d-Flow-ID" },
  { id_UESBI_Iu, "id-UESBI-Iu" },
  { id_PositionData, "id-PositionData" },
  { id_PositionDataSpecificToGERANIuMode, "id-PositionDataSpecificToGERANIuMode" },
  { id_CellLoadInformationGroup, "id-CellLoadInformationGroup" },
  { id_AccuracyFulfilmentIndicator, "id-AccuracyFulfilmentIndicator" },
  { id_InformationTransferType, "id-InformationTransferType" },
  { id_TraceRecordingSessionInformation, "id-TraceRecordingSessionInformation" },
  { id_TracePropagationParameters, "id-TracePropagationParameters" },
  { id_InterSystemInformationTransferType, "id-InterSystemInformationTransferType" },
  { id_SelectedPLMN_ID, "id-SelectedPLMN-ID" },
  { id_RedirectionCompleted, "id-RedirectionCompleted" },
  { id_RedirectionIndication, "id-RedirectionIndication" },
  { id_NAS_SequenceNumber, "id-NAS-SequenceNumber" },
  { id_RejectCauseValue, "id-RejectCauseValue" },
  { id_APN, "id-APN" },
  { id_CNMBMSLinkingInformation, "id-CNMBMSLinkingInformation" },
  { id_DeltaRAListofIdleModeUEs, "id-DeltaRAListofIdleModeUEs" },
  { id_FrequenceLayerConvergenceFlag, "id-FrequenceLayerConvergenceFlag" },
  { id_InformationExchangeID, "id-InformationExchangeID" },
  { id_InformationExchangeType, "id-InformationExchangeType" },
  { id_InformationRequested, "id-InformationRequested" },
  { id_InformationRequestType, "id-InformationRequestType" },
  { id_IPMulticastAddress, "id-IPMulticastAddress" },
  { id_JoinedMBMSBearerServicesList, "id-JoinedMBMSBearerServicesList" },
  { id_LeftMBMSBearerServicesList, "id-LeftMBMSBearerServicesList" },
  { id_MBMSBearerServiceType, "id-MBMSBearerServiceType" },
  { id_MBMSCNDe_Registration, "id-MBMSCNDe-Registration" },
  { id_MBMSServiceArea, "id-MBMSServiceArea" },
  { id_MBMSSessionDuration, "id-MBMSSessionDuration" },
  { id_MBMSSessionIdentity, "id-MBMSSessionIdentity" },
  { id_PDP_TypeInformation, "id-PDP-TypeInformation" },
  { id_RAB_Parameters, "id-RAB-Parameters" },
  { id_RAListofIdleModeUEs, "id-RAListofIdleModeUEs" },
  { id_MBMSRegistrationRequestType, "id-MBMSRegistrationRequestType" },
  { id_SessionUpdateID, "id-SessionUpdateID" },
  { id_TMGI, "id-TMGI" },
  { id_TransportLayerInformation, "id-TransportLayerInformation" },
  { id_UnsuccessfulLinkingList, "id-UnsuccessfulLinkingList" },
  { id_MBMSLinkingInformation, "id-MBMSLinkingInformation" },
  { id_MBMSSessionRepetitionNumber, "id-MBMSSessionRepetitionNumber" },
  { id_AlternativeRABConfiguration, "id-AlternativeRABConfiguration" },
  { id_AlternativeRABConfigurationRequest, "id-AlternativeRABConfigurationRequest" },
  { id_E_DCH_MAC_d_Flow_ID, "id-E-DCH-MAC-d-Flow-ID" },
  { id_SourceBSS_ToTargetBSS_TransparentContainer, "id-SourceBSS-ToTargetBSS-TransparentContainer" },
  { id_TargetBSS_ToSourceBSS_TransparentContainer, "id-TargetBSS-ToSourceBSS-TransparentContainer" },
  { id_TimeToMBMSDataTransfer, "id-TimeToMBMSDataTransfer" },
  { id_IncludeVelocity, "id-IncludeVelocity" },
  { id_VelocityEstimate, "id-VelocityEstimate" },
  { id_RedirectAttemptFlag, "id-RedirectAttemptFlag" },
  { id_RAT_Type, "id-RAT-Type" },
  { id_PeriodicLocationInfo, "id-PeriodicLocationInfo" },
  { id_MBMSCountingInformation, "id-MBMSCountingInformation" },
  { id_170_not_to_be_used_for_IE_ids, "id-170-not-to-be-used-for-IE-ids" },
  { id_ExtendedRNC_ID, "id-ExtendedRNC-ID" },
  { id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, "id-Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf" },
  { id_Alt_RAB_Parameter_ExtendedMaxBitrateInf, "id-Alt-RAB-Parameter-ExtendedMaxBitrateInf" },
  { id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-Ass-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_Ass_RAB_Parameter_ExtendedMaxBitrateList, "id-Ass-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_RAB_Parameter_ExtendedMaxBitrateList, "id-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_Requested_RAB_Parameter_ExtendedMaxBitrateList, "id-Requested-RAB-Parameter-ExtendedMaxBitrateList" },
  { id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, "id-Requested-RAB-Parameter-ExtendedGuaranteedBitrateList" },
  { id_LAofIdleModeUEs, "id-LAofIdleModeUEs" },
  { id_newLAListofIdleModeUEs, "id-newLAListofIdleModeUEs" },
  { id_LAListwithNoIdleModeUEsAnyMore, "id-LAListwithNoIdleModeUEsAnyMore" },
  { id_183_not_to_be_used_for_IE_ids, "id-183-not-to-be-used-for-IE-ids" },
  { id_GANSS_PositioningDataSet, "id-GANSS-PositioningDataSet" },
  { id_RequestedGANSSAssistanceData, "id-RequestedGANSSAssistanceData" },
  { id_BroadcastGANSSAssistanceDataDecipheringKeys, "id-BroadcastGANSSAssistanceDataDecipheringKeys" },
  { id_d_RNTI_for_NoIuCSUP, "id-d-RNTI-for-NoIuCSUP" },
  { id_RAB_SetupList_EnhancedRelocCompleteReq, "id-RAB-SetupList-EnhancedRelocCompleteReq" },
  { id_RAB_SetupItem_EnhancedRelocCompleteReq, "id-RAB-SetupItem-EnhancedRelocCompleteReq" },
  { id_RAB_SetupList_EnhancedRelocCompleteRes, "id-RAB-SetupList-EnhancedRelocCompleteRes" },
  { id_RAB_SetupItem_EnhancedRelocCompleteRes, "id-RAB-SetupItem-EnhancedRelocCompleteRes" },
  { id_RAB_SetupList_EnhRelocInfoReq, "id-RAB-SetupList-EnhRelocInfoReq" },
  { id_RAB_SetupItem_EnhRelocInfoReq, "id-RAB-SetupItem-EnhRelocInfoReq" },
  { id_RAB_SetupList_EnhRelocInfoRes, "id-RAB-SetupList-EnhRelocInfoRes" },
  { id_RAB_SetupItem_EnhRelocInfoRes, "id-RAB-SetupItem-EnhRelocInfoRes" },
  { id_OldIuSigConId, "id-OldIuSigConId" },
  { id_RAB_FailedList_EnhRelocInfoRes, "id-RAB-FailedList-EnhRelocInfoRes" },
  { id_RAB_FailedItem_EnhRelocInfoRes, "id-RAB-FailedItem-EnhRelocInfoRes" },
  { id_Global_ENB_ID, "id-Global-ENB-ID" },
  { id_UE_History_Information, "id-UE-History-Information" },
  { id_MBMSSynchronisationInformation, "id-MBMSSynchronisationInformation" },
  { id_SubscriberProfileIDforRFP, "id-SubscriberProfileIDforRFP" },
  { id_CSG_Id, "id-CSG-Id" },
  { id_OldIuSigConIdCS, "id-OldIuSigConIdCS" },
  { id_OldIuSigConIdPS, "id-OldIuSigConIdPS" },
  { id_GlobalCN_IDCS, "id-GlobalCN-IDCS" },
  { id_GlobalCN_IDPS, "id-GlobalCN-IDPS" },
  { id_SourceExtendedRNC_ID, "id-SourceExtendedRNC-ID" },
  { id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, "id-RAB-ToBeReleasedItem-EnhancedRelocCompleteRes" },
  { id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes, "id-RAB-ToBeReleasedList-EnhancedRelocCompleteRes" },
  { id_SourceRNC_ID, "id-SourceRNC-ID" },
  { id_Relocation_TargetRNC_ID, "id-Relocation-TargetRNC-ID" },
  { id_Relocation_TargetExtendedRNC_ID, "id-Relocation-TargetExtendedRNC-ID" },
  { id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, "id-Alt-RAB-Parameter-SupportedGuaranteedBitrateInf" },
  { id_Alt_RAB_Parameter_SupportedMaxBitrateInf, "id-Alt-RAB-Parameter-SupportedMaxBitrateInf" },
  { id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList, "id-Ass-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_Ass_RAB_Parameter_SupportedMaxBitrateList, "id-Ass-RAB-Parameter-SupportedMaxBitrateList" },
  { id_RAB_Parameter_SupportedGuaranteedBitrateList, "id-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_RAB_Parameter_SupportedMaxBitrateList, "id-RAB-Parameter-SupportedMaxBitrateList" },
  { id_Requested_RAB_Parameter_SupportedMaxBitrateList, "id-Requested-RAB-Parameter-SupportedMaxBitrateList" },
  { id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList, "id-Requested-RAB-Parameter-SupportedGuaranteedBitrateList" },
  { id_Relocation_SourceRNC_ID, "id-Relocation-SourceRNC-ID" },
  { id_Relocation_SourceExtendedRNC_ID, "id-Relocation-SourceExtendedRNC-ID" },
  { id_EncryptionKey, "id-EncryptionKey" },
  { id_IntegrityProtectionKey, "id-IntegrityProtectionKey" },
  { id_SRVCC_HO_Indication, "id-SRVCC-HO-Indication" },
  { id_SRVCC_Information, "id-SRVCC-Information" },
  { id_SRVCC_Operation_Possible, "id-SRVCC-Operation-Possible" },
  { id_CSG_Id_List, "id-CSG-Id-List" },
  { id_PSRABtobeReplaced, "id-PSRABtobeReplaced" },
  { id_E_UTRAN_Service_Handover, "id-E-UTRAN-Service-Handover" },
  { id_Not_Used_232, "id-Not-Used-232" },
  { id_UE_AggregateMaximumBitRate, "id-UE-AggregateMaximumBitRate" },
  { id_CSG_Membership_Status, "id-CSG-Membership-Status" },
  { id_Cell_Access_Mode, "id-Cell-Access-Mode" },
  { id_IP_Source_Address, "id-IP-Source-Address" },
  { id_CSFB_Information, "id-CSFB-Information" },
  { id_PDP_TypeInformation_extension, "id-PDP-TypeInformation-extension" },
  { id_MSISDN, "id-MSISDN" },
  { id_Offload_RAB_Parameters, "id-Offload-RAB-Parameters" },
  { id_LGW_TransportLayerAddress, "id-LGW-TransportLayerAddress" },
  { id_Correlation_ID, "id-Correlation-ID" },
  { id_IRAT_Measurement_Configuration, "id-IRAT-Measurement-Configuration" },
  { id_MDT_Configuration, "id-MDT-Configuration" },
  { id_Priority_Class_Indicator, "id-Priority-Class-Indicator" },
  { id_RNSAPRelocationParameters, "id-RNSAPRelocationParameters" },
  { id_RABParametersList, "id-RABParametersList" },
  { id_Management_Based_MDT_Allowed, "id-Management-Based-MDT-Allowed" },
  { id_HigherBitratesThan16MbpsFlag, "id-HigherBitratesThan16MbpsFlag" },
  { id_Trace_Collection_Entity_IP_Addess, "id-Trace-Collection-Entity-IP-Addess" },
  { id_End_Of_CSFB, "id-End-Of-CSFB" },
  { id_Time_UE_StayedInCell_EnhancedGranularity, "id-Time-UE-StayedInCell-EnhancedGranularity" },
  { id_Out_Of_UTRAN, "id-Out-Of-UTRAN" },
  { id_TraceRecordingSessionReference, "id-TraceRecordingSessionReference" },
  { id_IMSI, "id-IMSI" },
  { id_HO_Cause, "id-HO-Cause" },
  { id_VoiceSupportMatchIndicator, "id-VoiceSupportMatchIndicator" },
  { id_RSRVCC_HO_Indication, "id-RSRVCC-HO-Indication" },
  { id_RSRVCC_Information, "id-RSRVCC-Information" },
  { id_AnchorPLMN_ID, "id-AnchorPLMN-ID" },
  { id_Tunnel_Information_for_BBF, "id-Tunnel-Information-for-BBF" },
  { id_Management_Based_MDT_PLMN_List, "id-Management-Based-MDT-PLMN-List" },
  { id_SignallingBasedMDTPLMNList, "id-SignallingBasedMDTPLMNList" },
  { id_M4Report, "id-M4Report" },
  { id_M5Report, "id-M5Report" },
  { id_M6Report, "id-M6Report" },
  { id_M7Report, "id-M7Report" },
  { id_TimingDifferenceULDL, "id-TimingDifferenceULDL" },
  { id_Serving_Cell_Identifier, "id-Serving-Cell-Identifier" },
  { id_EARFCN_Extended, "id-EARFCN-Extended" },
  { id_RSRVCC_Operation_Possible, "id-RSRVCC-Operation-Possible" },
  { id_SIPTO_LGW_TransportLayerAddress, "id-SIPTO-LGW-TransportLayerAddress" },
  { id_SIPTO_Correlation_ID, "id-SIPTO-Correlation-ID" },
  { id_LHN_ID, "id-LHN-ID" },
  { id_Session_Re_establishment_Indicator, "id-Session-Re-establishment-Indicator" },
  { id_LastE_UTRANPLMNIdentity, "id-LastE-UTRANPLMNIdentity" },
  { id_RSRQ_Type, "id-RSRQ-Type" },
  { id_RSRQ_Extension, "id-RSRQ-Extension" },
  { id_Additional_CSPS_coordination_information, "id-Additional-CSPS-coordination-information" },
  { id_UERegistrationQueryResult, "id-UERegistrationQueryResult" },
  { id_IuSigConIdRangeEnd, "id-IuSigConIdRangeEnd" },
  { id_BarometricPressure, "id-BarometricPressure" },
  { id_Additional_PositioningDataSet, "id-Additional-PositioningDataSet" },
  { id_CivicAddress, "id-CivicAddress" },
  { id_SGSN_Group_Identity, "id-SGSN-Group-Identity" },
  { id_P_TMSI, "id-P-TMSI" },
  { id_RANAP_Message, "id-RANAP-Message" },
  { id_PowerSavingIndicator, "id-PowerSavingIndicator" },
  { id_UE_Usage_Type, "id-UE-Usage-Type" },
  { id_DCN_ID, "id-DCN-ID" },
  { id_UE_Application_Layer_Measurement_Configuration, "id-UE-Application-Layer-Measurement-Configuration" },
  { id_UE_Application_Layer_Measurement_Configuration_For_Relocation, "id-UE-Application-Layer-Measurement-Configuration-For-Relocation" },
  { 0, NULL }
};

static value_string_ext ranap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(ranap_ProtocolIE_ID_vals);


static int
dissect_ranap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str_ext(ProtocolIE_ID, &ranap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }
  return offset;
}


static const value_string ranap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessfull-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_ranap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_ranap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Field },
};

static int
dissect_ranap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_ranap_T_firstValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldPairFirstValue);

  return offset;
}



static int
dissect_ranap_T_secondValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldPairSecondValue);

  return offset;
}


static const per_sequence_t ProtocolIE_FieldPair_sequence[] = {
  { &hf_ranap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_firstCriticality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_firstValue    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_firstValue },
  { &hf_ranap_secondCriticality, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_secondValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_secondValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolIE_FieldPair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolIE_FieldPair, ProtocolIE_FieldPair_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerPair_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerPair_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_FieldPair },
};

static int
dissect_ranap_ProtocolIE_ContainerPair(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPair, ProtocolIE_ContainerPair_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerList_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
};

static int
dissect_ranap_ProtocolIE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  static const asn1_par_def_t ProtocolIE_ContainerList_pars[] = {
    { "lowerBound", ASN1_PAR_INTEGER },
    { "upperBound", ASN1_PAR_INTEGER },
    { NULL, (asn1_par_type)0 }
  };
  asn1_stack_frame_check(actx, "ProtocolIE-ContainerList", ProtocolIE_ContainerList_pars);
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerList, ProtocolIE_ContainerList_sequence_of,
                                                  asn1_param_get_integer(actx,"lowerBound"), asn1_param_get_integer(actx,"upperBound"), false);

  return offset;
}


static const per_sequence_t ProtocolIE_ContainerPairList_sequence_of[1] = {
  { &hf_ranap_ProtocolIE_ContainerPairList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ContainerPair },
};

static int
dissect_ranap_ProtocolIE_ContainerPairList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  static const asn1_par_def_t ProtocolIE_ContainerPairList_pars[] = {
    { "lowerBound", ASN1_PAR_INTEGER },
    { "upperBound", ASN1_PAR_INTEGER },
    { NULL, (asn1_par_type)0 }
  };
  asn1_stack_frame_check(actx, "ProtocolIE-ContainerPairList", ProtocolIE_ContainerPairList_pars);
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolIE_ContainerPairList, ProtocolIE_ContainerPairList_sequence_of,
                                                  asn1_param_get_integer(actx,"lowerBound"), asn1_param_get_integer(actx,"upperBound"), false);

  return offset;
}



static int
dissect_ranap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_ranap_ext_id        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolExtensionID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_ranap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolExtensionField },
};

static int
dissect_ranap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_ranap_T_private_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_ranap_private_id    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_ID },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_private_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_ranap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_Field },
};

static int
dissect_ranap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, false);

  return offset;
}


static const value_string ranap_AccuracyFulfilmentIndicator_vals[] = {
  {   0, "requested-Accuracy-Fulfilled" },
  {   1, "requested-Accuracy-Not-Fulfilled" },
  { 0, NULL }
};


static int
dissect_ranap_AccuracyFulfilmentIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}




static int
dissect_ranap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  e212_number_type_t number_type = private_data->number_type;
  private_data->number_type = E212_NONE;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                    3, 3, false, &parameter_tvb);

  if (!parameter_tvb)
    return offset;
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, number_type, false);

  return offset;
}



static int
dissect_ranap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t LAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  /* The RANAP ASN.1 defines the RAI as being composed of the LAI and a RAC
   * (cf. with the definition in the RNSAP ASN.1); don't override the fields
   * in that case.
   */
  if (private_data->number_type != E212_RAI) {
    private_data->number_type = E212_LAI;
  }

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LAI, LAI_sequence);



  return offset;
}



static int
dissect_ranap_RAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, 1, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t Additional_CSPS_coordination_information_sequence[] = {
  { &hf_ranap_old_LAI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_LAI },
  { &hf_ranap_old_RAC       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAC },
  { &hf_ranap_nRI           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_BIT_STRING_SIZE_10 },
  { &hf_ranap_uE_is_Attaching, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NULL },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Additional_CSPS_coordination_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Additional_CSPS_coordination_information, Additional_CSPS_coordination_information_sequence);

  return offset;
}



static int
dissect_ranap_Additional_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t Additional_PositioningDataSet_sequence_of[1] = {
  { &hf_ranap_Additional_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Additional_PositioningMethodAndUsage },
};

static int
dissect_ranap_Additional_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Additional_PositioningDataSet, Additional_PositioningDataSet_sequence_of,
                                                  1, maxAddPosSet, false);

  return offset;
}


static const value_string ranap_PriorityLevel_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority" },
  { 0, NULL }
};


static int
dissect_ranap_PriorityLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string ranap_Pre_emptionCapability_vals[] = {
  {   0, "shall-not-trigger-pre-emption" },
  {   1, "may-trigger-pre-emption" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string ranap_Pre_emptionVulnerability_vals[] = {
  {   0, "not-pre-emptable" },
  {   1, "pre-emptable" },
  { 0, NULL }
};


static int
dissect_ranap_Pre_emptionVulnerability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string ranap_QueuingAllowed_vals[] = {
  {   0, "queueing-not-allowed" },
  {   1, "queueing-allowed" },
  { 0, NULL }
};


static int
dissect_ranap_QueuingAllowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t AllocationOrRetentionPriority_sequence[] = {
  { &hf_ranap_priorityLevel , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PriorityLevel },
  { &hf_ranap_pre_emptionCapability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Pre_emptionCapability },
  { &hf_ranap_pre_emptionVulnerability, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Pre_emptionVulnerability },
  { &hf_ranap_queuingAllowed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_QueuingAllowed },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AllocationOrRetentionPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AllocationOrRetentionPriority, AllocationOrRetentionPriority_sequence);

  return offset;
}


static const value_string ranap_Alt_RAB_Parameter_MaxBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_MaxBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16000000U, NULL, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrateList, Alt_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_MaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_MaxBitrates, Alt_RAB_Parameter_MaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_MaxBitrateInf_sequence[] = {
  { &hf_ranap_altMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_MaxBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_MaxBitrateInf, Alt_RAB_Parameter_MaxBitrateInf_sequence);

  return offset;
}


static const value_string ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals[] = {
  {   0, "unspecified" },
  {   1, "value-range" },
  {   2, "discrete-values" },
  { 0, NULL }
};


static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_GuaranteedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16000000U, NULL, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList, Alt_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates, Alt_RAB_Parameter_GuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_GuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf, Alt_RAB_Parameter_GuaranteedBitrateInf_sequence);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameters_sequence[] = {
  { &hf_ranap_altMaxBitrateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_MaxBitrateInf },
  { &hf_ranap_altGuaranteedBitRateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameters, Alt_RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedGuaranteedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16000001U, 256000000U, NULL, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList, Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates, Alt_RAB_Parameter_ExtendedGuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altExtendedGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altExtendedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_sequence);

  return offset;
}



static int
dissect_ranap_SupportedBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, true);

  return offset;
}


static const per_sequence_t SupportedRAB_ParameterBitrateList_sequence_of[1] = {
  { &hf_ranap_SupportedRAB_ParameterBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedBitrate },
};

static int
dissect_ranap_SupportedRAB_ParameterBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SupportedRAB_ParameterBitrateList, SupportedRAB_ParameterBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedGuaranteedBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedRAB_ParameterBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates, Alt_RAB_Parameter_SupportedGuaranteedBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_sequence[] = {
  { &hf_ranap_altSupportedGuaranteedBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_GuaranteedBitrateType },
  { &hf_ranap_altSupportedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedMaxBitrate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            16000001U, 256000000U, NULL, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList, Alt_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates, Alt_RAB_Parameter_ExtendedMaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_ExtendedMaxBitrateInf_sequence[] = {
  { &hf_ranap_altExtendedMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altExtendedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf, Alt_RAB_Parameter_ExtendedMaxBitrateInf_sequence);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedMaxBitrates_sequence_of[1] = {
  { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SupportedRAB_ParameterBitrateList },
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates, Alt_RAB_Parameter_SupportedMaxBitrates_sequence_of,
                                                  1, maxNrOfAltValues, false);

  return offset;
}


static const per_sequence_t Alt_RAB_Parameter_SupportedMaxBitrateInf_sequence[] = {
  { &hf_ranap_altSupportedMaxBitrateType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Alt_RAB_Parameter_MaxBitrateType },
  { &hf_ranap_altSupportedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf, Alt_RAB_Parameter_SupportedMaxBitrateInf_sequence);

  return offset;
}


static const value_string ranap_AlternativeRABConfigurationRequest_vals[] = {
  {   0, "alternative-RAB-configuration-Requested" },
  { 0, NULL }
};


static int
dissect_ranap_AlternativeRABConfigurationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_OCTET_STRING_SIZE_1_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1000, false, NULL);

  return offset;
}



static int
dissect_ranap_Cell_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, false);

  return offset;
}


static const per_sequence_t CellIdList_sequence_of[1] = {
  { &hf_ranap_CellIdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Cell_Id },
};

static int
dissect_ranap_CellIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CellIdList, CellIdList_sequence_of,
                                                  1, maxNrOfCellIds, false);

  return offset;
}


static const per_sequence_t CellBased_sequence[] = {
  { &hf_ranap_cellIdList    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CellIdList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellBased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellBased, CellBased_sequence);

  return offset;
}


static const per_sequence_t LAI_List_sequence_of[1] = {
  { &hf_ranap_LAI_List_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
};

static int
dissect_ranap_LAI_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LAI_List, LAI_List_sequence_of,
                                                  1, maxNrOfLAIs, false);

  return offset;
}


static const per_sequence_t LABased_sequence[] = {
  { &hf_ranap_laiList       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAI_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LABased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LABased, LABased_sequence);

  return offset;
}


static const per_sequence_t RAI_sequence[] = {
  { &hf_ranap_lAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->number_type = E212_RAI;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAI, RAI_sequence);



  return offset;
}


static const per_sequence_t RAI_List_sequence_of[1] = {
  { &hf_ranap_RAI_List_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAI },
};

static int
dissect_ranap_RAI_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAI_List, RAI_List_sequence_of,
                                                  1, maxNrOfRAIs, false);

  return offset;
}


static const per_sequence_t RABased_sequence[] = {
  { &hf_ranap_raiList       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAI_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABased, RABased_sequence);

  return offset;
}


static const per_sequence_t PLMNList_sequence_of[1] = {
  { &hf_ranap_PLMNList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
};

static int
dissect_ranap_PLMNList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PLMNList, PLMNList_sequence_of,
                                                  1, maxnoofPLMNs, false);

  return offset;
}


static const per_sequence_t PLMNBased_sequence[] = {
  { &hf_ranap_plmnList      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PLMNBased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PLMNBased, PLMNBased_sequence);

  return offset;
}


static const value_string ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration_vals[] = {
  {   0, "cellbased" },
  {   1, "labased" },
  {   2, "rabased" },
  {   3, "plmn-area-based" },
  { 0, NULL }
};

static const per_choice_t AreaScopeForUEApplicationLayerMeasurementConfiguration_choice[] = {
  {   0, &hf_ranap_cellbased     , ASN1_EXTENSION_ROOT    , dissect_ranap_CellBased },
  {   1, &hf_ranap_labased       , ASN1_EXTENSION_ROOT    , dissect_ranap_LABased },
  {   2, &hf_ranap_rabased       , ASN1_EXTENSION_ROOT    , dissect_ranap_RABased },
  {   3, &hf_ranap_plmn_area_based, ASN1_EXTENSION_ROOT    , dissect_ranap_PLMNBased },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration, AreaScopeForUEApplicationLayerMeasurementConfiguration_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UE_Application_Layer_Measurement_Configuration_sequence[] = {
  { &hf_ranap_applicationLayerContainerForMeasurementConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_OCTET_STRING_SIZE_1_1000 },
  { &hf_ranap_areaScopeForUEApplicationLayerMeasurementConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_Application_Layer_Measurement_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_Application_Layer_Measurement_Configuration, UE_Application_Layer_Measurement_Configuration_sequence);

  return offset;
}



static int
dissect_ranap_TraceReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 3, false, NULL);

  return offset;
}



static int
dissect_ranap_TraceRecordingSessionReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const value_string ranap_TraceDepth_vals[] = {
  {   0, "minimum" },
  {   1, "medium" },
  {   2, "maximum" },
  { 0, NULL }
};


static int
dissect_ranap_TraceDepth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_T_interface_vals[] = {
  {   0, "iu-cs" },
  {   1, "iu-ps" },
  {   2, "iur" },
  {   3, "iub" },
  {   4, "uu" },
  { 0, NULL }
};


static int
dissect_ranap_T_interface(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t InterfacesToTraceItem_sequence[] = {
  { &hf_ranap_interface     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_interface },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterfacesToTraceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterfacesToTraceItem, InterfacesToTraceItem_sequence);

  return offset;
}


static const per_sequence_t ListOfInterfacesToTrace_sequence_of[1] = {
  { &hf_ranap_ListOfInterfacesToTrace_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_InterfacesToTraceItem },
};

static int
dissect_ranap_ListOfInterfacesToTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOfInterfacesToTrace, ListOfInterfacesToTrace_sequence_of,
                                                  1, maxNrOfInterfaces, false);

  return offset;
}


static const per_sequence_t TracePropagationParameters_sequence[] = {
  { &hf_ranap_traceRecordingSessionReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceRecordingSessionReference },
  { &hf_ranap_traceDepth    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceDepth },
  { &hf_ranap_listOfInterfacesToTrace, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ListOfInterfacesToTrace },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TracePropagationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TracePropagationParameters, TracePropagationParameters_sequence);

  return offset;
}



static int
dissect_ranap_TransportLayerAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  proto_item *item;
  proto_tree *subtree, *nsap_tree;
  uint8_t *padded_nsap_bytes;
  tvbuff_t *nsap_tvb;
  int tvb_len;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 160, true, NULL, 0, &parameter_tvb, NULL);

  if (!parameter_tvb)
    return offset;

  /* Get the length */
  tvb_len = tvb_reported_length(parameter_tvb);
  subtree = proto_item_add_subtree(actx->created_item, ett_ranap_transportLayerAddress);
  if (tvb_len == 4){
    /* IPv4 */
    proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_ipv4, parameter_tvb, 0, tvb_len, ENC_BIG_ENDIAN);
    private_data_set_transportLayerAddress_ipv4(actx, tvb_get_ipv4(parameter_tvb, 0));
  }
  if (tvb_len == 16){
    /* IPv6 */
    proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_ipv6, parameter_tvb, 0, tvb_len, ENC_NA);
  }
  if (tvb_len == 20 || tvb_len == 7){
    /* NSAP */
    if (tvb_len == 7){
      /* Unpadded IPv4 NSAP */
      /* Creating a new TVB with padding */
      padded_nsap_bytes = (uint8_t*) wmem_alloc0(actx->pinfo->pool, 20);
      tvb_memcpy(parameter_tvb, padded_nsap_bytes, 0, tvb_len);
      nsap_tvb = tvb_new_child_real_data(tvb, padded_nsap_bytes, 20, 20);
      add_new_data_source(actx->pinfo, nsap_tvb, "Padded NSAP Data");
    } else {
      /* Padded NSAP*/
      nsap_tvb = parameter_tvb;
    }
    item = proto_tree_add_item(subtree, hf_ranap_transportLayerAddress_nsap, parameter_tvb, 0, tvb_len, ENC_NA);
    nsap_tree = proto_item_add_subtree(item, ett_ranap_transportLayerAddress_nsap);

    if(tvb_get_ntoh24(parameter_tvb,0) == 0x350001){
      /* IPv4 */
      private_data_set_transportLayerAddress_ipv4(actx, tvb_get_ipv4(parameter_tvb, 3));
    }
    dissect_nsap(nsap_tvb, actx->pinfo, 0, 20, nsap_tree);
  }


  return offset;
}


static const per_sequence_t UE_Application_Layer_Measurement_Configuration_For_Relocation_sequence[] = {
  { &hf_ranap_areaScopeForUEApplicationLayerMeasurementConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration },
  { &hf_ranap_traceReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_tracePropagationParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TracePropagationParameters },
  { &hf_ranap_traceCollectionEntityIPAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation, UE_Application_Layer_Measurement_Configuration_For_Relocation_sequence);

  return offset;
}



static int
dissect_ranap_APN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, false, NULL);

  return offset;
}



static int
dissect_ranap_SAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t SAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_sAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->number_type = E212_SAI;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SAI, SAI_sequence);



  return offset;
}


static const value_string ranap_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ranap_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}



static int
dissect_ranap_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_ranap_latitudeSign  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_latitudeSign },
  { &hf_ranap_latitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_8388607 },
  { &hf_ranap_longitude     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M8388608_8388607 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GeographicalCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}


static const per_sequence_t GA_Point_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Point, GA_Point_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { &hf_ranap_uncertaintyCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertainty, GA_PointWithUnCertainty_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_item_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_Polygon_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_Polygon_item, GA_Polygon_item_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_sequence_of[1] = {
  { &hf_ranap_GA_Polygon_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GA_Polygon_item },
};

static int
dissect_ranap_GA_Polygon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_GA_Polygon, GA_Polygon_sequence_of,
                                                  1, maxNrOfPoints, false);

  return offset;
}



static int
dissect_ranap_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, false);

  return offset;
}


static const per_sequence_t GA_UncertaintyEllipse_sequence[] = {
  { &hf_ranap_uncertaintySemi_major, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_uncertaintySemi_minor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_UncertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_UncertaintyEllipse, GA_UncertaintyEllipse_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertaintyEllipse_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_UncertaintyEllipse },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithUnCertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithUnCertaintyEllipse, GA_PointWithUnCertaintyEllipse_sequence);

  return offset;
}


static const value_string ranap_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ranap_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t GA_AltitudeAndDirection_sequence[] = {
  { &hf_ranap_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_T_directionOfAltitude },
  { &hf_ranap_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_AltitudeAndDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_AltitudeAndDirection, GA_AltitudeAndDirection_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitude_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_AltitudeAndDirection },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitude, GA_PointWithAltitude_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_AltitudeAndDirection },
  { &hf_ranap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GA_UncertaintyEllipse },
  { &hf_ranap_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid, GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence);

  return offset;
}


static const per_sequence_t GA_EllipsoidArc_sequence[] = {
  { &hf_ranap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GeographicalCoordinates },
  { &hf_ranap_innerRadius   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_65535 },
  { &hf_ranap_uncertaintyRadius, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_offsetAngle   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { &hf_ranap_includedAngle , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_179 },
  { &hf_ranap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_127 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GA_EllipsoidArc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GA_EllipsoidArc, GA_EllipsoidArc_sequence);

  return offset;
}


static const value_string ranap_GeographicalArea_vals[] = {
  {   0, "point" },
  {   1, "pointWithUnCertainty" },
  {   2, "polygon" },
  {   3, "pointWithUncertaintyEllipse" },
  {   4, "pointWithAltitude" },
  {   5, "pointWithAltitudeAndUncertaintyEllipsoid" },
  {   6, "ellipsoidArc" },
  { 0, NULL }
};

static const per_choice_t GeographicalArea_choice[] = {
  {   0, &hf_ranap_point         , ASN1_EXTENSION_ROOT    , dissect_ranap_GA_Point },
  {   1, &hf_ranap_pointWithUnCertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_GA_PointWithUnCertainty },
  {   2, &hf_ranap_polygon       , ASN1_EXTENSION_ROOT    , dissect_ranap_GA_Polygon },
  {   3, &hf_ranap_pointWithUncertaintyEllipse, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithUnCertaintyEllipse },
  {   4, &hf_ranap_pointWithAltitude, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithAltitude },
  {   5, &hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid },
  {   6, &hf_ranap_ellipsoidArc  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_GA_EllipsoidArc },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_GeographicalArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_GeographicalArea, GeographicalArea_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_AreaIdentity_vals[] = {
  {   0, "sAI" },
  {   1, "geographicalArea" },
  { 0, NULL }
};

static const per_choice_t AreaIdentity_choice[] = {
  {   0, &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_SAI },
  {   1, &hf_ranap_geographicalArea, ASN1_EXTENSION_ROOT    , dissect_ranap_GeographicalArea },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_AreaIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_AreaIdentity, AreaIdentity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_MaxBitrateList, Ass_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList, Ass_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameters_sequence[] = {
  { &hf_ranap_assMaxBitrateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_assGuaranteedBitRateInf, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Ass_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Ass_RAB_Parameters, Ass_RAB_Parameters_sequence);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Ass_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList, Ass_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}



static int
dissect_ranap_SNAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t AuthorisedSNAs_sequence_of[1] = {
  { &hf_ranap_AuthorisedSNAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SNAC },
};

static int
dissect_ranap_AuthorisedSNAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedSNAs, AuthorisedSNAs_sequence_of,
                                                  1, maxNrOfSNAs, false);

  return offset;
}


static const per_sequence_t AuthorisedPLMNs_item_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_authorisedSNAsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_AuthorisedSNAs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_AuthorisedPLMNs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_AuthorisedPLMNs_item, AuthorisedPLMNs_item_sequence);

  return offset;
}


static const per_sequence_t AuthorisedPLMNs_sequence_of[1] = {
  { &hf_ranap_AuthorisedPLMNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_AuthorisedPLMNs_item },
};

static int
dissect_ranap_AuthorisedPLMNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_AuthorisedPLMNs, AuthorisedPLMNs_sequence_of,
                                                  1, maxNrOfPLMNsSN, false);

  return offset;
}



static int
dissect_ranap_BarometricPressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            30000U, 115000U, NULL, false);

  return offset;
}



static int
dissect_ranap_BindingID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &value_tvb);

  /* N.B. value_tvb is 4 bytes of OCTET STRING */
  if (tvb_get_ntohs(value_tvb, 2) == 0) {
    /* Will show first 2 bytes as an integer, as very likely to be a UDP port number */
    uint16_t port_number = tvb_get_ntohs(value_tvb, 0);
    private_data_set_binding_id_port(actx, port_number);
    proto_item_append_text(actx->created_item, " (%u)", port_number);
  }


  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_56(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     56, 56, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t BroadcastAssistanceDataDecipheringKeys_sequence[] = {
  { &hf_ranap_cipheringKeyFlag, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_1 },
  { &hf_ranap_currentDecipheringKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_56 },
  { &hf_ranap_nextDecipheringKey, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_56 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_BroadcastAssistanceDataDecipheringKeys, BroadcastAssistanceDataDecipheringKeys_sequence);

  return offset;
}


static const value_string ranap_CauseRadioNetwork_vals[] = {
  {   1, "rab-pre-empted" },
  {   2, "trelocoverall-expiry" },
  {   3, "trelocprep-expiry" },
  {   4, "treloccomplete-expiry" },
  {   5, "tqueing-expiry" },
  {   6, "relocation-triggered" },
  {   7, "trellocalloc-expiry" },
  {   8, "unable-to-establish-during-relocation" },
  {   9, "unknown-target-rnc" },
  {  10, "relocation-cancelled" },
  {  11, "successful-relocation" },
  {  12, "requested-ciphering-and-or-integrity-protection-algorithms-not-supported" },
  {  13, "conflict-with-already-existing-integrity-protection-and-or-ciphering-information" },
  {  14, "failure-in-the-radio-interface-procedure" },
  {  15, "release-due-to-utran-generated-reason" },
  {  16, "user-inactivity" },
  {  17, "time-critical-relocation" },
  {  18, "requested-traffic-class-not-available" },
  {  19, "invalid-rab-parameters-value" },
  {  20, "requested-maximum-bit-rate-not-available" },
  {  21, "requested-guaranteed-bit-rate-not-available" },
  {  22, "requested-transfer-delay-not-achievable" },
  {  23, "invalid-rab-parameters-combination" },
  {  24, "condition-violation-for-sdu-parameters" },
  {  25, "condition-violation-for-traffic-handling-priority" },
  {  26, "condition-violation-for-guaranteed-bit-rate" },
  {  27, "user-plane-versions-not-supported" },
  {  28, "iu-up-failure" },
  {  29, "relocation-failure-in-target-CN-RNC-or-target-system" },
  {  30, "invalid-RAB-ID" },
  {  31, "no-remaining-rab" },
  {  32, "interaction-with-other-procedure" },
  {  33, "requested-maximum-bit-rate-for-dl-not-available" },
  {  34, "requested-maximum-bit-rate-for-ul-not-available" },
  {  35, "requested-guaranteed-bit-rate-for-dl-not-available" },
  {  36, "requested-guaranteed-bit-rate-for-ul-not-available" },
  {  37, "repeated-integrity-checking-failure" },
  {  38, "requested-request-type-not-supported" },
  {  39, "request-superseded" },
  {  40, "release-due-to-UE-generated-signalling-connection-release" },
  {  41, "resource-optimisation-relocation" },
  {  42, "requested-information-not-available" },
  {  43, "relocation-desirable-for-radio-reasons" },
  {  44, "relocation-not-supported-in-target-RNC-or-target-system" },
  {  45, "directed-retry" },
  {  46, "radio-connection-with-UE-Lost" },
  {  47, "rNC-unable-to-establish-all-RFCs" },
  {  48, "deciphering-keys-not-available" },
  {  49, "dedicated-assistance-data-not-available" },
  {  50, "relocation-target-not-allowed" },
  {  51, "location-reporting-congestion" },
  {  52, "reduce-load-in-serving-cell" },
  {  53, "no-radio-resources-available-in-target-cell" },
  {  54, "gERAN-Iumode-failure" },
  {  55, "access-restricted-due-to-shared-networks" },
  {  56, "incoming-relocation-not-supported-due-to-PUESBINE-feature" },
  {  57, "traffic-load-in-the-target-cell-higher-than-in-the-source-cell" },
  {  58, "mBMS-no-multicast-service-for-this-UE" },
  {  59, "mBMS-unknown-UE-ID" },
  {  60, "successful-MBMS-session-start-no-data-bearer-necessary" },
  {  61, "mBMS-superseded-due-to-NNSF" },
  {  62, "mBMS-UE-linking-already-done" },
  {  63, "mBMS-UE-de-linking-failure-no-existing-UE-linking" },
  {  64, "tMGI-unknown" },
  { 0, NULL }
};

static value_string_ext ranap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(ranap_CauseRadioNetwork_vals);


static int
dissect_ranap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, false);

  return offset;
}


static const value_string ranap_CauseTransmissionNetwork_vals[] = {
  {  65, "signalling-transport-resource-failure" },
  {  66, "iu-transport-connection-failed-to-establish" },
  { 0, NULL }
};


static int
dissect_ranap_CauseTransmissionNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            65U, 80U, NULL, false);

  return offset;
}


static const value_string ranap_CauseNAS_vals[] = {
  {  81, "user-restriction-start-indication" },
  {  82, "user-restriction-end-indication" },
  {  83, "normal-release" },
  {  84, "csg-subscription-expiry" },
  { 0, NULL }
};


static int
dissect_ranap_CauseNAS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            81U, 96U, NULL, false);

  return offset;
}


static const value_string ranap_CauseProtocol_vals[] = {
  {  97, "transfer-syntax-error" },
  {  98, "semantic-error" },
  {  99, "message-not-compatible-with-receiver-state" },
  { 100, "abstract-syntax-error-reject" },
  { 101, "abstract-syntax-error-ignore-and-notify" },
  { 102, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_ranap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            97U, 112U, NULL, false);

  return offset;
}


static const value_string ranap_CauseMisc_vals[] = {
  { 113, "om-intervention" },
  { 114, "no-resource-available" },
  { 115, "unspecified-failure" },
  { 116, "network-optimisation" },
  { 0, NULL }
};


static int
dissect_ranap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            113U, 128U, NULL, false);

  return offset;
}



static int
dissect_ranap_CauseNon_Standard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            129U, 256U, NULL, false);

  return offset;
}


static const value_string ranap_CauseRadioNetworkExtension_vals[] = {
  { 257, "iP-multicast-address-and-APN-not-valid" },
  { 258, "mBMS-de-registration-rejected-due-to-implicit-registration" },
  { 259, "mBMS-request-superseded" },
  { 260, "mBMS-de-registration-during-session-not-allowed" },
  { 261, "mBMS-no-data-bearer-necessary" },
  { 262, "periodicLocationInformationNotAvailable" },
  { 263, "gTP-Resources-Unavailable" },
  { 264, "tMGI-inUse-overlapping-MBMS-service-area" },
  { 265, "mBMS-no-cell-in-MBMS-service-area" },
  { 266, "no-Iu-CS-UP-relocation" },
  { 267, "successful-MBMS-Session-Start-IP-Multicast-Bearer-established" },
  { 268, "cS-fallback-triggered" },
  { 269, "invalid-CSG-Id" },
  { 0, NULL }
};


static int
dissect_ranap_CauseRadioNetworkExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            257U, 512U, NULL, false);

  return offset;
}


static const value_string ranap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transmissionNetwork" },
  {   2, "nAS" },
  {   3, "protocol" },
  {   4, "misc" },
  {   5, "non-Standard" },
  {   6, "radioNetworkExtension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_ranap_radioNetwork  , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseRadioNetwork },
  {   1, &hf_ranap_transmissionNetwork, ASN1_EXTENSION_ROOT    , dissect_ranap_CauseTransmissionNetwork },
  {   2, &hf_ranap_nAS           , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseNAS },
  {   3, &hf_ranap_protocol      , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseProtocol },
  {   4, &hf_ranap_misc          , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseMisc },
  {   5, &hf_ranap_non_Standard  , ASN1_EXTENSION_ROOT    , dissect_ranap_CauseNon_Standard },
  {   6, &hf_ranap_radioNetworkExtension, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_CauseRadioNetworkExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_Cause, Cause_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_Cell_Access_Mode_vals[] = {
  {   0, "hybrid" },
  { 0, NULL }
};


static int
dissect_ranap_Cell_Access_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_Cell_Capacity_Class_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, true);

  return offset;
}



static int
dissect_ranap_LoadValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}



static int
dissect_ranap_RTLoadValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}



static int
dissect_ranap_NRTLoadInformationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t CellLoadInformation_sequence[] = {
  { &hf_ranap_cell_Capacity_Class_Value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cell_Capacity_Class_Value },
  { &hf_ranap_loadValue     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoadValue },
  { &hf_ranap_rTLoadValue   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RTLoadValue },
  { &hf_ranap_nRTLoadInformationValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NRTLoadInformationValue },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformation, CellLoadInformation_sequence);

  return offset;
}



static int
dissect_ranap_TargetCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, false);

  return offset;
}


static const per_sequence_t SourceUTRANCellID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_uTRANcellID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TargetCellId },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceUTRANCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceUTRANCellID, SourceUTRANCellID_sequence);

  return offset;
}



static int
dissect_ranap_CI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const per_sequence_t CGI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_cI            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CI },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->number_type = E212_CGI;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CGI, CGI_sequence);



  return offset;
}


static const value_string ranap_SourceCellID_vals[] = {
  {   0, "sourceUTRANCellID" },
  {   1, "sourceGERANCellID" },
  { 0, NULL }
};

static const per_choice_t SourceCellID_choice[] = {
  {   0, &hf_ranap_sourceUTRANCellID, ASN1_EXTENSION_ROOT    , dissect_ranap_SourceUTRANCellID },
  {   1, &hf_ranap_sourceGERANCellID, ASN1_EXTENSION_ROOT    , dissect_ranap_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceCellID, SourceCellID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellLoadInformationGroup_sequence[] = {
  { &hf_ranap_sourceCellID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SourceCellID },
  { &hf_ranap_uplinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_downlinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CellLoadInformationGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CellLoadInformationGroup, CellLoadInformationGroup_sequence);

  return offset;
}


static const value_string ranap_CellType_vals[] = {
  {   0, "macro" },
  {   1, "micro" },
  {   2, "pico" },
  {   3, "femto" },
  { 0, NULL }
};


static int
dissect_ranap_CellType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_CivicAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string ranap_ClientType_vals[] = {
  {   0, "emergency-Services" },
  {   1, "value-Added-Services" },
  {   2, "pLMN-Operator-Services" },
  {   3, "lawful-Intercept-Services" },
  {   4, "pLMN-Operator-Broadcast-Services" },
  {   5, "pLMN-Operator-O-et-M" },
  {   6, "pLMN-Operator-Anonymous-Statistics" },
  {   7, "pLMN-Operator-Target-MS-Service-Support" },
  { 0, NULL }
};


static int
dissect_ranap_ClientType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_RepetitionNumber0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_ranap_iECriticality , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RepetitionNumber0 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_ranap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_ranap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProcedureCode },
  { &hf_ranap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TriggeringMessage },
  { &hf_ranap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Criticality },
  { &hf_ranap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CriticalityDiagnostics_IE_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_ranap_RepetitionNumber1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t MessageStructure_item_sequence[] = {
  { &hf_ranap_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_ID },
  { &hf_ranap_item_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RepetitionNumber1 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MessageStructure_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MessageStructure_item, MessageStructure_item_sequence);

  return offset;
}


static const per_sequence_t MessageStructure_sequence_of[1] = {
  { &hf_ranap_MessageStructure_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MessageStructure_item },
};

static int
dissect_ranap_MessageStructure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MessageStructure, MessageStructure_sequence_of,
                                                  1, maxNrOfLevels, false);

  return offset;
}


static const value_string ranap_EncryptionAlgorithm_vals[] = {
  {   0, "no-encryption" },
  {   1, "standard-UMTS-encryption-algorith-UEA1" },
  {   2, "standard-UMTS-encryption-algorithm-UEA2" },
  { 0, NULL }
};


static int
dissect_ranap_EncryptionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_ranap_ChosenEncryptionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_EncryptionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ranap_IntegrityProtectionAlgorithm_vals[] = {
  {   0, "standard-UMTS-integrity-algorithm-UIA1" },
  {   1, "standard-UMTS-integrity-algorithm-UIA2" },
  {  15, "no-value" },
  { 0, NULL }
};


static int
dissect_ranap_IntegrityProtectionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IntegrityProtectionAlgorithm(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_ClassmarkInformation2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_ranap_ClassmarkInformation3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string ranap_CN_DomainIndicator_vals[] = {
  {   0, "cs-domain" },
  {   1, "ps-domain" },
  { 0, NULL }
};


static int
dissect_ranap_CN_DomainIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_CN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_ranap_Correlation_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const value_string ranap_CSFB_Information_vals[] = {
  {   0, "csfb" },
  {   1, "csfb-high-priority" },
  { 0, NULL }
};


static int
dissect_ranap_CSFB_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_CSG_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CSG_Id_List_sequence_of[1] = {
  { &hf_ranap_CSG_Id_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CSG_Id },
};

static int
dissect_ranap_CSG_Id_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_CSG_Id_List, CSG_Id_List_sequence_of,
                                                  1, maxNrOfCSGs, false);

  return offset;
}


static const value_string ranap_CSG_Membership_Status_vals[] = {
  {   0, "member" },
  {   1, "non-member" },
  { 0, NULL }
};


static int
dissect_ranap_CSG_Membership_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_DataPDUType_vals[] = {
  {   0, "pDUtype0" },
  {   1, "pDUtype1" },
  { 0, NULL }
};


static int
dissect_ranap_DataPDUType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_DataVolumeReference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string ranap_DataVolumeReportingIndication_vals[] = {
  {   0, "do-report" },
  {   1, "do-not-report" },
  { 0, NULL }
};


static int
dissect_ranap_DataVolumeReportingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_DCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_ranap_DCN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const value_string ranap_DeliveryOfErroneousSDU_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "no-error-detection-consideration" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOfErroneousSDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string ranap_DeliveryOrder_vals[] = {
  {   0, "delivery-order-requested" },
  {   1, "delivery-order-not-requested" },
  { 0, NULL }
};


static int
dissect_ranap_DeliveryOrder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t NewRAListofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_NewRAListofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_NewRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_NewRAListofIdleModeUEs, NewRAListofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, false);

  return offset;
}


static const per_sequence_t RAListwithNoIdleModeUEsAnyMore_sequence_of[1] = {
  { &hf_ranap_RAListwithNoIdleModeUEsAnyMore_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_RAListwithNoIdleModeUEsAnyMore(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAListwithNoIdleModeUEsAnyMore, RAListwithNoIdleModeUEsAnyMore_sequence_of,
                                                  1, maxMBMSRA, false);

  return offset;
}


static const per_sequence_t DeltaRAListofIdleModeUEs_sequence[] = {
  { &hf_ranap_newRAListofIdleModeUEs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_NewRAListofIdleModeUEs },
  { &hf_ranap_rAListwithNoIdleModeUEsAnyMore, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RAListwithNoIdleModeUEsAnyMore },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DeltaRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DeltaRAListofIdleModeUEs, DeltaRAListofIdleModeUEs_sequence);

  return offset;
}



static int
dissect_ranap_DL_GTP_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_DL_N_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_D_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, false);

  return offset;
}



static int
dissect_ranap_DRX_CycleLengthCoefficient(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            6U, 9U, NULL, false);

  return offset;
}



static int
dissect_ranap_DSCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_ranap_EARFCN_Extended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            65536U, 262143U, NULL, true);

  return offset;
}



static int
dissect_ranap_E_DCH_MAC_d_Flow_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfEDCHMACdFlows_1, NULL, false);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ranap_ENB_ID_vals[] = {
  {   0, "macroENB-ID" },
  {   1, "homeENB-ID" },
  {   2, "short-macroENB-ID" },
  {   3, "long-macroENB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_ranap_macroENB_ID   , ASN1_EXTENSION_ROOT    , dissect_ranap_BIT_STRING_SIZE_20 },
  {   1, &hf_ranap_homeENB_ID    , ASN1_EXTENSION_ROOT    , dissect_ranap_BIT_STRING_SIZE_28 },
  {   2, &hf_ranap_short_macroENB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_BIT_STRING_SIZE_18 },
  {   3, &hf_ranap_long_macroENB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_ranap_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PermittedEncryptionAlgorithms_sequence_of[1] = {
  { &hf_ranap_PermittedEncryptionAlgorithms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EncryptionAlgorithm },
};

static int
dissect_ranap_PermittedEncryptionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedEncryptionAlgorithms, PermittedEncryptionAlgorithms_sequence_of,
                                                  1, 16, false);

  return offset;
}



static int
dissect_ranap_EncryptionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EncryptionInformation_sequence[] = {
  { &hf_ranap_permittedAlgorithms, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PermittedEncryptionAlgorithms },
  { &hf_ranap_key           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EncryptionKey },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_EncryptionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EncryptionInformation, EncryptionInformation_sequence);

  return offset;
}


static const value_string ranap_End_Of_CSFB_vals[] = {
  {   0, "end-of-CSFB" },
  { 0, NULL }
};


static int
dissect_ranap_End_Of_CSFB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const per_sequence_t IMEIList_sequence_of[1] = {
  { &hf_ranap_IMEIList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEI },
};

static int
dissect_ranap_IMEIList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEIList, IMEIList_sequence_of,
                                                  1, maxNrOfUEsToBeTraced, false);

  return offset;
}



static int
dissect_ranap_IMEISV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const per_sequence_t IMEISVList_sequence_of[1] = {
  { &hf_ranap_IMEISVList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEISV },
};

static int
dissect_ranap_IMEISVList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_IMEISVList, IMEISVList_sequence_of,
                                                  1, maxNrOfUEsToBeTraced, false);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t IMEIGroup_sequence[] = {
  { &hf_ranap_iMEI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEI },
  { &hf_ranap_iMEIMask      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_7 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEIGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEIGroup, IMEIGroup_sequence);

  return offset;
}


static const per_sequence_t IMEISVGroup_sequence[] = {
  { &hf_ranap_iMEISV        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IMEISV },
  { &hf_ranap_iMEISVMask    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_7 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IMEISVGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IMEISVGroup, IMEISVGroup_sequence);

  return offset;
}


static const value_string ranap_EquipmentsToBeTraced_vals[] = {
  {   0, "iMEIlist" },
  {   1, "iMEISVlist" },
  {   2, "iMEIgroup" },
  {   3, "iMEISVgroup" },
  { 0, NULL }
};

static const per_choice_t EquipmentsToBeTraced_choice[] = {
  {   0, &hf_ranap_iMEIlist      , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEIList },
  {   1, &hf_ranap_iMEISVlist    , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEISVList },
  {   2, &hf_ranap_iMEIgroup     , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEIGroup },
  {   3, &hf_ranap_iMEISVgroup   , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEISVGroup },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_EquipmentsToBeTraced(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_EquipmentsToBeTraced, EquipmentsToBeTraced_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_E_UTRAN_Service_Handover_vals[] = {
  {   0, "handover-to-E-UTRAN-shall-not-be-performed" },
  { 0, NULL }
};


static int
dissect_ranap_E_UTRAN_Service_Handover(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_Event_vals[] = {
  {   0, "stop-change-of-service-area" },
  {   1, "direct" },
  {   2, "change-of-servicearea" },
  {   3, "stop-direct" },
  {   4, "periodic" },
  {   5, "stop-periodic" },
  { 0, NULL }
};


static int
dissect_ranap_Event(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 3, NULL);

  return offset;
}


static const value_string ranap_MeasurementQuantity_vals[] = {
  {   0, "cpichEcNo" },
  {   1, "cpichRSCP" },
  {   2, "pathloss" },
  { 0, NULL }
};


static int
dissect_ranap_MeasurementQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_M120_165(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -120, 165U, NULL, false);

  return offset;
}


static const per_sequence_t Event1F_Parameters_sequence[] = {
  { &hf_ranap_measurementQuantity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MeasurementQuantity },
  { &hf_ranap_threshold     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M120_165 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Event1F_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Event1F_Parameters, Event1F_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_M120_M25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -120, -25, NULL, false);

  return offset;
}


static const per_sequence_t Event1I_Parameters_sequence[] = {
  { &hf_ranap_threshold_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_M120_M25 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Event1I_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Event1I_Parameters, Event1I_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_ExtendedRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_FrameSequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string ranap_FrequenceLayerConvergenceFlag_vals[] = {
  {   0, "no-FLC-flag" },
  { 0, NULL }
};


static int
dissect_ranap_FrequenceLayerConvergenceFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_GANSS_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GANSS_PositioningDataSet_sequence_of[1] = {
  { &hf_ranap_GANSS_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GANSS_PositioningMethodAndUsage },
};

static int
dissect_ranap_GANSS_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_GANSS_PositioningDataSet, GANSS_PositioningDataSet_sequence_of,
                                                  1, maxGANSSSet, false);

  return offset;
}



static int
dissect_ranap_GERAN_BSC_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t GERAN_Cell_ID_sequence[] = {
  { &hf_ranap_lAI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
  { &hf_ranap_cI            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CI },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Cell_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Cell_ID, GERAN_Cell_ID_sequence);

  return offset;
}



static int
dissect_ranap_GERAN_Classmark(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t GlobalCN_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_cN_ID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_CN_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalCN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalCN_ID, GlobalCN_ID_sequence);

  return offset;
}



static int
dissect_ranap_RNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t GlobalRNC_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GlobalRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GlobalRNC_ID, GlobalRNC_ID_sequence);

  return offset;
}



static int
dissect_ranap_GTP_TEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;
  int saved_hf;

  saved_hf = hf_index;
  hf_index = -1;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, &parameter_tvb);


  if (!parameter_tvb)
    return offset;
  proto_tree_add_item(tree, saved_hf, parameter_tvb, 0, 4, ENC_BIG_ENDIAN);


  return offset;
}


static const value_string ranap_HigherBitratesThan16MbpsFlag_vals[] = {
  {   0, "allowed" },
  {   1, "not-allowed" },
  { 0, NULL }
};


static int
dissect_ranap_HigherBitratesThan16MbpsFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfHSDSCHMACdFlows_1, NULL, false);

  return offset;
}



static int
dissect_ranap_MeasurementsToActivate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ranap_ReportInterval_vals[] = {
  {   0, "ms250" },
  {   1, "ms500" },
  {   2, "ms1000" },
  {   3, "ms2000" },
  {   4, "ms3000" },
  {   5, "ms4000" },
  {   6, "ms6000" },
  {   7, "ms12000" },
  {   8, "ms16000" },
  {   9, "ms20000" },
  {  10, "ms24000" },
  {  11, "ms32000" },
  {  12, "ms64000" },
  {  13, "ms8000" },
  {  14, "ms28000" },
  { 0, NULL }
};


static int
dissect_ranap_ReportInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, true, 2, NULL);

  return offset;
}


static const value_string ranap_ReportAmount_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  {   6, "n64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_ranap_ReportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MDT_Report_Parameters_sequence[] = {
  { &hf_ranap_reportInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportInterval },
  { &hf_ranap_reportAmount  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportAmount },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MDT_Report_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MDT_Report_Parameters, MDT_Report_Parameters_sequence);

  return offset;
}


static const value_string ranap_M1Report_vals[] = {
  {   0, "periodic" },
  {   1, "event1F" },
  { 0, NULL }
};

static const per_choice_t M1Report_choice[] = {
  {   0, &hf_ranap_periodic      , ASN1_EXTENSION_ROOT    , dissect_ranap_MDT_Report_Parameters },
  {   1, &hf_ranap_event1F       , ASN1_EXTENSION_ROOT    , dissect_ranap_Event1F_Parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M1Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M1Report, M1Report_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_M2Report_vals[] = {
  {   0, "periodic" },
  {   1, "event1I" },
  { 0, NULL }
};

static const per_choice_t M2Report_choice[] = {
  {   0, &hf_ranap_periodic      , ASN1_EXTENSION_ROOT    , dissect_ranap_MDT_Report_Parameters },
  {   1, &hf_ranap_event1I       , ASN1_EXTENSION_ROOT    , dissect_ranap_Event1I_Parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M2Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M2Report, M2Report_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ImmediateMDT_sequence[] = {
  { &hf_ranap_measurementsToActivate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MeasurementsToActivate },
  { &hf_ranap_m1report      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_M1Report },
  { &hf_ranap_m2report      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_M2Report },
  { &hf_ranap_iE_Extensions , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ImmediateMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ImmediateMDT, ImmediateMDT_sequence);

  return offset;
}



static int
dissect_ranap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t* imsi_tvb;
  const char    *digit_str;
  sccp_msg_info_t *sccp_info;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, false, &imsi_tvb);

  if(!imsi_tvb)
    return offset;
  /* Hide the octet string default printout */
  proto_item_set_hidden(actx->created_item);
  digit_str = dissect_e212_imsi(imsi_tvb, actx->pinfo, tree,  0, tvb_reported_length(imsi_tvb), false);

  sccp_info = (sccp_msg_info_t *)p_get_proto_data(actx->pinfo->pool, actx->pinfo, proto_ranap, actx->pinfo->curr_layer_num);

  if ( sccp_info && sccp_info->data.co.assoc && ! sccp_info->data.co.assoc->calling_party ) {

    sccp_info->data.co.assoc->calling_party =
    wmem_strdup_printf(wmem_file_scope(), "IMSI: %s", digit_str );

    sccp_info->data.co.assoc->imsi = wmem_strdup(wmem_file_scope(), digit_str );
  }


  return offset;
}


static const value_string ranap_IncludeVelocity_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_ranap_IncludeVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_InformationExchangeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, false);

  return offset;
}


static const value_string ranap_InformationExchangeType_vals[] = {
  {   0, "transfer" },
  {   1, "request" },
  { 0, NULL }
};


static int
dissect_ranap_InformationExchangeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t TMGI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_serviceID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_OCTET_STRING_SIZE_3 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TMGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TMGI, TMGI_sequence);

  return offset;
}



static int
dissect_ranap_IPMulticastAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 16, false, NULL);

  return offset;
}


static const per_sequence_t MBMSIPMulticastAddressandAPNlist_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_iPMulticastAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IPMulticastAddress },
  { &hf_ranap_aPN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_APN },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNlist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSIPMulticastAddressandAPNlist, MBMSIPMulticastAddressandAPNlist_sequence);

  return offset;
}


static const per_sequence_t RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { &hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MBMSIPMulticastAddressandAPNlist },
};

static int
dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest, RequestedMBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, maxnoofMulticastServicesPerRNC, false);

  return offset;
}


static const per_sequence_t RequestedMulticastServiceList_sequence_of[1] = {
  { &hf_ranap_RequestedMulticastServiceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
};

static int
dissect_ranap_RequestedMulticastServiceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RequestedMulticastServiceList, RequestedMulticastServiceList_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, false);

  return offset;
}


static const value_string ranap_InformationRequested_vals[] = {
  {   0, "requestedMBMSIPMulticastAddressandAPNRequest" },
  {   1, "requestedMulticastServiceList" },
  { 0, NULL }
};

static const per_choice_t InformationRequested_choice[] = {
  {   0, &hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest, ASN1_EXTENSION_ROOT    , dissect_ranap_RequestedMBMSIPMulticastAddressandAPNRequest },
  {   1, &hf_ranap_requestedMulticastServiceList, ASN1_EXTENSION_ROOT    , dissect_ranap_RequestedMulticastServiceList },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequested, InformationRequested_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBMSIPMulticastAddressandAPNRequest_sequence_of[1] = {
  { &hf_ranap_MBMSIPMulticastAddressandAPNRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
};

static int
dissect_ranap_MBMSIPMulticastAddressandAPNRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MBMSIPMulticastAddressandAPNRequest, MBMSIPMulticastAddressandAPNRequest_sequence_of,
                                                  1, maxnoofMulticastServicesPerRNC, false);

  return offset;
}


static const value_string ranap_PermanentNAS_UE_ID_vals[] = {
  {   0, "iMSI" },
  { 0, NULL }
};

static const per_choice_t PermanentNAS_UE_ID_choice[] = {
  {   0, &hf_ranap_iMSI          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PermanentNAS_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PermanentNAS_UE_ID, PermanentNAS_UE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_InformationRequestType_vals[] = {
  {   0, "mBMSIPMulticastAddressandAPNRequest" },
  {   1, "permanentNAS-UE-ID" },
  { 0, NULL }
};

static const per_choice_t InformationRequestType_choice[] = {
  {   0, &hf_ranap_mBMSIPMulticastAddressandAPNRequest, ASN1_EXTENSION_ROOT    , dissect_ranap_MBMSIPMulticastAddressandAPNRequest },
  {   1, &hf_ranap_permanentNAS_UE_ID, ASN1_EXTENSION_ROOT    , dissect_ranap_PermanentNAS_UE_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationRequestType, InformationRequestType_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_InformationTransferID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, false);

  return offset;
}


static const value_string ranap_T_traceActivationIndicator_vals[] = {
  {   0, "activated" },
  {   1, "deactivated" },
  { 0, NULL }
};


static int
dissect_ranap_T_traceActivationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t RNCTraceInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_traceActivationIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_traceActivationIndicator },
  { &hf_ranap_equipmentsToBeTraced, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_EquipmentsToBeTraced },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RNCTraceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RNCTraceInformation, RNCTraceInformation_sequence);

  return offset;
}


static const value_string ranap_InformationTransferType_vals[] = {
  {   0, "rNCTraceInformation" },
  { 0, NULL }
};

static const per_choice_t InformationTransferType_choice[] = {
  {   0, &hf_ranap_rNCTraceInformation, ASN1_EXTENSION_ROOT    , dissect_ranap_RNCTraceInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InformationTransferType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InformationTransferType, InformationTransferType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PermittedIntegrityProtectionAlgorithms_sequence_of[1] = {
  { &hf_ranap_PermittedIntegrityProtectionAlgorithms_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IntegrityProtectionAlgorithm },
};

static int
dissect_ranap_PermittedIntegrityProtectionAlgorithms(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PermittedIntegrityProtectionAlgorithms, PermittedIntegrityProtectionAlgorithms_sequence_of,
                                                  1, 16, false);

  return offset;
}



static int
dissect_ranap_IntegrityProtectionKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t IntegrityProtectionInformation_sequence[] = {
  { &hf_ranap_permittedAlgorithms_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PermittedIntegrityProtectionAlgorithms },
  { &hf_ranap_key_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IntegrityProtectionKey },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_IntegrityProtectionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IntegrityProtectionInformation, IntegrityProtectionInformation_sequence);

  return offset;
}



static int
dissect_ranap_RIMInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb = NULL;

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &value_tvb);

  if (value_tvb){
    call_dissector_only(bssgp_handle, value_tvb, actx->pinfo, tree, NULL);
  }


  return offset;
}


static const per_sequence_t TargetRNC_ID_sequence[] = {
  { &hf_ranap_lAI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
  { &hf_ranap_rAC           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RAC },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

int
dissect_ranap_TargetRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ID, TargetRNC_ID_sequence);

  return offset;
}



static int
dissect_ranap_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t TAI_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_tAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TAC },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->number_type = E212_TAI;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TAI, TAI_sequence);




  return offset;
}


static const per_sequence_t TargetENB_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_eNB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ENB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { &hf_ranap_selectedTAI   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetENB_ID, TargetENB_ID_sequence);

  return offset;
}


static const value_string ranap_RIMRoutingAddress_vals[] = {
  {   0, "targetRNC-ID" },
  {   1, "gERAN-Cell-ID" },
  {   2, "targeteNB-ID" },
  { 0, NULL }
};

static const per_choice_t RIMRoutingAddress_choice[] = {
  {   0, &hf_ranap_targetRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_TargetRNC_ID },
  {   1, &hf_ranap_gERAN_Cell_ID , ASN1_EXTENSION_ROOT    , dissect_ranap_GERAN_Cell_ID },
  {   2, &hf_ranap_targeteNB_ID  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_TargetENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RIMRoutingAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RIMRoutingAddress, RIMRoutingAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RIM_Transfer_sequence[] = {
  { &hf_ranap_rIMInformation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RIMInformation },
  { &hf_ranap_rIMRoutingAddress, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_RIMRoutingAddress },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RIM_Transfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RIM_Transfer, RIM_Transfer_sequence);

  return offset;
}


static const value_string ranap_InterSystemInformationTransferType_vals[] = {
  {   0, "rIM-Transfer" },
  { 0, NULL }
};

static const per_choice_t InterSystemInformationTransferType_choice[] = {
  {   0, &hf_ranap_rIM_Transfer  , ASN1_EXTENSION_ROOT    , dissect_ranap_RIM_Transfer },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_InterSystemInformationTransferType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_InterSystemInformationTransferType, InterSystemInformationTransferType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterSystemInformation_TransparentContainer_sequence[] = {
  { &hf_ranap_downlinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_uplinkCellLoadInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_CellLoadInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InterSystemInformation_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InterSystemInformation_TransparentContainer, InterSystemInformation_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_IuSignallingConnectionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ranap_IuTransportAssociation_vals[] = {
  {   0, "gTP-TEI" },
  {   1, "bindingID" },
  { 0, NULL }
};

static const per_choice_t IuTransportAssociation_choice[] = {
  {   0, &hf_ranap_gTP_TEI       , ASN1_EXTENSION_ROOT    , dissect_ranap_GTP_TEI },
  {   1, &hf_ranap_bindingID     , ASN1_EXTENSION_ROOT    , dissect_ranap_BindingID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_IuTransportAssociation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_IuTransportAssociation, IuTransportAssociation_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_KeyStatus_vals[] = {
  {   0, "old" },
  {   1, "new" },
  { 0, NULL }
};


static int
dissect_ranap_KeyStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ListOF_SNAs_sequence_of[1] = {
  { &hf_ranap_ListOF_SNAs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SNAC },
};

static int
dissect_ranap_ListOF_SNAs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_ListOF_SNAs, ListOF_SNAs_sequence_of,
                                                  1, maxNrOfSNAs, false);

  return offset;
}


static const per_sequence_t LA_LIST_item_sequence[] = {
  { &hf_ranap_lAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LAC },
  { &hf_ranap_listOF_SNAs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ListOF_SNAs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LA_LIST_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LA_LIST_item, LA_LIST_item_sequence);

  return offset;
}


static const per_sequence_t LA_LIST_sequence_of[1] = {
  { &hf_ranap_LA_LIST_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LA_LIST_item },
};

static int
dissect_ranap_LA_LIST(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LA_LIST, LA_LIST_sequence_of,
                                                  1, maxNrOfLAs, false);

  return offset;
}


static const per_sequence_t LastKnownServiceArea_sequence[] = {
  { &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SAI },
  { &hf_ranap_ageOfSAI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_32767 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LastKnownServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LastKnownServiceArea, LastKnownServiceArea_sequence);

  return offset;
}


static const per_sequence_t UTRAN_CellID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_cellID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TargetCellId },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UTRAN_CellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UTRAN_CellID, UTRAN_CellID_sequence);

  return offset;
}



static int
dissect_ranap_Time_UE_StayedInCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t LastVisitedUTRANCell_Item_sequence[] = {
  { &hf_ranap_uTRAN_CellID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UTRAN_CellID },
  { &hf_ranap_cellType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CellType },
  { &hf_ranap_time_UE_StayedInCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Time_UE_StayedInCell },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LastVisitedUTRANCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LastVisitedUTRANCell_Item, LastVisitedUTRANCell_Item_sequence);

  return offset;
}



static int
dissect_ranap_LHN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       32, 256, false, NULL);

  return offset;
}


static const value_string ranap_Links_to_log_vals[] = {
  {   0, "uplink" },
  {   1, "downlink" },
  {   2, "both-uplink-and-downlink" },
  { 0, NULL }
};


static int
dissect_ranap_Links_to_log(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_RequestedLocationRelatedDataType_vals[] = {
  {   0, "decipheringKeysUEBasedOTDOA" },
  {   1, "decipheringKeysAssistedGPS" },
  {   2, "dedicatedAssistanceDataUEBasedOTDOA" },
  {   3, "dedicatedAssistanceDataAssistedGPS" },
  {   4, "decipheringKeysAssistedGANSS" },
  {   5, "dedicatedAssistanceDataAssistedGANSS" },
  {   6, "decipheringKeysAssistedGPSandGANSS" },
  {   7, "dedicatedAssistanceDataAssistedGPSandGANSS" },
  { 0, NULL }
};


static int
dissect_ranap_RequestedLocationRelatedDataType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 4, NULL);

  return offset;
}



static int
dissect_ranap_RequestedGPSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 38, false, NULL);

  return offset;
}


static const per_sequence_t LocationRelatedDataRequestType_sequence[] = {
  { &hf_ranap_requestedLocationRelatedDataType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RequestedLocationRelatedDataType },
  { &hf_ranap_requestedGPSAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RequestedGPSAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequestType, LocationRelatedDataRequestType_sequence);

  return offset;
}


static const value_string ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals[] = {
  {   0, "decipheringKeysEOTD" },
  {   1, "dedicatedMobileAssistedEOTDAssistanceData" },
  {   2, "dedicatedMobileBasedEOTDAssistanceData" },
  { 0, NULL }
};


static int
dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_ReportChangeOfSAI_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_ranap_ReportChangeOfSAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_PeriodicReportingIndicator_vals[] = {
  {   0, "periodicSAI" },
  {   1, "periodicGeo" },
  { 0, NULL }
};


static int
dissect_ranap_PeriodicReportingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_DirectReportingIndicator_vals[] = {
  {   0, "directSAI" },
  {   1, "directGeo" },
  { 0, NULL }
};


static int
dissect_ranap_DirectReportingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_VerticalAccuracyCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const value_string ranap_PositioningPriority_vals[] = {
  {   0, "high-Priority" },
  {   1, "normal-Priority" },
  { 0, NULL }
};


static int
dissect_ranap_PositioningPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_ResponseTime_vals[] = {
  {   0, "lowdelay" },
  {   1, "delaytolerant" },
  { 0, NULL }
};


static int
dissect_ranap_ResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_1_8639999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, true);

  return offset;
}


static const per_sequence_t PeriodicLocationInfo_sequence[] = {
  { &hf_ranap_reportingAmount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8639999_ },
  { &hf_ranap_reportingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8639999_ },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PeriodicLocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PeriodicLocationInfo, PeriodicLocationInfo_sequence);

  return offset;
}


static const per_sequence_t LocationReportingTransferInformation_sequence[] = {
  { &hf_ranap_reportChangeOfSAI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ReportChangeOfSAI },
  { &hf_ranap_periodicReportingIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PeriodicReportingIndicator },
  { &hf_ranap_directReportingIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DirectReportingIndicator },
  { &hf_ranap_verticalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_VerticalAccuracyCode },
  { &hf_ranap_positioningPriorityChangeSAI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningPriority },
  { &hf_ranap_positioningPriorityDirect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningPriority },
  { &hf_ranap_clientTypePeriodic, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ClientType },
  { &hf_ranap_clientTypeDirect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ClientType },
  { &hf_ranap_responseTime  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ResponseTime },
  { &hf_ranap_includeVelocity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IncludeVelocity },
  { &hf_ranap_periodicLocationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PeriodicLocationInfo },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReportingTransferInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReportingTransferInformation, LocationReportingTransferInformation_sequence);

  return offset;
}



static int
dissect_ranap_L3_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *l3_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &l3_info_tvb);

  if (l3_info_tvb)
    dissector_try_uint(nas_pdu_dissector_table, 0x1, l3_info_tvb, actx->pinfo, proto_tree_get_root(tree));

  return offset;
}


static const value_string ranap_M4_Period_vals[] = {
  {   0, "ms100" },
  {   1, "ms250" },
  {   2, "ms500" },
  {   3, "ms1000" },
  {   4, "ms2000" },
  {   5, "ms3000" },
  {   6, "ms4000" },
  {   7, "ms6000" },
  { 0, NULL }
};


static int
dissect_ranap_M4_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_M4_Threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}


static const per_sequence_t M4_Collection_Parameters_sequence[] = {
  { &hf_ranap_m4_period     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_M4_Period },
  { &hf_ranap_m4_threshold  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_M4_Threshold },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_M4_Collection_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_M4_Collection_Parameters, M4_Collection_Parameters_sequence);

  return offset;
}


static const value_string ranap_M4Report_vals[] = {
  {   0, "all" },
  {   1, "m4-collection-parameters" },
  { 0, NULL }
};

static const per_choice_t M4Report_choice[] = {
  {   0, &hf_ranap_all           , ASN1_EXTENSION_ROOT    , dissect_ranap_NULL },
  {   1, &hf_ranap_m4_collection_parameters, ASN1_EXTENSION_ROOT    , dissect_ranap_M4_Collection_Parameters },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M4Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M4Report, M4Report_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_M5_Period_vals[] = {
  {   0, "ms100" },
  {   1, "ms250" },
  {   2, "ms500" },
  {   3, "ms1000" },
  {   4, "ms2000" },
  {   5, "ms3000" },
  {   6, "ms4000" },
  {   7, "ms6000" },
  { 0, NULL }
};


static int
dissect_ranap_M5_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_M5Report_vals[] = {
  {   0, "when-available" },
  {   1, "m5-period" },
  { 0, NULL }
};

static const per_choice_t M5Report_choice[] = {
  {   0, &hf_ranap_when_available, ASN1_EXTENSION_ROOT    , dissect_ranap_NULL },
  {   1, &hf_ranap_m5_period     , ASN1_EXTENSION_ROOT    , dissect_ranap_M5_Period },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_M5Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_M5Report, M5Report_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_M6_Period_vals[] = {
  {   0, "ms1000" },
  {   1, "ms2000" },
  {   2, "ms3000" },
  {   3, "ms4000" },
  {   4, "ms6000" },
  {   5, "ms8000" },
  {   6, "ms12000" },
  {   7, "ms16000" },
  {   8, "ms20000" },
  {   9, "ms24000" },
  {  10, "ms28000" },
  {  11, "ms32000" },
  {  12, "ms64000" },
  { 0, NULL }
};


static int
dissect_ranap_M6_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t M6Report_sequence[] = {
  { &hf_ranap_m6_period     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_M6_Period },
  { &hf_ranap_m6_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Links_to_log },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_M6Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_M6Report, M6Report_sequence);

  return offset;
}


static const value_string ranap_M7_Period_vals[] = {
  {   0, "ms1000" },
  {   1, "ms2000" },
  {   2, "ms3000" },
  {   3, "ms4000" },
  {   4, "ms6000" },
  {   5, "ms8000" },
  {   6, "ms12000" },
  {   7, "ms16000" },
  {   8, "ms20000" },
  {   9, "ms24000" },
  {  10, "ms28000" },
  {  11, "ms32000" },
  {  12, "ms64000" },
  { 0, NULL }
};


static int
dissect_ranap_M7_Period(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t M7Report_sequence[] = {
  { &hf_ranap_m7_period     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_M7_Period },
  { &hf_ranap_m7_links_to_log, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Links_to_log },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_M7Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_M7Report, M7Report_sequence);

  return offset;
}


static const value_string ranap_Management_Based_MDT_Allowed_vals[] = {
  {   0, "allowed" },
  { 0, NULL }
};


static int
dissect_ranap_Management_Based_MDT_Allowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_MaxSDU_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32768U, NULL, false);

  return offset;
}



static int
dissect_ranap_MBMS_PTP_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ranap_MBMSBearerServiceType_vals[] = {
  {   0, "multicast" },
  {   1, "broadcast" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSBearerServiceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSCNDe_Registration_vals[] = {
  {   0, "normalsessionstop" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSCNDe_Registration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSCountingInformation_vals[] = {
  {   0, "counting" },
  {   1, "notcounting" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSCountingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSHCIndicator_vals[] = {
  {   0, "uncompressed-header" },
  {   1, "compressed-header" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSHCIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSLinkingInformation_vals[] = {
  {   0, "uE-has-joined-multicast-services" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSLinkingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MBMSRegistrationRequestType_vals[] = {
  {   0, "register" },
  {   1, "deregister" },
  { 0, NULL }
};


static int
dissect_ranap_MBMSRegistrationRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_MBMSServiceArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_ranap_MBMSSessionRepetitionNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const value_string ranap_MDT_Activation_vals[] = {
  {   0, "immediateMDTonly" },
  {   1, "loggedMDTonly" },
  {   2, "immediateMDTandTrace" },
  { 0, NULL }
};


static int
dissect_ranap_MDT_Activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_MDTAreaScope_vals[] = {
  {   0, "cellbased" },
  {   1, "labased" },
  {   2, "rabased" },
  {   3, "plmn-area-based" },
  { 0, NULL }
};

static const per_choice_t MDTAreaScope_choice[] = {
  {   0, &hf_ranap_cellbased     , ASN1_EXTENSION_ROOT    , dissect_ranap_CellBased },
  {   1, &hf_ranap_labased       , ASN1_EXTENSION_ROOT    , dissect_ranap_LABased },
  {   2, &hf_ranap_rabased       , ASN1_EXTENSION_ROOT    , dissect_ranap_RABased },
  {   3, &hf_ranap_plmn_area_based_01, ASN1_EXTENSION_ROOT    , dissect_ranap_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_MDTAreaScope(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_MDTAreaScope, MDTAreaScope_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_LoggingInterval_vals[] = {
  {   0, "s1d28" },
  {   1, "s2d56" },
  {   2, "s5d12" },
  {   3, "s10d24" },
  {   4, "s20d48" },
  {   5, "s30d72" },
  {   6, "s40d96" },
  {   7, "s61d44" },
  { 0, NULL }
};


static int
dissect_ranap_LoggingInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_LoggingDuration_vals[] = {
  {   0, "min10" },
  {   1, "min20" },
  {   2, "min40" },
  {   3, "min60" },
  {   4, "min90" },
  {   5, "min120" },
  { 0, NULL }
};


static int
dissect_ranap_LoggingDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t LoggedMDT_sequence[] = {
  { &hf_ranap_loggingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoggingInterval },
  { &hf_ranap_loggingDuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LoggingDuration },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LoggedMDT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LoggedMDT, LoggedMDT_sequence);

  return offset;
}


static const value_string ranap_MDTMode_vals[] = {
  {   0, "immediateMDT" },
  {   1, "loggedMDT" },
  { 0, NULL }
};

static const per_choice_t MDTMode_choice[] = {
  {   0, &hf_ranap_immediateMDT  , ASN1_EXTENSION_ROOT    , dissect_ranap_ImmediateMDT },
  {   1, &hf_ranap_loggedMDT     , ASN1_EXTENSION_ROOT    , dissect_ranap_LoggedMDT },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_MDTMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_MDTMode, MDTMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MDT_Configuration_sequence[] = {
  { &hf_ranap_mdtActivation , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDT_Activation },
  { &hf_ranap_mdtAreaScope  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDTAreaScope },
  { &hf_ranap_mdtMode       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MDTMode },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MDT_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MDT_Configuration, MDT_Configuration_sequence);

  return offset;
}


static const per_sequence_t MDT_PLMN_List_sequence_of[1] = {
  { &hf_ranap_MDT_PLMN_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
};

static int
dissect_ranap_MDT_PLMN_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_MDT_PLMN_List, MDT_PLMN_List_sequence_of,
                                                  1, maxnoofMDTPLMNs, false);

  return offset;
}



static int
dissect_ranap_MSISDN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 9, false, NULL);

  return offset;
}



static int
dissect_ranap_NAS_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *nas_pdu_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &nas_pdu_tvb);


  if (nas_pdu_tvb)
    dissector_try_uint(nas_pdu_dissector_table, 0x1, nas_pdu_tvb, actx->pinfo, proto_tree_get_root(tree));

  return offset;
}



static int
dissect_ranap_NAS_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_NAS_SynchronisationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_NewBSS_To_OldBSS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *bss_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &bss_info_tvb);

  if (bss_info_tvb)
    bssmap_new_bss_to_old_bss_info(bss_info_tvb, tree, actx->pinfo);

  return offset;
}


static const value_string ranap_NonSearchingIndication_vals[] = {
  {   0, "non-searching" },
  {   1, "searching" },
  { 0, NULL }
};


static int
dissect_ranap_NonSearchingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ranap_Null_NRI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_NumberOfIuInstances(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2U, NULL, false);

  return offset;
}



static int
dissect_ranap_NumberOfSteps(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, false);

  return offset;
}



static int
dissect_ranap_Offload_RAB_Parameters_APN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, false, NULL);

  return offset;
}



static int
dissect_ranap_Offload_RAB_Parameters_ChargingCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const per_sequence_t Offload_RAB_Parameters_sequence[] = {
  { &hf_ranap_accessPointName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Offload_RAB_Parameters_APN },
  { &hf_ranap_chargingCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Offload_RAB_Parameters_ChargingCharacteristics },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Offload_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Offload_RAB_Parameters, Offload_RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_OldBSS_ToNewBSS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *bss_info_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &bss_info_tvb);

  if (bss_info_tvb)
    bssmap_old_bss_to_new_bss_info(bss_info_tvb, tree, actx->pinfo);

  return offset;
}



static int
dissect_ranap_OMC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, false, NULL);

  return offset;
}


static const value_string ranap_Out_Of_UTRAN_vals[] = {
  {   0, "cell-reselection-to-EUTRAN" },
  { 0, NULL }
};


static int
dissect_ranap_Out_Of_UTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_PagingAreaID_vals[] = {
  {   0, "lAI" },
  {   1, "rAI" },
  { 0, NULL }
};

static const per_choice_t PagingAreaID_choice[] = {
  {   0, &hf_ranap_lAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_LAI },
  {   1, &hf_ranap_rAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_RAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_PagingAreaID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_PagingAreaID, PagingAreaID_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_PagingCause_vals[] = {
  {   0, "terminating-conversational-call" },
  {   1, "terminating-streaming-call" },
  {   2, "terminating-interactive-call" },
  {   3, "terminating-background-call" },
  {   4, "terminating-low-priority-signalling" },
  {   5, "terminating-high-priority-signalling" },
  { 0, NULL }
};


static int
dissect_ranap_PagingCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 1, NULL);

  return offset;
}


static const value_string ranap_PDP_Type_vals[] = {
  {   0, "empty" },
  {   1, "ppp" },
  {   2, "osp-ihoss" },
  {   3, "ipv4" },
  {   4, "ipv6" },
  { 0, NULL }
};


static int
dissect_ranap_PDP_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDP_TypeInformation_sequence_of[1] = {
  { &hf_ranap_PDP_TypeInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PDP_Type },
};

static int
dissect_ranap_PDP_TypeInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PDP_TypeInformation, PDP_TypeInformation_sequence_of,
                                                  1, maxNrOfPDPDirections, false);

  return offset;
}


static const value_string ranap_PDP_Type_extension_vals[] = {
  {   0, "ipv4-and-ipv6" },
  { 0, NULL }
};


static int
dissect_ranap_PDP_Type_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PDP_TypeInformation_extension_sequence_of[1] = {
  { &hf_ranap_PDP_TypeInformation_extension_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PDP_Type_extension },
};

static int
dissect_ranap_PDP_TypeInformation_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PDP_TypeInformation_extension, PDP_TypeInformation_extension_sequence_of,
                                                  1, maxNrOfPDPDirections, false);

  return offset;
}



static int
dissect_ranap_PDUType14FrameSequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t PLMNs_in_shared_network_item_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_lA_LIST       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_LA_LIST },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PLMNs_in_shared_network_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PLMNs_in_shared_network_item, PLMNs_in_shared_network_item_sequence);

  return offset;
}


static const per_sequence_t PLMNs_in_shared_network_sequence_of[1] = {
  { &hf_ranap_PLMNs_in_shared_network_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNs_in_shared_network_item },
};

static int
dissect_ranap_PLMNs_in_shared_network(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PLMNs_in_shared_network, PLMNs_in_shared_network_sequence_of,
                                                  1, maxNrOfPLMNsSN, false);

  return offset;
}



static int
dissect_ranap_Port_Number(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       2, 2, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ranap_PositioningDataDiscriminator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t PositioningDataSet_sequence_of[1] = {
  { &hf_ranap_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PositioningMethodAndUsage },
};

static int
dissect_ranap_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_PositioningDataSet, PositioningDataSet_sequence_of,
                                                  1, maxSet, false);

  return offset;
}


static const per_sequence_t PositionData_sequence[] = {
  { &hf_ranap_positioningDataDiscriminator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PositioningDataDiscriminator },
  { &hf_ranap_positioningDataSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PositioningDataSet },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PositionData, PositionData_sequence);

  return offset;
}



static int
dissect_ranap_PositionDataSpecificToGERANIuMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_ranap_Priority_Class_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Shared_Network_Information_sequence[] = {
  { &hf_ranap_pLMNs_in_shared_network, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNs_in_shared_network },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Shared_Network_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Shared_Network_Information, Shared_Network_Information_sequence);

  return offset;
}


static const value_string ranap_ProvidedData_vals[] = {
  {   0, "shared-network-information" },
  { 0, NULL }
};

static const per_choice_t ProvidedData_choice[] = {
  {   0, &hf_ranap_shared_network_information, ASN1_EXTENSION_ROOT    , dissect_ranap_Shared_Network_Information },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_ProvidedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_ProvidedData, ProvidedData_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_PowerSavingIndicator_vals[] = {
  {   0, "psmConfigured" },
  {   1, "eDRXConfigured" },
  { 0, NULL }
};


static int
dissect_ranap_PowerSavingIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_P_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const value_string ranap_RAB_AsymmetryIndicator_vals[] = {
  {   0, "symmetric-bidirectional" },
  {   1, "asymmetric-unidirectional-downlink" },
  {   2, "asymmetric-unidirectional-uplink" },
  {   3, "asymmetric-bidirectional" },
  { 0, NULL }
};


static int
dissect_ranap_RAB_AsymmetryIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_UnsuccessfullyTransmittedDataVolume(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t RABDataVolumeReport_item_sequence[] = {
  { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfullyTransmittedDataVolume },
  { &hf_ranap_dataVolumeReference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABDataVolumeReport_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABDataVolumeReport_item, RABDataVolumeReport_item_sequence);

  return offset;
}


static const per_sequence_t RABDataVolumeReport_sequence_of[1] = {
  { &hf_ranap_RABDataVolumeReport_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RABDataVolumeReport_item },
};

static int
dissect_ranap_RABDataVolumeReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RABDataVolumeReport, RABDataVolumeReport_sequence_of,
                                                  1, maxNrOfVol, false);

  return offset;
}



static int
dissect_ranap_RAB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList, RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_ExtendedMaxBitrateList, RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_GuaranteedBitrateList, RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_Parameter_MaxBitrateList, RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const value_string ranap_TrafficClass_vals[] = {
  {   0, "conversational" },
  {   1, "streaming" },
  {   2, "interactive" },
  {   3, "background" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_1_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 9U, NULL, false);

  return offset;
}



static int
dissect_ranap_INTEGER_1_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 6U, NULL, false);

  return offset;
}


static const per_sequence_t SDU_ErrorRatio_sequence[] = {
  { &hf_ranap_mantissa      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_9 },
  { &hf_ranap_exponent_1_8  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_6 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_ErrorRatio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_ErrorRatio, SDU_ErrorRatio_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, false);

  return offset;
}


static const per_sequence_t ResidualBitErrorRatio_sequence[] = {
  { &hf_ranap_mantissa      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_9 },
  { &hf_ranap_exponent      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_8 },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResidualBitErrorRatio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResidualBitErrorRatio, ResidualBitErrorRatio_sequence);

  return offset;
}



static int
dissect_ranap_SubflowSDU_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_ranap_RAB_SubflowCombinationBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16000000U, NULL, false);

  return offset;
}


static const per_sequence_t SDU_FormatInformationParameters_item_sequence[] = {
  { &hf_ranap_subflowSDU_Size, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SubflowSDU_Size },
  { &hf_ranap_rAB_SubflowCombinationBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_SubflowCombinationBitRate },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_FormatInformationParameters_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_FormatInformationParameters_item, SDU_FormatInformationParameters_item_sequence);

  return offset;
}


static const per_sequence_t SDU_FormatInformationParameters_sequence_of[1] = {
  { &hf_ranap_SDU_FormatInformationParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_FormatInformationParameters_item },
};

static int
dissect_ranap_SDU_FormatInformationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_FormatInformationParameters, SDU_FormatInformationParameters_sequence_of,
                                                  1, maxRAB_SubflowCombination, false);

  return offset;
}


static const per_sequence_t SDU_Parameters_item_sequence[] = {
  { &hf_ranap_sDU_ErrorRatio, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SDU_ErrorRatio },
  { &hf_ranap_residualBitErrorRatio, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ResidualBitErrorRatio },
  { &hf_ranap_deliveryOfErroneousSDU, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DeliveryOfErroneousSDU },
  { &hf_ranap_sDU_FormatInformationParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SDU_FormatInformationParameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SDU_Parameters_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SDU_Parameters_item, SDU_Parameters_item_sequence);

  return offset;
}


static const per_sequence_t SDU_Parameters_sequence_of[1] = {
  { &hf_ranap_SDU_Parameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_Parameters_item },
};

static int
dissect_ranap_SDU_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SDU_Parameters, SDU_Parameters_sequence_of,
                                                  1, maxRAB_Subflows, false);

  return offset;
}



static int
dissect_ranap_TransferDelay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const value_string ranap_TrafficHandlingPriority_vals[] = {
  {   0, "spare" },
  {   1, "highest" },
  {  14, "lowest" },
  {  15, "no-priority-used" },
  { 0, NULL }
};


static int
dissect_ranap_TrafficHandlingPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string ranap_SourceStatisticsDescriptor_vals[] = {
  {   0, "speech" },
  {   1, "unknown" },
  { 0, NULL }
};


static int
dissect_ranap_SourceStatisticsDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_RelocationRequirement_vals[] = {
  {   0, "lossless" },
  {   1, "none" },
  {   2, "realtime" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationRequirement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t RAB_Parameters_sequence[] = {
  { &hf_ranap_trafficClass  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrafficClass },
  { &hf_ranap_rAB_AsymmetryIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_AsymmetryIndicator },
  { &hf_ranap_maxBitrate    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_guaranteedBitRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_deliveryOrder , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DeliveryOrder },
  { &hf_ranap_maxSDU_Size   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MaxSDU_Size },
  { &hf_ranap_sDU_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SDU_Parameters },
  { &hf_ranap_transferDelay , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransferDelay },
  { &hf_ranap_trafficHandlingPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TrafficHandlingPriority },
  { &hf_ranap_allocationOrRetentionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_AllocationOrRetentionPriority },
  { &hf_ranap_sourceStatisticsDescriptor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SourceStatisticsDescriptor },
  { &hf_ranap_relocationRequirement, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RelocationRequirement },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_Parameters, RAB_Parameters_sequence);

  return offset;
}



static int
dissect_ranap_UPInitialisationFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t UPInformation_sequence[] = {
  { &hf_ranap_frameSeqNoUL  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_FrameSequenceNumber },
  { &hf_ranap_frameSeqNoDL  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_FrameSequenceNumber },
  { &hf_ranap_pdu14FrameSeqNoUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PDUType14FrameSequenceNumber },
  { &hf_ranap_pdu14FrameSeqNoDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PDUType14FrameSequenceNumber },
  { &hf_ranap_dataPDUType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_DataPDUType },
  { &hf_ranap_upinitialisationFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UPInitialisationFrame },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UPInformation, UPInformation_sequence);

  return offset;
}


static const per_sequence_t RABParametersList_item_sequence[] = {
  { &hf_ranap_rab_Id        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cn_domain     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rabDataVolumeReport, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RABDataVolumeReport },
  { &hf_ranap_upInformation , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UPInformation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABParametersList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABParametersList_item, RABParametersList_item_sequence);

  return offset;
}


static const per_sequence_t RABParametersList_sequence_of[1] = {
  { &hf_ranap_RABParametersList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RABParametersList_item },
};

static int
dissect_ranap_RABParametersList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RABParametersList, RABParametersList_sequence_of,
                                                  1, maxNrOfRABs, false);

  return offset;
}



static int
dissect_ranap_USCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t TrCH_ID_sequence[] = {
  { &hf_ranap_dCH_ID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DCH_ID },
  { &hf_ranap_dSCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DSCH_ID },
  { &hf_ranap_uSCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_USCH_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TrCH_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TrCH_ID, TrCH_ID_sequence);

  return offset;
}


static const per_sequence_t TrCH_ID_List_sequence_of[1] = {
  { &hf_ranap_TrCH_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID },
};

static int
dissect_ranap_TrCH_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_TrCH_ID_List, TrCH_ID_List_sequence_of,
                                                  1, maxRAB_Subflows, false);

  return offset;
}


static const per_sequence_t RAB_TrCH_MappingItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_trCH_ID_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID_List },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_TrCH_MappingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_TrCH_MappingItem, RAB_TrCH_MappingItem_sequence);

  return offset;
}


static const per_sequence_t RAB_TrCH_Mapping_sequence_of[1] = {
  { &hf_ranap_RAB_TrCH_Mapping_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_TrCH_MappingItem },
};

static int
dissect_ranap_RAB_TrCH_Mapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAB_TrCH_Mapping, RAB_TrCH_Mapping_sequence_of,
                                                  1, maxNrOfRABs, false);

  return offset;
}


static const per_sequence_t RAofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_RAofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAC },
};

static int
dissect_ranap_RAofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_RAofIdleModeUEs, RAofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, false);

  return offset;
}


static const per_sequence_t NotEmptyRAListofIdleModeUEs_sequence[] = {
  { &hf_ranap_rAofIdleModeUEs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RAofIdleModeUEs },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_NotEmptyRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_NotEmptyRAListofIdleModeUEs, NotEmptyRAListofIdleModeUEs_sequence);

  return offset;
}


static const value_string ranap_T_emptyFullRAListofIdleModeUEs_vals[] = {
  {   0, "emptylist" },
  {   1, "fulllist" },
  { 0, NULL }
};


static int
dissect_ranap_T_emptyFullRAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_RAListofIdleModeUEs_vals[] = {
  {   0, "notEmptyRAListofIdleModeUEs" },
  {   1, "emptyFullRAListofIdleModeUEs" },
  { 0, NULL }
};

static const per_choice_t RAListofIdleModeUEs_choice[] = {
  {   0, &hf_ranap_notEmptyRAListofIdleModeUEs, ASN1_EXTENSION_ROOT    , dissect_ranap_NotEmptyRAListofIdleModeUEs },
  {   1, &hf_ranap_emptyFullRAListofIdleModeUEs, ASN1_EXTENSION_ROOT    , dissect_ranap_T_emptyFullRAListofIdleModeUEs },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RAListofIdleModeUEs, RAListofIdleModeUEs_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LAListofIdleModeUEs_sequence_of[1] = {
  { &hf_ranap_LAListofIdleModeUEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LAI },
};

static int
dissect_ranap_LAListofIdleModeUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LAListofIdleModeUEs, LAListofIdleModeUEs_sequence_of,
                                                  1, maxMBMSRA, false);

  return offset;
}


static const value_string ranap_RAT_Type_vals[] = {
  {   0, "utran" },
  {   1, "geran" },
  { 0, NULL }
};


static int
dissect_ranap_RAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_RedirectAttemptFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ranap_RedirectionCompleted_vals[] = {
  {   0, "redirection-completed" },
  { 0, NULL }
};


static int
dissect_ranap_RedirectionCompleted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_RejectCauseValue_vals[] = {
  {   0, "pLMN-Not-Allowed" },
  {   1, "location-Area-Not-Allowed" },
  {   2, "roaming-Not-Allowed-In-This-Location-Area" },
  {   3, "no-Suitable-Cell-In-Location-Area" },
  {   4, "gPRS-Services-Not-Allowed-In-This-PLMN" },
  {   5, "cS-PS-coordination-required" },
  {   6, "network-failure" },
  {   7, "not-authorized-for-this-CSG" },
  { 0, NULL }
};


static int
dissect_ranap_RejectCauseValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 2, NULL);

  return offset;
}


static const value_string ranap_RelocationType_vals[] = {
  {   0, "ue-not-involved" },
  {   1, "ue-involved" },
  { 0, NULL }
};


static int
dissect_ranap_RelocationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_ReportArea_vals[] = {
  {   0, "service-area" },
  {   1, "geographical-area" },
  { 0, NULL }
};


static int
dissect_ranap_ReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_RequestedGANSSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 201, false, NULL);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_MaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_MaxBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_MaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_MaxBitrateList, Requested_RAB_Parameter_MaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_GuaranteedBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList, Requested_RAB_Parameter_GuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_Values_sequence[] = {
  { &hf_ranap_requestedMaxBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Requested_RAB_Parameter_MaxBitrateList },
  { &hf_ranap_requestedGuaranteedBitrates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Requested_RAB_Parameter_GuaranteedBitrateList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Requested_RAB_Parameter_Values(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Requested_RAB_Parameter_Values, Requested_RAB_Parameter_Values_sequence);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_ExtendedMaxBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedMaxBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList, Requested_RAB_Parameter_ExtendedMaxBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of[1] = {
  { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ExtendedGuaranteedBitrate },
};

static int
dissect_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_sequence_of,
                                                  1, maxNrOfSeparateTrafficDirections, false);

  return offset;
}


static const per_sequence_t RequestType_sequence[] = {
  { &hf_ranap_event         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Event },
  { &hf_ranap_reportArea    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ReportArea },
  { &hf_ranap_accuracyCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RequestType, RequestType_sequence);

  return offset;
}


static const value_string ranap_UE_ID_vals[] = {
  {   0, "imsi" },
  {   1, "imei" },
  {   2, "imeisv" },
  { 0, NULL }
};

static const per_choice_t UE_ID_choice[] = {
  {   0, &hf_ranap_imsi          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMSI },
  {   1, &hf_ranap_imei          , ASN1_EXTENSION_ROOT    , dissect_ranap_IMEI },
  {   2, &hf_ranap_imeisv        , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_IMEISV },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_UE_ID, UE_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TraceInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_ue_identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UE_ID },
  { &hf_ranap_tracePropagationParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TracePropagationParameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TraceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TraceInformation, TraceInformation_sequence);

  return offset;
}


static const per_sequence_t RNSAPRelocationParameters_sequence[] = {
  { &hf_ranap_rabParmetersList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RABParametersList },
  { &hf_ranap_locationReporting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_LocationReportingTransferInformation },
  { &hf_ranap_traceInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TraceInformation },
  { &hf_ranap_sourceSAI     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_SAI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RNSAPRelocationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RNSAPRelocationParameters, RNSAPRelocationParameters_sequence);

  return offset;
}



static int
dissect_ranap_RRC_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *rrc_message_tvb=NULL;
  uint8_t container_choice=0;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &rrc_message_tvb);


  if ((rrc_message_tvb)&&(tvb_reported_length(rrc_message_tvb)!=0)&&(glbl_dissect_container)){
    switch(ProtocolIE_ID){
      case id_Source_ToTarget_TransparentContainer: /* INTEGER ::= 61 */
        /* 9.2.1.30a Source to Target Transparent Container
         * Note: In the current version of this specification, this IE may
         * either carry the Source RNC to Target RNC Transparent Container
         * or the Source eNB to Target eNB Transparent Container IE as defined in [49]...
         */
        call_dissector(rrc_s_to_trnc_handle,rrc_message_tvb,actx->pinfo, proto_tree_get_root(tree));
      break;
      case id_Target_ToSource_TransparentContainer: /* INTEGER ::= 63 */
        /* 9.2.1.30b Target to Source Transparent Container
         * In the current version of this specification, this IE may
         * either carry the Target RNC to Source RNC Transparent Container
         * or the Target eNB to Source eNB Transparent Container IE as defined in [49]...
         */

        /* Assume a TargetRNC-ToSourceRNC-Container.  Peek the RRC octetstream to guess the choice*/
        container_choice = tvb_get_uint8(rrc_message_tvb, 0) >> 5;
        if (container_choice < 7) {
          /* Normal case (0-6): dissect as TargetRNC-ToSourceRNC-Container */
          call_dissector(rrc_t_to_srnc_handle,rrc_message_tvb,actx->pinfo, proto_tree_get_root(tree));
        } else {
          /* Special case (7 extension): it would have been decoded as NULL.  Attempt as HandoverToUTRANCommand instead*/
          call_dissector(rrc_ho_to_utran_cmd,rrc_message_tvb,actx->pinfo, proto_tree_get_root(tree));
        }
      break;
      default:
      break;
    }
  }

  return offset;
}


static const value_string ranap_RSRVCC_HO_Indication_vals[] = {
  {   0, "ps-only" },
  { 0, NULL }
};


static int
dissect_ranap_RSRVCC_HO_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_OCTET_STRING_SIZE_1_maxSizeOfIMSInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxSizeOfIMSInfo, false, NULL);

  return offset;
}


static const per_sequence_t RSRVCC_Information_sequence[] = {
  { &hf_ranap_nonce         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_128 },
  { &hf_ranap_iMSInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_OCTET_STRING_SIZE_1_maxSizeOfIMSInfo },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RSRVCC_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RSRVCC_Information, RSRVCC_Information_sequence);

  return offset;
}


static const value_string ranap_RSRVCC_Operation_Possible_vals[] = {
  {   0, "rsrvcc-possible" },
  { 0, NULL }
};


static int
dissect_ranap_RSRVCC_Operation_Possible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_SAPI_vals[] = {
  {   0, "sapi-0" },
  {   1, "sapi-3" },
  { 0, NULL }
};


static int
dissect_ranap_SAPI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_SessionUpdateID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, false);

  return offset;
}


static const value_string ranap_Session_Re_establishment_Indicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_ranap_Session_Re_establishment_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string ranap_SignallingIndication_vals[] = {
  {   0, "signalling" },
  { 0, NULL }
};


static int
dissect_ranap_SignallingIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_SGSN_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}


static const value_string ranap_SGSN_Group_Identity_vals[] = {
  {   0, "null-NRI" },
  {   1, "sGSN-Group-ID" },
  { 0, NULL }
};

static const per_choice_t SGSN_Group_Identity_choice[] = {
  {   0, &hf_ranap_null_NRI      , ASN1_NO_EXTENSIONS     , dissect_ranap_Null_NRI },
  {   1, &hf_ranap_sGSN_Group_ID , ASN1_NO_EXTENSIONS     , dissect_ranap_SGSN_Group_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SGSN_Group_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SGSN_Group_Identity, SGSN_Group_Identity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SNA_Access_Information_sequence[] = {
  { &hf_ranap_authorisedPLMNs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_AuthorisedPLMNs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SNA_Access_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SNA_Access_Information, SNA_Access_Information_sequence);

  return offset;
}


const value_string ranap_Service_Handover_vals[] = {
  {   0, "handover-to-GSM-should-be-performed" },
  {   1, "handover-to-GSM-should-not-be-performed" },
  {   2, "handover-to-GSM-shall-not-be-performed" },
  { 0, NULL }
};


int
dissect_ranap_Service_Handover(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_Source_ToTarget_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvb , offset, actx ,tree , hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU );


  return offset;
}



static int
dissect_ranap_SourceBSS_ToTargetBSS_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t SourceRNC_ID_sequence[] = {
  { &hf_ranap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_rNC_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_RNC_ID },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ID, SourceRNC_ID_sequence);

  return offset;
}


static const value_string ranap_SourceID_vals[] = {
  {   0, "sourceRNC-ID" },
  {   1, "sAI" },
  { 0, NULL }
};

static const per_choice_t SourceID_choice[] = {
  {   0, &hf_ranap_sourceRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_SourceRNC_ID },
  {   1, &hf_ranap_sAI           , ASN1_EXTENSION_ROOT    , dissect_ranap_SAI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_SourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_SourceID, SourceID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SourceRNC_ToTargetRNC_TransparentContainer_sequence[] = {
  { &hf_ranap_rRC_Container , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RRC_Container },
  { &hf_ranap_numberOfIuInstances, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_NumberOfIuInstances },
  { &hf_ranap_relocationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RelocationType },
  { &hf_ranap_chosenIntegrityProtectionAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenIntegrityProtectionAlgorithm },
  { &hf_ranap_integrityProtectionKey, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IntegrityProtectionKey },
  { &hf_ranap_chosenEncryptionAlgorithForSignalling, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_cipheringKey  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_EncryptionKey },
  { &hf_ranap_chosenEncryptionAlgorithForCS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_chosenEncryptionAlgorithForPS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ChosenEncryptionAlgorithm },
  { &hf_ranap_d_RNTI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_D_RNTI },
  { &hf_ranap_targetCellId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TargetCellId },
  { &hf_ranap_rAB_TrCH_Mapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_TrCH_Mapping },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* If SourceRNC-ToTargetRNC-TransparentContainer is called through
   dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU
   ProtocolIE_ID may be unset
   */


  ProtocolIE_ID = id_Source_ToTarget_TransparentContainer;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer, SourceRNC_ToTargetRNC_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_97(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, false);

  return offset;
}



static int
dissect_ranap_INTEGER_0_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, false);

  return offset;
}



static int
dissect_ranap_INTEGER_1_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, false);

  return offset;
}


static const value_string ranap_MeasBand_vals[] = {
  {   0, "v6" },
  {   1, "v15" },
  {   2, "v25" },
  {   3, "v50" },
  {   4, "v75" },
  {   5, "v100" },
  { 0, NULL }
};


static int
dissect_ranap_MeasBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t EUTRANFrequencies_item_sequence[] = {
  { &hf_ranap_earfcn        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_65535 },
  { &hf_ranap_measBand      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_MeasBand },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EUTRANFrequencies_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EUTRANFrequencies_item, EUTRANFrequencies_item_sequence);

  return offset;
}


static const per_sequence_t EUTRANFrequencies_sequence_of[1] = {
  { &hf_ranap_EUTRANFrequencies_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_EUTRANFrequencies_item },
};

static int
dissect_ranap_EUTRANFrequencies(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_EUTRANFrequencies, EUTRANFrequencies_sequence_of,
                                                  1, maxNrOfEUTRAFreqs, false);

  return offset;
}


static const per_sequence_t IRATmeasurementParameters_sequence[] = {
  { &hf_ranap_measurementDuration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_1_100 },
  { &hf_ranap_eUTRANFrequencies, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_EUTRANFrequencies },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IRATmeasurementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IRATmeasurementParameters, IRATmeasurementParameters_sequence);

  return offset;
}


static const per_sequence_t IRAT_Measurement_Configuration_sequence[] = {
  { &hf_ranap_rSRP          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_97 },
  { &hf_ranap_rSRQ          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_INTEGER_0_34 },
  { &hf_ranap_iRATmeasurementParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_IRATmeasurementParameters },
  { &hf_ranap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_IRAT_Measurement_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_IRAT_Measurement_Configuration, IRAT_Measurement_Configuration_sequence);

  return offset;
}



static int
dissect_ranap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RSRQ_Type_sequence[] = {
  { &hf_ranap_allSymbols    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BOOLEAN },
  { &hf_ranap_wideBand      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RSRQ_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RSRQ_Type, RSRQ_Type_sequence);

  return offset;
}



static int
dissect_ranap_RSRQ_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 46U, NULL, true);

  return offset;
}



static int
dissect_ranap_SubscriberProfileIDforRFP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}



static int
dissect_ranap_SRB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, false);

  return offset;
}


static const per_sequence_t SRB_TrCH_MappingItem_sequence[] = {
  { &hf_ranap_sRB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SRB_ID },
  { &hf_ranap_trCH_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TrCH_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRB_TrCH_MappingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRB_TrCH_MappingItem, SRB_TrCH_MappingItem_sequence);

  return offset;
}


static const per_sequence_t SRB_TrCH_Mapping_sequence_of[1] = {
  { &hf_ranap_SRB_TrCH_Mapping_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SRB_TrCH_MappingItem },
};

static int
dissect_ranap_SRB_TrCH_Mapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_SRB_TrCH_Mapping, SRB_TrCH_Mapping_sequence_of,
                                                  1, maxNrOfSRBs, false);

  return offset;
}


static const value_string ranap_SRVCC_HO_Indication_vals[] = {
  {   0, "ps-and-cs" },
  {   1, "cs-only" },
  { 0, NULL }
};


static int
dissect_ranap_SRVCC_HO_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SRVCC_Information_sequence[] = {
  { &hf_ranap_nonce         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_BIT_STRING_SIZE_128 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_Information, SRVCC_Information_sequence);

  return offset;
}


static const value_string ranap_SRVCC_Operation_Possible_vals[] = {
  {   0, "srvcc-possible" },
  { 0, NULL }
};


static int
dissect_ranap_SRVCC_Operation_Possible(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_Target_ToSource_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvb , offset, actx ,tree , hf_ranap_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU );



  return offset;
}



static int
dissect_ranap_TargetBSS_ToSourceBSS_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string ranap_TargetID_vals[] = {
  {   0, "targetRNC-ID" },
  {   1, "cGI" },
  {   2, "targeteNB-ID" },
  { 0, NULL }
};

static const per_choice_t TargetID_choice[] = {
  {   0, &hf_ranap_targetRNC_ID  , ASN1_EXTENSION_ROOT    , dissect_ranap_TargetRNC_ID },
  {   1, &hf_ranap_cGI           , ASN1_EXTENSION_ROOT    , dissect_ranap_CGI },
  {   2, &hf_ranap_targeteNB_ID  , ASN1_NOT_EXTENSION_ROOT, dissect_ranap_TargetENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_TargetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TargetID, TargetID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TargetRNC_ToSourceRNC_TransparentContainer_sequence[] = {
  { &hf_ranap_rRC_Container , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RRC_Container },
  { &hf_ranap_d_RNTI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_D_RNTI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* If TargetRNC-ToSourceRNC-TransparentContainer is called through
   dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU
   ProtocolIE_ID may be unset
   */


  ProtocolIE_ID = id_Target_ToSource_TransparentContainer;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer, TargetRNC_ToSourceRNC_TransparentContainer_sequence);

  return offset;
}



static int
dissect_ranap_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}


static const value_string ranap_TemporaryUE_ID_vals[] = {
  {   0, "tMSI" },
  {   1, "p-TMSI" },
  { 0, NULL }
};

static const per_choice_t TemporaryUE_ID_choice[] = {
  {   0, &hf_ranap_tMSI          , ASN1_EXTENSION_ROOT    , dissect_ranap_TMSI },
  {   1, &hf_ranap_p_TMSI        , ASN1_EXTENSION_ROOT    , dissect_ranap_P_TMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_TemporaryUE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_TemporaryUE_ID, TemporaryUE_ID_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_Time_UE_StayedInCell_EnhancedGranularity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 40950U, NULL, false);

  return offset;
}



static int
dissect_ranap_TimeToMBMSDataTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_ranap_TimingDifferenceULDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t TraceRecordingSessionInformation_sequence[] = {
  { &hf_ranap_traceReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceReference },
  { &hf_ranap_traceRecordingSessionReference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TraceRecordingSessionReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TraceRecordingSessionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TraceRecordingSessionInformation, TraceRecordingSessionInformation_sequence);

  return offset;
}



static int
dissect_ranap_TraceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_ranap_TriggerID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 22, false, NULL);

  return offset;
}


static const per_sequence_t TunnelInformation_sequence[] = {
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_uDP_Port_Number, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Port_Number },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TunnelInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TunnelInformation, TunnelInformation_sequence);

  return offset;
}


static const value_string ranap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_ranap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_UE_AggregateMaximumBitRateDownlink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, false);

  return offset;
}



static int
dissect_ranap_UE_AggregateMaximumBitRateUplink(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000000U, NULL, false);

  return offset;
}


static const per_sequence_t UE_AggregateMaximumBitRate_sequence[] = {
  { &hf_ranap_uE_AggregateMaximumBitRateDownlink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UE_AggregateMaximumBitRateDownlink },
  { &hf_ranap_uE_AggregateMaximumBitRateUplink, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UE_AggregateMaximumBitRateUplink },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_AggregateMaximumBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_AggregateMaximumBitRate, UE_AggregateMaximumBitRate_sequence);

  return offset;
}



static int
dissect_ranap_UE_History_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &value_tvb);

  if (value_tvb)
    dissect_s1ap_UE_HistoryInformation_PDU(value_tvb,  actx->pinfo, tree, NULL);


  return offset;
}


static const per_sequence_t UE_IsNotServed_sequence[] = {
  { &hf_ranap_permanentNAS_UE_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PermanentNAS_UE_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_IsNotServed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_IsNotServed, UE_IsNotServed_sequence);

  return offset;
}


static const per_sequence_t UE_IsServed_sequence[] = {
  { &hf_ranap_permanentNAS_UE_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PermanentNAS_UE_ID },
  { &hf_ranap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PLMNidentity },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UE_IsServed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UE_IsServed, UE_IsServed_sequence);

  return offset;
}



static int
dissect_ranap_UE_Usage_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string ranap_UERegistrationQueryResult_vals[] = {
  {   0, "uE-IsServed" },
  {   1, "uE-IsNotServed" },
  { 0, NULL }
};

static const per_choice_t UERegistrationQueryResult_choice[] = {
  {   0, &hf_ranap_uE_IsServed   , ASN1_NO_EXTENSIONS     , dissect_ranap_UE_IsServed },
  {   1, &hf_ranap_uE_IsNotServed, ASN1_NO_EXTENSIONS     , dissect_ranap_UE_IsNotServed },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_UERegistrationQueryResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_UERegistrationQueryResult, UERegistrationQueryResult_choice,
                                 NULL);

  return offset;
}



static int
dissect_ranap_UESBI_IuA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ranap_UESBI_IuB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t UESBI_Iu_sequence[] = {
  { &hf_ranap_uESBI_IuA     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UESBI_IuA },
  { &hf_ranap_uESBI_IuB     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UESBI_IuB },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESBI_Iu(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESBI_Iu, UESBI_Iu_sequence);

  return offset;
}



static int
dissect_ranap_UL_GTP_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_UL_N_PDU_SequenceNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ranap_UP_ModeVersions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ranap_UserPlaneMode_vals[] = {
  {   0, "transparent-mode" },
  {   1, "support-mode-for-predefined-SDU-sizes" },
  { 0, NULL }
};


static int
dissect_ranap_UserPlaneMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_INTEGER_0_359(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, false);

  return offset;
}



static int
dissect_ranap_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t HorizontalSpeedAndBearing_sequence[] = {
  { &hf_ranap_bearing       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_359 },
  { &hf_ranap_horizontalSpeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalSpeedAndBearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalSpeedAndBearing, HorizontalSpeedAndBearing_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocity_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalVelocity, HorizontalVelocity_sequence);

  return offset;
}



static int
dissect_ranap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string ranap_VerticalSpeedDirection_vals[] = {
  {   0, "upward" },
  {   1, "downward" },
  { 0, NULL }
};


static int
dissect_ranap_VerticalSpeedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t VerticalVelocity_sequence[] = {
  { &hf_ranap_veritcalSpeed , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_veritcalSpeedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalSpeedDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_VerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_VerticalVelocity, VerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocity_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_veritcalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalVelocity },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalWithVerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalWithVerticalVelocity, HorizontalWithVerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocityWithUncertainty_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_uncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalVelocityWithUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalVelocityWithUncertainty, HorizontalVelocityWithUncertainty_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocityAndUncertainty_sequence[] = {
  { &hf_ranap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_HorizontalSpeedAndBearing },
  { &hf_ranap_veritcalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_VerticalVelocity },
  { &hf_ranap_horizontalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_verticalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_INTEGER_0_255 },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_HorizontalWithVerticalVelocityAndUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_HorizontalWithVerticalVelocityAndUncertainty, HorizontalWithVerticalVelocityAndUncertainty_sequence);

  return offset;
}


static const value_string ranap_VelocityEstimate_vals[] = {
  {   0, "horizontalVelocity" },
  {   1, "horizontalWithVerticalVelocity" },
  {   2, "horizontalVelocityWithUncertainty" },
  {   3, "horizontalWithVeritcalVelocityAndUncertainty" },
  { 0, NULL }
};

static const per_choice_t VelocityEstimate_choice[] = {
  {   0, &hf_ranap_horizontalVelocity, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalVelocity },
  {   1, &hf_ranap_horizontalWithVerticalVelocity, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalWithVerticalVelocity },
  {   2, &hf_ranap_horizontalVelocityWithUncertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalVelocityWithUncertainty },
  {   3, &hf_ranap_horizontalWithVeritcalVelocityAndUncertainty, ASN1_EXTENSION_ROOT    , dissect_ranap_HorizontalWithVerticalVelocityAndUncertainty },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_VelocityEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_VelocityEstimate, VelocityEstimate_choice,
                                 NULL);

  return offset;
}


static const value_string ranap_VoiceSupportMatchIndicator_vals[] = {
  {   0, "supported" },
  {   1, "not-supported" },
  { 0, NULL }
};


static int
dissect_ranap_VoiceSupportMatchIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfRABs);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");

  return offset;
}



static int
dissect_ranap_RAB_IE_ContainerPairList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerPairList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfRABs);
  offset = dissect_ranap_ProtocolIE_ContainerPairList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerPairList");

  return offset;
}



static int
dissect_ranap_IuSigConId_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfIuSigConIds);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");

  return offset;
}



static int
dissect_ranap_DirectTransfer_IE_ContainerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  asn1_stack_frame_push(actx, "ProtocolIE-ContainerList");
  asn1_param_push_integer(actx, 1);
  asn1_param_push_integer(actx, maxNrOfDTs);
  offset = dissect_ranap_ProtocolIE_ContainerList(tvb, offset, actx, tree, hf_index);

  asn1_stack_frame_pop(actx, "ProtocolIE-ContainerList");

  return offset;
}


static const per_sequence_t Iu_ReleaseCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Iu-ReleaseCommand ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseCommand, Iu_ReleaseCommand_sequence);

  return offset;
}


static const per_sequence_t Iu_ReleaseComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Iu-ReleaseComplete ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseComplete, Iu_ReleaseComplete_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataVolumeReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t DataVolumeList_item_sequence[] = {
  { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfullyTransmittedDataVolume },
  { &hf_ranap_dataVolumeReference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReference },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeList_item, DataVolumeList_item_sequence);

  return offset;
}


static const per_sequence_t DataVolumeList_sequence_of[1] = {
  { &hf_ranap_DataVolumeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_DataVolumeList_item },
};

static int
dissect_ranap_DataVolumeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_DataVolumeList, DataVolumeList_sequence_of,
                                                  1, maxNrOfVol, false);

  return offset;
}


static const per_sequence_t RAB_DataVolumeReportItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportItem, RAB_DataVolumeReportItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleasedList_IuRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleasedItem_IuRelComp_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_uL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem_IuRelComp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem_IuRelComp, RAB_ReleasedItem_IuRelComp_sequence);

  return offset;
}


static const per_sequence_t RelocationRequired_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationRequired ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequired, RelocationRequired_sequence);

  return offset;
}


static const per_sequence_t RelocationCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationCommand ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCommand, RelocationCommand_sequence);

  return offset;
}



static int
dissect_ranap_RAB_RelocationReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_RelocationReleaseItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_RelocationReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_RelocationReleaseItem, RAB_RelocationReleaseItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataForwardingList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataForwardingItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem, RAB_DataForwardingItem_sequence);

  return offset;
}


static const per_sequence_t RelocationPreparationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationPreparationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationPreparationFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationPreparationFailure, RelocationPreparationFailure_sequence);

  return offset;
}


static const per_sequence_t RelocationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequest, RelocationRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_RelocReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t UserPlaneInformation_sequence[] = {
  { &hf_ranap_userPlaneMode , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneMode },
  { &hf_ranap_uP_ModeVersions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UP_ModeVersions },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UserPlaneInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UserPlaneInformation, UserPlaneInformation_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_RelocReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_nAS_SynchronisationIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NAS_SynchronisationIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameters },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReq, RAB_SetupItem_RelocReq_sequence);

  return offset;
}


static const per_sequence_t JoinedMBMSBearerService_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_mBMS_PTP_RAB_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MBMS_PTP_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_JoinedMBMSBearerService_IEs_item, JoinedMBMSBearerService_IEs_item_sequence);

  return offset;
}


static const per_sequence_t JoinedMBMSBearerService_IEs_sequence_of[1] = {
  { &hf_ranap_JoinedMBMSBearerService_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_JoinedMBMSBearerService_IEs_item },
};

static int
dissect_ranap_JoinedMBMSBearerService_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_JoinedMBMSBearerService_IEs, JoinedMBMSBearerService_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, false);

  return offset;
}


static const per_sequence_t CNMBMSLinkingInformation_sequence[] = {
  { &hf_ranap_joinedMBMSBearerService_IEs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_JoinedMBMSBearerService_IEs },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CNMBMSLinkingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CNMBMSLinkingInformation, CNMBMSLinkingInformation_sequence);

  return offset;
}


static const per_sequence_t RelocationRequestAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationRequestAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationRequestAcknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationRequestAcknowledge, RelocationRequestAcknowledge_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_RelocReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_RelocReqAck_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_RelocReqAck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_RelocReqAck, RAB_SetupItem_RelocReqAck_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_FailedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_FailedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_FailedItem, RAB_FailedItem_sequence);

  return offset;
}


static const per_sequence_t RelocationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationFailure, RelocationFailure_sequence);

  return offset;
}


static const per_sequence_t RelocationCancel_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationCancel ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancel, RelocationCancel_sequence);

  return offset;
}


static const per_sequence_t RelocationCancelAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationCancelAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationCancelAcknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationCancelAcknowledge, RelocationCancelAcknowledge_sequence);

  return offset;
}


static const per_sequence_t SRNS_ContextRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SRNS-ContextRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextRequest, SRNS_ContextRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataForwardingItem_SRNS_CtxReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq, RAB_DataForwardingItem_SRNS_CtxReq_sequence);

  return offset;
}


static const per_sequence_t SRNS_ContextResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_ContextResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SRNS-ContextResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_ContextResponse, SRNS_ContextResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ContextItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem, RAB_ContextItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextFailedtoTransferList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RABs_ContextFailedtoTransferItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_ContextFailedtoTransferItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_ContextFailedtoTransferItem, RABs_ContextFailedtoTransferItem_sequence);

  return offset;
}


static const per_sequence_t SecurityModeCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SecurityModeCommand ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeCommand, SecurityModeCommand_sequence);

  return offset;
}


static const per_sequence_t SecurityModeComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SecurityModeComplete ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeComplete, SecurityModeComplete_sequence);

  return offset;
}


static const per_sequence_t SecurityModeReject_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SecurityModeReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SecurityModeReject ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SecurityModeReject, SecurityModeReject_sequence);

  return offset;
}


static const per_sequence_t DataVolumeReportRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReportRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"DataVolumeReportRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReportRequest, DataVolumeReportRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_DataVolumeReportRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_DataVolumeReportRequestItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_DataVolumeReportRequestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_DataVolumeReportRequestItem, RAB_DataVolumeReportRequestItem_sequence);

  return offset;
}


static const per_sequence_t DataVolumeReport_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DataVolumeReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"DataVolumeReport ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DataVolumeReport, DataVolumeReport_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedtoReportList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RABs_failed_to_reportItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RABs_failed_to_reportItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RABs_failed_to_reportItem, RABs_failed_to_reportItem_sequence);

  return offset;
}


static const per_sequence_t Reset_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Reset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Reset ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Reset, Reset_sequence);

  return offset;
}


static const per_sequence_t ResetAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"ResetAcknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetAcknowledge, ResetAcknowledge_sequence);

  return offset;
}


static const per_sequence_t ResetResource_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"ResetResource ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResource, ResetResource_sequence);

  return offset;
}



static int
dissect_ranap_ResetResourceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ResetResourceItem_sequence[] = {
  { &hf_ranap_iuSigConId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuSignallingConnectionIdentifier },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceItem, ResetResourceItem_sequence);

  return offset;
}


static const per_sequence_t ResetResourceAcknowledge_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAcknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"ResetResourceAcknowledge ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAcknowledge, ResetResourceAcknowledge_sequence);

  return offset;
}



static int
dissect_ranap_ResetResourceAckList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_IuSigConId_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ResetResourceAckItem_sequence[] = {
  { &hf_ranap_iuSigConId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuSignallingConnectionIdentifier },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ResetResourceAckItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ResetResourceAckItem, ResetResourceAckItem_sequence);

  return offset;
}


static const per_sequence_t RAB_ReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RAB-ReleaseRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseRequest, RAB_ReleaseRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleaseItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleaseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleaseItem, RAB_ReleaseItem_sequence);

  return offset;
}


static const per_sequence_t Iu_ReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Iu_ReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Iu-ReleaseRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Iu_ReleaseRequest, Iu_ReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t RelocationDetect_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationDetect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationDetect ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationDetect, RelocationDetect_sequence);

  return offset;
}


static const per_sequence_t RelocationComplete_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RelocationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RelocationComplete ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RelocationComplete, RelocationComplete_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"EnhancedRelocationCompleteRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteRequest, EnhancedRelocationCompleteRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhancedRelocCompleteReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhancedRelocCompleteReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddressReq1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociationReq1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_ass_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq, RAB_SetupItem_EnhancedRelocCompleteReq_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"EnhancedRelocationCompleteResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteResponse, EnhancedRelocationCompleteResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhancedRelocCompleteRes_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameters },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerAddressRes1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociationRes1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_rab2beReleasedList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes, RAB_SetupItem_EnhancedRelocCompleteRes_sequence);

  return offset;
}


static const per_sequence_t RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"EnhancedRelocationCompleteFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteFailure, EnhancedRelocationCompleteFailure_sequence);

  return offset;
}


static const per_sequence_t EnhancedRelocationCompleteConfirm_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_EnhancedRelocationCompleteConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"EnhancedRelocationCompleteConfirm ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_EnhancedRelocationCompleteConfirm, EnhancedRelocationCompleteConfirm_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Paging ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Paging, Paging_sequence);

  return offset;
}


static const per_sequence_t CommonID_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CommonID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"CommonID ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CommonID, CommonID_sequence);

  return offset;
}


static const per_sequence_t CN_InvokeTrace_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_InvokeTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"CN-InvokeTrace ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_InvokeTrace, CN_InvokeTrace_sequence);

  return offset;
}


static const per_sequence_t CN_DeactivateTrace_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_CN_DeactivateTrace(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"CN-DeactivateTrace ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_CN_DeactivateTrace, CN_DeactivateTrace_sequence);

  return offset;
}


static const per_sequence_t LocationReportingControl_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReportingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"LocationReportingControl ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReportingControl, LocationReportingControl_sequence);

  return offset;
}


static const per_sequence_t LocationReport_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"LocationReport ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationReport, LocationReport_sequence);

  return offset;
}


static const per_sequence_t InitialUE_Message_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitialUE_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"InitialUE-Message ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitialUE_Message, InitialUE_Message_sequence);

  return offset;
}


static const per_sequence_t DirectTransfer_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"DirectTransfer ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransfer, DirectTransfer_sequence);

  return offset;
}



static int
dissect_ranap_RedirectionIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_ProtocolIE_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t Overload_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Overload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"Overload ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Overload, Overload_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"ErrorIndication ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t SRNS_DataForwardCommand_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRNS_DataForwardCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SRNS-DataForwardCommand ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRNS_DataForwardCommand, SRNS_DataForwardCommand_sequence);

  return offset;
}


static const per_sequence_t ForwardSRNS_Context_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_ForwardSRNS_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"ForwardSRNS-Context ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_ForwardSRNS_Context, ForwardSRNS_Context_sequence);

  return offset;
}


static const per_sequence_t RAB_AssignmentRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RAB-AssignmentRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentRequest, RAB_AssignmentRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupOrModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerPairList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TransportLayerInformation_sequence[] = {
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TransportLayerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TransportLayerInformation, TransportLayerInformation_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemFirst_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_nAS_SynchronisationIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_NAS_SynchronisationIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_RAB_Parameters },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UserPlaneInformation },
  { &hf_ranap_transportLayerInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerInformation },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemFirst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  address ipv4_addr;
  uint32_t transportLayerAddress_ipv4;
  uint16_t binding_id;

  private_data_set_transportLayerAddress_ipv4(actx, 0);
  private_data_set_binding_id_port(actx, 0);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemFirst, RAB_SetupOrModifyItemFirst_sequence);

  transportLayerAddress_ipv4 = private_data_get_transportLayerAddress_ipv4(actx);
  binding_id = private_data_get_binding_id_port(actx);
  if (actx->pinfo->fd->visited || transportLayerAddress_ipv4 == 0 || binding_id == 0){
    return offset;
  }
  set_address(&ipv4_addr, AT_IPv4, 4, &transportLayerAddress_ipv4);
  /* Set RTP dissector for the UDP stream of this RAB */
  rtp_add_address(actx->pinfo, PT_UDP, &ipv4_addr, binding_id, 0, "RANAP", actx->pinfo->num, false, 0);


  return offset;
}


static const per_sequence_t RAB_SetupOrModifyItemSecond_sequence[] = {
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifyItemSecond(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifyItemSecond, RAB_SetupOrModifyItemSecond_sequence);

  return offset;
}


static const per_sequence_t RAB_AssignmentResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_AssignmentResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RAB-AssignmentResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_AssignmentResponse, RAB_AssignmentResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupOrModifiedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_SetupOrModifiedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_IuTransportAssociation },
  { &hf_ranap_dl_dataVolumes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupOrModifiedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  address ipv4_addr;
  uint32_t transportLayerAddress_ipv4;
  uint16_t binding_id;

  private_data_set_transportLayerAddress_ipv4(actx, 0);
  private_data_set_binding_id_port(actx, 0);
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupOrModifiedItem, RAB_SetupOrModifiedItem_sequence);

  transportLayerAddress_ipv4 = private_data_get_transportLayerAddress_ipv4(actx);
  binding_id = private_data_get_binding_id_port(actx);
  if (actx->pinfo->fd->visited || transportLayerAddress_ipv4 == 0 || binding_id == 0){
    return offset;
  }
  set_address(&ipv4_addr, AT_IPv4, 4, &transportLayerAddress_ipv4);
  /* Set RTP dissector for the UDP stream of this RAB */
  rtp_add_address(actx->pinfo, PT_UDP, &ipv4_addr, binding_id, 0, "RANAP", actx->pinfo->num, false, 0);


  return offset;
}



static int
dissect_ranap_RAB_ReleasedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ReleasedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_dataVolumes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeList },
  { &hf_ranap_dL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_uL_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ReleasedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ReleasedItem, RAB_ReleasedItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_QueuedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_QueuedItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_QueuedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_QueuedItem, RAB_QueuedItem_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ReleaseFailedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_FailedList(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_gERAN_Classmark, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_GERAN_Classmark },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_ranap_privateIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"PrivateMessage ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t RANAP_RelocationInformation_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_RelocationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RANAP-RelocationInformation ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_RelocationInformation, RANAP_RelocationInformation_sequence);

  return offset;
}



static int
dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_DirectTransfer_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t DirectTransferInformationItem_RANAP_RelocInf_sequence[] = {
  { &hf_ranap_nAS_PDU       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_NAS_PDU },
  { &hf_ranap_sAPI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_SAPI },
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectTransferInformationItem_RANAP_RelocInf, DirectTransferInformationItem_RANAP_RelocInf_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ContextItem_RANAP_RelocInf_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dl_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_GTP_PDU_SequenceNumber },
  { &hf_ranap_ul_GTP_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_GTP_PDU_SequenceNumber },
  { &hf_ranap_dl_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DL_N_PDU_SequenceNumber },
  { &hf_ranap_ul_N_PDU_SequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_UL_N_PDU_SequenceNumber },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ContextItem_RANAP_RelocInf, RAB_ContextItem_RANAP_RelocInf_sequence);

  return offset;
}


static const per_sequence_t RANAP_EnhancedRelocationInformationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_EnhancedRelocationInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RANAP-EnhancedRelocationInformationRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_EnhancedRelocationInformationRequest, RANAP_EnhancedRelocationInformationRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhRelocInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TNLInformationEnhRelInfoReq_sequence[] = {
  { &hf_ranap_transportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_iuTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TNLInformationEnhRelInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TNLInformationEnhRelInfoReq, TNLInformationEnhRelInfoReq_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhRelocInfoReq_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_Parameters },
  { &hf_ranap_dataVolumeReportingIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_DataVolumeReportingIndication },
  { &hf_ranap_pDP_TypeInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_PDP_TypeInformation },
  { &hf_ranap_userPlaneInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_UserPlaneInformation },
  { &hf_ranap_dataForwardingInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoReq },
  { &hf_ranap_sourceSideIuULTNLInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoReq },
  { &hf_ranap_service_Handover, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Service_Handover },
  { &hf_ranap_alt_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Alt_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhRelocInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhRelocInfoReq, RAB_SetupItem_EnhRelocInfoReq_sequence);

  return offset;
}


static const per_sequence_t RANAP_EnhancedRelocationInformationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RANAP_EnhancedRelocationInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RANAP-EnhancedRelocationInformationResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RANAP_EnhancedRelocationInformationResponse, RANAP_EnhancedRelocationInformationResponse_sequence);

  return offset;
}



static int
dissect_ranap_RAB_SetupList_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t TNLInformationEnhRelInfoRes_sequence[] = {
  { &hf_ranap_dl_forwardingTransportLayerAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TransportLayerAddress },
  { &hf_ranap_dl_forwardingTransportAssociation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IuTransportAssociation },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_TNLInformationEnhRelInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_TNLInformationEnhRelInfoRes, TNLInformationEnhRelInfoRes_sequence);

  return offset;
}


static const per_sequence_t RAB_SetupItem_EnhRelocInfoRes_sequence[] = {
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_dataForwardingInformation_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_TNLInformationEnhRelInfoRes },
  { &hf_ranap_ass_RAB_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_Ass_RAB_Parameters },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_SetupItem_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_SetupItem_EnhRelocInfoRes, RAB_SetupItem_EnhRelocInfoRes_sequence);

  return offset;
}



static int
dissect_ranap_RAB_FailedList_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_FailedItem_EnhRelocInfoRes_sequence[] = {
  { &hf_ranap_cN_DomainIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_CN_DomainIndicator },
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_FailedItem_EnhRelocInfoRes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_FailedItem_EnhRelocInfoRes, RAB_FailedItem_EnhRelocInfoRes_sequence);

  return offset;
}


static const per_sequence_t RAB_ModifyRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RAB-ModifyRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyRequest, RAB_ModifyRequest_sequence);

  return offset;
}



static int
dissect_ranap_RAB_ModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ranap_RAB_IE_ContainerList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t RAB_ModifyItem_sequence[] = {
  { &hf_ranap_rAB_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_RAB_ID },
  { &hf_ranap_requested_RAB_Parameter_Values, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Requested_RAB_Parameter_Values },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RAB_ModifyItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RAB_ModifyItem, RAB_ModifyItem_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"LocationRelatedDataRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataRequest, LocationRelatedDataRequest_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"LocationRelatedDataResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataResponse, LocationRelatedDataResponse_sequence);

  return offset;
}


static const per_sequence_t LocationRelatedDataFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LocationRelatedDataFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"LocationRelatedDataFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LocationRelatedDataFailure, LocationRelatedDataFailure_sequence);

  return offset;
}


static const per_sequence_t InformationTransferIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"InformationTransferIndication ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferIndication, InformationTransferIndication_sequence);

  return offset;
}


static const per_sequence_t InformationTransferConfirmation_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferConfirmation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"InformationTransferConfirmation ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferConfirmation, InformationTransferConfirmation_sequence);

  return offset;
}


static const per_sequence_t InformationTransferFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InformationTransferFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"InformationTransferFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InformationTransferFailure, InformationTransferFailure_sequence);

  return offset;
}


static const per_sequence_t UESpecificInformationIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UESpecificInformationIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UESpecificInformationIndication ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UESpecificInformationIndication, UESpecificInformationIndication_sequence);

  return offset;
}


static const per_sequence_t DirectInformationTransfer_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_DirectInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"DirectInformationTransfer ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_DirectInformationTransfer, DirectInformationTransfer_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UplinkInformationExchangeRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeRequest, UplinkInformationExchangeRequest_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UplinkInformationExchangeResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeResponse, UplinkInformationExchangeResponse_sequence);

  return offset;
}


static const per_sequence_t UplinkInformationExchangeFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UplinkInformationExchangeFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UplinkInformationExchangeFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UplinkInformationExchangeFailure, UplinkInformationExchangeFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStart_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionStart ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStart, MBMSSessionStart_sequence);

  return offset;
}


static const per_sequence_t MBMSSynchronisationInformation_sequence[] = {
  { &hf_ranap_mBMSHCIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_MBMSHCIndicator },
  { &hf_ranap_iPMulticastAddress, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_IPMulticastAddress },
  { &hf_ranap_gTPDLTEID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_GTP_TEI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSynchronisationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSynchronisationInformation, MBMSSynchronisationInformation_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionStartResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartResponse, MBMSSessionStartResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStartFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStartFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionStartFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStartFailure, MBMSSessionStartFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdate_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionUpdate ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdate, MBMSSessionUpdate_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionUpdateResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateResponse, MBMSSessionUpdateResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionUpdateFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionUpdateFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionUpdateFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionUpdateFailure, MBMSSessionUpdateFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStop_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStop(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionStop ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStop, MBMSSessionStop_sequence);

  return offset;
}


static const per_sequence_t MBMSSessionStopResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSSessionStopResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSSessionStopResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSSessionStopResponse, MBMSSessionStopResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSUELinkingRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSUELinkingRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingRequest, MBMSUELinkingRequest_sequence);

  return offset;
}


static const per_sequence_t LeftMBMSBearerService_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_LeftMBMSBearerService_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_LeftMBMSBearerService_IEs_item, LeftMBMSBearerService_IEs_item_sequence);

  return offset;
}


static const per_sequence_t LeftMBMSBearerService_IEs_sequence_of[1] = {
  { &hf_ranap_LeftMBMSBearerService_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_LeftMBMSBearerService_IEs_item },
};

static int
dissect_ranap_LeftMBMSBearerService_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_LeftMBMSBearerService_IEs, LeftMBMSBearerService_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, false);

  return offset;
}


static const per_sequence_t MBMSUELinkingResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSUELinkingResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSUELinkingResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSUELinkingResponse, MBMSUELinkingResponse_sequence);

  return offset;
}


static const per_sequence_t UnsuccessfulLinking_IEs_item_sequence[] = {
  { &hf_ranap_tMGI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_TMGI },
  { &hf_ranap_cause         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_Cause },
  { &hf_ranap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulLinking_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulLinking_IEs_item, UnsuccessfulLinking_IEs_item_sequence);

  return offset;
}


static const per_sequence_t UnsuccessfulLinking_IEs_sequence_of[1] = {
  { &hf_ranap_UnsuccessfulLinking_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfulLinking_IEs_item },
};

static int
dissect_ranap_UnsuccessfulLinking_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ranap_UnsuccessfulLinking_IEs, UnsuccessfulLinking_IEs_sequence_of,
                                                  1, maxnoofMulticastServicesPerUE, false);

  return offset;
}


static const per_sequence_t MBMSRegistrationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRegistrationRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationRequest, MBMSRegistrationRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSRegistrationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRegistrationResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationResponse, MBMSRegistrationResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSRegistrationFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRegistrationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRegistrationFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRegistrationFailure, MBMSRegistrationFailure_sequence);

  return offset;
}


static const per_sequence_t MBMSCNDe_RegistrationRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSCNDe-RegistrationRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationRequest, MBMSCNDe_RegistrationRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSCNDe_RegistrationResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSCNDe_RegistrationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSCNDe-RegistrationResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSCNDe_RegistrationResponse, MBMSCNDe_RegistrationResponse_sequence);

  return offset;
}


static const per_sequence_t MBMSRABEstablishmentIndication_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABEstablishmentIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRABEstablishmentIndication ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABEstablishmentIndication, MBMSRABEstablishmentIndication_sequence);

  return offset;
}


static const per_sequence_t MBMSRABReleaseRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRABReleaseRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseRequest, MBMSRABReleaseRequest_sequence);

  return offset;
}


static const per_sequence_t MBMSRABRelease_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRABRelease ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABRelease, MBMSRABRelease_sequence);

  return offset;
}


static const per_sequence_t MBMSRABReleaseFailure_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_MBMSRABReleaseFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"MBMSRABReleaseFailure ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_MBMSRABReleaseFailure, MBMSRABReleaseFailure_sequence);

  return offset;
}


static const per_sequence_t SRVCC_CSKeysRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_CSKeysRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SRVCC-CSKeysRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_CSKeysRequest, SRVCC_CSKeysRequest_sequence);

  return offset;
}


static const per_sequence_t SRVCC_CSKeysResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SRVCC_CSKeysResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"SRVCC-CSKeysResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SRVCC_CSKeysResponse, SRVCC_CSKeysResponse_sequence);

  return offset;
}


static const per_sequence_t UeRadioCapabilityMatchRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UeRadioCapabilityMatchRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UeRadioCapabilityMatchRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UeRadioCapabilityMatchRequest, UeRadioCapabilityMatchRequest_sequence);

  return offset;
}


static const per_sequence_t UeRadioCapabilityMatchResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UeRadioCapabilityMatchResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UeRadioCapabilityMatchResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UeRadioCapabilityMatchResponse, UeRadioCapabilityMatchResponse_sequence);

  return offset;
}


static const per_sequence_t UeRegistrationQueryRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UeRegistrationQueryRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UeRegistrationQueryRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UeRegistrationQueryRequest, UeRegistrationQueryRequest_sequence);

  return offset;
}


static const per_sequence_t UeRegistrationQueryResponse_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UeRegistrationQueryResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"UeRegistrationQueryResponse ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UeRegistrationQueryResponse, UeRegistrationQueryResponse_sequence);

  return offset;
}


static const per_sequence_t RerouteNASRequest_sequence[] = {
  { &hf_ranap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ranap_ProtocolIE_Container },
  { &hf_ranap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ranap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_RerouteNASRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
col_set_str(actx->pinfo->cinfo, COL_INFO,"RerouteNASRequest ");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_RerouteNASRequest, RerouteNASRequest_sequence);

  return offset;
}



static int
dissect_ranap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_ranap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_ranap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_ranap_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_OutcomeValue);

  return offset;
}


static const per_sequence_t Outcome_sequence[] = {
  { &hf_ranap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_ProcedureCode },
  { &hf_ranap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_Criticality },
  { &hf_ranap_value         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ranap_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_ranap_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ranap_Outcome, Outcome_sequence);

  return offset;
}


static const value_string ranap_RANAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  {   3, "outcome" },
  { 0, NULL }
};

static const per_choice_t RANAP_PDU_choice[] = {
  {   0, &hf_ranap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_ranap_InitiatingMessage },
  {   1, &hf_ranap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ranap_SuccessfulOutcome },
  {   2, &hf_ranap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_ranap_UnsuccessfulOutcome },
  {   3, &hf_ranap_outcome       , ASN1_EXTENSION_ROOT    , dissect_ranap_Outcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_ranap_RANAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ranap_RANAP_PDU, RANAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AccuracyFulfilmentIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_AccuracyFulfilmentIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_AccuracyFulfilmentIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Additional_CSPS_coordination_information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Additional_CSPS_coordination_information(tvb, offset, &asn1_ctx, tree, hf_ranap_Additional_CSPS_coordination_information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Additional_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Additional_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_ranap_Additional_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf(tvb, offset, &asn1_ctx, tree, hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AlternativeRABConfigurationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_AlternativeRABConfigurationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_AlternativeRABConfigurationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Application_Layer_Measurement_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_Application_Layer_Measurement_Configuration(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_Application_Layer_Measurement_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Application_Layer_Measurement_Configuration_For_Relocation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_APN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_APN(tvb, offset, &asn1_ctx, tree, hf_ranap_APN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AreaIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_AreaIdentity(tvb, offset, &asn1_ctx, tree, hf_ranap_AreaIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BarometricPressure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_BarometricPressure(tvb, offset, &asn1_ctx, tree, hf_ranap_BarometricPressure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BroadcastAssistanceDataDecipheringKeys_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_BroadcastAssistanceDataDecipheringKeys(tvb, offset, &asn1_ctx, tree, hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Cause(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Access_Mode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Cell_Access_Mode(tvb, offset, &asn1_ctx, tree, hf_ranap_Cell_Access_Mode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellLoadInformationGroup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CellLoadInformationGroup(tvb, offset, &asn1_ctx, tree, hf_ranap_CellLoadInformationGroup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CivicAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CivicAddress(tvb, offset, &asn1_ctx, tree, hf_ranap_CivicAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClientType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ClientType(tvb, offset, &asn1_ctx, tree, hf_ranap_ClientType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_ranap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageStructure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MessageStructure(tvb, offset, &asn1_ctx, tree, hf_ranap_MessageStructure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ChosenEncryptionAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ChosenEncryptionAlgorithm(tvb, offset, &asn1_ctx, tree, hf_ranap_ChosenEncryptionAlgorithm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ChosenIntegrityProtectionAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ChosenIntegrityProtectionAlgorithm(tvb, offset, &asn1_ctx, tree, hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClassmarkInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ClassmarkInformation2(tvb, offset, &asn1_ctx, tree, hf_ranap_ClassmarkInformation2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClassmarkInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ClassmarkInformation3(tvb, offset, &asn1_ctx, tree, hf_ranap_ClassmarkInformation3_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_DomainIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CN_DomainIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_DomainIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Correlation_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_Correlation_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSFB_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CSFB_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_CSFB_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CSG_Id(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Id_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Id_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CSG_Id_List(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Id_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_Membership_Status_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CSG_Membership_Status(tvb, offset, &asn1_ctx, tree, hf_ranap_CSG_Membership_Status_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DCN_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DCN_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_DCN_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DeltaRAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DeltaRAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_DeltaRAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DRX_CycleLengthCoefficient_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DRX_CycleLengthCoefficient(tvb, offset, &asn1_ctx, tree, hf_ranap_DRX_CycleLengthCoefficient_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EARFCN_Extended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EARFCN_Extended(tvb, offset, &asn1_ctx, tree, hf_ranap_EARFCN_Extended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_DCH_MAC_d_Flow_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_E_DCH_MAC_d_Flow_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_E_DCH_MAC_d_Flow_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EncryptionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EncryptionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_EncryptionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EncryptionKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EncryptionKey(tvb, offset, &asn1_ctx, tree, hf_ranap_EncryptionKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_End_Of_CSFB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_End_Of_CSFB(tvb, offset, &asn1_ctx, tree, hf_ranap_End_Of_CSFB_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_UTRAN_Service_Handover_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_E_UTRAN_Service_Handover(tvb, offset, &asn1_ctx, tree, hf_ranap_E_UTRAN_Service_Handover_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ExtendedRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_ExtendedRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_FrequenceLayerConvergenceFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_FrequenceLayerConvergenceFlag(tvb, offset, &asn1_ctx, tree, hf_ranap_FrequenceLayerConvergenceFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GANSS_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_ranap_GANSS_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_BSC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GERAN_BSC_Container(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_BSC_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Classmark_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GERAN_Classmark(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Classmark_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalCN_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GlobalCN_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_GlobalCN_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GlobalRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GlobalRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_GlobalRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HigherBitratesThan16MbpsFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_HigherBitratesThan16MbpsFlag(tvb, offset, &asn1_ctx, tree, hf_ranap_HigherBitratesThan16MbpsFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HS_DSCH_MAC_d_Flow_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_HS_DSCH_MAC_d_Flow_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IMSI(tvb, offset, &asn1_ctx, tree, hf_ranap_IMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IncludeVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IncludeVelocity(tvb, offset, &asn1_ctx, tree, hf_ranap_IncludeVelocity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationExchangeID(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationExchangeID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationExchangeType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationExchangeType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationRequested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationRequested(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationRequested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationTransferID(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationTransferType(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntegrityProtectionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IntegrityProtectionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_IntegrityProtectionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntegrityProtectionKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IntegrityProtectionKey(tvb, offset, &asn1_ctx, tree, hf_ranap_IntegrityProtectionKey_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterSystemInformationTransferType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InterSystemInformationTransferType(tvb, offset, &asn1_ctx, tree, hf_ranap_InterSystemInformationTransferType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_InterSystemInformation_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InterSystemInformation_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_InterSystemInformation_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IPMulticastAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IPMulticastAddress(tvb, offset, &asn1_ctx, tree, hf_ranap_IPMulticastAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IuSignallingConnectionIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IuSignallingConnectionIdentifier(tvb, offset, &asn1_ctx, tree, hf_ranap_IuSignallingConnectionIdentifier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IuTransportAssociation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IuTransportAssociation(tvb, offset, &asn1_ctx, tree, hf_ranap_IuTransportAssociation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_KeyStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_KeyStatus(tvb, offset, &asn1_ctx, tree, hf_ranap_KeyStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LAI(tvb, offset, &asn1_ctx, tree, hf_ranap_LAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LastKnownServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LastKnownServiceArea(tvb, offset, &asn1_ctx, tree, hf_ranap_LastKnownServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_LastVisitedUTRANCell_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LastVisitedUTRANCell_Item(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_LastVisitedUTRANCell_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LHN_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LHN_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_LHN_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_L3_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_L3_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_L3_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M4Report_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_M4Report(tvb, offset, &asn1_ctx, tree, hf_ranap_M4Report_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M5Report_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_M5Report(tvb, offset, &asn1_ctx, tree, hf_ranap_M5Report_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M6Report_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_M6Report(tvb, offset, &asn1_ctx, tree, hf_ranap_M6Report_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_M7Report_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_M7Report(tvb, offset, &asn1_ctx, tree, hf_ranap_M7Report_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Management_Based_MDT_Allowed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Management_Based_MDT_Allowed(tvb, offset, &asn1_ctx, tree, hf_ranap_Management_Based_MDT_Allowed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSBearerServiceType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSBearerServiceType(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSBearerServiceType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_Registration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSCNDe_Registration(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_Registration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCountingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSCountingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCountingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSLinkingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSLinkingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSLinkingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRegistrationRequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSServiceArea_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSServiceArea(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSServiceArea_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionDuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionDuration(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionDuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionIdentity(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionRepetitionNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionRepetitionNumber(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionRepetitionNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MDT_Configuration(tvb, offset, &asn1_ctx, tree, hf_ranap_MDT_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MDT_PLMN_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MDT_PLMN_List(tvb, offset, &asn1_ctx, tree, hf_ranap_MDT_PLMN_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MSISDN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MSISDN(tvb, offset, &asn1_ctx, tree, hf_ranap_MSISDN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_NAS_PDU(tvb, offset, &asn1_ctx, tree, hf_ranap_NAS_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NAS_SequenceNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_NAS_SequenceNumber(tvb, offset, &asn1_ctx, tree, hf_ranap_NAS_SequenceNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NewBSS_To_OldBSS_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_NewBSS_To_OldBSS_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_NewBSS_To_OldBSS_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NonSearchingIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_NonSearchingIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_NonSearchingIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberOfSteps_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_NumberOfSteps(tvb, offset, &asn1_ctx, tree, hf_ranap_NumberOfSteps_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Offload_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Offload_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_Offload_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OldBSS_ToNewBSS_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_OldBSS_ToNewBSS_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_OldBSS_ToNewBSS_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OMC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_OMC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_OMC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Out_Of_UTRAN_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Out_Of_UTRAN(tvb, offset, &asn1_ctx, tree, hf_ranap_Out_Of_UTRAN_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingAreaID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PagingAreaID(tvb, offset, &asn1_ctx, tree, hf_ranap_PagingAreaID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PagingCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PagingCause(tvb, offset, &asn1_ctx, tree, hf_ranap_PagingCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDP_TypeInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PDP_TypeInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_PDP_TypeInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PDP_TypeInformation_extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PDP_TypeInformation_extension(tvb, offset, &asn1_ctx, tree, hf_ranap_PDP_TypeInformation_extension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PeriodicLocationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PeriodicLocationInfo(tvb, offset, &asn1_ctx, tree, hf_ranap_PeriodicLocationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PermanentNAS_UE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PermanentNAS_UE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_PermanentNAS_UE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMNidentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PLMNidentity(tvb, offset, &asn1_ctx, tree, hf_ranap_PLMNidentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PositioningPriority(tvb, offset, &asn1_ctx, tree, hf_ranap_PositioningPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PositionData(tvb, offset, &asn1_ctx, tree, hf_ranap_PositionData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionDataSpecificToGERANIuMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PositionDataSpecificToGERANIuMode(tvb, offset, &asn1_ctx, tree, hf_ranap_PositionDataSpecificToGERANIuMode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Priority_Class_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Priority_Class_Indicator(tvb, offset, &asn1_ctx, tree, hf_ranap_Priority_Class_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProvidedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ProvidedData(tvb, offset, &asn1_ctx, tree, hf_ranap_ProvidedData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PowerSavingIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PowerSavingIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_PowerSavingIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_P_TMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_P_TMSI(tvb, offset, &asn1_ctx, tree, hf_ranap_P_TMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_Parameters(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABParametersList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RABParametersList(tvb, offset, &asn1_ctx, tree, hf_ranap_RABParametersList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAC(tvb, offset, &asn1_ctx, tree, hf_ranap_RAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_RAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAListofIdleModeUEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LAListofIdleModeUEs(tvb, offset, &asn1_ctx, tree, hf_ranap_LAListofIdleModeUEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAT_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAT_Type(tvb, offset, &asn1_ctx, tree, hf_ranap_RAT_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectAttemptFlag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RedirectAttemptFlag(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectAttemptFlag_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectionCompleted_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RedirectionCompleted(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectionCompleted_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RejectCauseValue_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RejectCauseValue(tvb, offset, &asn1_ctx, tree, hf_ranap_RejectCauseValue_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationType(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedGANSSAssistanceData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RequestedGANSSAssistanceData(tvb, offset, &asn1_ctx, tree, hf_ranap_RequestedGANSSAssistanceData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RequestType(tvb, offset, &asn1_ctx, tree, hf_ranap_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResponseTime(tvb, offset, &asn1_ctx, tree, hf_ranap_ResponseTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RNSAPRelocationParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RNSAPRelocationParameters(tvb, offset, &asn1_ctx, tree, hf_ranap_RNSAPRelocationParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RRC_Container(tvb, offset, &asn1_ctx, tree, hf_ranap_RRC_Container_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRVCC_HO_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RSRVCC_HO_Indication(tvb, offset, &asn1_ctx, tree, hf_ranap_RSRVCC_HO_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRVCC_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RSRVCC_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_RSRVCC_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRVCC_Operation_Possible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RSRVCC_Operation_Possible(tvb, offset, &asn1_ctx, tree, hf_ranap_RSRVCC_Operation_Possible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SAI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SAI(tvb, offset, &asn1_ctx, tree, hf_ranap_SAI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SAPI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SAPI(tvb, offset, &asn1_ctx, tree, hf_ranap_SAPI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SessionUpdateID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SessionUpdateID(tvb, offset, &asn1_ctx, tree, hf_ranap_SessionUpdateID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Session_Re_establishment_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Session_Re_establishment_Indicator(tvb, offset, &asn1_ctx, tree, hf_ranap_Session_Re_establishment_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SignallingIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SignallingIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_SignallingIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SGSN_Group_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SGSN_Group_Identity(tvb, offset, &asn1_ctx, tree, hf_ranap_SGSN_Group_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SNA_Access_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SNA_Access_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_SNA_Access_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_Source_ToTarget_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Source_ToTarget_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_Source_ToTarget_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_SourceCellID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SourceCellID(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_SourceCellID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SourceBSS_ToTargetBSS_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SourceID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SourceID(tvb, offset, &asn1_ctx, tree, hf_ranap_SourceID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IRAT_Measurement_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_IRAT_Measurement_Configuration(tvb, offset, &asn1_ctx, tree, hf_ranap_IRAT_Measurement_Configuration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRQ_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RSRQ_Type(tvb, offset, &asn1_ctx, tree, hf_ranap_RSRQ_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RSRQ_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RSRQ_Extension(tvb, offset, &asn1_ctx, tree, hf_ranap_RSRQ_Extension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SubscriberProfileIDforRFP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SubscriberProfileIDforRFP(tvb, offset, &asn1_ctx, tree, hf_ranap_SubscriberProfileIDforRFP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportedRAB_ParameterBitrateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SupportedRAB_ParameterBitrateList(tvb, offset, &asn1_ctx, tree, hf_ranap_SupportedRAB_ParameterBitrateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRB_TrCH_Mapping_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRB_TrCH_Mapping(tvb, offset, &asn1_ctx, tree, hf_ranap_SRB_TrCH_Mapping_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_HO_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRVCC_HO_Indication(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_HO_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRVCC_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_Operation_Possible_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRVCC_Operation_Possible(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_Operation_Possible_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Target_ToSource_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Target_ToSource_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_Target_ToSource_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TargetBSS_ToSourceBSS_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TargetID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TargetID(tvb, offset, &asn1_ctx, tree, hf_ranap_TargetID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_TargetRNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TargetRNC_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_TargetRNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvb, offset, &asn1_ctx, tree, hf_ranap_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TemporaryUE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TemporaryUE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_TemporaryUE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Time_UE_StayedInCell_EnhancedGranularity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Time_UE_StayedInCell_EnhancedGranularity(tvb, offset, &asn1_ctx, tree, hf_ranap_Time_UE_StayedInCell_EnhancedGranularity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeToMBMSDataTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TimeToMBMSDataTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_TimeToMBMSDataTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimingDifferenceULDL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TimingDifferenceULDL(tvb, offset, &asn1_ctx, tree, hf_ranap_TimingDifferenceULDL_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TMGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TMGI(tvb, offset, &asn1_ctx, tree, hf_ranap_TMGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TracePropagationParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TracePropagationParameters(tvb, offset, &asn1_ctx, tree, hf_ranap_TracePropagationParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceRecordingSessionInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TraceRecordingSessionInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceRecordingSessionInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceRecordingSessionReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TraceRecordingSessionReference(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceRecordingSessionReference_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TraceReference(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceReference_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TraceType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TraceType(tvb, offset, &asn1_ctx, tree, hf_ranap_TraceType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TransportLayerAddress(tvb, offset, &asn1_ctx, tree, hf_ranap_TransportLayerAddress_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TriggerID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TriggerID(tvb, offset, &asn1_ctx, tree, hf_ranap_TriggerID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TunnelInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TunnelInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_TunnelInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TypeOfError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TypeOfError(tvb, offset, &asn1_ctx, tree, hf_ranap_TypeOfError_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_AggregateMaximumBitRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_AggregateMaximumBitRate(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_AggregateMaximumBitRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_History_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_History_Information(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_History_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_ID(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Usage_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UE_Usage_Type(tvb, offset, &asn1_ctx, tree, hf_ranap_UE_Usage_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERegistrationQueryResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UERegistrationQueryResult(tvb, offset, &asn1_ctx, tree, hf_ranap_UERegistrationQueryResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESBI_Iu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UESBI_Iu(tvb, offset, &asn1_ctx, tree, hf_ranap_UESBI_Iu_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTRAN_CellID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UTRAN_CellID(tvb, offset, &asn1_ctx, tree, hf_ranap_UTRAN_CellID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VelocityEstimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_VelocityEstimate(tvb, offset, &asn1_ctx, tree, hf_ranap_VelocityEstimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VerticalAccuracyCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_VerticalAccuracyCode(tvb, offset, &asn1_ctx, tree, hf_ranap_VerticalAccuracyCode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VoiceSupportMatchIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_VoiceSupportMatchIndicator(tvb, offset, &asn1_ctx, tree, hf_ranap_VoiceSupportMatchIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Iu_ReleaseCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Iu_ReleaseComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedList_IuRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleasedList_IuRelComp(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedList_IuRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedItem_IuRelComp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleasedItem_IuRelComp(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedItem_IuRelComp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationRequired(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_RelocationReleaseList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_RelocationReleaseList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_RelocationReleaseList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_RelocationReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_RelocationReleaseItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_RelocationReleaseItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataForwardingList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataForwardingItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationPreparationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationPreparationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationPreparationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_RelocReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_RelocReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_RelocReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_RelocReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_RelocReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_RelocReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CNMBMSLinkingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CNMBMSLinkingInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_CNMBMSLinkingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_JoinedMBMSBearerService_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_JoinedMBMSBearerService_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_JoinedMBMSBearerService_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationRequestAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationRequestAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationRequestAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_RelocReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_RelocReqAck(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_RelocReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_RelocReqAck_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_RelocReqAck(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_RelocReqAck_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_FailedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_FailedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCancel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationCancel(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCancel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationCancelAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationCancelAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationCancelAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_ContextRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRNS_ContextRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_ContextRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingList_SRNS_CtxReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataForwardingList_SRNS_CtxReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataForwardingItem_SRNS_CtxReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataForwardingItem_SRNS_CtxReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_ContextResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRNS_ContextResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_ContextResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ContextList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ContextItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextFailedtoTransferList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ContextFailedtoTransferList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextFailedtoTransferList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABs_ContextFailedtoTransferItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RABs_ContextFailedtoTransferItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RABs_ContextFailedtoTransferItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SecurityModeCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SecurityModeComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SecurityModeReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SecurityModeReject(tvb, offset, &asn1_ctx, tree, hf_ranap_SecurityModeReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataVolumeReportRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DataVolumeReportRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_DataVolumeReportRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportRequestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportRequestList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportRequestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_DataVolumeReportRequestItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_DataVolumeReportRequestItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_DataVolumeReportRequestItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DataVolumeReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DataVolumeReport(tvb, offset, &asn1_ctx, tree, hf_ranap_DataVolumeReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedtoReportList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_FailedtoReportList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedtoReportList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RABs_failed_to_reportItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RABs_failed_to_reportItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RABs_failed_to_reportItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Reset(tvb, offset, &asn1_ctx, tree, hf_ranap_Reset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResource(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResource_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResourceList(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResourceItem(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAcknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResourceAcknowledge(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAcknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAckList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResourceAckList(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAckList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResetResourceAckItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ResetResourceAckItem(tvb, offset, &asn1_ctx, tree, hf_ranap_ResetResourceAckItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleaseList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleaseItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Iu_ReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Iu_ReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_Iu_ReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationDetect_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationDetect(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationDetect_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelocationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RelocationComplete(tvb, offset, &asn1_ctx, tree, hf_ranap_RelocationComplete_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhancedRelocCompleteReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhancedRelocCompleteReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhancedRelocCompleteReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnhancedRelocationCompleteConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_EnhancedRelocationCompleteConfirm(tvb, offset, &asn1_ctx, tree, hf_ranap_EnhancedRelocationCompleteConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Paging_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Paging(tvb, offset, &asn1_ctx, tree, hf_ranap_Paging_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CommonID(tvb, offset, &asn1_ctx, tree, hf_ranap_CommonID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_InvokeTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CN_InvokeTrace(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_InvokeTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CN_DeactivateTrace_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_CN_DeactivateTrace(tvb, offset, &asn1_ctx, tree, hf_ranap_CN_DeactivateTrace_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReportingControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationReportingControl(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationReportingControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationReport(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InitialUE_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InitialUE_Message(tvb, offset, &asn1_ctx, tree, hf_ranap_InitialUE_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DirectTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RedirectionIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RedirectionIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_RedirectionIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Overload_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_Overload(tvb, offset, &asn1_ctx, tree, hf_ranap_Overload_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRNS_DataForwardCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRNS_DataForwardCommand(tvb, offset, &asn1_ctx, tree, hf_ranap_SRNS_DataForwardCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ForwardSRNS_Context_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_ForwardSRNS_Context(tvb, offset, &asn1_ctx, tree, hf_ranap_ForwardSRNS_Context_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_AssignmentRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_AssignmentRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_AssignmentRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyItemFirst_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyItemFirst(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyItemFirst_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransportLayerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_TransportLayerInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_TransportLayerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifyItemSecond_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifyItemSecond(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifyItemSecond_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_AssignmentResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_AssignmentResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_AssignmentResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifiedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifiedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifiedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupOrModifiedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupOrModifiedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupOrModifiedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleasedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleasedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleasedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleasedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_QueuedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_QueuedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_QueuedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_QueuedItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_QueuedItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_QueuedItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ReleaseFailedList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ReleaseFailedList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ReleaseFailedList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item(tvb, offset, &asn1_ctx, tree, hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_ranap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_RelocationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RANAP_RelocationInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_RelocationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransferInformationList_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DirectTransferInformationList_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectTransferInformationItem_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DirectTransferInformationItem_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextList_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ContextList_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ContextItem_RANAP_RelocInf_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ContextItem_RANAP_RelocInf(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_EnhancedRelocationInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RANAP_EnhancedRelocationInformationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhRelocInfoReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhRelocInfoReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhRelocInfoReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhRelocInfoReq(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_EnhancedRelocationInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RANAP_EnhancedRelocationInformationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupList_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupList_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_SetupItem_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_SetupItem_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedList_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_FailedList_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_FailedItem_EnhRelocInfoRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_FailedItem_EnhRelocInfoRes(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ModifyRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ModifyList(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAB_ModifyItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RAB_ModifyItem(tvb, offset, &asn1_ctx, tree, hf_ranap_RAB_ModifyItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationRelatedDataRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationRelatedDataResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LocationRelatedDataFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LocationRelatedDataFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_LocationRelatedDataFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationTransferIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferConfirmation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationTransferConfirmation(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferConfirmation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationTransferFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_InformationTransferFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_InformationTransferFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UESpecificInformationIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UESpecificInformationIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_UESpecificInformationIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DirectInformationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_DirectInformationTransfer(tvb, offset, &asn1_ctx, tree, hf_ranap_DirectInformationTransfer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UplinkInformationExchangeFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UplinkInformationExchangeFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_UplinkInformationExchangeFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStart_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionStart(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStart_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSynchronisationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSynchronisationInformation(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSynchronisationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionStartResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStartResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStartFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionStartFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStartFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionUpdate(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionUpdateResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdateResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionUpdateFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionUpdateFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionUpdateFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStop_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionStop(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStop_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSSessionStopResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSSessionStopResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSSessionStopResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSUELinkingRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSUELinkingRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSUELinkingRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LeftMBMSBearerService_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_LeftMBMSBearerService_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_LeftMBMSBearerService_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSUELinkingResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSUELinkingResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSUELinkingResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UnsuccessfulLinking_IEs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UnsuccessfulLinking_IEs(tvb, offset, &asn1_ctx, tree, hf_ranap_UnsuccessfulLinking_IEs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRegistrationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRegistrationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRegistrationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRegistrationFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRegistrationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_RegistrationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSCNDe_RegistrationRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_RegistrationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSCNDe_RegistrationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSCNDe_RegistrationResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSCNDe_RegistrationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABEstablishmentIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRABEstablishmentIndication(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABEstablishmentIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABReleaseRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRABReleaseRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABReleaseRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABRelease_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRABRelease(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABRelease_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MBMSRABReleaseFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_MBMSRABReleaseFailure(tvb, offset, &asn1_ctx, tree, hf_ranap_MBMSRABReleaseFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_CSKeysRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRVCC_CSKeysRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_CSKeysRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRVCC_CSKeysResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_SRVCC_CSKeysResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_SRVCC_CSKeysResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UeRadioCapabilityMatchRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UeRadioCapabilityMatchRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_UeRadioCapabilityMatchRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UeRadioCapabilityMatchResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UeRadioCapabilityMatchResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_UeRadioCapabilityMatchResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UeRegistrationQueryRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UeRegistrationQueryRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_UeRegistrationQueryRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UeRegistrationQueryResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_UeRegistrationQueryResponse(tvb, offset, &asn1_ctx, tree, hf_ranap_UeRegistrationQueryResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RerouteNASRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RerouteNASRequest(tvb, offset, &asn1_ctx, tree, hf_ranap_RerouteNASRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RANAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_ranap_RANAP_PDU(tvb, offset, &asn1_ctx, tree, hf_ranap_RANAP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int
dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

  int ret = 0;
  int key;

  /* Special handling, same ID used for different IE's depending on signal */
  switch(ProcedureCode){
    case id_RelocationPreparation:
      if((ProtocolIE_ID == id_Source_ToTarget_TransparentContainer)||(ProtocolIE_ID == id_Target_ToSource_TransparentContainer)){
        key = SPECIAL | ProtocolIE_ID;
        ret = (dissector_try_uint_with_data(ranap_ies_dissector_table, key, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
        break;
      }
      /* Fall through */
    default:
      /* no special handling */
      ret = (dissector_try_uint_with_data(ranap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
      if (ret == 0) {
        key = pdu_type | ProtocolIE_ID;
        ret = (dissector_try_uint_with_data(ranap_ies_dissector_table, key, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
      }
      break;
  }
  return ret;
}

static int
dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_with_data(ranap_ies_p1_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_with_data(ranap_ies_p2_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_with_data(ranap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  bool ret;

  pdu_type = IMSG;
  ret = dissector_try_uint_with_data(ranap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL);
  pdu_type = 0;
  return ret ? tvb_captured_length(tvb) : 0;
}

static int
dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  bool ret;

  pdu_type = SOUT;
  ret = dissector_try_uint_with_data(ranap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL);
  pdu_type = 0;
  return ret ? tvb_captured_length(tvb) : 0;
}

static int
dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_with_data(ranap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_with_data(ranap_proc_out_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  proto_item *ranap_item = NULL;
  proto_tree *ranap_tree = NULL;
  sccp_msg_info_t *sccp_msg_lcl = (sccp_msg_info_t *)data;

  pdu_type = 0;
  ProtocolIE_ID = 0;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

  /* create the ranap protocol tree */
  ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, ENC_NA);
  ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

  /* Save the sccp_msg_info_t data (if present) because it can't be passed
     through function calls */
  p_add_proto_data(pinfo->pool, pinfo, proto_ranap, pinfo->curr_layer_num, data);

  /* Clearing any old 'private data' stored */
  ranap_reset_private_data(pinfo);

  dissect_RANAP_PDU_PDU(tvb, pinfo, ranap_tree, NULL);
  if (sccp_msg_lcl) {

    if (sccp_msg_lcl->data.co.assoc)
      sccp_msg_lcl->data.co.assoc->payload = SCCP_PLOAD_RANAP;

    if (! sccp_msg_lcl->data.co.label && ProcedureCode != 0xFFFFFFFF) {
      const char* str = val_to_str_const(ProcedureCode, ranap_ProcedureCode_vals, "Unknown RANAP");
      sccp_msg_lcl->data.co.label = wmem_strdup(wmem_file_scope(), str);
    }
  }

  return tvb_reported_length(tvb);
}

#define RANAP_MSG_MIN_LENGTH 7
static bool
dissect_sccp_ranap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  uint8_t temp;
  uint16_t word;
  unsigned length;
  int offset;

  /* Is it a ranap packet?
   *
   * 4th octet should be the length of the rest of the message.
   * 3th octed is the Criticality field
   * 2nd octet is the message-type e Z[0, 28]
   * 1st octet is the PDU type (with the extension bit)
   * (obviously there must be at least four octets)
   *
   * If all of them hold true we'll assume it's RANAP
   */

  #define LENGTH_OFFSET 3
  #define CRIT_OFFSET 2
  #define MSG_TYPE_OFFSET 1
  #define PDU_TYPE_OFFSET 0
  if (tvb_captured_length(tvb) < RANAP_MSG_MIN_LENGTH) { return false; }

  temp = tvb_get_uint8(tvb, PDU_TYPE_OFFSET);
  if (temp & 0x1F) {
    /* PDU Type byte is not 0x00 (initiatingMessage), 0x20 (succesfulOutcome),
       0x40 (unsuccesfulOutcome) or 0x60 (outcome), ignore extension bit (0x80) */
    return false;
  }

  temp = tvb_get_uint8(tvb, CRIT_OFFSET);
  if (temp == 0xC0 || temp & 0x3F) {
    /* Criticality byte is not 0x00 (reject), 0x40 (ignore) or 0x80 (notify) */
    return false;
  }

  /* compute aligned PER length determinant without calling dissect_per_length_determinant()
     to avoid exceptions and info added to tree, info column and expert info */
  offset = LENGTH_OFFSET;
  length = tvb_get_uint8(tvb, offset);
  offset += 1;
  if ((length & 0x80) == 0x80) {
    if ((length & 0xc0) == 0x80) {
      length &= 0x3f;
      length <<= 8;
      length += tvb_get_uint8(tvb, offset);
      offset += 1;
    } else {
      length = 0;
    }
  }
  if (length!= (tvb_reported_length(tvb) - offset)){
    return false;
  }

  temp = tvb_get_uint8(tvb, MSG_TYPE_OFFSET);
  if (temp > RANAP_MAX_PC) { return false; }

  /* Try to strengthen the heuristic further, by checking the byte following the length and the bitfield indicating extensions etc
   * which usually is a sequence-of length
   */
  word = tvb_get_ntohs(tvb, offset + 1);
  if (word > 0x1ff){
    return false;
  }
  dissect_ranap(tvb, pinfo, tree, data);

  return true;
}

/*--- proto_register_ranap -------------------------------------------*/
void proto_register_ranap(void) {
  module_t *ranap_module;

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_ranap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "ranap.transportLayerAddress_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "ranap.transportLayerAddress_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_nsap,
      { "transportLayerAddress NSAP", "ranap.transportLayerAddress_NSAP",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},


    { &hf_ranap_AccuracyFulfilmentIndicator_PDU,
      { "AccuracyFulfilmentIndicator", "ranap.AccuracyFulfilmentIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_AccuracyFulfilmentIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Additional_CSPS_coordination_information_PDU,
      { "Additional-CSPS-coordination-information", "ranap.Additional_CSPS_coordination_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Additional_PositioningDataSet_PDU,
      { "Additional-PositioningDataSet", "ranap.Additional_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameters_PDU,
      { "Alt-RAB-Parameters", "ranap.Alt_RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU,
      { "Alt-RAB-Parameter-ExtendedGuaranteedBitrateInf", "ranap.Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU,
      { "Alt-RAB-Parameter-SupportedGuaranteedBitrateInf", "ranap.Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU,
      { "Alt-RAB-Parameter-ExtendedMaxBitrateInf", "ranap.Alt_RAB_Parameter_ExtendedMaxBitrateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU,
      { "Alt-RAB-Parameter-SupportedMaxBitrateInf", "ranap.Alt_RAB_Parameter_SupportedMaxBitrateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AlternativeRABConfigurationRequest_PDU,
      { "AlternativeRABConfigurationRequest", "ranap.AlternativeRABConfigurationRequest",
        FT_UINT32, BASE_DEC, VALS(ranap_AlternativeRABConfigurationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UE_Application_Layer_Measurement_Configuration_PDU,
      { "UE-Application-Layer-Measurement-Configuration", "ranap.UE_Application_Layer_Measurement_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation_PDU,
      { "UE-Application-Layer-Measurement-Configuration-For-Relocation", "ranap.UE_Application_Layer_Measurement_Configuration_For_Relocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_APN_PDU,
      { "APN", "ranap.APN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AreaIdentity_PDU,
      { "AreaIdentity", "ranap.AreaIdentity",
        FT_UINT32, BASE_DEC, VALS(ranap_AreaIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameters_PDU,
      { "Ass-RAB-Parameters", "ranap.Ass_RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "Ass-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Ass_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "Ass-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Ass_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_BarometricPressure_PDU,
      { "BarometricPressure", "ranap.BarometricPressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_BroadcastAssistanceDataDecipheringKeys_PDU,
      { "BroadcastAssistanceDataDecipheringKeys", "ranap.BroadcastAssistanceDataDecipheringKeys_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_Cause_PDU,
      { "Cause", "ranap.Cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Cell_Access_Mode_PDU,
      { "Cell-Access-Mode", "ranap.Cell_Access_Mode",
        FT_UINT32, BASE_DEC, VALS(ranap_Cell_Access_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CellLoadInformationGroup_PDU,
      { "CellLoadInformationGroup", "ranap.CellLoadInformationGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CivicAddress_PDU,
      { "CivicAddress", "ranap.CivicAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ClientType_PDU,
      { "ClientType", "ranap.ClientType",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "ranap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MessageStructure_PDU,
      { "MessageStructure", "ranap.MessageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ChosenEncryptionAlgorithm_PDU,
      { "ChosenEncryptionAlgorithm", "ranap.ChosenEncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ChosenIntegrityProtectionAlgorithm_PDU,
      { "ChosenIntegrityProtectionAlgorithm", "ranap.ChosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ClassmarkInformation2_PDU,
      { "ClassmarkInformation2", "ranap.ClassmarkInformation2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ClassmarkInformation3_PDU,
      { "ClassmarkInformation3", "ranap.ClassmarkInformation3",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_DomainIndicator_PDU,
      { "CN-DomainIndicator", "ranap.CN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Correlation_ID_PDU,
      { "Correlation-ID", "ranap.Correlation_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSFB_Information_PDU,
      { "CSFB-Information", "ranap.CSFB_Information",
        FT_UINT32, BASE_DEC, VALS(ranap_CSFB_Information_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_PDU,
      { "CSG-Id", "ranap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_List_PDU,
      { "CSG-Id-List", "ranap.CSG_Id_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Membership_Status_PDU,
      { "CSG-Membership-Status", "ranap.CSG_Membership_Status",
        FT_UINT32, BASE_DEC, VALS(ranap_CSG_Membership_Status_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_DCN_ID_PDU,
      { "DCN-ID", "ranap.DCN_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DeltaRAListofIdleModeUEs_PDU,
      { "DeltaRAListofIdleModeUEs", "ranap.DeltaRAListofIdleModeUEs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DRX_CycleLengthCoefficient_PDU,
      { "DRX-CycleLengthCoefficient", "ranap.DRX_CycleLengthCoefficient",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EARFCN_Extended_PDU,
      { "EARFCN-Extended", "ranap.EARFCN_Extended",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_E_DCH_MAC_d_Flow_ID_PDU,
      { "E-DCH-MAC-d-Flow-ID", "ranap.E_DCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EncryptionInformation_PDU,
      { "EncryptionInformation", "ranap.EncryptionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EncryptionKey_PDU,
      { "EncryptionKey", "ranap.EncryptionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_End_Of_CSFB_PDU,
      { "End-Of-CSFB", "ranap.End_Of_CSFB",
        FT_UINT32, BASE_DEC, VALS(ranap_End_Of_CSFB_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_E_UTRAN_Service_Handover_PDU,
      { "E-UTRAN-Service-Handover", "ranap.E_UTRAN_Service_Handover",
        FT_UINT32, BASE_DEC, VALS(ranap_E_UTRAN_Service_Handover_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ExtendedRNC_ID_PDU,
      { "ExtendedRNC-ID", "ranap.ExtendedRNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_FrequenceLayerConvergenceFlag_PDU,
      { "FrequenceLayerConvergenceFlag", "ranap.FrequenceLayerConvergenceFlag",
        FT_UINT32, BASE_DEC, VALS(ranap_FrequenceLayerConvergenceFlag_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_GANSS_PositioningDataSet_PDU,
      { "GANSS-PositioningDataSet", "ranap.GANSS_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_BSC_Container_PDU,
      { "GERAN-BSC-Container", "ranap.GERAN_BSC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Classmark_PDU,
      { "GERAN-Classmark", "ranap.GERAN_Classmark",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GlobalCN_ID_PDU,
      { "GlobalCN-ID", "ranap.GlobalCN_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GlobalRNC_ID_PDU,
      { "GlobalRNC-ID", "ranap.GlobalRNC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_HigherBitratesThan16MbpsFlag_PDU,
      { "HigherBitratesThan16MbpsFlag", "ranap.HigherBitratesThan16MbpsFlag",
        FT_UINT32, BASE_DEC, VALS(ranap_HigherBitratesThan16MbpsFlag_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_HS_DSCH_MAC_d_Flow_ID_PDU,
      { "HS-DSCH-MAC-d-Flow-ID", "ranap.HS_DSCH_MAC_d_Flow_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IMSI_PDU,
      { "IMSI", "ranap.IMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IncludeVelocity_PDU,
      { "IncludeVelocity", "ranap.IncludeVelocity",
        FT_UINT32, BASE_DEC, VALS(ranap_IncludeVelocity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationExchangeID_PDU,
      { "InformationExchangeID", "ranap.InformationExchangeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationExchangeType_PDU,
      { "InformationExchangeType", "ranap.InformationExchangeType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationExchangeType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationRequested_PDU,
      { "InformationRequested", "ranap.InformationRequested",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequested_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationRequestType_PDU,
      { "InformationRequestType", "ranap.InformationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationRequestType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferID_PDU,
      { "InformationTransferID", "ranap.InformationTransferID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferType_PDU,
      { "InformationTransferType", "ranap.InformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InformationTransferType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_IntegrityProtectionInformation_PDU,
      { "IntegrityProtectionInformation", "ranap.IntegrityProtectionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IntegrityProtectionKey_PDU,
      { "IntegrityProtectionKey", "ranap.IntegrityProtectionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InterSystemInformationTransferType_PDU,
      { "InterSystemInformationTransferType", "ranap.InterSystemInformationTransferType",
        FT_UINT32, BASE_DEC, VALS(ranap_InterSystemInformationTransferType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_InterSystemInformation_TransparentContainer_PDU,
      { "InterSystemInformation-TransparentContainer", "ranap.InterSystemInformation_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IPMulticastAddress_PDU,
      { "IPMulticastAddress", "ranap.IPMulticastAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IuSignallingConnectionIdentifier_PDU,
      { "IuSignallingConnectionIdentifier", "ranap.IuSignallingConnectionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IuTransportAssociation_PDU,
      { "IuTransportAssociation", "ranap.IuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_KeyStatus_PDU,
      { "KeyStatus", "ranap.KeyStatus",
        FT_UINT32, BASE_DEC, VALS(ranap_KeyStatus_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_LAI_PDU,
      { "LAI", "ranap.LAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LastKnownServiceArea_PDU,
      { "LastKnownServiceArea", "ranap.LastKnownServiceArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_LastVisitedUTRANCell_Item_PDU,
      { "LastVisitedUTRANCell-Item", "ranap.LastVisitedUTRANCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LHN_ID_PDU,
      { "LHN-ID", "ranap.LHN_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequestType_PDU,
      { "LocationRelatedDataRequestType", "ranap.LocationRelatedDataRequestType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU,
      { "LocationRelatedDataRequestTypeSpecificToGERANIuMode", "ranap.LocationRelatedDataRequestTypeSpecificToGERANIuMode",
        FT_UINT32, BASE_DEC, VALS(ranap_LocationRelatedDataRequestTypeSpecificToGERANIuMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_L3_Information_PDU,
      { "L3-Information", "ranap.L3_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_M4Report_PDU,
      { "M4Report", "ranap.M4Report",
        FT_UINT32, BASE_DEC, VALS(ranap_M4Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_M5Report_PDU,
      { "M5Report", "ranap.M5Report",
        FT_UINT32, BASE_DEC, VALS(ranap_M5Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_M6Report_PDU,
      { "M6Report", "ranap.M6Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_M7Report_PDU,
      { "M7Report", "ranap.M7Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Management_Based_MDT_Allowed_PDU,
      { "Management-Based-MDT-Allowed", "ranap.Management_Based_MDT_Allowed",
        FT_UINT32, BASE_DEC, VALS(ranap_Management_Based_MDT_Allowed_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSBearerServiceType_PDU,
      { "MBMSBearerServiceType", "ranap.MBMSBearerServiceType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSBearerServiceType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_Registration_PDU,
      { "MBMSCNDe-Registration", "ranap.MBMSCNDe_Registration",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSCNDe_Registration_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCountingInformation_PDU,
      { "MBMSCountingInformation", "ranap.MBMSCountingInformation",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSCountingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSLinkingInformation_PDU,
      { "MBMSLinkingInformation", "ranap.MBMSLinkingInformation",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSLinkingInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationRequestType_PDU,
      { "MBMSRegistrationRequestType", "ranap.MBMSRegistrationRequestType",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSRegistrationRequestType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSServiceArea_PDU,
      { "MBMSServiceArea", "ranap.MBMSServiceArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionDuration_PDU,
      { "MBMSSessionDuration", "ranap.MBMSSessionDuration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionIdentity_PDU,
      { "MBMSSessionIdentity", "ranap.MBMSSessionIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionRepetitionNumber_PDU,
      { "MBMSSessionRepetitionNumber", "ranap.MBMSSessionRepetitionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MDT_Configuration_PDU,
      { "MDT-Configuration", "ranap.MDT_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MDT_PLMN_List_PDU,
      { "MDT-PLMN-List", "ranap.MDT_PLMN_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MSISDN_PDU,
      { "MSISDN", "ranap.MSISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NAS_PDU_PDU,
      { "NAS-PDU", "ranap.NAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NAS_SequenceNumber_PDU,
      { "NAS-SequenceNumber", "ranap.NAS_SequenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NewBSS_To_OldBSS_Information_PDU,
      { "NewBSS-To-OldBSS-Information", "ranap.NewBSS_To_OldBSS_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NonSearchingIndication_PDU,
      { "NonSearchingIndication", "ranap.NonSearchingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_NonSearchingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_NumberOfSteps_PDU,
      { "NumberOfSteps", "ranap.NumberOfSteps",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Offload_RAB_Parameters_PDU,
      { "Offload-RAB-Parameters", "ranap.Offload_RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_OldBSS_ToNewBSS_Information_PDU,
      { "OldBSS-ToNewBSS-Information", "ranap.OldBSS_ToNewBSS_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_OMC_ID_PDU,
      { "OMC-ID", "ranap.OMC_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Out_Of_UTRAN_PDU,
      { "Out-Of-UTRAN", "ranap.Out_Of_UTRAN",
        FT_UINT32, BASE_DEC, VALS(ranap_Out_Of_UTRAN_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PagingAreaID_PDU,
      { "PagingAreaID", "ranap.PagingAreaID",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingAreaID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PagingCause_PDU,
      { "PagingCause", "ranap.PagingCause",
        FT_UINT32, BASE_DEC, VALS(ranap_PagingCause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_PDU,
      { "PDP-TypeInformation", "ranap.PDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_extension_PDU,
      { "PDP-TypeInformation-extension", "ranap.PDP_TypeInformation_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PeriodicLocationInfo_PDU,
      { "PeriodicLocationInfo", "ranap.PeriodicLocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PermanentNAS_UE_ID_PDU,
      { "PermanentNAS-UE-ID", "ranap.PermanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PLMNidentity_PDU,
      { "PLMNidentity", "ranap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositioningPriority_PDU,
      { "PositioningPriority", "ranap.PositioningPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PositionData_PDU,
      { "PositionData", "ranap.PositionData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositionDataSpecificToGERANIuMode_PDU,
      { "PositionDataSpecificToGERANIuMode", "ranap.PositionDataSpecificToGERANIuMode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Priority_Class_Indicator_PDU,
      { "Priority-Class-Indicator", "ranap.Priority_Class_Indicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProvidedData_PDU,
      { "ProvidedData", "ranap.ProvidedData",
        FT_UINT32, BASE_DEC, VALS(ranap_ProvidedData_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PowerSavingIndicator_PDU,
      { "PowerSavingIndicator", "ranap.PowerSavingIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_PowerSavingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_P_TMSI_PDU,
      { "P-TMSI", "ranap.P_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ID_PDU,
      { "RAB-ID", "ranap.RAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "RAB-Parameter-ExtendedMaxBitrateList", "ranap.RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameters_PDU,
      { "RAB-Parameters", "ranap.RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABParametersList_PDU,
      { "RABParametersList", "ranap.RABParametersList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAC_PDU,
      { "RAC", "ranap.RAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAListofIdleModeUEs_PDU,
      { "RAListofIdleModeUEs", "ranap.RAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_RAListofIdleModeUEs_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_LAListofIdleModeUEs_PDU,
      { "LAListofIdleModeUEs", "ranap.LAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAT_Type_PDU,
      { "RAT-Type", "ranap.RAT_Type",
        FT_UINT32, BASE_DEC, VALS(ranap_RAT_Type_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectAttemptFlag_PDU,
      { "RedirectAttemptFlag", "ranap.RedirectAttemptFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectionCompleted_PDU,
      { "RedirectionCompleted", "ranap.RedirectionCompleted",
        FT_UINT32, BASE_DEC, VALS(ranap_RedirectionCompleted_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RejectCauseValue_PDU,
      { "RejectCauseValue", "ranap.RejectCauseValue",
        FT_UINT32, BASE_DEC, VALS(ranap_RejectCauseValue_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationType_PDU,
      { "RelocationType", "ranap.RelocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedGANSSAssistanceData_PDU,
      { "RequestedGANSSAssistanceData", "ranap.RequestedGANSSAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU,
      { "Requested-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Requested_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU,
      { "Requested-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Requested_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestType_PDU,
      { "RequestType", "ranap.RequestType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResponseTime_PDU,
      { "ResponseTime", "ranap.ResponseTime",
        FT_UINT32, BASE_DEC, VALS(ranap_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RNSAPRelocationParameters_PDU,
      { "RNSAPRelocationParameters", "ranap.RNSAPRelocationParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RRC_Container_PDU,
      { "RRC-Container", "ranap.RRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RSRVCC_HO_Indication_PDU,
      { "RSRVCC-HO-Indication", "ranap.RSRVCC_HO_Indication",
        FT_UINT32, BASE_DEC, VALS(ranap_RSRVCC_HO_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RSRVCC_Information_PDU,
      { "RSRVCC-Information", "ranap.RSRVCC_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RSRVCC_Operation_Possible_PDU,
      { "RSRVCC-Operation-Possible", "ranap.RSRVCC_Operation_Possible",
        FT_UINT32, BASE_DEC, VALS(ranap_RSRVCC_Operation_Possible_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SAI_PDU,
      { "SAI", "ranap.SAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SAPI_PDU,
      { "SAPI", "ranap.SAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SessionUpdateID_PDU,
      { "SessionUpdateID", "ranap.SessionUpdateID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Session_Re_establishment_Indicator_PDU,
      { "Session-Re-establishment-Indicator", "ranap.Session_Re_establishment_Indicator",
        FT_UINT32, BASE_DEC, VALS(ranap_Session_Re_establishment_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SignallingIndication_PDU,
      { "SignallingIndication", "ranap.SignallingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_SignallingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SGSN_Group_Identity_PDU,
      { "SGSN-Group-Identity", "ranap.SGSN_Group_Identity",
        FT_UINT32, BASE_DEC, VALS(ranap_SGSN_Group_Identity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SNA_Access_Information_PDU,
      { "SNA-Access-Information", "ranap.SNA_Access_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_Source_ToTarget_TransparentContainer_PDU,
      { "Source-ToTarget-TransparentContainer", "ranap.Source_ToTarget_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_SourceCellID_PDU,
      { "SourceCellID", "ranap.SourceCellID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceCellID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SourceBSS_ToTargetBSS_TransparentContainer_PDU,
      { "SourceBSS-ToTargetBSS-TransparentContainer", "ranap.SourceBSS_ToTargetBSS_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SourceID_PDU,
      { "SourceID", "ranap.SourceID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU,
      { "SourceRNC-ToTargetRNC-TransparentContainer", "ranap.SourceRNC_ToTargetRNC_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_IRAT_Measurement_Configuration_PDU,
      { "IRAT-Measurement-Configuration", "ranap.IRAT_Measurement_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RSRQ_Type_PDU,
      { "RSRQ-Type", "ranap.RSRQ_Type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RSRQ_Extension_PDU,
      { "RSRQ-Extension", "ranap.RSRQ_Extension",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SubscriberProfileIDforRFP_PDU,
      { "SubscriberProfileIDforRFP", "ranap.SubscriberProfileIDforRFP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SupportedRAB_ParameterBitrateList_PDU,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRB_TrCH_Mapping_PDU,
      { "SRB-TrCH-Mapping", "ranap.SRB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_HO_Indication_PDU,
      { "SRVCC-HO-Indication", "ranap.SRVCC_HO_Indication",
        FT_UINT32, BASE_DEC, VALS(ranap_SRVCC_HO_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_Information_PDU,
      { "SRVCC-Information", "ranap.SRVCC_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_Operation_Possible_PDU,
      { "SRVCC-Operation-Possible", "ranap.SRVCC_Operation_Possible",
        FT_UINT32, BASE_DEC, VALS(ranap_SRVCC_Operation_Possible_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Target_ToSource_TransparentContainer_PDU,
      { "Target-ToSource-TransparentContainer", "ranap.Target_ToSource_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TargetBSS_ToSourceBSS_TransparentContainer_PDU,
      { "TargetBSS-ToSourceBSS-TransparentContainer", "ranap.TargetBSS_ToSourceBSS_TransparentContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TargetID_PDU,
      { "TargetID", "ranap.TargetID",
        FT_UINT32, BASE_DEC, VALS(ranap_TargetID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_TargetRNC_ID_PDU,
      { "TargetRNC-ID", "ranap.TargetRNC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU,
      { "TargetRNC-ToSourceRNC-TransparentContainer", "ranap.TargetRNC_ToSourceRNC_TransparentContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TemporaryUE_ID_PDU,
      { "TemporaryUE-ID", "ranap.TemporaryUE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_TemporaryUE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Time_UE_StayedInCell_EnhancedGranularity_PDU,
      { "Time-UE-StayedInCell-EnhancedGranularity", "ranap.Time_UE_StayedInCell_EnhancedGranularity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TimeToMBMSDataTransfer_PDU,
      { "TimeToMBMSDataTransfer", "ranap.TimeToMBMSDataTransfer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TimingDifferenceULDL_PDU,
      { "TimingDifferenceULDL", "ranap.TimingDifferenceULDL",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TMGI_PDU,
      { "TMGI", "ranap.TMGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TracePropagationParameters_PDU,
      { "TracePropagationParameters", "ranap.TracePropagationParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceRecordingSessionInformation_PDU,
      { "TraceRecordingSessionInformation", "ranap.TraceRecordingSessionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceRecordingSessionReference_PDU,
      { "TraceRecordingSessionReference", "ranap.TraceRecordingSessionReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceReference_PDU,
      { "TraceReference", "ranap.TraceReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TraceType_PDU,
      { "TraceType", "ranap.TraceType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TransportLayerAddress_PDU,
      { "TransportLayerAddress", "ranap.TransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TriggerID_PDU,
      { "TriggerID", "ranap.TriggerID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TunnelInformation_PDU,
      { "TunnelInformation", "ranap.TunnelInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TypeOfError_PDU,
      { "TypeOfError", "ranap.TypeOfError",
        FT_UINT32, BASE_DEC, VALS(ranap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UE_AggregateMaximumBitRate_PDU,
      { "UE-AggregateMaximumBitRate", "ranap.UE_AggregateMaximumBitRate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UE_History_Information_PDU,
      { "UE-History-Information", "ranap.UE_History_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UE_ID_PDU,
      { "UE-ID", "ranap.UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UE_Usage_Type_PDU,
      { "UE-Usage-Type", "ranap.UE_Usage_Type",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UERegistrationQueryResult_PDU,
      { "UERegistrationQueryResult", "ranap.UERegistrationQueryResult",
        FT_UINT32, BASE_DEC, VALS(ranap_UERegistrationQueryResult_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_UESBI_Iu_PDU,
      { "UESBI-Iu", "ranap.UESBI_Iu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UTRAN_CellID_PDU,
      { "UTRAN-CellID", "ranap.UTRAN_CellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_VelocityEstimate_PDU,
      { "VelocityEstimate", "ranap.VelocityEstimate",
        FT_UINT32, BASE_DEC, VALS(ranap_VelocityEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_VerticalAccuracyCode_PDU,
      { "VerticalAccuracyCode", "ranap.VerticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_VoiceSupportMatchIndicator_PDU,
      { "VoiceSupportMatchIndicator", "ranap.VoiceSupportMatchIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_VoiceSupportMatchIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseCommand_PDU,
      { "Iu-ReleaseCommand", "ranap.Iu_ReleaseCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseComplete_PDU,
      { "Iu-ReleaseComplete", "ranap.Iu_ReleaseComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportList_PDU,
      { "RAB-DataVolumeReportList", "ranap.RAB_DataVolumeReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportItem_PDU,
      { "RAB-DataVolumeReportItem", "ranap.RAB_DataVolumeReportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedList_IuRelComp_PDU,
      { "RAB-ReleasedList-IuRelComp", "ranap.RAB_ReleasedList_IuRelComp",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedItem_IuRelComp_PDU,
      { "RAB-ReleasedItem-IuRelComp", "ranap.RAB_ReleasedItem_IuRelComp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequired_PDU,
      { "RelocationRequired", "ranap.RelocationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCommand_PDU,
      { "RelocationCommand", "ranap.RelocationCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_RelocationReleaseList_PDU,
      { "RAB-RelocationReleaseList", "ranap.RAB_RelocationReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_RelocationReleaseItem_PDU,
      { "RAB-RelocationReleaseItem", "ranap.RAB_RelocationReleaseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingList_PDU,
      { "RAB-DataForwardingList", "ranap.RAB_DataForwardingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingItem_PDU,
      { "RAB-DataForwardingItem", "ranap.RAB_DataForwardingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationPreparationFailure_PDU,
      { "RelocationPreparationFailure", "ranap.RelocationPreparationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequest_PDU,
      { "RelocationRequest", "ranap.RelocationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_RelocReq_PDU,
      { "RAB-SetupList-RelocReq", "ranap.RAB_SetupList_RelocReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_RelocReq_PDU,
      { "RAB-SetupItem-RelocReq", "ranap.RAB_SetupItem_RelocReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CNMBMSLinkingInformation_PDU,
      { "CNMBMSLinkingInformation", "ranap.CNMBMSLinkingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_JoinedMBMSBearerService_IEs_PDU,
      { "JoinedMBMSBearerService-IEs", "ranap.JoinedMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationRequestAcknowledge_PDU,
      { "RelocationRequestAcknowledge", "ranap.RelocationRequestAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_RelocReqAck_PDU,
      { "RAB-SetupList-RelocReqAck", "ranap.RAB_SetupList_RelocReqAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_RelocReqAck_PDU,
      { "RAB-SetupItem-RelocReqAck", "ranap.RAB_SetupItem_RelocReqAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedList_PDU,
      { "RAB-FailedList", "ranap.RAB_FailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedItem_PDU,
      { "RAB-FailedItem", "ranap.RAB_FailedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationFailure_PDU,
      { "RelocationFailure", "ranap.RelocationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCancel_PDU,
      { "RelocationCancel", "ranap.RelocationCancel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationCancelAcknowledge_PDU,
      { "RelocationCancelAcknowledge", "ranap.RelocationCancelAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_ContextRequest_PDU,
      { "SRNS-ContextRequest", "ranap.SRNS_ContextRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingList_SRNS_CtxReq_PDU,
      { "RAB-DataForwardingList-SRNS-CtxReq", "ranap.RAB_DataForwardingList_SRNS_CtxReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataForwardingItem_SRNS_CtxReq_PDU,
      { "RAB-DataForwardingItem-SRNS-CtxReq", "ranap.RAB_DataForwardingItem_SRNS_CtxReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_ContextResponse_PDU,
      { "SRNS-ContextResponse", "ranap.SRNS_ContextResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextList_PDU,
      { "RAB-ContextList", "ranap.RAB_ContextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextItem_PDU,
      { "RAB-ContextItem", "ranap.RAB_ContextItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextFailedtoTransferList_PDU,
      { "RAB-ContextFailedtoTransferList", "ranap.RAB_ContextFailedtoTransferList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABs_ContextFailedtoTransferItem_PDU,
      { "RABs-ContextFailedtoTransferItem", "ranap.RABs_ContextFailedtoTransferItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeCommand_PDU,
      { "SecurityModeCommand", "ranap.SecurityModeCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeComplete_PDU,
      { "SecurityModeComplete", "ranap.SecurityModeComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SecurityModeReject_PDU,
      { "SecurityModeReject", "ranap.SecurityModeReject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DataVolumeReportRequest_PDU,
      { "DataVolumeReportRequest", "ranap.DataVolumeReportRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportRequestList_PDU,
      { "RAB-DataVolumeReportRequestList", "ranap.RAB_DataVolumeReportRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_DataVolumeReportRequestItem_PDU,
      { "RAB-DataVolumeReportRequestItem", "ranap.RAB_DataVolumeReportRequestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DataVolumeReport_PDU,
      { "DataVolumeReport", "ranap.DataVolumeReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedtoReportList_PDU,
      { "RAB-FailedtoReportList", "ranap.RAB_FailedtoReportList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABs_failed_to_reportItem_PDU,
      { "RABs-failed-to-reportItem", "ranap.RABs_failed_to_reportItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Reset_PDU,
      { "Reset", "ranap.Reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetAcknowledge_PDU,
      { "ResetAcknowledge", "ranap.ResetAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResource_PDU,
      { "ResetResource", "ranap.ResetResource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceList_PDU,
      { "ResetResourceList", "ranap.ResetResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceItem_PDU,
      { "ResetResourceItem", "ranap.ResetResourceItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAcknowledge_PDU,
      { "ResetResourceAcknowledge", "ranap.ResetResourceAcknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAckList_PDU,
      { "ResetResourceAckList", "ranap.ResetResourceAckList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ResetResourceAckItem_PDU,
      { "ResetResourceAckItem", "ranap.ResetResourceAckItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseRequest_PDU,
      { "RAB-ReleaseRequest", "ranap.RAB_ReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseList_PDU,
      { "RAB-ReleaseList", "ranap.RAB_ReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseItem_PDU,
      { "RAB-ReleaseItem", "ranap.RAB_ReleaseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Iu_ReleaseRequest_PDU,
      { "Iu-ReleaseRequest", "ranap.Iu_ReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationDetect_PDU,
      { "RelocationDetect", "ranap.RelocationDetect_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RelocationComplete_PDU,
      { "RelocationComplete", "ranap.RelocationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteRequest_PDU,
      { "EnhancedRelocationCompleteRequest", "ranap.EnhancedRelocationCompleteRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhancedRelocCompleteReq_PDU,
      { "RAB-SetupList-EnhancedRelocCompleteReq", "ranap.RAB_SetupList_EnhancedRelocCompleteReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhancedRelocCompleteReq_PDU,
      { "RAB-SetupItem-EnhancedRelocCompleteReq", "ranap.RAB_SetupItem_EnhancedRelocCompleteReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteResponse_PDU,
      { "EnhancedRelocationCompleteResponse", "ranap.EnhancedRelocationCompleteResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhancedRelocCompleteRes_PDU,
      { "RAB-SetupList-EnhancedRelocCompleteRes", "ranap.RAB_SetupList_EnhancedRelocCompleteRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhancedRelocCompleteRes_PDU,
      { "RAB-SetupItem-EnhancedRelocCompleteRes", "ranap.RAB_SetupItem_EnhancedRelocCompleteRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU,
      { "RAB-ToBeReleasedList-EnhancedRelocCompleteRes", "ranap.RAB_ToBeReleasedList_EnhancedRelocCompleteRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU,
      { "RAB-ToBeReleasedItem-EnhancedRelocCompleteRes", "ranap.RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteFailure_PDU,
      { "EnhancedRelocationCompleteFailure", "ranap.EnhancedRelocationCompleteFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_EnhancedRelocationCompleteConfirm_PDU,
      { "EnhancedRelocationCompleteConfirm", "ranap.EnhancedRelocationCompleteConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Paging_PDU,
      { "Paging", "ranap.Paging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CommonID_PDU,
      { "CommonID", "ranap.CommonID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_InvokeTrace_PDU,
      { "CN-InvokeTrace", "ranap.CN_InvokeTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CN_DeactivateTrace_PDU,
      { "CN-DeactivateTrace", "ranap.CN_DeactivateTrace_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationReportingControl_PDU,
      { "LocationReportingControl", "ranap.LocationReportingControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationReport_PDU,
      { "LocationReport", "ranap.LocationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InitialUE_Message_PDU,
      { "InitialUE-Message", "ranap.InitialUE_Message_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransfer_PDU,
      { "DirectTransfer", "ranap.DirectTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RedirectionIndication_PDU,
      { "RedirectionIndication", "ranap.RedirectionIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Overload_PDU,
      { "Overload", "ranap.Overload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ErrorIndication_PDU,
      { "ErrorIndication", "ranap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRNS_DataForwardCommand_PDU,
      { "SRNS-DataForwardCommand", "ranap.SRNS_DataForwardCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ForwardSRNS_Context_PDU,
      { "ForwardSRNS-Context", "ranap.ForwardSRNS_Context_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_AssignmentRequest_PDU,
      { "RAB-AssignmentRequest", "ranap.RAB_AssignmentRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyList_PDU,
      { "RAB-SetupOrModifyList", "ranap.RAB_SetupOrModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyItemFirst_PDU,
      { "RAB-SetupOrModifyItemFirst", "ranap.RAB_SetupOrModifyItemFirst_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TransportLayerInformation_PDU,
      { "TransportLayerInformation", "ranap.TransportLayerInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifyItemSecond_PDU,
      { "RAB-SetupOrModifyItemSecond", "ranap.RAB_SetupOrModifyItemSecond_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_AssignmentResponse_PDU,
      { "RAB-AssignmentResponse", "ranap.RAB_AssignmentResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifiedList_PDU,
      { "RAB-SetupOrModifiedList", "ranap.RAB_SetupOrModifiedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupOrModifiedItem_PDU,
      { "RAB-SetupOrModifiedItem", "ranap.RAB_SetupOrModifiedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedList_PDU,
      { "RAB-ReleasedList", "ranap.RAB_ReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleasedItem_PDU,
      { "RAB-ReleasedItem", "ranap.RAB_ReleasedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_QueuedList_PDU,
      { "RAB-QueuedList", "ranap.RAB_QueuedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_QueuedItem_PDU,
      { "RAB-QueuedItem", "ranap.RAB_QueuedItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ReleaseFailedList_PDU,
      { "RAB-ReleaseFailedList", "ranap.RAB_ReleaseFailedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU,
      { "GERAN-Iumode-RAB-FailedList-RABAssgntResponse", "ranap.GERAN_Iumode_RAB_FailedList_RABAssgntResponse",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU,
      { "GERAN-Iumode-RAB-Failed-RABAssgntResponse-Item", "ranap.GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PrivateMessage_PDU,
      { "PrivateMessage", "ranap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_RelocationInformation_PDU,
      { "RANAP-RelocationInformation", "ranap.RANAP_RelocationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransferInformationList_RANAP_RelocInf_PDU,
      { "DirectTransferInformationList-RANAP-RelocInf", "ranap.DirectTransferInformationList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectTransferInformationItem_RANAP_RelocInf_PDU,
      { "DirectTransferInformationItem-RANAP-RelocInf", "ranap.DirectTransferInformationItem_RANAP_RelocInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextList_RANAP_RelocInf_PDU,
      { "RAB-ContextList-RANAP-RelocInf", "ranap.RAB_ContextList_RANAP_RelocInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ContextItem_RANAP_RelocInf_PDU,
      { "RAB-ContextItem-RANAP-RelocInf", "ranap.RAB_ContextItem_RANAP_RelocInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_EnhancedRelocationInformationRequest_PDU,
      { "RANAP-EnhancedRelocationInformationRequest", "ranap.RANAP_EnhancedRelocationInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhRelocInfoReq_PDU,
      { "RAB-SetupList-EnhRelocInfoReq", "ranap.RAB_SetupList_EnhRelocInfoReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhRelocInfoReq_PDU,
      { "RAB-SetupItem-EnhRelocInfoReq", "ranap.RAB_SetupItem_EnhRelocInfoReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_EnhancedRelocationInformationResponse_PDU,
      { "RANAP-EnhancedRelocationInformationResponse", "ranap.RANAP_EnhancedRelocationInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupList_EnhRelocInfoRes_PDU,
      { "RAB-SetupList-EnhRelocInfoRes", "ranap.RAB_SetupList_EnhRelocInfoRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_SetupItem_EnhRelocInfoRes_PDU,
      { "RAB-SetupItem-EnhRelocInfoRes", "ranap.RAB_SetupItem_EnhRelocInfoRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedList_EnhRelocInfoRes_PDU,
      { "RAB-FailedList-EnhRelocInfoRes", "ranap.RAB_FailedList_EnhRelocInfoRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_FailedItem_EnhRelocInfoRes_PDU,
      { "RAB-FailedItem-EnhRelocInfoRes", "ranap.RAB_FailedItem_EnhRelocInfoRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyRequest_PDU,
      { "RAB-ModifyRequest", "ranap.RAB_ModifyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyList_PDU,
      { "RAB-ModifyList", "ranap.RAB_ModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_ModifyItem_PDU,
      { "RAB-ModifyItem", "ranap.RAB_ModifyItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataRequest_PDU,
      { "LocationRelatedDataRequest", "ranap.LocationRelatedDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataResponse_PDU,
      { "LocationRelatedDataResponse", "ranap.LocationRelatedDataResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LocationRelatedDataFailure_PDU,
      { "LocationRelatedDataFailure", "ranap.LocationRelatedDataFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferIndication_PDU,
      { "InformationTransferIndication", "ranap.InformationTransferIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferConfirmation_PDU,
      { "InformationTransferConfirmation", "ranap.InformationTransferConfirmation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_InformationTransferFailure_PDU,
      { "InformationTransferFailure", "ranap.InformationTransferFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UESpecificInformationIndication_PDU,
      { "UESpecificInformationIndication", "ranap.UESpecificInformationIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_DirectInformationTransfer_PDU,
      { "DirectInformationTransfer", "ranap.DirectInformationTransfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeRequest_PDU,
      { "UplinkInformationExchangeRequest", "ranap.UplinkInformationExchangeRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeResponse_PDU,
      { "UplinkInformationExchangeResponse", "ranap.UplinkInformationExchangeResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UplinkInformationExchangeFailure_PDU,
      { "UplinkInformationExchangeFailure", "ranap.UplinkInformationExchangeFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStart_PDU,
      { "MBMSSessionStart", "ranap.MBMSSessionStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSynchronisationInformation_PDU,
      { "MBMSSynchronisationInformation", "ranap.MBMSSynchronisationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStartResponse_PDU,
      { "MBMSSessionStartResponse", "ranap.MBMSSessionStartResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStartFailure_PDU,
      { "MBMSSessionStartFailure", "ranap.MBMSSessionStartFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdate_PDU,
      { "MBMSSessionUpdate", "ranap.MBMSSessionUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdateResponse_PDU,
      { "MBMSSessionUpdateResponse", "ranap.MBMSSessionUpdateResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionUpdateFailure_PDU,
      { "MBMSSessionUpdateFailure", "ranap.MBMSSessionUpdateFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStop_PDU,
      { "MBMSSessionStop", "ranap.MBMSSessionStop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSSessionStopResponse_PDU,
      { "MBMSSessionStopResponse", "ranap.MBMSSessionStopResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSUELinkingRequest_PDU,
      { "MBMSUELinkingRequest", "ranap.MBMSUELinkingRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LeftMBMSBearerService_IEs_PDU,
      { "LeftMBMSBearerService-IEs", "ranap.LeftMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSUELinkingResponse_PDU,
      { "MBMSUELinkingResponse", "ranap.MBMSUELinkingResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UnsuccessfulLinking_IEs_PDU,
      { "UnsuccessfulLinking-IEs", "ranap.UnsuccessfulLinking_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationRequest_PDU,
      { "MBMSRegistrationRequest", "ranap.MBMSRegistrationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationResponse_PDU,
      { "MBMSRegistrationResponse", "ranap.MBMSRegistrationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRegistrationFailure_PDU,
      { "MBMSRegistrationFailure", "ranap.MBMSRegistrationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_RegistrationRequest_PDU,
      { "MBMSCNDe-RegistrationRequest", "ranap.MBMSCNDe_RegistrationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSCNDe_RegistrationResponse_PDU,
      { "MBMSCNDe-RegistrationResponse", "ranap.MBMSCNDe_RegistrationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABEstablishmentIndication_PDU,
      { "MBMSRABEstablishmentIndication", "ranap.MBMSRABEstablishmentIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABReleaseRequest_PDU,
      { "MBMSRABReleaseRequest", "ranap.MBMSRABReleaseRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABRelease_PDU,
      { "MBMSRABRelease", "ranap.MBMSRABRelease_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MBMSRABReleaseFailure_PDU,
      { "MBMSRABReleaseFailure", "ranap.MBMSRABReleaseFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_CSKeysRequest_PDU,
      { "SRVCC-CSKeysRequest", "ranap.SRVCC_CSKeysRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SRVCC_CSKeysResponse_PDU,
      { "SRVCC-CSKeysResponse", "ranap.SRVCC_CSKeysResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UeRadioCapabilityMatchRequest_PDU,
      { "UeRadioCapabilityMatchRequest", "ranap.UeRadioCapabilityMatchRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UeRadioCapabilityMatchResponse_PDU,
      { "UeRadioCapabilityMatchResponse", "ranap.UeRadioCapabilityMatchResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UeRegistrationQueryRequest_PDU,
      { "UeRegistrationQueryRequest", "ranap.UeRegistrationQueryRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UeRegistrationQueryResponse_PDU,
      { "UeRegistrationQueryResponse", "ranap.UeRegistrationQueryResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RerouteNASRequest_PDU,
      { "RerouteNASRequest", "ranap.RerouteNASRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RANAP_PDU_PDU,
      { "RANAP-PDU", "ranap.RANAP_PDU",
        FT_UINT32, BASE_DEC, VALS(ranap_RANAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_local,
      { "local", "ranap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_global,
      { "global", "ranap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ranap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "ranap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_id,
      { "id", "ranap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ranap_criticality,
      { "criticality", "ranap.criticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_ie_field_value,
      { "value", "ranap.ie_field_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPair_item,
      { "ProtocolIE-FieldPair", "ranap.ProtocolIE_FieldPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_firstCriticality,
      { "firstCriticality", "ranap.firstCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_firstValue,
      { "firstValue", "ranap.firstValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_secondCriticality,
      { "secondCriticality", "ranap.secondCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_secondValue,
      { "secondValue", "ranap.secondValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolIE_ContainerList_item,
      { "ProtocolIE-Container", "ranap.ProtocolIE_Container",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolIE_ContainerPairList_item,
      { "ProtocolIE-ContainerPair", "ranap.ProtocolIE_ContainerPair",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "ranap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ext_id,
      { "id", "ranap.ext_id",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_ranap_extensionValue,
      { "extensionValue", "ranap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PrivateIE_Container_item,
      { "PrivateIE-Field", "ranap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_private_id,
      { "id", "ranap.private_id",
        FT_UINT32, BASE_DEC, VALS(ranap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_ranap_private_value,
      { "value", "ranap.private_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_private_value", HFILL }},
    { &hf_ranap_old_LAI,
      { "old-LAI", "ranap.old_LAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LAI", HFILL }},
    { &hf_ranap_old_RAC,
      { "old-RAC", "ranap.old_RAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        "RAC", HFILL }},
    { &hf_ranap_nRI,
      { "nRI", "ranap.nRI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_ranap_uE_is_Attaching,
      { "uE-is-Attaching", "ranap.uE_is_Attaching_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iE_Extensions,
      { "iE-Extensions", "ranap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ranap_Additional_PositioningDataSet_item,
      { "Additional-PositioningMethodAndUsage", "ranap.Additional_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_priorityLevel,
      { "priorityLevel", "ranap.priorityLevel",
        FT_UINT32, BASE_DEC, VALS(ranap_PriorityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pre_emptionCapability,
      { "pre-emptionCapability", "ranap.pre_emptionCapability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionCapability_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pre_emptionVulnerability,
      { "pre-emptionVulnerability", "ranap.pre_emptionVulnerability",
        FT_UINT32, BASE_DEC, VALS(ranap_Pre_emptionVulnerability_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_queuingAllowed,
      { "queuingAllowed", "ranap.queuingAllowed",
        FT_UINT32, BASE_DEC, VALS(ranap_QueuingAllowed_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_altMaxBitrateInf,
      { "altMaxBitrateInf", "ranap.altMaxBitrateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt_RAB_Parameter_MaxBitrateInf", HFILL }},
    { &hf_ranap_altGuaranteedBitRateInf,
      { "altGuaranteedBitRateInf", "ranap.altGuaranteedBitRateInf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Alt_RAB_Parameter_GuaranteedBitrateInf", HFILL }},
    { &hf_ranap_altExtendedGuaranteedBitrateType,
      { "altExtendedGuaranteedBitrateType", "ranap.altExtendedGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altExtendedGuaranteedBitrates,
      { "altExtendedGuaranteedBitrates", "ranap.altExtendedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_ExtendedGuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates_item,
      { "Alt-RAB-Parameter-ExtendedGuaranteedBitrateList", "ranap.Alt_RAB_Parameter_ExtendedGuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altGuaranteedBitrateType,
      { "altGuaranteedBitrateType", "ranap.altGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altGuaranteedBitrates,
      { "altGuaranteedBitrates", "ranap.altGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_GuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrates_item,
      { "Alt-RAB-Parameter-GuaranteedBitrateList", "ranap.Alt_RAB_Parameter_GuaranteedBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altSupportedGuaranteedBitrateType,
      { "altSupportedGuaranteedBitrateType", "ranap.altSupportedGuaranteedBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_GuaranteedBitrateType_vals), 0,
        "Alt_RAB_Parameter_GuaranteedBitrateType", HFILL }},
    { &hf_ranap_altSupportedGuaranteedBitrates,
      { "altSupportedGuaranteedBitrates", "ranap.altSupportedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_SupportedGuaranteedBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates_item,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altExtendedMaxBitrateType,
      { "altExtendedMaxBitrateType", "ranap.altExtendedMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altExtendedMaxBitrates,
      { "altExtendedMaxBitrates", "ranap.altExtendedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_ExtendedMaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates_item,
      { "Alt-RAB-Parameter-ExtendedMaxBitrateList", "ranap.Alt_RAB_Parameter_ExtendedMaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altMaxBitrateType,
      { "altMaxBitrateType", "ranap.altMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altMaxBitrates,
      { "altMaxBitrates", "ranap.altMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_MaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrates_item,
      { "Alt-RAB-Parameter-MaxBitrateList", "ranap.Alt_RAB_Parameter_MaxBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_altSupportedMaxBitrateType,
      { "altSupportedMaxBitrateType", "ranap.altSupportedMaxBitrateType",
        FT_UINT32, BASE_DEC, VALS(ranap_Alt_RAB_Parameter_MaxBitrateType_vals), 0,
        "Alt_RAB_Parameter_MaxBitrateType", HFILL }},
    { &hf_ranap_altSupportedMaxBitrates,
      { "altSupportedMaxBitrates", "ranap.altSupportedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alt_RAB_Parameter_SupportedMaxBitrates", HFILL }},
    { &hf_ranap_Alt_RAB_Parameter_SupportedMaxBitrates_item,
      { "SupportedRAB-ParameterBitrateList", "ranap.SupportedRAB_ParameterBitrateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_applicationLayerContainerForMeasurementConfiguration,
      { "applicationLayerContainerForMeasurementConfiguration", "ranap.applicationLayerContainerForMeasurementConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_1000", HFILL }},
    { &hf_ranap_areaScopeForUEApplicationLayerMeasurementConfiguration,
      { "areaScopeForUEApplicationLayerMeasurementConfiguration", "ranap.areaScopeForUEApplicationLayerMeasurementConfiguration",
        FT_UINT32, BASE_DEC, VALS(ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_traceReference,
      { "traceReference", "ranap.traceReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_tracePropagationParameters,
      { "tracePropagationParameters", "ranap.tracePropagationParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceCollectionEntityIPAddress,
      { "traceCollectionEntityIPAddress", "ranap.traceCollectionEntityIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_cellbased,
      { "cellbased", "ranap.cellbased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_labased,
      { "labased", "ranap.labased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rabased,
      { "rabased", "ranap.rabased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_plmn_area_based,
      { "plmn-area-based", "ranap.plmn_area_based_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PLMNBased", HFILL }},
    { &hf_ranap_sAI,
      { "sAI", "ranap.sAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_geographicalArea,
      { "geographicalArea", "ranap.geographicalArea",
        FT_UINT32, BASE_DEC, VALS(ranap_GeographicalArea_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_assMaxBitrateInf,
      { "assMaxBitrateInf", "ranap.assMaxBitrateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass_RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_assGuaranteedBitRateInf,
      { "assGuaranteedBitRateInf", "ranap.assGuaranteedBitRateInf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ass_RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Ass_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_AuthorisedPLMNs_item,
      { "AuthorisedPLMNs item", "ranap.AuthorisedPLMNs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_pLMNidentity,
      { "pLMNidentity", "ranap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_authorisedSNAsList,
      { "authorisedSNAsList", "ranap.authorisedSNAsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorisedSNAs", HFILL }},
    { &hf_ranap_AuthorisedSNAs_item,
      { "SNAC", "ranap.SNAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cipheringKeyFlag,
      { "cipheringKeyFlag", "ranap.cipheringKeyFlag",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_ranap_currentDecipheringKey,
      { "currentDecipheringKey", "ranap.currentDecipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_56", HFILL }},
    { &hf_ranap_nextDecipheringKey,
      { "nextDecipheringKey", "ranap.nextDecipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_56", HFILL }},
    { &hf_ranap_radioNetwork,
      { "radioNetwork", "ranap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_ranap_transmissionNetwork,
      { "transmissionNetwork", "ranap.transmissionNetwork",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseTransmissionNetwork_vals), 0,
        "CauseTransmissionNetwork", HFILL }},
    { &hf_ranap_nAS,
      { "nAS", "ranap.nAS",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseNAS_vals), 0,
        "CauseNAS", HFILL }},
    { &hf_ranap_protocol,
      { "protocol", "ranap.protocol",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_ranap_misc,
      { "misc", "ranap.misc",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_ranap_non_Standard,
      { "non-Standard", "ranap.non_Standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CauseNon_Standard", HFILL }},
    { &hf_ranap_radioNetworkExtension,
      { "radioNetworkExtension", "ranap.radioNetworkExtension",
        FT_UINT32, BASE_DEC, VALS(ranap_CauseRadioNetworkExtension_vals), 0,
        "CauseRadioNetworkExtension", HFILL }},
    { &hf_ranap_cellIdList,
      { "cellIdList", "ranap.cellIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CellIdList_item,
      { "Cell-Id", "ranap.Cell_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cell_Capacity_Class_Value,
      { "cell-Capacity-Class-Value", "ranap.cell_Capacity_Class_Value",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loadValue,
      { "loadValue", "ranap.loadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rTLoadValue,
      { "rTLoadValue", "ranap.rTLoadValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_nRTLoadInformationValue,
      { "nRTLoadInformationValue", "ranap.nRTLoadInformationValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceCellID,
      { "sourceCellID", "ranap.sourceCellID",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceCellID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_uplinkCellLoadInformation,
      { "uplinkCellLoadInformation", "ranap.uplinkCellLoadInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellLoadInformation", HFILL }},
    { &hf_ranap_downlinkCellLoadInformation,
      { "downlinkCellLoadInformation", "ranap.downlinkCellLoadInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellLoadInformation", HFILL }},
    { &hf_ranap_procedureCode,
      { "procedureCode", "ranap.procedureCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProcedureCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_ranap_triggeringMessage,
      { "triggeringMessage", "ranap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(ranap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_procedureCriticality,
      { "procedureCriticality", "ranap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "ranap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_ranap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "ranap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iECriticality,
      { "iECriticality", "ranap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(ranap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_ranap_iE_ID,
      { "iE-ID", "ranap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &ranap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_ranap_repetitionNumber,
      { "repetitionNumber", "ranap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber0", HFILL }},
    { &hf_ranap_MessageStructure_item,
      { "MessageStructure item", "ranap.MessageStructure_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_item_repetitionNumber,
      { "repetitionNumber", "ranap.item_repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RepetitionNumber1", HFILL }},
    { &hf_ranap_lAC,
      { "lAC", "ranap.lAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cI,
      { "cI", "ranap.cI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_CSG_Id_List_item,
      { "CSG-Id", "ranap.CSG_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_newRAListofIdleModeUEs,
      { "newRAListofIdleModeUEs", "ranap.newRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAListwithNoIdleModeUEsAnyMore,
      { "rAListwithNoIdleModeUEsAnyMore", "ranap.rAListwithNoIdleModeUEsAnyMore",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_NewRAListofIdleModeUEs_item,
      { "RAC", "ranap.RAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAListwithNoIdleModeUEsAnyMore_item,
      { "RAC", "ranap.RAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_macroENB_ID,
      { "macroENB-ID", "ranap.macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_ranap_homeENB_ID,
      { "homeENB-ID", "ranap.homeENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_ranap_short_macroENB_ID,
      { "short-macroENB-ID", "ranap.short_macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_ranap_long_macroENB_ID,
      { "long-macroENB-ID", "ranap.long_macroENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_ranap_permittedAlgorithms,
      { "permittedAlgorithms", "ranap.permittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PermittedEncryptionAlgorithms", HFILL }},
    { &hf_ranap_key,
      { "key", "ranap.key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_ranap_iMEIlist,
      { "iMEIlist", "ranap.iMEIlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVlist,
      { "iMEISVlist", "ranap.iMEISVlist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEIgroup,
      { "iMEIgroup", "ranap.iMEIgroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVgroup,
      { "iMEISVgroup", "ranap.iMEISVgroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementQuantity,
      { "measurementQuantity", "ranap.measurementQuantity",
        FT_UINT32, BASE_DEC, VALS(ranap_MeasurementQuantity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_threshold,
      { "threshold", "ranap.threshold",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M120_165", HFILL }},
    { &hf_ranap_threshold_01,
      { "threshold", "ranap.threshold",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M120_M25", HFILL }},
    { &hf_ranap_GANSS_PositioningDataSet_item,
      { "GANSS-PositioningMethodAndUsage", "ranap.GANSS_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_point,
      { "point", "ranap.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_Point", HFILL }},
    { &hf_ranap_pointWithUnCertainty,
      { "pointWithUnCertainty", "ranap.pointWithUnCertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertainty", HFILL }},
    { &hf_ranap_polygon,
      { "polygon", "ranap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA_Polygon", HFILL }},
    { &hf_ranap_pointWithUncertaintyEllipse,
      { "pointWithUncertaintyEllipse", "ranap.pointWithUncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertaintyEllipse", HFILL }},
    { &hf_ranap_pointWithAltitude,
      { "pointWithAltitude", "ranap.pointWithAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitude", HFILL }},
    { &hf_ranap_pointWithAltitudeAndUncertaintyEllipsoid,
      { "pointWithAltitudeAndUncertaintyEllipsoid", "ranap.pointWithAltitudeAndUncertaintyEllipsoid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitudeAndUncertaintyEllipsoid", HFILL }},
    { &hf_ranap_ellipsoidArc,
      { "ellipsoidArc", "ranap.ellipsoidArc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_EllipsoidArc", HFILL }},
    { &hf_ranap_latitudeSign,
      { "latitudeSign", "ranap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ranap_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_latitude,
      { "latitude", "ranap.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ranap_longitude,
      { "longitude", "ranap.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_ranap_directionOfAltitude,
      { "directionOfAltitude", "ranap.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(ranap_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_altitude,
      { "altitude", "ranap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ranap_geographicalCoordinates,
      { "geographicalCoordinates", "ranap.geographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_innerRadius,
      { "innerRadius", "ranap.innerRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_uncertaintyRadius,
      { "uncertaintyRadius", "ranap.uncertaintyRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_offsetAngle,
      { "offsetAngle", "ranap.offsetAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_includedAngle,
      { "includedAngle", "ranap.includedAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_confidence,
      { "confidence", "ranap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_altitudeAndDirection,
      { "altitudeAndDirection", "ranap.altitudeAndDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_AltitudeAndDirection", HFILL }},
    { &hf_ranap_uncertaintyEllipse,
      { "uncertaintyEllipse", "ranap.uncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_UncertaintyEllipse", HFILL }},
    { &hf_ranap_uncertaintyAltitude,
      { "uncertaintyAltitude", "ranap.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_uncertaintyCode,
      { "uncertaintyCode", "ranap.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_GA_Polygon_item,
      { "GA-Polygon item", "ranap.GA_Polygon_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uncertaintySemi_major,
      { "uncertaintySemi-major", "ranap.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "ranap.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "ranap.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ranap_lAI,
      { "lAI", "ranap.lAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAC,
      { "rAC", "ranap.rAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cN_ID,
      { "cN-ID", "ranap.cN_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rNC_ID,
      { "rNC-ID", "ranap.rNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEI,
      { "iMEI", "ranap.iMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEIMask,
      { "iMEIMask", "ranap.iMEIMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_ranap_IMEIList_item,
      { "IMEI", "ranap.IMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISV,
      { "iMEISV", "ranap.iMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iMEISVMask,
      { "iMEISVMask", "ranap.iMEISVMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_ranap_IMEISVList_item,
      { "IMEISV", "ranap.IMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementsToActivate,
      { "measurementsToActivate", "ranap.measurementsToActivate",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_m1report,
      { "m1report", "ranap.m1report",
        FT_UINT32, BASE_DEC, VALS(ranap_M1Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m2report,
      { "m2report", "ranap.m2report",
        FT_UINT32, BASE_DEC, VALS(ranap_M2Report_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMBMSIPMulticastAddressandAPNRequest,
      { "requestedMBMSIPMulticastAddressandAPNRequest", "ranap.requestedMBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMulticastServiceList,
      { "requestedMulticastServiceList", "ranap.requestedMulticastServiceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMSIPMulticastAddressandAPNRequest,
      { "mBMSIPMulticastAddressandAPNRequest", "ranap.mBMSIPMulticastAddressandAPNRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_permanentNAS_UE_ID,
      { "permanentNAS-UE-ID", "ranap.permanentNAS_UE_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_PermanentNAS_UE_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rNCTraceInformation,
      { "rNCTraceInformation", "ranap.rNCTraceInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_permittedAlgorithms_01,
      { "permittedAlgorithms", "ranap.permittedAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PermittedIntegrityProtectionAlgorithms", HFILL }},
    { &hf_ranap_key_01,
      { "key", "ranap.key",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IntegrityProtectionKey", HFILL }},
    { &hf_ranap_rIM_Transfer,
      { "rIM-Transfer", "ranap.rIM_Transfer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gTP_TEI,
      { "gTP-TEI", "ranap.gTP_TEI",
        FT_UINT32, BASE_HEX_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_bindingID,
      { "bindingID", "ranap.bindingID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LA_LIST_item,
      { "LA-LIST item", "ranap.LA_LIST_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_listOF_SNAs,
      { "listOF-SNAs", "ranap.listOF_SNAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ageOfSAI,
      { "ageOfSAI", "ranap.ageOfSAI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ranap_uTRAN_CellID,
      { "uTRAN-CellID", "ranap.uTRAN_CellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cellType,
      { "cellType", "ranap.cellType",
        FT_UINT32, BASE_DEC, VALS(ranap_CellType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_time_UE_StayedInCell,
      { "time-UE-StayedInCell", "ranap.time_UE_StayedInCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ListOF_SNAs_item,
      { "SNAC", "ranap.SNAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ListOfInterfacesToTrace_item,
      { "InterfacesToTraceItem", "ranap.InterfacesToTraceItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_interface,
      { "interface", "ranap.interface",
        FT_UINT32, BASE_DEC, VALS(ranap_T_interface_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedLocationRelatedDataType,
      { "requestedLocationRelatedDataType", "ranap.requestedLocationRelatedDataType",
        FT_UINT32, BASE_DEC, VALS(ranap_RequestedLocationRelatedDataType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_requestedGPSAssistanceData,
      { "requestedGPSAssistanceData", "ranap.requestedGPSAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_reportChangeOfSAI,
      { "reportChangeOfSAI", "ranap.reportChangeOfSAI",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportChangeOfSAI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_periodicReportingIndicator,
      { "periodicReportingIndicator", "ranap.periodicReportingIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_PeriodicReportingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_directReportingIndicator,
      { "directReportingIndicator", "ranap.directReportingIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_DirectReportingIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_verticalAccuracyCode,
      { "verticalAccuracyCode", "ranap.verticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningPriorityChangeSAI,
      { "positioningPriorityChangeSAI", "ranap.positioningPriorityChangeSAI",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        "PositioningPriority", HFILL }},
    { &hf_ranap_positioningPriorityDirect,
      { "positioningPriorityDirect", "ranap.positioningPriorityDirect",
        FT_UINT32, BASE_DEC, VALS(ranap_PositioningPriority_vals), 0,
        "PositioningPriority", HFILL }},
    { &hf_ranap_clientTypePeriodic,
      { "clientTypePeriodic", "ranap.clientTypePeriodic",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        "ClientType", HFILL }},
    { &hf_ranap_clientTypeDirect,
      { "clientTypeDirect", "ranap.clientTypeDirect",
        FT_UINT32, BASE_DEC, VALS(ranap_ClientType_vals), 0,
        "ClientType", HFILL }},
    { &hf_ranap_responseTime,
      { "responseTime", "ranap.responseTime",
        FT_UINT32, BASE_DEC, VALS(ranap_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_includeVelocity,
      { "includeVelocity", "ranap.includeVelocity",
        FT_UINT32, BASE_DEC, VALS(ranap_IncludeVelocity_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_periodicLocationInfo,
      { "periodicLocationInfo", "ranap.periodicLocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_periodic,
      { "periodic", "ranap.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MDT_Report_Parameters", HFILL }},
    { &hf_ranap_event1F,
      { "event1F", "ranap.event1F_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Event1F_Parameters", HFILL }},
    { &hf_ranap_event1I,
      { "event1I", "ranap.event1I_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Event1I_Parameters", HFILL }},
    { &hf_ranap_all,
      { "all", "ranap.all_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_m4_collection_parameters,
      { "m4-collection-parameters", "ranap.m4_collection_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_m4_period,
      { "m4-period", "ranap.m4_period",
        FT_UINT32, BASE_DEC, VALS(ranap_M4_Period_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m4_threshold,
      { "m4-threshold", "ranap.m4_threshold",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_when_available,
      { "when-available", "ranap.when_available_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_m5_period,
      { "m5-period", "ranap.m5_period",
        FT_UINT32, BASE_DEC, VALS(ranap_M5_Period_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m6_period,
      { "m6-period", "ranap.m6_period",
        FT_UINT32, BASE_DEC, VALS(ranap_M6_Period_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m6_links_to_log,
      { "m6-links-to-log", "ranap.m6_links_to_log",
        FT_UINT32, BASE_DEC, VALS(ranap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_ranap_m7_period,
      { "m7-period", "ranap.m7_period",
        FT_UINT32, BASE_DEC, VALS(ranap_M7_Period_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_m7_links_to_log,
      { "m7-links-to-log", "ranap.m7_links_to_log",
        FT_UINT32, BASE_DEC, VALS(ranap_Links_to_log_vals), 0,
        "Links_to_log", HFILL }},
    { &hf_ranap_MBMSIPMulticastAddressandAPNRequest_item,
      { "TMGI", "ranap.TMGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_plmn_area_based_01,
      { "plmn-area-based", "ranap.plmn_area_based_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mdtActivation,
      { "mdtActivation", "ranap.mdtActivation",
        FT_UINT32, BASE_DEC, VALS(ranap_MDT_Activation_vals), 0,
        "MDT_Activation", HFILL }},
    { &hf_ranap_mdtAreaScope,
      { "mdtAreaScope", "ranap.mdtAreaScope",
        FT_UINT32, BASE_DEC, VALS(ranap_MDTAreaScope_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_mdtMode,
      { "mdtMode", "ranap.mdtMode",
        FT_UINT32, BASE_DEC, VALS(ranap_MDTMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_immediateMDT,
      { "immediateMDT", "ranap.immediateMDT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loggedMDT,
      { "loggedMDT", "ranap.loggedMDT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_MDT_PLMN_List_item,
      { "PLMNidentity", "ranap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_reportInterval,
      { "reportInterval", "ranap.reportInterval",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportAmount,
      { "reportAmount", "ranap.reportAmount",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportAmount_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_accessPointName,
      { "accessPointName", "ranap.accessPointName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Offload_RAB_Parameters_APN", HFILL }},
    { &hf_ranap_chargingCharacteristics,
      { "chargingCharacteristics", "ranap.chargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Offload_RAB_Parameters_ChargingCharacteristics", HFILL }},
    { &hf_ranap_rAI,
      { "rAI", "ranap.rAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_item,
      { "PDP-Type", "ranap.PDP_Type",
        FT_UINT32, BASE_DEC, VALS(ranap_PDP_Type_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PDP_TypeInformation_extension_item,
      { "PDP-Type-extension", "ranap.PDP_Type_extension",
        FT_UINT32, BASE_DEC, VALS(ranap_PDP_Type_extension_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportingAmount,
      { "reportingAmount", "ranap.reportingAmount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_ranap_reportingInterval,
      { "reportingInterval", "ranap.reportingInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_ranap_iMSI,
      { "iMSI", "ranap.iMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PermittedEncryptionAlgorithms_item,
      { "EncryptionAlgorithm", "ranap.EncryptionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_PermittedIntegrityProtectionAlgorithms_item,
      { "IntegrityProtectionAlgorithm", "ranap.IntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_laiList,
      { "laiList", "ranap.laiList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LAI_List", HFILL }},
    { &hf_ranap_LAI_List_item,
      { "LAI", "ranap.LAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_loggingInterval,
      { "loggingInterval", "ranap.loggingInterval",
        FT_UINT32, BASE_DEC, VALS(ranap_LoggingInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_loggingDuration,
      { "loggingDuration", "ranap.loggingDuration",
        FT_UINT32, BASE_DEC, VALS(ranap_LoggingDuration_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_plmnList,
      { "plmnList", "ranap.plmnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PLMNList_item,
      { "PLMNidentity", "ranap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PLMNs_in_shared_network_item,
      { "PLMNs-in-shared-network item", "ranap.PLMNs_in_shared_network_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_lA_LIST,
      { "lA-LIST", "ranap.lA_LIST",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_PositioningDataSet_item,
      { "PositioningMethodAndUsage", "ranap.PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningDataDiscriminator,
      { "positioningDataDiscriminator", "ranap.positioningDataDiscriminator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_positioningDataSet,
      { "positioningDataSet", "ranap.positioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_shared_network_information,
      { "shared-network-information", "ranap.shared_network_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_raiList,
      { "raiList", "ranap.raiList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAI_List", HFILL }},
    { &hf_ranap_RAI_List_item,
      { "RAI", "ranap.RAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RABDataVolumeReport_item,
      { "RABDataVolumeReport item", "ranap.RABDataVolumeReport_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnsuccessfullyTransmittedDataVolume", HFILL }},
    { &hf_ranap_dataVolumeReference,
      { "dataVolumeReference", "ranap.dataVolumeReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trafficClass,
      { "trafficClass", "ranap.trafficClass",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficClass_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_AsymmetryIndicator,
      { "rAB-AsymmetryIndicator", "ranap.rAB_AsymmetryIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_RAB_AsymmetryIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_maxBitrate,
      { "maxBitrate", "ranap.maxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_guaranteedBitRate,
      { "guaranteedBitRate", "ranap.guaranteedBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_deliveryOrder,
      { "deliveryOrder", "ranap.deliveryOrder",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOrder_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_maxSDU_Size,
      { "maxSDU-Size", "ranap.maxSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_Parameters,
      { "sDU-Parameters", "ranap.sDU_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transferDelay,
      { "transferDelay", "ranap.transferDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trafficHandlingPriority,
      { "trafficHandlingPriority", "ranap.trafficHandlingPriority",
        FT_UINT32, BASE_DEC, VALS(ranap_TrafficHandlingPriority_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_allocationOrRetentionPriority,
      { "allocationOrRetentionPriority", "ranap.allocationOrRetentionPriority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceStatisticsDescriptor,
      { "sourceStatisticsDescriptor", "ranap.sourceStatisticsDescriptor",
        FT_UINT32, BASE_DEC, VALS(ranap_SourceStatisticsDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_relocationRequirement,
      { "relocationRequirement", "ranap.relocationRequirement",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationRequirement_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_RABParametersList_item,
      { "RABParametersList item", "ranap.RABParametersList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rab_Id,
      { "rab-Id", "ranap.rab_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cn_domain,
      { "cn-domain", "ranap.cn_domain",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        "CN_DomainIndicator", HFILL }},
    { &hf_ranap_rabDataVolumeReport,
      { "rabDataVolumeReport", "ranap.rabDataVolumeReport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_upInformation,
      { "upInformation", "ranap.upInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAB_TrCH_Mapping_item,
      { "RAB-TrCH-MappingItem", "ranap.RAB_TrCH_MappingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_ID,
      { "rAB-ID", "ranap.rAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trCH_ID_List,
      { "trCH-ID-List", "ranap.trCH_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_notEmptyRAListofIdleModeUEs,
      { "notEmptyRAListofIdleModeUEs", "ranap.notEmptyRAListofIdleModeUEs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_emptyFullRAListofIdleModeUEs,
      { "emptyFullRAListofIdleModeUEs", "ranap.emptyFullRAListofIdleModeUEs",
        FT_UINT32, BASE_DEC, VALS(ranap_T_emptyFullRAListofIdleModeUEs_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rAofIdleModeUEs,
      { "rAofIdleModeUEs", "ranap.rAofIdleModeUEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RAofIdleModeUEs_item,
      { "RAC", "ranap.RAC",
        FT_UINT8, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_LAListofIdleModeUEs_item,
      { "LAI", "ranap.LAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedMBMSIPMulticastAddressandAPNRequest_item,
      { "MBMSIPMulticastAddressandAPNlist", "ranap.MBMSIPMulticastAddressandAPNlist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_tMGI,
      { "tMGI", "ranap.tMGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iPMulticastAddress,
      { "iPMulticastAddress", "ranap.iPMulticastAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_aPN,
      { "aPN", "ranap.aPN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_RequestedMulticastServiceList_item,
      { "TMGI", "ranap.TMGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_requestedMaxBitrates,
      { "requestedMaxBitrates", "ranap.requestedMaxBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested_RAB_Parameter_MaxBitrateList", HFILL }},
    { &hf_ranap_requestedGuaranteedBitrates,
      { "requestedGuaranteedBitrates", "ranap.requestedGuaranteedBitrates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Requested_RAB_Parameter_GuaranteedBitrateList", HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList_item,
      { "ExtendedMaxBitrate", "ranap.ExtendedMaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_item,
      { "ExtendedGuaranteedBitrate", "ranap.ExtendedGuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_MaxBitrateList_item,
      { "MaxBitrate", "ranap.MaxBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_Requested_RAB_Parameter_GuaranteedBitrateList_item,
      { "GuaranteedBitrate", "ranap.GuaranteedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_event,
      { "event", "ranap.event",
        FT_UINT32, BASE_DEC, VALS(ranap_Event_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_reportArea,
      { "reportArea", "ranap.reportArea",
        FT_UINT32, BASE_DEC, VALS(ranap_ReportArea_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_accuracyCode,
      { "accuracyCode", "ranap.accuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ranap_mantissa,
      { "mantissa", "ranap.mantissa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_9", HFILL }},
    { &hf_ranap_exponent,
      { "exponent", "ranap.exponent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8", HFILL }},
    { &hf_ranap_rIMInformation,
      { "rIMInformation", "ranap.rIMInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rIMRoutingAddress,
      { "rIMRoutingAddress", "ranap.rIMRoutingAddress",
        FT_UINT32, BASE_DEC, VALS(ranap_RIMRoutingAddress_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_targetRNC_ID,
      { "targetRNC-ID", "ranap.targetRNC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gERAN_Cell_ID,
      { "gERAN-Cell-ID", "ranap.gERAN_Cell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_targeteNB_ID,
      { "targeteNB-ID", "ranap.targeteNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceActivationIndicator,
      { "traceActivationIndicator", "ranap.traceActivationIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_T_traceActivationIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_equipmentsToBeTraced,
      { "equipmentsToBeTraced", "ranap.equipmentsToBeTraced",
        FT_UINT32, BASE_DEC, VALS(ranap_EquipmentsToBeTraced_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_rabParmetersList,
      { "rabParmetersList", "ranap.rabParmetersList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RABParametersList", HFILL }},
    { &hf_ranap_locationReporting,
      { "locationReporting", "ranap.locationReporting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationReportingTransferInformation", HFILL }},
    { &hf_ranap_traceInformation,
      { "traceInformation", "ranap.traceInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceSAI,
      { "sourceSAI", "ranap.sourceSAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SAI", HFILL }},
    { &hf_ranap_nonce,
      { "nonce", "ranap.nonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ranap_iMSInformation,
      { "iMSInformation", "ranap.iMSInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_maxSizeOfIMSInfo", HFILL }},
    { &hf_ranap_sAC,
      { "sAC", "ranap.sAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_pLMNs_in_shared_network,
      { "pLMNs-in-shared-network", "ranap.pLMNs_in_shared_network",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_exponent_1_8,
      { "exponent", "ranap.exponent_1_8",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_6", HFILL }},
    { &hf_ranap_SDU_FormatInformationParameters_item,
      { "SDU-FormatInformationParameters item", "ranap.SDU_FormatInformationParameters_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_subflowSDU_Size,
      { "subflowSDU-Size", "ranap.subflowSDU_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_SubflowCombinationBitRate,
      { "rAB-SubflowCombinationBitRate", "ranap.rAB_SubflowCombinationBitRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_SDU_Parameters_item,
      { "SDU-Parameters item", "ranap.SDU_Parameters_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_ErrorRatio,
      { "sDU-ErrorRatio", "ranap.sDU_ErrorRatio_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_residualBitErrorRatio,
      { "residualBitErrorRatio", "ranap.residualBitErrorRatio_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_deliveryOfErroneousSDU,
      { "deliveryOfErroneousSDU", "ranap.deliveryOfErroneousSDU",
        FT_UINT32, BASE_DEC, VALS(ranap_DeliveryOfErroneousSDU_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_sDU_FormatInformationParameters,
      { "sDU-FormatInformationParameters", "ranap.sDU_FormatInformationParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_null_NRI,
      { "null-NRI", "ranap.null_NRI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sGSN_Group_ID,
      { "sGSN-Group-ID", "ranap.sGSN_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_authorisedPLMNs,
      { "authorisedPLMNs", "ranap.authorisedPLMNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceUTRANCellID,
      { "sourceUTRANCellID", "ranap.sourceUTRANCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sourceGERANCellID,
      { "sourceGERANCellID", "ranap.sourceGERANCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI", HFILL }},
    { &hf_ranap_sourceRNC_ID,
      { "sourceRNC-ID", "ranap.sourceRNC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rRC_Container,
      { "rRC-Container", "ranap.rRC_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_numberOfIuInstances,
      { "numberOfIuInstances", "ranap.numberOfIuInstances",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_relocationType,
      { "relocationType", "ranap.relocationType",
        FT_UINT32, BASE_DEC, VALS(ranap_RelocationType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_chosenIntegrityProtectionAlgorithm,
      { "chosenIntegrityProtectionAlgorithm", "ranap.chosenIntegrityProtectionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(ranap_IntegrityProtectionAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_integrityProtectionKey,
      { "integrityProtectionKey", "ranap.integrityProtectionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForSignalling,
      { "chosenEncryptionAlgorithForSignalling", "ranap.chosenEncryptionAlgorithForSignalling",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_cipheringKey,
      { "cipheringKey", "ranap.cipheringKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForCS,
      { "chosenEncryptionAlgorithForCS", "ranap.chosenEncryptionAlgorithForCS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_chosenEncryptionAlgorithForPS,
      { "chosenEncryptionAlgorithForPS", "ranap.chosenEncryptionAlgorithForPS",
        FT_UINT32, BASE_DEC, VALS(ranap_EncryptionAlgorithm_vals), 0,
        "ChosenEncryptionAlgorithm", HFILL }},
    { &hf_ranap_d_RNTI,
      { "d-RNTI", "ranap.d_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_targetCellId,
      { "targetCellId", "ranap.targetCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_TrCH_Mapping,
      { "rAB-TrCH-Mapping", "ranap.rAB_TrCH_Mapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rSRP,
      { "rSRP", "ranap.rSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_97", HFILL }},
    { &hf_ranap_rSRQ,
      { "rSRQ", "ranap.rSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_34", HFILL }},
    { &hf_ranap_iRATmeasurementParameters,
      { "iRATmeasurementParameters", "ranap.iRATmeasurementParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_measurementDuration,
      { "measurementDuration", "ranap.measurementDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_100", HFILL }},
    { &hf_ranap_eUTRANFrequencies,
      { "eUTRANFrequencies", "ranap.eUTRANFrequencies",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_allSymbols,
      { "allSymbols", "ranap.allSymbols",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ranap_wideBand,
      { "wideBand", "ranap.wideBand",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ranap_EUTRANFrequencies_item,
      { "EUTRANFrequencies item", "ranap.EUTRANFrequencies_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_earfcn,
      { "earfcn", "ranap.earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ranap_measBand,
      { "measBand", "ranap.measBand",
        FT_UINT32, BASE_DEC, VALS(ranap_MeasBand_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_SupportedRAB_ParameterBitrateList_item,
      { "SupportedBitrate", "ranap.SupportedBitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uTRANcellID,
      { "uTRANcellID", "ranap.uTRANcellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TargetCellId", HFILL }},
    { &hf_ranap_SRB_TrCH_Mapping_item,
      { "SRB-TrCH-MappingItem", "ranap.SRB_TrCH_MappingItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sRB_ID,
      { "sRB-ID", "ranap.sRB_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_trCH_ID,
      { "trCH-ID", "ranap.trCH_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_tAC,
      { "tAC", "ranap.tAC",
        FT_UINT16, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cGI,
      { "cGI", "ranap.cGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_eNB_ID,
      { "eNB-ID", "ranap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(ranap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_selectedTAI,
      { "selectedTAI", "ranap.selectedTAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TAI", HFILL }},
    { &hf_ranap_tMSI,
      { "tMSI", "ranap.tMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_p_TMSI,
      { "p-TMSI", "ranap.p_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_serviceID,
      { "serviceID", "ranap.serviceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_ranap_ue_identity,
      { "ue-identity", "ranap.ue_identity",
        FT_UINT32, BASE_DEC, VALS(ranap_UE_ID_vals), 0,
        "UE_ID", HFILL }},
    { &hf_ranap_traceRecordingSessionReference,
      { "traceRecordingSessionReference", "ranap.traceRecordingSessionReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_traceDepth,
      { "traceDepth", "ranap.traceDepth",
        FT_UINT32, BASE_DEC, VALS(ranap_TraceDepth_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_listOfInterfacesToTrace,
      { "listOfInterfacesToTrace", "ranap.listOfInterfacesToTrace",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dCH_ID,
      { "dCH-ID", "ranap.dCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dSCH_ID,
      { "dSCH-ID", "ranap.dSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uSCH_ID,
      { "uSCH-ID", "ranap.uSCH_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_TrCH_ID_List_item,
      { "TrCH-ID", "ranap.TrCH_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress,
      { "transportLayerAddress", "ranap.transportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uDP_Port_Number,
      { "uDP-Port-Number", "ranap.uDP_Port_Number",
        FT_UINT16, BASE_DEC, NULL, 0,
        "Port_Number", HFILL }},
    { &hf_ranap_uE_AggregateMaximumBitRateDownlink,
      { "uE-AggregateMaximumBitRateDownlink", "ranap.uE_AggregateMaximumBitRateDownlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uE_AggregateMaximumBitRateUplink,
      { "uE-AggregateMaximumBitRateUplink", "ranap.uE_AggregateMaximumBitRateUplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imsi,
      { "imsi", "ranap.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imei,
      { "imei", "ranap.imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_imeisv,
      { "imeisv", "ranap.imeisv",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uE_IsServed,
      { "uE-IsServed", "ranap.uE_IsServed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uE_IsNotServed,
      { "uE-IsNotServed", "ranap.uE_IsNotServed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uESBI_IuA,
      { "uESBI-IuA", "ranap.uESBI_IuA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uESBI_IuB,
      { "uESBI-IuB", "ranap.uESBI_IuB",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_frameSeqNoUL,
      { "frameSeqNoUL", "ranap.frameSeqNoUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrameSequenceNumber", HFILL }},
    { &hf_ranap_frameSeqNoDL,
      { "frameSeqNoDL", "ranap.frameSeqNoDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrameSequenceNumber", HFILL }},
    { &hf_ranap_pdu14FrameSeqNoUL,
      { "pdu14FrameSeqNoUL", "ranap.pdu14FrameSeqNoUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUType14FrameSequenceNumber", HFILL }},
    { &hf_ranap_pdu14FrameSeqNoDL,
      { "pdu14FrameSeqNoDL", "ranap.pdu14FrameSeqNoDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDUType14FrameSequenceNumber", HFILL }},
    { &hf_ranap_dataPDUType,
      { "dataPDUType", "ranap.dataPDUType",
        FT_UINT32, BASE_DEC, VALS(ranap_DataPDUType_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_upinitialisationFrame,
      { "upinitialisationFrame", "ranap.upinitialisationFrame",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cellID,
      { "cellID", "ranap.cellID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TargetCellId", HFILL }},
    { &hf_ranap_horizontalVelocity,
      { "horizontalVelocity", "ranap.horizontalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalWithVerticalVelocity,
      { "horizontalWithVerticalVelocity", "ranap.horizontalWithVerticalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalVelocityWithUncertainty,
      { "horizontalVelocityWithUncertainty", "ranap.horizontalVelocityWithUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_horizontalWithVeritcalVelocityAndUncertainty,
      { "horizontalWithVeritcalVelocityAndUncertainty", "ranap.horizontalWithVeritcalVelocityAndUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HorizontalWithVerticalVelocityAndUncertainty", HFILL }},
    { &hf_ranap_horizontalSpeedAndBearing,
      { "horizontalSpeedAndBearing", "ranap.horizontalSpeedAndBearing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_veritcalVelocity,
      { "veritcalVelocity", "ranap.veritcalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VerticalVelocity", HFILL }},
    { &hf_ranap_uncertaintySpeed,
      { "uncertaintySpeed", "ranap.uncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_horizontalUncertaintySpeed,
      { "horizontalUncertaintySpeed", "ranap.horizontalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_verticalUncertaintySpeed,
      { "verticalUncertaintySpeed", "ranap.verticalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_bearing,
      { "bearing", "ranap.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_ranap_horizontalSpeed,
      { "horizontalSpeed", "ranap.horizontalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_ranap_veritcalSpeed,
      { "veritcalSpeed", "ranap.veritcalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ranap_veritcalSpeedDirection,
      { "veritcalSpeedDirection", "ranap.veritcalSpeedDirection",
        FT_UINT32, BASE_DEC, VALS(ranap_VerticalSpeedDirection_vals), 0,
        "VerticalSpeedDirection", HFILL }},
    { &hf_ranap_protocolIEs,
      { "protocolIEs", "ranap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_ranap_protocolExtensions,
      { "protocolExtensions", "ranap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_ranap_rab_dl_UnsuccessfullyTransmittedDataVolume,
      { "dl-UnsuccessfullyTransmittedDataVolume", "ranap.rab_dl_UnsuccessfullyTransmittedDataVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList", HFILL }},
    { &hf_ranap_dL_GTP_PDU_SequenceNumber,
      { "dL-GTP-PDU-SequenceNumber", "ranap.dL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_uL_GTP_PDU_SequenceNumber,
      { "uL-GTP-PDU-SequenceNumber", "ranap.uL_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iuTransportAssociation,
      { "iuTransportAssociation", "ranap.iuTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_nAS_SynchronisationIndicator,
      { "nAS-SynchronisationIndicator", "ranap.nAS_SynchronisationIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_rAB_Parameters,
      { "rAB-Parameters", "ranap.rAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dataVolumeReportingIndication,
      { "dataVolumeReportingIndication", "ranap.dataVolumeReportingIndication",
        FT_UINT32, BASE_DEC, VALS(ranap_DataVolumeReportingIndication_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_pDP_TypeInformation,
      { "pDP-TypeInformation", "ranap.pDP_TypeInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_userPlaneInformation,
      { "userPlaneInformation", "ranap.userPlaneInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_service_Handover,
      { "service-Handover", "ranap.service_Handover",
        FT_UINT32, BASE_DEC, VALS(ranap_Service_Handover_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_userPlaneMode,
      { "userPlaneMode", "ranap.userPlaneMode",
        FT_UINT32, BASE_DEC, VALS(ranap_UserPlaneMode_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_uP_ModeVersions,
      { "uP-ModeVersions", "ranap.uP_ModeVersions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_joinedMBMSBearerService_IEs,
      { "joinedMBMSBearerService-IEs", "ranap.joinedMBMSBearerService_IEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_JoinedMBMSBearerService_IEs_item,
      { "JoinedMBMSBearerService-IEs item", "ranap.JoinedMBMSBearerService_IEs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMS_PTP_RAB_ID,
      { "mBMS-PTP-RAB-ID", "ranap.mBMS_PTP_RAB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_cause,
      { "cause", "ranap.cause",
        FT_UINT32, BASE_DEC, VALS(ranap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_dl_GTP_PDU_SequenceNumber,
      { "dl-GTP-PDU-SequenceNumber", "ranap.dl_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ul_GTP_PDU_SequenceNumber,
      { "ul-GTP-PDU-SequenceNumber", "ranap.ul_GTP_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_N_PDU_SequenceNumber,
      { "dl-N-PDU-SequenceNumber", "ranap.dl_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_ul_N_PDU_SequenceNumber,
      { "ul-N-PDU-SequenceNumber", "ranap.ul_N_PDU_SequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_iuSigConId,
      { "iuSigConId", "ranap.iuSigConId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IuSignallingConnectionIdentifier", HFILL }},
    { &hf_ranap_transportLayerAddressReq1,
      { "transportLayerAddressReq1", "ranap.transportLayerAddressReq1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_iuTransportAssociationReq1,
      { "iuTransportAssociationReq1", "ranap.iuTransportAssociationReq1",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_ass_RAB_Parameters,
      { "ass-RAB-Parameters", "ranap.ass_RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddressRes1,
      { "transportLayerAddressRes1", "ranap.transportLayerAddressRes1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_iuTransportAssociationRes1,
      { "iuTransportAssociationRes1", "ranap.iuTransportAssociationRes1",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_rab2beReleasedList,
      { "rab2beReleasedList", "ranap.rab2beReleasedList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RAB_ToBeReleasedList_EnhancedRelocCompleteRes", HFILL }},
    { &hf_ranap_transportLayerInformation,
      { "transportLayerInformation", "ranap.transportLayerInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dl_dataVolumes,
      { "dl-dataVolumes", "ranap.dl_dataVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataVolumeList", HFILL }},
    { &hf_ranap_DataVolumeList_item,
      { "DataVolumeList item", "ranap.DataVolumeList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_gERAN_Classmark,
      { "gERAN-Classmark", "ranap.gERAN_Classmark",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_privateIEs,
      { "privateIEs", "ranap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_ranap_nAS_PDU,
      { "nAS-PDU", "ranap.nAS_PDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_sAPI,
      { "sAPI", "ranap.sAPI",
        FT_UINT32, BASE_DEC, VALS(ranap_SAPI_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_cN_DomainIndicator,
      { "cN-DomainIndicator", "ranap.cN_DomainIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_CN_DomainIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_dataForwardingInformation,
      { "dataForwardingInformation", "ranap.dataForwardingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoReq", HFILL }},
    { &hf_ranap_sourceSideIuULTNLInfo,
      { "sourceSideIuULTNLInfo", "ranap.sourceSideIuULTNLInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoReq", HFILL }},
    { &hf_ranap_alt_RAB_Parameters,
      { "alt-RAB-Parameters", "ranap.alt_RAB_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_dataForwardingInformation_01,
      { "dataForwardingInformation", "ranap.dataForwardingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TNLInformationEnhRelInfoRes", HFILL }},
    { &hf_ranap_dl_forwardingTransportLayerAddress,
      { "dl-forwardingTransportLayerAddress", "ranap.dl_forwardingTransportLayerAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransportLayerAddress", HFILL }},
    { &hf_ranap_dl_forwardingTransportAssociation,
      { "dl-forwardingTransportAssociation", "ranap.dl_forwardingTransportAssociation",
        FT_UINT32, BASE_DEC, VALS(ranap_IuTransportAssociation_vals), 0,
        "IuTransportAssociation", HFILL }},
    { &hf_ranap_requested_RAB_Parameter_Values,
      { "requested-RAB-Parameter-Values", "ranap.requested_RAB_Parameter_Values_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_mBMSHCIndicator,
      { "mBMSHCIndicator", "ranap.mBMSHCIndicator",
        FT_UINT32, BASE_DEC, VALS(ranap_MBMSHCIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_ranap_gTPDLTEID,
      { "gTPDLTEID", "ranap.gTPDLTEID",
        FT_UINT32, BASE_HEX_DEC, NULL, 0,
        "GTP_TEI", HFILL }},
    { &hf_ranap_LeftMBMSBearerService_IEs_item,
      { "LeftMBMSBearerService-IEs item", "ranap.LeftMBMSBearerService_IEs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_UnsuccessfulLinking_IEs_item,
      { "UnsuccessfulLinking-IEs item", "ranap.UnsuccessfulLinking_IEs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_initiatingMessage,
      { "initiatingMessage", "ranap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_successfulOutcome,
      { "successfulOutcome", "ranap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "ranap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_outcome,
      { "outcome", "ranap.outcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_initiatingMessagevalue,
      { "value", "ranap.initiatingMessagevalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_ranap_successfulOutcome_value,
      { "value", "ranap.successfulOutcome_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_ranap_unsuccessfulOutcome_value,
      { "value", "ranap.unsuccessfulOutcome_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_ranap_value,
      { "value", "ranap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ranap,
    &ett_ranap_transportLayerAddress,
    &ett_ranap_transportLayerAddress_nsap,
    &ett_ranap_PrivateIE_ID,
    &ett_ranap_ProtocolIE_Container,
    &ett_ranap_ProtocolIE_Field,
    &ett_ranap_ProtocolIE_ContainerPair,
    &ett_ranap_ProtocolIE_FieldPair,
    &ett_ranap_ProtocolIE_ContainerList,
    &ett_ranap_ProtocolIE_ContainerPairList,
    &ett_ranap_ProtocolExtensionContainer,
    &ett_ranap_ProtocolExtensionField,
    &ett_ranap_PrivateIE_Container,
    &ett_ranap_PrivateIE_Field,
    &ett_ranap_Additional_CSPS_coordination_information,
    &ett_ranap_Additional_PositioningDataSet,
    &ett_ranap_AllocationOrRetentionPriority,
    &ett_ranap_Alt_RAB_Parameters,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_SupportedGuaranteedBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrates,
    &ett_ranap_Alt_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrates,
    &ett_ranap_Alt_RAB_Parameter_MaxBitrateList,
    &ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrateInf,
    &ett_ranap_Alt_RAB_Parameter_SupportedMaxBitrates,
    &ett_ranap_UE_Application_Layer_Measurement_Configuration,
    &ett_ranap_UE_Application_Layer_Measurement_Configuration_For_Relocation,
    &ett_ranap_AreaScopeForUEApplicationLayerMeasurementConfiguration,
    &ett_ranap_AreaIdentity,
    &ett_ranap_Ass_RAB_Parameters,
    &ett_ranap_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Ass_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Ass_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_Ass_RAB_Parameter_MaxBitrateList,
    &ett_ranap_AuthorisedPLMNs,
    &ett_ranap_AuthorisedPLMNs_item,
    &ett_ranap_AuthorisedSNAs,
    &ett_ranap_BroadcastAssistanceDataDecipheringKeys,
    &ett_ranap_Cause,
    &ett_ranap_CellBased,
    &ett_ranap_CellIdList,
    &ett_ranap_CellLoadInformation,
    &ett_ranap_CellLoadInformationGroup,
    &ett_ranap_CriticalityDiagnostics,
    &ett_ranap_CriticalityDiagnostics_IE_List,
    &ett_ranap_CriticalityDiagnostics_IE_List_item,
    &ett_ranap_MessageStructure,
    &ett_ranap_MessageStructure_item,
    &ett_ranap_CGI,
    &ett_ranap_CSG_Id_List,
    &ett_ranap_DeltaRAListofIdleModeUEs,
    &ett_ranap_NewRAListofIdleModeUEs,
    &ett_ranap_RAListwithNoIdleModeUEsAnyMore,
    &ett_ranap_ENB_ID,
    &ett_ranap_EncryptionInformation,
    &ett_ranap_EquipmentsToBeTraced,
    &ett_ranap_Event1F_Parameters,
    &ett_ranap_Event1I_Parameters,
    &ett_ranap_GANSS_PositioningDataSet,
    &ett_ranap_GeographicalArea,
    &ett_ranap_GeographicalCoordinates,
    &ett_ranap_GA_AltitudeAndDirection,
    &ett_ranap_GA_EllipsoidArc,
    &ett_ranap_GA_Point,
    &ett_ranap_GA_PointWithAltitude,
    &ett_ranap_GA_PointWithAltitudeAndUncertaintyEllipsoid,
    &ett_ranap_GA_PointWithUnCertainty,
    &ett_ranap_GA_PointWithUnCertaintyEllipse,
    &ett_ranap_GA_Polygon,
    &ett_ranap_GA_Polygon_item,
    &ett_ranap_GA_UncertaintyEllipse,
    &ett_ranap_GERAN_Cell_ID,
    &ett_ranap_GlobalCN_ID,
    &ett_ranap_GlobalRNC_ID,
    &ett_ranap_IMEIGroup,
    &ett_ranap_IMEIList,
    &ett_ranap_IMEISVGroup,
    &ett_ranap_IMEISVList,
    &ett_ranap_ImmediateMDT,
    &ett_ranap_InformationRequested,
    &ett_ranap_InformationRequestType,
    &ett_ranap_InformationTransferType,
    &ett_ranap_IntegrityProtectionInformation,
    &ett_ranap_InterSystemInformationTransferType,
    &ett_ranap_InterSystemInformation_TransparentContainer,
    &ett_ranap_IuTransportAssociation,
    &ett_ranap_LA_LIST,
    &ett_ranap_LA_LIST_item,
    &ett_ranap_LAI,
    &ett_ranap_LastKnownServiceArea,
    &ett_ranap_LastVisitedUTRANCell_Item,
    &ett_ranap_ListOF_SNAs,
    &ett_ranap_ListOfInterfacesToTrace,
    &ett_ranap_InterfacesToTraceItem,
    &ett_ranap_LocationRelatedDataRequestType,
    &ett_ranap_LocationReportingTransferInformation,
    &ett_ranap_M1Report,
    &ett_ranap_M2Report,
    &ett_ranap_M4Report,
    &ett_ranap_M4_Collection_Parameters,
    &ett_ranap_M5Report,
    &ett_ranap_M6Report,
    &ett_ranap_M7Report,
    &ett_ranap_MBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MDTAreaScope,
    &ett_ranap_MDT_Configuration,
    &ett_ranap_MDTMode,
    &ett_ranap_MDT_PLMN_List,
    &ett_ranap_MDT_Report_Parameters,
    &ett_ranap_Offload_RAB_Parameters,
    &ett_ranap_PagingAreaID,
    &ett_ranap_PDP_TypeInformation,
    &ett_ranap_PDP_TypeInformation_extension,
    &ett_ranap_PeriodicLocationInfo,
    &ett_ranap_PermanentNAS_UE_ID,
    &ett_ranap_PermittedEncryptionAlgorithms,
    &ett_ranap_PermittedIntegrityProtectionAlgorithms,
    &ett_ranap_LABased,
    &ett_ranap_LAI_List,
    &ett_ranap_LoggedMDT,
    &ett_ranap_PLMNBased,
    &ett_ranap_PLMNList,
    &ett_ranap_PLMNs_in_shared_network,
    &ett_ranap_PLMNs_in_shared_network_item,
    &ett_ranap_PositioningDataSet,
    &ett_ranap_PositionData,
    &ett_ranap_ProvidedData,
    &ett_ranap_RABased,
    &ett_ranap_RAI_List,
    &ett_ranap_RABDataVolumeReport,
    &ett_ranap_RABDataVolumeReport_item,
    &ett_ranap_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RAB_Parameter_MaxBitrateList,
    &ett_ranap_RAB_Parameters,
    &ett_ranap_RABParametersList,
    &ett_ranap_RABParametersList_item,
    &ett_ranap_RAB_TrCH_Mapping,
    &ett_ranap_RAB_TrCH_MappingItem,
    &ett_ranap_RAI,
    &ett_ranap_RAListofIdleModeUEs,
    &ett_ranap_NotEmptyRAListofIdleModeUEs,
    &ett_ranap_RAofIdleModeUEs,
    &ett_ranap_LAListofIdleModeUEs,
    &ett_ranap_RequestedMBMSIPMulticastAddressandAPNRequest,
    &ett_ranap_MBMSIPMulticastAddressandAPNlist,
    &ett_ranap_RequestedMulticastServiceList,
    &ett_ranap_Requested_RAB_Parameter_Values,
    &ett_ranap_Requested_RAB_Parameter_ExtendedMaxBitrateList,
    &ett_ranap_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList,
    &ett_ranap_Requested_RAB_Parameter_MaxBitrateList,
    &ett_ranap_Requested_RAB_Parameter_GuaranteedBitrateList,
    &ett_ranap_RequestType,
    &ett_ranap_ResidualBitErrorRatio,
    &ett_ranap_RIM_Transfer,
    &ett_ranap_RIMRoutingAddress,
    &ett_ranap_RNCTraceInformation,
    &ett_ranap_RNSAPRelocationParameters,
    &ett_ranap_RSRVCC_Information,
    &ett_ranap_SAI,
    &ett_ranap_Shared_Network_Information,
    &ett_ranap_SDU_ErrorRatio,
    &ett_ranap_SDU_FormatInformationParameters,
    &ett_ranap_SDU_FormatInformationParameters_item,
    &ett_ranap_SDU_Parameters,
    &ett_ranap_SDU_Parameters_item,
    &ett_ranap_SGSN_Group_Identity,
    &ett_ranap_SNA_Access_Information,
    &ett_ranap_SourceCellID,
    &ett_ranap_SourceID,
    &ett_ranap_SourceRNC_ID,
    &ett_ranap_SourceRNC_ToTargetRNC_TransparentContainer,
    &ett_ranap_IRAT_Measurement_Configuration,
    &ett_ranap_IRATmeasurementParameters,
    &ett_ranap_RSRQ_Type,
    &ett_ranap_EUTRANFrequencies,
    &ett_ranap_EUTRANFrequencies_item,
    &ett_ranap_SupportedRAB_ParameterBitrateList,
    &ett_ranap_SourceUTRANCellID,
    &ett_ranap_SRB_TrCH_Mapping,
    &ett_ranap_SRB_TrCH_MappingItem,
    &ett_ranap_SRVCC_Information,
    &ett_ranap_TAI,
    &ett_ranap_TargetID,
    &ett_ranap_TargetENB_ID,
    &ett_ranap_TargetRNC_ID,
    &ett_ranap_TargetRNC_ToSourceRNC_TransparentContainer,
    &ett_ranap_TemporaryUE_ID,
    &ett_ranap_TMGI,
    &ett_ranap_TraceInformation,
    &ett_ranap_TracePropagationParameters,
    &ett_ranap_TraceRecordingSessionInformation,
    &ett_ranap_TrCH_ID,
    &ett_ranap_TrCH_ID_List,
    &ett_ranap_TunnelInformation,
    &ett_ranap_UE_AggregateMaximumBitRate,
    &ett_ranap_UE_ID,
    &ett_ranap_UE_IsNotServed,
    &ett_ranap_UE_IsServed,
    &ett_ranap_UERegistrationQueryResult,
    &ett_ranap_UESBI_Iu,
    &ett_ranap_UPInformation,
    &ett_ranap_UTRAN_CellID,
    &ett_ranap_VelocityEstimate,
    &ett_ranap_HorizontalVelocity,
    &ett_ranap_HorizontalWithVerticalVelocity,
    &ett_ranap_HorizontalVelocityWithUncertainty,
    &ett_ranap_HorizontalWithVerticalVelocityAndUncertainty,
    &ett_ranap_HorizontalSpeedAndBearing,
    &ett_ranap_VerticalVelocity,
    &ett_ranap_Iu_ReleaseCommand,
    &ett_ranap_Iu_ReleaseComplete,
    &ett_ranap_RAB_DataVolumeReportItem,
    &ett_ranap_RAB_ReleasedItem_IuRelComp,
    &ett_ranap_RelocationRequired,
    &ett_ranap_RelocationCommand,
    &ett_ranap_RAB_RelocationReleaseItem,
    &ett_ranap_RAB_DataForwardingItem,
    &ett_ranap_RelocationPreparationFailure,
    &ett_ranap_RelocationRequest,
    &ett_ranap_RAB_SetupItem_RelocReq,
    &ett_ranap_UserPlaneInformation,
    &ett_ranap_CNMBMSLinkingInformation,
    &ett_ranap_JoinedMBMSBearerService_IEs,
    &ett_ranap_JoinedMBMSBearerService_IEs_item,
    &ett_ranap_RelocationRequestAcknowledge,
    &ett_ranap_RAB_SetupItem_RelocReqAck,
    &ett_ranap_RAB_FailedItem,
    &ett_ranap_RelocationFailure,
    &ett_ranap_RelocationCancel,
    &ett_ranap_RelocationCancelAcknowledge,
    &ett_ranap_SRNS_ContextRequest,
    &ett_ranap_RAB_DataForwardingItem_SRNS_CtxReq,
    &ett_ranap_SRNS_ContextResponse,
    &ett_ranap_RAB_ContextItem,
    &ett_ranap_RABs_ContextFailedtoTransferItem,
    &ett_ranap_SecurityModeCommand,
    &ett_ranap_SecurityModeComplete,
    &ett_ranap_SecurityModeReject,
    &ett_ranap_DataVolumeReportRequest,
    &ett_ranap_RAB_DataVolumeReportRequestItem,
    &ett_ranap_DataVolumeReport,
    &ett_ranap_RABs_failed_to_reportItem,
    &ett_ranap_Reset,
    &ett_ranap_ResetAcknowledge,
    &ett_ranap_ResetResource,
    &ett_ranap_ResetResourceItem,
    &ett_ranap_ResetResourceAcknowledge,
    &ett_ranap_ResetResourceAckItem,
    &ett_ranap_RAB_ReleaseRequest,
    &ett_ranap_RAB_ReleaseItem,
    &ett_ranap_Iu_ReleaseRequest,
    &ett_ranap_RelocationDetect,
    &ett_ranap_RelocationComplete,
    &ett_ranap_EnhancedRelocationCompleteRequest,
    &ett_ranap_RAB_SetupItem_EnhancedRelocCompleteReq,
    &ett_ranap_EnhancedRelocationCompleteResponse,
    &ett_ranap_RAB_SetupItem_EnhancedRelocCompleteRes,
    &ett_ranap_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes,
    &ett_ranap_EnhancedRelocationCompleteFailure,
    &ett_ranap_EnhancedRelocationCompleteConfirm,
    &ett_ranap_Paging,
    &ett_ranap_CommonID,
    &ett_ranap_CN_InvokeTrace,
    &ett_ranap_CN_DeactivateTrace,
    &ett_ranap_LocationReportingControl,
    &ett_ranap_LocationReport,
    &ett_ranap_InitialUE_Message,
    &ett_ranap_DirectTransfer,
    &ett_ranap_Overload,
    &ett_ranap_ErrorIndication,
    &ett_ranap_SRNS_DataForwardCommand,
    &ett_ranap_ForwardSRNS_Context,
    &ett_ranap_RAB_AssignmentRequest,
    &ett_ranap_RAB_SetupOrModifyItemFirst,
    &ett_ranap_TransportLayerInformation,
    &ett_ranap_RAB_SetupOrModifyItemSecond,
    &ett_ranap_RAB_AssignmentResponse,
    &ett_ranap_RAB_SetupOrModifiedItem,
    &ett_ranap_RAB_ReleasedItem,
    &ett_ranap_DataVolumeList,
    &ett_ranap_DataVolumeList_item,
    &ett_ranap_RAB_QueuedItem,
    &ett_ranap_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item,
    &ett_ranap_PrivateMessage,
    &ett_ranap_RANAP_RelocationInformation,
    &ett_ranap_DirectTransferInformationItem_RANAP_RelocInf,
    &ett_ranap_RAB_ContextItem_RANAP_RelocInf,
    &ett_ranap_RANAP_EnhancedRelocationInformationRequest,
    &ett_ranap_RAB_SetupItem_EnhRelocInfoReq,
    &ett_ranap_TNLInformationEnhRelInfoReq,
    &ett_ranap_RANAP_EnhancedRelocationInformationResponse,
    &ett_ranap_RAB_SetupItem_EnhRelocInfoRes,
    &ett_ranap_RAB_FailedItem_EnhRelocInfoRes,
    &ett_ranap_TNLInformationEnhRelInfoRes,
    &ett_ranap_RAB_ModifyRequest,
    &ett_ranap_RAB_ModifyItem,
    &ett_ranap_LocationRelatedDataRequest,
    &ett_ranap_LocationRelatedDataResponse,
    &ett_ranap_LocationRelatedDataFailure,
    &ett_ranap_InformationTransferIndication,
    &ett_ranap_InformationTransferConfirmation,
    &ett_ranap_InformationTransferFailure,
    &ett_ranap_UESpecificInformationIndication,
    &ett_ranap_DirectInformationTransfer,
    &ett_ranap_UplinkInformationExchangeRequest,
    &ett_ranap_UplinkInformationExchangeResponse,
    &ett_ranap_UplinkInformationExchangeFailure,
    &ett_ranap_MBMSSessionStart,
    &ett_ranap_MBMSSynchronisationInformation,
    &ett_ranap_MBMSSessionStartResponse,
    &ett_ranap_MBMSSessionStartFailure,
    &ett_ranap_MBMSSessionUpdate,
    &ett_ranap_MBMSSessionUpdateResponse,
    &ett_ranap_MBMSSessionUpdateFailure,
    &ett_ranap_MBMSSessionStop,
    &ett_ranap_MBMSSessionStopResponse,
    &ett_ranap_MBMSUELinkingRequest,
    &ett_ranap_LeftMBMSBearerService_IEs,
    &ett_ranap_LeftMBMSBearerService_IEs_item,
    &ett_ranap_MBMSUELinkingResponse,
    &ett_ranap_UnsuccessfulLinking_IEs,
    &ett_ranap_UnsuccessfulLinking_IEs_item,
    &ett_ranap_MBMSRegistrationRequest,
    &ett_ranap_MBMSRegistrationResponse,
    &ett_ranap_MBMSRegistrationFailure,
    &ett_ranap_MBMSCNDe_RegistrationRequest,
    &ett_ranap_MBMSCNDe_RegistrationResponse,
    &ett_ranap_MBMSRABEstablishmentIndication,
    &ett_ranap_MBMSRABReleaseRequest,
    &ett_ranap_MBMSRABRelease,
    &ett_ranap_MBMSRABReleaseFailure,
    &ett_ranap_SRVCC_CSKeysRequest,
    &ett_ranap_SRVCC_CSKeysResponse,
    &ett_ranap_UeRadioCapabilityMatchRequest,
    &ett_ranap_UeRadioCapabilityMatchResponse,
    &ett_ranap_UeRegistrationQueryRequest,
    &ett_ranap_UeRegistrationQueryResponse,
    &ett_ranap_RerouteNASRequest,
    &ett_ranap_RANAP_PDU,
    &ett_ranap_InitiatingMessage,
    &ett_ranap_SuccessfulOutcome,
    &ett_ranap_UnsuccessfulOutcome,
    &ett_ranap_Outcome,
  };


  /* Register protocol */
  proto_ranap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  ranap_handle = register_dissector("ranap", dissect_ranap, proto_ranap);

  /* Register dissector tables */
  ranap_ies_dissector_table = register_dissector_table("ranap.ies", "RANAP-PROTOCOL-IES", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_ies_p1_dissector_table = register_dissector_table("ranap.ies.pair.first", "RANAP-PROTOCOL-IES-PAIR FirstValue", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_ies_p2_dissector_table = register_dissector_table("ranap.ies.pair.second", "RANAP-PROTOCOL-IES-PAIR SecondValue", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_extension_dissector_table = register_dissector_table("ranap.extension", "RANAP-PROTOCOL-EXTENSION", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_imsg_dissector_table = register_dissector_table("ranap.proc.imsg", "RANAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_sout_dissector_table = register_dissector_table("ranap.proc.sout", "RANAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_uout_dissector_table = register_dissector_table("ranap.proc.uout", "RANAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_out_dissector_table = register_dissector_table("ranap.proc.out", "RANAP-ELEMENTARY-PROCEDURE Outcome", proto_ranap, FT_UINT32, BASE_DEC);

  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", proto_ranap, FT_UINT8, BASE_DEC);

  ranap_module = prefs_register_protocol(proto_ranap, NULL);
  prefs_register_bool_preference(ranap_module, "dissect_rrc_container",
                                 "Attempt to dissect RRC-Container",
                                 "Attempt to dissect RRC message embedded in RRC-Container IE",
                                 &glbl_dissect_container);
}


/*--- proto_reg_handoff_ranap ---------------------------------------*/
void
proto_reg_handoff_ranap(void)
{
  rrc_s_to_trnc_handle = find_dissector_add_dependency("rrc.s_to_trnc_cont", proto_ranap);
  rrc_t_to_srnc_handle = find_dissector_add_dependency("rrc.t_to_srnc_cont", proto_ranap);
  rrc_ho_to_utran_cmd = find_dissector_add_dependency("rrc.irat.ho_to_utran_cmd", proto_ranap);
  bssgp_handle = find_dissector("bssgp");
  heur_dissector_add("sccp", dissect_sccp_ranap_heur, "RANAP over SCCP", "ranap_sccp", proto_ranap, HEURISTIC_ENABLE);
  heur_dissector_add("sua", dissect_sccp_ranap_heur, "RANAP over SUA", "ranap_sua", proto_ranap, HEURISTIC_ENABLE);
  dissector_add_uint_with_preference("sccp.ssn", SCCP_SSN_RANAP, ranap_handle);
  dissector_add_uint("ranap.ies", id_Cause, create_dissector_handle(dissect_ranap_Cause_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportList, create_dissector_handle(dissect_RAB_DataVolumeReportList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedList_IuRelComp, create_dissector_handle(dissect_RAB_ReleasedList_IuRelComp_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportItem, create_dissector_handle(dissect_RAB_DataVolumeReportItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedItem_IuRelComp, create_dissector_handle(dissect_RAB_ReleasedItem_IuRelComp_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RelocationType, create_dissector_handle(dissect_RelocationType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SourceID, create_dissector_handle(dissect_SourceID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Source_ToTarget_TransparentContainer, create_dissector_handle(dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SPECIAL|id_Source_ToTarget_TransparentContainer, create_dissector_handle(dissect_ranap_Source_ToTarget_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TargetID, create_dissector_handle(dissect_TargetID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Target_ToSource_TransparentContainer, create_dissector_handle(dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SPECIAL|id_Target_ToSource_TransparentContainer, create_dissector_handle(dissect_Target_ToSource_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ClassmarkInformation2, create_dissector_handle(dissect_ClassmarkInformation2_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ClassmarkInformation3, create_dissector_handle(dissect_ClassmarkInformation3_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldBSS_ToNewBSS_Information, create_dissector_handle(dissect_OldBSS_ToNewBSS_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_L3_Information, create_dissector_handle(dissect_L3_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_RelocationReleaseList, create_dissector_handle(dissect_RAB_RelocationReleaseList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingList, create_dissector_handle(dissect_RAB_DataForwardingList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_RelocationReleaseItem, create_dissector_handle(dissect_RAB_RelocationReleaseItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingItem, create_dissector_handle(dissect_RAB_DataForwardingItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PermanentNAS_UE_ID, create_dissector_handle(dissect_PermanentNAS_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_CN_DomainIndicator, create_dissector_handle(dissect_CN_DomainIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_RelocReq, create_dissector_handle(dissect_RAB_SetupList_RelocReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IntegrityProtectionInformation, create_dissector_handle(dissect_IntegrityProtectionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_EncryptionInformation, create_dissector_handle(dissect_EncryptionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IuSigConId, create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DirectTransferInformationList_RANAP_RelocInf, create_dissector_handle(dissect_DirectTransferInformationList_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DirectTransferInformationItem_RANAP_RelocInf, create_dissector_handle(dissect_DirectTransferInformationItem_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_RelocReq, create_dissector_handle(dissect_RAB_SetupItem_RelocReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_RelocReqAck, create_dissector_handle(dissect_RAB_SetupList_RelocReqAck_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedList, create_dissector_handle(dissect_RAB_FailedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ChosenIntegrityProtectionAlgorithm, create_dissector_handle(dissect_ChosenIntegrityProtectionAlgorithm_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ChosenEncryptionAlgorithm, create_dissector_handle(dissect_ChosenEncryptionAlgorithm_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_RelocReqAck, create_dissector_handle(dissect_RAB_SetupItem_RelocReqAck_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedItem, create_dissector_handle(dissect_RAB_FailedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingList_SRNS_CtxReq, create_dissector_handle(dissect_RAB_DataForwardingList_SRNS_CtxReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataForwardingItem_SRNS_CtxReq, create_dissector_handle(dissect_RAB_DataForwardingItem_SRNS_CtxReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextList, create_dissector_handle(dissect_RAB_ContextList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextFailedtoTransferList, create_dissector_handle(dissect_RAB_ContextFailedtoTransferList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextItem, create_dissector_handle(dissect_RAB_ContextItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextFailedtoTransferItem, create_dissector_handle(dissect_RABs_ContextFailedtoTransferItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_KeyStatus, create_dissector_handle(dissect_KeyStatus_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportRequestList, create_dissector_handle(dissect_RAB_DataVolumeReportRequestList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_DataVolumeReportRequestItem, create_dissector_handle(dissect_RAB_DataVolumeReportRequestItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedtoReportList, create_dissector_handle(dissect_RAB_FailedtoReportList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedtoReportItem, create_dissector_handle(dissect_RABs_failed_to_reportItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalRNC_ID, create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", IMSG|id_IuSigConIdList, create_dissector_handle(dissect_ResetResourceList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", IMSG|id_IuSigConIdItem, create_dissector_handle(dissect_ResetResourceItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SOUT|id_IuSigConIdList, create_dissector_handle(dissect_ResetResourceAckList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", SOUT|id_IuSigConIdItem, create_dissector_handle(dissect_ResetResourceAckItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseList, create_dissector_handle(dissect_RAB_ReleaseList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseItem, create_dissector_handle(dissect_RAB_ReleaseItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TemporaryUE_ID, create_dissector_handle(dissect_TemporaryUE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PagingAreaID, create_dissector_handle(dissect_PagingAreaID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PagingCause, create_dissector_handle(dissect_PagingCause_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NonSearchingIndication, create_dissector_handle(dissect_NonSearchingIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DRX_CycleLengthCoefficient, create_dissector_handle(dissect_DRX_CycleLengthCoefficient_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TraceType, create_dissector_handle(dissect_TraceType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TraceReference, create_dissector_handle(dissect_TraceReference_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TriggerID, create_dissector_handle(dissect_TriggerID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UE_ID, create_dissector_handle(dissect_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OMC_ID, create_dissector_handle(dissect_OMC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RequestType, create_dissector_handle(dissect_RequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_AreaIdentity, create_dissector_handle(dissect_AreaIdentity_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LAI, create_dissector_handle(dissect_LAI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAC, create_dissector_handle(dissect_RAC_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SAI, create_dissector_handle(dissect_SAI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NAS_PDU, create_dissector_handle(dissect_NAS_PDU_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SAPI, create_dissector_handle(dissect_SAPI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RejectCauseValue, create_dissector_handle(dissect_RejectCauseValue_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NAS_SequenceNumber, create_dissector_handle(dissect_NAS_SequenceNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_NumberOfSteps, create_dissector_handle(dissect_NumberOfSteps_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifyList, create_dissector_handle(dissect_RAB_SetupOrModifyList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifiedList, create_dissector_handle(dissect_RAB_SetupOrModifiedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedList, create_dissector_handle(dissect_RAB_ReleasedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_QueuedList, create_dissector_handle(dissect_RAB_QueuedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleaseFailedList, create_dissector_handle(dissect_RAB_ReleaseFailedList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupOrModifiedItem, create_dissector_handle(dissect_RAB_SetupOrModifiedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ReleasedItem, create_dissector_handle(dissect_RAB_ReleasedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_QueuedItem, create_dissector_handle(dissect_RAB_QueuedItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item, create_dissector_handle(dissect_GERAN_Iumode_RAB_Failed_RABAssgntResponse_Item_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextList_RANAP_RelocInf, create_dissector_handle(dissect_RAB_ContextList_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ContextItem_RANAP_RelocInf, create_dissector_handle(dissect_RAB_ContextItem_RANAP_RelocInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ModifyList, create_dissector_handle(dissect_RAB_ModifyList_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ModifyItem, create_dissector_handle(dissect_RAB_ModifyItem_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LocationRelatedDataRequestType, create_dissector_handle(dissect_LocationRelatedDataRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_BroadcastAssistanceDataDecipheringKeys, create_dissector_handle(dissect_BroadcastAssistanceDataDecipheringKeys_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationTransferID, create_dissector_handle(dissect_InformationTransferID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_ProvidedData, create_dissector_handle(dissect_ProvidedData_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_ID, create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UESBI_Iu, create_dissector_handle(dissect_UESBI_Iu_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InterSystemInformationTransferType, create_dissector_handle(dissect_InterSystemInformationTransferType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationExchangeID, create_dissector_handle(dissect_InformationExchangeID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationExchangeType, create_dissector_handle(dissect_InformationExchangeType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationTransferType, create_dissector_handle(dissect_InformationTransferType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationRequestType, create_dissector_handle(dissect_InformationRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_InformationRequested, create_dissector_handle(dissect_InformationRequested_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TMGI, create_dissector_handle(dissect_TMGI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionIdentity, create_dissector_handle(dissect_MBMSSessionIdentity_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSBearerServiceType, create_dissector_handle(dissect_MBMSBearerServiceType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_Parameters, create_dissector_handle(dissect_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_PDP_TypeInformation, create_dissector_handle(dissect_PDP_TypeInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionDuration, create_dissector_handle(dissect_MBMSSessionDuration_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSServiceArea, create_dissector_handle(dissect_MBMSServiceArea_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_FrequenceLayerConvergenceFlag, create_dissector_handle(dissect_FrequenceLayerConvergenceFlag_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAListofIdleModeUEs, create_dissector_handle(dissect_RAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSSessionRepetitionNumber, create_dissector_handle(dissect_MBMSSessionRepetitionNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TimeToMBMSDataTransfer, create_dissector_handle(dissect_TimeToMBMSDataTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_TransportLayerInformation, create_dissector_handle(dissect_TransportLayerInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SessionUpdateID, create_dissector_handle(dissect_SessionUpdateID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_DeltaRAListofIdleModeUEs, create_dissector_handle(dissect_DeltaRAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSCNDe_Registration, create_dissector_handle(dissect_MBMSCNDe_Registration_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_JoinedMBMSBearerServicesList, create_dissector_handle(dissect_JoinedMBMSBearerService_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_LeftMBMSBearerServicesList, create_dissector_handle(dissect_LeftMBMSBearerService_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UnsuccessfulLinkingList, create_dissector_handle(dissect_UnsuccessfulLinking_IEs_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_MBMSRegistrationRequestType, create_dissector_handle(dissect_MBMSRegistrationRequestType_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IPMulticastAddress, create_dissector_handle(dissect_IPMulticastAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_APN, create_dissector_handle(dissect_APN_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhancedRelocCompleteReq, create_dissector_handle(dissect_RAB_SetupList_EnhancedRelocCompleteReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhancedRelocCompleteReq, create_dissector_handle(dissect_RAB_SetupItem_EnhancedRelocCompleteReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhancedRelocCompleteRes, create_dissector_handle(dissect_RAB_SetupList_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhancedRelocCompleteRes, create_dissector_handle(dissect_RAB_SetupItem_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhRelocInfoReq, create_dissector_handle(dissect_RAB_SetupList_EnhRelocInfoReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhRelocInfoReq, create_dissector_handle(dissect_RAB_SetupItem_EnhRelocInfoReq_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupList_EnhRelocInfoRes, create_dissector_handle(dissect_RAB_SetupList_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_SetupItem_EnhRelocInfoRes, create_dissector_handle(dissect_RAB_SetupItem_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConId, create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedList_EnhRelocInfoRes, create_dissector_handle(dissect_RAB_FailedList_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_FailedItem_EnhRelocInfoRes, create_dissector_handle(dissect_RAB_FailedItem_EnhRelocInfoRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConIdCS, create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_OldIuSigConIdPS, create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_IDCS, create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes, create_dissector_handle(dissect_RAB_ToBeReleasedItem_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_RAB_ToBeReleasedList_EnhancedRelocCompleteRes, create_dissector_handle(dissect_RAB_ToBeReleasedList_EnhancedRelocCompleteRes_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_TargetRNC_ID, create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_TargetExtendedRNC_ID, create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf, create_dissector_handle(dissect_Alt_RAB_Parameter_SupportedGuaranteedBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Alt_RAB_Parameter_SupportedMaxBitrateInf, create_dissector_handle(dissect_Alt_RAB_Parameter_SupportedMaxBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_SourceRNC_ID, create_dissector_handle(dissect_GlobalRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_Relocation_SourceExtendedRNC_ID, create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_EncryptionKey, create_dissector_handle(dissect_EncryptionKey_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_IntegrityProtectionKey, create_dissector_handle(dissect_IntegrityProtectionKey_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SRVCC_Information, create_dissector_handle(dissect_SRVCC_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_GlobalCN_IDPS, create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_VoiceSupportMatchIndicator, create_dissector_handle(dissect_VoiceSupportMatchIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_SGSN_Group_Identity, create_dissector_handle(dissect_SGSN_Group_Identity_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_P_TMSI, create_dissector_handle(dissect_P_TMSI_PDU, proto_ranap));
  dissector_add_uint("ranap.ies", id_UE_Usage_Type, create_dissector_handle(dissect_UE_Usage_Type_PDU, proto_ranap));
  dissector_add_uint("ranap.ies.pair.first", id_RAB_SetupOrModifyItem, create_dissector_handle(dissect_RAB_SetupOrModifyItemFirst_PDU, proto_ranap));
  dissector_add_uint("ranap.ies.pair.second", id_RAB_SetupOrModifyItem, create_dissector_handle(dissect_RAB_SetupOrModifyItemSecond_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AlternativeRABConfiguration, create_dissector_handle(dissect_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf, create_dissector_handle(dissect_Alt_RAB_Parameter_ExtendedGuaranteedBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameter_ExtendedMaxBitrateInf, create_dissector_handle(dissect_Alt_RAB_Parameter_ExtendedMaxBitrateInf_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList, create_dissector_handle(dissect_Ass_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_ExtendedMaxBitrateList, create_dissector_handle(dissect_Ass_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MessageStructure, create_dissector_handle(dissect_MessageStructure_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TypeOfError, create_dissector_handle(dissect_TypeOfError_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAC, create_dissector_handle(dissect_RAC_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_newLAListofIdleModeUEs, create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LAListwithNoIdleModeUEsAnyMore, create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GANSS_PositioningDataSet, create_dissector_handle(dissect_GANSS_PositioningDataSet_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SignallingIndication, create_dissector_handle(dissect_SignallingIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_ExtendedGuaranteedBitrateList, create_dissector_handle(dissect_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_ExtendedMaxBitrateList, create_dissector_handle(dissect_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CN_DomainIndicator, create_dissector_handle(dissect_CN_DomainIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LAofIdleModeUEs, create_dissector_handle(dissect_LAListofIdleModeUEs_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AlternativeRABConfigurationRequest, create_dissector_handle(dissect_AlternativeRABConfigurationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_ExtendedMaxBitrateList, create_dissector_handle(dissect_Requested_RAB_Parameter_ExtendedMaxBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList, create_dissector_handle(dissect_Requested_RAB_Parameter_ExtendedGuaranteedBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ExtendedRNC_ID, create_dissector_handle(dissect_ExtendedRNC_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRB_TrCH_Mapping, create_dissector_handle(dissect_SRB_TrCH_Mapping_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CellLoadInformationGroup, create_dissector_handle(dissect_CellLoadInformationGroup_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TraceRecordingSessionInformation, create_dissector_handle(dissect_TraceRecordingSessionInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSLinkingInformation, create_dissector_handle(dissect_MBMSLinkingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_hS_DSCH_MAC_d_Flow_ID, create_dissector_handle(dissect_HS_DSCH_MAC_d_Flow_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_E_DCH_MAC_d_Flow_ID, create_dissector_handle(dissect_E_DCH_MAC_d_Flow_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_Classmark, create_dissector_handle(dissect_GERAN_Classmark_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SourceBSS_ToTargetBSS_TransparentContainer, create_dissector_handle(dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TransportLayerAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IuTransportAssociation, create_dissector_handle(dissect_IuTransportAssociation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_InterSystemInformation_TransparentContainer, create_dissector_handle(dissect_ranap_InterSystemInformation_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TargetBSS_ToSourceBSS_TransparentContainer, create_dissector_handle(dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Alt_RAB_Parameters, create_dissector_handle(dissect_Alt_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_BSC_Container, create_dissector_handle(dissect_GERAN_BSC_Container_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GlobalCN_ID, create_dissector_handle(dissect_GlobalCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SNA_Access_Information, create_dissector_handle(dissect_SNA_Access_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UESBI_Iu, create_dissector_handle(dissect_UESBI_Iu_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SelectedPLMN_ID, create_dissector_handle(dissect_PLMNidentity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CNMBMSLinkingInformation, create_dissector_handle(dissect_CNMBMSLinkingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameters, create_dissector_handle(dissect_Ass_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_NewBSS_To_OldBSS_Information, create_dissector_handle(dissect_NewBSS_To_OldBSS_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAT_Type, create_dissector_handle(dissect_RAT_Type_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TracePropagationParameters, create_dissector_handle(dissect_TracePropagationParameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_VerticalAccuracyCode, create_dissector_handle(dissect_VerticalAccuracyCode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ResponseTime, create_dissector_handle(dissect_ResponseTime_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositioningPriority, create_dissector_handle(dissect_PositioningPriority_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_ClientType, create_dissector_handle(dissect_ClientType_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IncludeVelocity, create_dissector_handle(dissect_IncludeVelocity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PeriodicLocationInfo, create_dissector_handle(dissect_PeriodicLocationInfo_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LastKnownServiceArea, create_dissector_handle(dissect_LastKnownServiceArea_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositionData, create_dissector_handle(dissect_PositionData_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PositionDataSpecificToGERANIuMode, create_dissector_handle(dissect_PositionDataSpecificToGERANIuMode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AccuracyFulfilmentIndicator, create_dissector_handle(dissect_AccuracyFulfilmentIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_VelocityEstimate, create_dissector_handle(dissect_VelocityEstimate_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PermanentNAS_UE_ID, create_dissector_handle(dissect_PermanentNAS_UE_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_NAS_SequenceNumber, create_dissector_handle(dissect_NAS_SequenceNumber_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectAttemptFlag, create_dissector_handle(dissect_RedirectAttemptFlag_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectionIndication, create_dissector_handle(dissect_RedirectionIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RedirectionCompleted, create_dissector_handle(dissect_RedirectionCompleted_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SourceRNC_PDCP_context_info, create_dissector_handle(dissect_RRC_Container_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_GERAN_Iumode_RAB_FailedList_RABAssgntResponse, create_dissector_handle(dissect_GERAN_Iumode_RAB_FailedList_RABAssgntResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LocationRelatedDataRequestTypeSpecificToGERANIuMode, create_dissector_handle(dissect_LocationRelatedDataRequestTypeSpecificToGERANIuMode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RequestedGANSSAssistanceData, create_dissector_handle(dissect_RequestedGANSSAssistanceData_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSCountingInformation, create_dissector_handle(dissect_MBMSCountingInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_History_Information, create_dissector_handle(dissect_UE_History_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MBMSSynchronisationInformation, create_dissector_handle(dissect_MBMSSynchronisationInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SubscriberProfileIDforRFP, create_dissector_handle(dissect_SubscriberProfileIDforRFP_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Id, create_dissector_handle(dissect_CSG_Id_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_SupportedGuaranteedBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Ass_RAB_Parameter_SupportedMaxBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_SupportedGuaranteedBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RAB_Parameter_SupportedMaxBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_SupportedMaxBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Requested_RAB_Parameter_SupportedGuaranteedBitrateList, create_dissector_handle(dissect_SupportedRAB_ParameterBitrateList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRVCC_HO_Indication, create_dissector_handle(dissect_SRVCC_HO_Indication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SRVCC_Operation_Possible, create_dissector_handle(dissect_SRVCC_Operation_Possible_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Id_List, create_dissector_handle(dissect_CSG_Id_List_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PSRABtobeReplaced, create_dissector_handle(dissect_RAB_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_E_UTRAN_Service_Handover, create_dissector_handle(dissect_E_UTRAN_Service_Handover_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_AggregateMaximumBitRate, create_dissector_handle(dissect_UE_AggregateMaximumBitRate_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSG_Membership_Status, create_dissector_handle(dissect_CSG_Membership_Status_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Cell_Access_Mode, create_dissector_handle(dissect_Cell_Access_Mode_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IP_Source_Address, create_dissector_handle(dissect_IPMulticastAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CSFB_Information, create_dissector_handle(dissect_CSFB_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PDP_TypeInformation_extension, create_dissector_handle(dissect_PDP_TypeInformation_extension_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MSISDN, create_dissector_handle(dissect_MSISDN_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Offload_RAB_Parameters, create_dissector_handle(dissect_Offload_RAB_Parameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LGW_TransportLayerAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Correlation_ID, create_dissector_handle(dissect_Correlation_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IRAT_Measurement_Configuration, create_dissector_handle(dissect_IRAT_Measurement_Configuration_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_MDT_Configuration, create_dissector_handle(dissect_MDT_Configuration_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Priority_Class_Indicator, create_dissector_handle(dissect_Priority_Class_Indicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RNSAPRelocationParameters, create_dissector_handle(dissect_RNSAPRelocationParameters_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RABParametersList, create_dissector_handle(dissect_RABParametersList_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Management_Based_MDT_Allowed, create_dissector_handle(dissect_Management_Based_MDT_Allowed_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_HigherBitratesThan16MbpsFlag, create_dissector_handle(dissect_HigherBitratesThan16MbpsFlag_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Trace_Collection_Entity_IP_Addess, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_End_Of_CSFB, create_dissector_handle(dissect_End_Of_CSFB_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Time_UE_StayedInCell_EnhancedGranularity, create_dissector_handle(dissect_Time_UE_StayedInCell_EnhancedGranularity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Out_Of_UTRAN, create_dissector_handle(dissect_Out_Of_UTRAN_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TraceRecordingSessionReference, create_dissector_handle(dissect_TraceRecordingSessionReference_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IMSI, create_dissector_handle(dissect_IMSI_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_HO_Cause, create_dissector_handle(dissect_ranap_Cause_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RSRVCC_HO_Indication, create_dissector_handle(dissect_RSRVCC_HO_Indication_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RSRVCC_Information, create_dissector_handle(dissect_RSRVCC_Information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_AnchorPLMN_ID, create_dissector_handle(dissect_PLMNidentity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Tunnel_Information_for_BBF, create_dissector_handle(dissect_TunnelInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Management_Based_MDT_PLMN_List, create_dissector_handle(dissect_MDT_PLMN_List_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SignallingBasedMDTPLMNList, create_dissector_handle(dissect_MDT_PLMN_List_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_M4Report, create_dissector_handle(dissect_M4Report_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_M5Report, create_dissector_handle(dissect_M5Report_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_M6Report, create_dissector_handle(dissect_M6Report_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_M7Report, create_dissector_handle(dissect_M7Report_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_TimingDifferenceULDL, create_dissector_handle(dissect_TimingDifferenceULDL_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Serving_Cell_Identifier, create_dissector_handle(dissect_UTRAN_CellID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_EARFCN_Extended, create_dissector_handle(dissect_EARFCN_Extended_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RSRVCC_Operation_Possible, create_dissector_handle(dissect_RSRVCC_Operation_Possible_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SIPTO_LGW_TransportLayerAddress, create_dissector_handle(dissect_TransportLayerAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_SIPTO_Correlation_ID, create_dissector_handle(dissect_Correlation_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LHN_ID, create_dissector_handle(dissect_LHN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Session_Re_establishment_Indicator, create_dissector_handle(dissect_Session_Re_establishment_Indicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_LastE_UTRANPLMNIdentity, create_dissector_handle(dissect_PLMNidentity_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RSRQ_Type, create_dissector_handle(dissect_RSRQ_Type_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_RSRQ_Extension, create_dissector_handle(dissect_RSRQ_Extension_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Additional_CSPS_coordination_information, create_dissector_handle(dissect_Additional_CSPS_coordination_information_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UERegistrationQueryResult, create_dissector_handle(dissect_UERegistrationQueryResult_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_IuSigConIdRangeEnd, create_dissector_handle(dissect_IuSignallingConnectionIdentifier_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_BarometricPressure, create_dissector_handle(dissect_BarometricPressure_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_Additional_PositioningDataSet, create_dissector_handle(dissect_Additional_PositioningDataSet_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_CivicAddress, create_dissector_handle(dissect_CivicAddress_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_PowerSavingIndicator, create_dissector_handle(dissect_PowerSavingIndicator_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_DCN_ID, create_dissector_handle(dissect_DCN_ID_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_Application_Layer_Measurement_Configuration, create_dissector_handle(dissect_UE_Application_Layer_Measurement_Configuration_PDU, proto_ranap));
  dissector_add_uint("ranap.extension", id_UE_Application_Layer_Measurement_Configuration_For_Relocation, create_dissector_handle(dissect_UE_Application_Layer_Measurement_Configuration_For_Relocation_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Iu_Release, create_dissector_handle(dissect_Iu_ReleaseCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_Iu_Release, create_dissector_handle(dissect_Iu_ReleaseComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationPreparation, create_dissector_handle(dissect_RelocationRequired_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationPreparation, create_dissector_handle(dissect_RelocationCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_RelocationPreparation, create_dissector_handle(dissect_RelocationPreparationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationResourceAllocation, create_dissector_handle(dissect_RelocationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationResourceAllocation, create_dissector_handle(dissect_RelocationRequestAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_RelocationResourceAllocation, create_dissector_handle(dissect_RelocationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationCancel, create_dissector_handle(dissect_RelocationCancel_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RelocationCancel, create_dissector_handle(dissect_RelocationCancelAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRNS_ContextTransfer, create_dissector_handle(dissect_SRNS_ContextRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_SRNS_ContextTransfer, create_dissector_handle(dissect_SRNS_ContextResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SecurityModeControl, create_dissector_handle(dissect_SecurityModeCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_SecurityModeControl, create_dissector_handle(dissect_SecurityModeComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_SecurityModeControl, create_dissector_handle(dissect_SecurityModeReject_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DataVolumeReport, create_dissector_handle(dissect_DataVolumeReportRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_DataVolumeReport, create_dissector_handle(dissect_DataVolumeReport_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_Reset, create_dissector_handle(dissect_ResetAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_ReleaseRequest, create_dissector_handle(dissect_RAB_ReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Iu_ReleaseRequest, create_dissector_handle(dissect_Iu_ReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationDetect, create_dissector_handle(dissect_RelocationDetect_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RelocationComplete, create_dissector_handle(dissect_RelocationComplete_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_Paging, create_dissector_handle(dissect_Paging_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CommonID, create_dissector_handle(dissect_CommonID_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CN_InvokeTrace, create_dissector_handle(dissect_CN_InvokeTrace_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_CN_DeactivateTrace, create_dissector_handle(dissect_CN_DeactivateTrace_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationReportingControl, create_dissector_handle(dissect_LocationReportingControl_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationReport, create_dissector_handle(dissect_LocationReport_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_InitialUE_Message, create_dissector_handle(dissect_InitialUE_Message_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DirectTransfer, create_dissector_handle(dissect_DirectTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_OverloadControl, create_dissector_handle(dissect_Overload_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRNS_DataForward, create_dissector_handle(dissect_SRNS_DataForwardCommand_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ForwardSRNS_Context, create_dissector_handle(dissect_ForwardSRNS_Context_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_Assignment, create_dissector_handle(dissect_RAB_AssignmentRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_RAB_Assignment, create_dissector_handle(dissect_RAB_AssignmentResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_ResetResource, create_dissector_handle(dissect_ResetResource_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_ResetResource, create_dissector_handle(dissect_ResetResourceAcknowledge_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RANAP_Relocation, create_dissector_handle(dissect_RANAP_RelocationInformation_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RAB_ModifyRequest, create_dissector_handle(dissect_RAB_ModifyRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_LocationRelatedData, create_dissector_handle(dissect_LocationRelatedDataRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_LocationRelatedData, create_dissector_handle(dissect_LocationRelatedDataResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_LocationRelatedData, create_dissector_handle(dissect_LocationRelatedDataFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_InformationTransfer, create_dissector_handle(dissect_InformationTransferIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_InformationTransfer, create_dissector_handle(dissect_InformationTransferConfirmation_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_InformationTransfer, create_dissector_handle(dissect_InformationTransferFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UESpecificInformation, create_dissector_handle(dissect_UESpecificInformationIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_DirectInformationTransfer, create_dissector_handle(dissect_DirectInformationTransfer_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UplinkInformationExchange, create_dissector_handle(dissect_UplinkInformationExchangeRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_UplinkInformationExchange, create_dissector_handle(dissect_UplinkInformationExchangeResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_UplinkInformationExchange, create_dissector_handle(dissect_UplinkInformationExchangeFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionStart, create_dissector_handle(dissect_MBMSSessionStart_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionStart, create_dissector_handle(dissect_MBMSSessionStartResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSSessionStart, create_dissector_handle(dissect_MBMSSessionStartFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionUpdate, create_dissector_handle(dissect_MBMSSessionUpdate_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionUpdate, create_dissector_handle(dissect_MBMSSessionUpdateResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSSessionUpdate, create_dissector_handle(dissect_MBMSSessionUpdateFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSSessionStop, create_dissector_handle(dissect_MBMSSessionStop_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSSessionStop, create_dissector_handle(dissect_MBMSSessionStopResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSUELinking, create_dissector_handle(dissect_MBMSUELinkingRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_MBMSUELinking, create_dissector_handle(dissect_MBMSUELinkingResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRegistration, create_dissector_handle(dissect_MBMSRegistrationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSRegistration, create_dissector_handle(dissect_MBMSRegistrationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSRegistration, create_dissector_handle(dissect_MBMSRegistrationFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSCNDe_Registration_Procedure, create_dissector_handle(dissect_MBMSCNDe_RegistrationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSCNDe_Registration_Procedure, create_dissector_handle(dissect_MBMSCNDe_RegistrationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRABEstablishmentIndication, create_dissector_handle(dissect_MBMSRABEstablishmentIndication_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_MBMSRABRelease, create_dissector_handle(dissect_MBMSRABReleaseRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_MBMSRABRelease, create_dissector_handle(dissect_MBMSRABRelease_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_MBMSRABRelease, create_dissector_handle(dissect_MBMSRABReleaseFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_enhancedRelocationComplete, create_dissector_handle(dissect_EnhancedRelocationCompleteRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_enhancedRelocationComplete, create_dissector_handle(dissect_EnhancedRelocationCompleteResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.uout", id_enhancedRelocationComplete, create_dissector_handle(dissect_EnhancedRelocationCompleteFailure_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_enhancedRelocationCompleteConfirm, create_dissector_handle(dissect_EnhancedRelocationCompleteConfirm_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RANAPenhancedRelocation, create_dissector_handle(dissect_RANAP_EnhancedRelocationInformationRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.sout", id_RANAPenhancedRelocation, create_dissector_handle(dissect_RANAP_EnhancedRelocationInformationResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_SRVCCPreparation, create_dissector_handle(dissect_SRVCC_CSKeysRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_SRVCCPreparation, create_dissector_handle(dissect_SRVCC_CSKeysResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UeRadioCapabilityMatch, create_dissector_handle(dissect_UeRadioCapabilityMatchRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_UeRadioCapabilityMatch, create_dissector_handle(dissect_UeRadioCapabilityMatchResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_UeRegistrationQuery, create_dissector_handle(dissect_UeRegistrationQueryRequest_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.out", id_UeRegistrationQuery, create_dissector_handle(dissect_UeRegistrationQueryResponse_PDU, proto_ranap));
  dissector_add_uint("ranap.proc.imsg", id_RerouteNASRequest, create_dissector_handle(dissect_RerouteNASRequest_PDU, proto_ranap));


}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
