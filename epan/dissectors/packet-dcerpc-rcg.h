/* DO NOT EDIT
	This file was automatically generated by Pidl
	from rcg.idl and rcg.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files.
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be
	found at https://wiki.wireshark.org/Pidl
*/

#ifndef __PACKET_DCERPC_RCG_H
#define __PACKET_DCERPC_RCG_H

int rcg_dissect_struct_KERB_ASN1_DATA(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_ASN1_DATA_CHECKSUM(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_RPC_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_RPC_PA_DATA(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_RPC_ENCRYPTION_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_RPC_UNICODE_STRING(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_RPC_INTERNAL_NAME(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
#define RemoteCallKerbNegotiateVersion (0x100)
#define RemoteCallKerbBuildAsReqAuthenticator (0x101)
#define RemoteCallKerbVerifyServiceTicket (0x102)
#define RemoteCallKerbCreateApReqAuthenticator (0x103)
#define RemoteCallKerbDecryptApReply (0x104)
#define RemoteCallKerbUnpackKdcReplyBody (0x105)
#define RemoteCallKerbComputeTgsChecksum (0x106)
#define RemoteCallKerbBuildEncryptedAuthData (0x107)
#define RemoteCallKerbPackApReply (0x108)
#define RemoteCallKerbHashS4UPreauth (0x109)
#define RemoteCallKerbSignS4UPreauthData (0x10a)
#define RemoteCallKerbVerifyChecksum (0x10b)
#define RemoteCallKerbDecryptPacCredentials (0x113)
#define RemoteCallKerbCreateECDHKeyAgreement (0x114)
#define RemoteCallKerbCreateDHKeyAgreement (0x115)
#define RemoteCallKerbDestroyKeyAgreement (0x116)
#define RemoteCallKerbKeyAgreementGenerateNonce (0x117)
#define RemoteCallKerbFinalizeKeyAgreement (0x118)
#define RemoteCallNtlmNegotiateVersion (0x200)
#define RemoteCallNtlmLm20GetNtlm3ChallengeResponse (0x201)
#define RemoteCallNtlmCalculateNtResponse (0x202)
#define RemoteCallNtlmCalculateUserSessionKeyNt (0x203)
#define RemoteCallNtlmCompareCredentials (0x204)
extern const value_string rcg_RemoteGuardCallId_vals[];
int rcg_dissect_enum_RemoteGuardCallId(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint16_t *param _U_);
int rcg_dissect_struct_SECPKG_SUPPLEMENTAL_CRED(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_SECPKG_SUPPLEMENTAL_CRED_ARRAY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PSECPKG_SUPPLEMENTAL_CRED_ARRAY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KERB_RPC_CRYPTO_API_BLOB(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_NegotiateVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_LARGE_INTEGER(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PLARGE_INTEGER(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_BuildAsReqAuthenticatorReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_BuildAsReqAuthenticatorResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_VerifyServiceTicketReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_VerifyServiceTicketResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PRPC_UNICODE_STRING(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateApReqAuthenticatorReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateApReqAuthenticatorResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DecryptApReplyReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DecryptApReplyResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_UnpackKdcReplyBodyReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_UnpackKdcReplyBodyResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_ComputeTgsChecksumReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_ComputeTgsChecksumResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_BuildEncryptedAuthDataReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_BuildEncryptedAuthDataResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PackApReplyReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PackApReplyResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_HashS4UPreauthReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_HashS4UPreauthResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_SignS4UPreauthDataReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_SignS4UPreauthDataResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_VerifyChecksumReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_VerifyChecksumResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DecryptPacCredentialsReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DecryptPacCredentialsResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateECDHKeyAgreementReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateECDHKeyAgreementResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateDHKeyAgreementReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CreateDHKeyAgreementResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DestroyKeyAgreementReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_DestroyKeyAgreementResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KeyAgreementGenerateNonceReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KeyAgreementGenerateNonceResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_FinalizeKeyAgreementReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_FinalizeKeyAgreementResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KerbCredIsoRemoteInput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_KerbCredIsoRemoteOutput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_NT_RESPONSE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_NT_CHALLENGE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PNT_CHALLENGE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_LM_SESSION_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_MSV1_0_LM3_RESPONSE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PMSV1_0_LM3_RESPONSE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_USER_SESSION_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PUSER_SESSION_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_MSV1_0_CREDENTIAL_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PMSV1_0_CREDENTIAL_KEY(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_MSV1_0_REMOTE_ENCRYPTED_SECRETS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_PMSV1_0_REMOTE_ENCRYPTED_SECRETS(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_Lm20GetNtlm3ChallengeResponseReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_Lm20GetNtlm3ChallengeResponseResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CalculateNtResponseReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CalculateNtResponseResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CalculateUserSessionKeyNtReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CalculateUserSessionKeyNtResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CompareCredentialsReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_CompareCredentialsResp(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_NtlmCredIsoRemoteInput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int rcg_dissect_struct_NtlmCredIsoRemoteOutput(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
#endif /* __PACKET_DCERPC_RCG_H */
