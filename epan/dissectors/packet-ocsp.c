/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ocsp.c                                                              */
/* asn2wrs.py -b -q -L -p ocsp -c ./ocsp.cnf -s ./packet-ocsp-template -D . -O ../.. OCSP.asn */

/* packet-ocsp.c
 * Routines for Online Certificate Status Protocol (RFC2560) packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/array.h>

#include <asn1.h>

#include "packet-ber.h"
#include "packet-ocsp.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"

#define PNAME  "Online Certificate Status Protocol"
#define PSNAME "OCSP"
#define PFNAME "ocsp"

void proto_register_ocsp(void);
void proto_reg_handoff_ocsp(void);

static dissector_handle_t ocsp_request_handle;
static dissector_handle_t ocsp_response_handle;

/* Initialize the protocol and registered fields */
int proto_ocsp;
static int hf_ocsp_responseType_id;
static int hf_ocsp_BasicOCSPResponse_PDU;         /* BasicOCSPResponse */
static int hf_ocsp_ArchiveCutoff_PDU;             /* ArchiveCutoff */
static int hf_ocsp_AcceptableResponses_PDU;       /* AcceptableResponses */
static int hf_ocsp_ServiceLocator_PDU;            /* ServiceLocator */
static int hf_ocsp_CrlID_PDU;                     /* CrlID */
static int hf_ocsp_ReOcspNonce_PDU;               /* ReOcspNonce */
static int hf_ocsp_NULL_PDU;                      /* NULL */
static int hf_ocsp_tbsRequest;                    /* TBSRequest */
static int hf_ocsp_optionalSignature;             /* Signature */
static int hf_ocsp_version;                       /* Version */
static int hf_ocsp_requestorName;                 /* GeneralName */
static int hf_ocsp_requestList;                   /* SEQUENCE_OF_Request */
static int hf_ocsp_requestList_item;              /* Request */
static int hf_ocsp_requestExtensions;             /* Extensions */
static int hf_ocsp_signatureAlgorithm;            /* AlgorithmIdentifier */
static int hf_ocsp_signature;                     /* BIT_STRING */
static int hf_ocsp_certs;                         /* SEQUENCE_OF_Certificate */
static int hf_ocsp_certs_item;                    /* Certificate */
static int hf_ocsp_reqCert;                       /* CertID */
static int hf_ocsp_singleRequestExtensions;       /* Extensions */
static int hf_ocsp_hashAlgorithm;                 /* AlgorithmIdentifier */
static int hf_ocsp_issuerNameHash;                /* OCTET_STRING */
static int hf_ocsp_issuerKeyHash;                 /* OCTET_STRING */
static int hf_ocsp_serialNumber;                  /* CertificateSerialNumber */
static int hf_ocsp_responseStatus;                /* OCSPResponseStatus */
static int hf_ocsp_responseBytes;                 /* ResponseBytes */
static int hf_ocsp_responseType;                  /* T_responseType */
static int hf_ocsp_response;                      /* T_response */
static int hf_ocsp_tbsResponseData;               /* ResponseData */
static int hf_ocsp_responderID;                   /* ResponderID */
static int hf_ocsp_producedAt;                    /* GeneralizedTime */
static int hf_ocsp_responses;                     /* SEQUENCE_OF_SingleResponse */
static int hf_ocsp_responses_item;                /* SingleResponse */
static int hf_ocsp_responseExtensions;            /* Extensions */
static int hf_ocsp_byName;                        /* Name */
static int hf_ocsp_byKey;                         /* KeyHash */
static int hf_ocsp_certID;                        /* CertID */
static int hf_ocsp_certStatus;                    /* CertStatus */
static int hf_ocsp_thisUpdate;                    /* GeneralizedTime */
static int hf_ocsp_nextUpdate;                    /* GeneralizedTime */
static int hf_ocsp_singleExtensions;              /* Extensions */
static int hf_ocsp_good;                          /* NULL */
static int hf_ocsp_revoked;                       /* RevokedInfo */
static int hf_ocsp_unknown;                       /* UnknownInfo */
static int hf_ocsp_revocationTime;                /* GeneralizedTime */
static int hf_ocsp_revocationReason;              /* CRLReason */
static int hf_ocsp_AcceptableResponses_item;      /* OBJECT_IDENTIFIER */
static int hf_ocsp_issuer;                        /* Name */
static int hf_ocsp_locator;                       /* AuthorityInfoAccessSyntax */
static int hf_ocsp_crlUrl;                        /* IA5String */
static int hf_ocsp_crlNum;                        /* INTEGER */
static int hf_ocsp_crlTime;                       /* GeneralizedTime */

/* Initialize the subtree pointers */
static int ett_ocsp;
static int ett_ocsp_OCSPRequest;
static int ett_ocsp_TBSRequest;
static int ett_ocsp_SEQUENCE_OF_Request;
static int ett_ocsp_Signature;
static int ett_ocsp_SEQUENCE_OF_Certificate;
static int ett_ocsp_Request;
static int ett_ocsp_CertID;
static int ett_ocsp_OCSPResponse;
static int ett_ocsp_ResponseBytes;
static int ett_ocsp_BasicOCSPResponse;
static int ett_ocsp_ResponseData;
static int ett_ocsp_SEQUENCE_OF_SingleResponse;
static int ett_ocsp_ResponderID;
static int ett_ocsp_SingleResponse;
static int ett_ocsp_CertStatus;
static int ett_ocsp_RevokedInfo;
static int ett_ocsp_AcceptableResponses;
static int ett_ocsp_ServiceLocator;
static int ett_ocsp_CrlID;



static int
dissect_ocsp_Version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ocsp_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CertID_sequence[] = {
  { &hf_ocsp_hashAlgorithm  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_issuerNameHash , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCTET_STRING },
  { &hf_ocsp_issuerKeyHash  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCTET_STRING },
  { &hf_ocsp_serialNumber   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertID_sequence, hf_index, ett_ocsp_CertID);

  return offset;
}


static const ber_sequence_t Request_sequence[] = {
  { &hf_ocsp_reqCert        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_CertID },
  { &hf_ocsp_singleRequestExtensions, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Request_sequence, hf_index, ett_ocsp_Request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Request_sequence_of[1] = {
  { &hf_ocsp_requestList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_Request },
};

static int
dissect_ocsp_SEQUENCE_OF_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Request_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Request);

  return offset;
}


static const ber_sequence_t TBSRequest_sequence[] = {
  { &hf_ocsp_version        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Version },
  { &hf_ocsp_requestorName  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_GeneralName },
  { &hf_ocsp_requestList    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SEQUENCE_OF_Request },
  { &hf_ocsp_requestExtensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_TBSRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TBSRequest_sequence, hf_index, ett_ocsp_TBSRequest);

  return offset;
}



static int
dissect_ocsp_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Certificate_sequence_of[1] = {
  { &hf_ocsp_certs_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
};

static int
dissect_ocsp_SEQUENCE_OF_Certificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Certificate_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Certificate);

  return offset;
}


static const ber_sequence_t Signature_sequence[] = {
  { &hf_ocsp_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_signature      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_BIT_STRING },
  { &hf_ocsp_certs          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_SEQUENCE_OF_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_Signature(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_ocsp_Signature);

  return offset;
}


static const ber_sequence_t OCSPRequest_sequence[] = {
  { &hf_ocsp_tbsRequest     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_TBSRequest },
  { &hf_ocsp_optionalSignature, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Signature },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_OCSPRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCSPRequest_sequence, hf_index, ett_ocsp_OCSPRequest);

  return offset;
}


static const value_string ocsp_OCSPResponseStatus_vals[] = {
  {   0, "successful" },
  {   1, "malformedRequest" },
  {   2, "internalError" },
  {   3, "tryLater" },
  {   5, "sigRequired" },
  {   6, "unauthorized" },
  { 0, NULL }
};


static int
dissect_ocsp_OCSPResponseStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ocsp_T_responseType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_ocsp_responseType_id, &actx->external.direct_reference);

  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}



static int
dissect_ocsp_T_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int8_t appclass;
  bool pc, ind;
  int32_t tag;
  uint32_t len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &appclass, &pc, &tag);
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
  if (actx->external.direct_ref_present) {
    offset = call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);
  }


  return offset;
}


static const ber_sequence_t ResponseBytes_sequence[] = {
  { &hf_ocsp_responseType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ocsp_T_responseType },
  { &hf_ocsp_response       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_T_response },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseBytes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResponseBytes_sequence, hf_index, ett_ocsp_ResponseBytes);

  return offset;
}


static const ber_sequence_t OCSPResponse_sequence[] = {
  { &hf_ocsp_responseStatus , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCSPResponseStatus },
  { &hf_ocsp_responseBytes  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_ResponseBytes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_ocsp_OCSPResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCSPResponse_sequence, hf_index, ett_ocsp_OCSPResponse);

  return offset;
}



static int
dissect_ocsp_KeyHash(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ocsp_ResponderID_vals[] = {
  {   1, "byName" },
  {   2, "byKey" },
  { 0, NULL }
};

static const ber_choice_t ResponderID_choice[] = {
  {   1, &hf_ocsp_byName         , BER_CLASS_CON, 1, 0, dissect_pkix1explicit_Name },
  {   2, &hf_ocsp_byKey          , BER_CLASS_CON, 2, 0, dissect_ocsp_KeyHash },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponderID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ResponderID_choice, hf_index, ett_ocsp_ResponderID,
                                 NULL);

  return offset;
}



static int
dissect_ocsp_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ocsp_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t RevokedInfo_sequence[] = {
  { &hf_ocsp_revocationTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_revocationReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509ce_CRLReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_RevokedInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevokedInfo_sequence, hf_index, ett_ocsp_RevokedInfo);

  return offset;
}



static int
dissect_ocsp_UnknownInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string ocsp_CertStatus_vals[] = {
  {   0, "good" },
  {   1, "revoked" },
  {   2, "unknown" },
  { 0, NULL }
};

static const ber_choice_t CertStatus_choice[] = {
  {   0, &hf_ocsp_good           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ocsp_NULL },
  {   1, &hf_ocsp_revoked        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ocsp_RevokedInfo },
  {   2, &hf_ocsp_unknown        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ocsp_UnknownInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertStatus_choice, hf_index, ett_ocsp_CertStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SingleResponse_sequence[] = {
  { &hf_ocsp_certID         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_CertID },
  { &hf_ocsp_certStatus     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ocsp_CertStatus },
  { &hf_ocsp_thisUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_nextUpdate     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_singleExtensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_SingleResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SingleResponse_sequence, hf_index, ett_ocsp_SingleResponse);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SingleResponse_sequence_of[1] = {
  { &hf_ocsp_responses_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SingleResponse },
};

static int
dissect_ocsp_SEQUENCE_OF_SingleResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SingleResponse_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_SingleResponse);

  return offset;
}


static const ber_sequence_t ResponseData_sequence[] = {
  { &hf_ocsp_version        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Version },
  { &hf_ocsp_responderID    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ocsp_ResponderID },
  { &hf_ocsp_producedAt     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_responses      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SEQUENCE_OF_SingleResponse },
  { &hf_ocsp_responseExtensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResponseData_sequence, hf_index, ett_ocsp_ResponseData);

  return offset;
}


static const ber_sequence_t BasicOCSPResponse_sequence[] = {
  { &hf_ocsp_tbsResponseData, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_ResponseData },
  { &hf_ocsp_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_signature      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_BIT_STRING },
  { &hf_ocsp_certs          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_SEQUENCE_OF_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_BasicOCSPResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BasicOCSPResponse_sequence, hf_index, ett_ocsp_BasicOCSPResponse);

  return offset;
}



static int
dissect_ocsp_ArchiveCutoff(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ocsp_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AcceptableResponses_sequence_of[1] = {
  { &hf_ocsp_AcceptableResponses_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ocsp_OBJECT_IDENTIFIER },
};

static int
dissect_ocsp_AcceptableResponses(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AcceptableResponses_sequence_of, hf_index, ett_ocsp_AcceptableResponses);

  return offset;
}


static const ber_sequence_t ServiceLocator_sequence[] = {
  { &hf_ocsp_issuer         , BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Name },
  { &hf_ocsp_locator        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_AuthorityInfoAccessSyntax },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ServiceLocator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceLocator_sequence, hf_index, ett_ocsp_ServiceLocator);

  return offset;
}



static int
dissect_ocsp_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ocsp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CrlID_sequence[] = {
  { &hf_ocsp_crlUrl         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_IA5String },
  { &hf_ocsp_crlNum         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_ocsp_INTEGER },
  { &hf_ocsp_crlTime        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_ocsp_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CrlID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CrlID_sequence, hf_index, ett_ocsp_CrlID);

  return offset;
}



static int
dissect_ocsp_ReOcspNonce(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BasicOCSPResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_BasicOCSPResponse(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_BasicOCSPResponse_PDU);
  return offset;
}
static int dissect_ArchiveCutoff_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_ArchiveCutoff(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_ArchiveCutoff_PDU);
  return offset;
}
static int dissect_AcceptableResponses_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_AcceptableResponses(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_AcceptableResponses_PDU);
  return offset;
}
static int dissect_ServiceLocator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_ServiceLocator(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_ServiceLocator_PDU);
  return offset;
}
static int dissect_CrlID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_CrlID(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_CrlID_PDU);
  return offset;
}
static int dissect_ReOcspNonce_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_ReOcspNonce(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_ReOcspNonce_PDU);
  return offset;
}
static int dissect_NULL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ocsp_NULL(false, tvb, offset, &asn1_ctx, tree, hf_ocsp_NULL_PDU);
  return offset;
}



static int
dissect_ocsp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Request");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPRequest(false, tvb, 0, &asn1_ctx, tree, -1);
}


static int
dissect_ocsp_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Response");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPResponse(false, tvb, 0, &asn1_ctx, tree, -1);
}

/*--- proto_register_ocsp ----------------------------------------------*/
void proto_register_ocsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ocsp_responseType_id,
      { "ResponseType Id", "ocsp.responseType.id",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_BasicOCSPResponse_PDU,
      { "BasicOCSPResponse", "ocsp.BasicOCSPResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_ArchiveCutoff_PDU,
      { "ArchiveCutoff", "ocsp.ArchiveCutoff",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_AcceptableResponses_PDU,
      { "AcceptableResponses", "ocsp.AcceptableResponses",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_ServiceLocator_PDU,
      { "ServiceLocator", "ocsp.ServiceLocator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_CrlID_PDU,
      { "CrlID", "ocsp.CrlID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_ReOcspNonce_PDU,
      { "ReOcspNonce", "ocsp.ReOcspNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_NULL_PDU,
      { "NULL", "ocsp.NULL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_tbsRequest,
      { "tbsRequest", "ocsp.tbsRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_optionalSignature,
      { "optionalSignature", "ocsp.optionalSignature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Signature", HFILL }},
    { &hf_ocsp_version,
      { "version", "ocsp.version",
        FT_INT32, BASE_DEC, VALS(pkix1explicit_Version_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_requestorName,
      { "requestorName", "ocsp.requestorName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_ocsp_requestList,
      { "requestList", "ocsp.requestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Request", HFILL }},
    { &hf_ocsp_requestList_item,
      { "Request", "ocsp.Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_requestExtensions,
      { "requestExtensions", "ocsp.requestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_signatureAlgorithm,
      { "signatureAlgorithm", "ocsp.signatureAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_ocsp_signature,
      { "signature", "ocsp.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_ocsp_certs,
      { "certs", "ocsp.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Certificate", HFILL }},
    { &hf_ocsp_certs_item,
      { "Certificate", "ocsp.Certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_reqCert,
      { "reqCert", "ocsp.reqCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertID", HFILL }},
    { &hf_ocsp_singleRequestExtensions,
      { "singleRequestExtensions", "ocsp.singleRequestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_hashAlgorithm,
      { "hashAlgorithm", "ocsp.hashAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_ocsp_issuerNameHash,
      { "issuerNameHash", "ocsp.issuerNameHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ocsp_issuerKeyHash,
      { "issuerKeyHash", "ocsp.issuerKeyHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ocsp_serialNumber,
      { "serialNumber", "ocsp.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_ocsp_responseStatus,
      { "responseStatus", "ocsp.responseStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_OCSPResponseStatus_vals), 0,
        "OCSPResponseStatus", HFILL }},
    { &hf_ocsp_responseBytes,
      { "responseBytes", "ocsp.responseBytes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_responseType,
      { "responseType", "ocsp.responseType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_response,
      { "response", "ocsp.response",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_tbsResponseData,
      { "tbsResponseData", "ocsp.tbsResponseData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResponseData", HFILL }},
    { &hf_ocsp_responderID,
      { "responderID", "ocsp.responderID",
        FT_UINT32, BASE_DEC, VALS(ocsp_ResponderID_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_producedAt,
      { "producedAt", "ocsp.producedAt",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_responses,
      { "responses", "ocsp.responses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SingleResponse", HFILL }},
    { &hf_ocsp_responses_item,
      { "SingleResponse", "ocsp.SingleResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_responseExtensions,
      { "responseExtensions", "ocsp.responseExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_byName,
      { "byName", "ocsp.byName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_ocsp_byKey,
      { "byKey", "ocsp.byKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyHash", HFILL }},
    { &hf_ocsp_certID,
      { "certID", "ocsp.certID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_certStatus,
      { "certStatus", "ocsp.certStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_CertStatus_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_thisUpdate,
      { "thisUpdate", "ocsp.thisUpdate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_nextUpdate,
      { "nextUpdate", "ocsp.nextUpdate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_singleExtensions,
      { "singleExtensions", "ocsp.singleExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_good,
      { "good", "ocsp.good_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_revoked,
      { "revoked", "ocsp.revoked_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevokedInfo", HFILL }},
    { &hf_ocsp_unknown,
      { "unknown", "ocsp.unknown_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnknownInfo", HFILL }},
    { &hf_ocsp_revocationTime,
      { "revocationTime", "ocsp.revocationTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_revocationReason,
      { "revocationReason", "ocsp.revocationReason",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        "CRLReason", HFILL }},
    { &hf_ocsp_AcceptableResponses_item,
      { "AcceptableResponses item", "ocsp.AcceptableResponses_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ocsp_issuer,
      { "issuer", "ocsp.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_ocsp_locator,
      { "locator", "ocsp.locator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorityInfoAccessSyntax", HFILL }},
    { &hf_ocsp_crlUrl,
      { "crlUrl", "ocsp.crlUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_ocsp_crlNum,
      { "crlNum", "ocsp.crlNum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ocsp_crlTime,
      { "crlTime", "ocsp.crlTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ocsp,
    &ett_ocsp_OCSPRequest,
    &ett_ocsp_TBSRequest,
    &ett_ocsp_SEQUENCE_OF_Request,
    &ett_ocsp_Signature,
    &ett_ocsp_SEQUENCE_OF_Certificate,
    &ett_ocsp_Request,
    &ett_ocsp_CertID,
    &ett_ocsp_OCSPResponse,
    &ett_ocsp_ResponseBytes,
    &ett_ocsp_BasicOCSPResponse,
    &ett_ocsp_ResponseData,
    &ett_ocsp_SEQUENCE_OF_SingleResponse,
    &ett_ocsp_ResponderID,
    &ett_ocsp_SingleResponse,
    &ett_ocsp_CertStatus,
    &ett_ocsp_RevokedInfo,
    &ett_ocsp_AcceptableResponses,
    &ett_ocsp_ServiceLocator,
    &ett_ocsp_CrlID,
  };

  /* Register protocol */
  proto_ocsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ocsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissectors */
  ocsp_request_handle = register_dissector_with_description(PFNAME "_req", PSNAME " Request", dissect_ocsp_request, proto_ocsp);
  ocsp_response_handle = register_dissector_with_description(PFNAME "_res", PSNAME " Response", dissect_ocsp_response, proto_ocsp);
}

/*--- proto_reg_handoff_ocsp -------------------------------------------*/
void proto_reg_handoff_ocsp(void) {
	dissector_add_string("media_type", "application/ocsp-request", ocsp_request_handle);
	dissector_add_string("media_type", "application/ocsp-response", ocsp_response_handle);

  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.1", dissect_BasicOCSPResponse_PDU, proto_ocsp, "id-pkix-ocsp-basic");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.2", dissect_ReOcspNonce_PDU, proto_ocsp, "id-pkix-ocsp-nonce");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.3", dissect_CrlID_PDU, proto_ocsp, "id-pkix-ocsp-crl");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.4", dissect_AcceptableResponses_PDU, proto_ocsp, "id-pkix-ocsp-response");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.5", dissect_NULL_PDU, proto_ocsp, "id-pkix-ocsp-nocheck");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.6", dissect_ArchiveCutoff_PDU, proto_ocsp, "id-pkix-ocsp-archive-cutoff");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.7", dissect_ServiceLocator_PDU, proto_ocsp, "id-pkix-ocsp-service-locator");

}

