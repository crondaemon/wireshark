/* packet-per.h
 * Routines for dissection of ASN.1 Aligned PER
 * 2003  Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_PER_H__
#define __PACKET_PER_H__

#include "ws_symbol_export.h"

typedef int (*per_type_fn)(tvbuff_t*, int, asn1_ctx_t*, proto_tree*, int);

/* in all functions here, offset is uint32_t and is
   byteposition<<3 + bitposition
*/

/* value for value and size constraints */
#define NO_BOUND -1


/* values for extensions */
#define ASN1_NO_EXTENSIONS	0
#define ASN1_EXTENSION_ROOT	    ASN1_EXT_ROOT
#define ASN1_NOT_EXTENSION_ROOT	ASN1_EXT_EXT

/* value for optional */
#define ASN1_NOT_OPTIONAL	0
#define ASN1_OPTIONAL		ASN1_OPT

typedef struct _per_choice_t {
	int value;
	const int *p_id;
	int extension;
	per_type_fn func;
} per_choice_t;

typedef struct _per_sequence_t {
	const int *p_id;
	int extension;
	int optional;
	per_type_fn func;
} per_sequence_t;

WS_DLL_PUBLIC void dissect_per_not_decoded_yet(proto_tree* tree, packet_info* pinfo, tvbuff_t *tvb, const char* reason);

WS_DLL_PUBLIC uint32_t dissect_per_null(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

WS_DLL_PUBLIC uint32_t dissect_per_GeneralString(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

WS_DLL_PUBLIC uint32_t dissect_per_sequence_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const per_sequence_t *seq);

WS_DLL_PUBLIC uint32_t dissect_per_IA5String(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_NumericString(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_PrintableString(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_VisibleString(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_BMPString(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension);

WS_DLL_PUBLIC uint32_t dissect_per_UTF8String(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension);

extern uint32_t dissect_per_object_descriptor(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_constrained_sequence_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const per_sequence_t *seq, int min_len, int max_len, bool has_extension);

WS_DLL_PUBLIC uint32_t dissect_per_constrained_set_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const per_sequence_t *seq, int min_len, int max_len, bool has_extension);

WS_DLL_PUBLIC uint32_t dissect_per_set_of(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const per_sequence_t *seq);

WS_DLL_PUBLIC uint32_t dissect_per_object_identifier(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
WS_DLL_PUBLIC uint32_t dissect_per_object_identifier_str(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

WS_DLL_PUBLIC uint32_t dissect_per_relative_oid(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, tvbuff_t **value_tvb);
WS_DLL_PUBLIC uint32_t dissect_per_relative_oid_str(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, const char **value_stringx);

WS_DLL_PUBLIC uint32_t dissect_per_boolean(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, bool *bool_val);

WS_DLL_PUBLIC uint32_t dissect_per_integer(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int32_t *value);
WS_DLL_PUBLIC uint32_t dissect_per_integer64b(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int64_t *value);
WS_DLL_PUBLIC uint32_t dissect_per_constrained_integer(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, uint32_t min, uint32_t max, uint32_t *value, bool has_extension);
WS_DLL_PUBLIC uint32_t dissect_per_constrained_integer_64b(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, uint64_t min, uint64_t max, uint64_t *value, bool has_extension);

WS_DLL_PUBLIC uint32_t dissect_per_real(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, double *value);

WS_DLL_PUBLIC uint32_t dissect_per_choice(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int ett_index, const per_choice_t *choice, int *value);

WS_DLL_PUBLIC uint32_t dissect_per_sequence(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *parent_tree, int hf_index, int ett_index, const per_sequence_t *sequence);
WS_DLL_PUBLIC uint32_t dissect_per_sequence_eag(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, const per_sequence_t *sequence);

WS_DLL_PUBLIC uint32_t dissect_per_octet_string(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, tvbuff_t **value_tvb);
WS_DLL_PUBLIC uint32_t dissect_per_octet_string_containing_pdu_new(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, dissector_t type_cb);

WS_DLL_PUBLIC uint32_t dissect_per_bit_string(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, int * const *named_bits, int num_named_bits, tvbuff_t **value_tvb, int *len);

WS_DLL_PUBLIC uint32_t dissect_per_bit_string_containing_pdu_new(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, bool has_extension, dissector_t type_cb);

WS_DLL_PUBLIC uint32_t dissect_per_restricted_character_string(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len,  bool has_extension, const char *alphabet, int alphabet_length, tvbuff_t **value_tvb);

WS_DLL_PUBLIC uint32_t dissect_per_enumerated(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, uint32_t root_num, uint32_t *value, bool has_extension, uint32_t ext_num, uint32_t *value_map);

WS_DLL_PUBLIC uint32_t dissect_per_open_type(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb);
WS_DLL_PUBLIC uint32_t dissect_per_open_type_pdu_new(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, dissector_t type_cb);

WS_DLL_PUBLIC uint32_t dissect_per_external_type(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb);

WS_DLL_PUBLIC uint32_t dissect_per_size_constrained_type(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, per_type_fn type_cb, const char *name, int min_len, int max_len, bool has_extension);
extern bool get_size_constraint_from_stack(asn1_ctx_t *actx, const char *name, int *pmin_len, int *pmax_len, bool *phas_extension);

extern uint32_t dissect_per_length_determinant(tvbuff_t *tvb, uint32_t offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index, uint32_t *length, bool *is_fragmented);

WS_DLL_PUBLIC int call_per_oid_callback(const char *oid, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, asn1_ctx_t *actx, int hf_index);
WS_DLL_PUBLIC void add_per_encoded_label(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree);

/* Used by custom dissector */
WS_DLL_PUBLIC void register_per_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name);

#endif  /* __PACKET_PER_H__ */
