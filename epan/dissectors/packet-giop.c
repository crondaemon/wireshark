/* packet-giop.c
 * Routines for CORBA GIOP/IIOP packet disassembly
 *
 * Initial Code by,
 * Laurent Deniel <laurent.deniel@free.fr>
 * Craig Rodrigues <rodrigc@attbi.com>
 *
 * GIOP API extensions by,
 * Frank Singleton <frank.singleton@ericsson.com>
 * Trevor Shepherd <eustrsd@am1.ericsson.se>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*
 * TODO: -- FS
 * 1. heuristic giop dissector table [started]
 * 2. GUI options, see 20
 * 3. Remove unnecessary reply_status in heuristic dissector calls (now
 *    part of MessageHeader) [done]
 * 4. get_CDR_xxx should be passed an alignment offset value
 *    rather than GIOP_HEADER_SIZE, as alignment can also change in a
 *    octet stream when eg: encapsulation is used [done]
 * 5. GIOP users should eventually get there own tvbuff, and
 *    not rely on the GIOP tvbuff, more robust
 * 6. get_CDR_string, wchar, wstring etc should handle different
 *    GIOP versions [started]

 *
 * 8. Keep request_1_2 in step with request_1_1 [started]
 * 9. Explicit module name dissection [done]
 * 10. Decode IOR and put in a useful struct [IOR decode started]
 * 11. Fix encapsulation of IOR etc and boundary [done]
 * 12. handle get_CDR_typeCode() [started]
 * 13. Handle different IOR profiles
 * 14. Change printable_string to RETURN a new string, not to modify the old.
 *     or, new function, make_printable_string [done, make_printable_string]
 *
 * 15. Handle "TCKind", and forget about eg: enum translation to symbolic values
 *     otherwise need knowledge of sub dissectors data - YUK [done]
 * 16. Handle multiple RepoId representations, besides IDL:Echo:1.0 (see 13.)
 * 17. Pass subset of RepoID to explicit dissector.
 *     eg : If IDL:Mod1/Mod2/Int3:1.0 then pass "Mod1/Mode2/Int3" to sub dissector[done]
 * 18. Better hashing algorithms
 * 19. Handle hash collision properly .
 * 20. Allow users to paste a stringified IOR into the GUI, and tie it
 *     to a sub_dissector.
 * 21. Add complete_request_packet_list and complete_reply_packet_hash.[done]
 * 22. Handle case where users click in any order, AND try and match
 *     REPLY msg to the correct REQUEST msg when we have a request_id collision.[done]
 * 23. Clean up memory management for all those g_malloc's etc [done]
 * 24. register_giop_user_module could return a key for every distinct Module/Interface
 *     the sub_dissector uses. So, instead of strcmp()'s when  handling the
 *     namespace of an operation, we could have a lookup table instead.
 * 25. A few typedefs in the right place.
 * 26  Improve handling of char *  and use const char * where possible.
 * 27. Read/write IOR etc to/from file, allows objkey hash to be built from
 *     external data [read done, write incomplete]
 * 28. Call sub dissector only if tvb_offset_exists(). [Done, this is checked
 *     inside try_explicit_giop_dissector() ]
 *
 * 29. Make add/delete routine for objkey hash as it may be useful when say reading
 *     stringified IOR's from a file to add them to our hash. ie: There are other ways
 *     to populate our object key hash besides REPLY's to RESOLVE(request) [done]
 *
 * 30. Add routine to encode/decode stringified IOR's [decode done]
 * 31. Add routine to read IOR's from file [done]
 * 32. TypeCode -none-, needs decoding.
 * 33. Complete dissect_data_for_typecode.
 * 34. For complex TypeCodes need to check final offset against original offset + sequence length.
 * 35. Update REQUEST/REPLY 1_2 according to IDL (eg; ServiceContextList etc).
 * 36. Adding decode_ServiceContextList, incomplete.
 * 37. Helper functions should not ALWAYS rely on header to find  current endianness. It should
 *     be passed from user, eg Use   stream_is_big_endian. [started]
 * 38. Remove unwanted/unused function parameters, see decode_IOR [started]
 * 40. Add sequence <IOP::TaggedComponent> components to IIOP IOR profile. Perhaps
 *     decode_IOP_TaggedComponents as a helper function. [done - NOT helper]
 *
 * 41. Make important field searchable from Message header. ie: Remove add_text_
 * 42. Use sub-tree for decode_ServiceContextList, looks better.
 * 43. dissect_reply_body, no exception dissector calls
 *       - call subdiss directly, as we already have handle.
 *       - add repoid to heuristic call also.
 *
 * 44. typedef using xxx_t in .h file.
 * 45. Subdissectors should not be passed MessageHeader to find endianness and
 *     version, they should be passed directly ?
 * 46. get_CDR_wchar and wstring need wide chars decoded (just dumped in
 *     any readable form at present, not handled well at all, suggestions welcome -- FS
 * 47. Change ...add_text to ...add_xxx (ie use hf fields).
 *
 * 48. BUG - file load with a GIOP filter set, causes the FN/MFN data struct to be
 *     not initiated properly. Hit "Reload" as a workaround, til I fix this -- FS
 *
 */



/*
 * Intended Decode strategy:
 * =========================
 *
 * Initial Pass
 * ------------
 * REQUEST: objkey -> Repo_ID -> Module/Interface -> giop_sub_handle_t
 *          and populate complete_request_packet_hash
 *
 * REPLY:   FN -> MFN (via complete_reply_packet_hash) = Request FN -> giop_sub_handle_t
 *
 * User Clicks
 * -----------
 *
 * REQUEST: FN -> giop_sub_handle_t directly (via complete_request_packet_hash)
 *
 * REPLY:   FN -> MFN (via complete_reply_packet_hash) = Request FN -> giop_sub_handle_t
 *                                                                     (via complete_request_packet_hash
 *
 *
 * Limitations.
 * ============
 *
 * 1. Request_ID's are unique only per connection.
 *
 * 2. You must be monitoring the network when the client does
 *    a REQUEST(resolve), otherwise I have no knowledge of the
 *    association between object_key and REPOID. I could talk to
 *    a Nameserver, but then I would start "generating" packets.
 *    This is probably not a good thing for a protocol analyser.
 *    Also, how could I decode logfiles offline.
 *
 *    TODO -- Read stringified IORs from an input file.[done]
 *
 * 3. User clicks (REQUEST) is currently handle the same as
 *    the initial pass handling.
 *
 *    ie: objkey -> Repo_ID -> Module/Interface -> giop_sub_handle_t
 */


/*
 * Important Data Structures:
 *
 * giop_module_hash
 * ----------------
 *
 * This is a hash table that maps IDL Module/Interface Names (Key)
 * to sub_dissector handles, giop_sub_handle_t. It is populated
 * by subdissectors, via register_giop_user_module(). This
 * table is used when we have a REPOID, and explicitly wish to
 * call the subdissector that has registered responsibility for
 * that IDL module/interface.
 *
 *
 * giop_sub_list
 * -------------
 *
 * This singly linked list is used to hold entries for
 * heuristic based subdissectors. It is populated by sub_dissectors
 * wishing to be called via heuristic mechanisms. They do this
 * via the register_giop_user() function.
 *
 *
 * giop_objkey_hash
 * ----------------
 *
 * This hash table maps object_key's (key) onto REPOID's (val).
 * Once a client has REQUEST(resolve) an object , it knows about
 * an object (interface) via its object_key (see IOR). So in order to follow
 * packets that contain an object_key only, and to be able to forward it
 * to the correct explicit subdissector, we need this table.
 *
 * So, I listen in on REQUEST(resolve) messages between client and
 * Nameserver, and store the respones (REPLY/Objkey, Repo_ID) here.
 *
 * Also, stringified IOR's can be read from a file, e.g. "IOR.txt", and used
 * to populate this hash also.
 *
 *
 * Other Data structures
 * =======================
 *
 * These structures have  been added to minimise the possibility
 * of incorrectly interpreted packets when people click all
 * over the place, in no particular order, when the request_id's are
 * not unique as captured. If all request_is'd are unique, as captured, then
 * we would not have to deal with this problem.
 *
 *
 * When the logfile or packets are initially being processed, I will
 * build 2 structures. The intent is to be able to map a REPLY message
 * back to the most recent REQUEST message with the same Request_ID
 * (TODO and matching port and IP address ??)
 *
 * Abbrevs:
 * --------
 *
 * FN  - Frame Number
 * MFN - Matching Frame Number
 *
 *
 * complete_request_packet_list
 * ----------------------------
 *
 * This is a list that contains ALL the FN's that are REQUEST's, along with
 * operation, request_id and giop_sub_handle_t
 *
 * complete_reply_packet_hash
 * --------------------------
 *
 * This is a hash table. It is populated with FN (key) and MFN (val).
 * This allows me to handle the case, where if you click on any REPLY
 * message, I can lookup the matching request. This can improve
 * the match rate between REQUEST and REPLY when people click in
 * any old fashion, but is NOT foolproof.
 *
 * The algorithm I use to populate this hash during initial pass,
 * is as follows.
 *
 * If packet is a REPLY, note the reqid, and then traverse backwards
 * through the complete_request_packet_list from its tail, looking
 * for a FN that has the same Request_id. Once found, take the found FN
 * from complete_reply_packet_hash, and insert it into the MFN field
 * of the complete_reply_packet_hash.
 *
 *
 * See TODO for improvements to above algorithm.
 *
 * So now when people click on a REQUEST packet, I can call lookup the
 * giop_sub_handle_t directly from complete_request_packet_list.
 *
 * And, when they click on a REPLY, I grab the MFN of this FN from
 * complete_reply_packet_hash, then look that up in the complete_request_packet_list
 * and call the sub_dissector directly.
 *
 * So, how do I differentiate between the initial processing of incoming
 * packets, and a user clickin on one ? Good question.
 *
 * I leverage the pinfo_fd->visited  on a per frame
 * basis.
 *
 * To quote from the ever helpful development list
 *
 * " When a capture file is initially loaded, all "visited" flags
 * are 0. Wireshark then makes the first pass through file,
 * sequentially dissecting each packet. After the packet is
 * dissected the first time, "visited" is 1. (See the end of
 * dissect_packet() in epan/packet.c; that's the code that
 * sets "visited" to 1).

 * By the time a user clicks on a packet, "visited" will already
 * be 1 because Wireshark will have already done its first pass
 * through the packets.

 * Reload acts just like a normal Close/Open, except that it
 * doesn't need to ask for a filename. So yes, the reload button
 * clears the flags and re-dissects the file, just as if the file
 * had been "opened".  "
 *
 */


#define WS_LOG_DOMAIN "packet-giop"
#include "config.h"
#include <wireshark.h>

#include <errno.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/tfs.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include <wsutil/pint.h>
#include <wsutil/report_message.h>

#include "packet-giop.h"
#include "packet-ziop.h"
#include "packet-tcp.h"

void proto_register_giop(void);
void proto_reg_handoff_giop(void);

#define GIOP_MAX_RECURSION_DEPTH 100 // Arbitrary

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Private Helper function Declarations
 * ------------------------------------------------------------------------------------------+
 */


static void decode_IIOP_IOR_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    uint32_t boundary, bool new_endianness,
                                    const char *repobuf,
                                    bool store_flag);

static void decode_TaggedProfile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                 uint32_t boundary, bool stream_is_big_endian, const char *repobuf);

static void decode_IOR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                       uint32_t boundary, bool stream_is_big_endian );

static void decode_SystemExceptionReplyBody (tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                             bool stream_is_big_endian,
                                             uint32_t boundary);

/* Process a sequence of octets that represent the
 * Pseudo Object Type "TypeCode". Typecodes are used for example,
 * by "Any values".
 * This function also increments offset to the correct position.
 *
 * It will parse the TypeCode and output data to the "tree" provided
 * by the user
 *
 * It provides the parameters of the TypeCode as a doubly linked list via
 * the out parameter "parameterlist", this is needed for dissecting the data
 * of complex data types such as struct
 *
 * It returns a uint32_t representing a TCKind value.
 *
 * TODO: maybe making this into a public function, to have the parameter list available outside
 */
static uint32_t get_CDR_typeCode_with_params(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
                         int *offset, bool stream_is_big_endian,
                         int boundary, MessageHeader * header,
                         wmem_list_t *parameterlist);

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Data/Variables/Structs
 * ------------------------------------------------------------------------------------------+
 */

static int giop_tap;
static int proto_giop;
static int hf_giop_message_magic;
static int hf_giop_message_major_version;
static int hf_giop_message_minor_version;
static int hf_giop_message_flags;
static int hf_giop_message_flags_ziop_enabled;
static int hf_giop_message_flags_ziop_supported;
static int hf_giop_message_flags_fragment;
static int hf_giop_message_flags_little_endian;
static int hf_giop_message_type;
static int hf_giop_message_size;
static int hf_giop_repoid;
static int hf_giop_req_id;
static int hf_giop_req_operation_len;
static int hf_giop_req_operation;
static int hf_giop_req_principal_len;
static int hf_giop_req_principal;
static int hf_giop_string_length;
static int hf_giop_sequence_length;
static int hf_giop_profile_id;
static int hf_giop_type_id;
static int hf_giop_type_id_match;
static int hf_giop_iiop_v_maj;
static int hf_giop_iiop_v_min;
static int hf_giop_endianness; /* esp encapsulations */
/* static int hf_giop_compressed; */
/* static int hf_giop_IOR_tag; */
static int hf_giop_IIOP_tag;
static int hf_giop_locale_status;
static int hf_giop_addressing_disposition;
static int hf_giop_profile_data;
static int hf_giop_component_data;
static int hf_giop_char_data;
static int hf_giop_wchar_data;
static int hf_giop_rt_corba_priority;
static int hf_giop_context_data;
static int hf_giop_target_address_discriminant;
static int hf_giop_target_address_key_addr_len;
static int hf_giop_target_address_key_addr;
static int hf_giop_target_address_ref_addr_len;

static int hf_giop_TCKind;
static int hf_giop_typecode_count;
static int hf_giop_typecode_default_used;
static int hf_giop_typecode_digits;
static int hf_giop_typecode_length;
static int hf_giop_typecode_max_length;
static int hf_giop_typecode_member_name;
static int hf_giop_typecode_name;
static int hf_giop_typecode_scale;
static int hf_giop_typecode_ValueModifier;
static int hf_giop_typecode_Visibility;

static int hf_giop_type_boolean;
static int hf_giop_type_char;
static int hf_giop_type_double;
static int hf_giop_type_enum;
static int hf_giop_type_float;
static int hf_giop_type_long;
static int hf_giop_type_longlong;
static int hf_giop_type_ulonglong;
static int hf_giop_type_octet;
static int hf_giop_type_short;
static int hf_giop_type_string;
static int hf_giop_type_ulong;
static int hf_giop_type_ushort;

static int hf_giop_iiop_host;
static int hf_giop_iiop_port;
static int hf_giop_iiop_sc;
static int hf_giop_iiop_sc_vscid;
static int hf_giop_iiop_sc_omg_scid;
static int hf_giop_iiop_sc_vendor_scid;

static int hf_giop_reply_status;
static int hf_giop_exception_id;
static int hf_giop_exception_len;
static int hf_giop_objekt_key;
static int hf_giop_rsp_expected;
static int hf_giop_response_flag;
static int hf_giop_reserved;
static int hf_giop_objekt_key_len;
static int hf_giop_type_id_len;
static int hf_giop_stub_data;
static int hf_giop_address_disp;
static int hf_giop_reply_body;
static int hf_giop_minor_code_value;
static int hf_giop_completion_status;

/*
 * (sub)Tree declares
 */

static int ett_giop;
static int ett_giop_header;
static int ett_giop_header_version;
static int ett_giop_message_flags;
static int ett_giop_reply;
static int ett_giop_request;
static int ett_giop_cancel_request;
static int ett_giop_locate_request;
static int ett_giop_locate_reply;
static int ett_giop_fragment;

static int ett_giop_scl;  /* ServiceContextList */
static int ett_giop_sc;   /* ServiceContext */
static int ett_giop_ior;  /* IOR  */

// for complex data types like arrays, structs, sequences
static int ett_giop_array;
static int ett_giop_sequence;
static int ett_giop_struct;
static int ett_giop_typecode_parameters;

static int ett_giop_fragments;
static int ett_giop_fragment_;


static int hf_giop_fragments;
static int hf_giop_fragment;
static int hf_giop_fragment_overlap;
static int hf_giop_fragment_overlap_conflict;
static int hf_giop_fragment_multiple_tails;
static int hf_giop_fragment_too_long_fragment;
static int hf_giop_fragment_error;
static int hf_giop_fragment_count;
static int hf_giop_reassembled_in;
static int hf_giop_reassembled_length;


static const fragment_items giop_frag_items = {
    &ett_giop_fragment_,
    &ett_giop_fragments,
    &hf_giop_fragments,
    &hf_giop_fragment,
    &hf_giop_fragment_overlap,
    &hf_giop_fragment_overlap_conflict,
    &hf_giop_fragment_multiple_tails,
    &hf_giop_fragment_too_long_fragment,
    &hf_giop_fragment_error,
    &hf_giop_fragment_count,
    &hf_giop_reassembled_in,
    &hf_giop_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

/*
 * Reassembly of GIOP.
 */
static reassembly_table giop_reassembly_table;


static expert_field ei_giop_unknown_typecode_datatype;
static expert_field ei_giop_unknown_sign_value;
static expert_field ei_giop_unknown_tckind;
static expert_field ei_giop_length_too_big;
static expert_field ei_giop_version_not_supported;
static expert_field ei_giop_message_size_too_big;
static expert_field ei_giop_invalid_v_minor;
static expert_field ei_giop_max_recursion_depth_reached;
static expert_field ei_giop_offset_error;


static int * const giop_message_flags[] = {
  &hf_giop_message_flags_ziop_enabled,
  &hf_giop_message_flags_ziop_supported,
  &hf_giop_message_flags_fragment,
  &hf_giop_message_flags_little_endian,
  NULL
};

static dissector_handle_t giop_tcp_handle;

#define GIOP_MESSAGE_FLAGS_ZIOP_ENABLED   0x08
#define GIOP_MESSAGE_FLAGS_ZIOP_SUPPORTED 0x04
#define GIOP_MESSAGE_FLAGS_FRAGMENT       0x02
#define GIOP_MESSAGE_FLAGS_ENDIANNESS     0x01

/* GIOP endianness */

static const value_string giop_endianness_vals[] = {
  { 0x0, "Big Endian" },
  { 0x1, "Little Endian" },
  { 0, NULL}
};

static const value_string target_address_discriminant_vals[] = {
  { 0x0, "KeyAddr" },
  { 0x1, "ProfileAddr" },
  { 0x2, "ReferenceAddr" },
  { 0, NULL}
};

/*
  static const value_string sync_scope[] = {
  { 0x0, "SYNC_NONE" },
  { 0x1, "SYNC_WITH_TRANSPORT"},
  { 0x2, "SYNC_WITH_SERVER"},
  { 0x3, "SYNC_WITH_TARGET"},
  { 0, NULL}
  };
Bug fix:
https://gitlab.com/wireshark/wireshark/-/issues/2800
*/
static const value_string response_flags_vals[] = {
  { 0x0, "SyncScope NONE or WITH_TRANSPORT" },
  { 0x1, "SyncScope WITH_SERVER"},
  { 0x3, "SyncScope WITH_TARGET"},
  { 0, NULL}
};

/* Profile ID's */

static const value_string profile_id_vals[] = {
  { 0x0, "TAG_INTERNET_IOP" },
  { 0x1, "TAG_MULTIPLE_COMPONENTS"},
  { 0x2, "TAG_SCCP_IOP"},
  { 0x3, "TAG_UIPMC"},
  { 0, NULL}
};

static const value_string giop_message_types[] = {
  { 0x0, "Request" },
  { 0x1, "Reply"},
  { 0x2, "CancelRequest"},
  { 0x3, "LocateRequest"},
  { 0x4, "LocateReply"},
  { 0x5, "CloseConnection"},
  { 0x6, "MessageError"},
  { 0x7, "Fragment"},
  { 0, NULL}
};

static const value_string giop_locate_status_types[] = {
  { 0x0, "Unknown Object" },
  { 0x1, "Object Here"},
  { 0x2, "Object Forward"},
  { 0x3, "Object Forward Perm"},
  { 0x4, "Loc System Exception"},
  { 0x5, "Loc Needs Addressing Mode"},
  { 0, NULL }
};

static const value_string tckind_vals[] = {
  {  0, "tk_null"},
  {  1, "tk_void"},
  {  2, "tk_short"},
  {  3, "tk_long"},
  {  4, "tk_ushort"},
  {  5, "tk_ulong"},
  {  6, "tk_float"},
  {  7, "tk_double"},
  {  8, "tk_boolean"},
  {  9, "tk_char"},
  { 10, "tk_octet"},
  { 11, "tk_any"},
  { 12, "tk_TypeCode"},
  { 13, "tk_Principal"},
  { 14, "tk_objref"},
  { 15, "tk_struct"},
  { 16, "tk_union"},
  { 17, "tk_enum"},
  { 18, "tk_string"},
  { 19, "tk_sequence"},
  { 20, "tk_array"},
  { 21, "tk_alias"},
  { 22, "tk_except"},
  { 23, "tk_longlong"},
  { 24, "tk_ulonglong"},
  { 25, "tk_longdouble"},
  { 26, "tk_wchar"},
  { 27, "tk_wstring"},
  { 28, "tk_fixed"},
  { 29, "tk_value"},
  { 30, "tk_value_box"},
  { 31, "tk_native"},
  { 32, "tk_abstract_interface"},
  { 0, NULL }
};

/*
 *  These values are taken from the CORBA 3.0.2 standard,
 *  section 13.7.1 "Standard Service Contexts".
 */
static const value_string service_context_ids[] = {
  { 0x00, "TransactionService" },
  { 0x01, "CodeSets"},
  { 0x02, "ChainBypassCheck"},
  { 0x03, "ChainBypassInfo"},
  { 0x04, "LogicalThreadId"},
  { 0x05, "BI_DIR_IIOP"},
  { 0x06, "SendingContextRunTime"},
  { 0x07, "INVOCATION_POLICIES"},
  { 0x08, "FORWARDED_IDENTITY"},
  { 0x09, "UnknownExceptionInfo"},
  { 0x0a, "RTCorbaPriority"},
  { 0x0b, "RTCorbaPriorityRange"},
  { 0x0c, "FT_GROUP_VERSION"},
  { 0x0d, "FT_REQUEST"},
  { 0x0e, "ExceptionDetailMessage"},
  { 0x0f, "SecurityAttributeService"},
  { 0x10, "ActivityService"},
  { 0, NULL }
};

/*
 *  From Section 13.10.2.5 of the CORBA 3.0 spec.
 *
 *   module CONV_FRAME {
 *     typedef unsigned long CodeSetId;
 *     struct CodeSetContext {
 *        CodeSetId  char_data;
 *        CodeSetId  wchar_data;
 *     };
 *   };
 *
 *   Code sets are identified by a 32-bit integer id from OSF.
 *   See:  ftp://ftp.opengroup.org/pub/code_set_registry
 */
static const value_string giop_code_set_vals[] = {
  { 0x00010001, "ISO_8859_1" },
  { 0x00010002, "ISO_8859_2" },
  { 0x00010003, "ISO_8859_3" },
  { 0x00010004, "ISO_8859_4" },
  { 0x00010005, "ISO_8859_5" },
  { 0x00010006, "ISO_8859_6" },
  { 0x00010007, "ISO_8859_7" },
  { 0x00010008, "ISO_8859_8" },
  { 0x00010009, "ISO_8859_9" },
  { 0x0001000A, "ISO_8859_10" },
  { 0x0001000F, "ISO_8859_15" },
  { 0x00010020, "ISO_646" },
  { 0x00010100, "ISO_UCS_2_LEVEL_1" },
  { 0x00010101, "ISO_UCS_2_LEVEL_2" },
  { 0x00010102, "ISO_UCS_2_LEVEL_3"  },
  { 0x00010104, "ISO_UCS_4_LEVEL_1" },
  { 0x00010105, "ISO_UCS_4_LEVEL_2" },
  { 0x00010106, "ISO_UCS_4_LEVEL_3" },
  { 0x00010108, "ISO_UTF_8" },
  { 0x00010109, "ISO_UTF_16" },
  { 0x00030001, "JIS_X0201" },
  { 0x00030004, "JIS_X0208_1978" },
  { 0x00030005, "JIS_X0208_1983" },
  { 0x00030006, "JIS_X0208_1990" },
  { 0x0003000A, "JIS_X0212" },
  { 0x00030010, "JIS_EUCJP" },
  { 0x00040001, "KS_C5601" },
  { 0x00040002, "KS_C5657" },
  { 0x0004000A, "KS_EUCKR" },
  { 0x00050001, "CNS_11643_1986" },
  { 0x00050002, "CNS_11643_1992" },
  { 0x0005000A, "CNS_EUCTW_1991" },
  { 0x00050010, "CNS_EUCTW_1993" },
  { 0x000B0001, "TIS_620_2529"  },
  { 0x000D0001, "TTB_CCDC" },
  { 0x05000010, "OSF_JAPANESE_UJIS" },
  { 0x05000011, "OSF_JAPANESE_SJIS_1" },
  { 0x05000012, "OSF_JAPANESE_SJIS_2" },
  { 0x05010001, "XOPEN_UTF_8" },
  { 0x05020001, "JVC_EUCJP" },
  { 0x05020002, "JVC_SJIS" },
  { 0x10000001, "DEC_KANJI" },
  { 0x10000002, "SUPER_DEC_KANJI" },
  { 0x10000003, "DEC_SHIFT_JIS" },
  { 0x10010001, "HP_ROMAN8" },
  { 0x10010002, "HP_KANA8" },
  { 0x10010003, "HP_ARABIC8" },
  { 0x10010004, "HP_GREEK8" },
  { 0x10010005, "HP_HEBREW8" },
  { 0x10010006, "HP_TURKISH8" },
  { 0x10010007, "HP15CN" },
  { 0x10010008, "HP_BIG5" },
  { 0x10010009, "HP_JAPANESE15__SJIS_" },
  { 0x1001000A, "HP_SJISHI" },
  { 0x1001000B, "HP_SJISPC" },
  { 0x1001000C, "HP_UJIS" },
  { 0x10020025, "IBM_037" },
  { 0x10020111, "IBM_273" },
  { 0x10020115, "IBM_277" },
  { 0x10020116, "IBM_278" },
  { 0x10020118, "IBM_280" },
  { 0x1002011A, "IBM_282" },
  { 0x1002011C, "IBM_284" },
  { 0x1002011D, "IBM_285" },
  { 0x10020122, "IBM_290" },
  { 0x10020129, "IBM_297" },
  { 0x1002012C, "IBM_300" },
  { 0x1002012D, "IBM_301" },
  { 0x100201A4, "IBM_420" },
  { 0x100201A8, "IBM_424" },
  { 0x100201B5, "IBM_437" },
  { 0x100201F4, "IBM_500" },
  { 0x10020341, "IBM_833" },
  { 0x10020342, "IBM_834" },
  { 0x10020343, "IBM_835" },
  { 0x10020344, "IBM_836" },
  { 0x10020345, "IBM_837" },
  { 0x10020346, "IBM_838" },
  { 0x10020347, "IBM_839" },
  { 0x10020352, "IBM_850" },
  { 0x10020354, "IBM_852" },
  { 0x10020357, "IBM_855" },
  { 0x10020358, "IBM_856" },
  { 0x10020359, "IBM_857" },
  { 0x1002035D, "IBM_861" },
  { 0x1002035E, "IBM_862" },
  { 0x1002035F, "IBM_863" },
  { 0x10020360, "IBM_864" },
  { 0x10020362, "IBM_866" },
  { 0x10020364, "IBM_868" },
  { 0x10020365, "IBM_869" },
  { 0x10020366, "IBM_870" },
  { 0x10020367, "IBM_871" },
  { 0x1002036A, "IBM_874" },
  { 0x1002036B, "IBM_875" },
  { 0x10020370, "IBM_880" },
  { 0x1002037B, "IBM_891" },
  { 0x10020380, "IBM_896" },
  { 0x10020381, "IBM_897" },
  { 0x10020387, "IBM_903" },
  { 0x10020388, "IBM_904" },
  { 0x10020396, "IBM_918" },
  { 0x10020399, "IBM_921" },
  { 0x1002039A, "IBM_922" },
  { 0x1002039E, "IBM_926" },
  { 0x1002039F, "IBM_927" },
  { 0x100203A0, "IBM_928" },
  { 0x100203A1, "IBM_929" },
  { 0x100203A2, "IBM_930" },
  { 0x100203A4, "IBM_932" },
  { 0x100203A5, "IBM_933" },
  { 0x100203A6, "IBM_934" },
  { 0x100203A7, "IBM_935" },
  { 0x100203A8, "IBM_936" },
  { 0x100203A9, "IBM_937" },
  { 0x100203AA, "IBM_938" },
  { 0x100203AB, "IBM_939" },
  { 0x100203AD, "IBM_941" },
  { 0x100203AE, "IBM_942" },
  { 0x100203AF, "IBM_943" },
  { 0x100203B2, "IBM_946" },
  { 0x100203B3, "IBM_947" },
  { 0x100203B4, "IBM_948" },
  { 0x100203B5, "IBM_949" },
  { 0x100203B6, "IBM_950" },
  { 0x100203B7, "IBM_951" },
  { 0x100203BB, "IBM_955" },
  { 0x100203C4, "IBM_964" },
  { 0x100203CA, "IBM_970" },
  { 0x100203EE, "IBM_1006" },
  { 0x10020401, "IBM_1025" },
  { 0x10020402, "IBM_1026" },
  { 0x10020403, "IBM_1027" },
  { 0x10020410, "IBM_1040" },
  { 0x10020411, "IBM_1041" },
  { 0x10020413, "IBM_1043" },
  { 0x10020416, "IBM_1046" },
  { 0x10020417, "IBM_1047" },
  { 0x10020440, "IBM_1088" },
  { 0x10020449, "IBM_1097" },
  { 0x1002044A, "IBM_1098" },
  { 0x10020458, "IBM_1112" },
  { 0x1002045A, "IBM_1114" },
  { 0x1002045B, "IBM_1115" },
  { 0x10020462, "IBM_1122" },
  { 0x100204E2, "IBM_1250" },
  { 0x100204E3, "IBM_1251" },
  { 0x100204E4, "IBM_1252" },
  { 0x100204E5, "IBM_1253" },
  { 0x100204E6, "IBM_1254" },
  { 0x100204E7, "IBM_1255" },
  { 0x100204E8, "IBM_1256" },
  { 0x100204E9, "IBM_1257" },
  { 0x10020564, "IBM_1380" },
  { 0x10020565, "IBM_1381" },
  { 0x10020567, "IBM_1383" },
  { 0x1002112C, "IBM_4396" },
  { 0x10021352, "IBM_4946" },
  { 0x10021354, "IBM_4948" },
  { 0x10021357, "IBM_4951" },
  { 0x10021358, "IBM_4952" },
  { 0x10021359, "IBM_4953" },
  { 0x10021360, "IBM_4960" },
  { 0x10021364, "IBM_4964" },
  { 0x10021365, "IBM_4965" },
  { 0x100213A2, "IBM_5026" },
  { 0x100213A7, "IBM_5031" },
  { 0x100213AB, "IBM_5035" },
  { 0x100213B8, "IBM_5048" },
  { 0x100213B9, "IBM_5049" },
  { 0x100213CB, "IBM_5067" },
  { 0x100221A4, "IBM_8612" },
  { 0x10022341, "IBM_9025" },
  { 0x10022342, "IBM_9026" },
  { 0x10022346, "IBM_9030" },
  { 0x10022360, "IBM_9056" },
  { 0x1002236A, "IBM_9066" },
  { 0x100223A5, "IBM_9125" },
  { 0x10026352, "IBM_25426" },
  { 0x10026358, "IBM_25432" },
  { 0x10026412, "IBM_1042" },
  { 0x10027025, "IBM_28709" },
  { 0x10028358, "IBM_33624" },
  { 0x100283BA, "IBM_33722" },
  { 0x10030001, "HTCSJIS" },
  { 0x10030002, "HTCUJIS" },
  { 0x10040001, "FUJITSU_U90" },
  { 0x10040002, "FUJITSU_S90" },
  { 0x10040003, "FUJITSU_R90" },
  { 0x10040004, "EBCDIC_ASCII_AND_JEF" },
  { 0x10040005, "EBCDIC_KATAKANA_AND_JEF" },
  { 0x10040006, "EBCDIC_JAPANESE_ENGLISH_AND_JEF" },
  { 0, NULL }
};

static value_string_ext giop_code_set_vals_ext = VALUE_STRING_EXT_INIT(giop_code_set_vals);


/*
 * TAGS for IOR Profiles
 *
 * Chapter 13 Corba 2.4.2
 *
 */

#define IOP_TAG_INTERNET_IOP          0
#define IOP_TAG_MULTIPLE_COMPONENTS   1


/* Max Supported versions */

static const unsigned GIOP_MAJOR =  1;
static const unsigned GIOP_MINOR =  2;

/* 10 MB  Used as a sanity check to ensure correct endian of message size field */
static unsigned giop_max_message_size = 10*1048576;


static const value_string reply_status_types[] = {
  { NO_EXCEPTION,          "No Exception" } ,
  { USER_EXCEPTION,        "User Exception" } ,
  { SYSTEM_EXCEPTION,      "System Exception" } ,
  { LOCATION_FORWARD,      "Location Forward" } ,
  { LOCATION_FORWARD_PERM, "Location Forward Perm" } ,
  { NEEDS_ADDRESSING_MODE, "Needs Addressing Mode" } ,
  { 0, NULL }
};

static const true_false_string tfs_matched_not_matched = { "Matched", "Not matched" };


typedef enum LocateStatusType
{
  UNKNOWN_OBJECT,
  OBJECT_HERE,
  OBJECT_FORWARD,
  OBJECT_FORWARD_PERM,      /* new value for GIOP 1.2 */
  LOC_SYSTEM_EXCEPTION,     /* new value for GIOP 1.2 */
  LOC_NEEDS_ADDRESSING_MODE /* new value for GIOP 1.2 */
}
LocateStatusType_t;

typedef struct LocateReplyHeader
{
  uint32_t request_id;
  uint32_t locate_status;
}
LocateReplyHeader_t;


/*
 * DATA - complete_request_list
 */

static GList *giop_complete_request_list;

struct comp_req_list_entry {
  uint32_t           fn;        /* frame number */
  char              *operation; /* echo echoString */
  giop_sub_handle_t *subh;      /* handle to sub dissector */
  uint32_t           reqid;     /* request id */
  char              *repoid;    /* repository ID */
  address            src;       /* source address */
  uint32_t           srcport;   /* source port */
};

typedef struct comp_req_list_entry comp_req_list_entry_t;


/*
 * DATA - complete_reply_hash
 *
 * Maps reply FN to request MFN
 */

struct complete_reply_hash_key {
  uint32_t fn;                   /* reply frame number  */
};

struct complete_reply_hash_val {
  uint32_t mfn;                  /* matching frame number (request)  */
};

GHashTable *giop_complete_reply_hash; /* hash */

/*
 * DATA - Module Hash stuff to store data from register_giop_user_module
 *
 * ie: module (or interface ?) name, and ptr to sub_dissector handle
 *
 * With this knowledge, we can call a sub dissector directly,
 * by :
 *
 * objkey -> repoid -> sub_dissector via registered module/interface
 *
 */


struct giop_module_key {
  const char *module;                /* module (interface?) name  */
};

struct giop_module_val {
  giop_sub_handle_t *subh;      /* handle to sub dissector */
};

GHashTable *giop_module_hash; /* hash */


/*
 * DATA - GSList to store list of function (dissector) pointers.
 * for heuristic dissection.
 *
 */

static GSList *giop_sub_list;

/*
 * DATA - Hash stuff to follow request/reply. This is so if we get a REPLY
 * to a REQUEST (resolve), we can dump/store the RepoId and Object Key.
 *
 * With this knowledge, we can call a sub dissector directly later
 * by :
 *
 * objkey -> repoid -> sub_dissector via registered module/interface
 *
 * rather than heuristic calls that do not provide operation context.
 * (unless we pass the RepoID for a given objkey -- hmmm)
 *
 */

/*
 * Interesting operation list, add more if you want to save
 * interesting data.
 */

static const char  giop_op_resolve[]          = "resolve";
#if 0
static const char  giop_op_bind_new_context[] = "bind_new_context";
static const char  giop_op_bind[]             = "bind";
#endif
static const char  giop_op_is_a[]             = "_is_a";

/*
 * Enums  for interesting local operations, that we may need to monitor
 * with their subsequent replies
 *
 */

enum giop_op_val {
  request_resolve_op_val,            /* REQUEST (resolve) to get RepoID etc*/
  request_bind_new_context_op_val,   /* bind_new_context */
  request_bind_op_val,               /* bind */
  request_get_INIT_op_val            /* finding Nameserver */

};


/*
 * hash for mapping object keys onto object namespaces, so
 * I can call the correct dissector.
 *
 *
 */

/*
 * Where did I get the IOR from.
 */

enum ior_src {
  ior_src_req_res = 0,                  /* REQUEST (resolve) */
  ior_src_file                          /* stringified IOR' in a file */

};

typedef enum ior_src ior_src_t;



/*
 * Enums for my lists and hash's
 */

enum collection_data {
  cd_heuristic_users = 0,
  cd_module_hash,
  cd_objkey_hash,
  cd_complete_request_list,
  cd_complete_reply_hash
};

typedef enum collection_data collection_data_t;



struct giop_object_key {
  const uint8_t *objkey;         /* ptr to object key */
  uint32_t      objkey_len;     /* length */
};

struct giop_object_val {
  char      *repo_id;           /* ptr to Repository ID string */
  ior_src_t  src;               /* where did Iget this IOR from */
};

GHashTable *giop_objkey_hash; /* hash */

/*
 * Data structure attached to a conversation.
 * It maintains a list of the header.message_type of each header.req_id, so that reassembled
 * fragments can be dissected correctly.
 */

typedef struct giop_conv_info_t {
  wmem_map_t *optypes;
} giop_conv_info_t;


static bool giop_desegment = true;
static bool giop_reassemble = true;
static const char *giop_ior_file;

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Private helper functions
 * ------------------------------------------------------------------------------------------+
 */




/*
 * Insert FN, reqid, operation and sub handle in list. DOES not check for duplicates yet.
 */

static GList *insert_in_comp_req_list(GList *list, uint32_t fn, uint32_t reqid, const char * op, giop_sub_handle_t *sh, address *addr, uint32_t port ) {
  comp_req_list_entry_t *entry;

  entry =  wmem_new(wmem_file_scope(), comp_req_list_entry_t);

  entry->fn        = fn;
  entry->reqid     = reqid;
  entry->subh      = sh;
  entry->operation = wmem_strdup(wmem_file_scope(), op); /* duplicate operation for storage */
  entry->repoid    = NULL;      /* don't have yet */
  entry->srcport   = port ;
  copy_address_wmem (wmem_file_scope (), &entry->src, addr) ;

  return g_list_append (list, entry); /* append */
}


/*
 * Used to find an entry with matching Frame Number FN
 * in the complete_request_list list.
 */

static comp_req_list_entry_t * find_fn_in_list(uint32_t fn) {

  GList                 *element;   /*  entry in list */
  comp_req_list_entry_t *entry_ptr;

  element = g_list_last(giop_complete_request_list); /* start from  last  */

  while (element) {                      /* valid list entry */
    entry_ptr = (comp_req_list_entry_t *)element->data;  /* grab data pointer */
    if (entry_ptr->fn == fn) {  /* similar FN  */
      return entry_ptr;
    }
    element = g_list_previous(element); /* try next previous */
  }

  return NULL;                  /* no match so return NULL */
}


/*
 * Add/update a sub_dissector handle and repoid to a FN entry in the complete_request_list
 *
 * Call this when you know a FN and matching giop_sub_handle_t and repoid
 *
 * This is done in say, try_explicit_dissector for example.
 *
 */

static void add_sub_handle_repoid_to_comp_req_list(uint32_t fn, giop_sub_handle_t *sh, char *repoid ) {

  comp_req_list_entry_t * entry = NULL;
  entry = find_fn_in_list(fn);  /* grab FN data entry */

  if (entry) {
    entry->subh = sh;
    entry->repoid = g_strdup(repoid); /* copy and store */

  }
}




/* giop_complete_reply_hash  "EQUAL" Functions */

static int complete_reply_equal_fn(const void *v, const void *w) {
  const struct complete_reply_hash_key *mk1 = (const struct complete_reply_hash_key *)v;
  const struct complete_reply_hash_key *mk2 = (const struct complete_reply_hash_key *)w;

  if (mk1->fn == mk2->fn) {
    return 1;
  }

  return 0;                     /* found  differences */
}

/* giop_complete_reply_hash "HASH" Functions */

static uint32_t complete_reply_hash_fn(const void *v) {
  uint32_t val;          /* init hash value */
  const struct complete_reply_hash_key *key = (const struct complete_reply_hash_key *)v;

  val = key->fn;                /* simple and unique */

  return val;
}


/*
 * Insert the FN and MFN together in our complete_reply_hash.
 */

static void insert_in_complete_reply_hash(uint32_t fn, uint32_t mfn) {

  struct complete_reply_hash_key key, *new_key;
  struct complete_reply_hash_val *val = NULL;

  key.fn = fn;

  val = (struct complete_reply_hash_val *)g_hash_table_lookup(giop_complete_reply_hash, &key);

  if (val) {
    return;                     /* FN collision */
  }

  new_key = wmem_new(wmem_file_scope(), struct complete_reply_hash_key);
  new_key->fn = fn;             /* save FN */

  val = wmem_new(wmem_file_scope(), struct complete_reply_hash_val);
  val->mfn = mfn;               /* and MFN */

  g_hash_table_insert(giop_complete_reply_hash, new_key, val);

}

/*
 * Find the MFN values from a given FN key.
 * Assumes the complete_reply_hash is already populated.
 */

static uint32_t get_mfn_from_fn(uint32_t fn) {

  struct complete_reply_hash_key key;
  struct complete_reply_hash_val *val = NULL;
  uint32_t mfn = fn;             /* save */

  key.fn = fn;
  val = (struct complete_reply_hash_val *)g_hash_table_lookup(giop_complete_reply_hash, &key);

  if (val) {
    mfn = val->mfn;             /* grab it */
  }

  return mfn;                   /* mfn or fn if not found */

}

/*
 * Attempt to find the MFN for this FN, and return it.
 * Return MFN if found, or just FN if not. This is
 * only used when we are building
 */

static uint32_t get_mfn_from_fn_and_reqid(uint32_t fn, uint32_t reqid, address *addr, uint32_t pnum) {

  GList                 *element; /* last entry in list */
  comp_req_list_entry_t *entry_ptr = NULL;

  /* Need Some pretty snappy code */

  /* Loop back from current end of complete_request_list looking for */
  /* a FN with the same reqid -- TODO enhance with port/address checks -- FS */

  /*
   * As this routine is only called during initial pass of data,
   * and NOT when a user clicks, it is ok to start from Current
   * end of complete_request_list when searching for a match.
   * As that list is bing populated in the same order as FN's
   * are being read.
   *
   * Also, can make check for same reqid more detailed, but I start
   * with reqid. Could add say port or address checks etc later ??
   */


  element = g_list_last(giop_complete_request_list); /* get last  */

  while (element) {                      /* valid list entry */
    entry_ptr = (comp_req_list_entry_t *)element->data;  /* grab data pointer */
    if (entry_ptr->reqid == reqid && cmp_address (&entry_ptr->src, addr) == 0 && entry_ptr->srcport == pnum) {    /* similar reqid  */
      return entry_ptr->fn;     /* return MFN */
    }
    element = g_list_previous(element); /* try next previous */
  }

  return fn;                    /* no match so return FN */
}


/* Module Hash "EQUAL" Functions */

static int giop_hash_module_equal(const void *v, const void *w) {
  const struct giop_module_key *mk1 = (const struct giop_module_key *)v;
  const struct giop_module_key *mk2 = (const struct giop_module_key *)w;

  if (strcmp(mk1->module, mk2->module) == 0) {
    return 1;
  }

  return 0;                     /* found  differences */
}

/* Module Hash "HASH" Functions */

static uint32_t giop_hash_module_hash(const void *v) {

  int     i, len;
  uint32_t val = 0;              /* init hash value */

  const struct giop_module_key *key = (const struct giop_module_key *)v;

  /*
   * Hmm, try this simple hashing scheme for now.
   * ie: Simple summation, FIX later -- FS
   *
   *
   */

  len = (int)strlen(key->module);

  for (i=0; i<len; i++) {
    val += (uint8_t) key->module[i];
  }

  return val;

}


/*
 * ------------------------------------------------------------------------------------------+
 *                                 Public Utility functions
 * ------------------------------------------------------------------------------------------+
 */




/*
 * Routine to  allow giop users to register their sub dissector function, name, and
 * IDL module/interface name. Store in giop_module_hash. Also pass along their proto_XXX
 * value returned from their proto_register_protocol(), so we can enable/disbale it
 * through the GUI (edit protocols).
 *
 * This is used by try_explicit_giop_dissector() to find the
 * correct sub-dissector.
 *
 */

void register_giop_user_module(giop_sub_dissector_t *sub, const char *name, const char *module, int sub_proto) {

  struct giop_module_key  module_key, *new_module_key;
  struct giop_module_val *module_val;

  module_key.module = module; /*  module name */

  module_val = (struct giop_module_val *)g_hash_table_lookup(giop_module_hash, &module_key);

  if (module_val) {
    return;                     /* module name collision */
  }

  /* So, passed module name should NOT exist in hash at this point.*/

  ws_debug("Adding Module %s to module hash", module);
  ws_debug("Module sub dissector name is %s", name);

  new_module_key = wmem_new(wmem_epan_scope(), struct giop_module_key);
  new_module_key->module = module; /* save Module or interface name from IDL */

  module_val = wmem_new(wmem_epan_scope(), struct giop_module_val);

  module_val->subh = wmem_new(wmem_epan_scope(), giop_sub_handle_t); /* init subh  */

  module_val->subh->sub_name = name;    /* save dissector name */
  module_val->subh->sub_fn = sub;       /* save subdissector*/
  module_val->subh->sub_proto = find_protocol_by_id(sub_proto); /* save protocol_t for subdissector's protocol */

  g_hash_table_insert(giop_module_hash, new_module_key, module_val);

}




/* Object Key Hash "EQUAL" Functions */

static int giop_hash_objkey_equal(const void *v, const void *w) {
  const struct giop_object_key *v1 = (const struct giop_object_key *)v;
  const struct giop_object_key *v2 = (const struct giop_object_key *)w;

  if (v1->objkey_len != v2->objkey_len)
    return 0;                   /* no match because different length */

  /* Now do a byte comparison */

  if (memcmp(v1->objkey, v2->objkey, v1->objkey_len) == 0) {
    return 1;           /* compares ok */
  }

  ws_debug("Objkey's DO NOT match");

  return 0;                     /* found  differences */
}

/* Object Key Hash "HASH" Functions */

static uint32_t giop_hash_objkey_hash(const void *v) {
  const struct giop_object_key *key = (const struct giop_object_key *)v;

  uint32_t i;
  uint32_t val = 0;              /* init hash value */


  /*
   * Hmm, try this simple hashing scheme for now.
   * ie: Simple summation
   *
   *
   */

  ws_debug("Key length = %u", key->objkey_len );

  for (i=0; i< key->objkey_len; i++) {
    val += (uint8_t) key->objkey[i];
  }

  return val;

}

/*
 * Routine to take an object key octet sequence, and length, and ptr to
 * a (null terminated )repository ID string, and store them in the obect key hash.
 *
 * Blindly Inserts even if it does exist, See TODO at top for reason.
 */

static void insert_in_objkey_hash(GHashTable *hash, const uint8_t *obj, uint32_t len, const char *repoid, ior_src_t src) {

  struct giop_object_key  objkey_key, *new_objkey_key;
  struct giop_object_val *objkey_val;

  objkey_key.objkey_len = len;  /*  length  */
  objkey_key.objkey     = obj;  /*  object key octet sequence  */

  /* Look it up to see if it exists */

  objkey_val = (struct giop_object_val *)g_hash_table_lookup(hash, &objkey_key);

  /* CHANGED -- Same reqid, so abandon old entry */

  if (objkey_val) {
    g_hash_table_remove(hash, &objkey_key);
  }

  /* So, passed key should NOT exist in hash at this point.*/

  new_objkey_key = wmem_new(wmem_file_scope(), struct giop_object_key);
  new_objkey_key->objkey_len = len; /* save it */
  new_objkey_key->objkey = (uint8_t *) wmem_memdup(wmem_file_scope(), obj, len);        /* copy from object and allocate ptr */

  objkey_val = wmem_new(wmem_file_scope(), struct giop_object_val);
  objkey_val->repo_id = wmem_strdup(wmem_file_scope(), repoid); /* duplicate and store Repository ID string */
  objkey_val->src = src;                   /* where IOR came from */


  ws_debug("******* Inserting Objkey with RepoID = %s and key length = %u into hash",
         objkey_val->repo_id, new_objkey_key->objkey_len);

  g_hash_table_insert(hash, new_objkey_key, objkey_val);

}

/*
 * Convert from  stringified IOR of the kind IOR:af4f7e459f....
 * to an IOR octet sequence.
 *
 * Creates a new tvbuff and call decode_IOR with a NULL tree, just to
 * grab repoid etc for our objkey hash.
 *
 */

static uint32_t string_to_IOR(char *in, uint32_t in_len, uint8_t **out) {
  int8_t  tmpval_lsb;
  int8_t  tmpval_msb;
  int8_t  tmpval;        /* complete value */
  uint32_t i;

  *out = wmem_alloc0_array(NULL, uint8_t, in_len); /* allocate buffer */

  if (*out == NULL) {
    return 0;
  }

  /* skip past IOR:  and convert character pairs to uint8_t */

  for (i=4; i+1<in_len; i+=2) {
    if ( g_ascii_isxdigit(in[i]) && g_ascii_isxdigit(in[i+1]) ) { /* hex ? */

      if ( (tmpval_msb = ws_xton(in[i])) < 0 ) {
        report_failure("giop: Invalid value in IOR %i", tmpval_msb);

      }

      if ( (tmpval_lsb = ws_xton(in[i+1])) < 0 ) {
        report_failure("giop: Invalid value in IOR %i", tmpval_lsb);
      }

      tmpval = tmpval_msb << 4;
      tmpval += tmpval_lsb;
      (*out)[(i-4)/2] = (uint8_t) tmpval;

    }
    else {
      /* hmm  */
      break;
    }

  }

  return (i-4)/2;               /* length  */

}



/*
 * Simple "get a line" routine, copied from somewhere :)
 *
 */

static int giop_getline(FILE *fp, char *line, int maxlen) {

  if (fgets(line, maxlen, fp) == NULL)
    return 0;
  else
    return (int)strlen(line);

}


/*
 * Read a list of stringified IOR's from a named file, convert to IOR's
 * and store in object key hash
 */

static void read_IOR_strings_from_file(const char *name, int max_iorlen) {
  char     *buf;                /* NOTE reused for every line */
  int       len;
  int       ior_val_len;        /* length after unstringifying. */
  FILE     *fp;
  uint8_t  *out = NULL;         /* ptr to unstringified IOR */
  tvbuff_t *tvb;                /* temp tvbuff for dissecting IORs */
  int       my_offset = 0;
  bool      stream_is_big_endian;


  fp = ws_fopen(name, "r");      /* open read only */

  if (fp == NULL) {
    if (errno == EACCES)
      report_open_failure(name, errno, false);
    return;
  }

  buf = (char *)wmem_alloc0(NULL, max_iorlen+1);        /* input buf */

  while ((len = giop_getline(fp, buf, max_iorlen+1)) > 0) {
    my_offset = 0;              /* reset for every IOR read */

    ior_val_len = string_to_IOR(buf, len, &out);  /* convert */

    if (ior_val_len>0) {

      /* XXX - can this code throw an exception?  If so, we need to
         catch it and clean up, but we really shouldn't allow it - or
         "get_CDR_octet()", or "decode_IOR()" - to throw an exception.

         Either that, or don't reuse dissector code when we're not
         dissecting a packet. */

      tvb =  tvb_new_real_data(out, ior_val_len, ior_val_len);

      stream_is_big_endian = !get_CDR_octet(tvb, &my_offset);
      decode_IOR(tvb, NULL, NULL, &my_offset, 0, stream_is_big_endian);

      tvb_free(tvb);
    }

    wmem_free(NULL, out);
  }

  fclose(fp);                   /* be nice */

  wmem_free(NULL, buf);
}



/*
 * Init routine, setup our request hash stuff, or delete old ref's
 *
 * Cannot setup the module hash here as my init() may not be called before
 * users start registering. So I will move the module_hash stuff to
 * proto_register_giop, as is done with packet-rpc
 *
 *
 *
 * Also, setup our objectkey/repoid hash here.
 *
 */

static void giop_init(void) {
  giop_objkey_hash = g_hash_table_new(giop_hash_objkey_hash, giop_hash_objkey_equal);
  giop_complete_reply_hash = g_hash_table_new(complete_reply_hash_fn, complete_reply_equal_fn);

  giop_complete_request_list = NULL;
  read_IOR_strings_from_file(giop_ior_file, 600);
}

static void giop_cleanup(void) {
  g_hash_table_destroy(giop_objkey_hash);
  g_hash_table_destroy(giop_complete_reply_hash);
  g_list_free(giop_complete_request_list);
}


/*
 * Insert an entry in the GIOP Heuristic User table.
 * Uses a GList.
 * Uses giop_sub_handle_t to wrap giop user info.
 *
 */

void register_giop_user(giop_sub_dissector_t *sub, const char *name, int sub_proto) {

  giop_sub_handle_t *subh;

  subh = wmem_new(wmem_epan_scope(), giop_sub_handle_t);

  subh->sub_name = name;
  subh->sub_fn = sub;
  subh->sub_proto = find_protocol_by_id(sub_proto);     /* protocol_t for sub dissectors's proto_register_protocol() */

  giop_sub_list = g_slist_prepend (giop_sub_list, subh);

}


/*
 * Lookup an object key in our object key hash, and return the corresponding
 * Repo Id.
 *
 */

static char * get_repoid_from_objkey(GHashTable *hash, const uint8_t *obj, uint32_t len) {

  struct giop_object_key  objkey_key;
  struct giop_object_val *objkey_val;

  objkey_key.objkey_len = len;  /*  length  */
  objkey_key.objkey     = obj;  /*  object key octet sequence  */

  /* Look it up to see if it exists */

  objkey_val = (struct giop_object_val *)g_hash_table_lookup(hash, &objkey_key);

  if (objkey_val) {
    ws_debug("Lookup of object key returns  RepoId = %s", objkey_val->repo_id );
    return objkey_val->repo_id; /* found  */
  }

  ws_debug("FAILED Lookup of object key \n" );

  return NULL;                  /* not  found */
}



/*
 * Extract top level module/interface from repoid
 *
 * eg from -  "IDL:Echo/interface1:1.0"
 * get "Echo"
 *
 * Or, from "IDL:linux.org/Penguin/Teeth:1.0" get
 * get linux.org/Penguin/Teeth
 *
 *
 * User must free returned ptr after use.
 *
 * TODO -- generalize for other Repoid encodings
 */

static char * get_modname_from_repoid(wmem_allocator_t *scope, char *repoid) {

  char   *modname;
  char    c         = 'a';
  uint8_t stop_mod  = 0;        /* Index of last character of modname in Repoid  */
  const uint8_t start_mod = 4;  /* Index where Module name starts in repoid */
  int     i;

  /* Must start with IDL: , otherwise I get confused */

  if (g_ascii_strncasecmp("IDL:", repoid, 4))
    return NULL;

  /* Looks like a RepoID to me, so get Module or interface name */

  /* TODO -- put some code here to get Module name */

  for (i=4; c != '\0'; i++) {
    c = repoid[i];
    stop_mod = i;               /* save */
    if (c == ':' )              /* delimiters */
      break;

  }

  /* Now create a new string based on start and stop and \0 */

  modname = wmem_strndup(scope, repoid+4, stop_mod - start_mod);

  return modname;

}

/*
 * DEBUG CODE
 *
 */


/* TODO: fixing the debug messages, since they don't comply to the coding style */
///*
// * Display a "module" hash entry
// */
//
//static void display_module_hash(void *key, void *val, void *user_data) {
//
//  struct giop_module_val *mv = (struct giop_module_val *) val;
//  struct giop_module_key *mk = (struct giop_module_key *) key;
//
//  ws_debug("Key = (%s) , Val = (%s)", mk->module, mv->subh->sub_name);
//  ws_debug("pointer = (%p)", user_data);
//
//  return;
//
//}
//
///*
// * Display a "complete_reply " hash entry
// */
//
//static void display_complete_reply_hash(void *key, void *val, void *user_data) {
//
//  struct complete_reply_hash_val *mv = (struct complete_reply_hash_val *) val;
//  struct complete_reply_hash_key *mk = (struct complete_reply_hash_key *) key;
//
//  ws_debug("FN (key) = %8u , MFN (val) = %8u", mk->fn, mv->mfn);
//  ws_debug("pointer = (%p)", user_data);
//
//  return;
//
//}
//
//
///*
// * Display an "objkey" hash entry
// */
//
//static void display_objkey_hash(void *key, void *val, void *user_data) {
//  uint32_t i;
//  struct giop_object_val *mv = (struct giop_object_val *) val;
//  struct giop_object_key *mk = (struct giop_object_key *) key;
//
//
//  ws_debug("Key->objkey_len = %u,  Key->objkey pointer = (%p)",  mk->objkey_len, user_data);
//
//  // XXX: this logs each item on a separate line
//  for (i=0; i<mk->objkey_len; i++) {
//    ws_debug("%.2x ", mk->objkey[i]);
//  }
//
//  /*
//   * If read from file, mark it as such..
//   */
//
//  if (mv->src == 0) {
//    ws_debug("Repo ID = %s", mv->repo_id);
//  }
//  else {
//    ws_debug("Repo ID = %s , (file)", mv->repo_id);
//  }
//
//  return;
//
//}
//
///*
// * Display all giop_sub_list (GSList) entries
// */
//
//static void display_heuristic_user_list() {
//  int i;
//  int len;
//  giop_sub_handle_t *subh;      /* handle */
//
//  /* Get length of list */
//  len = g_slist_length(giop_sub_list); /* find length */
//
//  if (len == 0)
//    return;
//
//  for (i=0; i<len; i++) {
//    subh = ( giop_sub_handle_t *) g_slist_nth_data(giop_sub_list, i); /* grab entry */
//    ws_debug("Element = %i, Val (user) = %s", i, subh->sub_name);
//  }
//
//}
//
///*
// * Display all complete_request_list (GList) entries
// */
//
//static void display_complete_request_list() {
//  int i;
//  int len;
//  comp_req_list_entry_t *entry;
//
//  /* Get length of list */
//  len = g_list_length(giop_complete_request_list); /* find length */
//
//  if (len == 0)
//    return;
//
//  for (i=0; i<len; i++) {
//    entry = (comp_req_list_entry_t *) g_list_nth_data(giop_complete_request_list, i); /* grab entry */
//    ws_debug("Index = %8i , FN = %8i, reqid = %8u , operation = %20s , repoid = %30s", i, entry->fn,
//           entry->reqid, entry->operation, entry->repoid);
//  }
//
//}
//
//
//
//
///* Dump Hash/List contents
// *
// * collection_type specifies the list or hash to dump
// *
// */
//
//static void giop_dump_collection(collection_data_t collection_type) {
//
//  switch (collection_type) {
//  case cd_heuristic_users:
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Heuristic User (Begin) --------+");
//    ws_debug("+----------------------------------------------+");
//
//    display_heuristic_user_list();
//
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Heuristic User (End) ----------+");
//    ws_debug("+----------------------------------------------+");
//
//    break;
//
//  case cd_complete_request_list:
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+------------- Complete Request List (Begin) --+");
//    ws_debug("+----------------------------------------------+");
//
//    display_complete_request_list();
//
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+------------ Complete Request List (End) -----+");
//    ws_debug("+----------------------------------------------+");
//
//    break;
//
//  case cd_module_hash:
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Module (Begin) ----------------+");
//    ws_debug("+----------------------------------------------+");
//
//    g_hash_table_foreach(giop_module_hash, display_module_hash, NULL);
//
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Module ( End) -----------------+");
//    ws_debug("+----------------------------------------------+");
//
//    break;
//
//  case cd_objkey_hash:
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Objkey (Begin) ----------------+");
//    ws_debug("+----------------------------------------------+");
//
//    g_hash_table_foreach(giop_objkey_hash, display_objkey_hash, NULL);
//
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Objkey (End) ------------------+");
//    ws_debug("+----------------------------------------------+");
//
//    break;
//
//  case cd_complete_reply_hash:
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+-------------- Complete_Reply_Hash (Begin) ---+");
//    ws_debug("+----------------------------------------------+");
//
//    g_hash_table_foreach(giop_complete_reply_hash, display_complete_reply_hash, NULL);
//
//    ws_debug("+----------------------------------------------+");
//    ws_debug("+------------- Complete_Reply_Hash (End) ------+");
//    ws_debug("+----------------------------------------------+");
//
//    break;
//
//  default:
//
//    ws_debug("Unknown type");
//
//  }
//
//
//}
//
//

/*
 * Loop through all  subdissectors, and call them until someone
 * answers (returns true) and processes all bytes from the packet.
 * This function then returns true, otherwise it return false.
 *
 * It is necessary to check if the packet has been completely processed since
 * it is possible to have multiple potential hits for a given operation.
 * This is just a simple heuristic way to reduce the amount of false positives.
 *
 * But skip a subdissector if it has been disabled in GUI "edit protocols".
 */

static bool try_heuristic_giop_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                MessageHeader *header, const char *operation  ) {

  int                i, len;
  bool               res = false; /* result of calling a heuristic sub dissector */
  giop_sub_handle_t *subh;

  len = g_slist_length(giop_sub_list); /* find length */

  if (len == 0)
    return false;

  {
    uint32_t message_size;
    bool stream_is_big_endian = is_big_endian (header);

    if (stream_is_big_endian)
      message_size = pntoh32 (&header->message_size);
    else
      message_size = pletoh32 (&header->message_size);

    if (*offset < 0 || (uint32_t)*offset > message_size)
      return false;
  }
  ws_debug("operation = (%s)", operation);

  for (i=0; i<len; i++) {
    subh = (giop_sub_handle_t *) g_slist_nth_data(giop_sub_list, i); /* grab dissector handle */

    if (proto_is_protocol_enabled(subh->sub_proto)) {
      packet_info saved_pinfo = *pinfo;
      pinfo->current_proto =
        proto_get_protocol_short_name(subh->sub_proto);
      int saved_offset        = *offset;
      res = (subh->sub_fn)(tvb, pinfo, NULL, offset, header, operation, NULL); /* callit TODO - replace NULL */
      if (res) {
        ws_debug("operation is matching on (%s)", subh->sub_name);
        ws_debug("remaining data to process = (%u)", tvb_reported_length_remaining(tvb, *offset));
      }
      /* if the dissector returns true and parsed all bytes, it is the correct one*/
      if (res && tvb_reported_length_remaining(tvb, *offset) == 0) {
        ws_debug("Hit was on subdissector = (%s)", subh->sub_name);
        *offset = saved_offset;
        *pinfo = saved_pinfo;
        pinfo->current_proto =
          proto_get_protocol_short_name(subh->sub_proto);
        (subh->sub_fn)(tvb, pinfo, tree, offset, header, operation, NULL); /* callit TODO - replace NULL */
        return true;            /* found one, lets return */
      } else { // restoring data
        *pinfo  = saved_pinfo;
        *offset = saved_offset;
        res     = false;
      }
    } /* protocol_is_enabled */
  } /* loop */

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "GIOP");
  return res;                   /* result */
}


/*
 * Find the matching repoid in the module hash and call
 * the dissector function if offset exists.
 *
 *
 * Repoid is eg IDL:tux.antarctic/Penguin/Teeth:1.0 but subdissectors
 * will register possibly "tux.antarctic/Penguin" and "tux.antarctic/Penguin/Teeth".
 *
 *
 *
 */

static bool try_explicit_giop_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                            MessageHeader *header, const char *operation, char *repoid ) {

  giop_sub_handle_t      *subdiss; /* handle */
  bool                    res        = false;
  char                   *modname;
  struct giop_module_key  module_key;
  struct giop_module_val *module_val;
  const char             *saved_proto;


  /*
   * Get top level module/interface from complete repoid
   */

  modname = get_modname_from_repoid(pinfo->pool, repoid);
  if (modname == NULL) {
    return res;                 /* unknown module name */
  }


  /* Search for Module or interface name */

  module_key.module = modname; /*  module name */
  module_val = (struct giop_module_val *)g_hash_table_lookup(giop_module_hash, &module_key);

  if (module_val == NULL) {
    return res;                 /* module not registered */
  }

  subdiss = (giop_sub_handle_t *) module_val->subh; /* grab dissector handle */

  if (subdiss) {
    /* Add giop_sub_handle_t and repoid into complete_request_list, so REPLY can */
    /* look it up directly, later ie: FN -> MFN -> giop_sub_handle_t and repoid */
    /* but only if user not clicking */

    if (!pinfo->fd->visited)
      add_sub_handle_repoid_to_comp_req_list(pinfo->num, subdiss, repoid);


    /* Call subdissector if current offset exists , and dissector is enabled in GUI "edit protocols" */

    if (tvb_offset_exists(tvb, *offset)) {
      ws_debug("calling sub = %s with module = (%s)", subdiss->sub_name  , modname);

      if (proto_is_protocol_enabled(subdiss->sub_proto)) {

        saved_proto = pinfo->current_proto;
        pinfo->current_proto =
          proto_get_protocol_short_name(subdiss->sub_proto);
        res = (subdiss->sub_fn)(tvb, pinfo, tree, offset, header, operation, modname); /* callit, TODO replace NULL with idlname */
        pinfo->current_proto = saved_proto;

      } /* protocol_is_enabled */
    } /* offset exists */
  } /* subdiss */

  return res;                   /* return result */
}



/* Take in an array of char and create a new ephemeral string.
 * Replace non-printable characters with periods.
 *
 * The array may contain \0's so don't use strdup
 * The string is \0 terminated, and thus longer than
 * the initial sequence.
 */

char *make_printable_string (wmem_allocator_t *scope, const uint8_t *in, uint32_t len) {
  uint32_t i;
  char    *print_string;

  print_string = (char * )wmem_alloc0(scope, len + 1); /* make some space and zero it */
  memcpy(print_string, in, len);        /* and make a copy of input data */

  for (i=0; i < len; i++) {
    if ( !g_ascii_isprint( (unsigned char)print_string[i] ) )
      print_string[i] = '.';
  }

  return print_string;          /* return ptr */
}

/* Determine the byte order from the GIOP MessageHeader */

bool is_big_endian (MessageHeader * header) {
  bool big_endian = false;

  switch (header->GIOP_version.minor) {
  case 2:
  case 1:
    if (header->flags & GIOP_MESSAGE_FLAGS_ENDIANNESS)
      big_endian = false;
    else
      big_endian = true;
    break;
  case 0:
    if (header->flags)
      big_endian = false;
    else
      big_endian = true;
    break;
  default:
    break;
  }
  return big_endian;
}



/*
 * Calculate new offset, based on the current offset, and user supplied
 * "offset delta" value, and the alignment requirement.
 *
 *
 *
 * eg: Used for GIOP 1.2 where Request and Reply bodies are
 *     aligned on 8 byte boundaries.
 */

static void set_new_alignment(int *offset, int delta, int  alignment) {

  while ( ( (*offset + delta) % alignment) != 0)
          ++(*offset);


}

/*
 * Helper functions for dissecting TypeCodes
 *
 * These functions decode the complex parameter lists
 * of TypeCodes as defined in the CORBA spec chapter 15.
 */

/*
 * For a given data type, given by a TypeCode gets the associated data
 * and displays it in the relevant tree.
 *
 * data_name is allowed to be NULL or empty string
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_data_for_typecode_with_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      proto_item *item, int *offset,
                                      bool stream_is_big_endian, uint32_t boundary,
                                      MessageHeader * header, uint32_t data_type,
                                      wmem_list_t *params, char *data_name) {

  bool my_boolean; /* boolean */

  int8_t s_octet1;   /* signed int8 */
  uint8_t u_octet1;   /* unsigned int8 */

  int16_t s_octet2;  /* signed int16 */
  uint16_t u_octet2;  /* unsigned int16 */

  int32_t s_octet4;  /* signed int32 */
  uint32_t u_octet4;  /* unsigned int32 */

  int64_t s_octet8;  /* signed int64 */
  uint64_t u_octet8;  /* unsigned int64 */

  double my_double; /* double */
  float   my_float;  /* float */

  wmem_list_frame_t *parameter; // for parameter list
  wmem_list_t *inner_params;    // for recursive typecode resolution; e.g. alias, struct
  wmem_strbuf_t *strbuf = NULL; // string buffer for constructing strings
  proto_tree *mysubtree = NULL;
  int old_offset;

  uint32_t new_typecode;

  char *inner_name = NULL;           /* ptr to member name for complex data types */
  proto_item *it = NULL;

  const char *buf = NULL;            /* ptr to string buffer */

  unsigned recursion_depth = p_get_proto_depth(pinfo, proto_giop);
  if (recursion_depth > GIOP_MAX_RECURSION_DEPTH) {
    proto_tree_add_expert(tree, pinfo, &ei_giop_max_recursion_depth_reached, tvb, 0, 0);
    return;
  }
  p_set_proto_depth(pinfo, proto_giop, recursion_depth + 1);

  /* Grab the data according to data type */

  switch (data_type) {
  case tk_null:
    /* nothing to decode */
    break;
  case tk_void:
    /* nothing to decode */
    break;
  case tk_short:
    s_octet2 = get_CDR_short(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_int(tree, hf_giop_type_short, tvb, *offset-2, 2, s_octet2);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %hd", data_name, s_octet2);
    break;
  case tk_long:
    s_octet4 = get_CDR_long(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_int(tree, hf_giop_type_long, tvb, *offset-4, 4, s_octet4);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %d", data_name, s_octet4);
    break;
  case tk_ushort:
    u_octet2 = get_CDR_ushort(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_uint(tree, hf_giop_type_ushort, tvb, *offset-2, 2, u_octet2);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %hu", data_name, u_octet2);
    break;
  case tk_ulong:
    u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
    proto_tree_add_uint(tree, hf_giop_type_ulong, tvb, *offset-4, 4, u_octet4);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %u", data_name, u_octet4);
    break;
  case tk_float:
    my_float = get_CDR_float(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_float(tree, hf_giop_type_float, tvb, *offset-4, 4, my_float);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %f", data_name, my_float);
    break;
  case tk_double:
    my_double = get_CDR_double(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_double(tree, hf_giop_type_double, tvb, *offset-8, 8, my_double);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %lf", data_name, my_double);
    break;
  case tk_boolean:
    my_boolean = get_CDR_boolean(tvb, offset);
    it = proto_tree_add_boolean(tree, hf_giop_type_boolean, tvb, *offset-1, 1, my_boolean);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %d", data_name, my_boolean);
    break;
  case tk_char:
    u_octet1 = get_CDR_char(tvb, offset);
    it = proto_tree_add_uint(tree, hf_giop_type_char, tvb, *offset-1, 1, u_octet1);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %c", data_name, u_octet1);
    break;
  case tk_octet:
    u_octet1 = get_CDR_octet(tvb, offset);
    it = proto_tree_add_uint(tree, hf_giop_type_octet, tvb, *offset-1, 1, u_octet1);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %u", data_name, u_octet1);
    break;
  case tk_any:
    get_CDR_any(tvb, pinfo, tree, item, offset, stream_is_big_endian, boundary, header);
    break;
  case tk_TypeCode:
    get_CDR_typeCode(tvb, pinfo, tree, offset, stream_is_big_endian, boundary, header);
    break;
  case tk_Principal:
    break;
  case tk_objref:
    break;
  case tk_struct:
    parameter = wmem_list_head(params); // first parameter is the repoid
    parameter = wmem_list_frame_next(parameter); // get struct name
    // get count

    // concatenating the struct name properly over strbuf
    strbuf = wmem_strbuf_new(pinfo->pool, "struct ");
    wmem_strbuf_append(strbuf, wmem_list_frame_data(parameter));
    mysubtree = proto_tree_add_subtree(tree, tvb, *offset, -1,
        ett_giop_struct, NULL, wmem_strbuf_get_str(strbuf));
    (void)wmem_strbuf_destroy(strbuf), strbuf = NULL;

    parameter = wmem_list_frame_next(parameter);
    u_octet4 = *((uint32_t*)wmem_list_frame_data(parameter));

    old_offset = *offset;
    for (uint32_t i = 0; i < u_octet4; i++) {
      parameter = wmem_list_frame_next(parameter);
      char *name = wmem_list_frame_data(parameter);

      parameter = wmem_list_frame_next(parameter);
      new_typecode = *((uint32_t*) wmem_list_frame_data(parameter));
      parameter = wmem_list_frame_next(parameter);
      inner_params = (wmem_list_t*) wmem_list_frame_data(parameter);
      dissect_data_for_typecode_with_params(tvb, pinfo, mysubtree, item,
          offset, stream_is_big_endian, boundary, header, new_typecode,
          inner_params, name);
      if (*offset <= old_offset) {
        expert_add_info(pinfo, item, &ei_giop_offset_error);
        break;
      }
    }
    break;
  case tk_union:
    break;
  case tk_enum:
    u_octet4 = get_CDR_enum(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_uint(tree, hf_giop_type_enum, tvb, *offset-4, 4, u_octet4);
    parameter = wmem_list_head(params); // repoid
    parameter = wmem_list_frame_next(parameter); // name
    inner_name = wmem_list_frame_data(parameter);
    parameter = wmem_list_frame_next(parameter); // count
    if (u_octet4 > *((uint32_t*)wmem_list_frame_data(parameter)))
      proto_item_set_text(it, "%s:  ERROR value outside of enum!!! (%u)", inner_name, u_octet4);
    else {
      for (uint32_t i = 0; i < u_octet4; i++)
        parameter = wmem_list_frame_next(parameter);
      proto_item_set_text(it, "%s: %s (%u)", inner_name, (char*)wmem_list_frame_data(parameter), u_octet4);
    }
    break;
  case tk_string:
    u_octet4 = get_CDR_string(pinfo->pool, tvb, &buf, offset, stream_is_big_endian, boundary);
    proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                          *offset-u_octet4-4, 4, u_octet4);
    if (u_octet4 > 0) {
      proto_tree_add_string(tree, hf_giop_type_string, tvb,
                              *offset-u_octet4, u_octet4, buf);
    }
    break;
  case tk_sequence:
    parameter = wmem_list_head(params);
    // get typecode
    new_typecode = *((uint32_t*) wmem_list_frame_data(parameter));
    parameter = wmem_list_frame_next(parameter);
    inner_params = (wmem_list_t*) wmem_list_frame_data(parameter);
    parameter = wmem_list_frame_next(parameter);
    // get max length
    u_octet8 = *((uint32_t*) wmem_list_frame_data(parameter));
    // grab actual length
    u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
    proto_tree_add_uint(tree, hf_giop_typecode_length, tvb, *offset-4, 4, u_octet4);
    strbuf = wmem_strbuf_new(pinfo->pool, "sequence");
    if (data_name && strlen(data_name)) {
      wmem_strbuf_append(strbuf, " ");
      wmem_strbuf_append(strbuf, data_name);
    }
    mysubtree = proto_tree_add_subtree(tree, tvb, *offset, -1,
        ett_giop_sequence, NULL, wmem_strbuf_get_str(strbuf));
    (void)wmem_strbuf_destroy(strbuf), strbuf = NULL;

    if (u_octet8 == 0 || u_octet8 > u_octet4) { // unbounded or too little data
      // set max length to actual length
      u_octet8 = u_octet4;
    }
    old_offset = *offset;
    for (uint64_t i = 0; i < u_octet8; i ++) {
      dissect_data_for_typecode_with_params(tvb, pinfo, mysubtree, item, offset,
          stream_is_big_endian, boundary, header, new_typecode, inner_params, NULL);
      if (*offset <= old_offset) {
        expert_add_info(pinfo, mysubtree, &ei_giop_offset_error);
        break;
      }
    }
    break;
  case tk_array:
    parameter = wmem_list_head(params);
    new_typecode = *((uint32_t*) wmem_list_frame_data(parameter));
    parameter = wmem_list_frame_next(parameter);
    inner_params = (wmem_list_t*) wmem_list_frame_data(parameter);
    parameter = wmem_list_frame_next(parameter);
    // get length
    u_octet4 = *((uint32_t*) wmem_list_frame_data(parameter));
    strbuf = wmem_strbuf_new(pinfo->pool, "array");
    if (data_name && strlen(data_name)) {
      wmem_strbuf_append(strbuf, " ");
      wmem_strbuf_append(strbuf, data_name);
    }
    mysubtree = proto_tree_add_subtree(tree, tvb, *offset, -1,
        ett_giop_array, NULL, wmem_strbuf_get_str(strbuf));
    (void)wmem_strbuf_destroy(strbuf), strbuf = NULL;
    old_offset = *offset;
    for (uint32_t i = 0; i < u_octet4; i ++) {
      dissect_data_for_typecode_with_params(tvb, pinfo, mysubtree, item, offset,
          stream_is_big_endian, boundary, header, new_typecode, inner_params, NULL);
      if (*offset <= old_offset) {
        expert_add_info(pinfo, mysubtree, &ei_giop_offset_error);
        break;
      }
    }
    break;
  case tk_alias:
    parameter = wmem_list_head(params); // repoid
    parameter = wmem_list_frame_next(parameter);
    inner_name = (char*) wmem_list_frame_data(parameter); // alias name
    parameter = wmem_list_frame_next(parameter); // typecode
    new_typecode = *((uint32_t*) wmem_list_frame_data(parameter));
    parameter = wmem_list_frame_next(parameter);
    inner_params = (wmem_list_t*) wmem_list_frame_data(parameter);
    dissect_data_for_typecode_with_params(tvb, pinfo, tree, item, offset,
        stream_is_big_endian, boundary, header, new_typecode, inner_params, inner_name);
    break;
  case tk_except:
    break;
  case tk_longlong:
    s_octet8 = get_CDR_long_long(tvb, offset, stream_is_big_endian, boundary);
    it = proto_tree_add_int64(tree, hf_giop_type_longlong, tvb, *offset-8, 8, s_octet8);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %" PRId64, data_name, s_octet8);
    break;
  case tk_ulonglong:
    u_octet8 = get_CDR_ulong_long(tvb, offset, stream_is_big_endian, boundary);
    proto_tree_add_uint64(tree, hf_giop_type_ulonglong, tvb, *offset-8, 8, u_octet8);
    if (data_name && strlen(data_name))
      proto_item_set_text(it, "%s: %" PRIu64 , data_name, u_octet8);
    break;
  case tk_longdouble:
    break;
  case tk_wchar:
    s_octet1 = get_CDR_wchar(pinfo->pool, tvb, &buf, offset, header);
    if (tree) {
      if (s_octet1 < 0) { /* no size to add to tree */
        proto_tree_add_string(tree, hf_giop_type_string, tvb,
                              *offset+s_octet1, (-s_octet1), buf);
      } else {
        proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                            *offset-s_octet1-1, 1, s_octet1);
        proto_tree_add_string(tree, hf_giop_type_string, tvb,
                              *offset-s_octet1, s_octet1, buf);
      }
    }
    break;
  case tk_wstring:
    u_octet4 = get_CDR_wstring(pinfo->pool, tvb, &buf, offset, stream_is_big_endian, boundary, header);
    if (tree) {
       proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                           *offset-u_octet4-4, 4, u_octet4);
       proto_tree_add_string(tree, hf_giop_type_string, tvb,
                             *offset-u_octet4, u_octet4, buf);
     }
    break;
  case tk_fixed:
    break;
  case tk_value:
    break;
  case tk_value_box:
    break;
  case tk_native:
    break;
  case tk_abstract_interface:
    break;
  default:
    expert_add_info_format(pinfo, item, &ei_giop_unknown_typecode_datatype, "Unknown typecode data type %u", data_type);
    break;
  }
  p_set_proto_depth(pinfo, proto_giop, recursion_depth);
}

/*
static void dissect_data_for_typecode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                      proto_item *item, int *offset,
                                      bool stream_is_big_endian, uint32_t boundary,
                                      MessageHeader * header, uint32_t data_type ) {
  // leaving parameter list away, but dissecting as usual
  wmem_list_t *dummy = wmem_list_new(pinfo->pool);
  dissect_data_for_typecode_with_params(tvb, pinfo, tree, item, offset,
      stream_is_big_endian, boundary, header, data_type, dummy);
  wmem_destroy_list(dummy);
}
*/

/*
 * gets a TypeCode complex string parameter and
 * displays it in the relevant tree.
 */

static void dissect_typecode_string_param(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                          bool     new_stream_is_big_endian, uint32_t new_boundary, int hf_id, const char **str ) {

  uint32_t     u_octet4;        /* unsigned int32 */
  const char *buf = NULL;             /* ptr to string buffer */

  /* get string */
  u_octet4 = get_CDR_string(pinfo->pool, tvb, &buf, offset, new_stream_is_big_endian, new_boundary);
  proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                      *offset-u_octet4-4, 4, u_octet4);
  if (u_octet4 > 0) {
    proto_tree_add_string(tree, hf_id, tvb, *offset-u_octet4, u_octet4, buf);
  }
  *str = buf;
}

static void dissect_tk_objref_params(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                     bool stream_is_big_endian, uint32_t boundary) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *buf = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &buf);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &buf);

}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_struct_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                     bool stream_is_big_endian, uint32_t boundary,
                                     MessageHeader * header, wmem_list_t *params) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  /* parameter count (of tuples)  */
  uint32_t *count = wmem_new0(pinfo->pool, uint32_t);
  /*uint32_t seqlen;*/   /* sequence length */
  uint32_t i;

  /* get sequence length new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  wmem_list_append(params, (char *) str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

  wmem_list_append(params, (char *) str);

  /* get count of tuples */
  *count = get_CDR_ulong(tvb, offset, new_stream_is_big_endian, new_boundary);
  wmem_list_append(params, count);

  if (tree) {
    proto_tree_add_uint(tree, hf_giop_typecode_count, tvb,
                        *offset-(int)sizeof(uint32_t), 4, *count);
  }

  /* get all tuples */
  for (i=0; i< *count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name, &str);

    wmem_list_append(params, (char *) str);

    uint32_t *typecode = wmem_new(pinfo->pool, uint32_t);
    wmem_list_t *inner_params = wmem_list_new(pinfo->pool);
    /* get member type */
    *typecode = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset,
        new_stream_is_big_endian, new_boundary, header, inner_params);
    wmem_list_append(params, typecode);
    wmem_list_append(params, inner_params);
  }

}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_union_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item* item,
                                    int *offset, bool stream_is_big_endian, uint32_t boundary,
                                    MessageHeader * header) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  uint32_t TCKind;                   /* TypeCode */
  int32_t  s_octet4;                 /* signed int32 */

  uint32_t count;                    /* parameter count (of tuples)  */
  /*uint32_t seqlen;*/   /* sequence length */
  uint32_t i;

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

  /* get discriminant type */
  wmem_list_t *inner_params = wmem_list_new(pinfo->pool);
  TCKind = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset, new_stream_is_big_endian,
      new_boundary, header, inner_params);

  /* get default used */
  s_octet4 = get_CDR_long(tvb, offset, new_stream_is_big_endian, new_boundary);
  proto_tree_add_int(tree, hf_giop_typecode_default_used, tvb,
                        *offset-4, 4, s_octet4);

  /* get count of tuples */
  count = get_CDR_ulong(tvb, offset, new_stream_is_big_endian, new_boundary);
  proto_tree_add_uint(tree, hf_giop_typecode_count, tvb, *offset-4, 4, count);

  char *name = (char *)str;

  /* get all tuples */
  int old_offset = *offset;
  for (i=0; i< count; i++) {
    /* get label value, based on TCKind above  */
    dissect_data_for_typecode_with_params(tvb, pinfo, tree, item, offset, new_stream_is_big_endian, new_boundary, header, TCKind, inner_params, name);
    if (*offset <= old_offset) {
      expert_add_info(pinfo, tree, &ei_giop_offset_error);
      break;
    }

    /* get member name */
    dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name, &str);

    /* get member type */
    get_CDR_typeCode(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary, header);
  }

}


static void dissect_tk_enum_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                   bool stream_is_big_endian, uint32_t boundary, wmem_list_t *params) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  uint32_t *count = wmem_alloc0(pinfo->pool, sizeof(uint32_t));    /* parameter count (of tuples)  */
  /*uint32_t seqlen;*/   /* sequence length */
  uint32_t i;

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);
  wmem_list_append(params, (char *) str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);
  wmem_list_append(params, (char *) str);

  /* get count of tuples */
  *count = get_CDR_ulong(tvb, offset, new_stream_is_big_endian, new_boundary);
  proto_tree_add_uint(tree, hf_giop_typecode_count, tvb,
                        *offset-4, 4, *count);
  wmem_list_append(params, count);

  /* get all tuples */
  for (i=0; i< *count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name, &str);
    wmem_list_append(params, (char *) str);
  }

}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_sequence_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                       bool stream_is_big_endian, uint32_t boundary,
                                       MessageHeader * header, wmem_list_t *params) {

  uint32_t new_boundary;        /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  uint32_t *u_octet4 = wmem_new(pinfo->pool, uint32_t);            /* unsigned int32 */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  uint32_t *typecode = wmem_new(pinfo->pool, uint32_t);
  wmem_list_t *inner_params = wmem_list_new(pinfo->pool);
  /* get element type */
  *typecode = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset,
      new_stream_is_big_endian, new_boundary, header, inner_params);

  /* get max length */
  *u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_typecode_max_length, tvb,
                        *offset-4, 4, *u_octet4);
  wmem_list_append(params, typecode);
  wmem_list_append(params, inner_params);
  wmem_list_append(params, u_octet4); // max_length
}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_array_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    bool stream_is_big_endian, uint32_t boundary,
                                    MessageHeader * header, wmem_list_t *params) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  uint32_t *u_octet4 = wmem_new(pinfo->pool, uint32_t); /* unsigned int32 */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
      stream_is_big_endian, boundary,
      &new_stream_is_big_endian, &new_boundary);

  uint32_t *type_code = wmem_new(pinfo->pool, uint32_t);
  wmem_list_t *inner_params = wmem_list_new(pinfo->pool);
  /* get element type */
  *type_code = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset,
      new_stream_is_big_endian, new_boundary, header, inner_params);

  /* get length */
  *u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_typecode_length, tvb,
      *offset-4, 4, *u_octet4);

  wmem_list_append(params, type_code);
  wmem_list_append(params, inner_params); // inner params for type_code
  wmem_list_append(params, u_octet4); // length
}

/* dissects parameters for the alias type and puts them into the linked list
 * params.
 *
 * It also dissects the parameters for the inner TypeCode to enable recursive
 * dissection of nested (complex) types. Those are saved into a nested linked
 * list which can be handed into dissect_data_for_typecode_with_params
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_alias_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    bool stream_is_big_endian, uint32_t boundary,
                                    MessageHeader * header, wmem_list_t *params) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence legnth, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;
  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);
  wmem_list_append(params, (char *) str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);
  wmem_list_append(params, (char *) str);

  uint32_t *tckind = wmem_new(pinfo->pool, uint32_t);
  wmem_list_t *inner_params = wmem_list_new(pinfo->pool);
  /* get ??? (noname) TypeCode */
  *tckind = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset,
      new_stream_is_big_endian, new_boundary, header, inner_params);
  wmem_list_append(params, tckind); // adding typecode to parameter list
  wmem_list_append(params, inner_params); // adding nested parameters
}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_except_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                     bool stream_is_big_endian, uint32_t boundary,
                                     MessageHeader * header) {

  uint32_t new_boundary;        /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  uint32_t count;               /* parameter count (of tuples)  */
  /*uint32_t seqlen;*/            /* sequence length */
  uint32_t i;                   /* loop index */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);


  /* get count of tuples */
  count = get_CDR_ulong(tvb, offset, new_stream_is_big_endian, new_boundary);
  if (tree) {
    proto_tree_add_uint(tree, hf_giop_typecode_count, tvb,
                        *offset-(int)sizeof(count), 4, count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name, &str);

    /* get member type */
    get_CDR_typeCode(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary, header);
  }

}

// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_value_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    bool stream_is_big_endian, uint32_t boundary,
                                    MessageHeader * header) {

  uint32_t new_boundary;        /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  int16_t  s_octet2;            /* signed int16 */

  uint32_t count;               /* parameter count (of tuples)  */
  /*uint32_t seqlen;*/            /* sequence length */
  uint32_t i;                   /* loop index */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);
  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

  /* get ValueModifier */
  s_octet2 = get_CDR_short(tvb, offset, stream_is_big_endian, boundary);
  proto_tree_add_int(tree, hf_giop_typecode_ValueModifier, tvb,
                       *offset-2, 2, s_octet2);

  /* get conrete base */
  get_CDR_typeCode(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary, header);

  /* get count of tuples */
  count = get_CDR_ulong(tvb, offset, new_stream_is_big_endian, new_boundary);
  proto_tree_add_uint(tree, hf_giop_typecode_count, tvb,
                        *offset-4, 4, count);

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name, &str);

    /* get member type */
    get_CDR_typeCode(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary, header);

    /* get Visibility */
    s_octet2 = get_CDR_short(tvb, offset, stream_is_big_endian, boundary);
    if (tree) {
      proto_tree_add_int(tree, hf_giop_typecode_Visibility, tvb,
                          *offset-(int)sizeof(s_octet2), 2, s_octet2);
    }
  }

}


// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_tk_value_box_params(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                        bool stream_is_big_endian, uint32_t boundary,
                                        MessageHeader * header) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;
  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

  /* get ??? (noname) TypeCode */
  get_CDR_typeCode(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary, header);
}


static void dissect_tk_native_params(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                     bool stream_is_big_endian, uint32_t boundary) {

  uint32_t new_boundary;             /* new boundary for encapsulation */
  bool     new_stream_is_big_endian; /* new endianness for encapsulation */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

}


static void dissect_tk_abstract_interface_params(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                                 bool stream_is_big_endian, uint32_t boundary) {

  uint32_t new_boundary;              /* new boundary for encapsulation */
  bool     new_stream_is_big_endian;  /* new endianness for encapsulation */

  /*uint32_t seqlen;*/   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  /*seqlen = */get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  const char *str = NULL;

  /* get repository ID */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid, &str);

  /* get name */
  dissect_typecode_string_param(tvb, pinfo, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name, &str);

}

/* Typecode parameter lists are encoded as encapsulations and
 * this function gets the encapsulation information; see
 * CORBA spec chapter 15
 *
 *
 * Renamed to get_CDR_encap_info() for any encapsulation
 * we come across, useful helper function
 *
 * Also, should return immediately if seqlen == 0.
 * ie: Forget about trying to grab endianness for
 *     zero length sequence.
 *
 * Caller must always check seqlen == 0, and not assume its value
 *
 *
 * Note: there seemed to be considerable confusion in corba
 * circles as to the correct interpretation of encapsulations,
 * and zero length sequences etc, but this is our best bet at the
 * moment.
 *
 * -- FS
 *
 */

uint32_t get_CDR_encap_info(tvbuff_t *tvb, proto_tree *tree, int *offset,
                       bool old_stream_is_big_endian, uint32_t old_boundary,
                       bool *new_stream_is_big_endian_ptr, uint32_t *new_boundary_ptr ) {

  uint32_t seqlen;   /* sequence length */
  uint8_t giop_endianness;

  /* Get sequence length of parameter list */
  seqlen = get_CDR_ulong(tvb, offset, old_stream_is_big_endian, old_boundary);
  proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                        *offset-(int)sizeof(seqlen), 4, seqlen);

  /*
   * seqlen == 0, implies no endianness and no data
   * so just return. Populate new_boundary_ptr and
   * new_stream_is_big_endian_ptr with current (old)
   * values, just to keep everyone happy. -- FS
   *
   */
  if (seqlen == 0) {

    *new_boundary_ptr = old_boundary;
    *new_stream_is_big_endian_ptr = old_stream_is_big_endian;
    return seqlen;
  }

  /*  Start of encapsulation of parameter list */
  *new_boundary_ptr = *offset;  /* remember  */
  giop_endianness =  get_CDR_octet(tvb, offset);

  *new_stream_is_big_endian_ptr = ! giop_endianness;

  /*
   * Glib: typedef int    bool;
   * ie: It is not a uint8_t, so cannot use sizeof to correctly
   * highlight octet.
   */
  proto_tree_add_uint(tree, hf_giop_endianness, tvb,
                        *offset-1, 1, giop_endianness);

  return seqlen;
}

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Public get_CDR_xxx functions.
 * ------------------------------------------------------------------------------------------+
 */



/*
 * Gets data of type any. This is encoded as a TypeCode
 * followed by the encoded value.
 */

// NOLINTNEXTLINE(misc-no-recursion)
void get_CDR_any(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item,
                 int *offset, bool stream_is_big_endian, int boundary,
                 MessageHeader * header ) {

  uint32_t TCKind;    /* TypeCode */

  wmem_list_t *params = wmem_list_new(pinfo->pool);

  /* get TypeCode of any */
  TCKind = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset, stream_is_big_endian, boundary, header,
      params);
  ws_debug("TCKind = (%u)", TCKind);

  /* dissect data of type TCKind */
  dissect_data_for_typecode_with_params(tvb, pinfo, tree, item, offset, stream_is_big_endian, boundary, header, TCKind, params, NULL );
}


/* Copy a 1 octet sequence from the tvbuff
 * which represents a boolean value, and convert
 * it to a boolean value.
 * Offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

bool get_CDR_boolean(tvbuff_t *tvb, int *offset) {
  uint8_t val;

  val = tvb_get_uint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}

/* Copy a 1 octet sequence from the tvbuff
 * which represents a char, and convert
 * it to an char value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

uint8_t get_CDR_char(tvbuff_t *tvb, int *offset) {
  uint8_t val;

  val = tvb_get_uint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}



/*
 * Floating Point Data Type double IEEE 754-1985
 *
 * Copy an 8 octet sequence from the tvbuff
 * which represents a double value, and convert
 * it to a double value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for double values.
 * offset is then incremented by 8, to indicate the 8 octets which
 * have been processed.
 */

double get_CDR_double(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  double val;

  /* double values must be aligned on a 8 byte boundary */

  while ( ( (*offset + boundary) % 8) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohieee_double (tvb, *offset) :
                                 tvb_get_letohieee_double (tvb, *offset);

  *offset += 8;
  return val;

}


/* Copy a 4 octet sequence from the tvbuff
 * which represents an enum value, and convert
 * it to an enum value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for an enum (4)
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 *
 * Enum values are encoded as unsigned long.
 */


uint32_t get_CDR_enum(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  return get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary );

}


/*
 * Copy an octet sequence from the tvbuff
 * which represents a Fixed point decimal type, and create a string representing
 * a Fixed point decimal type. There are no alignment restrictions.
 * Size and scale of fixed decimal type is determined by IDL.
 *
 * digits - IDL specified number of "digits" for this fixed type
 * scale  - IDL specified "scale" for this fixed type
 *
 *
 * eg: typedef fixed <5,2> fixed_t;
 *     could represent numbers like 123.45, 789.12,
 *
 *
 * As the fixed type could be any size, I will not try to fit it into our
 * simple types like double or long etc. I will just create a string buffer holding
 * a  representation (after scale is applied), and with a decimal point or zero padding
 * inserted at the right place if necessary. The string is null terminated
 *
 * so string may look like
 *
 *
 *  "+1.234" or "-3456.78" or "1234567309475760377365465897891" or "-2789000000" etc
 *
 * According to spec, digits <= 31
 * and scale is positive (except for constants eg: 1000 has digit=1 and implied scale = -3)
 * or <4,0> ?
 *
 */
void get_CDR_fixed(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, char **seq,
                   int *offset, uint32_t digits, int32_t scale) {

  uint8_t  sign;                /* 0x0c is positive, 0x0d is negative */
  uint32_t i ;                  /* loop */
  uint32_t slen;                /* number of bytes to hold digits + extra 0's if scale <0 */
                                /* this does not include sign, decimal point and \0 */
  uint32_t sindex = 0;          /* string index */
  char    *tmpbuf;              /* temp buff, holds string without scaling */
  uint8_t  tval;                /* temp val storage */

  /*
   * how many bytes to hold digits and scale (if scale <0)
   *
   * eg: fixed <5,2> = 5 digits
   *     fixed <5,-2> = 7 digits (5 + 2 added 0's)
   */

    ws_debug("digits = %u, scale = %u", digits, scale);

  if (scale <0) {
    slen = digits - scale;      /* allow for digits + padding 0's for negative scal */
  } else {
    slen = digits;              /*  digits */
  }

    ws_debug("slen =  %.2x", slen);

  tmpbuf = (char *)wmem_alloc0(pinfo->pool, slen);     /* allocate temp buffer */

  /* If even , grab 1st dig */

  if (!(digits & 0x01)) {
    tval = get_CDR_octet(tvb, offset);
    ws_debug("even: octet = %.2x", tval);
    tmpbuf[sindex] = (tval & 0x0f) + 0x30; /* convert top nibble to ascii */
    sindex++;
  }

  /*
   * Loop, but stop BEFORE we hit last digit and sign
   * if digits = 1 or 2, then this part is skipped
   */

  if (digits>2) {
    for (i=0; i< ((digits-1)/2 ); i++) {
      tval = get_CDR_octet(tvb, offset);
      ws_debug("odd: octet = %.2x", tval);

      tmpbuf[sindex] = ((tval & 0xf0) >> 4) + 0x30; /* convert top nibble to ascii */
      sindex++;
      tmpbuf[sindex] = (tval & 0x0f)  + 0x30; /* convert bot nibble to ascii */
      sindex++;

    }
  } /* digits > 3 */

    ws_debug("before last digit \n");

  /* Last digit and sign if digits >1, or 1st dig and sign if digits = 1 */

    tval = get_CDR_octet(tvb, offset);
    ws_debug("octet = %.2x", tval);
    tmpbuf[sindex] = (( tval & 0xf0)>> 4) + 0x30; /* convert top nibble to ascii */
    sindex++;

    sign = tval & 0x0f; /* get sign */

    /* So now, we have all digits in an array, and the sign byte
     * so lets generate a printable string, taking into account the scale
     * and sign values.
     */

    sindex = 0;                         /* reset */
    *seq = wmem_alloc0_array(pinfo->pool, char, slen + 3); /* allocate temp buffer , including space for sign, decimal point and
                                                                     * \0 -- TODO check slen is reasonable first */
    ws_debug("sign =  %.2x", sign);

    switch (sign) {
    case 0x0c:
      (*seq)[sindex] = '+';     /* put sign in first string position */
      break;
    case 0x0d:
      (*seq)[sindex] = '-';
      break;
    default:
      expert_add_info_format(pinfo, item, &ei_giop_unknown_sign_value,
          "Unknown sign value in fixed type %u", sign);
      (*seq)[sindex] = '*';     /* flag as sign unknown */
      break;
    }

    sindex++;

    /* Add decimal point or padding 0's, depending if scale is positive or
     * negative, respectively
     */

    if (scale>0) {
      for (i=0; i<digits-scale; i++) {
        (*seq)[sindex] = tmpbuf[i]; /* digits to the left of the decimal point */
        sindex++;
      }

      (*seq)[sindex] = '.'; /* decimal point */
      sindex++;

      for (i=digits-scale; i<digits; i++) {
        (*seq)[sindex] = tmpbuf[i]; /* remaining digits to the right of the decimal point */
        sindex++;
      }

      (*seq)[sindex] = '\0'; /* string terminator */

    } else {

      /* negative scale, dump digits and  pad out with 0's */

      for (i=0; i<digits-scale; i++) {
        if (i<digits) {
          (*seq)[sindex] = tmpbuf[i]; /* save digits */
        } else {
          (*seq)[sindex] = '0'; /* all digits used up, so pad with 0's */
        }
        sindex++;
      }

      (*seq)[sindex] = '\0'; /* string terminator */

    }

    ws_debug("value = %s", *seq);

    return;

}



/*
 * Floating Point Data Type float IEEE 754-1985
 *
 * Copy an 4 octet sequence from the tvbuff
 * which represents a float value, and convert
 * it to a float value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for float values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

float get_CDR_float(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  float val;

  /* float values must be aligned on a 4 byte boundary */

  while ( ( (*offset + boundary) % 4) != 0)
    ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohieee_float (tvb, *offset) :
                                 tvb_get_letohieee_float (tvb, *offset);

  *offset += 4;
  return val;

}


/*
 * Decode an Interface type, and display it on the tree.
 */

void get_CDR_interface(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                       bool stream_is_big_endian, int boundary) {


  decode_IOR(tvb, pinfo, tree, offset, boundary, stream_is_big_endian);

  return;
}


/* Copy a 4 octet sequence from the tvbuff
 * which represents a signed long value, and convert
 * it to an signed long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

int32_t get_CDR_long(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  int32_t val;

  /* unsigned long values must be aligned on a 4 byte boundary */
  while ( ( (*offset + boundary) % 4) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohl (tvb, *offset) :
                                 tvb_get_letohl (tvb, *offset);

  *offset += 4;
  return val;
}

/* Copy a 8 octet sequence from the tvbuff
 * which represents a signed long long value, and convert
 * it to an signed long long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for long long values.
 * offset is then incremented by 8, to indicate the 8 octets which
 * have been processed.
 */

int64_t get_CDR_long_long(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  int64_t val;

  /* unsigned long long values must be aligned on a 8 byte boundary */
  while ( ( (*offset + boundary) % 8) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntoh64 (tvb, *offset) :
                                 tvb_get_letoh64 (tvb, *offset);

  *offset += 8;
  return val;
}

/*
 * Decode an Object type, and display it on the tree.
 */

void get_CDR_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                    bool stream_is_big_endian, int boundary) {

  decode_IOR(tvb, pinfo, tree, offset, boundary, stream_is_big_endian);

  return;
}


/* Copy a 1 octet sequence from the tvbuff
 * which represents a octet, and convert
 * it to an octet value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

uint8_t get_CDR_octet(tvbuff_t *tvb, int *offset) {
  uint8_t val;

  val = tvb_get_uint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}


/* Copy a sequence of octets from the tvbuff.
 * This function also increments offset by len.
 */

void get_CDR_octet_seq(wmem_allocator_t *scope, tvbuff_t *tvb, const uint8_t **seq, int *offset, uint32_t len) {
  uint8_t *seq_buf;

  /*
   * Make sure that the entire sequence of octets is in the buffer before
   * allocating the buffer, so that we don't try to allocate a buffer bigger
   * than the data we'll actually be copying, and thus don't run the risk
   * of crashing if the buffer is *so* big that we fail to allocate it
   * and "wmem_alloc0_array()" aborts.
   */
  tvb_ensure_bytes_exist(tvb, *offset, len);

  /*
   * XXX - should we just allocate "len" bytes, and have "get_CDR_string()"
   * do what we do now, and null-terminate the string (which also means
   * we don't need to zero out the entire allocation, just the last byte)?
   */
  seq_buf = wmem_alloc0_array(scope, uint8_t, len + 1);
  tvb_memcpy( tvb, seq_buf, *offset, len);
  *seq = seq_buf;
  *offset += len;
}


/* Copy a 2 octet sequence from the tvbuff
 * which represents a signed short value, and convert
 * it to a signed short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

int16_t get_CDR_short(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  int16_t val;

  /* short values must be aligned on a 2 byte boundary */
  while ( ( (*offset + boundary) % 2) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2;
  return val;
}


/* Add an octet string to the tree.  This function exists in an attempt
 * to eliminate function-local variables in packet-parlay.c .
 */
void
giop_add_CDR_string(proto_tree *tree, tvbuff_t *tvb, int *offset,
                    bool stream_is_big_endian, int boundary, int hf)
{
    uint32_t     u_octet4;
    const char *seq = NULL;

    u_octet4 = get_CDR_string(wmem_packet_scope(), tvb, &seq, offset, stream_is_big_endian, boundary);
    proto_tree_add_string(tree, hf, tvb, *offset-u_octet4, u_octet4, (u_octet4 > 0) ? seq : "");
}


/* Copy an octet sequence from the tvbuff
 * which represents a string, and convert
 * it to an string value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for string values. (begins with an unsigned long LI)
 *
 * String sequence is copied to a  buffer "seq".
 * Memory is allocated in packet pool and will be
 * automatically freed once the packet dissection is finished.
 * offset is then incremented, to indicate the  octets which
 * have been processed.
 *
 * returns number of octets in the sequence - which is *NOT*
 * necessarily the number of bytes in the string, which has been
 * converted to UTF-8 for internal Wireshark use.
 *
 * Note: This function only supports single byte encoding at the
 *       moment until I get a handle on multibyte encoding etc.
 *
 */


uint32_t get_CDR_string(wmem_allocator_t* scope, tvbuff_t *tvb, const char **seq, int *offset, bool stream_is_big_endian,
                       int boundary ) {
  uint32_t slength;
  int     reported_length;

  /* This could be done as a FT_UINT_STRING */
  slength = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary); /* get length first */

#if 0
  (*offset)++;                  /* must step past \0 delimiter */
#endif

  reported_length = tvb_reported_length_remaining(tvb, *offset-4);
  /* XXX - CORBA 3.0 spec 13.10.2.6 "Code Set Negotiation"
   * "If no char transmission code set is specified in the code set service
   * context, then the char transmission code set is considered to be
   * ISO 8859-1 for backward compatibility."
   * Until we get this from conversation data, use ISO 8859-1.
   */
  if (slength > (uint32_t)reported_length) {
    /* Size exceeds packet size, so just grab the rest of the packet */
    /* XXX - add expert_add_info_format note */
    slength = (uint32_t)reported_length;
  }
  *seq = tvb_get_string_enc(scope, tvb, *offset, slength, ENC_ISO_8859_1);
  *offset += slength;

  return slength;               /* return length */

}

/* Process a sequence of octets that represent the
 * Pseudo Object Type "TypeCode". Typecodes are used for example,
 * by "Any values".
 * This function also increments offset to the correct position.
 *
 * It will parse the TypeCode and output data to the "tree" provided
 * by the user
 *
 * It returns a uint32_t representing a TCKind value.
 */
// NOLINTNEXTLINE(misc-no-recursion)
uint32_t get_CDR_typeCode(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
                         int *offset, bool stream_is_big_endian,
                         int boundary, MessageHeader * header ) {
  wmem_list_t *dummy = wmem_list_new(pinfo->pool);
  uint32_t ret = get_CDR_typeCode_with_params(tvb, pinfo, tree, offset,
      stream_is_big_endian, boundary, header, dummy);
  wmem_destroy_list(dummy);
  return ret;
}


// NOLINTNEXTLINE(misc-no-recursion)
static uint32_t get_CDR_typeCode_with_params(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree,
                         int *offset, bool stream_is_big_endian,
                         int boundary, MessageHeader * header,
                         wmem_list_t *parameterlist) {
  uint32_t    val;

  int16_t     s_octet2;         /* signed int16 */
  uint16_t    u_octet2;         /* unsigned int16 */
  uint32_t    u_octet4;         /* unsigned int32 */
  proto_item *ti;

  val = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary); /* get TCKind enum */

  unsigned recursion_depth = p_get_proto_depth(pinfo, proto_giop);
  if (recursion_depth > GIOP_MAX_RECURSION_DEPTH) {
    proto_tree_add_expert(tree, pinfo, &ei_giop_max_recursion_depth_reached, tvb, 0, 0);
    return val;
  }
  p_set_proto_depth(pinfo, proto_giop, recursion_depth + 1);

  ti = proto_tree_add_uint(tree, hf_giop_TCKind, tvb, *offset-4, 4, val);
  proto_tree *params_tree = proto_tree_add_subtree(tree, tvb, *offset, -1, ett_giop_typecode_parameters, NULL, "TypeCode-Parameters");

  /* Grab the data according to Typecode Table - Corba Chapter 15 */

  switch (val) {
  case tk_null: /* empty parameter list */
    break;
  case tk_void: /* empty parameter list */
    break;
  case tk_short: /* empty parameter list */
    break;
  case tk_long: /* empty parameter list */
    break;
  case tk_ushort: /* empty parameter list */
    break;
  case tk_ulong: /* empty parameter list */
    break;
  case tk_float: /* empty parameter list */
    break;
  case tk_double: /* empty parameter list */
    break;
  case tk_boolean: /* empty parameter list */
    break;
  case tk_char: /* empty parameter list */
    break;
  case tk_octet: /* empty parameter list */
    break;
  case tk_any: /* empty parameter list */
    break;
  case tk_TypeCode: /* empty parameter list */
    break;
  case tk_Principal: /* empty parameter list */
    break;
  case tk_objref: /* complex parameter list */
    dissect_tk_objref_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary);
    break;
  case tk_struct: /* complex parameter list */
    dissect_tk_struct_params(tvb, pinfo, params_tree, offset, stream_is_big_endian,
        boundary, header, parameterlist);
    break;
  case tk_union: /* complex parameter list */
    dissect_tk_union_params(tvb, pinfo, params_tree, ti, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_enum: /* complex parameter list */
    dissect_tk_enum_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, parameterlist);
    break;

  case tk_string: /* simple parameter list */
    u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary); /* get maximum length */
    if (params_tree) {
      proto_tree_add_uint(params_tree, hf_giop_typecode_max_length, tvb,
                          *offset-(int)sizeof(u_octet4), 4, u_octet4);
    }
    break;

  case tk_sequence: /* complex parameter list */
    dissect_tk_sequence_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header, parameterlist);
    break;
  case tk_array: /* complex parameter list */
    dissect_tk_array_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header, parameterlist);
    break;
  case tk_alias: /* complex parameter list */
    dissect_tk_alias_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header, parameterlist);
    break;
  case tk_except: /* complex parameter list */
    dissect_tk_except_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_longlong: /* empty parameter list */
    break;
  case tk_ulonglong: /* empty parameter list */
    break;
  case tk_longdouble: /* empty parameter list */
    break;
  case tk_wchar: /* empty parameter list */
    break;
  case tk_wstring: /* simple parameter list */
    u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary); /* get maximum length */
    if (params_tree) {
      proto_tree_add_uint(params_tree, hf_giop_typecode_max_length, tvb,
                          *offset-(int)sizeof(u_octet4), 4, u_octet4);
    }
    break;

  case tk_fixed: /* simple parameter list */
    u_octet2 = get_CDR_ushort(tvb, offset, stream_is_big_endian, boundary); /* get digits */
    if (params_tree) {
      proto_tree_add_uint(params_tree, hf_giop_typecode_digits, tvb,
                          *offset-(int)sizeof(u_octet2), 2, u_octet2);
    }

    s_octet2 = get_CDR_short(tvb, offset, stream_is_big_endian, boundary); /* get scale */
    if (params_tree) {
      proto_tree_add_int(params_tree, hf_giop_typecode_scale, tvb,
                          *offset-(int)sizeof(s_octet2), 2, s_octet2);
    }
    break;

  case tk_value: /* complex parameter list */
    dissect_tk_value_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_value_box: /* complex parameter list */
    dissect_tk_value_box_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_native: /* complex parameter list */
    dissect_tk_native_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary);
    break;
  case tk_abstract_interface: /* complex parameter list */
    dissect_tk_abstract_interface_params(tvb, pinfo, params_tree, offset, stream_is_big_endian, boundary);
    break;
  default:
    expert_add_info_format(pinfo, ti, &ei_giop_unknown_tckind, "Unknown TCKind %u", val);
    break;
  } /* val */

  p_set_proto_depth(pinfo, proto_giop, recursion_depth);

  return val;
}



/* Copy a 4 octet sequence from the tvbuff
 * which represents an unsigned long value, and convert
 * it to an unsigned long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

uint32_t get_CDR_ulong(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  uint32_t val;

  /* unsigned long values must be aligned on a 4 byte boundary */
  while ( ( (*offset + boundary) % 4) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohl (tvb, *offset) :
                                 tvb_get_letohl (tvb, *offset);

  *offset += 4;
  return val;
}

/* Copy a 8 octet sequence from the tvbuff
 * which represents an unsigned long long value, and convert
 * it to an unsigned long long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

uint64_t get_CDR_ulong_long(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  uint64_t val;

  /* unsigned long long values must be aligned on a 8 byte boundary */
  while ( ( (*offset + boundary) % 8) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntoh64 (tvb, *offset) :
                                 tvb_get_letoh64 (tvb, *offset);

  *offset += 8;
  return val;
}

/* Copy a 2 octet sequence from the tvbuff
 * which represents an unsigned short value, and convert
 * it to an unsigned short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

uint16_t get_CDR_ushort(tvbuff_t *tvb, int *offset, bool stream_is_big_endian, int boundary) {

  uint16_t val;

  /* unsigned short values must be aligned on a 2 byte boundary */
  while ( ( (*offset + boundary) % 2) != 0)
          ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2;
  return val;
}



/* Copy a wchar from the tvbuff.
 * Memory is allocated in packet pool and will be
 * automatically freed once the packet dissection is finished.
 * This function also increments offset according to
 * the wchar size.
 *
 * For GIOP 1.1 read 2 octets and return size -2. The
 * negation means there is no size element in the packet
 * and therefore no size to add to the tree.
 *
 * For GIOP 1.2 read size of wchar and the size
 * octets. size is returned as a int8_t.
 *
 * For both GIOP versions the wchar is returned
 * as a printable string.
 *
 */

/* NOTE: This is very primitive in that it just reads
 * the wchar as a series of octets and returns them
 * to the user. No translation is attempted based on
 * byte orientation, nor on code set. I.e it only
 * really reads past the wchar and sets the offset
 * correctly.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wchar is not supported for GIOP 1.0.
 */

int get_CDR_wchar(wmem_allocator_t *scope, tvbuff_t *tvb, const char **seq, int *offset, MessageHeader * header) {

  int          slength;
  const uint8_t *raw_wstring;

  /* CORBA chapter 15:
   *   - prior to GIOP 1.2 wchar limited to two octet fixed length.
   *   - GIOP 1.2 wchar is encoded as an unsigned binary octet
   *     followed by the elements of the octet sequence representing
   *     the encoded value of the wchar.
   */

  *seq = NULL; /* set in case GIOP 1.2 length is 0 */
  slength = 2; /* set for GIOP 1.1 length in octets */

  if (header->GIOP_version.minor > 1) /* if GIOP 1.2 get length of wchar */
    slength = get_CDR_octet(tvb, offset);

  if (slength > 0) {
    /* ??? assume alignment is ok for GIOP 1.1 ??? */
    get_CDR_octet_seq(scope, tvb, &raw_wstring, offset, slength);

    /* now turn octets (wchar) into something that can be printed by the user */
    *seq = make_printable_string(scope, raw_wstring, slength);
  }

  /* if GIOP 1.1 negate length to indicate not an item to add to tree */
  if (header->GIOP_version.minor < 2)
    slength = -slength;

  return slength;               /* return length */

}


/* Copy a wstring from the tvbuff.
 * Memory is allocated in packet pool and will be
 * automatically freed once the packet dissection is finished.
 * This function also increments offset, according to
 * wstring length. length is returned as uint32_t
 */

/* NOTE: This is very primitive in that it just reads
 * the wstring as a series of octets and returns them
 * to the user. No translation is attempted based on
 * byte orientation, nor on code set. I.e it only
 * really reads past the wstring and sets the offset
 * correctly.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wstring is not supported for GIOP 1.0.
 */


uint32_t get_CDR_wstring(wmem_allocator_t *scope, tvbuff_t *tvb, const char **seq, int *offset, bool stream_is_big_endian,
                       int boundary, MessageHeader * header) {

  uint32_t     slength;
  int          reported_length;
  const uint8_t *raw_wstring;

  /* CORBA chapter 15:
   *   - prior to GIOP 1.2 wstring limited to two octet fixed length.
   *     length and string are NUL terminated (length???).
   *   - GIOP 1.2 length is total number of octets. wstring is NOT NUL
   *     terminated.
   */

  *seq = NULL; /* set in case GIOP 1.2 length is 0 */

  /* get length, same for all GIOP versions,
   * although for 1.2 CORBA doesn't say, so assume.
   */
  slength = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);

  if (slength>200) {
        ws_warning("giop:get_CDR_wstring, length %u > 200, truncating to 5", slength);
        slength = 5;            /* better than core dumping during debug */
  }

  if (header->GIOP_version.minor < 2) {
#if 0
    (*offset)++;  /* must step past \0 delimiter */
#endif
    /* assume length is number of characters and not octets, spec not clear */
    slength = slength * 2; /* length in octets is 2 * wstring length */
  }

  reported_length = tvb_reported_length_remaining(tvb, *offset-4);
  if (slength > (uint32_t)reported_length) {
      slength = reported_length;
    /* XXX - add expert_add_info_format note */
  }

  if (slength > 0) {
    get_CDR_octet_seq(scope, tvb, &raw_wstring, offset, slength);

    /* now turn octets (wstring) into something that can be printed by the user */
    *seq = make_printable_string(scope, raw_wstring, slength);
  }

  return slength;               /* return length */

}

/**
 *  Dissects a TargetAddress which is defined in (CORBA 2.4, section 15.4.2)
 *  GIOP 1.2
 *  typedef short AddressingDisposition;
 *  const short KeyAddr = 0;
 *  const short ProfileAddr = 1;
 *  const short ReferenceAddr = 2;
 *  struct IORAddressingInfo {
 *    unsigned long selected_profile_index;
 *    IOP::IOR ior;
 *  };
 *
 *  union TargetAddress switch (AddressingDisposition) {
 *      case KeyAddr: sequence <octet> object_key;
 *      case ProfileAddr: IOP::TaggedProfile profile;
 *      case ReferenceAddr: IORAddressingInfo ior;
 *  };
 */

static void
dissect_target_address(tvbuff_t * tvb, packet_info *pinfo, int *offset, proto_tree * tree,
                       bool stream_is_big_endian, uint32_t *object_key_len,
                       const uint8_t **object_key_val)
{
  uint16_t     discriminant;
  const uint8_t *object_key = NULL;
  uint32_t     len        = 0;
  uint32_t     u_octet4;
  proto_item*  ti;

  discriminant = get_CDR_ushort(tvb, offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  proto_tree_add_uint (tree, hf_giop_target_address_discriminant, tvb, *offset -2, 2, discriminant);

  switch (discriminant)
  {
  case 0:  /* KeyAddr */
    len = get_CDR_ulong(tvb, offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    ti = proto_tree_add_uint (tree, hf_giop_target_address_key_addr_len, tvb, *offset -4, 4, len);

    if (len > (uint32_t)tvb_reported_length_remaining(tvb, *offset-4)) {
        expert_add_info_format(pinfo, ti, &ei_giop_length_too_big, "KeyAddr key length bigger than packet size");
        return;
    }

    if (len > 0) {

      get_CDR_octet_seq(pinfo->pool, tvb, &object_key, offset, len);

      proto_tree_add_string(tree, hf_giop_target_address_key_addr, tvb, *offset - len,
                            len, make_printable_string( pinfo->pool, object_key, len ));

      if (object_key_len) {
        *object_key_len = len;
      }
      if (object_key_val) {
        *object_key_val = object_key;
      }
    }
    break;
  case 1: /* ProfileAddr */
    decode_TaggedProfile(tvb, pinfo, tree, offset, GIOP_HEADER_SIZE,
                         stream_is_big_endian, NULL);
    break;
  case 2: /* ReferenceAddr */
    u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    proto_tree_add_uint (tree, hf_giop_target_address_ref_addr_len, tvb, *offset -4, 4, u_octet4);

    decode_IOR(tvb, pinfo, tree, offset, GIOP_HEADER_SIZE, stream_is_big_endian);
    break;
  default:
    break;
  }
}
static void decode_CodeSetServiceContext(tvbuff_t *tvb, proto_tree *tree,
                                         int *offset, bool stream_is_be,
                                         uint32_t boundary) {

  /* The boundary being passed in is the offset where the context_data
   * sequence begins. */

  uint32_t code_set_id;

  /* We pass in -boundary, because the alignment is calculated relative to
     the beginning of the context_data sequence.
     Inside get_CDR_ulong(), the calculation will be (offset +(- boundary)) % 4
     to determine the correct alignment of the short. */

  /* XXX We should save these code set values as conversation data.
   * CORBA 3.0 spec 13.10.2.6 Code Set Negotiation:
   * "Code set negotiation is not performed on a per-request basis,
   * but only when a client initially connects to a server."
   * The server sends its native code sets via the code set component of
   * the IOR multi-component profile structure (13.10.2.4) and then
   * the client determines based on that and its own native code sets
   * what to use for each transmission.
   */
  code_set_id = get_CDR_ulong(tvb, offset, stream_is_be, -((int32_t) boundary) );
  proto_tree_add_uint(tree, hf_giop_char_data, tvb, *offset - 4, 4, code_set_id);

  code_set_id = get_CDR_ulong(tvb, offset, stream_is_be, -((int32_t) boundary) );
  proto_tree_add_uint(tree, hf_giop_wchar_data, tvb, *offset - 4, 4, code_set_id);
}

/*
 *  From Section 2.7.3 of the Real-time CORBA 1.1 Standard, the CORBA priority
 *  is represented in the GIOP service request as:
 *
 *  module IOP {
 *     typedef short ServiceId;
 *     const ServiceId  RTCorbaPriority = 10;
 *  };
 *
 *  The RT-CORBA priority is a CDR encoded short value in a sequence<octet>
 *  buffer.
 */
static void decode_RTCorbaPriority(tvbuff_t *tvb, proto_tree *tree, int *offset,
                                   bool stream_is_be, uint32_t boundary) {

  /* The boundary being passed in is the offset where the context_data
   * sequence begins. */

  int16_t rtpriority;

  /* RTCorbaPriority is stored as a CDR encoded short */
  /* We pass in -boundary, because the alignment is calculated relative to
     the beginning of the context_data sequence.
     Inside get_CDR_short(), the calculation will be (offset + (- boundary)) % 2
     to determine the correct alignment of the short. */
  rtpriority = get_CDR_short(tvb, offset, stream_is_be, -((int32_t) boundary) );

  /* Highlight all of context_data except for the first endian byte */
  proto_tree_add_uint(tree, hf_giop_rt_corba_priority, tvb, *offset - 2, 2, rtpriority);
}

static void decode_UnknownServiceContext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                         int *offset, bool stream_is_be _U_,
                                         uint32_t boundary _U_,
                                         uint32_t context_data_len) {

  const uint8_t *context_data;

  /* return if zero length sequence */
  if (context_data_len == 0)
    return;

  /*
   * Decode sequence according to vendor ServiceId, but I don't
   * have that yet, so just dump it as data.
   */

  /* fetch all octets in this sequence */

  get_CDR_octet_seq(pinfo->pool, tvb, &context_data, offset, context_data_len);

  /* Make a printable string */
  proto_tree_add_string(tree, hf_giop_context_data, tvb, *offset - context_data_len ,
                          context_data_len, make_printable_string( pinfo->pool, context_data, context_data_len));
}

/*
 * Corba , chp 13.7
 *
 *
 *
 *      typedef unsigned long ServiceID;
 *
 *      struct ServiceContext {
 *              ServiceID context_id;
 *              sequence <octet> context_data;
 *      };
 *      typedef sequence <ServiceContext> ServiceContextList;
 *
 *
 * Note: Spec says context_data is an encapsulation.
 *
 *
 */

static void decode_ServiceContextList(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, int *offset,
                                      bool stream_is_be, uint32_t boundary) {

  uint32_t    seqlen;           /* sequence length  */
  uint32_t    context_data_len; /* context data sequence length  */

  proto_tree *tree;             /* ServiceContextList tree */
  proto_item *tf;
  proto_item *sc_item;
  proto_tree *sc_tree;

  uint32_t    context_id;

  uint32_t    i;
  uint32_t    vscid;            /* Vendor Service context id */
  uint32_t    scid;
  bool        encapsulation_is_be;
  uint32_t    encapsulation_boundary;
  int         temp_offset;
  int         start_offset = *offset;
  int         dissected_len;

  /* create a subtree */

  /* set length to -1 (to the end) now and correct with proto_item_set_len()
   * later
   */
  tree = proto_tree_add_subtree(ptree, tvb, *offset, -1, ett_giop_scl, &tf, "ServiceContextList");

  /* Get sequence length (number of elements) */
  seqlen = get_CDR_ulong(tvb, offset, stream_is_be, boundary);
  proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                        *offset-(int)sizeof(seqlen), 4, seqlen);

  /* return if zero length sequence */

  if (seqlen == 0) {
    if (*offset-start_offset > 0) {
      proto_item_set_len(tf, *offset - start_offset);
    }
    return;
  }

  /* Loop for all ServiceContext's */

  for (i=0; i<seqlen; i++) {

    context_id = get_CDR_ulong(tvb, offset, stream_is_be, boundary);

    sc_item = proto_tree_add_item(tree, hf_giop_iiop_sc, tvb, *offset-4, -1, ENC_NA);
    sc_tree = proto_item_add_subtree (sc_item, ett_giop_sc);

    vscid = (context_id & 0xffffff00) >> 8; /* vendor info, top 24 bits */
    scid = context_id  & 0x000000ff; /* standard service info, lower 8 bits */
    proto_tree_add_uint(sc_tree, hf_giop_iiop_sc_vscid, tvb,
                          *offset-4, 4, vscid);
    if (vscid == 0)
    {
        proto_tree_add_uint(sc_tree, hf_giop_iiop_sc_omg_scid, tvb,
                              *offset-4, 4, scid);
    }
    else
    {
        proto_tree_add_uint(sc_tree, hf_giop_iiop_sc_vendor_scid, tvb,
                              *offset-4, 4, scid);
    }

    temp_offset = *offset;

    /* get sequence length, new endianness and boundary for encapsulation
     * See CORBA 3.0.2 standard, section Section 15.3.3 "Encapsulation",
     * for how CDR types can be marshalled into a sequence<octet>.
     * The first octet in the sequence determines endian order,
     * 0 == big-endian, 1 == little-endian
     */
    context_data_len = get_CDR_encap_info(tvb, sc_tree, offset,
                                          stream_is_be, boundary,
                                          &encapsulation_is_be,
                                          &encapsulation_boundary);

    if (context_data_len != 0)
    {
      /* A VSCID of 0 is for the OMG; all others are for vendors.
       * We only handle OMG service contexts. */
      if ( vscid != 0)
      {
        decode_UnknownServiceContext(tvb, pinfo, sc_tree, offset, encapsulation_is_be,
                                     encapsulation_boundary,
                                     context_data_len - 1);
      }
      else
      {
        switch (scid)
        {
        case 0x01: /* CodeSet */
          decode_CodeSetServiceContext(tvb, sc_tree, offset,
                                       encapsulation_is_be,
                                       encapsulation_boundary);
          break;

        case 0x0a: /* RTCorbaPriority */
          decode_RTCorbaPriority(tvb, sc_tree, offset,
                                 encapsulation_is_be, encapsulation_boundary);
          break;

        default:
          /* Need to fill these in as we learn them */
          decode_UnknownServiceContext(tvb, pinfo, sc_tree, offset,
                                       encapsulation_is_be,
                                       encapsulation_boundary,
                                       context_data_len - 1);
          break;
        }
      }
    }
    /* OK, we've processed what *should* be the entire service context.
     * Was that more than, less than, or equal to the actual data length?
     */
    dissected_len = *offset - (temp_offset + 4);
    if ((uint32_t)dissected_len > context_data_len)
    {
      /* XXX - it's a bit late to detect this *now*; just back up
       * the offset to where it should be.
       */
      *offset = temp_offset + 4 + context_data_len;
    }
    else if ((uint32_t)dissected_len < context_data_len)
    {
      /* Extra stuff at the end.  Make sure it exists, and then
       * skip over it.
       */
      tvb_ensure_bytes_exist(tvb, *offset, context_data_len - dissected_len);
      *offset = temp_offset + 4 + context_data_len;
    }
    proto_item_set_end(sc_item, tvb, *offset);

  } /* for seqlen  */

  proto_item_set_len(tf, *offset - start_offset);
}

static void
dissect_reply_body (tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, bool stream_is_big_endian,
                    uint32_t reply_status, MessageHeader *header, proto_tree *giop_tree) {

  unsigned sequence_length;
  bool exres = false;       /* result of trying explicit dissectors */
  int      reply_body_length;

  /*
   * comp_req_list stuff
   */

  comp_req_list_entry_t *entry = NULL; /* data element in our list */

  uint32_t mfn;

  switch (reply_status)
  {
  case SYSTEM_EXCEPTION:

    decode_SystemExceptionReplyBody (tvb, pinfo, tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    break;

  case USER_EXCEPTION:

    sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    proto_tree_add_uint(tree, hf_giop_exception_len, tvb, offset-4, 4,
                         sequence_length);

    if (sequence_length != 0 && sequence_length < ITEM_LABEL_LENGTH)
    {
      header->exception_id = tvb_get_stringz_enc(pinfo->pool, tvb, offset, &sequence_length, ENC_ASCII);

      proto_tree_add_string(tree, hf_giop_exception_id, tvb, offset,
                            sequence_length, header->exception_id);
      offset += sequence_length;
    }

    /*
     * Now just fall through to the NO_EXCEPTION part
     * as this is common .
     */


    /* FALL THROUGH */
  case NO_EXCEPTION:


    /* lookup MFN in hash directly */

    mfn = get_mfn_from_fn(pinfo->num);

    if (mfn == pinfo->num)
      return;                 /* no matching frame number, what am I */

    /* get entry for this MFN */
    entry = find_fn_in_list(mfn); /* get data entry in complete_request_list */

    if (!entry)
      return;                 /* no matching entry */


    /*
     * If this packet is a REPLY to a RESOLVE(request)
     * then decode IOR.
     * TODO - make this lookup faster -- FS
     */

    if (!strcmp(giop_op_resolve, entry->operation)) {
      decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);
      return;         /* done */
    }

    /* TODO -- Put stuff here for other "interesting operations" */

    /*
     *
     * Call sub dissector.
     * First try an find a explicit sub_dissector, then if that
     * fails, try the heuristic method.
     */


    if (entry->repoid) {
      exres = try_explicit_giop_dissector(tvb, pinfo, giop_tree, &offset, header, entry->operation, entry->repoid );
    }

    /* Only call heuristic if no explicit dissector was found */

    if (! exres) {
      exres = try_heuristic_giop_dissector(tvb, pinfo, giop_tree, &offset, header, entry->operation);
    }

    if (!exres && !strcmp(giop_op_is_a, entry->operation)) {
      proto_tree_add_boolean(tree, hf_giop_type_id_match, tvb, offset - 1, 1,
                          get_CDR_boolean(tvb, &offset));
    }

    if (! exres) {
      int stub_length = tvb_reported_length_remaining(tvb, offset);
      if (stub_length >0)
         proto_tree_add_item(tree, hf_giop_stub_data, tvb,
                             offset, stub_length, ENC_NA);
    }

    break;

  case LOCATION_FORWARD:
    decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);

    break;

  case LOCATION_FORWARD_PERM:
    decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);

    break;

  case NEEDS_ADDRESSING_MODE: {
    uint16_t addr_disp;
    addr_disp = get_CDR_ushort(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    proto_tree_add_uint (tree, hf_giop_address_disp, tvb, offset-2, 2, addr_disp);
    break;
    }

  default:
    reply_body_length = tvb_reported_length_remaining(tvb, offset);
    if (reply_body_length >0)
      proto_tree_add_item(tree, hf_giop_reply_body, tvb,
                             offset, reply_body_length, ENC_NA);
    break;

  }
}





/* The format of the Reply Header for GIOP 1.0 and 1.1
 * is documented in Section 15.4.3.1 of the CORBA 2.4 standard.

    struct ReplyHeader_1_0 {
          IOP::ServiceContextList service_context;
          unsigned long request_id;
          ReplyStatusType_1_0 reply_status;
    };
 */

static void dissect_giop_reply (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                                MessageHeader * header,
                                bool stream_is_big_endian) {

  int         offset = 0;
  uint32_t    request_id;
  uint32_t    reply_status;
  proto_tree *reply_tree;
  uint32_t    mfn;              /* matching frame number */

  reply_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_reply, NULL, "General Inter-ORB Protocol Reply");

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, pinfo, reply_tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);

  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id );

  proto_tree_add_uint(reply_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                    val_to_str(reply_status, reply_status_types, "Unknown (%u)"));
  proto_tree_add_uint(reply_tree, hf_giop_reply_status, tvb,
                         offset-4, 4, reply_status);

  /*
   * Save FN and MFN in complete_reply_hash, only if user is NOT clicking
   */

  if (! pinfo->fd->visited) {
    mfn = get_mfn_from_fn_and_reqid(pinfo->num, request_id, &pinfo->dst, pinfo->destport); /* find MFN for this FN */
    if (mfn != pinfo->num) { /* if mfn is not fn, good */
      insert_in_complete_reply_hash(pinfo->num, mfn);
    }
  }

  header->req_id = request_id;          /* save for sub dissector */
  header->rep_status = reply_status;   /* save for sub dissector */

  /* Do we have a body */
  if (tvb_reported_length_remaining(tvb, offset) > 0)
       dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
                          reply_status, header, tree);
}

/** The format of the GIOP 1.2 Reply header is very similar to the 1.0
 *  and 1.1 header, only the fields have been rearranged.  From Section
 *  15.4.3.1 of the CORBA 2.4 specification:
 *
 *   struct ReplyHeader_1_2 {
 *         unsigned long request_id;
 *         ReplyStatusType_1_2 reply_status;
 *         IOP:ServiceContextList service_context;
 *    };
 */

static void dissect_giop_reply_1_2 (tvbuff_t * tvb, packet_info * pinfo,
                                    proto_tree * tree,
                                    MessageHeader * header,
                                    bool stream_is_big_endian) {

  int         offset = 0;
  uint32_t    request_id;
  uint32_t    reply_status;
  proto_tree *reply_tree;
  uint32_t    mfn;              /* matching frame number */

  reply_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_reply, NULL, "General Inter-ORB Protocol Reply");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (reply_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                  val_to_str(reply_status, reply_status_types, "Unknown (%u)"));
  proto_tree_add_uint(reply_tree, hf_giop_reply_status, tvb,
                         offset-4, 4, reply_status);

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, pinfo, reply_tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);

  /*
   * GIOP 1.2 Reply body must fall on an 8 octet alignment.
   */

  set_new_alignment(&offset, GIOP_HEADER_SIZE, 8);

  /*
   * Save FN and MFN in complete_reply_hash, only if user is NOT clicking
   */

  if (! pinfo->fd->visited) {
    mfn = get_mfn_from_fn_and_reqid(pinfo->num, request_id, &pinfo->dst, pinfo->destport); /* find MFN for this FN */
    if (mfn != pinfo->num) { /* if mfn is not fn, good */
      insert_in_complete_reply_hash(pinfo->num, mfn);
    }
  }

  /*
   * Add header to argument list so sub dissector can get header info.
   */

  header->req_id = request_id;          /* save for sub dissector */
  header->rep_status = reply_status;   /* save for sub dissector */

  dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
                     reply_status, header, tree);
}

static void dissect_giop_cancel_request (tvbuff_t * tvb, packet_info * pinfo,
                        proto_tree * tree,
                        bool stream_is_big_endian) {

  int         offset = 0;
  uint32_t    request_id;
  proto_tree *cancel_request_tree;

  cancel_request_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
        ett_giop_cancel_request, NULL, "General Inter-ORB Protocol CancelRequest");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (cancel_request_tree, hf_giop_req_id, tvb, offset-4, 4,  request_id);
}

/**  The formats for GIOP 1.0 and 1.1 Request messages are defined
 *   in section 15.4.2.1 of the CORBA 2.4 specification.
 *
 *   struct RequestHeader{
 *          IOP::ServiceContextList   service_context;
 *          unsigned long             request_id;
 *          boolean                   response_expected;
 *          octet                     reserved[3];  // Only in GIOP 1.1
 *          sequence<octet>           object_key;
 *          string                    operation;
 *          CORBA::OctetSeq           requesting_principal;
 *   }
 */
static void
dissect_giop_request_1_1 (tvbuff_t * tvb, packet_info * pinfo,
                        proto_tree * tree,
                        MessageHeader * header, bool stream_is_big_endian)
{
  int          offset     = 0;
  uint32_t     request_id;
  uint32_t     len        = 0;

  uint32_t     objkey_len = 0;     /* object key length */
  const uint8_t *objkey    = NULL;  /* object key sequence */
  bool         exres      = false; /* result of trying explicit dissectors */

  const char *operation;
  const uint8_t *requesting_principal;
  uint8_t      response_expected;
  const uint8_t *reserved;
  char         miop[4];
  proto_tree  *request_tree;
  proto_item  *tf;

  char        *repoid;        /* from object key lookup in objkey hash */

  request_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_request, &tf, "General Inter-ORB Protocol Request");

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, pinfo, request_tree, &offset, stream_is_big_endian, 0);


  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (request_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  response_expected = tvb_get_uint8( tvb, offset );
  col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    response_expected ? "two-way" : "one-way");
  proto_tree_add_item(request_tree, hf_giop_rsp_expected, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if ( header->GIOP_version.minor > 0)
  {
    get_CDR_octet_seq(pinfo->pool, tvb, &reserved, &offset, 3);
    proto_tree_add_item(request_tree, hf_giop_reserved, tvb, offset-3, 3, ENC_NA);
  }

  /* Prior to GIOP 1.2, MIOP profile address prefixed with 'MIOP' */

  miop[0] = get_CDR_octet (tvb, &offset);
  miop[1] = get_CDR_octet (tvb, &offset);
  miop[2] = get_CDR_octet (tvb, &offset);
  miop[3] = get_CDR_octet (tvb, &offset);

  if (miop[0] == 'M' && miop[1] == 'I' && miop[2] == 'O' && miop[3] == 'P')
  {
    proto_tree_add_string(request_tree, hf_giop_message_magic, tvb, offset - 4, 4, "MIOP");
    decode_TaggedProfile (tvb, pinfo, request_tree, &offset, GIOP_HEADER_SIZE,
                          stream_is_big_endian, NULL);
  }
  else
  {
    /* Wind back if not MIOP profile */

    offset -= 4;

    /* Length of object_key sequence */
    objkey_len = get_CDR_ulong (tvb, &offset, stream_is_big_endian,
                                GIOP_HEADER_SIZE);
    tf = proto_tree_add_uint (request_tree, hf_giop_objekt_key_len, tvb, offset-4, 4, objkey_len);

    if (objkey_len > (uint32_t)tvb_reported_length_remaining(tvb, offset-4)) {
        expert_add_info_format(pinfo, tf, &ei_giop_length_too_big, "Object key length bigger than packet size");
        return;
    }

    if (objkey_len > 0)
    {
      get_CDR_octet_seq(pinfo->pool, tvb, &objkey, &offset, objkey_len);
      proto_tree_add_item(request_tree, hf_giop_objekt_key, tvb,
                             offset - objkey_len, objkey_len, ENC_NA);
    }
  }

  /* length of operation string and string */
  len = get_CDR_string(pinfo->pool, tvb, &operation, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  proto_tree_add_uint (request_tree, hf_giop_req_operation_len, tvb, offset - 4 - len, 4,  len);

  if ( len > 0)
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, ": op=%s", format_text(pinfo->pool, operation, (size_t)len));
    proto_tree_add_string(request_tree, hf_giop_req_operation, tvb, offset - len, len, operation);
  }

  /* length of requesting_principal string */
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  tf = proto_tree_add_uint (request_tree, hf_giop_req_principal_len, tvb, offset - 4, 4, len);

  if (len > (uint32_t)tvb_reported_length_remaining(tvb, offset-4)) {
    expert_add_info_format(pinfo, tf, &ei_giop_length_too_big, "Requesting Principal length bigger than packet size");
    return;
  }

  if ( len > 0)
  {
    get_CDR_octet_seq(pinfo->pool, tvb, &requesting_principal, &offset, len);
    proto_tree_add_string(request_tree, hf_giop_req_principal, tvb, offset - len, len,
                          make_printable_string(pinfo->pool, requesting_principal, len));
  }


  /*
   * Save FN, reqid, and operation for later. Add sub_handle later.
   * But only if user is NOT clicking.
   */
  if (! pinfo->fd->visited)
    giop_complete_request_list = insert_in_comp_req_list(giop_complete_request_list, pinfo->num,
                                                         request_id, operation, NULL, &pinfo->src, pinfo->srcport);


  /*
   * Call subdissector here before freeing "operation" and "key"
   * pass request_id also.
   * First try an find an explicit sub_dissector, then if that
   * fails, try the heuristic method.
   *
   */


  header->req_id = request_id;          /* save for sub dissector */
  repoid = get_repoid_from_objkey(giop_objkey_hash, objkey, objkey_len);


  if (repoid) {
    exres = try_explicit_giop_dissector(tvb, pinfo, tree, &offset, header, operation, repoid);
  }

  /* Only call heuristic if no explicit dissector was found */

  if (! exres) {
    exres = try_heuristic_giop_dissector(tvb, pinfo, tree, &offset, header, operation);
  }

  if (!exres && !strcmp(giop_op_is_a, operation) && request_tree) {
    const char *type_id;
    len = get_CDR_string(pinfo->pool, tvb, &type_id, &offset, stream_is_big_endian, 0);
    proto_tree_add_uint (request_tree, hf_giop_type_id_len, tvb, offset - 4 - len, 4,  len);
    proto_tree_add_string(request_tree, hf_giop_type_id, tvb, offset - len, len, type_id);
  }

  if (! exres) {
    int stub_length = tvb_reported_length_remaining(tvb, offset);
    proto_tree_add_item(request_tree, hf_giop_stub_data, tvb,
                             offset, stub_length, ENC_NA);
  }
}

/**  The format of a GIOP 1.2 RequestHeader message is
 *   (CORBA 2.4, sec. 15.4.2):
 *
 *   struct RequestHeader_1_2 {
 *       unsigned long request_id;
 *       octet response_flags;
 *       octet reserved[3];
 *       TargetAddress target;
 *       string operation;
 *       IOP::ServiceContextList service_context;
 *       // requesting_principal not in GIOP 1.2
 *   };
 */
static void
dissect_giop_request_1_2 (tvbuff_t * tvb, packet_info * pinfo,
                        proto_tree * tree,
                        MessageHeader * header, bool stream_is_big_endian)
{
  int          offset     = 0;
  uint32_t     request_id;
  uint32_t     len        = 0;
  const uint8_t *reserved;
  const char *operation  = NULL;
  proto_tree  *request_tree;
  bool         exres      = false; /* result of trying explicit dissectors */

  uint32_t     objkey_len = 0;  /* object key length */
  const uint8_t *objkey    = NULL; /* object key sequence */
  char        *repoid     = NULL; /* from object key lookup in objkey hash */

  request_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_request, NULL, "General Inter-ORB Protocol Request");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  header->req_id = request_id;
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (request_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  proto_tree_add_item(request_tree, hf_giop_response_flag, tvb,
                             offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  get_CDR_octet_seq(pinfo->pool, tvb, &reserved, &offset, 3);
  proto_tree_add_item(request_tree, hf_giop_reserved, tvb, offset-3, 3, ENC_NA);

  dissect_target_address(tvb, pinfo, &offset, request_tree, stream_is_big_endian,
                         &objkey_len, &objkey);
  if (objkey) {
    repoid = get_repoid_from_objkey(giop_objkey_hash, objkey, objkey_len);
  }

  /* length of operation string and string */
  len = get_CDR_string(pinfo->pool, tvb, &operation, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  proto_tree_add_uint (request_tree, hf_giop_req_operation_len, tvb, offset - 4 - len, 4,  len);

  if ( len > 0)
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, ": op=%s", format_text(pinfo->pool, operation, (size_t)len));
    proto_tree_add_string(request_tree, hf_giop_req_operation, tvb, offset - len, len, operation);
  }

  /*
   * Decode IOP::ServiceContextList
   */
  decode_ServiceContextList(tvb, pinfo, request_tree, &offset,  stream_is_big_endian, GIOP_HEADER_SIZE);

  /*
   * GIOP 1.2 Request body must fall on an 8 octet alignment, taking into
   * account we are in a new tvbuff, GIOP_HEADER_SIZE octets from the
   * GIOP octet stream start.
   */

  if (tvb_reported_length_remaining(tvb, offset) > 0)
  {
    set_new_alignment(&offset, GIOP_HEADER_SIZE, 8);
  }

  /*
   * Save FN, reqid, and operation for later. Add sub_handle later.
   * But only if user is NOT clicking.
   */

  if (! pinfo->fd->visited)
    giop_complete_request_list = insert_in_comp_req_list(giop_complete_request_list, pinfo->num,
                                                         request_id, operation, NULL, &pinfo->src, pinfo->srcport);

  /*
   *
   * Call sub dissector.
   * First try an find a explicit sub_dissector, then if that
   * fails, try the heuristic method.
   */

  if (repoid) {
    exres = try_explicit_giop_dissector(tvb, pinfo, tree, &offset, header, operation, repoid);
  }

  /* Only call heuristic if no explicit dissector was found */

  if (! exres) {
    exres = try_heuristic_giop_dissector(tvb, pinfo, tree, &offset, header, operation);
  }

  if (!exres && !strcmp(giop_op_is_a, operation) && request_tree) {
    const char *type_id;
    len = get_CDR_string(pinfo->pool, tvb, &type_id, &offset, stream_is_big_endian, 0);
    proto_tree_add_uint (request_tree, hf_giop_type_id_len, tvb, offset - 4 - len, 4,  len);
    proto_tree_add_string(request_tree, hf_giop_type_id, tvb, offset - len, len, type_id);
  }

  if (! exres) {
    int stub_length = tvb_reported_length_remaining(tvb, offset);
    if (stub_length > 0)
         proto_tree_add_item(request_tree, hf_giop_stub_data, tvb,
                             offset, stub_length, ENC_NA);
  }
}

static void
dissect_giop_locate_request( tvbuff_t * tvb, packet_info * pinfo,
                             proto_tree * tree, MessageHeader * header,
                             bool stream_is_big_endian)
{
  int         offset = 0;
  uint32_t    request_id;
  uint32_t    len    = 0;
  proto_tree *locate_request_tree;
  proto_item *tf;

  locate_request_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
      ett_giop_locate_request, &tf, "General Inter-ORB Locate Request");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u op=LocateRequest", request_id);
  proto_tree_add_uint (locate_request_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  if (header->GIOP_version.minor < 2)
  {
    len = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    proto_tree_add_uint (locate_request_tree, hf_giop_objekt_key_len, tvb, offset-4, 4, len);

    if (len > (uint32_t)tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info_format(pinfo, tf, &ei_giop_length_too_big, "Object key length bigger than packet size");
        return;
    }

    if (len > 0) {
        proto_tree_add_item(locate_request_tree, hf_giop_objekt_key, tvb, offset, len, ENC_NA);
    }
  }
  else     /* GIOP 1.2 and higher */
  {
    dissect_target_address(tvb, pinfo, &offset, locate_request_tree,
                           stream_is_big_endian, NULL, NULL);
  }
}

static void
dissect_giop_locate_reply( tvbuff_t * tvb, packet_info * pinfo,
                        proto_tree * tree, MessageHeader * header,
                        bool stream_is_big_endian)
{
  int     offset = 0;
  uint32_t request_id;
  uint32_t locate_status;
  uint16_t addr_disp;

  proto_tree *locate_reply_tree;

  locate_reply_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_locate_reply, NULL, "General Inter-ORB Locate Reply");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (locate_reply_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);

  locate_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  proto_tree_add_uint (locate_reply_tree, hf_giop_locale_status, tvb, offset-4, 4, locate_status);

  /* Decode the LocateReply body.
   *
   * For GIOP 1.0 and 1.1 body immediately follows header.
   * For GIOP 1.2 it is aligned on 8 octet boundary so need to
   * spin up.
   */

  if (header->GIOP_version.minor > 1) {
    while ( ( (offset + GIOP_HEADER_SIZE) % 8) != 0)
      ++(offset);
  }

  switch (locate_status) {
  case OBJECT_FORWARD: /* fall through to OBJECT_FORWARD_PERM */
  case OBJECT_FORWARD_PERM:
    decode_IOR(tvb, pinfo, locate_reply_tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);
    break;
  case LOC_SYSTEM_EXCEPTION:
    decode_SystemExceptionReplyBody (tvb, pinfo, tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    break;
  case LOC_NEEDS_ADDRESSING_MODE:
    addr_disp = get_CDR_ushort(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    proto_tree_add_uint (tree, hf_giop_addressing_disposition, tvb, offset-2, 2, addr_disp);
    break;
  default: /* others have no reply body */
    break;
  }

}

static void
dissect_giop_fragment( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
                bool stream_is_big_endian)
{
  int         offset = 0;
  uint32_t    request_id;
  proto_tree *fragment_tree;

  fragment_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_giop_fragment, NULL, "General Inter-ORB Fragment");

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
  col_append_fstr(pinfo->cinfo, COL_INFO, " id=%u", request_id);
  proto_tree_add_uint (fragment_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);
}


/* Main entry point */

static int dissect_giop_common (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {
  int            offset = 0;
  MessageHeader  header;
  tvbuff_t      *payload_tvb;

  proto_tree    *giop_tree, *header_tree, *header_version_tree;
  proto_item    *ti, *version_item;
  unsigned       message_size;
  bool           stream_is_big_endian;

  conversation_t *conversation;
  uint8_t        message_type;
  giop_conv_info_t *giop_info;

//  giop_dump_collection(cd_module_hash);
//  giop_dump_collection(cd_objkey_hash);
//  giop_dump_collection(cd_heuristic_users);
//  giop_dump_collection(cd_complete_reply_hash);
//  giop_dump_collection(cd_complete_request_list);

  header.exception_id = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GIOP");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item (tree, proto_giop, tvb, 0, -1, ENC_NA);
  giop_tree = proto_item_add_subtree (ti, ett_giop);

  /* Get raw header data */
  tvb_memcpy (tvb, (uint8_t *)&header, 0, GIOP_HEADER_SIZE );
  stream_is_big_endian = is_big_endian (&header);

  /* Dissect GIOP header */
  header_tree = proto_tree_add_subtree(giop_tree, tvb, offset, GIOP_HEADER_SIZE, ett_giop_header, NULL, "GIOP Header");
  proto_tree_add_item(header_tree, hf_giop_message_magic, tvb, 0, 4, ENC_ASCII);

  header_version_tree = proto_tree_add_subtree_format(header_tree, tvb, 4, 2, ett_giop_header_version, &version_item,
                     "Version: %u.%u", header.GIOP_version.major, header.GIOP_version.minor);
  proto_tree_add_item(header_version_tree, hf_giop_message_major_version, tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(header_version_tree, hf_giop_message_minor_version, tvb, 5, 1, ENC_BIG_ENDIAN);

  if ((header.GIOP_version.major != GIOP_MAJOR) ||
      (header.GIOP_version.minor > GIOP_MINOR))
  {
    /* Bad version number; should we note that and dissect the rest
       as data, or should this be done outside dissect_giop_common()
       (which is called as the PDU dissector for GIOP-over-TCP,
       so it can't return anything), with the test returning false
       on the theory that it might have been some other packet that
       happened to begin with "GIOP"?  We do the former, for now.
       If we should return false, we should do so *without* setting
       the "Info" column, *without* setting the "Protocol" column,
       and *without* adding anything to the protocol tree. */
    col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
                  header.GIOP_version.major, header.GIOP_version.minor);

    expert_add_info_format(pinfo, version_item, &ei_giop_version_not_supported, "Version %u.%u not supported",
                           header.GIOP_version.major, header.GIOP_version.minor);

    payload_tvb = tvb_new_subset_remaining (tvb, GIOP_HEADER_SIZE);
    call_data_dissector(payload_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
  }

  switch (header.GIOP_version.minor)
  {
    case 2:
    case 1:
      ti = proto_tree_add_bitmask(header_version_tree, tvb, 6,
                              hf_giop_message_flags, ett_giop_message_flags,
                              giop_message_flags, ENC_BIG_ENDIAN);
      if ((header.flags & GIOP_MESSAGE_FLAGS_ENDIANNESS) == 0)
        proto_item_append_text(ti, ", (Big Endian)");  /* hack to show "Big Endian" when endianness flag == 0 */
      break;
    case 0:
      proto_tree_add_boolean(header_tree, hf_giop_message_flags_little_endian, tvb, 6, 1, stream_is_big_endian ? 0 : 1);
      break;
  }

  proto_tree_add_item(header_tree, hf_giop_message_type, tvb, 7, 1, ENC_BIG_ENDIAN);

  if (stream_is_big_endian)
  {
    message_size = tvb_get_ntohl(tvb, 8);
  }
  else
  {
    message_size = tvb_get_letohl(tvb, 8);
  }

  col_add_fstr (pinfo->cinfo, COL_INFO, "GIOP %u.%u %s, s=%u",
                header.GIOP_version.major, header.GIOP_version.minor,
                val_to_str(header.message_type, giop_message_types, "Unknown message type (0x%02x)"),
                message_size);

  ti = proto_tree_add_uint(header_tree, hf_giop_message_size, tvb, 8, 4, message_size);
  if (message_size > giop_max_message_size)
  {
      expert_add_info_format(pinfo, ti, &ei_giop_message_size_too_big,
            "Message size %u is too big, perhaps it's an endian issue?", message_size);
      return 8;
  }

  if (message_size == 0) {
      return 8;
  }

  if (header.flags & GIOP_MESSAGE_FLAGS_ZIOP_ENABLED)
  {
    int rem_len;

    rem_len = tvb_captured_length_remaining(tvb, GIOP_HEADER_SIZE);
    if (rem_len <= 0)
      return 8;

    payload_tvb = tvb_child_uncompress_zlib(tvb, tvb, GIOP_HEADER_SIZE, rem_len);
    if (payload_tvb) {
      add_new_data_source (pinfo, payload_tvb, "decompressed Content");
    } else {
      /* Decompression failed. */
      /* XXX: Consider:  add expert item ? do data dissection ? */
      return 8;
    }
  } else {
    payload_tvb = tvb_new_subset_remaining (tvb, GIOP_HEADER_SIZE);
  }

  if(giop_reassemble) {
    /* This is a fragmented message - try and put it back together */
    fragment_head *fd_head = NULL;
    tvbuff_t      *reassembled_tvb;
    int frag_offset = 0;

    /* request id is the first 4 bytes */
    header.req_id = get_CDR_ulong(payload_tvb, &frag_offset, stream_is_big_endian, GIOP_HEADER_SIZE);

    if(header.message_type != Fragment)
      frag_offset = 0; /* Maintain the request id for everything but fragments */

    fd_head = fragment_add_seq_next(&giop_reassembly_table,
                                    payload_tvb, frag_offset, pinfo,
                                    header.req_id, NULL,
                                    tvb_captured_length_remaining(payload_tvb, frag_offset),
                                    header.flags & GIOP_MESSAGE_FLAGS_FRAGMENT);

    reassembled_tvb = process_reassembled_data(payload_tvb, frag_offset, pinfo, "Reassembled GIOP",
                                           fd_head, &giop_frag_items, NULL, tree);

    if(reassembled_tvb != NULL)
      payload_tvb = reassembled_tvb;

    /* Record the type of this request id so we can dissect it correctly later */
    conversation = find_or_create_conversation(pinfo);

    giop_info = (giop_conv_info_t *)conversation_get_proto_data(conversation, proto_giop);

    if(giop_info == NULL) {

      giop_info = wmem_new0(wmem_file_scope(), giop_conv_info_t);

      giop_info->optypes = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

      conversation_add_proto_data(conversation, proto_giop, giop_info);
    }

    if(header.message_type != Fragment) {
      /* Record the type of this request id so we can dissect it correctly later */
      wmem_map_insert(giop_info->optypes, GUINT_TO_POINTER(header.req_id), GUINT_TO_POINTER((unsigned)header.message_type));
    } else if (!(header.flags & GIOP_MESSAGE_FLAGS_FRAGMENT)) {
      /* This is the last fragment, recoverr the original messagetype */
      message_type = (uint8_t)GPOINTER_TO_UINT(wmem_map_lookup(giop_info->optypes, GUINT_TO_POINTER(header.req_id)));

      /* We override the header message type and size */
      header.message_type = message_type;
      header.message_size = tvb_captured_length_remaining(payload_tvb, 0);
    }
  }

  switch (header.message_type)
  {

  case Request:
    if (header.GIOP_version.minor < 2)
    {
      dissect_giop_request_1_1 (payload_tvb, pinfo, tree,
                                &header, stream_is_big_endian);
    }
    else
    {
      dissect_giop_request_1_2 (payload_tvb, pinfo, tree,
                                &header, stream_is_big_endian);
    }

    break;


  case Reply:
    if (header.GIOP_version.minor < 2)
    {
      dissect_giop_reply (payload_tvb, pinfo, tree, &header,
                          stream_is_big_endian);
    }
    else
    {
      dissect_giop_reply_1_2 (payload_tvb, pinfo, tree,
                              &header, stream_is_big_endian);
    }
    break;
  case CancelRequest:
    dissect_giop_cancel_request(payload_tvb, pinfo, tree,
                                stream_is_big_endian);
    break;
  case LocateRequest:
    dissect_giop_locate_request(payload_tvb, pinfo, tree, &header,
                                stream_is_big_endian);
    break;
  case LocateReply:
    dissect_giop_locate_reply(payload_tvb, pinfo, tree, &header,
                              stream_is_big_endian);
    break;
  case Fragment:
    dissect_giop_fragment(payload_tvb, pinfo, tree,
                          stream_is_big_endian);
    break;
  default:
    break;

  }                               /* switch message_type */

  return tvb_captured_length(tvb);
}

static unsigned
get_giop_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{

  MessageHeader header;
  unsigned message_size;

  if (tvb_reported_length_remaining(tvb, offset) < GIOP_HEADER_SIZE)
    return 0;

  if (tvb_get_ntohl(tvb, 0 + offset) != GIOP_MAGIC_NUMBER)
    return 0;

  /* Get minimal header information to determine endianness, size */
  header.GIOP_version.minor = tvb_get_uint8(tvb, 5 + offset);
  header.flags = tvb_get_uint8(tvb, 6 + offset);

  if (is_big_endian (&header))
    message_size = tvb_get_ntohl(tvb, 8 + offset);
  else
    message_size = tvb_get_letohl(tvb, 8 + offset);

  /* Make sure the size is reasonable, otherwise just take the header */
  if (message_size > giop_max_message_size)
      return GIOP_HEADER_SIZE;

  return message_size + GIOP_HEADER_SIZE;
}

static bool
dissect_giop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *);


bool dissect_giop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  return dissect_giop_heur(tvb, pinfo, tree, NULL);
}


static int
dissect_giop_tcp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data) {

  if (tvb_get_ntohl(tvb, 0) != GIOP_MAGIC_NUMBER) {

    if ( tvb_memeql(tvb, 0, (const uint8_t *)ZIOP_MAGIC , 4) == 0)
      if (!dissect_ziop_heur(tvb, pinfo, tree, NULL))
        return 0;

    return tvb_captured_length(tvb);
  }

  tcp_dissect_pdus(tvb, pinfo, tree, giop_desegment, GIOP_HEADER_SIZE,
                   get_giop_pdu_len, dissect_giop_common, data);
  return tvb_captured_length(tvb);
}

static bool
dissect_giop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * data) {

  unsigned tot_len;

  conversation_t *conversation;
  /* check magic number and version */

  /*define END_OF_GIOP_MESSAGE (offset - first_offset - GIOP_HEADER_SIZE) */

  tot_len = tvb_captured_length(tvb);

  if (tot_len < GIOP_HEADER_SIZE) /* tot_len < 12 */
  {
    /* Not enough data captured to hold the GIOP header; don't try
       to interpret it as GIOP. */
    return false;
  }

  if (tvb_get_ntohl(tvb, 0) != GIOP_MAGIC_NUMBER)
     return false;

  if ( pinfo->ptype == PT_TCP )
  {
    /*
     * Make the GIOP dissector the dissector for this conversation.
     *
     * If this isn't the first time this packet has been processed,
     * we've already done this work, so we don't need to do it
     * again.
     */
    if (!pinfo->fd->visited)
    {
      conversation = find_or_create_conversation(pinfo);

      /* Set dissector */
      conversation_set_dissector(conversation, giop_tcp_handle);
    }
    dissect_giop_tcp (tvb, pinfo, tree, data);
  }
  else
  {
    dissect_giop_common (tvb, pinfo, tree, data);
  }

  return true;

}

static void
giop_shutdown(void)
{
	g_slist_free(giop_sub_list);
	g_hash_table_destroy(giop_module_hash);
}

void
proto_register_giop (void)
{
  static hf_register_info hf[] = {
    { &hf_giop_message_magic,
      { "Magic", "giop.magic",
        FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &hf_giop_message_major_version,
      { "Major Version", "giop.major_version",
        FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_giop_message_minor_version,
      { "Minor Version", "giop.minor_version",
        FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &hf_giop_message_flags,
      { "Message Flags", "giop.flags",
        FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
    },

    { &hf_giop_message_flags_ziop_enabled,
      { "ZIOP Enabled", "giop.flags.ziop_enabled",
        FT_BOOLEAN, 8, NULL, GIOP_MESSAGE_FLAGS_ZIOP_ENABLED, NULL, HFILL }
    },

    { &hf_giop_message_flags_ziop_supported,
      { "ZIOP Supported", "giop.flags.ziop_supported",
        FT_BOOLEAN, 8, NULL, GIOP_MESSAGE_FLAGS_ZIOP_SUPPORTED, NULL, HFILL }
    },

    { &hf_giop_message_flags_fragment,
      { "Fragment", "giop.flags.fragment",
        FT_BOOLEAN, 8, NULL, GIOP_MESSAGE_FLAGS_FRAGMENT, NULL, HFILL }
    },

    { &hf_giop_message_flags_little_endian,
      { "Little Endian", "giop.flags.little_endian",
        FT_BOOLEAN, 8, NULL, GIOP_MESSAGE_FLAGS_ENDIANNESS, NULL, HFILL }
    },

    { &hf_giop_message_type,
      { "Message type", "giop.type",
        FT_UINT8, BASE_DEC, VALS(giop_message_types), 0x0, NULL, HFILL }
    },

    { &hf_giop_message_size,
      { "Message size", "giop.len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_repoid,
      { "Repository ID", "giop.repoid",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_string_length,
      { "String Length", "giop.strlen",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_sequence_length,
      { "Sequence Length", "giop.seqlen",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_profile_id,
      { "Profile ID", "giop.profid",
        FT_UINT32, BASE_DEC, VALS(profile_id_vals), 0x0, NULL, HFILL }
    },

    { &hf_giop_type_id,
      { "IOR::type_id", "giop.typeid",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_id_match,
      { "Type Id", "giop.typeid.match",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_matched_not_matched), 0x0, NULL, HFILL }
    },

    { &hf_giop_type_id_len,
      { "Type Id length", "giop.typeid_len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_iiop_v_maj,
      { "IIOP Major Version", "giop.iiop_vmaj",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    }
    ,
    { &hf_giop_iiop_v_min,
      { "IIOP Minor Version", "giop.iiop_vmin",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

#if 0
    { &hf_giop_compressed,
      { "ZIOP", "giop.compressed",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
#endif

    { &hf_giop_endianness,
      { "Endianness", "giop.endianness",
        FT_UINT8, BASE_DEC, VALS(giop_endianness_vals), 0x0, NULL, HFILL }
    },

    { &hf_giop_locale_status,
      { "Locate status", "giop.locale_status",
        FT_UINT32, BASE_DEC, VALS(giop_locate_status_types), 0x0, NULL, HFILL }
    },

    { &hf_giop_addressing_disposition,
      { "Addressing Disposition", "giop.addressing_disposition",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_profile_data,
      { "Profile Data", "giop.profile_data",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_component_data,
      { "Component Data", "giop.component_data",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_rt_corba_priority,
      { "RTCorbaPriority", "giop.rt_corba_priority",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_target_address_discriminant,
      { "TargetAddress", "giop.target_address.discriminant",
        FT_UINT16, BASE_DEC, VALS(target_address_discriminant_vals), 0x0, NULL, HFILL }
    },

    { &hf_giop_target_address_key_addr_len,
      { "Key Address Length", "giop.target_address.key_addr_len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_target_address_key_addr,
      { "Key Address", "giop.target_address.key_addr",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_target_address_ref_addr_len,
      { "Reference Address Length", "giop.target_address.ref_addr_len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_context_data,
      { "Context Data", "giop.context_data",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_char_data,
      { "char data", "giop.char_data",
        FT_UINT32, BASE_DEC | BASE_EXT_STRING, &giop_code_set_vals_ext, 0x0, NULL, HFILL }
    },

    { &hf_giop_wchar_data,
      { "wchar data", "giop.wchar_data",
        FT_UINT32, BASE_DEC | BASE_EXT_STRING, &giop_code_set_vals_ext, 0x0, NULL, HFILL }
    },

    { &hf_giop_IIOP_tag,
      { "IIOP Component TAG", "giop.iioptag",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

#if 0
    { &hf_giop_IOR_tag,
      { "IOR Profile TAG", "giop.iortag",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
#endif

    { &hf_giop_TCKind,
      { "TypeCode enum", "giop.TCKind",
        FT_UINT32, BASE_DEC, VALS(tckind_vals), 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_count,
      { "TypeCode count", "giop.tccount",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_default_used,
      { "default_used", "giop.tcdefault_used",
        FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_digits,
      { "Digits", "giop.tcdigits",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },


    { &hf_giop_typecode_length,
      { "Length", "giop.tclength",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_max_length,
      { "Maximum length", "giop.tcmaxlen",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_member_name,
      { "TypeCode member name", "giop.tcmemname",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_name,
      { "TypeCode name", "giop.tcname",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_scale,
      { "Scale", "giop.tcscale",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_ValueModifier,
      { "ValueModifier", "giop.tcValueModifier",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_typecode_Visibility,
      { "Visibility", "giop.tcVisibility",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },



    { &hf_giop_type_boolean,
      { "TypeCode boolean data", "giop.tcboolean",
        FT_BOOLEAN, BASE_NONE,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_char,
      { "TypeCode char data", "giop.tcchar",
        FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_double,
      { "TypeCode double data", "giop.tcdouble",
        FT_DOUBLE, BASE_NONE,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_enum,
      { "TypeCode enum data", "giop.tcenumdata",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_float,
      { "TypeCode float data", "giop.tcfloat",
        FT_FLOAT, BASE_NONE,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_long,
      { "TypeCode long data", "giop.tclongdata",
        FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_longlong,
      { "TypeCode longlong data", "giop.tclonglongdata",
        FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_ulonglong,
      { "TypeCode ulonglong data", "giop.tculonglongdata",
        FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_octet,
      { "TypeCode octet data", "giop.tcoctet",
        FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_short,
      { "TypeCode short data", "giop.tcshortdata",
        FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_string,
      { "TypeCode string data", "giop.tcstring",
        FT_STRING, BASE_NONE,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_ulong,
      { "TypeCode ulong data", "giop.tculongdata",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_type_ushort,
      { "TypeCode ushort data", "giop.tcushortdata",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /*
     * IIOP Module - Chapter 15.10.2
     */

    { &hf_giop_iiop_host,
      { "IIOP::Profile_host", "giop.iiop.host",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_iiop_port,
      { "IIOP::Profile_port", "giop.iiop.port",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    /*
     * IIOP ServiceContext
     */

    { &hf_giop_iiop_sc,
      { "ServiceContext", "giop.iiop.sc",
        FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},

    { &hf_giop_iiop_sc_vscid,
      { "VSCID", "giop.iiop.sc.vscid",
        FT_UINT32, BASE_HEX, NULL, 0xffffff00, NULL, HFILL }
    },

    /* SCID for OMG */
    { &hf_giop_iiop_sc_omg_scid,
      { "SCID", "giop.iiop.sc.scid",
        FT_UINT32, BASE_HEX, VALS(service_context_ids), 0x000000ff, NULL, HFILL }
    },

    /* SCID for vendor */
    { &hf_giop_iiop_sc_vendor_scid,
      { "SCID", "giop.iiop.sc.scid",
        FT_UINT32, BASE_HEX, NULL, 0x000000ff, NULL, HFILL }
    },

    { &hf_giop_req_id,
      { "Request id", "giop.request_id",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_giop_req_operation_len,
      { "Operation length", "giop.request_op_len",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_giop_req_operation,
      { "Request operation", "giop.request_op",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_req_principal_len,
      { "Requesting Principal Length", "giop.request_principal_len",
        FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
    },

    { &hf_giop_req_principal,
      { "Requesting Principal", "giop.request_principal",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_reply_status,
      { "Reply status", "giop.replystatus",
        FT_UINT32, BASE_DEC, VALS(reply_status_types), 0x0, NULL, HFILL }
    },

    { &hf_giop_exception_len,
      { "Exception length", "giop.exceptionid_len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_exception_id,
      { "Exception id", "giop.exceptionid",
        FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_objekt_key,
      { "Object Key", "giop.objektkey",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_objekt_key_len,
      { "Object Key length", "giop.objektkey_len",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_rsp_expected,
      { "Response expected", "giop.rsp_expected",
        FT_UINT8, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_response_flag,
      { "Response flags", "giop.response_flag",
        FT_UINT8, BASE_DEC, VALS(response_flags_vals), 0x0, NULL, HFILL }
    },

    { &hf_giop_reserved,
      { "Reserved", "giop.reserved",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_stub_data,
      { "Stub data", "giop.stub_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_address_disp,
      { "Addressing Disposition", "giop.address_disposition",
        FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_minor_code_value,
      { "Minor code value", "giop.minor_code_value",
        FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_completion_status,
      { "Completion Status", "giop.completion_status",
        FT_UINT32, BASE_DEC,  NULL, 0x0, NULL, HFILL }
    },

    { &hf_giop_reply_body,
      { "Reply body", "giop.reply_body",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &hf_giop_fragment_overlap,
      { "Fragment overlap", "giop.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
    { &hf_giop_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap", "giop.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_giop_fragment_multiple_tails,
            { "Multiple tail fragments found", "giop.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when reassembling the packet", HFILL }},

        { &hf_giop_fragment_too_long_fragment,
            { "Fragment too long", "giop.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }},

        { &hf_giop_fragment_error,
            { "Reassembly error", "giop.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Reassembly error due to illegal fragments", HFILL }},

        { &hf_giop_fragment_count,
            { "Fragment count", "giop.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_giop_fragment,
            { "GIOP Fragment", "giop.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_giop_fragments,
            { "GIOP Fragments", "giop.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_giop_reassembled_in,
            { "Reassembled GIOP in frame", "giop.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This GIOP packet is reassembled in this frame", HFILL }},

        { &hf_giop_reassembled_length,
            { "Reassembled GIOP length", "giop.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }}
  };

  static int *ett[] = {
    &ett_giop,
    &ett_giop_header,
    &ett_giop_header_version,
    &ett_giop_message_flags,
    &ett_giop_reply,
    &ett_giop_request,
    &ett_giop_cancel_request,
    &ett_giop_locate_request,
    &ett_giop_locate_reply,
    &ett_giop_fragment,
    &ett_giop_scl,
    &ett_giop_sc,
    &ett_giop_ior,
    &ett_giop_fragment_,
    &ett_giop_fragments,

    &ett_giop_array,
    &ett_giop_sequence,
    &ett_giop_struct,
    &ett_giop_typecode_parameters,

  };

  static ei_register_info ei[] = {
    { &ei_giop_unknown_typecode_datatype, { "giop.unknown_typecode_datatype", PI_PROTOCOL, PI_WARN, "Unknown typecode data type", EXPFILL }},
    { &ei_giop_unknown_sign_value, { "giop.unknown_sign_value", PI_PROTOCOL, PI_WARN, "Unknown sign value in fixed type", EXPFILL }},
    { &ei_giop_unknown_tckind, { "giop.unknown_tckind", PI_PROTOCOL, PI_WARN, "Unknown TCKind", EXPFILL }},
    { &ei_giop_length_too_big, { "giop.length_too_big", PI_MALFORMED, PI_ERROR, "length bigger than packet size", EXPFILL }},
    { &ei_giop_version_not_supported, { "giop.version_not_supported", PI_PROTOCOL, PI_WARN, "Version not supported", EXPFILL }},
    { &ei_giop_message_size_too_big, { "giop.message_size_too_big", PI_PROTOCOL, PI_WARN, "Message size is too big", EXPFILL }},
    { &ei_giop_invalid_v_minor, { "giop.invalid_v_minor", PI_PROTOCOL, PI_WARN, "Invalid v_minor value", EXPFILL }},
    { &ei_giop_max_recursion_depth_reached, { "giop.max_recursion_depth_reached", PI_PROTOCOL, PI_WARN, "Maximum allowed recursion depth reached. Dissection stopped.", EXPFILL }},
    { &ei_giop_offset_error, { "giop.offset_error", PI_PROTOCOL, PI_WARN, "Offset field error", EXPFILL } },
  };

  module_t *giop_module;
  expert_module_t* expert_giop;

  proto_giop = proto_register_protocol("General Inter-ORB Protocol", "GIOP", "giop");

  /* Register by name */
  giop_tcp_handle = register_dissector("giop", dissect_giop_tcp, proto_giop);

  proto_register_field_array (proto_giop, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_giop = expert_register_protocol(proto_giop);
  expert_register_field_array(expert_giop, ei, array_length(ei));


  /* register init routine */

  register_init_routine( &giop_init); /* any init stuff */
  register_cleanup_routine( &giop_cleanup);

  reassembly_table_register(&giop_reassembly_table,
                        &addresses_reassembly_table_functions);

  /* Register for tapping */
  giop_tap = register_tap(GIOP_TAP_NAME); /* GIOP statistics tap */


  /* register preferences */
  giop_module = prefs_register_protocol(proto_giop, NULL);
  prefs_register_bool_preference(giop_module, "desegment_giop_messages",
    "Reassemble GIOP messages spanning multiple TCP segments",
    "Whether the GIOP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &giop_desegment);
  prefs_register_bool_preference(giop_module, "reassemble",
                                 "Reassemble fragmented GIOP messages",
                                 "Whether fragmented GIOP messages should be reassembled",
                                 &giop_reassemble);
  prefs_register_uint_preference(giop_module, "max_message_size",
                                 "Maximum allowed message size",
                                 "Maximum allowed message size in bytes (default=10485760)",
                                 10, &giop_max_message_size);

  prefs_register_filename_preference(giop_module, "ior_txt", "Stringified IORs",
    "File containing stringified IORs, one per line.", &giop_ior_file, false);

  /*
   * Init the giop user module hash tables here, as giop users
   * will populate it via register_giop_user_module BEFORE my
   * own giop_init() is called.
   */

  giop_module_hash = g_hash_table_new(giop_hash_module_hash, giop_hash_module_equal);

  register_shutdown_routine(giop_shutdown);
}



void proto_reg_handoff_giop (void) {
  heur_dissector_add("tcp", dissect_giop_heur, "GIOP over TCP", "giop_tcp", proto_giop, HEURISTIC_ENABLE);
  /* Support DIOP (GIOP/UDP) */
  heur_dissector_add("udp", dissect_giop_heur, "DIOP (GIOP/UDP)", "giop_udp", proto_giop, HEURISTIC_ENABLE);
  dissector_add_for_decode_as_with_preference("tcp.port", giop_tcp_handle);
}




/*
 * Decode IOR
 *
 * Ref Corba v2.4.2 Chapter 13
 *
 */

/*

module IOP{

    typedef unsigned long ProfileId;

    const ProfileId TAG_INTERNET_IOP = 0;
    const ProfileId TAG_MULTIPLE_COMPONENTS = 1;

    struct TaggedProfile {
      ProfileId tag;
      sequence <octet> profile_data;
    };

    struct IOR {
      string type_id;
      sequence <TaggedProfile> profiles;
    };

    typedef unsigned long ComponentId;

    struct TaggedComponent {
      ComponentId tag;
      sequence <octet> component_data;
    };

    typedef sequence <TaggedComponent> MultipleComponentProfile;

};

*/

static void decode_IOR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, int *offset,
                       uint32_t boundary, bool stream_is_big_endian) {


  uint32_t seqlen_p;     /* sequence length of profiles */
  uint32_t u_octet4;

  proto_tree *tree;     /* IOR tree */

  const char *repobuf; /* for repository ID */

  uint32_t i;

  /* create a subtree */
  tree = proto_tree_add_subtree(ptree, tvb, *offset, -1, ett_giop_ior, NULL, "IOR");

  /* Get type_id  == Repository ID */

  u_octet4 = get_CDR_string(pinfo->pool, tvb, &repobuf, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                        *offset-u_octet4-(int)sizeof(u_octet4), 4, u_octet4);
  if (u_octet4 > 0) {
      proto_tree_add_string(tree, hf_giop_type_id, tvb,
                            *offset-u_octet4, u_octet4, repobuf);
  }

  /* Now get a sequence of profiles */
  /* Get sequence length (number of elements) */

  seqlen_p = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                        *offset-(int)sizeof(seqlen_p), 4, seqlen_p);

  /* fetch all TaggedProfiles in this sequence */
  for (i=0; i< seqlen_p; i++) {
    decode_TaggedProfile(tvb, pinfo, tree, offset, boundary, stream_is_big_endian, repobuf);
  }
}

static void decode_TaggedProfile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                 uint32_t boundary, bool stream_is_big_endian, const char *repobuf) {

  uint32_t     seqlen_pd;          /* sequence length of profile data */
  uint32_t     pidtag;             /* profile ID TAG */
  const uint8_t *profile_data;       /* profile_data pointer */
  uint32_t     new_boundary;       /* for encapsulations encountered */
  bool         new_big_endianness; /* for encapsulations encountered */
  proto_item  *ti;

  /* Get ProfileId tag */
  pidtag = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  ti = proto_tree_add_uint(tree, hf_giop_profile_id, tvb,
                        *offset-(int)sizeof(pidtag), 4, pidtag);

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen_pd = get_CDR_encap_info(tvb, tree, offset,
                                 stream_is_big_endian, boundary,
                                 &new_big_endianness, &new_boundary);

  /* return if zero length sequence */
  if (seqlen_pd == 0)
    return;


  /*
   * Lets see what kind of TAG it is. If TAG_INTERNET_IOP then
   * decode it, otherwise just dump the octet sequence
   *
   * also, store IOR in our objectkey hash
   *
   * TODO - handle other TAGS
   */

  switch (pidtag) {
  case IOP_TAG_INTERNET_IOP:

    decode_IIOP_IOR_profile(tvb, pinfo, tree, offset, new_boundary, new_big_endianness, repobuf, true);
    break;

  default:

    if (seqlen_pd-1 > (uint32_t)tvb_reported_length_remaining(tvb, *offset-4)) {
      expert_add_info_format(pinfo, ti, &ei_giop_length_too_big, "Profile data bigger than packet size");
      break;
    }

    /* fetch all octets in this sequence , but skip endianness */
    get_CDR_octet_seq(pinfo->pool, tvb, &profile_data, offset, seqlen_pd -1);

    /* Make a printable string */
    proto_tree_add_string(tree, hf_giop_profile_data, tvb, *offset -seqlen_pd + 1, seqlen_pd - 1,
                          make_printable_string( pinfo->pool, profile_data, seqlen_pd -1));
    break;
  }
}



/*
 * Decode IIOP IOR Profile
 * Ref Chap 15.7.2 in Corba Spec
 */


static void decode_IIOP_IOR_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    uint32_t boundary, bool stream_is_big_endian,
                                    const char *repo_id_buf,
                                    bool store_flag) {

  uint32_t     i;                /* loop index */

  uint8_t      v_major, v_minor; /* IIOP version */
  const char  *string;
  const uint8_t *octets;
  uint32_t     u_octet4;         /* u long */
  uint16_t     u_octet2;         /* u short */
  uint32_t     seqlen;           /* generic sequence length */
  uint32_t     seqlen1;          /* generic sequence length */
  const uint8_t *objkey;          /* object key pointer */
  proto_item  *ti, *ti_minor;


  /* Get major/minor version */

  v_major = get_CDR_octet(tvb, offset);
  v_minor = get_CDR_octet(tvb, offset);

  proto_tree_add_uint(tree, hf_giop_iiop_v_maj, tvb,
                        *offset-2, 1, v_major  );
  ti_minor = proto_tree_add_uint(tree, hf_giop_iiop_v_min, tvb,
                        *offset-1, 1, v_minor  );

  /* host */
  u_octet4 = get_CDR_string(pinfo->pool, tvb, &string, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_string_length, tvb,
                        *offset-u_octet4-4, 4, u_octet4);
  if (u_octet4 > 0) {
    proto_tree_add_string(tree, hf_giop_iiop_host, tvb,
                            *offset-u_octet4, u_octet4, string);
  }

  /* Port */

  u_octet2 = get_CDR_ushort(tvb, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_iiop_port, tvb,
                        *offset-2, 2, u_octet2);

  /* Object Key - sequence<octet> object_key */
  seqlen = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  ti = proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                        *offset-4, 4, seqlen);
  if (seqlen > (uint32_t)tvb_reported_length_remaining(tvb, *offset-4)) {
    expert_add_info_format(pinfo, ti, &ei_giop_length_too_big, "Sequence length bigger than packet size");
    return;
  }

  if (seqlen > 0) {
    /* fetch all octets in this sequence */
    get_CDR_octet_seq(pinfo->pool, tvb, &objkey, offset, seqlen);

    /*
     * Now we may have the Repository ID from earlier, as well
     * as the object key sequence and lengh. So lets store them in
     * our objectkey hash and free buffers.
     *
     * But only insert if user is not clicking and repo id not NULL.
     *
     */

    if (repo_id_buf) {
      if (pinfo) {
        if (!pinfo->fd->visited)
          insert_in_objkey_hash(giop_objkey_hash, objkey, seqlen, repo_id_buf, ior_src_req_res);
      }
      else {

        /*
         * No pinfo, but store anyway if flag set. eg: IOR read from file
         */

        if (store_flag)
          insert_in_objkey_hash(giop_objkey_hash, objkey, seqlen, repo_id_buf, ior_src_file);
      }
    }

    proto_tree_add_item(tree, hf_giop_objekt_key, tvb, *offset -seqlen, seqlen, ENC_NA);
  }

  /*
   * Now see if it's v1.1 or 1.2, as they can contain
   * extra sequence of IOP::TaggedComponents
   *
   */

  switch (v_minor) {
  case 0:

    /* nothing extra */
    break;

  case 1:
  case 2:

    /* sequence of IOP::TaggedComponents */
    /* Ref Chap 13 in Corba Spec */

    /* get sequence length */
    seqlen = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
    proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                          *offset-4, 4, seqlen);

    for (i=0; i< seqlen; i++) {
      /* get tag */
      u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
      proto_tree_add_uint(tree, hf_giop_IIOP_tag, tvb, *offset-4, 4, u_octet4);

      /* get component_data */
      seqlen1 = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
      ti = proto_tree_add_uint(tree, hf_giop_sequence_length, tvb,
                            *offset-4, 4, seqlen1);
      if (seqlen1 > (uint32_t)tvb_reported_length_remaining(tvb, *offset-4)) {
        expert_add_info_format(pinfo, ti, &ei_giop_length_too_big, "Sequence length bigger than packet size");
        return;
      }

      if (seqlen1 > 0) {
        get_CDR_octet_seq(pinfo->pool, tvb, &octets, offset, seqlen1);
        proto_tree_add_string(tree, hf_giop_component_data, tvb, *offset -seqlen1, seqlen1,
                          make_printable_string(pinfo->pool, octets, seqlen1));
      }

    }
    break;

  default:
    expert_add_info_format(pinfo, ti_minor, &ei_giop_invalid_v_minor, "Invalid v_minor value = %u", v_minor);
    break;
  }

}

/* Decode SystemExceptionReplyBody as defined in the CORBA spec chapter 15.
 */

static void decode_SystemExceptionReplyBody (tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int *offset,
                                             bool stream_is_big_endian,
                                             uint32_t boundary) {

  uint32_t length;            /* string length */
  uint32_t minor_code_value;
  uint32_t completion_status;

  const char *buf;          /* pointer to string buffer */

  length = get_CDR_string(pinfo->pool, tvb, &buf, offset, stream_is_big_endian, boundary);
  proto_tree_add_uint(tree, hf_giop_exception_len, tvb, *offset-4, 4, length);

  if (length > 0)
    proto_tree_add_string(tree, hf_giop_exception_id, tvb,
                          *offset - length, length, buf);

  minor_code_value = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  completion_status = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);

  proto_tree_add_uint(tree, hf_giop_minor_code_value, tvb, *offset-8, 4, minor_code_value);
  proto_tree_add_uint(tree, hf_giop_completion_status, tvb, *offset-4, 4, completion_status);
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
