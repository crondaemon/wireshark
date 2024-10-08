/* packet-memcache.c
 * Routines for Memcache Binary Protocol
 * http://code.google.com/p/memcached/wiki/MemcacheBinaryProtocol
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Routines for Memcache Textual Protocol
 * http://code.sixapart.com/svn/memcached/trunk/server/doc/protocol.txt
 *
 * Copyright 2009, Rama Chitta <rama@gear6.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>	/* for sscanf() */
#include <stdlib.h>	/* for strtoul() */

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

void proto_register_memcache (void);
void proto_reg_handoff_memcache(void);

#define PNAME  "Memcache Protocol"
#define PSNAME "MEMCACHE"
#define PFNAME "memcache"

#define MEMCACHE_DEFAULT_RANGE  "11211"
#define MEMCACHE_HEADER_LEN   24

/* Magic Byte */
#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81

/* Response Status */
#define RS_NO_ERROR           0x0000
#define RS_KEY_NOT_FOUND      0x0001
#define RS_KEY_EXISTS         0x0002
#define RS_VALUE_TOO_BIG      0x0003
#define RS_INVALID_ARGUMENTS  0x0004
#define RS_ITEM_NOT_STORED    0x0005
#define RS_UNKNOWN_COMMAND    0x0081
#define RS_OUT_OF_MEMORY      0x0082

/* Command Opcodes */
#define OP_GET                0x00
#define OP_SET                0x01
#define OP_ADD                0x02
#define OP_REPLACE            0x03
#define OP_DELETE             0x04
#define OP_INCREMENT          0x05
#define OP_DECREMENT          0x06
#define OP_QUIT               0x07
#define OP_FLUSH              0x08
#define OP_GET_Q              0x09
#define OP_NO_OP              0x0A
#define OP_VERSION            0x0B
#define OP_GET_K              0x0C
#define OP_GET_K_Q            0x0D
#define OP_APPEND             0x0E
#define OP_PREPEND            0x0F
#define OP_STAT               0x10
#define OP_SET_Q              0x11
#define OP_ADD_Q              0x12
#define OP_REPLACE_Q          0x13
#define OP_DELETE_Q           0x14
#define OP_INCREMENT_Q        0x15
#define OP_DECREMENT_Q        0x16
#define OP_QUIT_Q             0x17
#define OP_FLUSH_Q            0x18
#define OP_APPEND_Q           0x19
#define OP_PREPEND_Q          0x1A

/* Internally defined command opcodes used in the textual dissector only */
/* This values are not defined in any standard and can be redefined here */
#define OP_GETS               0xF0
#define OP_CAS                0xF1
#define OP_VERBOSE            0xF2

/* Data Types */
#define DT_RAW_BYTES          0x00

static int proto_memcache;

static dissector_handle_t memcache_tcp_handle;
static dissector_handle_t memcache_udp_handle;

static int hf_magic;
static int hf_opcode;
static int hf_extras_length;
static int hf_key_length;
static int hf_value_length;
static int hf_data_type;
static int hf_reserved;
static int hf_status;
static int hf_total_body_length;
static int hf_opaque;
static int hf_cas;
static int hf_extras;
static int hf_extras_flags;
static int hf_extras_expiration;
static int hf_extras_delta;
static int hf_extras_initial;
static int hf_extras_unknown;
static int hf_key;
static int hf_value;
static int hf_uint64_response;

static int hf_command;
static int hf_subcommand;
static int hf_flags;
static int hf_expiration;
static int hf_noreply;

static int hf_response;

static int hf_version;
static int hf_slabclass;
static int hf_name;
static int hf_name_value;

static int ett_memcache;
static int ett_extras;

static expert_field ei_value_missing;
static expert_field ei_extras_missing;
static expert_field ei_value_length;
static expert_field ei_key_missing;
static expert_field ei_key_unknown;
static expert_field ei_extras_unknown;
static expert_field ei_value_unknown;
static expert_field ei_status_response;
static expert_field ei_opcode_unknown;
static expert_field ei_reserved_value;
static expert_field ei_magic_unknown;

static const value_string magic_vals[] = {
  { MAGIC_REQUEST,         "Request"            },
  { MAGIC_RESPONSE,        "Response"           },
  { 0, NULL }
};

static const value_string status_vals[] = {
  { RS_NO_ERROR,           "No error"           },
  { RS_KEY_NOT_FOUND,      "Key not found"      },
  { RS_KEY_EXISTS,         "Key exists"         },
  { RS_VALUE_TOO_BIG,      "Value too big"      },
  { RS_INVALID_ARGUMENTS,  "Invalid arguments"  },
  { RS_ITEM_NOT_STORED,    "Item not stored"    },
  { RS_UNKNOWN_COMMAND,    "Unknown command"    },
  { RS_OUT_OF_MEMORY,      "Out of memory"      },
  { 0, NULL }
};

static const value_string opcode_vals[] = {
  { OP_GET,                "Get"                },
  { OP_SET,                "Set"                },
  { OP_ADD,                "Add"                },
  { OP_REPLACE,            "Replace"            },
  { OP_DELETE,             "Delete"             },
  { OP_INCREMENT,          "Increment"          },
  { OP_DECREMENT,          "Decrement"          },
  { OP_QUIT,               "Quit"               },
  { OP_FLUSH,              "Flush"              },
  { OP_GET_Q,              "Get Quietly"        },
  { OP_NO_OP,              "No-op"              },
  { OP_VERSION,            "Version"            },
  { OP_GET_K,              "Get Key"            },
  { OP_GET_K_Q,            "Get Key Quietly"    },
  { OP_APPEND,             "Append"             },
  { OP_PREPEND,            "Prepend"            },
  { OP_STAT,               "Statistics"         },
  { OP_SET_Q,              "Set Quietly"        },
  { OP_ADD_Q,              "Add Quietly"        },
  { OP_REPLACE_Q,          "Replace Quietly"    },
  { OP_DELETE_Q,           "Delete Quietly"     },
  { OP_INCREMENT_Q,        "Increment Quietly"  },
  { OP_DECREMENT_Q,        "Decrement Quietly"  },
  { OP_QUIT_Q,             "Quit Quietly"       },
  { OP_FLUSH_Q,            "Flush Quietly"      },
  { OP_APPEND_Q,           "Append Quietly"     },
  { OP_PREPEND_Q,          "Prepend Quietly"    },
  /* Internally defined values not valid here */
  { 0, NULL }
};

static const value_string data_type_vals[] = {
  { DT_RAW_BYTES,          "Raw bytes"          },
  { 0, NULL }
};

/* memcache message types. */
typedef enum _memcache_type {
  MEMCACHE_REQUEST,
  MEMCACHE_RESPONSE,
  MEMCACHE_UNKNOWN
} memcache_type_t;

/* desegmentation of MEMCACHE header */
static bool memcache_desegment_headers = true;

/* desegmentation of MEMCACHE payload */
static bool memcache_desegment_body = true;

/* should refer to either the request or the response dissector.
 */
typedef int (*ReqRespDissector)(tvbuff_t*, packet_info *, proto_tree *,
                                int, const unsigned char*, const unsigned char*, uint8_t);

/* determines if a packet contains a memcache
 * request or reply by looking at its first token.
 */
static int
is_memcache_request_or_reply(const char *data, int linelen, uint8_t *opcode,
                             memcache_type_t *type, bool *expect_content_length,
                             ReqRespDissector *reqresp_dissector);

static unsigned
get_memcache_pdu_len (packet_info *pinfo _U_, tvbuff_t *tvb,
                      int offset, void *data _U_)
{
  uint32_t body_len;

  /* Get the length of the memcache body */
  body_len = tvb_get_ntohl(tvb, offset+8);

  /* That length doesn't include the header; add that in */
  return body_len + MEMCACHE_HEADER_LEN;
}

static void
dissect_extras (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                int offset, uint8_t extras_len, uint8_t opcode, bool request)
{
  proto_tree *extras_tree = NULL;
  proto_item *extras_item = NULL, *ti;
  int         save_offset = offset;
  bool        illegal = false;  /* Set when extras shall not be present */
  bool        missing = false;  /* Set when extras is missing */

  if (extras_len) {
    extras_item = proto_tree_add_item (tree, hf_extras, tvb, offset, extras_len, ENC_NA);
    extras_tree = proto_item_add_subtree (extras_item, ett_extras);
  }

  switch (opcode) {

  case OP_GET:
  case OP_GET_Q:
  case OP_GET_K:
  case OP_GET_K_Q:
    if (extras_len) {
      if (request) {
        /* Request shall not have extras */
        illegal = true;
      } else {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    } else if (!request) {
      /* Response must have extras */
      missing = true;
    }
    break;

  case OP_SET:
  case OP_SET_Q:
  case OP_ADD:
  case OP_ADD_Q:
  case OP_REPLACE:
  case OP_REPLACE_Q:
    if (extras_len) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        /* Response shall not have extras */
        illegal = true;
      }
    } else if (request) {
      /* Request must have extras */
      missing = true;
    }
    break;

  case OP_INCREMENT:
  case OP_INCREMENT_Q:
  case OP_DECREMENT:
  case OP_DECREMENT_Q:
    if (extras_len) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_delta, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_initial, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        /* Response must not have extras (response is in Value) */
        illegal = true;
      }
    } else if (request) {
      /* Request must have extras */
      missing = true;
    }
    break;

  case OP_FLUSH:
  case OP_FLUSH_Q:
    if (extras_len) {
      proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    break;

  case OP_DELETE:
  case OP_DELETE_Q:
  case OP_QUIT:
  case OP_QUIT_Q:
  case OP_VERSION:
  case OP_APPEND:
  case OP_APPEND_Q:
  case OP_PREPEND:
  case OP_PREPEND_Q:
  case OP_STAT:
    /* Must not have extras */
    if (extras_len) {
      illegal = true;
    }
    break;

  default:
    if (extras_len) {
      /* Decode as unknown extras */
      proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extras_len, ENC_NA);
      offset += extras_len;
    }
    break;
  }

  if (illegal) {
    ti = proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extras_len, ENC_NA);
    expert_add_info_format(pinfo, ti, &ei_extras_unknown, "%s %s shall not have Extras",
                    val_to_str (opcode, opcode_vals, "Opcode %d"),
                    request ? "Request" : "Response");
    offset += extras_len;
  } else if (missing) {
    proto_tree_add_expert_format(tree, pinfo, &ei_extras_missing, tvb, offset, 0, "%s %s must have Extras",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  }

  if ((offset - save_offset) != extras_len) {
    expert_add_info_format(pinfo, extras_item, &ei_extras_unknown, "Illegal Extras length, should be %d", offset - save_offset);
  }
}

static void
dissect_key (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
             int offset, int key_len, uint8_t opcode, bool request)
{
  proto_item *ti = NULL;
  bool        illegal = false;  /* Set when key shall not be present */
  bool        missing = false;  /* Set when key is missing */

  if (key_len) {
    ti = proto_tree_add_item (tree, hf_key, tvb, offset, key_len, ENC_ASCII);
    offset += key_len;

    if ((opcode == OP_QUIT) || (opcode == OP_QUIT_Q) || (opcode == OP_NO_OP) || (opcode == OP_VERSION)) {
      /* Request and Response must not have key */
      illegal = true;
    }
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) || (opcode == OP_DELETE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) || (opcode == OP_DELETE_Q) ||
        (opcode == OP_FLUSH) || (opcode == OP_APPEND) || (opcode == OP_PREPEND) ||
        (opcode == OP_FLUSH_Q) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Response must not have a key */
      if (!request) {
        illegal = true;
      }
    }
  } else {
    if ((opcode == OP_GET) || (opcode == OP_GET_Q) || (opcode == OP_GET_K) || (opcode == OP_GET_K_Q) ||
        (opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) || (opcode == OP_DELETE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) || (opcode == OP_DELETE_Q) ||
        (opcode == OP_INCREMENT) || (opcode == OP_DECREMENT) || (opcode == OP_INCREMENT_Q) || (opcode == OP_DECREMENT_Q))
    {
      /* Request must have key */
      if (request) {
        missing = true;
      }
    }
  }

  if (illegal) {
    expert_add_info_format(pinfo, ti, &ei_key_unknown, "%s %s shall not have Key",
            val_to_str (opcode, opcode_vals, "Opcode %d"),
            request ? "Request" : "Response");
  } else if (missing) {
    proto_tree_add_expert_format(tree, pinfo, &ei_key_missing, tvb, offset, 0, "%s Request must have Key",
                            val_to_str (opcode, opcode_vals, "Opcode %d"));
  }
}

static void
dissect_value (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               int offset, uint32_t value_len, uint8_t opcode, bool request)
{
  proto_item *ti = NULL;
  bool        illegal = false;  /* Set when value shall not be present */
  bool        missing = false;  /* Set when value is missing */

  if (value_len > 0) {
    if (!request && ((opcode == OP_INCREMENT) || (opcode == OP_DECREMENT))) {
      ti = proto_tree_add_item (tree, hf_uint64_response, tvb, offset, 8, ENC_BIG_ENDIAN);
      if (value_len != 8) {
        expert_add_info_format(pinfo, ti, &ei_value_length, "Illegal Value length, should be 8");
      }
    } else {
      ti = proto_tree_add_item (tree, hf_value, tvb, offset, value_len, ENC_ASCII);
    }
    offset += value_len;
  }

  /* Sanity check */
  if (value_len) {
    if ((opcode == OP_GET) || (opcode == OP_GET_Q) || (opcode == OP_GET_K) || (opcode == OP_GET_K_Q) ||
        (opcode == OP_INCREMENT) || (opcode == OP_DECREMENT) || (opcode == OP_VERSION) ||
        (opcode == OP_INCREMENT_Q) || (opcode == OP_DECREMENT_Q))
    {
      /* Request must not have value */
      if (request) {
        illegal = true;
      }
    }
    if ((opcode == OP_DELETE) ||  (opcode == OP_QUIT) || (opcode == OP_FLUSH) || (opcode == OP_NO_OP) ||
        (opcode == OP_DELETE_Q) ||  (opcode == OP_QUIT_Q) || (opcode == OP_FLUSH_Q))
    {
      /* Request and Response must not have value */
      illegal = true;
    }
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) ||
        (opcode == OP_APPEND) || (opcode == OP_PREPEND) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Response must not have value */
      if (!request) {
        illegal = true;
      }
    }
  } else {
    if ((opcode == OP_SET) || (opcode == OP_ADD) || (opcode == OP_REPLACE) ||
        (opcode == OP_SET_Q) || (opcode == OP_ADD_Q) || (opcode == OP_REPLACE_Q) ||
        (opcode == OP_APPEND) || (opcode == OP_PREPEND) || (opcode == OP_APPEND_Q) || (opcode == OP_PREPEND_Q))
    {
      /* Request must have a value */
      if (request) {
        missing = true;
      }
    }
  }

  if (illegal) {
    expert_add_info_format(pinfo, ti, &ei_value_unknown, "%s %s shall not have Value",
            val_to_str (opcode, opcode_vals, "Opcode %d"),
            request ? "Request" : "Response");
  } else if (missing) {
    proto_tree_add_expert_format(tree, pinfo, &ei_value_missing, tvb, offset, 0, "%s %s must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            request ? "Request" : "Response");
  }
}

static int
dissect_memcache (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *memcache_tree;
  proto_item *memcache_item, *ti;
  int         offset = 0;
  uint8_t     magic, opcode, extras_len;
  uint16_t    key_len, status = 0;
  uint32_t    body_len, value_len;
  bool        request;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);

  memcache_item = proto_tree_add_item (tree, proto_memcache, tvb, offset, -1, ENC_NA);
  memcache_tree = proto_item_add_subtree (memcache_item, ett_memcache);

  magic = tvb_get_uint8 (tvb, offset);
  ti = proto_tree_add_item (memcache_tree, hf_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (try_val_to_str (magic, magic_vals) == NULL) {
    expert_add_info_format(pinfo, ti, &ei_magic_unknown, "Unknown magic byte: %d", magic);
  }

  opcode = tvb_get_uint8 (tvb, offset);
  ti = proto_tree_add_item (memcache_tree, hf_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (try_val_to_str (opcode, opcode_vals) == NULL) {
    expert_add_info_format(pinfo, ti, &ei_opcode_unknown, "Unknown opcode: %d", opcode);
  }

  proto_item_append_text (memcache_item, ", %s %s", val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                          val_to_str (magic, magic_vals, "Unknown magic (%d)"));

  col_append_fstr (pinfo->cinfo, COL_INFO, "%s %s",
                   val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                   val_to_str (magic, magic_vals, "Unknown magic (%d)"));

  key_len = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (memcache_tree, hf_key_length, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  extras_len = tvb_get_uint8 (tvb, offset);
  proto_tree_add_item (memcache_tree, hf_extras_length, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item (memcache_tree, hf_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  status = tvb_get_ntohs (tvb, offset);
  if (magic & 0x01) {    /* We suppose this is a response, even when unknown magic byte */
    request = false;
    ti = proto_tree_add_item (memcache_tree, hf_status, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (status != 0) {
      expert_add_info_format(pinfo, ti, &ei_status_response, "%s: %s",
                              val_to_str (opcode, opcode_vals, "Unknown opcode (%d)"),
                              val_to_str (status, status_vals, "Status: %d"));
    }
  } else {
    request = true;
    ti = proto_tree_add_item (memcache_tree, hf_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (status != 0) {
      expert_add_info_format(pinfo, ti, &ei_reserved_value, "Reserved value: %d", status);
    }
  }
  offset += 2;

  body_len = tvb_get_ntohl (tvb, offset);
  value_len = body_len - extras_len - key_len;
  ti = proto_tree_add_uint (memcache_tree, hf_value_length, tvb, offset, 0, value_len);
  proto_item_set_generated (ti);

  proto_tree_add_item (memcache_tree, hf_total_body_length, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item (memcache_tree, hf_opaque, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item (memcache_tree, hf_cas, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  if (status == 0) {
    dissect_extras (tvb, pinfo, memcache_tree, offset, extras_len, opcode, request);
    offset += extras_len;

    dissect_key (tvb, pinfo, memcache_tree, offset, key_len, opcode, request);
    offset += key_len;

    dissect_value (tvb, pinfo, memcache_tree, offset, value_len, opcode, request);
    /*offset += value_len;*/
  } else if (body_len) {
    proto_tree_add_item (memcache_tree, hf_value, tvb, offset, body_len, ENC_ASCII);
    /*offset += body_len;*/

    col_append_fstr (pinfo->cinfo, COL_INFO, " (%s)",
                     val_to_str (status, status_vals, "Unknown status: %d"));
  } else {
    proto_tree_add_expert_format(memcache_tree, pinfo, &ei_value_missing, tvb, offset, 0, "%s with status %s (%d) must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode %d"),
                            val_to_str_const (status, status_vals, "Unknown"), status);
  }

  return tvb_captured_length(tvb);
}

/* Obtain the content length by peeping into the header.
 */
static bool
get_payload_length (tvbuff_t *tvb, packet_info *pinfo, const int token_number, int offset,
                    uint32_t *bytes, bool *content_length_found)
{
  const unsigned char *next_token;
  const unsigned char *line, *lineend;
  unsigned char       *bytes_val;
  int           tokenlen, i = 0, linelen;
  int           next_offset;

  /* get the header line. */
  linelen = tvb_find_line_end (tvb, offset, -1, &next_offset,
                               false);
  if (linelen < 0) {
    return false;
  }

  line = tvb_get_ptr (tvb, offset, linelen);
  lineend = line + linelen;

  while (++i < token_number) {
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return false;
    }
    offset += (int) (next_token - line);
    line = next_token;
  }

  /* line or the next_token has the value we want. */
  tokenlen = get_token_len (line, lineend, &next_token);
  if (tokenlen == 0)  {
    return false;
  }

  bytes_val = tvb_get_string_enc(pinfo->pool, tvb, offset, tokenlen, ENC_ASCII);
  if (bytes_val) {
    if (sscanf (bytes_val, "%u", bytes) == 1) {
      *content_length_found = true;
    } else {
      return false;
    }
  } else {
    return false;
  }

  /* reached this far, we got what we want. */
  return true;
}

/* check if a PDU needs to be desegmented. */
static bool
desegment_pdus (tvbuff_t *tvb, packet_info *pinfo, const int offset,
                const int data_offset, uint32_t content_length)
{
  int length_remaining, reported_length_remaining;

  /* data_offset has been set to start of the data block. */
  if (!tvb_bytes_exist (tvb, data_offset, content_length)) {

    length_remaining = tvb_captured_length_remaining (tvb, data_offset);
    reported_length_remaining = tvb_reported_length_remaining (tvb, data_offset);

    if (length_remaining < reported_length_remaining) {
      /* It's a waste of time asking for more
       * data, because that data wasn't captured.
       */
      return false;
    }

    if (length_remaining == -1) {
      length_remaining = 0;
    }

    pinfo->desegment_offset = offset; /* start of the packet. */
    pinfo->desegment_len = (content_length + 2) - length_remaining; /* add 2 for /r/n */

    return true;
  }
  return false;
}

/*
 * Optionally do reassembly of the requests, responses and data.
 */
static bool
memcache_req_resp_hdrs_do_reassembly (
    tvbuff_t *tvb, const int offset, packet_info *pinfo,
    const bool desegment_headers, const bool desegment_body,
    const memcache_type_t type, const bool expect_content_length)
{
  int       linelen;
  int       next_offset;
  int       length_remaining;
  int       reported_length_remaining;
  uint32_t  content_length          = 0;
  bool      content_length_found    = false;
  bool      ret                     = false;

  /*
   * If header desegmentation is activated, check the
   * header in this tvbuff.
   * request one more byte (we don't know how many bytes
   * we'll need, so we just ask for one).
   */
  if (desegment_headers && pinfo->can_desegment) {
    next_offset = offset;

    reported_length_remaining = tvb_reported_length_remaining (tvb, next_offset);
    /*
     * Request one more byte if there're no
     * bytes left in the reported data (if there're
     * bytes left in the reported data, but not in
     * the available data, requesting more bytes
     * won't help, as those bytes weren't captured).
     */
    if (reported_length_remaining < 1) {
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return false;
    }

    length_remaining = tvb_captured_length_remaining (tvb, next_offset);

    /* Request one more byte if we cannot find a
     * header (i.e. a line end).
     */
    linelen = tvb_find_line_end (tvb, next_offset, -1, &next_offset, true);
    if (linelen == -1 && length_remaining >= reported_length_remaining) {
      /* Not enough data; ask for one more byte. */
      pinfo->desegment_offset = offset;
      pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
      return false;
    }

    /* Browse through the header to find the content length.
     *
     * request:
     * <command name> <key> <flags> <exptime> <bytes> [noreply]\r\n
     * cas <key> <flags> <exptime> <bytes> <cas unqiue> [noreply]\r\n
     *
     * response:
     * VALUE <key> <flags> <bytes> [<cas unique>]\r\n
     * <data block>\r\n
     */
    if (expect_content_length == true) {
      switch (type) {

      case MEMCACHE_REQUEST:
        /* Get the fifth token in the header.*/
        ret = get_payload_length (tvb, pinfo, 5 , offset, &content_length, &content_length_found);
        if (!ret) {
          return false;
        }
        break;

      case MEMCACHE_RESPONSE:
        /* Get the fourth token in the header.*/
        ret =  get_payload_length (tvb, pinfo, 4 , offset, &content_length, &content_length_found);
        if (!ret) {
          return false;
        }
        break;

      default:
        /* Unrecognized message type. */
        return false;
      }
    }
  }

  /* We have reached the end of a header, so there
   * should be 'content_length' bytes after this
   * followed by CRLF. The next_offset points to the
   * start of the data bytes.
   */
  if (desegment_body && content_length_found) {
    return !desegment_pdus (tvb, pinfo, offset, next_offset, content_length);
  }

  /* No further desegmentation needed. */
  return true;
}

/* Dissect a memcache message. */
static int
dissect_memcache_message (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
  const unsigned char      *line;
  const unsigned char      *lineend;
  int                orig_offset;
  int                first_linelen;
  int                datalen;
  bool               expect_content_length = false;
  int                next_offset;

  bool               is_request_or_reply;
  memcache_type_t    memcache_type;
  ReqRespDissector   reqresp_dissector  = NULL;
  proto_tree        *memcache_tree      = NULL;
  proto_item        *memcache_item      = NULL;
  uint8_t            opcode = 0xff; /* set to something that is not in the list. */

  /* Find a line end in the packet.
   * Note that "tvb_find_line_end ()" will return a value that
   * is not longer than what's in the buffer, so the
   * "tvb_get_ptr ()" call won't throw an exception.
   */
  first_linelen = tvb_find_line_end (tvb, offset, -1, &next_offset,
                                     false);
  if (first_linelen < 0) {
    return -1;
  }

  line = tvb_get_ptr (tvb, offset, first_linelen);
  lineend = line + first_linelen;

  memcache_type = MEMCACHE_UNKNOWN; /* packet type not known yet */

  /* Look at the first token of the first line to
   * determine if it is a request or a response?
   */
  is_request_or_reply =
    is_memcache_request_or_reply ((const char *)line,
                                  first_linelen, &opcode, &memcache_type,
                                  &expect_content_length, &reqresp_dissector);
  if (is_request_or_reply) {

    /* Yes, it is a request or a response.
     * Do header and body desegmentation if we've been told to.
     */
    if (!memcache_req_resp_hdrs_do_reassembly (tvb, offset, pinfo, memcache_desegment_headers,
                                               memcache_desegment_body, memcache_type,
                                               expect_content_length))
    {
      /* More data needed for desegmentation. */
      return -1;
    }
  }

  /* Columns and summary display. */
  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);

  /* If the packet is a memcache request or reply,
   * put the first line from the buffer into the summary
   * Otherwise, just call it a continuation.
   */
  if (is_request_or_reply) {
    line = tvb_get_ptr (tvb, offset, first_linelen);
    col_add_fstr (pinfo->cinfo, COL_INFO, "%s ",
                 format_text(pinfo->pool, line, first_linelen));
  } else {
    col_set_str (pinfo->cinfo, COL_INFO, "MEMCACHE Continuation");
  }

  orig_offset = offset;

  memcache_item = proto_tree_add_item (tree, proto_memcache, tvb, offset, -1, ENC_NA);
  memcache_tree = proto_item_add_subtree (memcache_item, ett_memcache);

  /* Process the packet data. The first line is expected to be a
   * header. If it's not a header then we don't dissect.
   * At this point, we already know if it is a request or a
   * response.
   */
  if (tvb_reported_length_remaining (tvb, offset) != 0) {
    /* Dissect a request or a response. */
    if (is_request_or_reply && reqresp_dissector) {
      next_offset = reqresp_dissector (tvb, pinfo, memcache_tree,
                                       offset, line, lineend, opcode);
      if (next_offset == -1) {
        /* Error in dissecting. */
        return -1;
      }
      offset = next_offset;
    }
  }

  /*
   * If a 'bytes' value was supplied, the amount of data to be
   * processed as MEMCACHE payload is the minimum of the 'bytes'
   * value and the amount of data remaining in the frame.
   *
   */
  datalen = tvb_captured_length_remaining (tvb, offset);
  if (datalen > 0) {
    /*
     * We've processed "datalen" bytes worth of data
     * (which may be no data at all); advance the
     * offset past whatever data we've processed.
     */
    offset += datalen;
  }

  return offset - orig_offset;
}

/* Payload dissector
 * <data block>\r\n
 */
static int
content_data_dissector (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                       int content_length, uint8_t opcode)
{
  int           datalen;
  bool          short_pkt = false;

  /*
   * Expecting to read 'content_length' number of bytes from
   * the buffer. It is not necessary that we have all the
   * content_length bytes available to read.
   */
  if (tvb_reported_length_remaining (tvb, offset) != 0) {
    /* bytes actually remaining in this tvbuff. */
    datalen = tvb_captured_length_remaining (tvb, offset);
    if (content_length >= 0) {
      if (datalen >= (content_length + 2)) { /* also consider \r\n*/
        datalen = content_length;
      } else {
        short_pkt = true;
      }
    }

    /* dissect the data block. */
    dissect_value (tvb, pinfo, tree, offset, datalen, opcode, true);
    if (datalen > 0) {
      /*
       * We've processed "datalen" bytes worth of data
       * (which may be no data at all); advance the
       * offset past whatever data we've processed.
       */
      if (!short_pkt) {
        offset += (datalen + 2); /* go past /r/n*/
      } else {
        offset += datalen; /* short packet; no /r/n*/
      }
    }
  }

  return offset;
}

/* Find the occurrences of a ':' in a stat response. */
static unsigned
find_stat_colon (const unsigned char *line, const unsigned char *lineend,
                 const unsigned char **first_colon, const unsigned char **last_colon)
{
  const unsigned char *linep, *temp;
  unsigned      occurrences = 0;
  unsigned char c;

  linep = line;
  while (linep < lineend) {
    temp = linep;
    c = *linep++;

    switch (c) {
    case ':':
      occurrences++;
      if (occurrences == 1) {
        *first_colon = temp;
      } else if (occurrences == 2) {
        *last_colon = temp;
      } else {
        /* anything other than 1 or 2;
         * return immediately
         */
        return occurrences;
      }
      break;
    default:
      break;
    }
  }

  return occurrences;
}

/* incr/decr response dissector */
static int
incr_dissector (tvbuff_t *tvb, proto_tree *tree, int offset)
{
  int            next_offset;
  int            linelen;
  const unsigned char  *line, *lineend;

  const unsigned char  *next_token;
  int            tokenlen;

  /* expecting to read 'bytes' number of bytes from the buffer. */
  if (tvb_offset_exists (tvb, offset)) {
    /* Find the end of the line. */
    linelen = tvb_find_line_end (tvb, offset, -1, &next_offset, false);
    if (linelen < 0) {
      /* header is out of the packet limits. */
      return -1;
    }

    /*
     * Get a buffer that refers to the line.
     * in other words, the unstructured portion
     * of memcache.
     */
    line = tvb_get_ptr (tvb, offset, linelen);
    lineend = line + linelen;

    /* 64 bit value */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }

    proto_tree_add_item (tree, hf_uint64_response, tvb, offset, tokenlen, ENC_BIG_ENDIAN);

    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return next_offset;
    } else {
      return -1; /* invalid token */
    }
  }

  return offset;
}

/* stats response dissector */
static int
stat_dissector (tvbuff_t *tvb, proto_tree *tree, int offset)
{
  unsigned      occurrences = 0;
  const unsigned char *first_colon = NULL, *last_colon = NULL;
  int           tokenlen, linelen;
  int           next_offset;
  const unsigned char *next_token;
  const unsigned char *line, *lineend;
  uint32_t      slabclass;
  unsigned char response_chars[21];

  while (tvb_offset_exists (tvb, offset)) {
    /* Find the end of the line. */
    linelen = tvb_find_line_end (tvb, offset, -1, &next_offset,
                                 false);
    if (linelen < 0) {
      return -1;
    }

    /*
     * Get a buffer that refers to the line.
     */
    line = tvb_get_ptr (tvb, offset, linelen);
    lineend = line + linelen;

    tokenlen = get_token_len (line, lineend, &next_token);
    if ((tokenlen == 4) && strncmp (line, "STAT", tokenlen) == 0) {
      proto_tree_add_item (tree, hf_command, tvb, offset, tokenlen, ENC_ASCII);
      offset += (int) (next_token - line);
      line = next_token;
      occurrences = find_stat_colon (line, lineend, &first_colon, &last_colon);
    } else if ((tokenlen == 3) && strncmp (line, "END", tokenlen) == 0) {
      /* done. reached an end of response. */
      offset += (int) (next_token - line);
      return offset;
    } else {
      /* invalid token */
      return -1;
    }

    switch (occurrences) {
    case 2: /* stats items: 2 colons */
      /* subcommand 'items' */
      tokenlen = (int) (first_colon - line);
      proto_tree_add_item (tree, hf_subcommand, tvb, offset, tokenlen, ENC_ASCII);
      offset += tokenlen + 1;

      /* slabclass */
      tokenlen = (int) (last_colon - first_colon - 1);
      if (tokenlen > 10 || tokenlen <= 0) {
        return -1;
      }
      memcpy (response_chars, first_colon + 1, tokenlen);
      response_chars[tokenlen] = '\0';

      slabclass = (uint32_t) strtoul (response_chars, NULL, 10);
      proto_tree_add_uint (tree, hf_slabclass, tvb, offset, tokenlen, slabclass);
      offset += tokenlen + 1;
      line = last_colon + 1;
      break;

    case 1: /* stats slabs: 1 colon */
      tokenlen = (int) (first_colon - line);
      if (tokenlen > 10 || tokenlen <= 0) {
        return -1;
      }
      memcpy (response_chars, line, tokenlen);
      response_chars[tokenlen] = '\0';

      slabclass = (uint32_t) strtoul (response_chars, NULL, 10);
      proto_tree_add_uint (tree, hf_slabclass, tvb, offset, tokenlen, slabclass);

      offset += (int) (tokenlen + 1);
      line = first_colon + 1;
      break;

    case 0: /* stats: 0 colons */
      break;

    default:
      /* invalid token. */
      return -1;
    }

    /* <hf_name> <hf_name_value>\r\n */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1; /* invalid token */
    }

    proto_tree_add_item (tree, hf_name, tvb, offset, tokenlen, ENC_ASCII);
    offset += (int) (next_token - line);
    line = next_token;

    /* value */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1; /* invalid token */
    }
    proto_tree_add_item (tree, hf_name_value, tvb, offset, tokenlen, ENC_ASCII);

    offset = next_offset;
  }

  return offset;
}

/* get/gets response dissector */
static int
get_response_dissector (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  int            next_offset;
  int            linelen;
  const unsigned char  *line, *lineend;
  const unsigned char  *next_token;
  int            tokenlen;
  uint16_t       flags;
  uint32_t       bytes;
  uint64_t       cas;
  uint8_t        opcode = 0xff;
  char           response_chars[21]; /* cover uint64 (20 + 1) bytes*/

  /* expecting to read 'bytes' number of bytes from the buffer. */
  while (tvb_offset_exists (tvb, offset)) {
    /* Find the end of the line. */
    linelen = tvb_find_line_end (tvb, offset, -1, &next_offset,
                                 false);
    if (linelen < 0) {
      /* header is out of the packet limits. */
      return -1;
    }

    /*
     * Get a buffer that refers to the line.
     * in other words, the unstructured portion
     * of memcache.
     */
    line = tvb_get_ptr (tvb, offset, linelen);
    lineend = line + linelen;

    /* VALUE token  */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      /* error */
      return -1;
    }

    if ((tokenlen == 5) && strncmp (line, "VALUE", tokenlen) == 0) {
      /* proceed */
    } else if ((tokenlen == 3) && strncmp (line, "END", tokenlen) == 0) {
      /* done. reached an end of response. */
      offset += (int) (next_token - line);
      return offset;
    } else {
      /* invalid token */
      return -1;
    }

    offset += (int) (next_token - line);
    line = next_token;

    /* key */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }
    dissect_key (tvb, pinfo, tree, offset, tokenlen, opcode, true);
    offset += (int) (next_token - line);
    line = next_token;

    /* flags */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0 || tokenlen > 5) {
      return -1;
    }
    memcpy (response_chars, line, tokenlen);
    response_chars[tokenlen] = '\0';

    flags = (uint16_t) strtoul (response_chars, NULL, 10);
    proto_tree_add_uint (tree, hf_flags, tvb, offset, tokenlen, flags);

    offset += (int) (next_token - line);
    line = next_token;

    /* bytes */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0 || tokenlen > 10) {
      return -1;
    }
    memcpy (response_chars, line, tokenlen);
    response_chars[tokenlen] = '\0';

    bytes = (uint32_t) strtoul (response_chars, NULL, 10);
    proto_tree_add_uint (tree, hf_value_length, tvb, offset, tokenlen, bytes);

    offset += (int) (next_token - line);
    line = next_token;

    /* check if cas id is present */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen > 20) {
      return -1;
    }

    if (tokenlen != 0) {  /* reached the end of line; CRLF */
      memcpy (response_chars, line, tokenlen);
      response_chars[tokenlen] = '\0';

      cas = (uint64_t) strtoul (response_chars, NULL, 10);
      proto_tree_add_uint64 (tree, hf_cas, tvb, offset, tokenlen, cas);

      /* CRLF */
      tokenlen = get_token_len (line, lineend, &next_token);
      if (tokenlen != 0) {
        return -1; /* invalid token */
      }
    }

    offset = next_offset;
    /* <datablock>\r\n */
    offset = content_data_dissector (tvb, pinfo, tree, offset, bytes, opcode);
    if (offset == -1) {
      return offset;
    }
  }

  return offset;
}

/* Basic memcache response dissector. */
static int
memcache_response_dissector (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             const unsigned char *line, const unsigned char *lineend, uint8_t opcode)
{
  const unsigned char *next_token;
  int           tokenlen;

  switch (opcode) {

  case OP_GET:
  case OP_GETS:
    return get_response_dissector (tvb, pinfo, tree, offset);

  case OP_VERSION:
    /* response code.  */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }
    if ((tokenlen == 7) && strncmp (line, "VERSION", tokenlen) == 0) {
      offset += (int) (next_token - line);
      line = next_token;
    } else {
      return -1;
    }

    /* version string */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      /* expecting version string. */
      return -1;
    }

    proto_tree_add_item (tree, hf_version, tvb, offset, tokenlen, ENC_ASCII);
    offset += (int) (next_token - line);
    line = next_token;

    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen != 0) {
      /* invalid token */
      return -1;
    }

    return offset;

  case OP_STAT:
    return stat_dissector (tvb, tree, offset);

  default:
    break;
  }

  /* response code.  */
  tokenlen = get_token_len (line, lineend, &next_token);
  if (tokenlen == 0) {
    return -1;
  }

  /* all the following mark an end of a response.
   * should take care of set, add, cas, append, replace
   * prepend, flush_all, verbosity, delete and to an extent
   * incr, decr and stat commands.
   */
  if ((tokenlen == 6 && strncmp (line, "STORED", tokenlen) == 0) ||
      (tokenlen == 10 && strncmp (line, "NOT_STORED", tokenlen) == 0) ||
      (tokenlen == 6 && strncmp (line, "EXISTS", tokenlen) == 0) ||
      (tokenlen == 9 && strncmp (line, "NOT_FOUND", tokenlen) == 0) ||
      (tokenlen == 7 && strncmp (line, "DELETED", tokenlen) == 0) ||
      (tokenlen == 2 && strncmp (line, "OK", tokenlen) == 0) ||
      (tokenlen == 3 && strncmp (line, "END", tokenlen) == 0))
  {
    proto_tree_add_item (tree, hf_response, tvb, offset, tokenlen, ENC_ASCII);
    offset += (int) (next_token - line);
    return offset;
  }

  /* if we have reached this point:
   * it is either an incr/decr response of the format
   *  <value>\r\n.
   *  or
   *  "stats sizes" response of the format:
   *  <size> <count> \r\n
   */
  if (opcode == OP_INCREMENT) {
    return incr_dissector (tvb, tree, offset);
  }

  return offset;
}

/* Basic memcache request dissector. */
static int
memcache_request_dissector (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                            const unsigned char *line, const unsigned char *lineend, uint8_t opcode)
{
  const unsigned char *next_token;
  int           tokenlen;

  uint16_t      flags;
  uint32_t      expiration;
  uint32_t      bytes;
  uint64_t      cas;
  char          response_chars[21]; /* cover uint64 (20 + 1) bytes*/

  /* command. */
  tokenlen = get_token_len (line, lineend, &next_token);
  if (tokenlen == 0) {
    return -1;
  }
  proto_tree_add_item (tree, hf_command, tvb, offset, tokenlen, ENC_ASCII);
  offset += (int) (next_token - line);
  line = next_token;

  switch (opcode) {

  case OP_SET:
  case OP_ADD:
  case OP_REPLACE:
  case OP_APPEND:
  case OP_PREPEND:
  case OP_CAS:

    /* key */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }

    dissect_key (tvb, pinfo, tree, offset, tokenlen, opcode, true);
    offset += (int) (next_token - line);
    line = next_token;

    /* flags */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0 || tokenlen > 5) {
      return -1;
    }
    memcpy (response_chars, line, tokenlen);
    response_chars[tokenlen] = '\0';

    flags = (uint16_t) strtoul (response_chars, NULL, 10);
    proto_tree_add_uint (tree, hf_flags, tvb, offset, tokenlen, flags);

    offset += (int) (next_token - line);
    line = next_token;

    /* expiration */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0 || tokenlen > 10) {
      return -1;
    }
    memcpy (response_chars, line, tokenlen);
    response_chars[tokenlen] = '\0';

    expiration = (uint32_t) strtoul (response_chars, NULL, 10);
    proto_tree_add_uint (tree, hf_expiration, tvb, offset, tokenlen, expiration);

    offset += (int) (next_token - line);
    line = next_token;

    /* bytes */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0 || tokenlen > 10) {
      return -1;
    }
    memcpy (response_chars, line, tokenlen);
    response_chars[tokenlen] = '\0';

    bytes = (uint32_t) strtoul (response_chars, NULL, 10);
    proto_tree_add_uint (tree, hf_value_length, tvb, offset, tokenlen, bytes);

    offset += (int) (next_token - line);
    line = next_token;

    /* cas id. */
    if (opcode == OP_CAS) {
      tokenlen = get_token_len (line, lineend, &next_token);
      if (tokenlen == 0 || tokenlen > 20) {
        return -1;
      }
      memcpy (response_chars, line, tokenlen);
      response_chars[tokenlen] = '\0';

      cas = (uint64_t) strtoul (response_chars, NULL, 10);
      proto_tree_add_uint64 (tree, hf_cas, tvb, offset, tokenlen, cas);

      offset += (int) (next_token - line);
      line = next_token;
    }

    /* check if the following bit is "noreply" or
     * the actual data block.
     */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen != 0) {
      if (tokenlen == 7 && strncmp (line, "noreply", 7) == 0) {
        proto_tree_add_item (tree, hf_noreply, tvb, offset, tokenlen, ENC_ASCII);
      }
      offset += (int) (next_token - line);
    }

    offset += 2 ; /* go past /r/n*/
    /* <datablock>\r\n */
    offset = content_data_dissector (tvb, pinfo, tree, offset, bytes, opcode);
    if (offset == -1) {
      return offset;
    }
    break;

  case OP_INCREMENT:
  case OP_DECREMENT:
    /* key */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }
    dissect_key (tvb, pinfo, tree, offset, tokenlen, opcode, true);
    offset += (int) (next_token - line);
    line = next_token;

    /* value */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }
    proto_tree_add_item (tree, hf_value, tvb, offset, tokenlen, ENC_ASCII);
    offset += (int) (next_token - line);
    line = next_token;

    /* check for "noreply" */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset; /* reached CRLF */
    }
    if (tokenlen == 7 && strncmp (line, "noreply", 7) == 0) {
      proto_tree_add_item (tree, hf_noreply, tvb, offset, tokenlen, ENC_ASCII);
      offset += (int) (next_token - line);
      line = next_token;
    } else {
      return -1; /* should have been noreply or CRLF. */
    }

    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset; /* CRLF */
    } else {
      /*something's wrong; invalid command maybe. */
      return -1;
    }
    break;

  case OP_DELETE:
    /* key */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return -1;
    }
    /* dissect key. */
    dissect_key (tvb, pinfo, tree, offset, tokenlen, opcode, true);
    offset += (int) (next_token - line);
    line = next_token;

    /* check if it's expiration or noreply */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset; /* neither expiration nor noreply; CRLF */
    }
    if (tokenlen <= 10) {
      if (tokenlen == 7 && strncmp (line, "noreply", 7) == 0) {
        /* noreply */
        proto_tree_add_item (tree, hf_noreply, tvb, offset, tokenlen, ENC_ASCII);
      } else {
        /* expiration */
        memcpy (response_chars, line, tokenlen);
        response_chars[tokenlen] = '\0';

        expiration = (uint32_t) strtoul (response_chars, NULL, 10);
        proto_tree_add_uint (tree, hf_expiration, tvb, offset, tokenlen, expiration);
      }
      offset += (int) (next_token - line);
      line = next_token;
    } else {
      return -1;
    }

    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset;
    } else {
      /*something's wrong; invalid command maybe. */
      return -1;
    }
    break;

  case OP_GET:
  case OP_GETS:
    /* could be followed by any number of keys, add
     * them one by one. tokenlen cannot be 0 to begin
     * with.
     */
    while (tokenlen != 0) {
      tokenlen = get_token_len (line, lineend, &next_token);
      if (tokenlen == 0) {
        return offset; /* CRLF */
      }
      dissect_key (tvb, pinfo, tree, offset, tokenlen, opcode, true);
      offset += (int) (next_token - line);
      line = next_token;
    }
    break;

  case OP_STAT:
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) { /* just the 'stats' command;*/
      return offset;
    } else { /* there is a sub command; record it*/
      proto_tree_add_item (tree, hf_subcommand, tvb, offset, tokenlen, ENC_ASCII);
      offset += (int) (next_token - line);
      line = next_token;
    }

    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset;
    } else {
      /* something's wrong; invalid command maybe. */
      return -1;
    }
    break;

  case OP_FLUSH:
    /* check if it's expiration or noreply */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset; /* neither expiration nor noreply; CRLF */
    }
    if (tokenlen <= 10) {
      if (tokenlen == 7 && strncmp (line, "noreply", 7) == 0) {
        /* noreply */
        proto_tree_add_item (tree, hf_noreply, tvb, offset, tokenlen, ENC_ASCII);
      } else {
        /* expiration */
        memcpy (response_chars, line, tokenlen);
        response_chars[tokenlen] = '\0';

        expiration = (uint32_t) strtoul (response_chars, NULL, 10);
        proto_tree_add_uint (tree, hf_expiration, tvb, offset, tokenlen, expiration);
      }
      offset += (int) (next_token - line);
      line = next_token;
    } else {
      return -1;
    }

    /* maybe noreply now? */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset;
    }
    if (tokenlen == 7 && strncmp (line, "noreply", 7) == 0) {
      /* noreply */
      proto_tree_add_item (tree, hf_noreply, tvb, offset, tokenlen, ENC_ASCII);
      offset += (int) (next_token - line);
    } else {
      return -1; /* expecting CRLF and if not noreply*/
    }
    break;

  case OP_VERBOSE:
    /* not implemented for now.*/
    break;

  case OP_VERSION:
  case OP_QUIT:
    /* CRLF */
    tokenlen = get_token_len (line, lineend, &next_token);
    if (tokenlen == 0) {
      return offset;
    } else {
      /*something's wrong; invalid command maybe. */
      return -1;
    }

  default:
    /* invalid command maybe; break out. */
    break;
  }

  return offset;
}

/*
 * any message that is not starting with the following keywords
 * is a response.
 */
static int
is_memcache_request_or_reply (const char *data, int linelen, uint8_t *opcode,
                             memcache_type_t *type, bool *expect_content_length,
                             ReqRespDissector *reqresp_dissector)
{
  const unsigned char *ptr = (const unsigned char *)data;
  bool          is_request_or_response = false;
  int           indx = 0;

  /* look for a space */
  while (indx < linelen) {
    if (*ptr == ' ')
      break;

    ptr++;
    indx++;
  }

  /* is it a response? */
  switch (indx) {
  case 2:
    if (strncmp (data, "OK", indx) == 0) {
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 3:
    if (strncmp (data, "END", indx) == 0) {
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 4:
    if (strncmp (data, "STAT", indx) == 0) {
      *opcode = OP_STAT;
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 5:
    if (strncmp (data, "VALUE", indx) == 0) {
      *opcode = OP_GET;
      *type = MEMCACHE_RESPONSE;
      *expect_content_length = true;
      is_request_or_response = true;
    }
    break;

  case 6:
    if (strncmp (data, "EXISTS", indx) == 0 ||
        strncmp (data, "STORED", indx) == 0) {
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 7:
    if (strncmp (data, "VERSION", indx) == 0) {
      *opcode = OP_VERSION;
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    } else if (strncmp (data, "DELETED", indx) == 0) {
      *opcode = OP_DELETE;
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 9:
    if (strncmp (data, "NOT_FOUND", indx) == 0) {
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  case 10:
    if (strncmp (data, "NOT_STORED", indx) == 0) {
      *type = MEMCACHE_RESPONSE;
      is_request_or_response = true;
    }
    break;

  default:
    break; /* is it a request? */
  }

  if (is_request_or_response && reqresp_dissector) {
    *reqresp_dissector = memcache_response_dissector;
    return is_request_or_response;
  }

  /* is it a request?  */
  switch (indx) {
  case 3:
    if (strncmp (data, "get", indx) == 0) {
      *opcode = OP_GET;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    } else if (strncmp (data, "set", indx) == 0) {
      *opcode = OP_SET;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    } else if (strncmp (data, "add", indx) == 0) {
      *opcode = OP_ADD;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    } else if (strncmp (data, "cas", indx) == 0) {
      *opcode = OP_CAS;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    }
    break;

  case 4:
    if (strncmp (data, "gets", indx) == 0) {
      *opcode = OP_GETS;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    } else if (strncmp (data, "incr", indx) == 0) {
      *opcode = OP_INCREMENT;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    } else if (strncmp (data, "decr", indx) == 0) {
      *opcode = OP_DECREMENT;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    } else if (strncmp (data, "quit", indx) == 0) {
      *opcode = OP_QUIT;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    }
    break;

  case 5:
    if (strncmp (data, "stats", indx) == 0) {
      *opcode = OP_STAT;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    }
    break;

  case 6:
    if (strncmp (data, "append", indx) == 0) {
      *opcode = OP_APPEND;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    } else if (strncmp (data, "delete", indx) == 0) {
      *opcode = OP_DELETE;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    }
    break;

  case 7:
    if (strncmp (data, "replace", indx) == 0) {
      *opcode = OP_REPLACE;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    } else if (strncmp (data, "prepend", indx) == 0) {
      *opcode = OP_PREPEND;
      *type = MEMCACHE_REQUEST;
      *expect_content_length = true;
      is_request_or_response = true;
    } else if (strncmp (data, "version", indx) == 0) {
      *opcode = OP_VERSION;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    }
    break;

  case 9:
    if (strncmp (data, "flush_all", indx) == 0) {
      *opcode = OP_FLUSH;
      *type = MEMCACHE_REQUEST;
      is_request_or_response = true;
    }
    break;

  default:
    break; /* check if it is an 'incr' or 'stats sizes' response. */
  }

  if (is_request_or_response && reqresp_dissector) {
    *reqresp_dissector = memcache_request_dissector;
    return is_request_or_response;
  }

  /* XXX:
   * Recognize 'incr', 'decr' and 'stats sizes' responses.
   * I don't have a solution for this yet.
   */
  return is_request_or_response;
}

/* dissect memcache textual protocol PDUs. */
static void
dissect_memcache_text (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int   offset = 0;
  int   len;

  while (tvb_reported_length_remaining (tvb, offset) != 0) {

    /* dissect the memcache packet. */
    len = dissect_memcache_message (tvb, offset, pinfo, tree);
    if (len == -1)
      break;
    offset += len;

    /*
     * OK, we've set the Protocol and Info columns for the
     * first MEMCACHE message; set a fence so that subsequent
     * MEMCACHE messages don't overwrite the Info column.
     */
    col_set_fence (pinfo->cinfo, COL_INFO);
  }
}

/* Dissect tcp packets based on the type of protocol (text/binary) */
static int
dissect_memcache_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int         offset = 0;
  uint8_t     magic;

  magic = tvb_get_uint8 (tvb, offset);

  if (try_val_to_str (magic, magic_vals) != NULL) {
    tcp_dissect_pdus (tvb, pinfo, tree, memcache_desegment_body, 12,
                      get_memcache_pdu_len, dissect_memcache, data);
  } else {
    dissect_memcache_text (tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/* Dissect udp packets based on the type of protocol (text/binary) */
static int
dissect_memcache_udp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  int         offset = 0;
  uint8_t     magic;

  magic = tvb_get_uint8 (tvb, offset);

  if (try_val_to_str (magic, magic_vals) != NULL) {
    dissect_memcache (tvb, pinfo, tree, data);
  } else {
    dissect_memcache_message (tvb, 0, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

/* Registration functions; register memcache protocol,
 * its configuration options and also register the tcp and udp
 * dissectors.
 */
void
proto_register_memcache (void)
{
  static hf_register_info hf[] = {
    { &hf_magic,
      { "Magic", "memcache.magic",
        FT_UINT8, BASE_DEC, VALS (magic_vals), 0x0,
        "Magic number", HFILL } },

    { &hf_opcode,
      { "Opcode", "memcache.opcode",
        FT_UINT8, BASE_DEC, VALS (opcode_vals), 0x0,
        "Command code", HFILL } },

    { &hf_extras_length,
      { "Extras length", "memcache.extras.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length in bytes of the command extras", HFILL } },

    { &hf_key_length,
      { "Key Length", "memcache.key.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length in bytes of the text key that follows the command extras", HFILL } },

    { &hf_value_length,
      { "Value length", "memcache.value.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Length in bytes of the value that follows the key", HFILL } },

    { &hf_data_type,
      { "Data type", "memcache.data_type",
        FT_UINT8, BASE_DEC, VALS (data_type_vals), 0x0,
        NULL, HFILL } },

    { &hf_reserved,
      { "Reserved", "memcache.reserved",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Reserved for future use", HFILL } },

    { &hf_status,
      { "Status", "memcache.status",
        FT_UINT16, BASE_DEC, VALS (status_vals), 0x0,
        "Status of the response", HFILL } },

    { &hf_total_body_length,
      { "Total body length", "memcache.total_body_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Length in bytes of extra + key + value", HFILL } },

    { &hf_opaque,
      { "Opaque", "memcache.opaque",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_cas,
      { "CAS", "memcache.cas",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Data version check", HFILL } },

    { &hf_extras,
      { "Extras", "memcache.extras",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_flags,
      { "Flags", "memcache.extras.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_expiration,
      { "Expiration", "memcache.extras.expiration",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_delta,
      { "Amount to add", "memcache.extras.delta",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_initial,
      { "Initial value", "memcache.extras.initial",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_unknown,
      { "Unknown", "memcache.extras.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Extras", HFILL } },

    { &hf_key,
      { "Key", "memcache.key",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_value,
      { "Value", "memcache.value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_uint64_response,
      { "Response", "memcache.extras.response",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_command,
      { "Command", "memcache.command",
        FT_STRING, BASE_NONE , NULL, 0x0,
        NULL, HFILL } },

    { &hf_subcommand,
      { "Sub command", "memcache.subcommand",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Sub command if any", HFILL } },

    { &hf_flags,
      { "Flags", "memcache.flags",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_expiration,
      { "Expiration", "memcache.expiration",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_noreply,
      { "Noreply", "memcache.noreply",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Client does not expect a reply", HFILL } },

    { &hf_response,
      { "Response", "memcache.response",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Response command", HFILL } },

    { &hf_version,
      { "Version", "memcache.version",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Version of running memcache", HFILL } },

    { &hf_slabclass,
      { "Slab class", "memcache.slabclass",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Slab class of a stat", HFILL } },

    { &hf_name,
      { "Stat name", "memcache.name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Name of a stat", HFILL } },

    { &hf_name_value,
      { "Stat value", "memcache.name_value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Value of a stat", HFILL } },
  };

  static int *ett[] = {
    &ett_memcache,
    &ett_extras
  };

  static ei_register_info ei[] = {
      { &ei_extras_unknown,  { "memcache.extras.notexpected", PI_UNDECODED, PI_WARN, "shall not have Extras", EXPFILL }},
      { &ei_extras_missing,  { "memcache.extras.missing", PI_UNDECODED, PI_WARN, "must have Extras", EXPFILL }},
      { &ei_key_unknown,     { "memcache.key.notexpected", PI_UNDECODED, PI_WARN, "shall not have Key", EXPFILL }},
      { &ei_key_missing,     { "memcache.key.missing", PI_UNDECODED, PI_WARN, "must have Key", EXPFILL }},
      { &ei_value_length,    { "memcache.value.invalid", PI_UNDECODED, PI_WARN, "Illegal Value length, should be 8", EXPFILL }},
      { &ei_value_unknown,   { "memcache.value.notexpected", PI_UNDECODED, PI_WARN, "shall not have Value", EXPFILL }},
      { &ei_value_missing,   { "memcache.value.missing", PI_UNDECODED, PI_WARN, "must have Value", EXPFILL }},
      { &ei_magic_unknown,   { "memcache.magic.unknown", PI_UNDECODED, PI_WARN, "Unknown magic byte", EXPFILL }},
      { &ei_opcode_unknown,  { "memcache.opcode.unknown", PI_UNDECODED, PI_WARN, "Unknown opcode", EXPFILL }},
      { &ei_status_response, { "memcache.status.response", PI_RESPONSE_CODE, PI_NOTE, "Error response", EXPFILL }},
      { &ei_reserved_value,  { "memcache.reserved.expert", PI_UNDECODED, PI_WARN, "Reserved value", EXPFILL }},
  };

  module_t        *memcache_module;
  expert_module_t *expert_memcache;

  proto_memcache = proto_register_protocol (PNAME, PSNAME, PFNAME);
  memcache_tcp_handle = register_dissector ("memcache.tcp", dissect_memcache_tcp, proto_memcache);
  memcache_udp_handle = register_dissector ("memcache.udp", dissect_memcache_udp, proto_memcache);

  proto_register_field_array (proto_memcache, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_memcache = expert_register_protocol(proto_memcache);
  expert_register_field_array(expert_memcache, ei, array_length(ei));

  /* Register our configuration options */
  memcache_module = prefs_register_protocol (proto_memcache, NULL);

  prefs_register_bool_preference (memcache_module, "desegment_headers",
                                 "Reassemble MEMCACHE headers spanning multiple TCP segments",
                                 "Whether the MEMCACHE dissector should reassemble headers "
                                 "of a request spanning multiple TCP segments. "
                                 "To use this option, you must also enable "
                                 "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &memcache_desegment_headers);

  prefs_register_bool_preference (memcache_module, "desegment_pdus",
                                  "Reassemble PDUs spanning multiple TCP segments",
                                  "Whether the memcache dissector should reassemble PDUs"
                                  " spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors"
                                  " to reassemble TCP streams\" in the TCP protocol settings.",
                                  &memcache_desegment_body);
}

/* Register the tcp and udp memcache dissectors. */
void
proto_reg_handoff_memcache (void)
{
  dissector_add_uint_range_with_preference("tcp.port", MEMCACHE_DEFAULT_RANGE, memcache_tcp_handle);
  dissector_add_uint_range_with_preference("udp.port", MEMCACHE_DEFAULT_RANGE, memcache_udp_handle);
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
