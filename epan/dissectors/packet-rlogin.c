/* packet-rlogin.c
 * Routines for unix rlogin packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste[AT]woodward.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based upon RFC-1282 - BSD Rlogin
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/strtoi.h>
#include "packet-tcp.h"

#define RLOGIN_PORT 513

void proto_register_rlogin(void);
void proto_reg_handoff_rlogin(void);

static dissector_handle_t rlogin_handle;

static int proto_rlogin;

static int ett_rlogin;
static int ett_rlogin_window;
static int ett_rlogin_user_info;
static int ett_rlogin_window_rows;
static int ett_rlogin_window_cols;
static int ett_rlogin_window_x_pixels;
static int ett_rlogin_window_y_pixels;

static int hf_user_info;
static int hf_client_startup_flag;
static int hf_startup_info_received_flag;
static int hf_user_info_client_user_name;
static int hf_user_info_server_user_name;
static int hf_user_info_terminal_type;
static int hf_user_info_terminal_speed;
static int hf_control_message;
static int hf_magic_cookie;
static int hf_window_info;
static int hf_window_info_ss;
static int hf_window_info_rows;
static int hf_window_info_cols;
static int hf_window_info_x_pixels;
static int hf_window_info_y_pixels;
static int hf_data;

static expert_field ei_rlogin_termlen_invalid;

static const value_string control_message_vals[] =
{
	{ 0x02,     "Clear buffer"        },
	{ 0x10,     "Raw mode"            },
	{ 0x20,     "Cooked mode"         },
	{ 0x80,     "Window size request" },
	{ 0, NULL }
};


typedef enum  {
	NONE=0,
	USER_INFO_WAIT=1,
	DONE=2
} session_state_t;

#define NAME_LEN 32
typedef struct {
	session_state_t  state;
	uint32_t         info_framenum;
	char             user_name[NAME_LEN];
} rlogin_hash_entry_t;



/* Decoder State Machine.  Currently only used to snoop on
   client-user-name as sent by the client up connection establishment.
*/
static void
rlogin_state_machine(rlogin_hash_entry_t *hash_info, tvbuff_t *tvb, packet_info *pinfo)
{
	unsigned length;
	int stringlen;

	/* Won't change state if already seen this packet */
	if (pinfo->fd->visited)
	{
		return;
	}

	/* rlogin stream decoder */
	/* Just watch for the second packet from client with the user name and */
	/* terminal type information. */

	if (pinfo->destport != RLOGIN_PORT)
	{
		return;
	}

	/* exit if already passed username in conversation */
	if (hash_info->state == DONE)
	{
		return;
	}

	/* exit if no data */
	length = tvb_captured_length(tvb);
	if (length == 0)
	{
		return;
	}

	if (hash_info->state == NONE)
	{
		/* new connection*/
		if (tvb_get_uint8(tvb, 0) != '\0')
		{
			/* We expected a null, but didn't get one; quit. */
			hash_info->state = DONE;
			return;
		}
		else
		{
			if (length <= 1)
			{
				/* Still waiting for data */
				hash_info->state = USER_INFO_WAIT;
			}
			else
			{
				/* Have info, store frame number */
				hash_info->state = DONE;
				hash_info->info_framenum = pinfo->num;
			}
		}
	}
	/* expect user data here */
	/* TODO: may need to do more checking here? */
	else
	if (hash_info->state == USER_INFO_WAIT)
	{
		/* Store frame number here */
		hash_info->state = DONE;
		hash_info->info_framenum = pinfo->num;

		/* Work out length of string to copy */
		stringlen = tvb_strnlen(tvb, 0, NAME_LEN);
		if (stringlen == -1)
			stringlen = NAME_LEN - 1;   /* no '\0' found */
		else if (stringlen > NAME_LEN - 1)
			stringlen = NAME_LEN - 1;   /* name too long */

		/* Copy and terminate string into hash name */
		tvb_memcpy(tvb, (uint8_t *)hash_info->user_name, 0, stringlen);
		hash_info->user_name[stringlen] = '\0';

		col_append_str(pinfo->cinfo, COL_INFO, ", (User information)");
	}
}

/* Dissect details of packet */
static void rlogin_display(rlogin_hash_entry_t *hash_info,
			   tvbuff_t *tvb,
			   packet_info *pinfo,
			   proto_tree *tree,
			   struct tcpinfo *tcpinfo)
{
	/* Display the proto tree */
	int             offset = 0;
	proto_tree      *rlogin_tree, *user_info_tree, *window_tree;
	proto_item      *ti;
	unsigned        length;
	int             str_len;
	int             ti_offset;
	proto_item      *user_info_item, *window_info_item;

	/* Create rlogin subtree */
	ti = proto_tree_add_item(tree, proto_rlogin, tvb, 0, -1, ENC_NA);
	rlogin_tree = proto_item_add_subtree(ti, ett_rlogin);

	/* Return if data empty */
	length = tvb_captured_length(tvb);
	if (length == 0)
	{
		return;
	}

	/*
	 * XXX - this works only if the urgent pointer points to something
	 * in this segment; to make it work if the urgent pointer points
	 * to something past this segment, we'd have to remember the urgent
	 * pointer setting for this conversation.
	 */
	if (tcpinfo && IS_TH_URG(tcpinfo->flags) &&      /* if urgent pointer set */
	    length >= tcpinfo->urgent_pointer) /* and it's in this frame */
	{
		/* Get urgent byte into Temp */
		int urgent_offset = tcpinfo->urgent_pointer - 1;
		uint8_t control_byte;

		/* Check for text data in front */
		if (urgent_offset > offset)
		{
			proto_tree_add_item(rlogin_tree, hf_data, tvb, offset, urgent_offset, ENC_ASCII);
		}

		/* Show control byte */
		proto_tree_add_item(rlogin_tree, hf_control_message, tvb,
		                    urgent_offset, 1, ENC_BIG_ENDIAN);
		control_byte = tvb_get_uint8(tvb, urgent_offset);
		col_append_fstr(pinfo->cinfo, COL_INFO,
			               " (%s)", val_to_str_const(control_byte, control_message_vals, "Unknown"));

		offset = urgent_offset + 1; /* adjust offset */
	}
	else
	if (tvb_get_uint8(tvb, offset) == '\0')
	{
		/* Startup */
		if (pinfo->srcport == RLOGIN_PORT)   /* from server */
		{
			proto_tree_add_item(rlogin_tree, hf_startup_info_received_flag,
			                    tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		else
		{
			proto_tree_add_item(rlogin_tree, hf_client_startup_flag,
			                    tvb, offset, 1, ENC_BIG_ENDIAN);
		}
		++offset;
	}

	if (!tvb_offset_exists(tvb, offset))
	{
		/* No more data to check */
		return;
	}

	if (hash_info->info_framenum == pinfo->num)
	{
		int info_len;
		int slash_offset;

		/* First frame of conversation, assume user info... */

		info_len = tvb_captured_length_remaining(tvb, offset);
		if (info_len <= 0)
			return;

		/* User info tree */
		user_info_item = proto_tree_add_string_format(rlogin_tree, hf_user_info, tvb,
		                                              offset, info_len, NULL,
		                                              "User info (%s)",
		                                              tvb_format_text(pinfo->pool, tvb, offset, info_len));
		user_info_tree = proto_item_add_subtree(user_info_item,
		                                        ett_rlogin_user_info);

		/* Client user name. */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(user_info_tree, hf_user_info_client_user_name,
		                    tvb, offset, str_len, ENC_ASCII);
		offset += str_len;

		/* Server user name. */
		str_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(user_info_tree, hf_user_info_server_user_name,
		                    tvb, offset, str_len, ENC_ASCII);
		offset += str_len;

		/* Terminal type/speed. */
		slash_offset = tvb_find_uint8(tvb, offset, -1, '/');
		if (slash_offset != -1)
		{
			uint8_t* str = NULL;
			uint32_t term_len = 0;
			bool term_len_valid;
			proto_item* pi = NULL;

			/* Terminal type */
			proto_tree_add_item(user_info_tree, hf_user_info_terminal_type,
			                    tvb, offset, slash_offset-offset, ENC_ASCII);
			offset = slash_offset + 1;

			/* Terminal speed */
			str_len = tvb_strsize(tvb, offset);
			str = tvb_get_string_enc(pinfo->pool, tvb, offset, str_len,
				ENC_NA|ENC_ASCII);
			term_len_valid = ws_strtou32(str, NULL, &term_len);
			pi = proto_tree_add_uint(user_info_tree,
				hf_user_info_terminal_speed,
				tvb, offset, str_len, term_len);
			if (!term_len_valid)
				expert_add_info(pinfo, pi, &ei_rlogin_termlen_invalid);

			offset += str_len;
		}
	}

	if (!tvb_offset_exists(tvb, offset))
	{
		/* No more data to check */
		return;
	}

	/* Test for terminal information, the data will have 2 0xff bytes */
	/* look for first 0xff byte */
	ti_offset = tvb_find_uint8(tvb, offset, -1, 0xff);

	/* Next byte must also be 0xff */
	if (ti_offset != -1 &&
	    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
	    tvb_get_uint8(tvb, ti_offset + 1) == 0xff)
	{
		uint16_t rows, columns;

		/* Have found terminal info. */
		if (ti_offset > offset)
		{
			/* There's data before the terminal info. */
			proto_tree_add_item(rlogin_tree, hf_data, tvb,
			                    offset, ti_offset - offset, ENC_ASCII);
		}

		/* Create window info tree */
		window_info_item =
			proto_tree_add_item(rlogin_tree, hf_window_info, tvb, offset, 12, ENC_NA);
		window_tree = proto_item_add_subtree(window_info_item, ett_rlogin_window);

		/* Cookie */
		proto_tree_add_item(window_tree, hf_magic_cookie, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* These bytes should be "ss" */
		proto_tree_add_item(window_tree, hf_window_info_ss, tvb, offset, 2, ENC_ASCII);
		offset += 2;

		/* Character rows */
		rows = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(window_tree, hf_window_info_rows, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Characters per row */
		columns = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(window_tree, hf_window_info_cols, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* x pixels */
		proto_tree_add_item(window_tree, hf_window_info_x_pixels, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* y pixels */
		proto_tree_add_item(window_tree, hf_window_info_y_pixels, tvb,
		                    offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Show setting highlights in info column */
		col_append_fstr(pinfo->cinfo, COL_INFO, " (rows=%u, cols=%u)",
			                rows, columns);
	}

	if (tvb_offset_exists(tvb, offset))
	{
		/* There's more data in the frame. */
		proto_tree_add_item(rlogin_tree, hf_data, tvb, offset, -1, ENC_ASCII);
	}
}


/****************************************************************
 * Main dissection function
 ****************************************************************/
static int
dissect_rlogin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	struct tcpinfo *tcpinfo = (struct tcpinfo *)data;
	conversation_t *conversation;
	rlogin_hash_entry_t *hash_info;
	unsigned length;
	int ti_offset;

	/* Get or create conversation */
	conversation = find_or_create_conversation(pinfo);

	/* Get or create data associated with this conversation */
	hash_info = (rlogin_hash_entry_t *)conversation_get_proto_data(conversation, proto_rlogin);
	if (!hash_info)
	{
		/* Populate new data struct... */
		hash_info = wmem_new(wmem_file_scope(), rlogin_hash_entry_t);
		hash_info->state = NONE;
		hash_info->info_framenum = 0;  /* no frame has the number 0 */
		hash_info->user_name[0] = '\0';

		/* ... and store in conversation */
		conversation_add_proto_data(conversation, proto_rlogin, hash_info);
	}

	/* Set protocol column text */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Rlogin");

	/* Set info column */
	/* Show user-name if available */
	if (hash_info->user_name[0])
	{
		col_add_fstr(pinfo->cinfo, COL_INFO,
		              "User name: %s, ", hash_info->user_name);
	}
	else
	{
		col_clear(pinfo->cinfo, COL_INFO);
	}

	/* Work out packet content summary for display */
	length = tvb_reported_length(tvb);
	if (length != 0)
	{
		/* Initial NULL byte represents part of connection handshake */
		if (tvb_get_uint8(tvb, 0) == '\0')
		{
			col_append_str(pinfo->cinfo, COL_INFO,
				               (pinfo->destport == RLOGIN_PORT) ?
				                   "Start Handshake" :
				                   "Startup info received");
		}
		else
		if (tcpinfo && IS_TH_URG(tcpinfo->flags) && length >= tcpinfo->urgent_pointer)
		{
			/* Urgent pointer inside current data represents a control message */
			col_append_str(pinfo->cinfo, COL_INFO, "Control Message");
		}
		else
		{
			/* Search for 2 consecutive ff bytes
			  (signifies window change control message) */
			ti_offset = tvb_find_uint8(tvb, 0, -1, 0xff);
			if (ti_offset != -1 &&
			    tvb_bytes_exist(tvb, ti_offset + 1, 1) &&
			    tvb_get_uint8(tvb, ti_offset + 1) == 0xff)
			{
				col_append_str(pinfo->cinfo, COL_INFO, "Terminal Info");
			}
			else
			{
				/* Show any text data in the frame */
				int bytes_to_copy = tvb_captured_length(tvb);
				if (bytes_to_copy > 128)
				{
					/* Truncate to 128 bytes for display */
					bytes_to_copy = 128;
				}

				/* Add data into info column */
				col_append_fstr(pinfo->cinfo, COL_INFO,
				                "Data: %s",
				                 tvb_format_text(pinfo->pool, tvb, 0, bytes_to_copy));
			}
		}
	}

	/* See if conversation state needs to be updated */
	rlogin_state_machine(hash_info, tvb, pinfo);

	/* Dissect in detail */
	rlogin_display(hash_info, tvb, pinfo, tree, tcpinfo);

	return tvb_captured_length(tvb);
}


void proto_register_rlogin(void)
{
	expert_module_t* expert_rlogin;

	static int *ett[] = {
		&ett_rlogin,
		&ett_rlogin_window,
		&ett_rlogin_window_rows,
		&ett_rlogin_window_cols,
		&ett_rlogin_window_x_pixels,
		&ett_rlogin_window_y_pixels,
		&ett_rlogin_user_info
	};

	static hf_register_info hf[] =
	{
		{ &hf_user_info,
			{ "User Info", "rlogin.user_info", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_client_startup_flag,
			{ "Client startup flag", "rlogin.client_startup_flag", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_startup_info_received_flag,
			{ "Startup info received flag", "rlogin.startup_info_received_flag", FT_UINT8, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_client_user_name,
			{ "Client-user-name", "rlogin.client_user_name", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_server_user_name,
			{ "Server-user-name", "rlogin.server_user_name", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_terminal_type,
			{ "Terminal-type", "rlogin.terminal_type", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_user_info_terminal_speed,
			{ "Terminal-speed", "rlogin.terminal_speed", FT_UINT32, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_control_message,
			{ "Control message", "rlogin.control_message", FT_UINT8, BASE_HEX,
				 VALS(control_message_vals), 0x0, NULL, HFILL
			}
		},
		{ &hf_magic_cookie,
			{ "Magic Cookie", "rlogin.magic_cookie", FT_UINT16, BASE_HEX,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info,
			{ "Window Info", "rlogin.window_size", FT_NONE, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_ss,
			{ "Window size marker", "rlogin.window_size.ss", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_rows,
			{ "Rows", "rlogin.window_size.rows", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_cols,
			{ "Columns", "rlogin.window_size.cols", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_x_pixels,
			{ "X Pixels", "rlogin.window_size.x_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_window_info_y_pixels,
			{ "Y Pixels", "rlogin.window_size.y_pixels", FT_UINT16, BASE_DEC,
				 NULL, 0x0, NULL, HFILL
			}
		},
		{ &hf_data,
			{ "Data", "rlogin.data", FT_STRING, BASE_NONE,
				 NULL, 0x0, NULL, HFILL
			}
		}
	};

	static ei_register_info ei[] = {
		{ &ei_rlogin_termlen_invalid, { "rlogin.terminal_speed.invalid", PI_MALFORMED, PI_ERROR,
			"Terminal length must be a string containing an integer", EXPFILL }}
	};

	proto_rlogin = proto_register_protocol("Rlogin Protocol", "Rlogin", "rlogin");

	proto_register_field_array(proto_rlogin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_rlogin = expert_register_protocol(proto_rlogin);
	expert_register_field_array(expert_rlogin, ei, array_length(ei));

	rlogin_handle = register_dissector("rlogin", dissect_rlogin,proto_rlogin);
}

void proto_reg_handoff_rlogin(void)
{
	/* Dissector install routine */
	dissector_add_uint_with_preference("tcp.port", RLOGIN_PORT, rlogin_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
