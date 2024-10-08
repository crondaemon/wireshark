/* file-pcapng-darwin.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <wsutil/array.h>

#include <epan/dissectors/file-pcapng.h>

/*
 * Apple's Pcapng Darwin Process Event Block
 *
 *    A Darwin Process Event Block (DPEB) is an Apple defined container
 *    for information describing a Darwin process.
 *
 *    Tools that write / read the capture file associate an incrementing
 *    32-bit number (starting from '0') to each Darwin Process Event Block,
 *    called the DPEB ID for the process in question.  This number is
 *    unique within each Section and identifies a specific DPEB; a DPEB ID
 *    is only unique inside the current section. Two Sections can have different
 *    processes identified by the same DPEB ID values.  DPEB ID are referenced
 *    by Enhanced Packet Blocks that include options to indicate the Darwin
 *    process to which the EPB refers.
 *
 *
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *         +---------------------------------------------------------------+
 *       0 |                   Block Type = 0x80000001                     |
 *         +---------------------------------------------------------------+
 *       4 |                     Block Total Length                        |
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       8 |                          Process ID                           |
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      12 /                                                               /
 *         /                      Options (variable)                       /
 *         /                                                               /
 *         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         |                     Block Total Length                        |
 *         +---------------------------------------------------------------+
 *
 *                   Figure XXX.1: Darwin Process Event Block
 *
 *    The meaning of the fields are:
 *
 *    o  Block Type: The block type of a Darwin Process Event Block is 2147483649.
 *
 *       Note: This specific block type number falls into the range defined
 *       for "local use" but has in fact been available publicly since Darwin
 *       13.0 for pcapng files generated by Apple's tcpdump when using the PKTAP
 *       enhanced interface.
 *
 *    o  Block Total Length: Total size of this block, as described in
 *       Pcapng Section 3.1 (General Block Structure).
 *
 *    o  Process ID: The process ID (PID) of the process.
 *
 *       Note: It is not known if this field is officially defined as a 32 bits
 *       (4 octets) or something smaller since Darwin PIDs currently appear to
 *       be limited to maximum value of 100000.
 *
 *    o  Options: A list of options (formatted according to the rules defined
 *       in Section 3.5) can be present.
 *
 *    In addition to the options defined in Section 3.5, the following
 *    Apple defined Darwin options are valid within this block:
 *
 *           +------------------+------+----------+-------------------+
 *           | Name             | Code | Length   | Multiple allowed? |
 *           +------------------+------+----------+-------------------+
 *           | darwin_proc_name | 2    | variable | no                |
 *           | darwin_proc_uuid | 4    | 16       | no                |
 *           +------------------+------+----------+-------------------+
 *
 *              Table XXX.1: Darwin Process Description Block Options
 *
 *    darwin_proc_name:
 *            The darwin_proc_name option is a UTF-8 string containing the
 *            name of a process producing or consuming an EPB.
 *
 *            Examples: "mDNSResponder", "GoogleSoftwareU".
 *
 *            Note: It appears that Apple's tcpdump currently truncates process
 *            names to a maximum of 15 octets followed by a NUL character.
 *            Multi-byte UTF-8 sequences in process names might be truncated
 *            resulting in an invalid final UTF-8 character.
 *
 *            This is probably because the process name comes from the
 *            p_comm field in a proc structure in the kernel; that field
 *            is MAXCOMLEN+1 bytes long, with the +1 being for the NUL
 *            terminator.  That would give 16 characters, but the
 *            proc_info kernel interface has a structure with a
 *            process name field of only MAXCOMLEN bytes.
 *
 *            This all ultimately dates back to the "kernel accounting"
 *            mechanism that appeared in V7 UNIX, with an "accounting
 *            file" with entries appended whenever a process exits; not
 *            surprisingly, that code thinks a file name is just a bunch
 *            of "char"s, with no multi-byte encodings (1979 called, they
 *            want their character encoding back), so, yes, this can
 *            mangle UTF-8 file names containing non-ASCII characters.
 *
 *    darwin_proc_uuid:
 *            The darwin_proc_uuid option is a set of 16 octets representing
 *            the process UUID.
 *
 */

static int proto_pcapng_darwin_process_info;

void proto_register_pcapng_darwin_process_info(void);
void proto_reg_handoff_pcapng_darwin_process_info(void);


static int hf_pcapng_option_code_darwin_process_info;
static int hf_pcapng_darwin_process_id;
static int hf_pcapng_option_darwin_process_name;
static int hf_pcapng_option_darwin_process_uuid;

#define BLOCK_DARWIN_PROCESS         0x80000001
#define BLOCK_DARWIN_PROCESS_NAME    "Darwin Process Event Block"


static const value_string option_code_darwin_process_info_vals[] = {
    { 0,  "End of Options" },
    { 1,  "Comment" },
    { 2,  "Darwin Process Name" },
    { 4,  "Darwin Process UUID" },
    { 0, NULL }
};

/* Dissect an individual option */
static
void dissect_darwin_process_info_option(proto_tree *option_tree, proto_item *option_item,
                                        packet_info *pinfo, tvbuff_t *tvb, int offset,
                                        int unknown_option_hf,
                                        uint32_t option_code, uint32_t option_length,
                                        unsigned encoding _U_)
{
    char         *str;
    e_guid_t      uuid;

    switch (option_code) {
        case 2: /* Darwin Process Name */
            proto_tree_add_item_ret_display_string(option_tree, hf_pcapng_option_darwin_process_name, tvb, offset, option_length, ENC_NA | ENC_UTF_8, pinfo->pool, &str);
            break;

        case 4: /* Darwin Process UUID */
            proto_tree_add_item(option_tree, hf_pcapng_option_darwin_process_uuid, tvb, offset, option_length, ENC_BIG_ENDIAN);
            tvb_get_guid(tvb, offset, &uuid, ENC_BIG_ENDIAN);

            proto_item_append_text(option_item, " = %s",
                guid_to_str(pinfo->pool, &uuid));

            break;
        default:
            proto_tree_add_item(option_tree, unknown_option_hf, tvb, offset, option_length, ENC_NA);
            break;
    }
}

/* Dissect this block type */
static void
dissect_darwin_process_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
                            block_data_arg *argp)
{
    int offset = 0;

    /* Show current nuber of these blocks, and increment */
    proto_item_append_text(argp->block_item, " %u", argp->info->darwin_process_event_number);
    argp->info->darwin_process_event_number += 1;

    /* Process ID */
    proto_tree_add_item(tree, hf_pcapng_darwin_process_id, tvb, offset, 4, argp->info->encoding);
    offset += 4;

    /* Options */
    dissect_options(tree, pinfo, BLOCK_DARWIN_PROCESS, tvb, offset, argp->info->encoding, NULL);
}


void
proto_register_pcapng_darwin_process_info(void)
{
    static hf_register_info hf[] = {

        { &hf_pcapng_option_code_darwin_process_info,
            { "Code",                                      "pcapng.darwin.options.option.code",
            FT_UINT16, BASE_DEC, VALS(option_code_darwin_process_info_vals), 0x00,
            "Darwin Process Info block option", HFILL }
        },
        { &hf_pcapng_darwin_process_id,
            { "Darwin Process ID",                         "pcapng.darwin.process_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            "Process ID for Darwin Process Info", HFILL }
        },
        { &hf_pcapng_option_darwin_process_name,
            { "Darwin Process Name",                       "pcapng.darwin.process_name",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "Process name for Darwin Process Info", HFILL }
        },
        { &hf_pcapng_option_darwin_process_uuid,
            { "Darwin Process UUID",                       "pcapng.darwin.process_uuid",
            FT_GUID, BASE_NONE, NULL, 0x00,
            "Process UUID for Darwin Process Info", HFILL }
        },
    };

    proto_pcapng_darwin_process_info = proto_register_protocol("PCAPNG Darwin Process Information Block", "Darwin-Process-Information", "pcapng.darwin");

    proto_register_field_array(proto_pcapng_darwin_process_info, hf, array_length(hf));
}

void
proto_reg_handoff_pcapng_darwin_process_info(void)
{
    /* Register with pcapng dissector */
    static local_block_callback_info_t dissector_info;
    dissector_info.name = BLOCK_DARWIN_PROCESS_NAME;
    /* Block-dissector function */
    dissector_info.dissector = dissect_darwin_process_data;
    /* Options-related */
    dissector_info.option_root_hf = hf_pcapng_option_code_darwin_process_info;
    dissector_info.option_vals = option_code_darwin_process_info_vals;
    dissector_info.option_dissector = dissect_darwin_process_info_option;

    register_pcapng_local_block_dissector(BLOCK_DARWIN_PROCESS, &dissector_info);
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
