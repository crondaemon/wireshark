/* vms.c
 *
 * Wiretap Library
 * Copyright (c) 2001 by Marc Milgram <ethereal@mmilgram.NOSPAMmail.net>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Notes:
 *   TCPIPtrace TCP fragments don't have the header line.  So, we are never
 *   to look for that line for the first line of a packet except the first
 *   packet.  This allows us to read fragmented packets.  Define
 *   TCPIPTRACE_FRAGMENTS_HAVE_HEADER_LINE to expect the first line to be
 *   at the start of every packet.
 */
#include "config.h"
#include "vms.h"
#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/strtoi.h>

#include <stdlib.h>
#include <string.h>

/* This module reads the output of the various VMS TCPIP trace utilities
 * such as TCPIPTRACE, TCPTRACE and UCX$TRACE
 *
 * It was initially based on toshiba.c and refined with code from cosine.c

--------------------------------------------------------------------------------
   Example TCPIPTRACE TCPTRACE output data:

   TCPIPtrace full display RCV packet 8 at 10-JUL-2001 14:54:19.56

   IP Version = 4,  IHL = 5,  TOS = 00,   Total Length = 84 = ^x0054
   IP Identifier  = ^x178F,  Flags (0=0,DF=0,MF=0),
         Fragment Offset = 0 = ^x0000,   Calculated Offset = 0 = ^x0000
   IP TTL = 64 = ^x40,  Protocol = 17 = ^x11,  Header Checksum = ^x4C71
   IP Source Address      = 10.12.1.80
   IP Destination Address = 10.12.1.50

   UDP Source Port = 731,   UDP Destination Port = 111
   UDP Header and Datagram Length = 64 = ^x0040,   Checksum = ^xB6C0

   50010C0A   714C1140   00008F17   54000045    0000    E..T....@.Lq...P
   27E54C3C | C0B64000   6F00DB02 | 32010C0A    0010    ...2...o.@..<L.'
   02000000   A0860100   02000000   00000000    0020    ................
   00000000   00000000   00000000   03000000    0030    ................
   06000000   01000000   A5860100   00000000    0040    ................
                                    00000000    0050    ....
--------------------------------------------------------------------------------

   Example UCX$TRACE output data:

    UCX INTERnet trace RCV packet seq # = 1 at 14-MAY-2003 11:32:10.93

   IP Version = 4,  IHL = 5,  TOS = 00,   Total Length = 583 = ^x0247
   IP Identifier  = ^x702E,  Flags (0=0,DF=0,MF=0),
         Fragment Offset = 0 = ^x0000,   Calculated Offset = 0 = ^x0000
   IP TTL = 128 = ^x80,  Protocol = 17 = ^x11,  Header Checksum = ^x70EC
   IP Source Address      = 10.20.4.159
   IP Destination Address = 10.20.4.255

   UDP Source Port = 138,   UDP Destination Port = 138
   UDP Header and Datagram Length = 563 = ^x0233,   Checksum = ^xB913

   9F04140A   70EC1180   0000702E   47020045    0000    E..G.p.....p....
   B1B80E11 | B9133302   8A008A00 | FF04140A    0010    .........3......
   46484648   45200000   1D028A00   9F04140A    0020    ...........EHFHF
   43414341   4341434D   454D4546   45454550    0030    PEEEFEMEMCACACAC

--------------------------------------------------------------------------------

   Alternate UCX$TRACE type output data:

   TCPIP INTERnet trace RCV packet seq # = 1 at 23-OCT-1998 15:19:33.29

   IP Version = 4,  IHL = 5,  TOS = 00,   Total Length = 217 = ^x00D9
   IP Identifier  = ^x0065,  Flags (0=0,DF=0,MF=0),
         Fragment Offset = 0 = ^x0000,   Calculated Offset = 0 = ^x0000
   IP TTL = 32 = ^x20,  Protocol = 17 = ^x11,  Header Checksum = ^x8F6C
   IP Source Address      = 16.20.168.93
   IP Destination Address = 16.20.255.255

   UDP Source Port = 138,   UDP Destination Port = 138
   UDP Header and Datagram Length = 197 = ^x00C5,   Checksum = ^x0E77

   5DA81410   8F6C1120   00000065   D9000045    0000    E...awe.....l....]
            | 0E77C500   8A008A00 | FFFF1410    0010    ..........w.

--------------------------------------------------------------------------------

The only difference between the utilities is the Packet header line, primarily
the utility identifier and the packet sequence formats.

There appear to be 2 formats for packet sequencing

Format 1:

 ... packet nn at DD-MMM-YYYY hh:mm:ss.ss

Format 2:

 ... packet seq # = nn at DD-MMM-YYYY hh:mm:ss.ss

If there are other formats then code will have to be written in parse_vms_packet()
to handle them.

--------------------------------------------------------------------------------

 */

/* Magic text to check for VMS-ness of file using possible utility names
 *
 */
#define VMS_HDR_MAGIC_STR1      "TCPIPtrace"
#define VMS_HDR_MAGIC_STR2      "TCPtrace"
#define VMS_HDR_MAGIC_STR3      "INTERnet trace"

/* Magic text for start of packet */
#define VMS_REC_MAGIC_STR1      VMS_HDR_MAGIC_STR1
#define VMS_REC_MAGIC_STR2      VMS_HDR_MAGIC_STR2
#define VMS_REC_MAGIC_STR3      VMS_HDR_MAGIC_STR3

#define VMS_HEADER_LINES_TO_CHECK    200
#define VMS_LINE_LENGTH              240

static bool vms_read(wtap *wth, wtap_rec *rec, int *err,
    char **err_info, int64_t *data_offset);
static bool vms_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    int *err, char **err_info);
static bool parse_single_hex_dump_line(char* rec, uint8_t *buf,
    long byte_offset, int in_off, int remaining_bytes);
static bool parse_vms_packet(wtap *wth, FILE_T fh, wtap_rec *rec, int *err,
    char **err_info);

static int vms_file_type_subtype = -1;

void register_vms(void);

#ifdef TCPIPTRACE_FRAGMENTS_HAVE_HEADER_LINE
/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error
   and sets "*err_info" to null or an additional error string. */
static long vms_seek_next_packet(wtap *wth, int *err, char **err_info)
{
    long cur_off;
    char buf[VMS_LINE_LENGTH];

    while (1) {
        cur_off = file_tell(wth->fh);
        if (cur_off == -1) {
            /* Error */
            *err = file_error(wth->fh, err_info);
            return -1;
        }
        if (file_gets(buf, sizeof(buf), wth->fh) == NULL) {
            /* EOF or error. */
            *err = file_error(wth->fh, err_info);
            break;
        }
        if (strstr(buf, VMS_REC_MAGIC_STR1) ||
            strstr(buf, VMS_REC_MAGIC_STR2) ||
            strstr(buf, VMS_REC_MAGIC_STR2)) {
            (void) g_strlcpy(hdr, buf,VMS_LINE_LENGTH);
            return cur_off;
        }
    }
    return -1;
}
#endif /* TCPIPTRACE_FRAGMENTS_HAVE_HEADER_LINE */

/* Look through the first part of a file to see if this is
 * a VMS trace file.
 *
 * Returns true if it is, false if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value and
 * "*err_info will be set to null or an additional error string.
 *
 * Leaves file handle at beginning of line that contains the VMS Magic
 * identifier.
 */
static bool vms_check_file_type(wtap *wth, int *err, char **err_info)
{
    char buf[VMS_LINE_LENGTH];
    unsigned reclen, line;
    int64_t mpos;

    buf[VMS_LINE_LENGTH-1] = '\0';

    for (line = 0; line < VMS_HEADER_LINES_TO_CHECK; line++) {
        mpos = file_tell(wth->fh);
        if (mpos == -1) {
            /* Error. */
            *err = file_error(wth->fh, err_info);
            return false;
        }
        if (file_gets(buf, VMS_LINE_LENGTH, wth->fh) == NULL) {
            /* EOF or error. */
            *err = file_error(wth->fh, err_info);
            return false;
        }

        reclen = (unsigned) strlen(buf);
        if (reclen < strlen(VMS_HDR_MAGIC_STR1) ||
            reclen < strlen(VMS_HDR_MAGIC_STR2) ||
            reclen < strlen(VMS_HDR_MAGIC_STR3)) {
            continue;
        }

        if (strstr(buf, VMS_HDR_MAGIC_STR1) ||
            strstr(buf, VMS_HDR_MAGIC_STR2) ||
            strstr(buf, VMS_HDR_MAGIC_STR3)) {
            /* Go back to the beginning of this line, so we will
             * re-read it. */
            if (file_seek(wth->fh, mpos, SEEK_SET, err) == -1) {
                /* Error. */
                return false;
            }
            return true;
        }
    }
    *err = 0;
    return false;
}


wtap_open_return_val vms_open(wtap *wth, int *err, char **err_info)
{
    /* Look for VMS header */
    if (!vms_check_file_type(wth, err, err_info)) {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    wth->file_encap = WTAP_ENCAP_RAW_IP;
    wth->file_type_subtype = vms_file_type_subtype;
    wth->snapshot_length = 0; /* not known */
    wth->subtype_read = vms_read;
    wth->subtype_seek_read = vms_seek_read;
    wth->file_tsprec = WTAP_TSPREC_10_MSEC;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/* Find the next packet and parse it; called from wtap_read(). */
static bool vms_read(wtap *wth, wtap_rec *rec, int *err,
    char **err_info, int64_t *data_offset)
{
    int64_t  offset = 0;

    /* Find the next packet */
#ifdef TCPIPTRACE_FRAGMENTS_HAVE_HEADER_LINE
    offset = vms_seek_next_packet(wth, err, err_info);
#else
    offset = file_tell(wth->fh);
#endif
    if (offset < 1) {
        *err = file_error(wth->fh, err_info);
        return false;
    }
    *data_offset = offset;

    /* Parse the packet */
    return parse_vms_packet(wth, wth->fh, rec, err, err_info);
}

/* Used to read packets in random-access fashion */
static bool vms_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
        return false;

    if (!parse_vms_packet(wth, wth->random_fh, rec, err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    return true;
}

/* isdumpline assumes that dump lines start with some non-alphanumerics
 * followed by 4 hex numbers - each 8 digits long, each hex number followed
 * by 3 spaces.
 */
static int
isdumpline( char *line )
{
    int i, j;

    while (*line && !g_ascii_isalnum(*line))
        line++;

    for (j=0; j<4; j++) {
        for (i=0; i<8; i++, line++)
            if (! g_ascii_isxdigit(*line))
                return false;

        for (i=0; i<3; i++, line++)
            if (*line != ' ')
                return false;
    }

    return g_ascii_isspace(*line);
}

/* Parses a packet record. */
static bool
parse_vms_packet(wtap *wth, FILE_T fh, wtap_rec *rec, int *err, char **err_info)
{
    char    line[VMS_LINE_LENGTH + 1];
    int     num_items_scanned;
    bool have_pkt_len = false;
    uint32_t pkt_len = 0;
    int     pktnum;
    int     csec = 101;
    struct tm tm;
    char mon[4] = {'J', 'A', 'N', 0};
    char   *p;
    const char *endp;
    static const char months[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";
    uint32_t i;
    int     offset = 0;
    uint8_t *pd;

    tm.tm_year = 1970;
    tm.tm_mon = 0;
    tm.tm_mday = 1;
    tm.tm_hour = 1;
    tm.tm_min = 1;
    tm.tm_sec = 1;

    /* Skip lines until one starts with a hex number */
    do {
        if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
            *err = file_error(fh, err_info);
            if ((*err == 0) && (csec != 101)) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return false;
        }
        line[VMS_LINE_LENGTH] = '\0';

        if ((csec == 101) && (p = strstr(line, "packet ")) != NULL
            && (! strstr(line, "could not save "))) {
            /* Find text in line starting with "packet ". */

            /* First look for the Format 1 type sequencing */
            num_items_scanned = sscanf(p,
                                       "packet %9d at %2d-%3s-%4d %2d:%2d:%2d.%9d",
                                       &pktnum, &tm.tm_mday, mon,
                                       &tm.tm_year, &tm.tm_hour,
                                       &tm.tm_min, &tm.tm_sec, &csec);
            /* Next look for the Format 2 type sequencing */
            if (num_items_scanned != 8) {
              num_items_scanned = sscanf(p,
                                         "packet seq # = %9d at %2d-%3s-%4d %2d:%2d:%2d.%9d",
                                         &pktnum, &tm.tm_mday, mon,
                                         &tm.tm_year, &tm.tm_hour,
                                         &tm.tm_min, &tm.tm_sec, &csec);
            }
            /* if unknown format then exit with error        */
            /* We will need to add code to handle new format */
            if (num_items_scanned != 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("vms: header line not valid");
                return false;
            }
        }
        if ( (! have_pkt_len) && (p = strstr(line, "Length "))) {
            p += sizeof("Length ");
            while (*p && ! g_ascii_isdigit(*p))
                p++;

            if ( !*p ) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("vms: Length field not valid");
                return false;
            }

            if (!ws_strtou32(p, &endp, &pkt_len) || (*endp != '\0' && !g_ascii_isspace(*endp))) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("vms: Length field '%s' not valid", p);
                return false;
            }
            have_pkt_len = true;
            break;
        }
    } while (! isdumpline(line));
    if (! have_pkt_len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("vms: Length field not found");
        return false;
    }
    if (pkt_len > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; return an error,
         * so that our caller doesn't blow up trying to allocate
         * space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("vms: File has %u-byte packet, bigger than maximum of %u",
                                    pkt_len, WTAP_MAX_PACKET_SIZE_STANDARD);
        return false;
    }

    p = strstr(months, mon);
    if (p)
        tm.tm_mon = (int) (p - months) / 3;
    tm.tm_year -= 1900;
    tm.tm_isdst = -1;

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts.secs = mktime(&tm);
    rec->ts.nsecs = csec * 10000000;
    rec->rec_header.packet_header.caplen = pkt_len;
    rec->rec_header.packet_header.len = pkt_len;

    /* Make sure we have enough room for the packet */
    ws_buffer_assure_space(&rec->data, pkt_len);
    pd = ws_buffer_start_ptr(&rec->data);

    /* Convert the ASCII hex dump to binary data */
    for (i = 0; i < pkt_len; i += 16) {
        if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
            *err = file_error(fh, err_info);
            if (*err == 0) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return false;
        }
        line[VMS_LINE_LENGTH] = '\0';
        if (i == 0) {
            while (! isdumpline(line)) { /* advance to start of hex data */
                if (file_gets(line, VMS_LINE_LENGTH, fh) == NULL) {
                    *err = file_error(fh, err_info);
                    if (*err == 0) {
                        *err = WTAP_ERR_SHORT_READ;
                    }
                    return false;
                }
                line[VMS_LINE_LENGTH] = '\0';
            }
            while (line[offset] && !g_ascii_isxdigit(line[offset]))
                offset++;
        }
        if (!parse_single_hex_dump_line(line, pd, i,
                                        offset, pkt_len - i)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("vms: hex dump not valid");
            return false;
        }
    }
    /* Avoid TCPIPTRACE-W-BUFFERSFUL, TCPIPtrace could not save n packets.
     * errors.
     *
     * XXX - when we support packet drop report information in the
     * Wiretap API, we should parse those lines and return "n" as
     * a packet drop count. */
    if (!file_gets(line, VMS_LINE_LENGTH, fh)) {
        *err = file_error(fh, err_info);
        if (*err == 0) {
            /* There is no next line, so there's no "TCPIPtrace could not
             * save n packets" line; not an error. */
            return true;
        }
        return false;
    }
    return true;
}

/*
          1         2         3         4
0123456789012345678901234567890123456789012345
   50010C0A   A34C0640   00009017   2C000045    0000    E..,....@.L....P
   00000000   14945E52   0A00DC02 | 32010C0A    0010    ...2....R^......
       0000 | B4050402   00003496   00020260    0020    `....4........
*/

#define START_POS    7
#define HEX_LENGTH    ((8 * 4) + 7) /* eight clumps of 4 bytes with 7 inner spaces */
/* Take a string representing one line from a hex dump and converts the
 * text to binary data. We check the printed offset with the offset
 * we are passed to validate the record. We place the bytes in the buffer
 * at the specified offset.
 *
 * Returns true if good hex dump, false if bad.
 */
static bool
parse_single_hex_dump_line(char* rec, uint8_t *buf, long byte_offset,
               int in_off, int remaining_bytes) {

    int        i;
    char        *s;
    int        value;
    static const int offsets[16] = {39,37,35,33,28,26,24,22,17,15,13,11,6,4,2,0};
    char lbuf[3] = {0,0,0};


    /* Get the byte_offset directly from the record */
    s = rec;
    value = (int)strtoul(s + 45 + in_off, NULL, 16);    /* XXX - error check? */

    if (value != byte_offset) {
        return false;
    }

    if (remaining_bytes > 16)
        remaining_bytes = 16;

    /* Read the octets right to left, as that is how they are displayed
     * in VMS.
     */

    for (i = 0; i < remaining_bytes; i++) {
        lbuf[0] = rec[offsets[i] + in_off];
        lbuf[1] = rec[offsets[i] + 1 + in_off];

        buf[byte_offset + i] = (uint8_t) strtoul(lbuf, NULL, 16);
    }

    return true;
}

static const struct supported_block_type vms_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info vms_info = {
    "TCPIPtrace (VMS)", "tcpiptrace", "txt", NULL,
    false, BLOCKS_SUPPORTED(vms_blocks_supported),
    NULL, NULL, NULL
};

void register_vms(void)
{
    vms_file_type_subtype = wtap_register_file_type_subtype(&vms_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("VMS",
                                                   vms_file_type_subtype);
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
