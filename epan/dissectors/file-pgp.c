/* file-pgp.c
 *
 * Routines for dissecting PGP files
 *
 * Copyright 2019, Dario Lombardo <lomato@gmail.com>
 *
 * https://tools.ietf.org/html/rfc4880
 *
 * A useful tool for analyzing PGP files is pgpdump
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

static int proto_pgp = -1;

static int hf_pgp_one = -1;
static int hf_pgp_format = -1;
static int hf_pgp_tag = -1;
static int hf_pgp_length_type = -1;
static int hf_pgp_packet_length = -1;
static int hf_pgp_public_key_version = -1;
static int hf_pgp_public_key_created = -1;
static int hf_pgp_public_key_algo = -1;
static int hf_pgp_mpi_len = -1;
static int hf_pgp_mpi_value = -1;
static int hf_pgp_string_to_key = -1;
static int hf_pgp_sym_algo = -1;
static int hf_pgp_s2k_octet_zero = -1;
static int hf_pgp_hash_algo = -1;
static int hf_pgp_salt = -1;
static int hf_pgp_count = -1;
static int hf_pgp_iv = -1;

static gint ett_pgp = -1;
static gint ett_pgp_ptag = -1;
static gint ett_pgp_mpi = -1;
static gint ett_pgp_s2k = -1;

static expert_field ei_pgp_unsupported = EI_INIT;

void proto_register_rbm(void);
void proto_reg_handoff_rbm(void);

#define EXPBIAS 6

static const value_string gpg_formats[] = {
	{ 0, "Old" },
	{ 1, "New" },
	{ 0, NULL }
};

// PGP tags define the message types
#define TAG_RESERVED 0
#define TAG_PUBLIC_KEY_ENC_SESSION_KEY 1
#define TAG_SIGNATURE 2
#define TAG_SYM_KEY_ENCRYPTED_SESSION_KEY 3
#define TAG_ONE_PASS_SIGNATURE 4
#define TAG_SECRET_KEY 5
#define TAG_PUBLIC_KEY 6
#define TAG_SECRET_SUBKEY 7
#define TAG_COMPRESSED_DATA 8
#define TAG_SYM_ENCRYPTED_DATA 9
#define TAG_MARKER 10
#define TAG_LITERAL_DATA 11
#define TAG_TRUST 12
#define TAG_USER_ID 13
#define TAG_PUBLIC_SUBKEY 14
#define TAG_USER_ATTRIBUTE 17
#define TAG_SYM_ENC_AND_INT_PROT 18
#define TAG_MODIFICATION_DETECTION_CODE 19
#define TAG_PRIVATE_EXPERIMENTAL_1 60
#define TAG_PRIVATE_EXPERIMENTAL_2 61
#define TAG_PRIVATE_EXPERIMENTAL_3 62
#define TAG_PRIVATE_EXPERIMENTAL_4 63

static const value_string gpg_tags[] = {
	{ TAG_RESERVED, "Reserved - a packet tag MUST NOT have this value" },
	{ TAG_PUBLIC_KEY_ENC_SESSION_KEY, "Public-Key Encrypted Session Key Packet" },
	{ TAG_SIGNATURE, "Signature Packet" },
	{ TAG_SYM_KEY_ENCRYPTED_SESSION_KEY, "Symmetric-Key Encrypted Session Key Packet" },
	{ TAG_ONE_PASS_SIGNATURE, "One-Pass Signature Packet" },
	{ TAG_SECRET_KEY, "Secret-Key Packet" },
	{ TAG_PUBLIC_KEY, "Public-Key Packet" },
	{ TAG_SECRET_SUBKEY, "Secret-Subkey Packet" },
	{ TAG_COMPRESSED_DATA, "Compressed Data Packet" },
	{ TAG_SYM_ENCRYPTED_DATA, "Symmetrically Encrypted Data Packet" },
	{ TAG_MARKER, "Marker Packet" },
	{ TAG_LITERAL_DATA, "Literal Data Packet" },
	{ TAG_TRUST, "Trust Packet" },
	{ TAG_USER_ID, "User ID Packet" },
	{ TAG_PUBLIC_SUBKEY, "Public-Subkey Packet" },
	{ TAG_USER_ATTRIBUTE, "User Attribute Packet" },
	{ TAG_SYM_ENC_AND_INT_PROT, "Sym. Encrypted and Integrity Protected Data Packet" },
	{ TAG_MODIFICATION_DETECTION_CODE, "Modification Detection Code Packet" },
	{ TAG_PRIVATE_EXPERIMENTAL_1, "Private or Experimental Value" },
	{ TAG_PRIVATE_EXPERIMENTAL_2, "Private or Experimental Value" },
	{ TAG_PRIVATE_EXPERIMENTAL_3, "Private or Experimental Value" },
	{ TAG_PRIVATE_EXPERIMENTAL_4, "Private or Experimental Value" },
	{ 0,  NULL }
};

// Encryption algorhitms
#define ALGO_RSA_ENC_SIGN 1
#define ALGO_RSA_ENC 2
#define ALGO_RSA_SIGN 3
#define ALGO_ELGAMAL 16
#define ALGO_DSA 17
#define ALGO_RESERVED_ELLIPTIC 18
#define ALGO_RESERVED_ECDSA 19
#define ALGO_RESERVED_LEGACY 20
#define ALGO_RESERVED_DH 21

static const value_string public_key_algorithms[] = {
	{ ALGO_RSA_ENC_SIGN, "RSA (Encrypt or Sign)" },
	{ ALGO_RSA_ENC, "RSA Encrypt-Only" },
	{ ALGO_RSA_SIGN, "RSA Sign-Only" },
	{ ALGO_ELGAMAL, "Elgamal (Encrypt-Only)" },
	{ ALGO_DSA, "DSA (Digital Signature Algorithm)" },
	{ ALGO_RESERVED_ELLIPTIC, "Reserved for Elliptic Curve" },
	{ ALGO_RESERVED_ECDSA, "Reserved for ECDSA" },
	{ ALGO_RESERVED_LEGACY, "Reserved (formerly Elgamal Encrypt or Sign)" },
	{ ALGO_RESERVED_DH, "Reserved for Diffie-Hellman" },
	{ 0,  NULL }
};

// 9.2.  Symmetric-Key Algorithms
#define SYM_ALGO_PLAINTEXT 0
#define SYM_ALGO_IDEA 1
#define SYM_ALGO_TRIPLEDES 2
#define SYM_ALGO_CAST5 3
#define SYM_ALGO_BLOWFISH 4
#define SYM_ALGO_RESERVED_1 5
#define SYM_ALGO_RESERVED_2 6
#define SYM_ALGO_AES_128  7
#define SYM_ALGO_AES_192 8
#define SYM_ALGO_AES_256 9
#define SYM_ALGO_TWOFISH 10
#define SYM_ALGO_PRIVATE_1 100
#define SYM_ALGO_PRIVATE_2 101
#define SYM_ALGO_PRIVATE_3 102
#define SYM_ALGO_PRIVATE_4 103
#define SYM_ALGO_PRIVATE_5 104
#define SYM_ALGO_PRIVATE_6 105
#define SYM_ALGO_PRIVATE_7 106
#define SYM_ALGO_PRIVATE_8 107
#define SYM_ALGO_PRIVATE_9 108
#define SYM_ALGO_PRIVATE_10 109
#define SYM_ALGO_PRIVATE_11 110

static const value_string sym_algos[] = {
	{ SYM_ALGO_PLAINTEXT, "Plaintext or unencrypted data" },
	{ SYM_ALGO_IDEA, "IDEA" },
	{ SYM_ALGO_TRIPLEDES, "TripleDES" },
	{ SYM_ALGO_CAST5, "CAST5" },
	{ SYM_ALGO_BLOWFISH, "Blowfish" },
	{ SYM_ALGO_RESERVED_1, "Reserved" },
	{ SYM_ALGO_RESERVED_2, "Reserved" },
	{ SYM_ALGO_AES_128, "AES with 128-bit key" },
	{ SYM_ALGO_AES_192, "AES with 192-bit key" },
	{ SYM_ALGO_AES_256, "AES with 256-bit key" },
	{ SYM_ALGO_TWOFISH, "Twofish with 256-bit key" },
	{ SYM_ALGO_PRIVATE_1, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_2, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_3, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_4, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_5, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_6, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_7, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_8, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_9, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_10, "Private/Experimental algorithm" },
	{ SYM_ALGO_PRIVATE_11, "Private/Experimental algorithm" },
	{ 0, NULL }
};

#define S2K_SIMPLE 0
#define S2K_SALTED 1
#define S2K_RESERVED 2
#define S2K_ITERATED_AND_SALTED 3
#define S2K_PRIVATE_1 100
#define S2K_PRIVATE_2 101
#define S2K_PRIVATE_3 102
#define S2K_PRIVATE_4 103
#define S2K_PRIVATE_5 104
#define S2K_PRIVATE_6 105
#define S2K_PRIVATE_7 106
#define S2K_PRIVATE_8 107
#define S2K_PRIVATE_9 108
#define S2K_PRIVATE_10 109
#define S2K_PRIVATE_11 110

static const value_string s2k_types[] = {
	{ S2K_SIMPLE, "Simple S2K" },
	{ S2K_SALTED, "Salted S2K" },
	{ S2K_RESERVED, "Reserved value" },
	{ S2K_ITERATED_AND_SALTED, "Iterated and Salted S2K" },
	{ S2K_PRIVATE_1, "Private/Experimental S2K" },
	{ S2K_PRIVATE_2, "Private/Experimental S2K" },
	{ S2K_PRIVATE_3, "Private/Experimental S2K" },
	{ S2K_PRIVATE_4, "Private/Experimental S2K" },
	{ S2K_PRIVATE_5, "Private/Experimental S2K" },
	{ S2K_PRIVATE_6, "Private/Experimental S2K" },
	{ S2K_PRIVATE_7, "Private/Experimental S2K" },
	{ S2K_PRIVATE_8, "Private/Experimental S2K" },
	{ S2K_PRIVATE_9, "Private/Experimental S2K" },
	{ S2K_PRIVATE_10, "Private/Experimental S2K" },
	{ S2K_PRIVATE_11, "Private/Experimental S2K" },
	{ 0, NULL }
};

static const value_string hash_algos[] = {
	{ 1, "MD5" },
	{ 2, "SHA-1" },
	{ 3, "RIPE-MD/160" },
	{ 4, "Reserved" },
	{ 5, "Reserved" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 8, "SHA256" },
	{ 9, "SHA384" },
	{ 10, "SHA512" },
	{ 11, "SHA224" },
	{ 100, "Private/Experimental algorithm" },
	{ 101, "Private/Experimental algorithm" },
	{ 102, "Private/Experimental algorithm" },
	{ 103, "Private/Experimental algorithm" },
	{ 104, "Private/Experimental algorithm" },
	{ 105, "Private/Experimental algorithm" },
	{ 106, "Private/Experimental algorithm" },
	{ 107, "Private/Experimental algorithm" },
	{ 108, "Private/Experimental algorithm" },
	{ 109, "Private/Experimental algorithm" },
	{ 110, "Private/Experimental algorithm" },
	{ 0, NULL }
};

static void dissect_pgp_mpi(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, guint* offset, const gchar* text)
{
	guint16 mpi_len;
	guint mpi_len_bytes;
	proto_tree* tree_mpi;

	mpi_len = tvb_get_guint16(tvb, *offset, ENC_BIG_ENDIAN);

	tree_mpi = proto_tree_add_subtree_format(tree, tvb, *offset, 2 + mpi_len, ett_pgp_mpi, NULL, "MPI: %s", text);
	proto_tree_add_item(tree_mpi, hf_pgp_mpi_len, tvb, *offset, 2, ENC_BIG_ENDIAN);
	*offset += 2;

	// The length of the mpi in bytes
	mpi_len_bytes = (mpi_len + 7) / 8;
	proto_tree_add_item(tree_mpi, hf_pgp_mpi_value, tvb, *offset, mpi_len_bytes, ENC_NA);
	*offset += mpi_len_bytes;
}

static void dissect_pgp_s2k(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, guint* offset _U_)
{
	guint8 type;
	proto_tree* s2k_tree;
	guint octet_zero;
	guint c, count;
	guint start_offset = *offset;
	guint algo;

	type = tvb_get_guint8(tvb, *offset);

	s2k_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_pgp_s2k, NULL, "%s: ",
		val_to_str(type, s2k_types, "Unknown (0x%02x)"));

	proto_tree_add_item_ret_uint(s2k_tree, hf_pgp_s2k_octet_zero, tvb, *offset, 1, ENC_NA, &octet_zero);
	*offset += 1;

	proto_tree_add_item_ret_uint(s2k_tree, hf_pgp_hash_algo, tvb, *offset, 1, ENC_NA, &algo);
	*offset += 1;

	proto_item_append_text(s2k_tree, "%s", val_to_str(algo, hash_algos, "Unknown (0x%02x)"));

	switch (type) {
		case S2K_SIMPLE:
			if (octet_zero != 0x0) {
				// TODO error
				return;
			}
			break;
		case S2K_SALTED:
			if (octet_zero != 0x1) {
				// TODO error
				return;
			}
			proto_tree_add_item(s2k_tree, hf_pgp_salt, tvb, *offset, 8, ENC_NA);
			*offset += 8;
			break;
		case S2K_ITERATED_AND_SALTED:
			if (octet_zero != 0x3) {
				// TODO error
				return;
			}
			proto_tree_add_item(s2k_tree, hf_pgp_salt, tvb, *offset, 8, ENC_NA);
			*offset += 8;
			c = tvb_get_guint8(tvb, *offset);
			count = ((guint32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
			proto_tree_add_uint_format_value(s2k_tree, hf_pgp_count, tvb, *offset, 1, count, "%u (coded: %u)", count, c);
			*offset += 1;
			break;
		default:
			break;
	}

	proto_item_set_len(s2k_tree, *offset - start_offset);
}

static void dissect_pgp_public_key_v3(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, guint* offset _U_, gint algo _U_)
{
}

static void dissect_pgp_public_key_v4(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset, guint algo)
{
	switch (algo) {
		case ALGO_RSA_ENC_SIGN:
		case ALGO_RSA_ENC:
		case ALGO_RSA_SIGN:
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "RSA public modulus n");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "RSA public encryption exponent e");
			break;
		case ALGO_DSA:
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "MPI of DSA prime p");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "MPI of DSA group order q");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "MPI of DSA group generator g");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "MPI of DSA public-key value y");
			break;
		case ALGO_ELGAMAL:
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "Elgamal prime p");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "Elgamal group generator g");
			dissect_pgp_mpi(tvb, pinfo, tree, offset, "Elgamal public key value y");
			break;
		default:
			expert_add_info(pinfo, tree, &ei_pgp_unsupported);
			return;
	}
}

static void dissect_pgp_public_key(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset)
{
	guint version;
	guint algo;
	proto_item* pi;

	pi = proto_tree_add_item_ret_uint(tree, hf_pgp_public_key_version, tvb, *offset, 1, ENC_NA, &version);
	*offset += 1;

	proto_tree_add_item(tree, hf_pgp_public_key_created, tvb, *offset, 4, ENC_TIME_SECS);
	*offset += 4;

	proto_tree_add_item_ret_uint(tree, hf_pgp_public_key_algo, tvb, *offset, 1, ENC_NA, &algo);
	*offset += 1;

	switch (version) {
		case 3:
			dissect_pgp_public_key_v3(tvb, pinfo, tree, offset, algo);
			break;
		case 4:
			dissect_pgp_public_key_v4(tvb, pinfo, tree, offset, algo);
			break;
		default:
			expert_add_info(pinfo, pi, &ei_pgp_unsupported);
	}
}

static void dissect_pgp_secret_key(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, guint* offset)
{
	guint string_to_key_convention;
	proto_item* pi;
	guint algo;
	gboolean encrypted = FALSE;

	dissect_pgp_public_key(tvb, pinfo, tree, offset);

	pi = proto_tree_add_item_ret_uint(tree, hf_pgp_string_to_key, tvb, *offset, 1, ENC_NA, &string_to_key_convention);

	switch (string_to_key_convention) {
		case 0:
			expert_add_info(pinfo, pi, &ei_pgp_unsupported);
			break;
		case 254:
		case 255:
			*offset += 1;
			pi = proto_tree_add_item_ret_uint(tree, hf_pgp_sym_algo, tvb, *offset, 1, ENC_NA, &algo);
			*offset += 1;
			dissect_pgp_s2k(tvb, pinfo, tree, offset);
			encrypted = TRUE;
			break;
		default:
			proto_tree_add_item(tree, hf_pgp_sym_algo, tvb, *offset, 1, ENC_NA);
	}

	switch (algo) {
		case SYM_ALGO_AES_128:
			if (encrypted)
				proto_tree_add_item(tree, hf_pgp_iv, tvb, *offset, 16, ENC_NA);
			break;
		default:
			expert_add_info(pinfo, pi, &ei_pgp_unsupported);
			return;
	}
}

static int dissect_pgp_new(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, proto_tree* ptag_tree _U_)
{
	guint offset = 1;
	expert_add_info(pinfo, tree, &ei_pgp_unsupported);
	return offset;
}

static int dissect_pgp_old(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_tree* ptag_tree)
{
	guint offset = 0;
	guint8 tag;
	guint8 length_type;
	guint8 header_length;
	proto_item* tag_item;

	tag_item = proto_tree_add_item(ptag_tree, hf_pgp_tag, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(ptag_tree, hf_pgp_length_type, tvb, offset, 1, ENC_NA);
	length_type = tvb_get_guint8(tvb, 0) & 0x3;

	switch(length_type) {
		case 0:
			header_length = 2;
			break;
		case 1:
			header_length = 3;
			break;
		case 2:
			header_length = 5;
			break;
		case 3:
			header_length = 1;
			break;
		default:
			// TODO: error, expert info
			return offset;
	}

	tag = (tvb_get_guint8(tvb, 0) & 0x3c) >> 2;
	col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s", val_to_str(tag, gpg_tags, "Unknown (0x%02x)"));
	proto_item_append_text(ptag_tree, "%s", val_to_str(tag, gpg_tags, "Unknown (0x%02x)"));

	proto_tree_add_item(tree, hf_pgp_packet_length, tvb, 1, header_length - 1, ENC_BIG_ENDIAN);
	offset = header_length;

	switch (tag) {
		case TAG_SECRET_KEY:
		case TAG_SECRET_SUBKEY:
			dissect_pgp_secret_key(tvb, pinfo, tree, &offset);
			break;
		case TAG_PUBLIC_KEY:
		case TAG_PUBLIC_SUBKEY:
			dissect_pgp_public_key(tvb, pinfo, tree, &offset);
			break;
		default:
			expert_add_info(pinfo, tag_item, &ei_pgp_unsupported);
			return offset;
	}

	return offset;
}

static int dissect_pgp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	proto_item* ti;
	proto_tree* pgp_tree;
	proto_tree* ptag_tree;
	guint8 ptag;
	guint offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_pgp, tvb, 0, -1, ENC_NA);
	pgp_tree = proto_item_add_subtree(ti, ett_pgp);

	ptag = tvb_get_guint8(tvb, 0);
	ptag_tree = proto_tree_add_subtree_format(pgp_tree, tvb, 0, 1, ett_pgp_ptag, NULL, "Packet Tag: ");

	proto_tree_add_item(ptag_tree, hf_pgp_one, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(ptag_tree, hf_pgp_format, tvb, 0, 1, ENC_NA);

	if (ptag && 0x40 >> 6) {
		offset = dissect_pgp_old(tvb, pinfo, pgp_tree, ptag_tree);
	} else {
		offset = dissect_pgp_new(tvb, pinfo, pgp_tree, ptag_tree);
	}
	return offset;
}

void proto_register_pgp(void)
{
	expert_module_t* expert_pgp;

	static hf_register_info hf[] = {
		{ &hf_pgp_one,
			{ "One", "pgp.one", FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_pgp_format,
			{ "Format", "pgp.format", FT_UINT8, BASE_HEX, VALS(gpg_formats), 0x40, NULL, HFILL }
		},
		{ &hf_pgp_tag,
			{ "Tag", "pgp.tag", FT_UINT8, BASE_HEX, VALS(gpg_tags), 0x3C, NULL, HFILL }
		},
		{ &hf_pgp_length_type,
			{ "Length Type", "pgp.format", FT_UINT8, BASE_HEX, NULL, 0x3, NULL, HFILL }
		},
		{ &hf_pgp_packet_length,
			{ "Packet Length", "pgp.packet_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_public_key_version,
			{ "Public Key Version", "pgp.public_key.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_public_key_created,
			{ "Public Key created at", "pgp.public_key.created", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_public_key_algo,
			{ "Public Key Algorhithm", "pgp.public_key.algorithm", FT_UINT8, BASE_HEX, VALS(public_key_algorithms), 0x0, NULL, HFILL }
		},
		{ &hf_pgp_mpi_len,
			{ "MPI length (bits)", "pgp.mpi.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_mpi_value,
			{ "MPI value", "pgp.mpi.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_string_to_key,
			{ "String to key", "pgp.secret_key.string_to_key", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_sym_algo,
			{ "Symmetric Algorhithm", "pgp.sym.algorithm", FT_UINT8, BASE_HEX, VALS(sym_algos), 0x0, NULL, HFILL }
		},
		{ &hf_pgp_s2k_octet_zero,
			{ "Octet 0", "pgp.s2k.octet_zero", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_hash_algo,
			{ "Hash Algorhithm", "pgp.s2k.hash_algorithm", FT_UINT8, BASE_HEX, VALS(hash_algos), 0x0, NULL, HFILL }
		},
		{ &hf_pgp_salt,
			{ "Salt", "pgp.salt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_count,
			{ "Count", "pgp.s2k.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_pgp_iv,
			{ "IV", "pgp.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint* ett[] = {
		&ett_pgp,
		&ett_pgp_ptag,
		&ett_pgp_mpi,
		&ett_pgp_s2k
	};

	static ei_register_info ei[] = {
		{ &ei_pgp_unsupported, { "pgp.unsupported", PI_UNDECODED, PI_WARN, "Unsupported PGP packet", EXPFILL }}
	};

	proto_pgp = proto_register_protocol("OpenPGP Message Format", "PGP", "pgp");

	expert_pgp = expert_register_protocol(proto_pgp);
	expert_register_field_array(expert_pgp, ei, array_length(ei));

	proto_register_field_array(proto_pgp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_pgp(void)
{
	dissector_handle_t pgp_file_handle = create_dissector_handle(dissect_pgp, proto_pgp);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_PGP, pgp_file_handle);
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
