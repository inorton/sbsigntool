/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <getopt.h>

#include <openssl/x509.h>

#include <ccan/array_size/array_size.h>
#include <ccan/talloc/talloc.h>

#include "guid.h"
#include "fileio.h"
#include "sigdb.h"
#include "config.h"

static const char *toolname = "sbsigdb";

static struct option options[] = {
	{ "efivarfs-header", no_argument, NULL, 'e' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

struct cert_type;
struct sigdb_context;

typedef void (*certdata_print_fn)(struct sigdb_context *ctx,
		struct cert_type *type, int idx, void *data, size_t size);

struct cert_type {
	const char		*name;
	const EFI_GUID		guid;
	certdata_print_fn	print_fn;
};

struct sigdb_context {
	const char	*filename;
	const char	*basename;

	int		idx;

	uint8_t		*buf;
	size_t		size;
};


static void print_hex_data(struct sigdb_context *ctx,
		struct cert_type *type __attribute__((unused)),
		int idx __attribute__((unused)),
		void *data, size_t size)
{
	int width = strlen("00");
	unsigned int i;
	char *buf;

	buf = talloc_array(ctx, char, size * width);
	for (i = 0; i < size; i++)
		snprintf(buf + (width * i), width + 1, "%02x",
				((uint8_t *)data)[i]);

	printf("  hex data:\n");
	printf("    %s\n", buf);
}

static void save_data_external(struct sigdb_context *ctx,
		struct cert_type *type,
		int idx, void *data, size_t size)
{
	char * filename;
	int rc;

	filename = talloc_asprintf(ctx, "%s.%d.%s",
			ctx->basename, idx, type ? type->name : "bin");

	rc = fileio_write_file(filename, data, size);

	if (rc)
		fprintf(stderr, "error saving to file %s\n", filename);
	else
		printf("  [ data saved to file %s ]\n", filename);
}

static void print_save_x509(struct sigdb_context *ctx,
		struct cert_type *type,
		int idx, void *data, size_t size)
{
	const uint8_t *tmp;
	X509 *x509;

	tmp = data;

	x509 = d2i_X509(NULL, &tmp, size);
	if (!x509) {
		fprintf(stderr, "can't parse x509 data\n");
		return;
	}

	printf("  x509 subject:\n");
	X509_NAME_print_ex_fp(stdout, x509->cert_info->subject, 4,
			XN_FLAG_MULTILINE);
	printf("\n");
	printf("  x509 issuer:\n");
	X509_NAME_print_ex_fp(stdout, x509->cert_info->issuer, 4,
			XN_FLAG_MULTILINE);
	printf("\n");

	save_data_external(ctx, type, idx, data, size);
}

struct cert_type cert_types[] = {
	{ "x509",   EFI_CERT_X509_GUID,   print_save_x509 },
	{ "sha256", EFI_CERT_SHA256_GUID, print_hex_data },
};

void usage(void)
{
	printf("Usage: %s [options] <sigdb-file>\n"
		"Prints the contents of an EFI signature database"
		"Options:\n"
		"\t--efivarfs-header  Skip 4-byte efivarfs header\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

static struct cert_type *lookup_type(const EFI_GUID *guid)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++)
		if (!memcmp(&cert_types[i].guid, guid, sizeof(*guid)))
			return &cert_types[i];

	return NULL;
}

static const char *type_to_str(struct cert_type *type, const EFI_GUID *guid)
{
	static char guid_str[GUID_STRLEN+1], str[100];
	size_t len;

	len = sizeof(str) - 1;

	if (type) {
		snprintf(str, len, "%s", type->name);
	} else {
		guid_to_str(guid, str);
		snprintf(str, len, "unknown (GUID: %s)", guid_str);
	}

	return str;
}

static int print_sigdb_entry(EFI_SIGNATURE_DATA *data, int size,
		const EFI_GUID *type_guid, void *arg)
{
	struct sigdb_context *ctx = arg;
	char guid_str[GUID_STRLEN];
	struct cert_type *type;
	const char *type_str;
	int data_size;

	type = lookup_type(type_guid);

	type_str = type_to_str(type, type_guid);

	ctx->idx++;
	data_size = size - sizeof(*data);

	printf("Entry %d:\n", ctx->idx);
	printf("  type:  %s\n", type_str);
	printf("  size:  0x%x\n", data_size);

	guid_to_str(&data->SignatureOwner, guid_str);
	printf("  owner: %s\n", guid_str);

	if (type && type->print_fn) {
		type->print_fn(ctx, type, ctx->idx, data->SignatureData,
				data_size);
	}

	printf("\n");

	return 0;
}


int main(int argc, char **argv)
{
	struct sigdb_context *ctx;
	bool skip_efivarfs_header;
	char *tmp;
	int c, rc;

	skip_efivarfs_header = false;

	ctx = talloc_zero(NULL, struct sigdb_context);

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "eVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'e':
			skip_efivarfs_header = true;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (argc != optind + 1) {
		usage();
		return EXIT_FAILURE;
	}

	ctx->idx = 0;
	ctx->filename = argv[optind];
	tmp = talloc_strdup(ctx, ctx->filename);
	ctx->basename = talloc_strdup(ctx, basename(tmp));
	talloc_free(tmp);

	rc = fileio_read_file(ctx, ctx->filename, &ctx->buf, &ctx->size);
	if (rc) {
		rc = EXIT_FAILURE;
		goto out;
	}

	if (skip_efivarfs_header)
		ctx->buf += sizeof(uint32_t);

	sigdb_iterate(ctx->buf, ctx->size, print_sigdb_entry, ctx);

	rc = EXIT_SUCCESS;
out:
	talloc_free(ctx);
	return rc;
}
