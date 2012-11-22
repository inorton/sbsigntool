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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <ccan/endian/endian.h>
#include <ccan/talloc/talloc.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/build_assert/build_assert.h>
#include <openssl/sha.h>

#include "fileio.h"
#include "image.h"

#define IMAGE_ALIGN		8

#define DATA_DIR_CERT_TABLE	4

#define CERT_TABLE_TYPE_PKCS	0x0002	/* PKCS signedData */
#define CERT_TABLE_REVISION	0x0200	/* revision 2 */

/**
 * The PE/COFF headers export struct fields as arrays of chars. So, define
 * a couple of accessor functions that allow fields to be deferenced as their
 * native types, to allow strict aliasing. This also allows for endian-
 * neutral behaviour.
 */
static uint32_t __pehdr_u32(char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return (ufield[3] << 24) +
		(ufield[2] << 16) +
		(ufield[1] << 8) +
		ufield[0];
}

static uint16_t __pehdr_u16(char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return (ufield[1] << 8) +
		ufield[0];
}

/* wrappers to ensure type correctness */
#define pehdr_u32(f) __pehdr_u32(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 4))
#define pehdr_u16(f) __pehdr_u16(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 2))

/* accessors for interesting parts of the image */
static struct external_PEI_DOS_hdr *image_doshdr(struct image *image)
{
	return image->buf;
}

static struct external_PEI_IMAGE_hdr *image_pehdr(struct image *image)
{
	return image->buf + image->pehdr_offset;
}

static int image_opthdr_offset(struct image *image)
{
	return image->pehdr_offset + sizeof(struct external_PEI_IMAGE_hdr);
}

static int image_data_dir_cert_table_offset(struct image *image)
{
	return image->data_dir_offset +
		DATA_DIR_CERT_TABLE * sizeof(struct data_dir_entry);

}

static struct data_dir_entry *image_data_dir_cert_table(
		struct image *image)
{
	return image->buf + image_data_dir_cert_table_offset(image);
}

static int image_scnhdr_offset(struct image *image)
{
	return image_opthdr_offset(image) + image->opthdr_size;
}

static struct external_scnhdr *image_scnhdr(struct image *image)
{
	return image->buf + image_scnhdr_offset(image);
}

static unsigned int image_data_size(struct image *image)
{
	struct data_dir_entry *entry = image_data_dir_cert_table(image);
	return image->size - entry->size;
}

static struct cert_table_header *image_cert_table(struct image *image)
{
	struct cert_table_header *cert_table;
	struct data_dir_entry *cert_table_dir =
		image_data_dir_cert_table(image);

	if (cert_table_dir->size == 0)
		return NULL;

	if (cert_table_dir->addr + cert_table_dir->size > image->size) {
		fprintf(stderr, "error: invalid signature table reference "
				"in data directory\n");
		return NULL;
	}

	cert_table = image->buf + cert_table_dir->addr;
	if (cert_table->size > cert_table_dir->size) {
		fprintf(stderr, "error: invalid certificate table header\n");
		return NULL;
	}

	return cert_table;
}

int image_signature(struct image *image, void **sig, size_t *size)
{
	struct cert_table_header *cert_table = image_cert_table(image);

	if (!cert_table)
		return -1;

	if (sig)
		*sig = cert_table + 1;
	if (size)
		*size = cert_table->size;

	return 0;
}

/* Machine-specific PE/COFF parse functions. These parse the relevant a.out
 * header for the machine type, and set the following members of struct image:
 *   - aouthdr_size
 *   - file_alignment
 *   - header_size
 *   - data_dir
 *   - checksum
 *
 *  These functions require image->pehdr_offset to be set by the caller.
 */
static int image_pecoff_parse_32(struct image *image)
{
	unsigned int opthdr_offset = image_opthdr_offset(image);
	PEAOUTHDR *opt_32 = image->buf + opthdr_offset;

	if (opt_32->standard.magic[0] != 0x0b ||
			opt_32->standard.magic[1] != 0x01) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*opt_32) -
				sizeof(opt_32->DataDirectory);

	image->file_alignment =	pehdr_u32(opt_32->FileAlignment);
	image->header_size = pehdr_u32(opt_32->SizeOfHeaders);

	image->checksum_offset = opthdr_offset + offsetof(PEAOUTHDR, CheckSum);
	image->data_dir_offset = opthdr_offset +
					offsetof(PEAOUTHDR, DataDirectory);
	return 0;
}

static int image_pecoff_parse_64(struct image *image)
{
	unsigned int opthdr_offset = image_opthdr_offset(image);
	PEPAOUTHDR *opt_64 = image->buf + opthdr_offset;

	if (opt_64->standard.magic[0] != 0x0b ||
			opt_64->standard.magic[1] != 0x02) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*opt_64) -
				sizeof(opt_64->DataDirectory);

	image->file_alignment =	pehdr_u32(opt_64->FileAlignment);
	image->header_size = pehdr_u32(opt_64->SizeOfHeaders);

	image->checksum_offset = opthdr_offset + offsetof(PEPAOUTHDR, CheckSum);
	image->data_dir_offset = opthdr_offset +
					offsetof(PEPAOUTHDR, DataDirectory);
	return 0;
}

static uint16_t csum_update_fold(uint16_t csum, uint16_t x)
{
	uint32_t new = csum + x;
	new = (new >> 16) + (new & 0xffff);
	return new;
}

static uint16_t csum_bytes(uint16_t checksum, void *buf, size_t len)
{
	unsigned int i;
	uint16_t *p;

	for (i = 0; i < len; i += sizeof(*p)) {
		p = buf + i;
		checksum = csum_update_fold(checksum, le32_to_cpu(*p));
	}

	return checksum;
}

static void image_pecoff_update_checksum(struct image *image)
{
	uint32_t checksum;

	checksum = csum_bytes(0, image->buf, image->checksum_offset);
	checksum = csum_bytes(checksum,
			image->buf + image->checksum_offset + sizeof(checksum),
			image->size - image->checksum_offset
				- sizeof(checksum));

	checksum += image->size;

	*(uint32_t *)(image->buf + image->checksum_offset)
			= cpu_to_le32(checksum);
}

static int image_iterate_sections(struct image *image,
		int (*it)(struct image *,
			struct external_scnhdr *, int, void *),
		void *arg)
{
	struct external_scnhdr *scnhdr;
	unsigned int i;
	int rc;

	for (i = 0; i < image->sections; i++) {
		scnhdr = &image_scnhdr(image)[i];
		rc = it(image, scnhdr, i, arg);
		if (rc)
			break;
	}

	return rc;
}

static int image_pecoff_parse(struct image *image)
{
	struct external_PEI_IMAGE_hdr *pehdr;
	struct external_PEI_DOS_hdr *doshdr;
	char nt_sig[] = {'P', 'E', 0, 0};
	size_t size = image->size;
	int rc, cert_table_offset;
	uint16_t magic;
	uint32_t addr;

	/* sanity checks */
	if (size < sizeof(*doshdr)) {
		fprintf(stderr, "file is too small for DOS header\n");
		return -1;
	}

	doshdr = image_doshdr(image);

	if (doshdr->e_magic[0] != 0x4d || doshdr->e_magic[1] != 0x5a) {
		fprintf(stderr, "Invalid DOS header magic\n");
		return -1;
	}

	addr = pehdr_u32(doshdr->e_lfanew);
	if (addr >= image->size) {
		fprintf(stderr, "pehdr is beyond end of file [0x%08x]\n",
				addr);
		return -1;
	}

	if (addr + sizeof(*pehdr) > image->size) {
		fprintf(stderr, "File not large enough to contain pehdr\n");
		return -1;
	}

	image->pehdr_offset = addr;
	pehdr = image_pehdr(image);

	if (memcmp(pehdr->nt_signature, nt_sig, sizeof(nt_sig))) {
		fprintf(stderr, "Invalid PE header signature\n");
		return -1;
	}

	magic = pehdr_u16(pehdr->f_magic);

	if (magic == IMAGE_FILE_MACHINE_AMD64) {
		rc = image_pecoff_parse_64(image);

	} else if (magic == IMAGE_FILE_MACHINE_I386) {
		rc = image_pecoff_parse_32(image);

	} else {
		fprintf(stderr, "Invalid PE header magic\n");
		return -1;
	}

	if (rc) {
		fprintf(stderr, "Error parsing a.out header\n");
		return -1;
	}

	/* the optional header has a variable size, as the data directory
	 * has a variable number of entries. Ensure that the we have enough
	 * space to include the security directory entry */
	image->opthdr_size = pehdr_u16(pehdr->f_opthdr);
	cert_table_offset = sizeof(struct data_dir_entry) *
				(DATA_DIR_CERT_TABLE + 1);

	if (image->opthdr_size < image->opthdr_min_size + cert_table_offset) {
		fprintf(stderr, "PE opt header too small (%d bytes) to contain "
				"a suitable data directory (need %d bytes)\n",
				image->opthdr_size,
				image->opthdr_min_size + cert_table_offset);
		return -1;
	}

	if (image->size < sizeof(*doshdr) + sizeof(*pehdr) +
			image->opthdr_size) {
		fprintf(stderr, "file is too small for a.out header\n");
		return -1;
	}

	image->sections = pehdr_u16(pehdr->f_nscns);

	/* ensure we have space for the full section table */
	if (image->size < image_scnhdr_offset(image) +
			image->sections * sizeof(struct external_scnhdr)) {
		fprintf(stderr, "file is too small for section table\n");
		return -1;
	}

	return 0;
}

static unsigned int align_up(int size, int align)
{
	return (size + align - 1) & ~(align - 1);
}

static unsigned int pad_len(int size, int align)
{
	return align_up(size, align) - size;
}

static int cmp_regions(const void *p1, const void *p2)
{
	const struct region *r1 = p1, *r2 = p2;

	if (r1->offset < r2->offset)
		return -1;
	if (r1->offset > r2->offset)
		return 1;
	return 0;
}

static void set_region_from_range(struct region *region,
		unsigned int start_offset, unsigned int end_offset)
{
	region->offset = start_offset;
	region->size = end_offset - start_offset;
}

struct add_ctx {
	int *gap_warn;
	size_t *bytes;
};

static int add_section_region(struct image *image,
		struct external_scnhdr *scnhdr, int i, void *arg)
{
	uint32_t file_offset, file_size;
	struct add_ctx *add_ctx = arg;
	struct region *regions;

	file_offset = pehdr_u32(scnhdr->s_scnptr);
	file_size = pehdr_u32(scnhdr->s_size);

	if (!file_size)
		return 0;

	image->n_checksum_regions++;
	image->checksum_regions = talloc_realloc(image,
			image->checksum_regions,
			struct region,
			image->n_checksum_regions);
	regions = image->checksum_regions;

	regions[i+3].offset = file_offset;
	regions[i+3].size = align_up(file_size, image->file_alignment);
	regions[i+3].name = talloc_strndup(image->checksum_regions,
				scnhdr->s_name, 8);
	*add_ctx->bytes += regions[i+3].size;

	if (regions[i+3].offset + regions[i+3].size > image->size) {
		fprintf(stderr, "warning: file-aligned section %s "
				"extends beyond end of file\n",
				regions[i+3].name);
	}

	if (regions[i+2].offset + regions[i+2].size != regions[i+3].offset) {
		fprintf(stderr, "warning: gap in section table:\n");
		fprintf(stderr, "    %-8s: 0x%08x - 0x%08x,\n",
				regions[i+2].name,
				regions[i+2].offset,
				regions[i+2].offset +
					regions[i+2].size);
		fprintf(stderr, "    %-8s: 0x%08x - 0x%08x,\n",
				regions[i+3].name,
				regions[i+3].offset,
				regions[i+3].offset +
					regions[i+3].size);


		*add_ctx->gap_warn = 1;
	}
	return 0;
}

static int image_find_regions(struct image *image,
		unsigned int *data_size)
{
	struct data_dir_entry *data_dir_entry;
	size_t bytes, sig_bytes;
	struct region *regions;
	struct add_ctx add_ctx;
	int gap_warn;

	gap_warn = 0;
	bytes = 0;

	if (image->checksum_regions)
		talloc_free(image->checksum_regions);

	image->n_checksum_regions = 3;
	image->checksum_regions = talloc_zero_array(image,
					struct region,
					image->n_checksum_regions);

	/* first region: beginning to checksum field */
	regions = image->checksum_regions;
	set_region_from_range(&regions[0], 0, image->checksum_offset);
	regions[0].name = "begin->cksum";
	bytes += regions[0].size;

	bytes += sizeof(uint32_t);

	/* second region: end of checksum to certificate table entry */
	set_region_from_range(&regions[1],
			image->checksum_offset + sizeof(uint32_t),
			image_data_dir_cert_table_offset(image));
	regions[1].name = "cksum->datadir[CERT]";
	bytes += regions[1].size;

	bytes += sizeof(struct data_dir_entry);

	/* third region: end of checksum to end of headers */
	set_region_from_range(&regions[2],
			image_data_dir_cert_table_offset(image)
				+ sizeof(struct data_dir_entry),
			image->header_size);
	regions[2].name = "datadir[CERT]->headers";
	bytes += regions[2].size;

	/* add COFF sections */
	add_ctx.bytes = &bytes;
	add_ctx.gap_warn = &gap_warn;
	image_iterate_sections(image, add_section_region, &add_ctx);

	if (gap_warn)
		fprintf(stderr, "gaps in the section table may result in "
				"different checksums\n");

	qsort(image->checksum_regions, image->n_checksum_regions,
			sizeof(struct region), cmp_regions);

	data_dir_entry = image_data_dir_cert_table(image);
	sig_bytes = data_dir_entry->addr ? data_dir_entry->size : 0;

	if (bytes + sig_bytes < image->size) {
		int n = image->n_checksum_regions++;
		struct region *r;

		image->checksum_regions = talloc_realloc(image,
				image->checksum_regions,
				struct region,
				image->n_checksum_regions);
		r = &image->checksum_regions[n];
		r->name = "endjunk";
		r->offset = bytes;
		r->size = image->size - bytes - sig_bytes;

		fprintf(stderr, "warning: data remaining[%zd vs %zd]: gaps "
				"between PE/COFF sections?\n",
				bytes + sig_bytes, image->size);

		bytes += r->size;
	} else if (bytes + sig_bytes > image->size) {
		fprintf(stderr, "warning: checksum areas (%zd,%zd) are greater than "
				"image size (%zd). Invalid section table?\n",
				bytes, sig_bytes, image->size);
	}

	/* record the size of non-signature data */
	if (data_size)
		*data_size = bytes;

	return 0;
}

static void image_find_signature(struct image *image)
{
	size_t size;
	void *sig;
	int rc;

	rc = image_signature(image, &sig, &size);
	if (rc)
		return;

	image->sigsize = size;
	image->sigbuf = talloc_memdup(image, sig, size);
}

struct image *image_load(const char *filename)
{
	unsigned int data_size;
	struct image *image;
	uint8_t *buf;
	int rc;

	image = talloc_zero(NULL, struct image);
	if (!image) {
		perror("talloc(image)");
		return NULL;
	}

	rc = fileio_read_file(image, filename, &buf, &image->size);
	if (rc)
		goto err;

	image->buf = buf;

	rc = image_pecoff_parse(image);
	if (rc)
		goto err;

	rc = image_find_regions(image, &data_size);
	if (rc)
		goto err;

	/* Some images may have incorrectly aligned sections, which get rounded
	 * up to a size that is larger that the image itself (and the buffer
	 * that we've allocated). We would have generated a warning about this,
	 * but we can improve our chances that the verification hash will
	 * succeed by padding the image out to the aligned size, and including
	 * the pad in the signed data.
	 */
	if (data_size > image->size) {
		image->buf = talloc_realloc(image, image->buf, uint8_t,
				data_size);
		memset(image->buf + image->size, 0, data_size - image->size);
		image->size = data_size;
	}

	image_find_signature(image);

	return image;
err:
	talloc_free(image);
	return NULL;
}

void image_pad_for_signing(struct image *image)
{
	size_t padded_size;

	padded_size = align_up(image->size, IMAGE_ALIGN);
	if (padded_size == image->size)
		return;

	image->buf = talloc_realloc(image, image->buf, uint8_t, padded_size);
	memset(image->buf + image->size, 0, padded_size - image->size);
	image->size = padded_size;

	/* we'll need to include the image in the checksum regions, so
	 * recalculate */
	image_find_regions(image, NULL);

	return;
}

int image_hash_sha256(struct image *image, uint8_t digest[])
{
	struct region *region;
	SHA256_CTX ctx;
	int rc, i, n;

	rc = SHA256_Init(&ctx);
	if (!rc)
		return -1;

	n = 0;

	for (i = 0; i < image->n_checksum_regions; i++) {
		region = &image->checksum_regions[i];
		n += region->size;
		rc = SHA256_Update(&ctx, image->buf + region->offset,
					region->size);
		if (!rc)
			return -1;
	}

	rc = SHA256_Final(digest, &ctx);

	return !rc;
}

void image_print_regions(struct image *image)
{
	struct region *region;
	int i;

	for (i = 0; i < image->n_checksum_regions; i++) {
		region = &image->checksum_regions[i];

		printf("sum region  0x%04x -> 0x%04x [0x%04x bytes] %s\n",
				region->offset,
				region->offset + region->size - 1,
				region->size,
				region->name);
	}
}

int image_add_signature(struct image *image, void *sig, unsigned int size)
{
	unsigned int data_size, cert_table_size, pad, len;
	struct data_dir_entry *data_dir_cert_table;
	struct cert_table_header *cert_table;

	/* we lay out the signed image as follows:
	 *
	 * +-------------------+
	 * | image data        |
	 * +-------------------+
	 * | pad to 8 bytes    |
	 * +-------------------+
	 * | cert table header |
	 * +-------------------+
	 * | signature         |
	 * +--+----------------+
	 * |  | pad to 8 bytes |
	 * +--+----------------+
	 *
	 * The first chunk of padding should always be present, as the image
	 * will have been processed with image_pad_for_signing().
	 *
	 * The last chunk of padding is included in the size of the
	 * certificate table as specificed by the PE/COFF data directory.
	 * However, the header on the certificate table does not include
	 * this padding.
	 */

	data_size = image_data_size(image);
	assert(align_up(data_size, IMAGE_ALIGN) == data_size);

	cert_table_size = sizeof(struct cert_table_header) + size;
	pad = pad_len(cert_table_size, IMAGE_ALIGN);

	len = data_size + cert_table_size + pad;

	if (image->size != len) {
		image->buf = talloc_realloc(image, image->buf, uint8_t, len);
		image->size = len;
	}

	/* construct the data directory */
	data_dir_cert_table = image_data_dir_cert_table(image);
	data_dir_cert_table->addr = data_size;
	data_dir_cert_table->size = cert_table_size + pad;

	cert_table = image_cert_table(image);
	/* we just put it there! */
	assert(cert_table);

	cert_table->size = cert_table_size;
	cert_table->revision = CERT_TABLE_REVISION;
	cert_table->type = CERT_TABLE_TYPE_PKCS;

	memcpy((void *)(cert_table + 1), sig, size);

	image_pecoff_update_checksum(image);

	return 0;
}

void image_remove_signature(struct image *image)
{
	struct data_dir_entry *data_dir_entry;
	unsigned int new_size;

	data_dir_entry = image_data_dir_cert_table(image);

	new_size = image->size - data_dir_entry->size;

	data_dir_entry->addr = 0;
	data_dir_entry->size = 0;

	image->size = new_size;
}

int image_write(struct image *image, const char *filename)
{
	return fileio_write_file(filename, image->buf, image->size);
}

int image_write_detached(struct image *image, const char *filename)
{
	return fileio_write_file(filename, image->sigbuf, image->sigsize);
}
