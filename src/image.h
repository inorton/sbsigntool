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
#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

#include <bfd.h>
#define DO_NOT_DEFINE_LINENO

#include "coff/external.h"
#include "coff/pe.h"

struct region {
	unsigned int	offset;
	unsigned int	size;
	char		*name;
};

struct image {
	void		*buf;
	size_t		size;

	/* Offsets to interesting parts of the image, calculated during
	 * image parse */
	unsigned int	pehdr_offset,
			checksum_offset,
			data_dir_offset,
			cert_table_offset;

	/* size of a minimal opthdr for this machine, without data
	 * directories */
	unsigned int	opthdr_min_size;
	/* size of the opthdr as specified by the image */
	unsigned int	opthdr_size;

	unsigned int	sections;
	unsigned int	cert_table_size;
#if 0
	uint32_t	*checksum;
	struct external_PEI_DOS_hdr *doshdr;
	struct external_PEI_IMAGE_hdr *pehdr;
	struct data_dir_entry *data_dir;
	struct data_dir_entry *data_dir_sigtable;
	struct external_scnhdr *scnhdr;
#endif

	/* We cache a few values from the aout header, so we don't have to
	 * keep checking whether to use the 32- or 64-bit version */
	uint32_t	file_alignment;
	uint32_t	header_size;

	/* Regions that are included in the image hash: populated
	 * during image parsing, then used during the hash process.
	 */
	struct region	*checksum_regions;
	int		n_checksum_regions;

	/* Generated signature */
	void		*sigbuf;
	size_t		sigsize;

};

union	{
	PEPAOUTHDR	*opt_64;
	PEAOUTHDR	*opt_32;
	void		*addr;
} opthdr;

struct data_dir_entry {
	uint32_t	addr;
	uint32_t	size;
} __attribute__((packed));

struct cert_table_header {
	uint32_t size;
	uint16_t revision;
	uint16_t type;
} __attribute__((packed));

struct image *image_load(const char *filename);
void image_pad_for_signing(struct image *image);

int image_hash_sha256(struct image *image, uint8_t digest[]);
int image_add_signature(struct image *, void *sig, unsigned int size);
void image_remove_signature(struct image *image);
int image_signature(struct image *image, void **buf, size_t *size);
int image_write(struct image *image, const char *filename);
int image_write_detached(struct image *image, const char *filename);
void image_print_regions(struct image *image);

#endif /* IMAGE_H */

