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

#include <stdint.h>

#include "sigdb.h"

/**
 * Iterates an buffer of EFI_SIGNATURE_LISTs (at db_data, of length len),
 * and calls fn on each EFI_SIGNATURE_DATA item found.
 *
 * fn is passed the EFI_SIGNATURE_DATA pointer, and the length of the
 * signature data (including GUID header), the type of the signature list,
 * and a context pointer.
 */
int sigdb_iterate(void *db_data, size_t len, sigdata_fn fn, void *arg)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	unsigned int i, j;
	int rc = 0;

	if (len == 0)
		return 0;

	if (len < sizeof(*siglist))
		return -1;

	for (i = 0, siglist = db_data + i;
			i + sizeof(*siglist) <= len &&
			i + siglist->SignatureListSize > i &&
			i + siglist->SignatureListSize <= len && !rc;
			i += siglist->SignatureListSize,
			siglist = db_data + i) {

		/* ensure that the header & sig sizes are sensible */
		if (siglist->SignatureHeaderSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize > siglist->SignatureListSize)
			continue;

		if (siglist->SignatureSize < sizeof(*sigdata))
			continue;

		/* iterate through the (constant-sized) signature data blocks */
		for (j = sizeof(*siglist) + siglist->SignatureHeaderSize;
				j < siglist->SignatureListSize && !rc;
				j += siglist->SignatureSize)
		{
			sigdata = (void *)(siglist) + j;

			rc = fn(sigdata, siglist->SignatureSize,
					&siglist->SignatureType, arg);

		}

	}

	return rc;
}
