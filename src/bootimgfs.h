/*
 * Copyright (C) 2014 Dmitry Osipenko
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include "bootimg.h"

#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)

#define member_size(type, member) sizeof(((type *)0)->member)

struct bootimgfile {
	struct boot_img_hdr hdr;
	FILE *pFile;
	int dirty : 1;
	long int bootimg_max_size;
	unsigned header_offset;
};

int bootimg_open(struct bootimgfile *bif, char *path, int verbose);
void calc_bootimg_checksum(void *sha1_id,
			   void *kernel_data, unsigned kernel_size,
			   void *ramdisk_data, unsigned ramdisk_size,
			   void *second_data, unsigned second_size);
