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

#include <stdlib.h>
#include <string.h>

#include "bootimgfs.h"
#include "config.h"

#ifdef HAVE_SHA1
#include <openssl/sha.h>

void calc_bootimg_checksum(void *sha1_id,
			   void *kernel_data, unsigned kernel_size,
			   void *ramdisk_data, unsigned ramdisk_size,
			   void *second_data, unsigned second_size)
{
	SHA_CTX ctx;

	memset(sha1_id, 0, member_size(boot_img_hdr, id));

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, kernel_data, kernel_size);
	SHA1_Update(&ctx, &kernel_size, sizeof(unsigned));
	SHA1_Update(&ctx, ramdisk_data, ramdisk_size);
	SHA1_Update(&ctx, &ramdisk_size, sizeof(unsigned));
	SHA1_Update(&ctx, second_data, second_size);
	SHA1_Update(&ctx, &second_size, sizeof(unsigned));
	SHA1_Final(sha1_id, &ctx);
}
#endif

int bootimg_open(struct bootimgfile *bif, char *path, int probe)
{
	struct boot_img_hdr *hdr = &bif->hdr;
	void *kernel_data = NULL;
	void *ramdisk_data = NULL;
	void *second_data = NULL;
	unsigned hdr_offset;
	unsigned id[8];
	int res;

	bif->pFile = fopen(path, "r+");
	if (bif->pFile == NULL) {
		fprintf(stderr, "failed to open %s!\n", path);
		return -1;
	}

	for (hdr_offset = 0; hdr_offset <= 512; hdr_offset++) {
		fseek(bif->pFile, hdr_offset, SEEK_SET);
		res = fread(hdr->magic, 1, BOOT_MAGIC_SIZE, bif->pFile);

		if (res != BOOT_MAGIC_SIZE)
			fprintf(stderr, "bootimg read failed at: %#08x\n",
				hdr_offset);

		if (memcmp(hdr->magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0)
		    break;
	}

	if (hdr_offset > 512) {
		fprintf(stderr, "BOOT_MAGIC header not found!\n");
		goto error;
	}

	if (probe)
		printf("header found at offset: 0x%08x\n", hdr_offset);

	fseek(bif->pFile, hdr_offset, SEEK_SET);
	res = fread(hdr, 1, sizeof(*hdr), bif->pFile);

	if (res != sizeof(*hdr)) {
		fprintf(stderr, "failed to read bootimg header!\n");
		goto error;
	}

	if (probe) {
		printf("kernel base: %#08x\n", hdr->kernel_addr - 0x00008000);
		printf("kernel size: %d\n", hdr->kernel_size);
		printf("kernel tags base: %#08x\n", hdr->tags_addr);
		printf("cmdline: %s\n", hdr->cmdline);
		printf("ramdisk base: %#08x\n", hdr->ramdisk_addr);
		printf("ramdisk size: %d\n", hdr->ramdisk_size);
		printf("second base: %#08x\n", hdr->second_addr);
		printf("second size: %d\n", hdr->second_size);
		printf("page size: %d\n", hdr->page_size);
		printf("product name: %s\n", hdr->name);
		printf("id: %08x%08x%08x%08x%08x%08x%08x%08x\n",
		       hdr->id[7], hdr->id[6], hdr->id[5], hdr->id[4],
		       hdr->id[3], hdr->id[2], hdr->id[1], hdr->id[0]);
	}

	if (hdr->kernel_size) {
		kernel_data = malloc(hdr->kernel_size);
		off_t offset;

		if (kernel_data == NULL) {
			fprintf(stderr, "failed to alloc kernel_data!\n");
			goto error;
		}

		offset = ALIGN(sizeof(*hdr), hdr->page_size);
		offset -= sizeof(*hdr);

		fseek(bif->pFile, offset, SEEK_CUR);
		res = fread(kernel_data, 1, hdr->kernel_size, bif->pFile);

		if (res != hdr->kernel_size) {
			fprintf(stderr, "failed to read kernel_data!\n");
			goto error;
		}
	}

	if (hdr->ramdisk_size) {
		ramdisk_data = malloc(hdr->ramdisk_size);
		off_t offset;

		if (ramdisk_data == NULL) {
			fprintf(stderr, "failed to alloc ramdisk_data!\n");
			goto error;
		}

		offset = ALIGN(hdr->kernel_size, hdr->page_size);
		offset -= hdr->kernel_size;

		fseek(bif->pFile, offset, SEEK_CUR);
		res = fread(ramdisk_data, 1, hdr->ramdisk_size, bif->pFile);

		if (res != hdr->ramdisk_size) {
			fprintf(stderr, "failed to read ramdisk_data!\n");
			goto error;
		}
	}

	if (hdr->second_size) {
		second_data = malloc(hdr->second_size);
		off_t offset;

		if (second_data == NULL) {
			fprintf(stderr, "failed to alloc second_data!\n");
			goto error;
		}

		offset = ALIGN(hdr->ramdisk_size, hdr->page_size);
		offset -= hdr->ramdisk_size;

		fseek(bif->pFile, offset, SEEK_CUR);
		res = fread(second_data, 1, hdr->second_size, bif->pFile);

		if (res != hdr->second_size) {
			fprintf(stderr, "failed to read second_data!\n");
			goto error;
		}
	}

#ifdef HAVE_SHA1
	calc_bootimg_checksum(id, kernel_data, hdr->kernel_size,
			      ramdisk_data, hdr->ramdisk_size,
			      second_data, hdr->second_size);

	if (memcmp(hdr->id, id, sizeof(hdr->id)) != 0)
		fprintf(stderr, "WARN: checksum possibly is invalid!\n");
#endif

#if 0
	fprintf(stderr, "sha1 id: %08x%08x%08x%08x%08x%08x%08x%08x\n",
		id[7], id[6], id[5], id[4], id[3], id[2], id[1], id[0]);
#endif

	fseek(bif->pFile, 0, SEEK_END);

	bif->header_offset = hdr_offset;
	bif->bootimg_max_size = ftell(bif->pFile);
	bif->dirty = 0;

	if (bif->bootimg_max_size < 0) {
		fprintf(stderr, "failed to get bootimg size!\n");
		goto error;
	}

	free(kernel_data);
	free(ramdisk_data);
	free(second_data);

	if (probe)
		fclose(bif->pFile);

	return 0;

error:
	free(kernel_data);
	free(ramdisk_data);
	free(second_data);

	fclose(bif->pFile);

	return -1;
}
