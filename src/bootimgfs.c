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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "bootimgfs.h"
#include "config.h"

#define INIT_HEADER_FILE(_fid, _hdr_offset, _member_name, _size, _max_size) \
	files[_fid].size = _size;					\
	files[_fid].max_size = _max_size;				\
	files[_fid].offset = _hdr_offset + offsetof(boot_img_hdr, _member_name)

#define INIT_IMG_FILE(_f, _fid, _hdr, _prev_img_offset, _prev_img_sz, _size) \
	files[_fid].size = _size;					\
	files[_fid].offset = _prev_img_offset +				\
				ALIGN(_prev_img_sz, _hdr.page_size);	\
	if (_size) {							\
		files[_fid].data = malloc(_size);			\
		assert(files[_fid].data != NULL);			\
		fseek(_f, files[_fid].offset, SEEK_SET);		\
		assert(_size == fread(files[_fid].data, 1, _size, _f));	\
	}

enum {
	SECOND_STAGE_BASE = 0,
	KERNEL_TAGS_BASE,
	SECOND_STAGE,
	PRODUCT_NAME,
	RAMDISK_BASE,
	KERNEL_BASE,
	PAGE_SIZE,
	RAMDISK,
	CMDLINE,
	KERNEL,
	ID,
	FILES_NB,
};

struct bootimg_file {
	const char *path;
	void *data;
	off_t offset;
	unsigned size;
	size_t max_size;
	const size_t mode;
};

static pthread_mutex_t bootimg_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct bootimg_file files[FILES_NB] = {
	[ID] = { .path = "/id", .mode = 0444 },
	[KERNEL] = { .path = "/zImage", .mode = 0644 },
	[CMDLINE] = { .path = "/cmdline", .mode = 0644 },
	[RAMDISK] = { .path = "/ramdisk.gz", .mode = 0644 },
	[PAGE_SIZE] = { .path = "/page_size", .mode = 0644 },
	[KERNEL_BASE] = { .path = "/kernel_base", .mode = 0644 },
	[RAMDISK_BASE] = { .path = "/ramdisk_base", .mode = 0644 },
	[PRODUCT_NAME] = { .path = "/product_name", .mode = 0644 },
	[SECOND_STAGE] = { .path = "/second_stage", .mode = 0644 },
	[KERNEL_TAGS_BASE] = { .path = "/kernel_tags_base", .mode = 0644 },
	[SECOND_STAGE_BASE] = { .path = "/second_stage_base", .mode = 0644 },
};

static size_t bootimg_read(void *ptr, off_t offset, size_t size,
			   size_t count, FILE *pFile)
{
	size_t ret;

	pthread_mutex_lock(&bootimg_mutex);

	fseek(pFile, offset, SEEK_SET);
	ret = fread(ptr, size, count, pFile);

	pthread_mutex_unlock(&bootimg_mutex);

	return ret;
}

static size_t bootimg_write(const void *ptr, off_t offset, size_t size,
			    size_t count, FILE *pFile)
{
	size_t ret;

	pthread_mutex_lock(&bootimg_mutex);

	fseek(pFile, offset, SEEK_SET);
	ret = fwrite(ptr, size, count, pFile);

	pthread_mutex_unlock(&bootimg_mutex);

	return ret;
}

static int bootimgfs_get_file_id(const char *path)
{
	int fid;

	for (fid = 0; fid < FILES_NB; fid++)
		if (strcmp(path, files[fid].path) == 0)
			return fid;

	return -ENOENT;
}

static int bootimgfs_getattr(const char *path, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(*stbuf));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = FILES_NB + 2;
	} else {
		int fid = bootimgfs_get_file_id(path);
		if (fid < 0)
			return -ENOENT;

		stbuf->st_mode = S_IFREG | files[fid].mode;
		stbuf->st_size = files[fid].size;
		stbuf->st_nlink = 1;
	}

	return 0;
}

static int bootimgfs_readdir(const char *path, void *buf,
			     fuse_fill_dir_t filler, off_t offset,
			     struct fuse_file_info *fi)
{
	int fid;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	for (fid = 0; fid < FILES_NB; fid++)
		filler(buf, files[fid].path + 1, NULL, 0);

	return 0;
}

static int bootimgfs_statfs(const char *path, struct statvfs *st)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;
	unsigned images_size = bif->bootimg_max_size - files[KERNEL].offset;
	unsigned used_size;

	pthread_mutex_lock(&bootimg_mutex);

	used_size = ALIGN(files[KERNEL].size, bif->hdr.page_size);
	used_size += ALIGN(files[RAMDISK].size, bif->hdr.page_size);
	used_size += ALIGN(files[SECOND_STAGE].size, bif->hdr.page_size);

	st->f_frsize = bif->hdr.page_size;
	st->f_blocks = images_size / bif->hdr.page_size;
	st->f_bfree = (images_size - used_size) / bif->hdr.page_size;
	st->f_bavail = st->f_bfree;

	pthread_mutex_unlock(&bootimg_mutex);

	return 0;
}

static int bootimgfs_open(const char *path, struct fuse_file_info *fi)
{
	int fid = bootimgfs_get_file_id(path);

	return fid < 0 ? -ENOENT : 0;
}

static int bootimgfs_read(const char *path, char *buf, size_t size,
			  off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;
	int fid = bootimgfs_get_file_id(path);
	char tmp_buf[65];
	unsigned tmp;
	int ret;

	if (fid < 0)
		return -ENOENT;

	switch (fid) {
	case PAGE_SIZE:
		sprintf(tmp_buf, "%u", bif->hdr.page_size);
		tmp = strlen(tmp_buf);
		memset(tmp_buf + tmp, ' ', files[fid].size - tmp);
		memcpy(buf, tmp_buf + offset, size);
		break;
	case SECOND_STAGE_BASE:
	case KERNEL_TAGS_BASE:
	case RAMDISK_BASE:
	case KERNEL_BASE:
		ret = bootimg_read(&tmp, files[fid].offset,
				   1, sizeof(tmp), bif->pFile);
		if (ret != sizeof(tmp))
			return -EIO;

		if (fid == KERNEL_BASE)
			tmp -= 0x00008000;

		sprintf(tmp_buf, "0x%08x", tmp);
		memcpy(buf, tmp_buf + offset, size);
		break;
	case PRODUCT_NAME:
	case CMDLINE:
		size = bootimg_read(buf, files[fid].offset + offset,
				    1, size, bif->pFile);
		break;
	case KERNEL:
	case RAMDISK:
	case SECOND_STAGE:
		pthread_mutex_lock(&bootimg_mutex);

		if (files[fid].data == NULL) {
			pthread_mutex_unlock(&bootimg_mutex);
			return -EIO;
		}

		memcpy(buf, files[fid].data + offset, size);

		pthread_mutex_unlock(&bootimg_mutex);
		break;
	case ID:
		snprintf(tmp_buf, 65, "%08x%08x%08x%08x%08x%08x%08x%08x",
			 bif->hdr.id[7], bif->hdr.id[6], bif->hdr.id[5],
			 bif->hdr.id[4], bif->hdr.id[3], bif->hdr.id[2],
			 bif->hdr.id[1], bif->hdr.id[0]);
		memcpy(buf, tmp_buf + offset, size);
		break;
	default:
		return -EIO;
	}

	return size;
}

static int bootimgfs_write(const char *path, const char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;
	int fid = bootimgfs_get_file_id(path);
	off_t new_bootimg_size;
	unsigned tmp;
	int ret;

	if (fid < 0)
		return -ENOENT;

	switch (fid) {
	case PAGE_SIZE:
		ret = sscanf(buf, "%u", &tmp);
		if (ret != 1)
			return -EINVAL;

		pthread_mutex_lock(&bootimg_mutex);

		new_bootimg_size = files[KERNEL].offset;
		new_bootimg_size += ALIGN(files[KERNEL].size, tmp);
		new_bootimg_size += ALIGN(files[RAMDISK].size, tmp);
		new_bootimg_size += ALIGN(files[SECOND_STAGE].size, tmp);

		if (new_bootimg_size > bif->bootimg_max_size) {
			pthread_mutex_unlock(&bootimg_mutex);
			return -EINVAL;
		}

		bif->hdr.page_size = tmp;
		bif->dirty = 1;

		pthread_mutex_unlock(&bootimg_mutex);
		break;
	case SECOND_STAGE_BASE:
	case KERNEL_TAGS_BASE:
	case RAMDISK_BASE:
	case KERNEL_BASE:
		ret = sscanf(buf, "%x", &tmp);
		if (ret != 1)
			return -EINVAL;

		if (fid == KERNEL_BASE)
			tmp += 0x00008000;

		ret = bootimg_write(&tmp, files[fid].offset,
				    sizeof(tmp), 1, bif->pFile);
		if (ret != 1)
			return -EIO;
		break;
	case PRODUCT_NAME:
	case CMDLINE:
		if (offset + size > files[fid].max_size)
			return -ENOSPC;

		ret = bootimg_write(buf, files[fid].offset + offset,
				    size, 1, bif->pFile);

		if (offset + size > files[fid].size) {
			tmp = offset + size - (buf[size-1] == 0xA ? 1 : 0);
			bootimg_write("", files[fid].offset + tmp,
				      size, 1, bif->pFile);
			files[fid].size = tmp;
		}
		return ret;
	case KERNEL:
	case RAMDISK:
	case SECOND_STAGE:
		pthread_mutex_lock(&bootimg_mutex);

		if (offset + size > files[fid].size) {
			void *new_alloc;

			tmp = files[fid].size;
			files[fid].size = offset + size;

			new_bootimg_size = files[KERNEL].offset;
			new_bootimg_size += ALIGN(files[KERNEL].size,
							bif->hdr.page_size);
			new_bootimg_size += ALIGN(files[RAMDISK].size,
							bif->hdr.page_size);
			new_bootimg_size += ALIGN(files[SECOND_STAGE].size,
							bif->hdr.page_size);
			if (new_bootimg_size > bif->bootimg_max_size) {
				files[fid].size = tmp;
				pthread_mutex_unlock(&bootimg_mutex);
				return -ENOSPC;
			}

			new_alloc = realloc(files[fid].data, files[fid].size);
			if (new_alloc == NULL) {
				files[fid].size = tmp;
				pthread_mutex_unlock(&bootimg_mutex);
				return -ENOMEM;
			}

			files[fid].data = new_alloc;
		}

		memcpy(files[fid].data + offset, buf, size);
		bif->dirty = 1;

		pthread_mutex_unlock(&bootimg_mutex);
		break;
	default:
		return -EIO;
	}

	return size;
}

static int bootimgfs_truncate(const char* path, off_t size)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;
	int fid = bootimgfs_get_file_id(path);
	void *new_alloc;

	if (fid < 0)
		return -ENOENT;

	pthread_mutex_lock(&bootimg_mutex);

	switch (fid) {
	case KERNEL:
	case RAMDISK:
	case SECOND_STAGE:
		if (size != 0) {
			new_alloc = realloc(files[fid].data, size);
			if (new_alloc == NULL) {
				pthread_mutex_unlock(&bootimg_mutex);
				return -ENOMEM;
			}

			files[fid].data = new_alloc;
		} else {
			free(files[fid].data);
			files[fid].data = NULL;
		}

		bif->dirty = 1;
		break;
	case PRODUCT_NAME:
	case CMDLINE:
		if (size >= files[fid].max_size)
			return -ENOSPC;
	}

	files[fid].size = size;

	pthread_mutex_unlock(&bootimg_mutex);

	return 0;
}

static void bootimgfs_rebuild_img(void)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;
	off_t offset;

	pthread_mutex_lock(&bootimg_mutex);

	if (!bif->dirty) {
		pthread_mutex_unlock(&bootimg_mutex);
		return;
	}

	/* header */
	bif->hdr.kernel_size  = files[KERNEL].size;
	bif->hdr.ramdisk_size = files[RAMDISK].size;
	bif->hdr.second_size  = files[SECOND_STAGE].size;

#ifdef HAVE_SHA1
	calc_bootimg_checksum(bif->hdr.id,
			files[KERNEL].data, files[KERNEL].size,
			files[RAMDISK].data, files[RAMDISK].size,
			files[SECOND_STAGE].data, files[SECOND_STAGE].size);
#else
	memset(bif->hdr.id, 0, member_size(boot_img_hdr, id));
#endif

	fseek(bif->pFile, bif->header_offset, SEEK_SET);
	fwrite(&bif->hdr, sizeof(bif->hdr), 1, bif->pFile);

	/* kernel */
	fseek(bif->pFile, files[KERNEL].offset, SEEK_SET);
	fwrite(files[KERNEL].data, files[KERNEL].size, 1, bif->pFile);

	/* ramdisk */
	offset = files[KERNEL].offset;
	offset += ALIGN(files[KERNEL].size, bif->hdr.page_size);

	files[RAMDISK].offset = offset;
	fseek(bif->pFile, files[RAMDISK].offset, SEEK_SET);
	fwrite(files[RAMDISK].data, files[RAMDISK].size, 1, bif->pFile);

	/* second stage */
	offset = files[RAMDISK].offset;
	offset += ALIGN(files[RAMDISK].size, bif->hdr.page_size);

	files[SECOND_STAGE].offset = offset;
	fseek(bif->pFile, files[SECOND_STAGE].offset, SEEK_SET);
	fwrite(files[SECOND_STAGE].data,
	       files[SECOND_STAGE].size, 1, bif->pFile);

	bif->dirty = 0;

	pthread_mutex_unlock(&bootimg_mutex);
}

static int bootimgfs_flush(const char *path, struct fuse_file_info *fi)
{
	int fid = bootimgfs_get_file_id(path);

	if (fid < 0)
		return -ENOENT;

	switch (fid) {
	case KERNEL:
	case RAMDISK:
	case SECOND_STAGE:
	case PAGE_SIZE:
	case ID:
		bootimgfs_rebuild_img();
	}

	return 0;
}

static int bootimgfs_fsync(const char *path, int datasync,
			   struct fuse_file_info *fi)
{
	int fid = bootimgfs_get_file_id(path);

	if (fid < 0)
		return -ENOENT;

	switch (fid) {
	case KERNEL:
	case RAMDISK:
	case SECOND_STAGE:
	case PAGE_SIZE:
	case ID:
		bootimgfs_rebuild_img();
	}

	return 0;
}

static void *bootimgfs_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctx = fuse_get_context();
	struct bootimgfile *bif = ctx->private_data;

	INIT_HEADER_FILE(ID, bif->header_offset, id, 64, 64);

	INIT_HEADER_FILE(PAGE_SIZE, bif->header_offset, page_size, 10, 10);

	INIT_HEADER_FILE(KERNEL_BASE, bif->header_offset, kernel_addr, 10, 10);

	INIT_HEADER_FILE(KERNEL_TAGS_BASE, bif->header_offset, tags_addr,
			 10, 10);

	INIT_HEADER_FILE(RAMDISK_BASE, bif->header_offset, ramdisk_addr,
			 10, 10);

	INIT_HEADER_FILE(SECOND_STAGE_BASE, bif->header_offset, second_addr,
			 10, 10);

	INIT_HEADER_FILE(PRODUCT_NAME, bif->header_offset, name,
			 strnlen(bif->hdr.name, BOOT_NAME_SIZE - 1),
			 BOOT_NAME_SIZE - 1);

	INIT_HEADER_FILE(CMDLINE, bif->header_offset, cmdline,
			 strnlen(bif->hdr.cmdline, BOOT_ARGS_SIZE - 1),
			 BOOT_ARGS_SIZE - 1);

	INIT_IMG_FILE(bif->pFile, KERNEL, bif->hdr, bif->header_offset,
		      sizeof(bif->hdr), bif->hdr.kernel_size);

	INIT_IMG_FILE(bif->pFile, RAMDISK, bif->hdr, files[KERNEL].offset,
		      bif->hdr.kernel_size, bif->hdr.ramdisk_size);

	INIT_IMG_FILE(bif->pFile, SECOND_STAGE, bif->hdr, files[RAMDISK].offset,
		      bif->hdr.ramdisk_size, bif->hdr.second_size);

	return bif;
}

static void bootimgfs_destroy(void *arg)
{
	struct bootimgfile *bif = arg;
	fclose(bif->pFile);
}

static struct fuse_operations bootimgfs_ops = {
	.getattr = bootimgfs_getattr,
	.readdir = bootimgfs_readdir,
	.statfs = bootimgfs_statfs,
	.open = bootimgfs_open,
	.read = bootimgfs_read,
	.write = bootimgfs_write,
	.truncate = bootimgfs_truncate,
	.flush = bootimgfs_flush,
	.fsync = bootimgfs_fsync,
	.init = bootimgfs_init,
	.destroy = bootimgfs_destroy,
};

int main(int argc, char *argv[])
{
	struct fuse_args fargs = FUSE_ARGS_INIT(0, NULL);
	struct bootimgfile bif;
	char *mnt_path = argv[2];
	char *mnt_dev = argv[1];

	if (argc != 3 || bootimg_open(&bif, mnt_dev, 0))
		return 1;

	assert(fuse_opt_add_arg(&fargs, argv[0]) == 0);
	assert(fuse_opt_add_arg(&fargs, "-ofsname=bootimgfs") == 0);
	assert(fuse_opt_add_arg(&fargs, "-oallow_other") == 0);
	assert(fuse_opt_add_arg(&fargs, "-ononempty") == 0);
	assert(fuse_opt_add_arg(&fargs, mnt_path) == 0);

	return fuse_main(fargs.argc, fargs.argv, &bootimgfs_ops, &bif);
}
