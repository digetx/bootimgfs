bin_PROGRAMS = bootimgfs

bootimgfs_SOURCES = bootimgfs.c common.c
bootimgfs_CFLAGS = $(AM_CFLAGS) $(FUSE_CFLAGS) -DFUSE_USE_VERSION=26
bootimgfs_LDADD = $(FUSE_LIBS)


sbin_PROGRAMS = bootimgfs.probe

bootimgfs_probe_SOURCES = bootimgfs.probe.c common.c
bootimgfs_probe_CFLAGS = $(AM_CFLAGS)
