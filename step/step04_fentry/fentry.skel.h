/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __FENTRY_SKEL_H__
#define __FENTRY_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct fentry {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *events;
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *tcp_connect;
	} progs;
	struct {
		struct bpf_link *tcp_connect;
	} links;
	struct fentry__bss {
		struct event *unused;
	} *bss;

#ifdef __cplusplus
	static inline struct fentry *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct fentry *open_and_load();
	static inline int load(struct fentry *skel);
	static inline int attach(struct fentry *skel);
	static inline void detach(struct fentry *skel);
	static inline void destroy(struct fentry *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
fentry__destroy(struct fentry *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
fentry__create_skeleton(struct fentry *obj);

static inline struct fentry *
fentry__open_opts(const struct bpf_object_open_opts *opts)
{
	struct fentry *obj;
	int err;

	obj = (struct fentry *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = fentry__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	fentry__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct fentry *
fentry__open(void)
{
	return fentry__open_opts(NULL);
}

static inline int
fentry__load(struct fentry *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct fentry *
fentry__open_and_load(void)
{
	struct fentry *obj;
	int err;

	obj = fentry__open();
	if (!obj)
		return NULL;
	err = fentry__load(obj);
	if (err) {
		fentry__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
fentry__attach(struct fentry *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
fentry__detach(struct fentry *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *fentry__elf_bytes(size_t *sz);

static inline int
fentry__create_skeleton(struct fentry *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "fentry";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "events";
	s->maps[0].map = &obj->maps.events;

	s->maps[1].name = "fentry.bss";
	s->maps[1].map = &obj->maps.bss;
	s->maps[1].mmaped = (void **)&obj->bss;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "tcp_connect";
	s->progs[0].prog = &obj->progs.tcp_connect;
	s->progs[0].link = &obj->links.tcp_connect;

	s->data = fentry__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *fentry__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x48\x0a\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0e\0\
\x01\0\x79\x17\0\0\0\0\0\0\x69\x71\x10\0\0\0\0\0\x55\x01\x16\0\x02\0\0\0\x18\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x1c\0\0\0\xb7\x03\0\0\0\0\0\0\x85\
\0\0\0\x83\0\0\0\xbf\x06\0\0\0\0\0\0\x15\x06\x0f\0\0\0\0\0\x61\x71\x04\0\0\0\0\
\0\x63\x16\x14\0\0\0\0\0\x61\x71\0\0\0\0\0\0\x63\x16\x18\0\0\0\0\0\x69\x71\x0c\
\0\0\0\0\0\x6b\x16\x12\0\0\0\0\0\x69\x71\x0e\0\0\0\0\0\xdc\x01\0\0\x10\0\0\0\
\x6b\x16\x10\0\0\0\0\0\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\x10\0\0\0\x85\0\0\0\x10\
\0\0\0\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xb7\0\0\0\0\
\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x4d\x49\x54\x2f\x47\x50\x4c\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x4c\x02\0\0\
\x4c\x02\0\0\xf2\x02\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\
\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\
\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\0\0\x01\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\
\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\x31\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\
\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x44\0\0\0\x09\0\0\0\x48\0\0\0\x01\0\0\x0c\
\x0b\0\0\0\x5a\x02\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\
\0\x0d\0\0\0\x04\0\0\0\x0d\0\0\0\x5f\x02\0\0\0\0\0\x0e\x0e\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\x02\x11\0\0\0\x69\x02\0\0\x05\0\0\x04\x1c\0\0\0\x6f\x02\0\0\x15\0\0\
\0\0\0\0\0\x74\x02\0\0\x16\0\0\0\x80\0\0\0\x7a\x02\0\0\x18\0\0\0\x90\0\0\0\x80\
\x02\0\0\x19\0\0\0\xa0\0\0\0\x86\x02\0\0\x19\0\0\0\xc0\0\0\0\x8c\x02\0\0\0\0\0\
\x08\x13\0\0\0\x8f\x02\0\0\0\0\0\x08\x14\0\0\0\x94\x02\0\0\0\0\0\x01\x01\0\0\0\
\x08\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x12\0\0\0\x04\0\0\0\x10\0\0\0\xa2\x02\0\0\
\0\0\0\x08\x17\0\0\0\xa8\x02\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\xb7\x02\0\0\0\0\
\0\x08\x16\0\0\0\xbe\x02\0\0\0\0\0\x08\x1a\0\0\0\xc5\x02\0\0\0\0\0\x08\x1b\0\0\
\0\xcb\x02\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\xd8\x02\0\0\0\0\0\x0e\x10\0\0\0\
\x01\0\0\0\xdf\x02\0\0\x01\0\0\x0f\0\0\0\0\x1c\0\0\0\0\0\0\0\x08\0\0\0\xe4\x02\
\0\0\x01\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\xea\x02\0\0\x01\0\0\x0f\0\
\0\0\0\x0f\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\
\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x65\x76\x65\x6e\x74\x73\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\
\x74\x63\x70\x5f\x63\x6f\x6e\x6e\x65\x63\x74\0\x66\x65\x6e\x74\x72\x79\x2f\x74\
\x63\x70\x5f\x63\x6f\x6e\x6e\x65\x63\x74\0\x2f\x72\x6f\x6f\x74\x2f\x67\x6f\x2f\
\x73\x72\x63\x2f\x65\x62\x70\x66\x2d\x67\x6f\x2f\x66\x65\x6e\x74\x72\x79\x2f\
\x66\x65\x6e\x74\x72\x79\x2e\x63\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\
\x47\x28\x74\x63\x70\x5f\x63\x6f\x6e\x6e\x65\x63\x74\x2c\x20\x73\x74\x72\x75\
\x63\x74\x20\x73\x6f\x63\x6b\x20\x2a\x73\x6b\x29\x20\x7b\0\x09\x69\x66\x20\x28\
\x73\x6b\x2d\x3e\x5f\x5f\x73\x6b\x5f\x63\x6f\x6d\x6d\x6f\x6e\x2e\x73\x6b\x63\
\x5f\x66\x61\x6d\x69\x6c\x79\x20\x21\x3d\x20\x41\x46\x5f\x49\x4e\x45\x54\x29\
\x20\x7b\0\x09\x74\x63\x70\x5f\x69\x6e\x66\x6f\x20\x3d\x20\x62\x70\x66\x5f\x72\
\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\x76\x65\x28\x26\x65\x76\x65\
\x6e\x74\x73\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x73\x74\x72\x75\x63\x74\x20\
\x65\x76\x65\x6e\x74\x29\x2c\x20\x30\x29\x3b\0\x09\x69\x66\x20\x28\x21\x74\x63\
\x70\x5f\x69\x6e\x66\x6f\x29\x20\x7b\0\x09\x74\x63\x70\x5f\x69\x6e\x66\x6f\x2d\
\x3e\x73\x61\x64\x64\x72\x20\x3d\x20\x73\x6b\x2d\x3e\x5f\x5f\x73\x6b\x5f\x63\
\x6f\x6d\x6d\x6f\x6e\x2e\x73\x6b\x63\x5f\x72\x63\x76\x5f\x73\x61\x64\x64\x72\
\x3b\0\x09\x74\x63\x70\x5f\x69\x6e\x66\x6f\x2d\x3e\x64\x61\x64\x64\x72\x20\x3d\
\x20\x73\x6b\x2d\x3e\x5f\x5f\x73\x6b\x5f\x63\x6f\x6d\x6d\x6f\x6e\x2e\x73\x6b\
\x63\x5f\x64\x61\x64\x64\x72\x3b\0\x09\x74\x63\x70\x5f\x69\x6e\x66\x6f\x2d\x3e\
\x64\x70\x6f\x72\x74\x20\x3d\x20\x73\x6b\x2d\x3e\x5f\x5f\x73\x6b\x5f\x63\x6f\
\x6d\x6d\x6f\x6e\x2e\x73\x6b\x63\x5f\x64\x70\x6f\x72\x74\x3b\0\x09\x74\x63\x70\
\x5f\x69\x6e\x66\x6f\x2d\x3e\x73\x70\x6f\x72\x74\x20\x3d\x20\x62\x70\x66\x5f\
\x68\x74\x6f\x6e\x73\x28\x73\x6b\x2d\x3e\x5f\x5f\x73\x6b\x5f\x63\x6f\x6d\x6d\
\x6f\x6e\x2e\x73\x6b\x63\x5f\x6e\x75\x6d\x29\x3b\0\x09\x62\x70\x66\x5f\x67\x65\
\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x74\x63\x70\
\x5f\x69\x6e\x66\x6f\x2d\x3e\x63\x6f\x6d\x6d\x2c\x20\x54\x41\x53\x4b\x5f\x43\
\x4f\x4d\x4d\x5f\x4c\x45\x4e\x29\x3b\0\x09\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\
\x75\x66\x5f\x73\x75\x62\x6d\x69\x74\x28\x74\x63\x70\x5f\x69\x6e\x66\x6f\x2c\
\x20\x30\x29\x3b\0\x63\x68\x61\x72\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x65\
\x76\x65\x6e\x74\0\x63\x6f\x6d\x6d\0\x73\x70\x6f\x72\x74\0\x64\x70\x6f\x72\x74\
\0\x73\x61\x64\x64\x72\0\x64\x61\x64\x64\x72\0\x75\x38\0\x5f\x5f\x75\x38\0\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x5f\x5f\x75\x31\x36\0\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x5f\x5f\x62\x65\x31\x36\
\0\x5f\x5f\x62\x65\x33\x32\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\
\x64\x20\x69\x6e\x74\0\x75\x6e\x75\x73\x65\x64\0\x2e\x62\x73\x73\0\x2e\x6d\x61\
\x70\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\
\x14\0\0\0\x14\0\0\0\x0c\x01\0\0\x20\x01\0\0\0\0\0\0\x08\0\0\0\x54\0\0\0\x01\0\
\0\0\0\0\0\0\x0c\0\0\0\x10\0\0\0\x54\0\0\0\x10\0\0\0\0\0\0\0\x67\0\0\0\x8c\0\0\
\0\x05\x34\x01\0\x08\0\0\0\x67\0\0\0\xb9\0\0\0\x16\x38\x01\0\x10\0\0\0\x67\0\0\
\0\xb9\0\0\0\x06\x38\x01\0\x18\0\0\0\x67\0\0\0\xe7\0\0\0\x0d\x4c\x01\0\x48\0\0\
\0\x67\0\0\0\x2a\x01\0\0\x06\x50\x01\0\x50\0\0\0\x67\0\0\0\x3c\x01\0\0\x24\x60\
\x01\0\x58\0\0\0\x67\0\0\0\x3c\x01\0\0\x12\x60\x01\0\x60\0\0\0\x67\0\0\0\x6e\
\x01\0\0\x24\x64\x01\0\x68\0\0\0\x67\0\0\0\x6e\x01\0\0\x12\x64\x01\0\x70\0\0\0\
\x67\0\0\0\x9c\x01\0\0\x24\x68\x01\0\x78\0\0\0\x67\0\0\0\x9c\x01\0\0\x12\x68\
\x01\0\x80\0\0\0\x67\0\0\0\xca\x01\0\0\x14\x6c\x01\0\x90\0\0\0\x67\0\0\0\xca\
\x01\0\0\x12\x6c\x01\0\x98\0\0\0\x67\0\0\0\x01\x02\0\0\x02\x74\x01\0\xb0\0\0\0\
\x67\0\0\0\x38\x02\0\0\x02\x7c\x01\0\xc8\0\0\0\x67\0\0\0\x8c\0\0\0\x05\x34\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x75\0\0\0\0\0\x03\0\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x1f\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\x2b\0\0\0\x11\0\x06\0\
\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4b\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\
\0\0\0\0\0\0\x55\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\
\0\0\0\0\x01\0\0\0\x04\0\0\0\x2c\x02\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x44\x02\0\
\0\0\0\0\0\x04\0\0\0\x04\0\0\0\x5c\x02\0\0\0\0\0\0\x04\0\0\0\x05\0\0\0\x2c\0\0\
\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\0\0\0\
\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\
\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\
\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\
\0\x04\0\0\0\x01\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xe0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xf0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x10\x01\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x20\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x30\x01\0\0\0\0\0\
\0\x04\0\0\0\x01\0\0\0\x0c\x0e\x0d\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x72\x65\x6c\x66\x65\x6e\x74\x72\x79\x2f\x74\
\x63\x70\x5f\x63\x6f\x6e\x6e\x65\x63\x74\0\x65\x76\x65\x6e\x74\x73\0\x2e\x62\
\x73\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\
\x69\x67\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x75\x6e\x75\x73\x65\x64\0\x2e\
\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x33\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x5c\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcb\x09\0\0\
\0\0\0\0\x7c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\0\0\0\x01\0\0\
\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x78\x08\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0d\0\0\0\x03\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x4d\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x37\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x28\x01\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x32\0\0\0\x08\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x01\0\0\0\
\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x01\0\0\0\0\0\0\x56\x05\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6c\0\0\0\x09\0\0\
\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x08\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x0d\
\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x06\0\0\0\0\0\0\x40\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xb8\x08\0\0\0\0\0\0\x10\x01\0\0\0\0\0\0\x0d\0\0\0\x0a\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x3d\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\
\0\0\0\0\0\0\0\xc8\x09\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x64\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xd0\x07\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\
\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct fentry *fentry::open(const struct bpf_object_open_opts *opts) { return fentry__open_opts(opts); }
struct fentry *fentry::open_and_load() { return fentry__open_and_load(); }
int fentry::load(struct fentry *skel) { return fentry__load(skel); }
int fentry::attach(struct fentry *skel) { return fentry__attach(skel); }
void fentry::detach(struct fentry *skel) { fentry__detach(skel); }
void fentry::destroy(struct fentry *skel) { fentry__destroy(skel); }
const void *fentry::elf_bytes(size_t *sz) { return fentry__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
fentry__assert(struct fentry *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->unused) == 8, "unexpected size of 'unused'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __FENTRY_SKEL_H__ */
