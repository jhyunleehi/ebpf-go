/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __KPROBE_PERCPU_SKEL_H__
#define __KPROBE_PERCPU_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct kprobe_percpu {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *kprobe_map;
	} maps;
	struct {
		struct bpf_program *kprobe_execve;
	} progs;
	struct {
		struct bpf_link *kprobe_execve;
	} links;

#ifdef __cplusplus
	static inline struct kprobe_percpu *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct kprobe_percpu *open_and_load();
	static inline int load(struct kprobe_percpu *skel);
	static inline int attach(struct kprobe_percpu *skel);
	static inline void detach(struct kprobe_percpu *skel);
	static inline void destroy(struct kprobe_percpu *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
kprobe_percpu__destroy(struct kprobe_percpu *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
kprobe_percpu__create_skeleton(struct kprobe_percpu *obj);

static inline struct kprobe_percpu *
kprobe_percpu__open_opts(const struct bpf_object_open_opts *opts)
{
	struct kprobe_percpu *obj;
	int err;

	obj = (struct kprobe_percpu *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = kprobe_percpu__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	kprobe_percpu__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct kprobe_percpu *
kprobe_percpu__open(void)
{
	return kprobe_percpu__open_opts(NULL);
}

static inline int
kprobe_percpu__load(struct kprobe_percpu *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct kprobe_percpu *
kprobe_percpu__open_and_load(void)
{
	struct kprobe_percpu *obj;
	int err;

	obj = kprobe_percpu__open();
	if (!obj)
		return NULL;
	err = kprobe_percpu__load(obj);
	if (err) {
		kprobe_percpu__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
kprobe_percpu__attach(struct kprobe_percpu *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
kprobe_percpu__detach(struct kprobe_percpu *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *kprobe_percpu__elf_bytes(size_t *sz);

static inline int
kprobe_percpu__create_skeleton(struct kprobe_percpu *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "kprobe_percpu";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "kprobe_map";
	s->maps[0].map = &obj->maps.kprobe_map;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "kprobe_execve";
	s->progs[0].prog = &obj->progs.kprobe_execve;
	s->progs[0].link = &obj->links.kprobe_execve;

	s->data = kprobe_percpu__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *kprobe_percpu__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x88\x07\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0d\0\
\x01\0\xb7\x01\0\0\0\0\0\0\x63\x1a\xfc\xff\0\0\0\0\xb7\x06\0\0\x01\0\0\0\x7b\
\x6a\xf0\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x55\0\x09\0\0\0\0\0\xbf\xa2\0\0\
\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xf0\xff\
\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x02\
\0\0\0\x05\0\x01\0\0\0\0\0\xdb\x60\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x75\
\x61\x6c\x20\x4d\x49\x54\x2f\x47\x50\x4c\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\
\0\x84\x01\0\0\x84\x01\0\0\xbd\x01\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\
\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\
\x06\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\
\x19\0\0\0\0\0\0\x08\x07\0\0\0\x1f\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\
\0\0\0\x02\x09\0\0\0\x2c\0\0\0\0\0\0\x08\x0a\0\0\0\x32\0\0\0\0\0\0\x01\x08\0\0\
\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\
\x04\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x45\0\0\0\x01\0\0\0\0\0\0\0\
\x4a\0\0\0\x05\0\0\0\x40\0\0\0\x4e\0\0\0\x08\0\0\0\x80\0\0\0\x54\0\0\0\x0b\0\0\
\0\xc0\0\0\0\x60\0\0\0\0\0\0\x0e\x0d\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0d\x02\0\0\
\0\x6b\0\0\0\x01\0\0\x0c\x0f\0\0\0\xa0\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\
\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x0d\0\0\0\xa5\x01\0\0\0\0\0\x0e\
\x12\0\0\0\x01\0\0\0\xaf\x01\0\0\x01\0\0\x0f\0\0\0\0\x0e\0\0\0\0\0\0\0\x20\0\0\
\0\xb5\x01\0\0\x01\0\0\x0f\0\0\0\0\x13\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\x6e\x74\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\
\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\
\x6f\x6e\x67\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x70\x72\x6f\x62\x65\x5f\x6d\x61\x70\
\0\x6b\x70\x72\x6f\x62\x65\x5f\x65\x78\x65\x63\x76\x65\0\x6b\x70\x72\x6f\x62\
\x65\x2f\x73\x79\x73\x5f\x65\x78\x65\x63\x76\x65\0\x2f\x72\x6f\x6f\x74\x2f\x67\
\x6f\x2f\x73\x72\x63\x2f\x65\x62\x70\x66\x2d\x67\x6f\x2f\x73\x74\x65\x70\x30\
\x36\x5f\x6b\x70\x72\x6f\x62\x65\x5f\x6d\x61\x70\x2f\x6b\x70\x72\x6f\x62\x65\
\x5f\x70\x65\x72\x63\x70\x75\x2e\x63\0\x69\x6e\x74\x20\x6b\x70\x72\x6f\x62\x65\
\x5f\x65\x78\x65\x63\x76\x65\x28\x29\x20\x7b\0\x09\x75\x33\x32\x20\x6b\x65\x79\
\x20\x20\x20\x20\x20\x3d\x20\x30\x3b\0\x09\x75\x36\x34\x20\x69\x6e\x69\x74\x76\
\x61\x6c\x20\x3d\x20\x31\x2c\x20\x2a\x76\x61\x6c\x70\x3b\0\x09\x76\x61\x6c\x70\
\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\
\x6c\x65\x6d\x28\x26\x6b\x70\x72\x6f\x62\x65\x5f\x6d\x61\x70\x2c\x20\x26\x6b\
\x65\x79\x29\x3b\0\x09\x69\x66\x20\x28\x21\x76\x61\x6c\x70\x29\x20\x7b\0\x09\
\x09\x62\x70\x66\x5f\x6d\x61\x70\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\
\x6d\x28\x26\x6b\x70\x72\x6f\x62\x65\x5f\x6d\x61\x70\x2c\x20\x26\x6b\x65\x79\
\x2c\x20\x26\x69\x6e\x69\x74\x76\x61\x6c\x2c\x20\x42\x50\x46\x5f\x41\x4e\x59\
\x29\x3b\0\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\
\x5f\x61\x64\x64\x28\x76\x61\x6c\x70\x2c\x20\x31\x29\x3b\0\x7d\0\x63\x68\x61\
\x72\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\
\xac\0\0\0\xc0\0\0\0\0\0\0\0\x08\0\0\0\x79\0\0\0\x01\0\0\0\0\0\0\0\x10\0\0\0\
\x10\0\0\0\x79\0\0\0\x0a\0\0\0\0\0\0\0\x8b\0\0\0\xc2\0\0\0\0\x44\0\0\x08\0\0\0\
\x8b\0\0\0\xd8\0\0\0\x06\x48\0\0\x18\0\0\0\x8b\0\0\0\xea\0\0\0\x06\x4c\0\0\x28\
\0\0\0\x8b\0\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\x8b\0\0\0\x03\x01\0\0\x09\x54\0\0\
\x48\0\0\0\x8b\0\0\0\x33\x01\0\0\x06\x58\0\0\x58\0\0\0\x8b\0\0\0\0\0\0\0\0\0\0\
\0\x70\0\0\0\x8b\0\0\0\x41\x01\0\0\x03\x5c\0\0\x98\0\0\0\x8b\0\0\0\x7e\x01\0\0\
\x02\x68\0\0\xa0\0\0\0\x8b\0\0\0\x9e\x01\0\0\x01\x74\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x81\0\0\0\0\0\x03\0\x98\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7a\0\0\0\0\0\
\x03\0\xa0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x49\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\
\xb0\0\0\0\0\0\0\0\x1a\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x57\
\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x01\0\0\
\0\x05\0\0\0\x70\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x7c\x01\0\0\0\0\0\0\x04\0\0\
\0\x05\0\0\0\x94\x01\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\
\0\x01\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\0\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\x0d\x0e\x0f\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\x2e\x6d\x61\x70\x73\0\x6b\x70\x72\x6f\x62\x65\x5f\x6d\x61\
\x70\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x2e\x72\x65\x6c\
\x6b\x70\x72\x6f\x62\x65\x2f\x73\x79\x73\x5f\x65\x78\x65\x63\x76\x65\0\x6b\x70\
\x72\x6f\x62\x65\x5f\x65\x78\x65\x63\x76\x65\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\
\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\
\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\x5f\x32\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\0\0\0\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\x06\0\0\0\0\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x37\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x40\0\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x33\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x06\0\0\0\0\
\0\0\x20\0\0\0\0\0\0\0\x0c\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x14\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x20\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x59\0\0\0\x01\0\
\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x01\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x20\x01\0\0\0\0\0\0\x59\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x28\x06\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x0c\0\0\0\x07\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x7c\x04\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x06\0\0\0\
\0\0\0\xb0\0\0\0\0\0\0\0\x0c\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x25\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xf8\x06\0\0\0\0\
\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x69\0\
\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x05\0\0\0\0\0\0\xa8\0\0\0\0\
\0\0\0\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct kprobe_percpu *kprobe_percpu::open(const struct bpf_object_open_opts *opts) { return kprobe_percpu__open_opts(opts); }
struct kprobe_percpu *kprobe_percpu::open_and_load() { return kprobe_percpu__open_and_load(); }
int kprobe_percpu::load(struct kprobe_percpu *skel) { return kprobe_percpu__load(skel); }
int kprobe_percpu::attach(struct kprobe_percpu *skel) { return kprobe_percpu__attach(skel); }
void kprobe_percpu::detach(struct kprobe_percpu *skel) { kprobe_percpu__detach(skel); }
void kprobe_percpu::destroy(struct kprobe_percpu *skel) { kprobe_percpu__destroy(skel); }
const void *kprobe_percpu::elf_bytes(size_t *sz) { return kprobe_percpu__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
kprobe_percpu__assert(struct kprobe_percpu *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __KPROBE_PERCPU_SKEL_H__ */
