/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __RINGBUFFER_SKEL_H__
#define __RINGBUFFER_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct ringbuffer {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *events;
		struct bpf_map *bss;
	} maps;
	struct {
		struct bpf_program *kprobe_execve;
	} progs;
	struct {
		struct bpf_link *kprobe_execve;
	} links;
	struct ringbuffer__bss {
		struct event *unused;
	} *bss;

#ifdef __cplusplus
	static inline struct ringbuffer *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct ringbuffer *open_and_load();
	static inline int load(struct ringbuffer *skel);
	static inline int attach(struct ringbuffer *skel);
	static inline void detach(struct ringbuffer *skel);
	static inline void destroy(struct ringbuffer *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
ringbuffer__destroy(struct ringbuffer *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
ringbuffer__create_skeleton(struct ringbuffer *obj);

static inline struct ringbuffer *
ringbuffer__open_opts(const struct bpf_object_open_opts *opts)
{
	struct ringbuffer *obj;
	int err;

	obj = (struct ringbuffer *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = ringbuffer__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	ringbuffer__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct ringbuffer *
ringbuffer__open(void)
{
	return ringbuffer__open_opts(NULL);
}

static inline int
ringbuffer__load(struct ringbuffer *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct ringbuffer *
ringbuffer__open_and_load(void)
{
	struct ringbuffer *obj;
	int err;

	obj = ringbuffer__open();
	if (!obj)
		return NULL;
	err = ringbuffer__load(obj);
	if (err) {
		ringbuffer__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
ringbuffer__attach(struct ringbuffer *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
ringbuffer__detach(struct ringbuffer *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *ringbuffer__elf_bytes(size_t *sz);

static inline int
ringbuffer__create_skeleton(struct ringbuffer *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "ringbuffer";
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

	s->maps[1].name = "ringbuff.bss";
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

	s->progs[0].name = "kprobe_execve";
	s->progs[0].prog = &obj->progs.kprobe_execve;
	s->progs[0].link = &obj->links.kprobe_execve;

	s->data = ringbuffer__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *ringbuffer__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x68\x09\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0e\0\
\x01\0\x85\0\0\0\x0e\0\0\0\xbf\x07\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb7\x02\0\0\x54\0\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x83\0\0\0\xbf\x06\0\0\
\0\0\0\0\x15\x06\x09\0\0\0\0\0\x77\x07\0\0\x20\0\0\0\x63\x76\0\0\0\0\0\0\xbf\
\x61\0\0\0\0\0\0\x07\x01\0\0\x04\0\0\0\xb7\x02\0\0\x50\0\0\0\x85\0\0\0\x10\0\0\
\0\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xb7\0\0\0\0\0\0\
\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x4d\x49\x54\x2f\x47\x50\x4c\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x14\x03\0\0\x14\
\x03\0\0\x50\x02\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x02\0\0\0\x04\0\0\0\0\0\0\x01\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\
\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\x31\0\0\0\x15\0\0\x04\xa8\0\0\0\x39\0\0\
\0\x0b\0\0\0\0\0\0\0\x3d\0\0\0\x0b\0\0\0\x40\0\0\0\x41\0\0\0\x0b\0\0\0\x80\0\0\
\0\x45\0\0\0\x0b\0\0\0\xc0\0\0\0\x49\0\0\0\x0b\0\0\0\0\x01\0\0\x4c\0\0\0\x0b\0\
\0\0\x40\x01\0\0\x4f\0\0\0\x0b\0\0\0\x80\x01\0\0\x53\0\0\0\x0b\0\0\0\xc0\x01\0\
\0\x57\0\0\0\x0b\0\0\0\0\x02\0\0\x5a\0\0\0\x0b\0\0\0\x40\x02\0\0\x5d\0\0\0\x0b\
\0\0\0\x80\x02\0\0\x60\0\0\0\x0b\0\0\0\xc0\x02\0\0\x63\0\0\0\x0b\0\0\0\0\x03\0\
\0\x66\0\0\0\x0b\0\0\0\x40\x03\0\0\x69\0\0\0\x0b\0\0\0\x80\x03\0\0\x6c\0\0\0\
\x0b\0\0\0\xc0\x03\0\0\x74\0\0\0\x0b\0\0\0\0\x04\0\0\x77\0\0\0\x0b\0\0\0\x40\
\x04\0\0\x7a\0\0\0\x0b\0\0\0\x80\x04\0\0\x80\0\0\0\x0b\0\0\0\xc0\x04\0\0\x83\0\
\0\0\x0b\0\0\0\0\x05\0\0\x86\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\
\0\x0d\x02\0\0\0\x94\0\0\0\x09\0\0\0\x98\0\0\0\x01\0\0\x0c\x0c\0\0\0\xeb\x01\0\
\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0e\0\0\0\x04\0\0\
\0\x0d\0\0\0\xf0\x01\0\0\0\0\0\x0e\x0f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x12\0\
\0\0\0\0\0\0\0\0\0\x0a\x13\0\0\0\xfa\x01\0\0\x02\0\0\x04\x54\0\0\0\0\x02\0\0\
\x14\0\0\0\0\0\0\0\x04\x02\0\0\x1a\0\0\0\x20\0\0\0\x09\x02\0\0\0\0\0\x08\x15\0\
\0\0\x0d\x02\0\0\0\0\0\x08\x16\0\0\0\x13\x02\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\
\x20\x02\0\0\0\0\0\x08\x18\0\0\0\x23\x02\0\0\0\0\0\x08\x19\0\0\0\x28\x02\0\0\0\
\0\0\x01\x01\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x17\0\0\0\x04\0\0\0\x50\
\0\0\0\x36\x02\0\0\0\0\0\x0e\x11\0\0\0\x01\0\0\0\x3d\x02\0\0\x01\0\0\x0f\0\0\0\
\0\x1b\0\0\0\0\0\0\0\x08\0\0\0\x42\x02\0\0\x01\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\
\0\x10\0\0\0\x48\x02\0\0\x01\0\0\x0f\0\0\0\0\x10\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x65\
\x76\x65\x6e\x74\x73\0\x70\x74\x5f\x72\x65\x67\x73\0\x72\x31\x35\0\x72\x31\x34\
\0\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\x62\x78\0\x72\x31\x31\0\x72\x31\x30\0\
\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\x64\x78\0\x73\x69\0\x64\x69\0\x6f\x72\
\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\0\x66\x6c\x61\x67\x73\0\x73\x70\0\x73\
\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x6b\
\x70\x72\x6f\x62\x65\x5f\x65\x78\x65\x63\x76\x65\0\x6b\x70\x72\x6f\x62\x65\x2f\
\x73\x79\x73\x5f\x65\x78\x65\x63\x76\x65\0\x2f\x72\x6f\x6f\x74\x2f\x67\x6f\x2f\
\x73\x72\x63\x2f\x65\x62\x70\x66\x2d\x67\x6f\x2f\x73\x74\x65\x70\x30\x37\x5f\
\x72\x69\x6e\x67\x62\x75\x66\x66\x65\x72\x2f\x72\x69\x6e\x67\x62\x75\x66\x66\
\x65\x72\x2e\x63\0\x09\x75\x36\x34\x20\x69\x64\x20\x20\x20\x3d\x20\x62\x70\x66\
\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\
\x69\x64\x28\x29\x3b\0\x09\x74\x61\x73\x6b\x5f\x69\x6e\x66\x6f\x20\x3d\x20\x62\
\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\x76\x65\x28\
\x26\x65\x76\x65\x6e\x74\x73\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x73\x74\x72\
\x75\x63\x74\x20\x65\x76\x65\x6e\x74\x29\x2c\x20\x30\x29\x3b\0\x09\x69\x66\x20\
\x28\x21\x74\x61\x73\x6b\x5f\x69\x6e\x66\x6f\x29\x20\x7b\0\x09\x75\x33\x32\x20\
\x74\x67\x69\x64\x20\x3d\x20\x69\x64\x20\x3e\x3e\x20\x33\x32\x3b\0\x09\x74\x61\
\x73\x6b\x5f\x69\x6e\x66\x6f\x2d\x3e\x70\x69\x64\x20\x3d\x20\x74\x67\x69\x64\
\x3b\0\x09\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\
\x6f\x6d\x6d\x28\x26\x74\x61\x73\x6b\x5f\x69\x6e\x66\x6f\x2d\x3e\x63\x6f\x6d\
\x6d\x2c\x20\x38\x30\x29\x3b\0\x09\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\
\x5f\x73\x75\x62\x6d\x69\x74\x28\x74\x61\x73\x6b\x5f\x69\x6e\x66\x6f\x2c\x20\
\x30\x29\x3b\0\x7d\0\x63\x68\x61\x72\0\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\
\x65\x76\x65\x6e\x74\0\x70\x69\x64\0\x63\x6f\x6d\x6d\0\x75\x33\x32\0\x5f\x5f\
\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x75\x38\0\x5f\
\x5f\x75\x38\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x75\x6e\
\x75\x73\x65\x64\0\x2e\x62\x73\x73\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x9c\0\0\0\xb0\0\
\0\0\0\0\0\0\x08\0\0\0\xa6\0\0\0\x01\0\0\0\0\0\0\0\x0d\0\0\0\x10\0\0\0\xa6\0\0\
\0\x09\0\0\0\0\0\0\0\xb8\0\0\0\xec\0\0\0\x0d\x58\0\0\x10\0\0\0\xb8\0\0\0\x14\
\x01\0\0\x0e\x68\0\0\x40\0\0\0\xb8\0\0\0\x58\x01\0\0\x06\x6c\0\0\x48\0\0\0\xb8\
\0\0\0\x6b\x01\0\0\x10\x5c\0\0\x50\0\0\0\xb8\0\0\0\x81\x01\0\0\x11\x7c\0\0\x58\
\0\0\0\xb8\0\0\0\x99\x01\0\0\x23\x80\0\0\x68\0\0\0\xb8\0\0\0\x99\x01\0\0\x02\
\x80\0\0\x78\0\0\0\xb8\0\0\0\xc6\x01\0\0\x02\x88\0\0\x90\0\0\0\xb8\0\0\0\xe9\
\x01\0\0\x01\x94\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x82\0\0\0\0\0\x03\0\x90\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x4a\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xa0\0\0\0\0\0\
\0\0\x14\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x58\0\0\0\x11\0\
\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x62\0\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\xf4\x02\0\0\0\0\0\0\
\x04\0\0\0\x06\0\0\0\x0c\x03\0\0\0\0\0\0\x04\0\0\0\x04\0\0\0\x24\x03\0\0\0\0\0\
\0\x04\0\0\0\x05\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xc0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x0c\x0e\x0d\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\x2e\x65\x78\x74\0\x65\x76\x65\x6e\x74\x73\0\x2e\x62\x73\x73\0\x2e\
\x6d\x61\x70\x73\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x2e\
\x72\x65\x6c\x6b\x70\x72\x6f\x62\x65\x2f\x73\x79\x73\x5f\x65\x78\x65\x63\x76\
\x65\0\x6b\x70\x72\x6f\x62\x65\x5f\x65\x78\x65\x63\x76\x65\0\x5f\x5f\x6c\x69\
\x63\x65\x6e\x73\x65\0\x75\x6e\x75\x73\x65\x64\0\x2e\x73\x74\x72\x74\x61\x62\0\
\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\
\x30\x5f\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x69\0\
\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdb\x08\0\0\0\0\0\0\x89\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\
\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xf8\x07\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0d\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x5a\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\0\
\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x20\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x10\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1b\0\0\0\x08\
\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7d\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x7c\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x79\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x08\x08\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x0d\0\0\0\x08\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x7c\x06\0\0\0\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x08\0\0\0\
\0\0\0\xa0\0\0\0\0\0\0\0\x0d\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x26\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x08\0\0\0\0\
\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\0\
\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x07\0\0\0\0\0\0\xa8\0\0\0\0\
\0\0\0\x01\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct ringbuffer *ringbuffer::open(const struct bpf_object_open_opts *opts) { return ringbuffer__open_opts(opts); }
struct ringbuffer *ringbuffer::open_and_load() { return ringbuffer__open_and_load(); }
int ringbuffer::load(struct ringbuffer *skel) { return ringbuffer__load(skel); }
int ringbuffer::attach(struct ringbuffer *skel) { return ringbuffer__attach(skel); }
void ringbuffer::detach(struct ringbuffer *skel) { ringbuffer__detach(skel); }
void ringbuffer::destroy(struct ringbuffer *skel) { ringbuffer__destroy(skel); }
const void *ringbuffer::elf_bytes(size_t *sz) { return ringbuffer__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
ringbuffer__assert(struct ringbuffer *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->unused) == 8, "unexpected size of 'unused'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __RINGBUFFER_SKEL_H__ */
