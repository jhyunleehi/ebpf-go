/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __COUNTER_BPF_SKEL_H__
#define __COUNTER_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct counter_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *pkt_count;
	} maps;
	struct {
		struct bpf_program *count_packets;
	} progs;
	struct {
		struct bpf_link *count_packets;
	} links;

#ifdef __cplusplus
	static inline struct counter_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct counter_bpf *open_and_load();
	static inline int load(struct counter_bpf *skel);
	static inline int attach(struct counter_bpf *skel);
	static inline void detach(struct counter_bpf *skel);
	static inline void destroy(struct counter_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
counter_bpf__destroy(struct counter_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
counter_bpf__create_skeleton(struct counter_bpf *obj);

static inline struct counter_bpf *
counter_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct counter_bpf *obj;
	int err;

	obj = (struct counter_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = counter_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	counter_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct counter_bpf *
counter_bpf__open(void)
{
	return counter_bpf__open_opts(NULL);
}

static inline int
counter_bpf__load(struct counter_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct counter_bpf *
counter_bpf__open_and_load(void)
{
	struct counter_bpf *obj;
	int err;

	obj = counter_bpf__open();
	if (!obj)
		return NULL;
	err = counter_bpf__load(obj);
	if (err) {
		counter_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
counter_bpf__attach(struct counter_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
counter_bpf__detach(struct counter_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *counter_bpf__elf_bytes(size_t *sz);

static inline int
counter_bpf__create_skeleton(struct counter_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "counter_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "pkt_count";
	s->maps[0].map = &obj->maps.pkt_count;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "count_packets";
	s->progs[0].prog = &obj->progs.count_packets;
	s->progs[0].link = &obj->links.count_packets;

	s->data = counter_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *counter_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x50\x06\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0d\0\
\x01\0\xb7\x01\0\0\0\0\0\0\x63\x1a\xfc\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\
\0\0\xfc\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\
\x15\0\x02\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\xdb\x10\0\0\0\0\0\0\xb7\0\0\0\x02\0\
\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x44\x75\x61\x6c\x20\x4d\x49\x54\x2f\x47\x50\x4c\0\0\0\0\x9f\xeb\x01\0\
\x18\0\0\0\0\0\0\0\x84\x01\0\0\x84\x01\0\0\x78\x01\0\0\0\0\0\0\0\0\0\x02\x03\0\
\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\
\0\0\x04\0\0\0\x02\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\
\x02\x06\0\0\0\x19\0\0\0\0\0\0\x08\x07\0\0\0\x1f\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\0\0\0\0\0\0\0\0\x02\x09\0\0\0\x2c\0\0\0\0\0\0\x08\x0a\0\0\0\x32\0\0\0\0\0\
\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\
\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x45\0\0\0\x01\0\
\0\0\0\0\0\0\x4a\0\0\0\x05\0\0\0\x40\0\0\0\x4e\0\0\0\x08\0\0\0\x80\0\0\0\x54\0\
\0\0\x0b\0\0\0\xc0\0\0\0\x60\0\0\0\0\0\0\x0e\x0d\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\x0d\x02\0\0\0\x6a\0\0\0\x01\0\0\x0c\x0f\0\0\0\x5b\x01\0\0\0\0\0\x01\x01\0\0\0\
\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x0d\0\0\0\x60\x01\0\
\0\0\0\0\x0e\x12\0\0\0\x01\0\0\0\x6a\x01\0\0\x01\0\0\x0f\0\0\0\0\x0e\0\0\0\0\0\
\0\0\x20\0\0\0\x70\x01\0\0\x01\0\0\x0f\0\0\0\0\x13\0\0\0\0\0\0\0\x0d\0\0\0\0\
\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\
\x45\x5f\x5f\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\
\x6e\x67\x20\x6c\x6f\x6e\x67\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\
\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x70\x6b\x74\x5f\x63\x6f\
\x75\x6e\x74\0\x63\x6f\x75\x6e\x74\x5f\x70\x61\x63\x6b\x65\x74\x73\0\x78\x64\
\x70\0\x2f\x72\x6f\x6f\x74\x2f\x67\x6f\x2f\x73\x72\x63\x2f\x65\x62\x70\x66\x2d\
\x67\x6f\x2f\x73\x74\x2f\x63\x6f\x75\x6e\x74\x65\x72\x2e\x62\x70\x66\x2e\x63\0\
\x69\x6e\x74\x20\x63\x6f\x75\x6e\x74\x5f\x70\x61\x63\x6b\x65\x74\x73\x28\x29\
\x20\x7b\0\x20\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x6b\x65\x79\x20\x20\x20\x20\
\x3d\x20\x30\x3b\x20\0\x20\x20\x20\x20\x5f\x5f\x75\x36\x34\x20\x2a\x63\x6f\x75\
\x6e\x74\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\
\x5f\x65\x6c\x65\x6d\x28\x26\x70\x6b\x74\x5f\x63\x6f\x75\x6e\x74\x2c\x20\x26\
\x6b\x65\x79\x29\x3b\x20\0\x20\x20\x20\x20\x69\x66\x20\x28\x63\x6f\x75\x6e\x74\
\x29\x20\x7b\x20\0\x20\x20\x20\x20\x20\x20\x20\x20\x5f\x5f\x73\x79\x6e\x63\x5f\
\x66\x65\x74\x63\x68\x5f\x61\x6e\x64\x5f\x61\x64\x64\x28\x63\x6f\x75\x6e\x74\
\x2c\x20\x31\x29\x3b\x20\0\x20\x20\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x58\x44\
\x50\x5f\x50\x41\x53\x53\x3b\x20\0\x63\x68\x61\x72\0\x5f\x5f\x6c\x69\x63\x65\
\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\
\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x7c\0\0\0\x90\0\0\0\0\0\0\0\x08\0\0\0\
\x78\0\0\0\x01\0\0\0\0\0\0\0\x10\0\0\0\x10\0\0\0\x78\0\0\0\x07\0\0\0\0\0\0\0\
\x7c\0\0\0\xa2\0\0\0\0\x40\0\0\x08\0\0\0\x7c\0\0\0\xb8\0\0\0\x0b\x44\0\0\x18\0\
\0\0\x7c\0\0\0\0\0\0\0\0\0\0\0\x20\0\0\0\x7c\0\0\0\xcf\0\0\0\x14\x48\0\0\x38\0\
\0\0\x7c\0\0\0\x0a\x01\0\0\x09\x4c\0\0\x48\0\0\0\x7c\0\0\0\x1c\x01\0\0\x09\x50\
\0\0\x50\0\0\0\x7c\0\0\0\x45\x01\0\0\x05\x5c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x6b\0\0\0\0\0\x03\0\x50\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1e\0\0\0\x12\0\x03\0\0\
\0\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x14\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\
\0\0\0\0\0\x48\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x20\0\0\0\0\
\0\0\0\x01\0\0\0\x04\0\0\0\x7c\x01\0\0\0\0\0\0\x04\0\0\0\x04\0\0\0\x94\x01\0\0\
\0\0\0\0\x04\0\0\0\x05\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\
\0\0\0\x04\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\
\0\0\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\
\0\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x0c\x0d\x0e\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\
\x42\x54\x46\x2e\x65\x78\x74\0\x70\x6b\x74\x5f\x63\x6f\x75\x6e\x74\0\x63\x6f\
\x75\x6e\x74\x5f\x70\x61\x63\x6b\x65\x74\x73\0\x2e\x6d\x61\x70\x73\0\x2e\x72\
\x65\x6c\x78\x64\x70\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\
\x5f\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\
\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\
\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x52\0\0\0\x03\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdb\x05\0\0\0\0\0\0\x72\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x36\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x40\0\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x32\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x05\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x0c\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x2c\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\
\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4a\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x66\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xd0\0\0\0\0\0\0\0\x14\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x62\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x38\x05\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x0c\0\0\0\x07\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xe4\x03\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x05\0\0\
\0\0\0\0\x80\0\0\0\0\0\0\0\x0c\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x3a\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x05\0\0\0\
\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5a\
\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x04\0\0\0\0\0\0\x90\0\0\0\
\0\0\0\0\x01\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct counter_bpf *counter_bpf::open(const struct bpf_object_open_opts *opts) { return counter_bpf__open_opts(opts); }
struct counter_bpf *counter_bpf::open_and_load() { return counter_bpf__open_and_load(); }
int counter_bpf::load(struct counter_bpf *skel) { return counter_bpf__load(skel); }
int counter_bpf::attach(struct counter_bpf *skel) { return counter_bpf__attach(skel); }
void counter_bpf::detach(struct counter_bpf *skel) { counter_bpf__detach(skel); }
void counter_bpf::destroy(struct counter_bpf *skel) { counter_bpf__destroy(skel); }
const void *counter_bpf::elf_bytes(size_t *sz) { return counter_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
counter_bpf__assert(struct counter_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __COUNTER_BPF_SKEL_H__ */
