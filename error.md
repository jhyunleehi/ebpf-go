# Error list


### bpf2go compile error   
```
$(TARGET): $(USER_SKEL) 
	echo  go build...	
	go get github.com/cilium/ebpf/cmd/bpf2go
	go run github.com/cilium/ebpf/cmd/bpf2go  bpf ${TARGET}.c -- -I../headers
	go generate
	go build  
```

```
root@Good:~/go/src/ebpf-go/step09# make
clang \
    -target bpf \
        -D __TARGET_ARCH_x86 \
    -Wall \
    -O2 -g -o tcprtt.o -c tcprtt.c
llvm-strip -g tcprtt.o
bpftool gen skeleton tcprtt.o > tcprtt.skel.h
echo  go build...
go build...
go get github.com/cilium/ebpf/cmd/bpf2go
go run github.com/cilium/ebpf/cmd/bpf2go  bpf tcprtt.c -- -I../headers
/root/go/src/ebpf-go/step09/tcprtt.c:96:5: error: The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb
int BPF_KPROBE(vfs_open, struct path *path, struct file *file)
    ^
/root/go/src/ebpf-go/step09/bpf_tracing.h:461:20: note: expanded from macro 'BPF_KPROBE'
        return ____##name(___bpf_kprobe_args(args));                        \
                          ^
/root/go/src/ebpf-go/step09/bpf_tracing.h:441:2: note: expanded from macro '___bpf_kprobe_args'
        ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
        ^
/root/go/src/ebpf-go/step09/bpf_helpers.h:157:29: note: expanded from macro '___bpf_apply'
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
                            ^
note: (skipping 3 expansions in backtrace; use -fmacro-backtrace-limit=0 to see all)
/root/go/src/ebpf-go/step09/bpf_tracing.h:431:33: note: expanded from macro '___bpf_kprobe_args1'
        ___bpf_kprobe_args0(), (void *)PT_REGS_PARM1(ctx)
                                       ^
/root/go/src/ebpf-go/step09/bpf_tracing.h:341:29: note: expanded from macro 'PT_REGS_PARM1'
#define PT_REGS_PARM1(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
                            ^
<scratch space>:51:6: note: expanded from here
 GCC error "The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb"
     ^
/root/go/src/ebpf-go/step09/tcprtt.c:96:5: error: The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb
/root/go/src/ebpf-go/step09/bpf_tracing.h:461:20: note: expanded from macro 'BPF_KPROBE'
        return ____##name(___bpf_kprobe_args(args));                        \
                          ^
/root/go/src/ebpf-go/step09/bpf_tracing.h:441:2: note: expanded from macro '___bpf_kprobe_args'
        ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
        ^
/root/go/src/ebpf-go/step09/bpf_helpers.h:157:29: note: expanded from macro '___bpf_apply'
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
                            ^
note: (skipping 2 expansions in backtrace; use -fmacro-backtrace-limit=0 to see all)
/root/go/src/ebpf-go/step09/bpf_tracing.h:433:37: note: expanded from macro '___bpf_kprobe_args2'
        ___bpf_kprobe_args1(args), (void *)PT_REGS_PARM2(ctx)
                                           ^
/root/go/src/ebpf-go/step09/bpf_tracing.h:342:29: note: expanded from macro 'PT_REGS_PARM2'
#define PT_REGS_PARM2(x) ({ _Pragma(__BPF_TARGET_MISSING); 0l; })
                            ^
<scratch space>:53:6: note: expanded from here
 GCC error "The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb"
     ^
2 errors generated.
Error: can't execute clang: exit status 1
exit status 1
make: *** [Makefile:16: tcprtt] 오류 1
root@Good:~/go/src/ebpf-go/step09# 
```