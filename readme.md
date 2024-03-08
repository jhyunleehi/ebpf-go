
### dependencies

* Linux kernel version 5.7 or later, for bpf_link support
* LLVM 11 or later 1 (clang and llvm-strip)
* libbpf headers 2
* Linux kernel headers 3
* Go compiler version supported by ebpf-go's Go module

### install package and heade file 

* clang --version 
* apt install libbpf-dev
* apt install linux-headers-amd64
* ln -sf /usr/include/asm-generic/ /usr/include/asm

### run vscode sudo 

```
root@Good:~# cat .profile 
export PATH=$PATH:/usr/local/go/bin

root@Good:~/go/src/ebpf# cat code.sh
sudo code --no-sandbox --user-data-dir=/root/.config/vscode_data
```

### cross compile 
bpf2go가 두 개의 파일 세트
*_bpfel.o*_bpfel.goamd64, arm64, riscv64 및 loong64와 같은 리틀 엔디안 아키텍처의 경우
*_bpfeb.o*_bpfeb.gos390(x), mips 및 sparc와 같은 빅엔디안 아키텍처의 경우


#### make error 
* libbpf libary compile and install 

```sh
root@Good:~/go/src/ebpf-go/step01# make
clang \
    -target bpf \
        -D __TARGET_ARCH_x86 \
    -Wall \
    -O2 -g -o counter.bpf.o -c counter.bpf.c
llvm-strip -g counter.bpf.o
bpftool gen skeleton counter.bpf.o > counter.skel.h
gcc -Wall -o counter counter.c -L../libbpf/src -l:libbpf.a -lelf -lz
In file included from counter.c:5:
counter.c:12:13: error: expected ‘=’, ‘,’, ‘;’, ‘asm’ or ‘__attribute__’ before ‘#pragma’
   12 | } pkt_count SEC(".maps");
      |             ^~~
counter.c:12:13: error: expected identifier or ‘(’ before ‘#pragma’
   12 | } pkt_count SEC(".maps");
      |             ^~~
counter.c:15:1: error: expected identifier or ‘(’ before ‘#pragma’
   15 | SEC("xdp")
      | ^~~
counter.c:26:18: error: expected ‘=’, ‘,’, ‘;’, ‘asm’ or ‘__attribute__’ before ‘#pragma’
   26 | char __license[] SEC("license") = "Dual MIT/GPL";
      |                  ^~~
counter.c:26:18: error: expected identifier or ‘(’ before ‘#pragma’
   26 | char __license[] SEC("license") = "Dual MIT/GPL";
      |                  ^~~
make: *** [Makefile:12: counter] 오류 1
```
==>

* reinstall libbpf
```
$ git clone --recurse-submodules https://github.com/lizrice/learning-ebpf
$ cd learning-ebpf/libbpf/src
$ sudo make install
```


#### llvm-readelf
```
root@Good:~/go/src/ebpf-go/step03# readelf -SW s3.bpf.o
There are 11 section headers, starting at offset 0x3b0:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .strtab           STRTAB          0000000000000000 000352 000057 00      0   0  1
  [ 2] .text             PROGBITS        0000000000000000 000040 000000 00  AX  0   0  4
  [ 3] socket            PROGBITS        0000000000000000 000040 000010 00  AX  0   0  8
  [ 4] .maps             PROGBITS        0000000000000000 000050 000020 00  WA  0   0  8
  [ 5] .BTF              PROGBITS        0000000000000000 000070 0001fb 00      0   0  4
  [ 6] .rel.BTF          REL             0000000000000000 000320 000010 10   I 10   5  8
  [ 7] .BTF.ext          PROGBITS        0000000000000000 00026c 000050 00      0   0  4
  [ 8] .rel.BTF.ext      REL             0000000000000000 000330 000020 10   I 10   7  8
  [ 9] .llvm_addrsig     LOOS+0xfff4c03  0000000000000000 000350 000002 00   E  0   0  1
  [10] .symtab           SYMTAB          0000000000000000 0002c0 000060 18      1   2  8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)  
```

```
# readelf --section-details --headers .output/opensnoop.bpf.o -W
```

#### llvm-objdump 
```
root@Good:~/go/src/ebpf-go/step03# llvm-objdump -SD  s3.bpf.o 

s3.bpf.o:       file format elf64-bpf

```

## bpftool 
* bpftool prog show id 540
* bpftool prog show name hello
* bpftool prog show tag d35b94b4c0c10efb
* bpftool prog show pinned /sys/fs/bpf/hello
* bpftool prog dump xlated name hello
* bpftool prog show id 487 --pretty
* bpftool prog list
* bpftool prog list name hello
* bpftool prog load hello.bpf.o  /sys/fs/bpf/hello
* bpftool prog load hello-func.bpf.o /sys/fs/bpf/hello
* bpftool prog load hello.bpf.o /sys/fs/bpf/hello
* bpftool prog show id 487 --pretty
* bpftool prog show name hello
* bpftool prog dump xlated name hello
* bpftool prog dump xlated name hello
* bpftool prog trace log
* bpftool prog trace log
* bpftool prog show name hello
* bpftool map list
* bpftool map show id $MAP_ID
* bpftool map dump id $MAP_ID
* bpftool map show id $MAP_ID 
* bpftool map lookup id $MAP_ID key 100 0 0 0 0 0 0 0
* bpftool map lookup id $MAP_ID key 105  0 0 0 0 0 0 0
* bpftool map lookup id $MAP_ID key 0x64 0 0 0 0 0 0 0
* bpftool map lookup id $MAP_ID key hex 64 0 0 0 0 0 0 0
* bpftool map update  id $MAP_ID key 255 0 0 0 0 0 0 0 value 255 0 0 0 0 0 0 0
* bpftool map dump name hello.rodata
* bpftool gen skeleton hello-buffer-config.bpf.o > hello-buffer-config.skel.h
* bpftool net list
* bpftool net detach xdp  dev lo
* bpftool net attach xdp name hello dev lo



## go mod env 

Go 환경 설정에서  

root 디렉토리에서  go.mod

```sh
module ebpf-go
go 1.22.0
```

각 개별 디렉토리에서 main 패키지

ebpf-go/fenty  디렉토리에서 main 패키지 설정하려면 

go.mod 파일 설정 필요 

```sh
module ebpf-go/fentry

go 1.22.0

require github.com/cilium/ebpf v0.13.2

require (
golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
golang.org/x/sys v0.15.0 // indirect
)

```

#### fentry

eBPF (Extended Berkeley Packet Filter)는 리눅스 커널 내에서 안전하게 실행되는 프로그램을 삽입하여 네트워크 처리, 보안, 추적 및 다른 작업을 위한 기능을 확장하는 기술입니다. eBPF는 프로그램을 컴파일하여 커널에 주입하고, 이를 이용하여 커널 내의 다양한 동작을 확장할 수 있습니다.

여기서 "fentry"는 eBPF의 한 유형의 프로그램이며, "fentry"는 "function entry"를 의미합니다. 즉, 이 프로그램은 함수가 호출될 때 발생하는 이벤트를 가로채고 처리하는 용도로 사용됩니다.

"fentry" 프로그램은 주로 함수 호출 시에 발생하는 이벤트를 모니터링하거나 트레이싱할 때 사용됩니다. 예를 들어, 네트워크 스택에서 특정 함수가 호출될 때마다 호출되는 시간을 측정하거나, 특정 시스템 호출이 얼마나 자주 발생하는지 확인할 때 사용될 수 있습니다.

eBPF의 "fentry" 프로그램은 주로 프로그램 실행 중 함수 호출의 흐름을 추적하고, 이를 통해 성능 프로파일링, 디버깅, 보안 검사 등 다양한 용도로 활용됩니다.


#### ebpf.o object file read 
```go
// Do not access this directly.
//
//go:embed fentry_bpfel.o
var _FentryBytes []byte
```

ChatGPT
The code snippet you've provided contains a directive comment //go:embed followed by a variable declaration. This syntax is used in Go 1.16 or later to embed files directly into the Go binary at compile time.

Here's what this snippet does:

//go:embed fentry_bpfel.o: This is a directive comment telling the Go compiler to embed the file named fentry_bpfel.o into the Go binary.
var _FentryBytes []byte: This declares a variable _FentryBytes of type []byte. The leading underscore _ is used to indicate that this variable is not meant to be directly accessed by the code.
So, essentially, this code embeds the contents of the file fentry_bpfel.o into the Go binary as a byte slice named _FentryBytes, making it accessible within the Go program. However, since the variable name starts with an underscore, it is not intended to be accessed directly by other parts of the code. Instead, it is typically used by other parts of the program that need access to the embedded file's contents.




## tool 
### kprobe event 어떻게 발견하는가?
* kprobe 
```sh
$ sudo apt install linux-tools-common
$ sudo apt install linux-tools-generic
$ sudo apt install linux-tools-6.5.0-18-generic
$ sudo apt install trace-cmd
$ sudo trace-cmd list -l | grep  exec
workqueue:workqueue_execute_end
workqueue:workqueue_execute_start
sched:sched_process_exec
sched:sched_kthread_work_execute_end
sched:sched_kthread_work_execute_start
syscalls:sys_exit_kexec_load
syscalls:sys_enter_kexec_load
syscalls:sys_exit_kexec_file_load
syscalls:sys_enter_kexec_file_load
syscalls:sys_exit_execveat
syscalls:sys_enter_execveat
syscalls:sys_exit_execve
syscalls:sys_enter_execve
writeback:writeback_exec
libata:ata_exec_command
```
### ftrace 가능한 커널 함수 목록
```sh
root@Good:/sys/kernel/debug/tracing# grep  blk_account_io  avail*
available_filter_functions:blk_account_io_merge_bio
available_filter_functions:blk_account_io_completion.part.0
available_filter_functions_addrs:ffffffff87f77a90 blk_account_io_merge_bio
available_filter_functions_addrs:ffffffff87f7b5b0 blk_account_io_completion.part.0
```

### trace argement format 
*  /sys/kernel/debug/tracing/events/random/urandom_read/format 디렉토리에서  format 파일을 통해 argument format를 찾을 수 있다.  

```c
// from /sys/kernel/debug/tracing/events/random/urandom_read/format
struct urandom_read_args {    
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};
```

### trace-cmd
```
$ sudo trace-cmd list | grep bio
block:block_bio_remap
block:block_bio_queue
block:block_bio_frontmerge
block:block_bio_backmerge
block:block_bio_bounce
block:block_bio_complete
```

### SYSCALL 목록 확인
* 현재 kernel의 system call 목록과 이름 확인 
```
$ grep   __SYSCALL /usr/include/asm-generic/unistd.h
$ grep   clone  /usr/include/asm-generic/unistd.h

#define __NR_clone 220
__SYSCALL(__NR_clone, sys_clone)
#define __NR_clone3 435
__SYSCALL(__NR_clone3, sys_clone3)

```
### 커널 심볼 
```
$ cat /proc/kallsyms | grep blk_account_io_done
```

### iotop 
```
source code
```

### BPF_HASH
* 제일 궁금한 것은 BPF_HASH(counter_table) 이것이 어디에 정의 되어 있는가?
* BPF_HASH() is a BCC macro that defines a hash table map. 라고 하는데 어디에 정의되어 있는지를 모르겠네..
* 무슨 소스 코드가 이렇게 되어 있냐?
  - You can navigate to the src/cc directory and find the bpf_helpers.h file where the BPF_HASH() macro is defined
  - The source code for the BPF_HASH() macro in BCC (BPF Compiler Collection) can be found in the BCC GitHub repository. 
  - BCC is an open-source project, and its source code is hosted on GitHub. 
  - You can find the definition of the BPF_HASH() macro in the bpf_helpers.h header file within the BCC repository.
  - 이것이 macro 인데 실제 파일에 가서 보면  
* bcc repository에서  소스 코드가 이렇게 되어 있는 것은 무엇을 의미하냐 ?  R"********(  
이런 사연이 있었구만 ...

소스 코드가 `R"********(`와 같은 형태로 시작되는 것은 C++11부터 도입된 Raw String Literal 문법을 나타냅니다. 이 문법을 사용하면 문자열을 이스케이프 문자 없이 그대로 표현할 수 있습니다. "********"는 임의의 종료 문자열로, 소스 코드 내에서 나오는 문자열이 이 문자열로 끝나는 것을 나타냅니다.

`bcc/src/export/helpers.h` 에 정의된 내용 을 보면 BPF_F_TABLE macro로 정의한 것을 사용한다. 

```c
R"********(

#define BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, _flags) \
struct _name##_table_t { \
  _key_type key; \
  _leaf_type leaf; \
  _leaf_type * (*lookup) (_key_type *); \
  _leaf_type * (*lookup_or_init) (_key_type *, _leaf_type *); \
  _leaf_type * (*lookup_or_try_init) (_key_type *, _leaf_type *); \
  int (*update) (_key_type *, _leaf_type *); \
  int (*insert) (_key_type *, _leaf_type *); \
  int (*delete) (_key_type *); \
  void (*call) (void *, int index); \
  void (*increment) (_key_type, ...); \
  void (*atomic_increment) (_key_type, ...); \
  int (*get_stackid) (void *, u64); \
  void * (*sk_storage_get) (void *, void *, int); \
  int (*sk_storage_delete) (void *); \
  void * (*inode_storage_get) (void *, void *, int); \
  int (*inode_storage_delete) (void *); \
  void * (*task_storage_get) (void *, void *, int); \
  int (*task_storage_delete) (void *); \
  u32 max_entries; \
  int flags; \
}; \
__attribute__((section("maps/" _table_type))) \
struct _name##_table_t _name = { .flags = (_flags), .max_entries = (_max_entries) }; \
BPF_ANNOTATE_KV_PAIR(_name, _key_type, _leaf_type)



#define BPF_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries) \
BPF_F_TABLE(_table_type, _key_type, _leaf_type, _name, _max_entries, 0)


#define BPF_HASH1(_name) \
  BPF_TABLE("hash", u64, u64, _name, 10240)
#define BPF_HASH2(_name, _key_type) \
  BPF_TABLE("hash", _key_type, u64, _name, 10240)
#define BPF_HASH3(_name, _key_type, _leaf_type) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, 10240)
#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  BPF_TABLE("hash", _key_type, _leaf_type, _name, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME


// Define a hash function, some arguments optional
// BPF_HASH(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3, BPF_HASH2, BPF_HASH1)(__VA_ARGS__)

```



##  kprobe  and  ftrace (/sys/kernel/debug/tracing) 차이점 

When learning about the Linux kernel, understanding the difference between Kprobes and Ftrace can be crucial, as they are both tools used for kernel debugging and tracing, but they serve different purposes and operate at different levels of the kernel.

Kprobes: Kprobes is a dynamic kernel debugging mechanism that allows developers to insert breakpoints (probes) into running kernel code. These probes can be used to monitor the execution flow of the kernel, gather information about specific events, or debug kernel code without requiring recompilation or rebooting the system. Kprobes allows developers to attach "probe handlers" to specific locations in the kernel code, which are executed when the probe is hit. This mechanism is particularly useful for debugging complex kernel issues or analyzing kernel behavior in real-time.

Ftrace: Ftrace, on the other hand, is a kernel tracing framework that provides a set of tools for tracing various kernel events and functions. It allows developers to dynamically instrument the kernel to collect detailed information about its behavior, such as function call traces, context switches, interrupt activity, and more. Ftrace provides a powerful interface for analyzing kernel performance, identifying bottlenecks, and diagnosing issues. It consists of several components, including function tracer, function graph tracer, event tracer, and tracepoints. Ftrace is typically used for performance analysis, optimization, and understanding kernel internals.

Here's a summary of the key differences between Kprobes and Ftrace:


#### Purpose: 
* kprobe : 커널 코드에 대한 동적 디버깅하기 위해서 handler 커널에 코드를 집어 넣는 것
* ftrace : 커널 활동을 tracing 하고 성능을 분석하기위한 것
* Kprobes is primarily used for dynamic kernel debugging by inserting probes into running kernel code to monitor specific events or gather information
* Ftrace is used for tracing kernel activities and performance analysis.

#### Granularity: 
* kprobe : instruction level에서 커널의 동작을 확인하기 위해서 디거깅용 코그를 넣기 때문에 더 작은 단위
* ftrace : 좀더 high level에서  system  call, event 등을 tracing 하는 것 
* Kprobes operates at the instruction level, allowing developers to insert probes at specific locations within kernel code
* Ftrace operates at a higher level, tracing function calls, events, and system activities.

#### Flexibility: 
* kprobe : 커널 코드에 대한 세밀한 제어를 할 수 있다. 
* ftrace : 추적 기능과 분석 도구가 내장된 framework 
* Kprobes provides fine-grained control over the instrumentation of kernel code and allows developers to specify custom probe handlers
* Ftrace provides a more high-level tracing framework with built-in tracing capabilities and analysis tools.

#### Use Cases: 
* kprobe : 커널의 특정한 이슈에 대한 디버깅, 커널 개발자가 사용하는 도구
* ftrace :  성능 분석 및 최적화 커널의 전반적 동작을 이해하는데 사용 
* Kprobes is typically used for debugging specific kernel issues or analyzing kernel behavior in real-time
* Ftrace is used for performance analysis, optimization, and understanding the overall behavior of the kernel.

In summary, while both Kprobes and Ftrace are powerful tools for kernel debugging and tracing, they serve different purposes and offer different levels of granularity and flexibility. Developers may choose to use one or both of these tools depending on their specific debugging and tracing requirements.


## 결론 
* 커널 수준의 개발자가 이슈 디버깅을 위해서는 kprobe를 사용하는 것이 맞고 
    - BPF: kbpobes
    - BPF: kretprobe
* 성능 분석 및 모니터링 정도를 하려면 ftrace를 이용한 eBPF를 사용하는 것이 맞다.  
    - BPF: tracepoint 
```
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

## ftrace에서 함수호출, event 추적

### 1.available_events 
* 커널 내에서 추적에 사용할 수 있는 이벤트를 나타냅니다. 
* 이러한 이벤트는 다양한 함수 호출, 스케줄러 이벤트, 인터럽트 또는 커널 내의 기타 추적 가능한 활동일 수 있습니다. 
* available_events이러한 이벤트는 일반적으로 추적 디렉터리( )의 파일 에 나열됩니다 /sys/kernel/debug/tracing/. 
* 런타임 중에 발생하는 이벤트에 대한 정보를 수집하기 위해 이러한 이벤트에 대한 추적을 활성화할 수 있습니다.
```
root@Good:/sys/kernel/debug/tracing# cat available_events  | grep openat
syscalls:sys_exit_openat2
syscalls:sys_enter_openat2
```

### 2. available_filter_functions
* 추적 데이터를 필터링하는 데 사용할 수 있는 커널 내의 함수입니다. 
* 이러한 기능은 추적 범위를 커널 내의 특정 관심 영역으로 좁히는 데 도움이 될 수 있습니다. 
* available_filter_functions추적 디렉터리의 파일 에 나열되는 경우가 많습니다 . 이러한 함수를 사용하여 함수 이름, 모듈 이름 또는 기타 속성과 같은 특정 기준에 따라 이벤트를 필터링할 수 있습니다.
```
root@Good:/sys/kernel/debug/tracing# cat available_filter_functions | grep openat2
__audit_openat2_how
do_sys_openat2
__x64_sys_openat2
__ia32_sys_openat2
io_openat2_prep
io_openat2
```

### 3. available_filter_functions_addrs : 
*available_filter_functions와 유사하지만 함수 이름을 나열하는 대신 커널 내 함수의 주소를 제공합니다. 이는 이름이 아닌 함수 주소를 기준으로 필터링해야 하는 경우 유용할 수 있습니다.
```
root@Good:/sys/kernel/debug/tracing# cat available_filter_functions_addrs | grep openat2
ffffffff87a46340 __audit_openat2_how
ffffffff87ca95c0 do_sys_openat2
ffffffff87ca97e0 __x64_sys_openat2
ffffffff87ca9820 __ia32_sys_openat2
ffffffff87fd3c10 io_openat2_prep
ffffffff87fd3cb0 io_openat2
```
### 4. available_tracers : 
* 파일 available_tracers에는 커널에서 사용할 수 있는 추적 프로그램이 나열되어 있습니다. 
* 추적 프로그램의 예로는 함수 추적 프로그램, 함수 그래프 추적 프로그램, 이벤트 추적 프로그램 등이 있습니다.
* 추적 프로그램은 ftrace커널 내의 특정 이벤트 또는 함수 호출에 대한 추적 데이터를 캡처할 수 있는 메커니즘입니다. 추적 프로그램마다 기능과 오버헤드가 다릅니다. 
```
root@Good:/sys/kernel/debug/tracing# cat available_tracers 
timerlat osnoise hwlat blk mmiotrace function_graph wakeup_dl wakeup_rt wakeup function no
```


## tracing with ftrace

### tracer 설정
ftrace는 nop, function, graph_function 트레이서를 제공합니다.
* nop: 기본 트레이서입니다. ftrace 이벤트만 출력합니다.**
* function: 함수 트레이서입니다. set_ftrace_filter로 지정한 함수를 누가 호출하는지 출력합니다.**
* graph_function: 함수 실행 시간과 세부 호출 정보를 그래프 포맷으로 출력합니다.**
```
root@raspberrypi:/sys/kernel/debug/tracing# cat current_tracer
nop
```
#### event trace.sh
```sh
#!/bin/bash
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/events/enable
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_wakeup/enable
echo 1 > /sys/kernel/debug/tracing/events/sched/sched_switch/enable
echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_entry/enable
echo 1 > /sys/kernel/debug/tracing/events/irq/irq_handler_exit/enable
echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/enable
echo 1 > /sys/kernel/debug/tracing/options/func_stack_trace
echo 1 > /sys/kernel/debug/tracing/options/sym-offset
echo 1 > /sys/kernel/debug/tracing/tracing_on
```
###  set_ftrace_filter 설정
* set_ftrace_filter 파일에 트레이싱하고 싶은 함수를 지정하면 된다.
* 위의 tracer 설정의 function 혹은 function_graph으로 설정한 경우 작동하는 파일이다.
* 리눅스 커널에 존재하는 모든 함수를 필터로 지정할 수는 없다.
* /sys/kernel/debug/tracing/available_filter_functions 파일에 포함된 함수만 지정할 수 있다.
* 함수를 지정하지 않은 경우 모든 함수를 트레이싱하게 되어 락업이 상태에 빠지게 된다.
* available_filter_functions 파일에 없는 함수를 지정하려도 락업 상태가 될 수 있으니 주의하자.
* set_ftrace_filter에 아무것도 설정하지 않고 ftrace를 키면, ftrace는 모든 커널 함수에 대하여 트레이싱을 한다.
* 모든 커널 함수에 의해 트레이스가 발생되면, 그 오버헤드가 엄청나 시스템은 락업 상태에 빠진다.
* 그러므로 부팅 이후 절대 불리지 않을 함수secondary_start_kernel2를 트레이스 포인트로 찍어준다.

### kernel함수 trace (file open,read,write,close)
```sh
#!/bin/bash
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/events/enable
echo function > /sys/kernel/debug/tracing/current_tracer
echo do_sys_openat2  > /sys/kernel/debug/tracing/set_ftrace_filter
echo ksys_read   >> /sys/kernel/debug/tracing/set_ftrace_filter
echo ksys_write  >> /sys/kernel/debug/tracing/set_ftrace_filter
echo close_fd  >> /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/options/func_stack_trace
echo 1 > /sys/kernel/debug/tracing/options/sym-offset
echo 1 > /sys/kernel/debug/tracing/tracing_on
```
```sh
#!/bin/bash
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/events/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
cp  /sys/kernel/debug/tracing/trace ftrace.log
```




#### trace-cmd
* interacts with ftrace linuc kernel internal tracer
* ftrace front utility

```c
# apt  install trace-cmd
# trace-cmd  record -p function ./hello
# trace-cmd  record -p function ./hello  
# trace-cmd  record -p function-graph ./hello  
# trace-cmd  record -p function ./hello  
# trace-cmd  repoort >t.log  
```

### perf stat
```log
root@gpu-1:~# perf stat ./hello
 Performance counter stats for './hello':
              0.49 msec task-clock                       #    0.541 CPUs utilized            
                 0      context-switches                 #    0.000 /sec                      
                 0      cpu-migrations                   #    0.000 /sec                      
                63      page-faults                      #  127.476 K/sec                    
         2,048,928      cycles                           #    4.146 GHz                      
         1,376,140      instructions                     #    0.67  insn per cycle            
           245,301      branches                         #  496.350 M/sec                    
             8,908      branch-misses                    #    3.63% of all branches          
       0.000914125 seconds time elapsed
       0.000985000 seconds user
       0.000000000 seconds sys
```

## tracing with uftrace
```sh
$ gdb  ./hello
(gdb) list
(gdb) break 5
(gdb) run
(gdb) info frame
(gdb) info files
(gdb) info local
(gdb) info proc
(gdb) info break
(gdb) print VAL
(gdb) display i
(gdb) disas main
$ stat ./hello
$ perf record -a -g  ./hello
$ perf report --header  -F overhead,comm,parent
$ perf stat ./hello
$ strace ./hello
$ stat  ./hello
$ sudo uftrace -K 5 ./hello
$ sudo uftrace record -K 5 ./hello
$ sudo uftrace tui
```