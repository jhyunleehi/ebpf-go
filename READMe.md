
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

// Do not access this directly.
//
//go:embed fentry_bpfel.o
var _FentryBytes []byte
ChatGPT
The code snippet you've provided contains a directive comment //go:embed followed by a variable declaration. This syntax is used in Go 1.16 or later to embed files directly into the Go binary at compile time.

Here's what this snippet does:

//go:embed fentry_bpfel.o: This is a directive comment telling the Go compiler to embed the file named fentry_bpfel.o into the Go binary.
var _FentryBytes []byte: This declares a variable _FentryBytes of type []byte. The leading underscore _ is used to indicate that this variable is not meant to be directly accessed by the code.
So, essentially, this code embeds the contents of the file fentry_bpfel.o into the Go binary as a byte slice named _FentryBytes, making it accessible within the Go program. However, since the variable name starts with an underscore, it is not intended to be accessed directly by other parts of the code. Instead, it is typically used by other parts of the program that need access to the embedded file's contents.



