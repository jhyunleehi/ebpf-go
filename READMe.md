
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