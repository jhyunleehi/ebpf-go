# Tracing and Visualizing

1. perf
2. /proc 
2. chrom://tracing 
3. perfetto 
4. ftrace 
5. uftrace 

dstat 

## 1. perf - Performance analysis tools for Linux
perf는 리눅스 시스템에서의 성능 분석과 프로파일링을 위한 강력한 도구입니다. 이를 사용하면 CPU 사용량, 메모리 액세스, 함수 호출 및 여러 다른 이벤트를 추적하여 시스템의 동작을 분석할 수 있습니다.

1. perf 

```sh
$ sudo apt install linux-tools
$ sudo apt install linux-cloud-tools 
$ sudo perf list 
$ sudo perf list | grep  sys_enter_openat
  syscalls:sys_enter_openat                          [Tracepoint event]
  syscalls:sys_enter_openat2                         [Tracepoint event]
```

2. make hello
```sh
$ gcc -g -pg  -o hello hello.c
$ ldd hello
	linux-vdso.so.1 (0x00007ffc91b67000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x000072f894800000)
	/lib64/ld-linux-x86-64.so.2 (0x000072f894a5f000)

$ file  hello
hello: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=950f5919b87ec318f94ac423ef161d968cb7c6a9, for GNU/Linux 3.2.0, with debug_info, not stripped

$ readelf  -l hello

$ objdump -d hello

$ gdb  ./hello

(gdb) info file
(gdb) info proc
(gdb) info stack
(gdb) info frame
(gdb) info r

(gdb) p message  ==> $4 = "hello, world!\n"

(gdb) x/20x  0x0000555555555120  <<-- text segment 
(gdb) disas main
(gdb) x/10x 0x00005555555552d4


$ xxd ./hello | header 
```

### perf command 

### 1. cpu event 분석
CPU의 instruction retired 이벤트를 추적하여 프로그램의 명령어 실행 수를 확인할 수 있습니다.

```sh
$ sudo perf stat -e instructions  ./hello

 Performance counter stats for './hello':

         1,438,114      instructions                                                          

       0.001684180 seconds time elapsed

       0.001680000 seconds user
       0.000000000 seconds sys

```


### 2. Profiling 
프로그램 실행 시간을 추적하여 코드에서 시간이 가장 많이 소비되는 함수를 확인할 수 있습니다.

```sh
$ sudo perf record -e cpu-clock -g -- ./hello
$ ll
합계 84
drwxrwxr-x 2 jhyunlee jhyunlee  4096  4월 14 15:00 ./
drwxrwxr-x 4 jhyunlee jhyunlee  4096  4월 14 13:56 ../
-rw-rw-r-- 1 jhyunlee jhyunlee  2599  4월 14 15:00 gmon.out
-rwxrwxr-x 1 jhyunlee jhyunlee 19472  4월 14 14:22 hello*
-rw-rw-r-- 1 jhyunlee jhyunlee   361  4월 14 14:20 hello.c
-rw-rw-r-- 1 jhyunlee jhyunlee   353  4월 14 15:00 output.txt
-rw------- 1 jhyunlee jhyunlee 41138  4월 14 15:00 perf.data
$ sudo  perf report -f
```

### 3. 히트맵 출력:
프로그램 실행 중에 perf를 사용하여 동적으로 히트맵을 출력합니다.

```sh
$ perf record -e cpu-clock  -ag -- sleep 10
$ perf report --stdio --sort comm,dso,symbol --tui
```
결론 ==> 이것은 분석하기 너무 힘들다.


### Flame Graph 

```sh
$ git clone https://github.com/brendangregg/Flamegraph.git

```
