# Tracing and Visualizing

1. perf
2. /proc 
2. chrom://tracing 
3. perfetto 
4. ftrace 
5. uftrace 

dstat 

## 1. perf : Performance analysis tools for Linux
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

2. make hello trace
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

$ xxd ./hello | header 
```

* gdb를 통한 추적
```
$ gdb  ./hello
(gdb) b main
(gdb) info break 
(gdb) info file
(gdb) info proc
(gdb) info stack
(gdb) info frame
(gdb) info r

(gdb) p message 
 $4 = "hello, world!\n"

(gdb) x/20x  0x0000555555555120  <<-- text segment 
(gdb) disas main
(gdb) x/10x 0x00005555555552d4

```

* user process 추적
```sh
$ struss ./hello
```

이렇게 추적하는 것은 user space에서만 추적인 가능하다. 

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
* -p : process 정보 지정
* -a : 모든 process 정보
* -g : stack 정보 저장 
* -e : 특정 event 저장 
* -F : 분석 frequency 지정 


* hello trace heat map 
```sh
$ sudo perf record  -g -- ./hello
$ perf report --stdio --sort comm,dso,symbol --tui
```
* event 지정 
```sh 
$ sudo perf record  -e cpu-clock -g -- ./hello
$ ll
-rw------- 1 jhyunlee jhyunlee 41138  4월 14 15:00 perf.data
$ sudo  perf report -f

e key
c key
```


### 3. 히트맵 출력:
프로그램 실행 중에 perf를 사용하여 동적으로 히트맵을 출력합니다.

```sh
$ perf record -e cpu-clock  -ag -- sleep 10
$ perf report --stdio --sort comm,dso,symbol --tui
```
결론 ==> 이것은 분석하기 너무 힘들다.


### 4. Flame Graph 
* 설치 방법 
```sh
$ git clone https://github.com/brendangregg/Flamegraph.git
$ sudo perf script | ../Flamegraph/stackcollapse-perf.pl | ../Flamegraph/flamegraph.pl > graph.svg
```
* 흥미로운 결과가 나온다. 
```sh
$ sudo perf record  -ag -- sleep 10
$ sudo perf script | ../Flamegraph/stackcollapse-perf.pl | ../Flamegraph/flamegraph.pl > graph.svg
`
```

* hello flame graph
```sh
$ sudo perf record  -g -- ./hello
$ sudo perf script | ../Flamegraph/stackcollapse-perf.pl | ../Flamegraph/flamegraph.pl > graph.svg
```





### perf와 trace-cmd의 차이점 
### perf:
1. perf는 linux kernel의 일부분으로 성능분석 도구이다.   
2. cpu, memoery, io 등 전반적인 성능 분석을 위한 기능들을 제공한다.  
3. perf can be used for profiling CPU usage, monitoring hardware performance counters, tracing function calls, and more.
4. profiling 방식은 sampling-based profiling, tracing-based profiling 2가지를 지원한다.  
5. perf operates at the system level and can provide insights into both kernel-space and user-space activities.

### trace-cmd:
1. trace-cmd는 Ftrace 시스템과 연동하여 기능을 제공하는 coomand-line tool 이다.  
2. Ftrace는 a built-in Linux kernel tracing framework.
3. It provides a convenient way to control and manage kernel tracing sessions using Ftrace.
4. you can start and stop tracing sessions, configure trace buffers, view trace data, and more.
5. trace-cmd focuses specifically on kernel tracing and provides a higher-level interface compared to using Ftrace directly.












### Quickstart: Record traces on Linux
https://perfetto.dev/docs/quickstart/linux-tracing?_gl=1*15ruz9r*_ga*MTQ3NjY1ODc1NS4xNzEzMDE5NzY0*_ga_BD89KT2P3C*MTcxMzA4OTIwMC4yLjEuMTcxMzA5MTE2NS4wLjAuMA..


Building from source

```sh
1. Check out the code:
$ git clone https://android.googlesource.com/platform/external/perfetto/ && cd perfetto

2. Download and extract build dependencies:
  If the script fails with SSL errors, try upgrading your openssl package.
$ tools/install-build-deps

3. Generate the build configuration
$ tools/gn gen --args='is_debug=false' out/linux
# Or use `tools/setup_all_configs.py` to generate more build configs.

4. Build the Linux tracing binaries (On Linux it uses a hermetic clang toolchain, downloaded as part of step 2):
$ tools/ninja -C out/linux tracebox traced traced_probes perfetto 
```


