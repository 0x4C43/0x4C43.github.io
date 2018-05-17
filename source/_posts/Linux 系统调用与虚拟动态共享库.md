---

title: Linux 系统调用与虚拟动态共享库
date: 2018-05-17 14:35:20
tags: [Linux,系统调用, vsdo]
categories: Linux
keywords: [Linux,系统调用, vsdo]
---

系统调用是应用程序与操作系统间的接口。Linux 下使用 0x80 号中断作为系统调用入口，使用 eax寄存器指定系统调用号，ebx、ecx、edx、esi、edi 和 ebp 用于传递调用参数；Windows 下使用0x2E 号中断作为系统调用入口。

 直接使用系统调用编程有以下弊端：1）系统调用接口过于原始，使用不方便；2）各操作系统间系统调用不兼容。因此，运行库作为操作系统与应用程序间的抽象层可实现源码级的可移植性。

### **0x01 Linux 经典系统调用**

现代操作系统中有用户模式和内核模式两种特权模式。操作系统通过中断从用户态切换到内核态。不同中断具有不同的中断号，一个中断号对应一个中断处理程序。内核中使用中断向量表存放中断处理程序的指针。

操作系统使用一个中断号对应所有的系统调用，如 Linux 下的 0x80 为中断处理程序 system_call 的中断号。不同系统调用函数通过 eax 寄存器传递系统调用号指定。Linux经典系统调用实现如下：

1） 触发中断    
使用 int 0x80 触发系统调用中断。

2） 切换堆栈    

- 从用户态切换到内核态时程序的当前栈也要从用户栈切换到内核栈。具体过程为：
- 将用户态的寄存器 SS、ESP、EFLAGS、CS 和 EIP 压入内核栈；
- 将 SS、ESP 设置为内核栈的相应值。

当从内核态回到用户态时则进行相反的操作。

3） 中断处理程序    
int 0x80 切换了栈之后进入中断处理程序 system_call 进行系统调用。

### **0x02 Linux 快速系统调用机制**

vsyscall 和 vdso 是用于在 Linux 中加速某些系统调用的两种机制。vsyscall 是早期的加速方式，它将部分内核代码放在vsyscall 区域。使得用户态程序可以直接调用简单的系统调用，比如 gettimeofday() 。该方式的问题是 vsyscall 的地址在内存空间中是固定的，并不能被地址随机化。vdso 与 vsyscall 的功能相同，其区别在于 vdso 地址可以被 ASLR 随机化。

vdso 是将部分内核调用映射到用户态的地址空间中，使得调用开销更小。由于使用 sysenter/sysexit 没有特权级别检查的处理，也就没有压栈操作，所以执行速度比 int n/iret 快了不少。

Linux 2.5 之后的版本通过虚拟共享库（Virtual Dynamic Shared Object，vdso）支持 sysenter/sysexit。vsdo 不存在实际的文件，只存在于进程虚拟地址空间中。新版本的 vdso 为 linux-vdso.so.1，而在旧版本系统中为 linux-gate.so.1。 该虚拟库为用户程序以处理器可支持的最快的方式调用系统函数提供了必要的逻辑。vsdo 中导出了一系列函数，其中 `__kernel_vsyscall` 函数负责系统调用。该函数通过 sysenter 进行系统调用。

```sh
➜  syscall ldd getuid_x64
        linux-vdso.so.1 =>  (0x00007fff851e9000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fde9626d000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fde96637000)
➜  syscall ldd getuid_x86_d
        linux-gate.so.1 =>  (0xf7fae000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7ddb000)
        /lib/ld-linux.so.2 (0xf7fb0000)
```

系统调用多被封装成库函数提供给应用程序调用，应用程序调用库函数后，由 glibc 库负责进入内核调用系统调用函数。在 2.4 内核加上旧版的 glibc 的情况下，库函数通过 int 指令来完成系统调用，而内核提供的系统调用接口很简单，只要在 IDT 中提供 int0x80 的入口，库就可以完成中断调用。

在 2.6 内核中，内核代码同时包含了对 int 0x80 中断方式和 sysenter 指令方式调用的支持，因此内核会给用户空间提供一段入口代码，内核启动时根据 CPU 类型，决定这段代码采取哪种系统调用方式。对于 glibc 来说，无需考虑系统调用方式，直接调用这段入口代码，即可完成系统调用。

系统调用会有两种方式，在静态链接（gcc -static）时，采用 `call *_dl_sysinfo`指令；在动态链接时，采用 `call *gs:0x10`指令。用以下示例程序说明这两种情况；

```c++
int main()
{
    getuid();
    return 0;
}
```

#### **1. 静态链接**

首先编译生成静态链接可执行文件，接着使用 gdb 加载，并反编译 main 函数。main 函数中调用 getuid。

```sh
➜  syscall gcc -static -m32 getuid.c -o getuid_x86_s
➜  syscall gdb getuid_x86_s -q
Reading symbols from getuid_x86_s...(no debugging symbols found)...done.

gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0804887c <+0>:     lea    ecx,[esp+0x4]
   0x08048880 <+4>:     and    esp,0xfffffff0
   0x08048883 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048886 <+10>:    push   ebp
   0x08048887 <+11>:    mov    ebp,esp
   0x08048889 <+13>:    push   ecx
   0x0804888a <+14>:    sub    esp,0x4
   0x0804888d <+17>:    call   0x806c730 <getuid>
   0x08048892 <+22>:    mov    eax,0x0
   0x08048897 <+27>:    add    esp,0x4
   0x0804889a <+30>:    pop    ecx
   0x0804889b <+31>:    pop    ebp
   0x0804889c <+32>:    lea    esp,[ecx-0x4]
   0x0804889f <+35>:    ret    
End of assembler dump.
```

反编译 getuid 函数，可看到它通过 eax 传入中断号 0xC7，并调用 `ds:0x80ea9f0`。`ds:0x80ea9f0` 内存处的值指向 `_dl_sysinfo` 函数，并不是内核映射页面的代码。

```sh
gdb-peda$ disassemble 0x806c730
Dump of assembler code for function getuid:
   0x0806c730 <+0>:     mov    eax,0xc7
   0x0806c735 <+5>:     call   DWORD PTR ds:0x80ea9f0
   0x0806c73b <+11>:    ret    
End of assembler dump.

gdb-peda$ telescope 0x80ea9f0
Warning: not running or target is remote
0000| 0x80ea9f0 --> 0x806f0c0 (<_dl_sysinfo_int80>:     int    0x80)
0004| 0x80ea9f4 --> 0x8099bd0 (<_dl_make_stack_executable>:     push   esi)
0008| 0x80ea9f8 --> 0x7
0012| 0x80ea9fc --> 0x37f

gdb-peda$ disassemble 0x806f0c0
Dump of assembler code for function _dl_sysinfo_int80:
   0x0806f0c0 <+0>:     int    0x80
   0x0806f0c2 <+2>:     ret    
End of assembler dump.
```

运行程序，再次查看 `ds:0x80ea9f0` 的值，此时为内核函数`__kernel_vsyscall` 函数的地址，该函数中通过 sysenter 进行系统调用。

```sh
gdb-peda$ telescope 0x80ea9f0
0000| 0x80ea9f0 --> 0xf7ffcdc0 (<__kernel_vsyscall>:    push   ecx)
0004| 0x80ea9f4 --> 0x8099bd0 (<_dl_make_stack_executable>:     push   esi)
0008| 0x80ea9f8 --> 0x6
0012| 0x80ea9fc --> 0x37f
0016| 0x80eaa00 --> 0x3

gdb-peda$ disassemble 0xf7ffcdc0
Dump of assembler code for function __kernel_vsyscall:
   0xf7ffcdc0 <+0>:     push   ecx
   0xf7ffcdc1 <+1>:     push   edx
   0xf7ffcdc2 <+2>:     push   ebp
   0xf7ffcdc3 <+3>:     mov    ebp,esp
   0xf7ffcdc5 <+5>:     sysenter
   0xf7ffcdc7 <+7>:     int    0x80
   0xf7ffcdc9 <+9>:     pop    ebp
   0xf7ffcdca <+10>:    pop    edx
   0xf7ffcdcb <+11>:    pop    ecx
   0xf7ffcdcc <+12>:    ret
```

查看该进程的虚拟内存空间，可看到 `__kernel_vsyscall` 函数在 vdso 区域。

```sh
➜  syscall cat /proc/36067/maps
08048000-080e9000 r-xp 00000000 08:01 796245                             /home/lc/Load/syscall/getuid_x86_s
080e9000-080eb000 rw-p 000a0000 08:01 796245                             /home/lc/Load/syscall/getuid_x86_s
080eb000-0810e000 rw-p 00000000 00:00 0                                  [heap]
f7ff9000-f7ffc000 r--p 00000000 00:00 0                                  [vvar]
f7ffc000-f7ffe000 r-xp 00000000 00:00 0                                  [vdso]
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```

#### **2. 动态链接**

使用以下命令编译动态链接可执行文件，并使用 gdb 加载程序。

```
➜  syscall gcc -m32 getuid.c -o getuid_x86_d
➜  syscall gdb getuid_x86_d
```

运行程序后查看 main 函数和 getuid 函数的指令如下，getuid 函数中使用 eax 传入系统调用号，并通过 `gs: 010` 进行系统调用。

```
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0804840b <+0>:     lea    ecx,[esp+0x4]
   0x0804840f <+4>:     and    esp,0xfffffff0
   0x08048412 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048415 <+10>:    push   ebp
   0x08048416 <+11>:    mov    ebp,esp
   0x08048418 <+13>:    push   ecx
=> 0x08048419 <+14>:    sub    esp,0x4
   0x0804841c <+17>:    call   0x80482e0 <getuid@plt>
   0x08048421 <+22>:    mov    eax,0x0
   0x08048426 <+27>:    add    esp,0x4
   0x08048429 <+30>:    pop    ecx
   0x0804842a <+31>:    pop    ebp
   0x0804842b <+32>:    lea    esp,[ecx-0x4]
   0x0804842e <+35>:    ret    
End of assembler dump.

gdb-peda$ disassemble getuid
Dump of assembler code for function getuid:
   0xf7eb5270 <+0>:     mov    eax,0xc7
   0xf7eb5275 <+5>:     call   DWORD PTR gs:0x10
   0xf7eb527c <+12>:    ret    
End of assembler dump.
```

---

References:   
[1] [
Linux 2.6 对新型 CPU 快速系统调用的支持](https://www.ibm.com/developerworks/cn/linux/kernel/l-k26ncpu/index.html)     
[2] 《程序员的自我修养》
