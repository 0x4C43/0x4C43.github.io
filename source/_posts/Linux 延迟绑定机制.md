---
title: Linux 延迟绑定机制
date: 2018-04-29 21:05:02
tags: [PLT, Lazy Binding]
categories: Linux
keywords: [PLT, Lazy Binding]
---

如果使用动态链接方式生成的程序模块中使用大量的函数引用，在程序执行时会花费大量的时间用于模块间函数引用的符号查找和重定位，导致程序性能下降。由于程序中可能存在部分不常用的功能模块，那么在程序开始执行时就完成所有函数的链接工作将会是一种浪费。因此，Linux 系统采用延迟绑定机制优化动态链接程序的符号重定位过程。

### **0x01 延迟绑定原理**
延迟绑定是当函数第一次被调用的时候才进行绑定（包括符号查找、重定位等），如果函数不被调用就不进行绑定。延迟绑定机制可以大大加快程序的启动速度，特别有利于一些引用了大量函数的程序。
>GOT（Global Offset Table，全局偏移表）    
GOT 是数据段用于地址无关代码的 Linux ELF 文件中确定全局变量和外部函数地址的表。ELF 中有 .got 和 .plt.got 两个 GOT 表，.got 表用于全局变量的引用地址，.got.plt 用于保存函数引用的地址。  
>   
>PLT（Procedure Linkage Table，程序链接表）    
PLT 是 Linux ELF 文件中用于延迟绑定的表。

下面介绍延迟绑定的基本原理。假设程序中调用 func 函数，该函数在 .plt 段中相应的项为 func@plt，在 .got.plt 中相应的项为 func@got，链接器在初始化时将 func@got 中的值填充为 “preapre resolver” 指令处的地址。func@plt 的伪代码如下：
```C
func@plt:
jmp *(func@got)
prepare resolver
jmp _dl_runtime_resolve
```
#### **1. 首次调用**
第一次调用 func 函数时，首先会跳转到 PLT 执行 `jmp *(func@got)`，由于该函数没被调用过，func@got 中的值不是 func 函数的地址，而是 PLT 中的 “preapre resolver” 指令的地址，所以会跳转到 “preapre resolver” 执行，接着会调用 \_dl_runtime_resolve 解析 func 函数的地址，并将该函数真正的地址填充到 func@got，最后跳转到 func 函数继续执行代码。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-29/78087498.jpg)    

#### **2. 非首次调用**
当再次调用 func 函数时，由于 func@got 中已填充正确的函数地址，此时执行 PLT 中的 `jmp *(func@got)` 即可成功跳转到 func 函数中执行。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-29/26402902.jpg)    

### **0x02 实例调试**
下面通过调试程序中 func 函数的调用过程说明延迟绑定的原理。首先函数执行 call 指令调用 func 函数时会跳转到 0x8048420（func@plt）处执行。
```C
[-------------------------------------code-------------------------------------]
   0x8048546 <main+11>: mov    ebp,esp
   0x8048548 <main+13>: push   ecx
   0x8048549 <main+14>: sub    esp,0x4
=> 0x804854c <main+17>: call   0x8048420 <func@plt>
   0x8048551 <main+22>: nop
   0x8048552 <main+23>: add    esp,0x4
   0x8048555 <main+26>: pop    ecx
   0x8048556 <main+27>: pop    ebp
Guessed arguments:
arg[0]: 0xf7fb33dc --> 0xf7fb41e0 --> 0x0
arg[1]: 0xffffced0 --> 0x1
arg[2]: 0x0
```
接着跳转到 ds[0x804a010]（func@got）处，由于是第一次调用该函数，func@got 中的地址并非函数的真实地址，需要对其进行地址重定位。
```C
[-------------------------------------code-------------------------------------]
   0x8048410 <__libc_start_main@plt>:   jmp    DWORD PTR ds:0x804a00c
   0x8048416 <__libc_start_main@plt+6>: push   0x0
   0x804841b <__libc_start_main@plt+11>:        jmp    0x8048400
=> 0x8048420 <func@plt>:        jmp    DWORD PTR ds:0x804a010
 | 0x8048426 <func@plt+6>:      push   0x8
 | 0x804842b <func@plt+11>:     jmp    0x8048400
 | 0x8048430:   jmp    DWORD PTR ds:0x8049ffc
 | 0x8048436:   xchg   ax,ax
 |->   0x8048426 <func@plt+6>:  push   0x8
       0x804842b <func@plt+11>: jmp    0x8048400
       0x8048430:       jmp    DWORD PTR ds:0x8049ffc
       0x8048436:       xchg   ax,ax
                                                                  JUMP is taken
```
0x804a010 是 func 函数的重定位偏移，即重定位表中 func 函数的重定位入口。此时 0x804a010（func@got）中的地址为 0x8048426，即 PLT 中准备进行地址解析的指令地址。
```C
readelf -r test_lib1

Relocation section '.rel.plt' at offset 0x3c0 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a010  00000407 R_386_JUMP_SLOT   00000000   func

gdb-peda$ telescope 0x804a010
0000| 0x804a010 --> 0x8048426 (<func@plt+6>:    push   0x8)
0004| 0x804a014 --> 0x0
0008| 0x804a018 --> 0x0
```
程序跳转到 0x8048426 后，又经过 2 次跳转到 ds[0x804a008] 处执行。
```C
[-------------------------------------code-------------------------------------]
   0x804841b <__libc_start_main@plt+11>:        jmp    0x8048400
   0x8048420 <func@plt>:        jmp    DWORD PTR ds:0x804a010
   0x8048426 <func@plt+6>:      push   0x8
=> 0x804842b <func@plt+11>:     jmp    0x8048400
 | 0x8048430:   jmp    DWORD PTR ds:0x8049ffc
 | 0x8048436:   xchg   ax,ax
 | 0x8048438:   add    BYTE PTR [eax],al
 | 0x804843a:   add    BYTE PTR [eax],al
 |->   0x8048400:       push   DWORD PTR ds:0x804a004
       0x8048406:       jmp    DWORD PTR ds:0x804a008
       0x804840c:       add    BYTE PTR [eax],al
       0x804840e:       add    BYTE PTR [eax],al
                                                                  JUMP is taken
```
ds[0x804a008] 处即为用于解析 func 地址的 \_dl_runtime_resolve 函数。
```C
[-------------------------------------code-------------------------------------]
   0x80483fd:   add    BYTE PTR [eax],al
   0x80483ff:   add    bh,bh
   0x8048401:   xor    eax,0x804a004
=> 0x8048406:   jmp    DWORD PTR ds:0x804a008
 | 0x804840c:   add    BYTE PTR [eax],al
 | 0x804840e:   add    BYTE PTR [eax],al
 | 0x8048410 <__libc_start_main@plt>:   jmp    DWORD PTR ds:0x804a00c
 | 0x8048416 <__libc_start_main@plt+6>: push   0x0
 |->   0xf7fee000 <_dl_runtime_resolve>:        push   eax
       0xf7fee001 <_dl_runtime_resolve+1>:      push   ecx
       0xf7fee002 <_dl_runtime_resolve+2>:      push   edx
       0xf7fee003 <_dl_runtime_resolve+3>:      mov    edx,DWORD PTR [esp+0x10]
                                                                  JUMP is taken
```
\_dl_runtime_resolve 函数会将 func 函数的真实地址填充到 0x804a010（func@got）中，并返回到 func 函数中继续执行。
```C
[-------------------------------------code-------------------------------------]
   0xf7fd051c <__x86.get_pc_thunk.dx>:  mov    edx,DWORD PTR [esp]
   0xf7fd051f <__x86.get_pc_thunk.dx+3>:        ret    
   0xf7fd0520 <func>:   push   ebp
=> 0xf7fd0521 <func+1>: mov    ebp,esp
   0xf7fd0523 <func+3>: push   ebx
   0xf7fd0524 <func+4>: sub    esp,0x4
   0xf7fd0527 <func+7>: call   0xf7fd054b <__x86.get_pc_thunk.ax>
   0xf7fd052c <func+12>:        add    eax,0x1ad4

gdb-peda$ telescope 0x804a010
0000| 0x804a010 --> 0xf7fd0520 (<func>: push   ebp)
```
至此，使用延迟绑定的可执行文件中函数地址重定位已完成，当再次调用 func 函数时即可通过 jmp ds[0x804a010] 直接跳转到 func 函数中执行。
____
References:    
[1]《程序员的自我修养》      
[2] [通过 GDB 调试理解 GOT/PLT](http://rickgray.me/2015/08/07/use-gdb-to-study-got-and-plt/)   
[3] [手把手教你栈溢出从入门到放弃（下）](https://zhuanlan.zhihu.com/p/25892385)
