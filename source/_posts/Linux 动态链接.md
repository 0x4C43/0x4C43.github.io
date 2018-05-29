---
title: Linux 动态链接
date: 2018-05-8 14:53:14
tags: [Memory Address, dynamic Linking]
categories: Linux
keywords: [Memory Address, dynamic Linking]
---

动态链接在程序运行时才对组成程序的目标文件进行链接，使用动态链接的方式可使得多个进程共用物理内存中的同一个共享目标文件，从而可节省内存空间。此外，使用动态链接使得各个模块更独立，并方便模块的更新。

为了验证多个进程是否可以共用物理内存中同一个共享对象文件中的代码段，需要将进程虚拟地址转换为对应的物理地址。

# 0x01 内存地址转换
Linux内核采用页式存储管理，进程的虚拟地址空间被划分成固定大小的页面（ Virtual Page, VP ），物理内存同样被分为与页面大小相同的物理页（Physical Page, PP）。页表是记录虚拟页与物理页映射关系的数据结构。CPU在获得虚拟地址之后，需要通过内存管理单元（Memory Management Unit，MMU）借助页表将虚拟地址映射为物理地址。

将虚拟地址转换为物理地址需要访问页表，然而只有内核态的程序才能访问到页表，用户态程序无权访问。此外，Linux 系统提供了一种用户态程序访问页表的方式，通过查看 `/proc/pid/pagemap` 文件可得到虚拟内存页映射与物理内存页的映射关系。显然后者更为简单，所以下面使用该方法实现地址转换。

Linux 系统上的 /proc/ 目录是一种虚拟文件系统，存储的是当前内核运行状态的一系列特殊文件，用户可以通过这些文件查看系统硬件及系统正在运行进程的信息，或者通过修改这些文件来改变内核的运行状态。

根据内核文档可知，每个虚拟页在 `/proc/pid/pagemap` 中对应一项长度为 64 bits 的数据，其中 Bit 63 为 page present，表示物理内存页是否已存在；若物理页已存在，则 Bits 0-54 表示物理页号。此外，需要 root 权限的进程才能读取 `/proc/pid/pagemap` 中的内容。
>pagemap is a new (as of 2.6.25) set of interfaces in the kernel that allow
userspace programs to examine the page tables and related information by
reading files in /proc.
>
>There are four components to pagemap:
>
> \*/proc/pid/pagemap.  This file lets a userspace process find out which
   physical frame each virtual page is mapped to.  It contains one 64-bit
   value for each virtual page, containing the following data (from
   fs/proc/task_mmu.c, above pagemap_read):    
>   \* <font color=red>Bits 0-54  page frame number (PFN) if present</font>  
>   \* Bits 0-4   swap type if swapped    
>   \* Bits 5-54  swap offset if swapped   
>   \* Bit  55    pte is soft-dirty (see Documentation/vm/soft-dirty.txt)    
>   \* Bit  56    page exclusively mapped (since 4.2)    
>   \* Bits 57-60 zero    
>   \* Bit  61    page is file-page or shared-anon (since 3.5)    
>   \* Bit  62    page swapped    
>   \* <font color=red>Bit  63    page present</font>  
>
>   Since Linux 4.0 only users with the CAP_SYS_ADMIN capability can get PFNs.
   In 4.0 and 4.1 opens by unprivileged fail with -EPERM.  <font color=red>Starting from
   4.2 the PFN field is zeroed if the user does not have CAP_SYS_ADMIN.</font>
   Reason: information about PFNs helps in exploiting Rowhammer vulnerability.

根据以上信息，利用 `/proc/pid/pagemap` 可将虚拟地址转换为物理地址，具体步骤如下：    
1）计算虚拟地址所在虚拟页对应的数据项在 `/proc/pid/pagmap` 中的偏移；    
`offset = (viraddr / pagesize) * sizeof(uint64_t)`    
2）读取长度为 64 bits 的数据项；    
3）根据 Bit 63 判断物理内存页是否存在；    
4）若物理内存页已存在，则取 bits 0 - 54 作为物理页号；    
5）计算出物理页起始地址加上页内偏移即得到物理地址；    
`phyaddr = pageframenum * pagesize + viraddr % pagesize;`

具体代码实现如下：
```C
#include <stdio.h>      
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

size_t virtual_to_physical(uint32_t pid, size_t viraddr)
{
    char path[30] = {0};
    sprintf(path , "/proc/%d/pagemap", pid);
    int fd = open(path, O_RDONLY);
    if(fd < 0) {
        printf("open '/proc/self/pagemap' failed!\n");
        return 0;
    }
    size_t pagesize = getpagesize();
    size_t offset = (viraddr / pagesize) * sizeof(uint64_t);
    if(lseek(fd, offset, SEEK_SET) < 0) {
        printf("lseek() failed!\n");
        close(fd);
        return 0 ;
    }
    uint64_t info;
    if(read(fd, &info, sizeof(uint64_t)) != sizeof(uint64_t)) {
        printf("read() failed!\n");
        close(fd);
        return 0;
    }
    if(info & (((uint64_t)1 << 63)) == 0) {
        printf("page is not present!\n");
        close(fd);
        return 0;
    }
    size_t pageframenum = info & (((uint64_t)1 << 55) -1);
    size_t phyaddr = pageframenum * pagesize + viraddr % pagesize;
    close(fd);
    return phyaddr;
}

int main()
{
    size_t phyaddr;
    size_t viraddr;
    uint32_t pid;

    printf("pid = ");
    scanf("%u", &pid);
    printf("virtual address = ");
    scanf("%x", &viraddr);
    phyaddr = virtual_to_physical(pid, viraddr);
    printf("virtual address = %p,physical address = %p\n", viraddr, phyaddr);
    return 0;
}
```

# 0x02 动态链接
动态链接在Linux中的实现称为动态共享对象（Dynamic Shared Objects），文件扩展名为 .so；Windows 中为动态链接库（Dynamical Linking Library），文件扩展名为 .dll。

程序与共享对象的链接过程在开始运行程序时由动态链接器完成，之后便开始执行程序。由于共享对象装载到进程空间时的地址不确定，无法在编译阶段进行重定位确定代码中的符号地址。可通过装载时重定位和地址无关代码解决该问题。

通过以下代码说明这两种情况：
```C
➜  dynamic_link cat Lib.c
#include <stdio.h>

void foobar(int i){
    printf("printing from Lib.so %d\n",i);
    sleep(-1);
}
➜  dynamic_link cat prog1.c
#include "Lib.h"

int main(){
    foobar(1);
    return 0;
}
```

## 1. 装载时重定位
在可执行程序装载时对地址引用进行符号重定位。由于这种方法需要修改指令中的地址，而同一个共享对象在不同进程中的加载地址不同，导致不同的进程必须在内存中有独立的对象模块，无法实现多个进程共用共享对象中的指令。

首先编译生成非地址无关的共享对象 Lib_noPIC.so 以及可执行程序 prog1_noPIC：
```python
gcc -m32 -shared Lib.c -o Lib_noPIC.so
gcc -m32 prog1.c -o prog1_noPIC ./Lib_noPIC.so
```
同时运行两个 prog1_noPIC 进程，并查看其进程虚拟内存空间分布如下，可以看到两个进程的虚拟地址空间分布是相同的。
```python
➜  dynamic_link pidof prog1_noPIC
18365 18364
➜  dynamic_link cat /proc/18365/maps
08048000-08049000 r-xp 00000000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
08049000-0804a000 r--p 00000000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
0804a000-0804b000 rw-p 00001000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
0804b000-0806c000 rw-p 00000000 00:00 0                                  [heap]
f7e00000-f7e01000 rw-p 00000000 00:00 0
f7e01000-f7fb1000 r-xp 00000000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb1000-f7fb3000 r--p 001af000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb3000-f7fb4000 rw-p 001b1000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb4000-f7fb7000 rw-p 00000000 00:00 0
f7fd0000-f7fd1000 r-xp 00000000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
f7fd1000-f7fd2000 r--p 00000000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
f7fd2000-f7fd3000 rw-p 00001000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
...
➜  dynamic_link cat /proc/18364/maps
08048000-08049000 r-xp 00000000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
08049000-0804a000 r--p 00000000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
0804a000-0804b000 rw-p 00001000 08:01 787009                             /home/lc/Load/dynamic_link/prog1_noPIC
0804b000-0806c000 rw-p 00000000 00:00 0                                  [heap]
f7e00000-f7e01000 rw-p 00000000 00:00 0
f7e01000-f7fb1000 r-xp 00000000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb1000-f7fb3000 r--p 001af000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb3000-f7fb4000 rw-p 001b1000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb4000-f7fb7000 rw-p 00000000 00:00 0
f7fd0000-f7fd1000 r-xp 00000000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
f7fd1000-f7fd2000 r--p 00000000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
f7fd2000-f7fd3000 rw-p 00001000 08:01 793527                             /home/lc/Load/dynamic_link/Lib_noPIC.so
...
```
根据 0xf7fd0000-0xf7fd1000 地址段内存的可执行权限可知该段为 Lib_noPIC.so 代码内存区域，下面通过查看代码段中的虚拟地址对应的物理地址是否相同，以验证不同进程是否共享物理内存中同一个 Lib_noPIC.so 的代码段。
```python
➜  dynamic_link pidof prog1_noPIC
18365 18364
➜  dynamic_link sudo ./virtual_to_physical
pid = 18365
virtual address = f7fd0005
virtual address = 0xf7fd0005,physical address = 0x6b7ea005
➜  dynamic_link sudo ./virtual_to_physical
pid = 18364
virtual address = f7fd0005
virtual address = 0xf7fd0005,physical address = 0x2e2cc005
```
从结果中可看到，不同进程中 0xf7fd0005 对应的物理内存分别为 0x6b7ea005 和 0x2e2cc005。由此说明非地址无关的共享对象中的代码段无法被不同进程共用。

## 2. 地址无关代码
地址无关代码 PIC（Position-Independent Code）把与地址相关的部分放入到数据段的全局偏移表 GOT（Global Offset Table）中，这样指令部分可保持不变，[重定位时只需修改 GOT](http://0x4c43.cn/Linux%20%E5%BB%B6%E8%BF%9F%E7%BB%91%E5%AE%9A%E6%9C%BA%E5%88%B6/)，而数据部分可在每个进程中拥有一个副本，从而实现共用共享对象的指令部分。

使用以下命令编译生成地址无关的共享对象 Lib_PIC.so 以及可执行程序 prog1_PIC：
```python
gcc -m32 -fPIC -shared Lib.c -o Lib_PIC.so
gcc -m32 prog1.c -o prog1_PIC ./Lib_PIC.so
```
同时运行两个 prog1_PIC 进程，查看其进程虚拟内存空间分布如下，可以看到两个进程的虚拟地址空间分布也是相同的。
```python
➜  dynamic_link pidof prog1_PIC  
19118 19113
➜  dynamic_link cat /proc/19118/maps
08048000-08049000 r-xp 00000000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
08049000-0804a000 r--p 00000000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
0804a000-0804b000 rw-p 00001000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
0804b000-0806c000 rw-p 00000000 00:00 0                                  [heap]
f7e00000-f7e01000 rw-p 00000000 00:00 0
f7e01000-f7fb1000 r-xp 00000000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb1000-f7fb3000 r--p 001af000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb3000-f7fb4000 rw-p 001b1000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb4000-f7fb7000 rw-p 00000000 00:00 0
f7fd0000-f7fd1000 r-xp 00000000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
f7fd1000-f7fd2000 r--p 00000000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
f7fd2000-f7fd3000 rw-p 00001000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
...
➜  dynamic_link cat /proc/19113/maps
08048000-08049000 r-xp 00000000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
08049000-0804a000 r--p 00000000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
0804a000-0804b000 rw-p 00001000 08:01 787010                             /home/lc/Load/dynamic_link/prog1_PIC
0804b000-0806c000 rw-p 00000000 00:00 0                                  [heap]
f7e00000-f7e01000 rw-p 00000000 00:00 0
f7e01000-f7fb1000 r-xp 00000000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb1000-f7fb3000 r--p 001af000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb3000-f7fb4000 rw-p 001b1000 08:01 935035                             /lib/i386-linux-gnu/libc-2.23.so
f7fb4000-f7fb7000 rw-p 00000000 00:00 0
f7fd0000-f7fd1000 r-xp 00000000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
f7fd1000-f7fd2000 r--p 00000000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
f7fd2000-f7fd3000 rw-p 00001000 08:01 793524                             /home/lc/Load/dynamic_link/Lib_PIC.so
```
查看不同进程中 Lib_PIC.so 代码内存区域中的虚拟地址 0xf7fd0005 对应的物理内存地址，结果显示都为 0x2464e005。表明地址无关共享对象中的代码段可供不同进程共同使用，从而可节省内存空间。
```python
➜  dynamic_link pidof prog1_PIC           
19118 19113
➜  dynamic_link sudo ./virtual_to_physical
pid = 19118
virtual address = f7fd0005
virtual address = 0xf7fd0005,physical address = 0x2464e005
➜  dynamic_link sudo ./virtual_to_physical
pid = 19113
virtual address = f7fd0005
virtual address = 0xf7fd0005,physical address = 0x2464e005
```
此外，共享对象的数据段在每个进程中都有独立的副本，以确保不同进程对数据的读写不影响其他进程。
```python
➜  dynamic_link sudo ./virtual_to_physical
pid = 19118
virtual address = f7fd1005
virtual address = 0xf7fd1005,physical address = 0x105b6005
➜  dynamic_link sudo ./virtual_to_physical
pid = 19113
virtual address = f7fd1005
virtual address = 0xf7fd1005,physical address = 0x6cd47005
```
____
References:   
[1] [Linux 获取虚拟地址对应的物理地址 ](https://zhoujianshi.github.io/articles/2017/Linux%20%E8%8E%B7%E5%8F%96%E8%99%9A%E6%8B%9F%E5%9C%B0%E5%9D%80%E5%AF%B9%E5%BA%94%E7%9A%84%E7%89%A9%E7%90%86%E5%9C%B0%E5%9D%80/index.html)     
[2] 《程序员的自我修养》
