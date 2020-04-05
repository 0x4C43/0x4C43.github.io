---
title: Linux 堆内存溢出 unlink 攻击
date: 2017-12-31 14:53:28
tags: [堆溢出,unlink]
categories: Exploit
keywords: [堆溢出,unlink]
---

在二进制漏洞利用中，缓冲区溢出漏洞是最常见的一类漏洞，这类漏洞具有很强的危害性，通常能被攻击者利用并实现任意代码执行。缓冲区溢出漏洞可分为基于栈的内存溢出和基于堆的内存溢出。本文主要介绍如何利用堆内存溢出进行 unlink 攻击，进而实现任意代码执行。

首先看以下漏洞程序：
```c
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]){
    char *first, *second;
    first = malloc(666);
    second = malloc(12);
    if (argc != 1)
        strcpy(first, argv[1]);
    free(first);
    free(second);
    return 0;
}
```
上述程序在分配完堆后，堆内存分布如下图所示。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020379_17968347.jpg)

程序中 strcpy 函数会导致堆溢出，argv[1] 大于 666 字节时，可覆盖第二个 chunk 的各个字段为指定的值，从而使堆管理器将第二个 chunk 判断为空闲状态。根据 malloc 的内存回收机制，在 free(first) 时会将上图中的 second chunk 从 bin 中 unlink，并与第一个 chunk 合并。通过修改 second chunk 的 fd、bk 字段，unlink 时可把 free 函数的 GOT 表项写为 shellcode 地址。当程序再次调用 free 函数时会执行 shellcode。     

下面具体介绍 unlink 机制和 unlink 攻击的原理。

# 0x01 释放堆与 unlink
释放堆时会判断当前 chunk 的相邻 chunk 是否为空闲状态，若是则会进行堆合并。合并时会将空闲 chunk 从 bin 中 unlink，并将合并后的 chunk 添加到 unsorted bin 中。堆合并分为向前合并和向后合并。

## 1. 向后合并
首先判断前一个 chunk 是否空闲，即检查当前 chunk 的 PREV_INUSE（P）位是否为 0。若为空闲，则将其合并。合并时，改变当前 chunk 指针指向前一个 chunk，使用 unlink 宏将前一个空闲 chunk 从 bin 中移除，最后更新合并后 chunk 的大小。

malloc.c 中向后合并的代码如下：
```c
INTERNAL_SIZE_T hd = p->size; /* its head field */
INTERNAL_SIZE_T sz;  /* its size */
INTERNAL_SIZE_T prevsz; /* size of previous contiguous chunk */

sz = hd & ~PREV_INUSE;
/* consolidate backward */
if (!(hd & PREV_INUSE))
{
  prevsz = p->prev_size;
  p = chunk_at_offset(p, -(long)prevsz);
  sz += prevsz;
  unlink(p, bck, fwd);
}
set_head(p, sz | PREV_INUSE);
```
本例中，释放 1st chunk 时，当前 chunk(1st chunk) 的前一个 chunk 是 allocated，所以不能向后合并，unlink 宏不会被调用。

## 2. 向前合并
首先判断下个 chunk 是否空闲，即检查下下个 chunk（相对当前 chunk）的 PREV_INUSE（P）位是否为 0，若为 0 表明下个 chunk 是空闲的，则进行合并。合并时使用 unlink 宏将下个 chunk 从它的 bin 中移除，并更新合并后的 chunk 大小。

malloc.c 中向前合并的代码如下：
```c
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)\
 (((mchunkptr)(((char*)(p)) + (s)))->size & PREV_INUSE)

INTERNAL_SIZE_T hd = p->size; /* its head field */
INTERNAL_SIZE_T sz;  /* its size */
sz = hd & ~PREV_INUSE;
next = chunk_at_offset(p, sz);
nextsz = chunksize(next);
/* consolidate forward */
if (!(inuse_bit_at_offset(next, nextsz)))   
{
  sz += nextsz;
  ...
  unlink(next, bck, fwd);
  next = chunk_at_offset(p, sz);
}

set_head(p, sz | PREV_INUSE);
next->prev_size = sz;
```
本例中，释放第一个 chunk 时，当前 chunk 的下一个 chunk（2nd chunk）是 allocated，所以不能向前合并，unlink 宏不会被调用。

## 3. unlink
当前释放的堆与前一个或后一个空闲 chunk 进行合并时，会把空闲 chunk 从 bin 中移除，移除过程使用 unlink 宏来实现。unlink 宏的定义如下：
```c
/* Take a chunk off a bin list */
#define unlink(P, BK, FD) {  \
  FD = P->fd;             \
  BK = P->bk;             \
  FD->bk = BK;            \
  BK->fd = FD;            \
}
```
unlink 即为将 P 从链表中删除的过程。

# 0x02 unlink 攻击
在 dlmalloc 中，unlink 的定义如上一节所示，只有与指针操作相关的 4 条语句。但在较新版本的 glibc 中，为了缓解攻击者进行 unlink 攻击，在宏定义中加入了安全校验，使得利用难度加大，只能在特定条件下使用一些技巧绕过校验。

## 1. 原始的 unlink 攻击
上述例子中，传入的字符串参数长度大于 666 字节时 strcpy 会使 first chunk 溢出，可覆盖 second chunk 的头部字段为如下值：
```c
prev_size = 偶数
size = -4
fd = free@got - 12
bk = shellcode address
```
在执行 free(first) 时，当前释放的 frist chunk 的下下个 chunk 不是 top chunk。因为 second chunk 的大小覆盖为 -4，所以下下个 chunk 在 second chunk 偏移为 -4 的位置，因此 malloc 把 second chunk 的 prev_size 当做下下个 chunk 的 size。而 prev_size 已被覆盖为偶数（PREV_INUSE位为0），malloc 会将 second chunk 当作空闲 chunk。

释放 first chunk 时会将 second chunk 从 bin 中 unlink，并将其合并到 first chunk。这个过程会触发 unlink（second），此时 `P = second chunk ptr`，unlink 过程如下：
```C
1）FD = second chunk ptr->fd = free@got – 12；
2）BK = second chunk ptr->bk = shellcode address；
3）FD->bk = BK，即 *((free@got–12)->bk) = shellcode address；
4）BK->fd = FD，即 *(shellcode address->fd) = free@got – 12。
```
unlink 步骤 1）和 2）将 second chunk 的 fd 和 bk 复制到 FD 和 BK。如下图所示，复制后 `FD = free@got-12`，`BK = shellcode address`，即 second chunk 的 fd、bk 指针分别指向 `free@got-12` 和 `shellcode address`。

步骤 3）中 FD 是 malloc_chunk 结构体指针，FD->bk 相当于 `FD+12 = free@got-12+12 = free@got`，即 FD->bk 指向 free 的 GOT 表项，FD->bk = BK 相当于 `free@got = shellcode address`，即 free 的 GOT 表项被修改为了 shellcode 地址。因此，程序在执行第二个 free 时就会执行 shellcode。

同理，步骤4）中将 `shellcode addr + 8` 处 4 个字节覆盖为 `free@got - 12`，所以在编写 shellcode 时应跳过这 4 个字节。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020400_81536873.jpg)

## 2. 绕过安全校验
首先，需要了解 glibc 中 unlink 的校验机制。以下为 glibc-2.19 中 unlink 宏的部分代码，在删除 P 节点之前会检查 `FD->bk != P || BK->fd != P` 是否成立，即检查当前 chunk 前一个 chunk 的 bk 与后一个 chunk 的 fd 是否指向当前 chunk。若当前 chunk 的 fd 和 bk 被修改则无法通过这项检查，`FD->bk = BK` 与 `BK->fd = FD` 不会执行，导致 unlink 攻击不能进行。
```c
/* Take a chunk off a bin list */
#define unlink(P, BK, FD) {         \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P);      \
    else {								          \
        FD->bk = BK;						    \
        BK->fd = FD;						    \
        ...
    }									              \
}
```
为了绕过以上指针校验，需要以下条件：
>a） 程序中存在一个全局指针变量 ptr    
b） ptr 指向的堆内存可由用户控制

若具备以上条件，攻击者可在指针 ptr 指向的内存中伪造一个空闲 chunk P，根据 ptr 构造合适的地址覆盖 chunk P 的 fd 和 bk，使得 `FD->bk == P && BK->fd == P` 成立。具体如下：
```c
P->fd = ptr - 0xC
P->bk = ptr - 0x8
```
在执行 unlink（P）时的指针操作如下：
```c
1）FD = P->fd = ptr - 0xC;
2）BK = P->bk = ptr - 0x8;
// FD->bk = ptr - 0xC + 0xC = ptr; BK->fd = ptr -0x8 + 0x8 = ptr
// 由于 ptr 指向 P,可成功绕过指针校验
3）FD->bk = BK，即 *ptr = ptr - 0x8;
4）BK->fd = FD，即 *ptr = ptr - 0xC。
```
由以上过程可知，借助指向 chunk P 的 ptr 指针可绕过 "corrupted double-linked list" 安全机制，并通过 unlink 攻击实现写内存，最终使得 ptr 指向 ptr - 0xc。

unlink 后，对 ptr 指向的内存进行写入，如 `‘A’*0xC + free@got`，使得 ptr 指向 free@got，再次对 ptr 指向的内存进行写入，可以把 free@got 修改为 system 的地址，之后调用 free 可任意命令执行。

## 3. 实例分析
通过调试网上找的一个例子来具体分析 unlink 利用及其安全机制的绕过，相关文件可在 [Github](https://github.com/0x4C43/Linux-Exploit/tree/master/heap_unlink) 中下载。    
程序功能为堆的 4 种基本操作：
```c
ssize_t menu()
{
  write(1, "1.Add chunk\n", 0xCu);
  write(1, "2.Set chunk\n", 0xCu);
  write(1, "3.Delete chunk\n", 0xFu);
  write(1, "4.Print chunk\n", 0xEu);
  return write(1, "5.Exit\n", 7u);
}
```

程序中有一个全局指针数组用于存储每一个 malloc 所分配堆块返回的指针。
```c
void *add()
{
  void *result; // eax
  int v1; // ebx
  size_t size; // [esp+Ch] [ebp-Ch]

  size = 0;
  if ( index > 9 )
    return (void *)write(1, "cannot add chunks!", 0x12u);
  write(1, "Input the size of chunk you want to add:", 0x28u);
  __isoc99_scanf("%d", &size);
  result = (void *)size;
  if ( (signed int)size > 0 )
  {
    v1 = index++;
    result = malloc(size);
    buf[v1] = result;  // 把堆块指针保存到 buf 中
  }
  return result;
}
// buf 为全局指针数组
.bss:08049D60 buf             dd ?                    ; DATA XREF: add+7A↑w
```

首先使用 `add`功能申请 4 个大小为 0x80 的堆（small chunk），程序会将 malloc 返回的用户空间指针 ptr_mem 存放在全局指针数组 buf[n] 中，该数组起始地址 buf 为 0x8049d60。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020392_74608133.jpg)       
申请好堆后，使用 `set` 功能把字符串 “/bin/sh” 写入到 chunk3 中，为后面执行 system 函数做准备。        
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020387_40338931.jpg)        
使用 `set` 功能编辑 chunk0 的内容可溢出并覆盖 chunk1，在 chunk0 中伪造一个大小为 0x80 的空闲 chunk P，将其 fd 和 bk 设置为 buf[0]-0xc 和 buf[0]-0x8，并且修改 chunk1 的 prev_size 和 size 字段。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020395_80701083.jpg)    
接着使用 `delete` 释放 chunk1，由于相邻的 chunk P 为空闲块，会触发 unlink(P) 把 chunk P 从 smallbins 中解除，并与 chunk1 合并为大小为 0x108 的空闲块。unlink 过程中可绕过 “指针破坏” 检测，并实现写内存。最终会把 buf[0] 修改为 buf[0]-0xC。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020373_14873045.jpg)    
使用 `set` 编辑 chunk0 可覆盖 buf[0]，从而再次修改 buf[0]，控制其指向的内存。可将其修改为 free@got。     
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020384_20886310.jpg)     
接着使用 `print` 输出 chunk0 的内容，可泄露出内存中 free 函数的地址，从而可计算得到 system 函数的地址。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020389_4598652.jpg)    
再次编辑 chunk0 的内容，把 system 的地址写入 free@got 中。写完后可查看 free@got 已指向 system 函数。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020381_20330158.jpg)    
当使用 `delete` 删除 chunk3 时执行的 free(chunk3) 实际上是 system(“\bin\sh”)，从而成功 getshell。    
![](https://raw.githubusercontent.com/0x4C43/BlogImages/master/1586020399_8077018.jpg)    

____
References:   
[1] [Linux堆溢出漏洞利用之unlink](https://jaq.alibaba.com/community/art/show?articleid=360)      
[2] [堆溢出的unlink利用方法](http://wooyun.jozxing.cc/static/drops/tips-7326.html)         
[3] [Heap Overflow Using Unlink & Double Free](http://pwn4.fun/2016/05/07/Heap-Overflow-Using-Unlink-Double-Free/)    
