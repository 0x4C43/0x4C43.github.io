---
title: Linux 内存管理与堆
tags:
  - 内存管理
  - malloc
  - 堆
categories: Linux
keywords:
  - 内存管理
  - malloc
  - 堆
translate_title: linux-memory-management-and-heap
date: 2017-10-24 23:18:34
---

目前各大平台主要有如下几种堆内存管理机制：
```
dlmalloc – General purpose allocator
ptmalloc2 – glibc
jemalloc – FreeBSD and Firefox
tcmalloc – Google
libumem – Solaris
```
Linux 的早期版本使用的默认内存分配器为 dlmalloc，Wolfram Gloger 在 dlmalloc 基础上改进的 ptmalloc2 提供了多线程支持，所以 Linux 后来采用 ptmalloc2 作为默认内存分配器。多线程支持可以提升内存分配器的性能，进而提升了应用程序的性能。

在dlmalloc中，当多个线程同时调用malloc时，因为空闲列表被所有线程共享，所以只有一个线程能够访问临界区。因此，使用dlmalloc的多线程程序会在内存分配上耗费过多时间，导致整体性能下降。而在ptmalloc2中，每个线程都维护着一个独立的堆段，维护这些堆的空闲列表也是独立的。当有两个线程同时调用malloc时，均可立即分配到内存。

下面结合 unbuntu glibc 2.19 环境来学习内存的分配与回收。

# 0x01 内存管理数据结构
堆内存管理过程中有三个重要概念，分别是：arena、chunk、bin。
## 1. arena
程序在第一次使用 malloc 申请内存时，系统会分配一段连续的堆内存（132KB），这段内存被称为 arena。当程序申请再次申请内存时会先从 arena 的剩余部分申请，直到用完时再增加 arena 的大小。同理，当 arena中有过多空闲内存时也会缩小 arena 的大小。

为了使 dlmalloc 可以支持多线程，ptmalloc 增加了非主分配区（non main arena）支持。由主线程创建的 arena 称为主分配区（main arena），由其它线程创建的 arena 称为非主分配区（non main arena）。主分配区与非主分配区用环形链表进行管理。每一个分配区利用互斥锁（mutex）使线程对于该分配区的访问互斥。

每个进程只有一个主分配区，但可能存在多个非主分配区，ptmalloc 根据系统对分配区的争用情况动态增加非主分配区的数量，分配区的数量一旦增加，就不会再减少了。

主分配区可以使用 sbrk 和 mmap 向操作系统申请虚拟内存。非主分配区只能使用 mmap 向操作系统申请虚拟内存。

在程序线程较多的情况下，锁等待的时间就会延长，导致 malloc 性能下降。一次加锁操作需要消耗 100ns 左右，正是锁的缘故，导致 ptmalloc 在多线程竞争情况下性能远远落后于 tcmalloc。

arena的数量由系统的核数量决定：
>32位系统：    
arena 的数量 = 2 * 核的数量    
64位系统：    
arena 的数量 = 8 * 核的数量

一个多线程（主线程+3个用户线程）应用在一个单核的32位系统上运行，线程数 > 2*核数，因此  malloc 需要确保 arena 能被线程共享。

>a) 主线程第一次调用 malloc 时创建 main arena；    
b) thread1 和thread2 第一次调用 malloc 时，分别为它们创建 thread arena；    
c) thread3 第一次调用 malloc 时 arena 已达上限，所以只能重用已存在的 arena（main arena、arena1 或 arena2. ；    
重用 arena 过程：    
遍历所有 arena，当找到可用的 arena 时，尝试 lock arena。如果 lock 成功，将 arena 返回给用户；如果没有空闲的 arena，阻塞排队等待 arena。

## 2. chunk
逻辑上划分的一小块内存，根据作用不同分为4类：Allocated chunk、Free chunk、Top chunk、Last Remainder chunk。
chunk 结构的定义如下：
```C
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
chunk 结构中各字段的含义如下：
**prev_size：** 如果前一个 chunk 是空闲状态，则该字段保存前一个 chunk 的大小。如果前一个 chunk 被分配使用，那么该字段保存前一个 chunk 的用户数据。
**size：** 该字段为整个 chunk 的大小，包括保存用户数据的部分和 malloc_chunk 结构大小，并且包含进行内存对齐时填充字节的大小。由于内存按8字节对齐，所以该字段的低3位不用于表示 size，用于表示以下状态信息：
```
bit0 — PREV_INUSE (P)：前一个 chunk 被分配使用时为1；
bit1 — IS_MMAPPED (M)：当此 chunk 是由 mmap() 创建则为1；
bit2 — NON_MAIN_ARENA (N)：如果此 chunk 属于 non main arena 则为1。
```

```C
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1
/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)

/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2
/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)

/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4
/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)
```
**fd：** 在空闲 chunk 中指向相同 bin 里的后一个 chunk，在已分配的 chunk 中用于保存用户数据。    
**bk：** 在空闲 chunk 中指向相同 bin 里的前一个 chunk，在已分配的 chunk 中用于保存用户数据。

**a）Allocated chunk**    
Allocated chunk 结构图如下：
```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |N|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_space() bytes)                     .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk                                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
chunk 指针指向一个 chunk 的开始，mem 指针为真正返回给用户的内存指针。

malloc chunk 的空间复用机制使得 Allocated chunk 会占用下一个 chunk 的 prev_size，这样能提高内存空间利用率。例如，用户使用 malloc(42) 申请 42 字节内存，那么最终分配的 allocated chunk 的 size 为 48。
```
len = 42(用户请求) + 8(prev_size/size) - 4(复用next chunk prev_size) = 46
size = Align(len, 8) = 48
```

**b）Free chunk**    
Free chunk 结构图如下：
```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**c）Top chunk**    
堆内存是从低地址向高地址进行分配的，在堆内存的最高处，必然存在着一块空闲 chunk，叫做 top  chunk。当 bins 和 fast bins 中的 chunk 都不能满足分配需要的时候，malloc 会在 top chunk 中分出一块内存给用户。

不论 top chunk 有多大，它都不会被放到 fast  bins 或者是 bins 中。top  chunk 的大小是随着分配和回收不停变换的，如果从 top  chunk 分配内存会导致 top  chunk 减小，同时 top chunk 的指针增大；如果回收的 chunk 恰好与 top chunk 相邻，那么回收的 chunk 就会合并到 top chunk 中，从而使 top chunk 变大，top chunk 的指针减小。

```
            +---------------------+   <--first chunk ptr
            |     prev_size       |
            +---------------------+
            |        size         |          
            +---------------------+   <--first mem                  
            |                     |
            |     allocated       |         
            |      chunk          |      
            +---------------------+   <--second chunk ptr                
            |      prev_size      |         
            +---------------------+                     
            |        size         |         
            +---------------------+   <--second mem              
            |     Allocated       |         
            |       chunk         |     
            +---------------------+   <-- top                  
            |     prev_size       |            
            +---------------------+                     
            |    size=0x205d1     |           
            +---------------------+                      
            |                     |
            |        TOP          |   
            |       CHUNK         |    
            |                     |
            +---------------------+
```
例如，先申请两个大小为 89 的 chunk，然后释放第二个 chunk。释放后的 chunk 将会与 top chunk 合并，使得 top chunk 增大，同时 chunk 指针减小。    
![](http://ooyovxue7.bkt.clouddn.com/17-10-24/1257914.jpg)

**d） Last Remainder chunk**    
Last remainder 与 top chunk 一样，不会在任何 bins 中找到这种 chunk。当需要分配一个 small chunk，但在 small bins 中找不到合适的 chunk 时，如果 last remainder chunk 大于所需的 small chunk，last remainder chunk 被分成两个 chunk，其中一个 chunk 返回给用户，另一个 chunk 变成新的 last remainder chuk。

## 3. Bin
用户 free 掉的内存并不会马上归还给系统，malloc 会统一管理 heap 和 mmap 映射区域中的空闲 chunk，当用户进行下一次分配请求时，malloc 会首先试图在空闲 chunk 中挑选一块给用户，这样就避免了频繁的系统调用，降低了内存分配的开销。

用于保存 free chunk 链表表头信息的指针数组称为 bin，按所悬挂链表的类型可以分为4类：Fast bin、Unsorted bin、Small bin、Large bin。保存 bin 的数据结构为 fastbinsY 和 bins 两个数组：fastbinsY 数组保存 fast bin，bins 数组保存 unsorted、small 和 large bin，总共有 126 个 bin：Bin 1 为 Unsorted bin、Bin 2 to Bin 63 为 Small bin、Bin 64 to Bin 126 为 Large bin。
![](http://ooyovxue7.bkt.clouddn.com/17-10-24/55042966.jpg)

**Fast Bin**    
fast chunk 的大小为16~64 bytes 的 chunk，保存 fast chunk 的 bin 被称为 fast bin，fast bin 在内存中分配和回收的速度最快。

小于64 bytes 的 chunk 被释放后，会被放到 fast bins 中。fast  bins 中的 chunk 并不改变它的使用标志 P，所以就无法进行合并。当需要分配的 chunk 小于或等于64 bytes 时，malloc 首先会在 fast  bins 中查找相应的空闲块，若没有找到合适的 chunk 再去查找 bins 中的空闲 chunk。fast bin 具有以下特点：
>a) bin 的数量：总共10 个，每个 fast bin 包含一个 free chunk 的单向链表，单项链表的增加和删除都在链表头（LIFO）。    
b) Chunk size：不同 bin 中 chunk 大小以8字节递增，同一个 fast bin 的 chunk大小相同。例如，第一个 fast bin 的 chunk为16字节；第二个 fast bin 的 chunk 为24字节，以此类推。在 malloc 初始化阶段，fast bin 最大64字节，因此默认 16~64 字节的 chunk是 fast chunk。    
c) 不合并：两个相邻的 free chunk 不会合并，虽然会产生更多碎片，但是 free 的速度提高了。

例如，申请3个大小为 0x30（size 为 0x41. 的 chunk，然后将 2-1-3 的顺序将其释放，结果如下：
```
pwndbg> heap                                                                                                                              [5/1809]
Top Chunk: 0x804c078
Last Remainder: 0

0x804c000 FASTBIN {
  prev_size = 0,
  size = 41,
  fd = 0x804c028,
  ...
}
0x804c028 FASTBIN {
  prev_size = 0,
  size = 41,
  fd = 0x0,
  ...
}
0x804c050 FASTBIN {
  prev_size = 0,
  size = 41,
  fd = 0x804c000,
  ...
}
0x804c078 PREV_INUSE {
  prev_size = 0,
  size = 135049,
  fd = 0x0,
  ...
}

pwndbg> fastbins
fastbins
0x10: 0x0
0x18: 0x0
0x20: 0x0
0x28: 0x804c050 —▸ 0x804c000 —▸ 0x804c028 ◂— 0x0
0x30: 0x0
0x38: 0x0
0x40: 0x0
```
从以上结果可看出，释放时将 chunk 添加到链表的表头，释放后的 fast chunk 的 P 标识位仍为 1，从而避免了空闲堆块的合并。

**Unsorted Bin**    
当 small 或 large chunk 释放后，不会立即把它们加到对应的 bin，而是加到 unsorted bin 中。这样能使 malloc 重用最近释放的 chunk，减少查找合适 bin 的时间，使内存的分配和回收速度得到提高。

在进行 malloc 操作时，如果在 fast bins 中没有找到合适的 chunk，malloc 会先在 unsorted bin 中查找合适的空闲 chunk，然后才查找 bins。如果 unsorted bin 不能满足分配要求，malloc 便会将 unsorted bin 中的 chunk 加入对应的 bins 中。因此，unsorted bin 可以看做是 bins 的一个缓冲区，它能加快内存分配的速度。Unsorted Bin 的特点如下：
>a）bin 的数量：只有1个。    
b）循环双向链表：unsorted bin 包含一个 free chunk 的循环双向链表。链表的增加在表头位置，找到合适大小的 chunk 即可删除。    
c）Chunk size：没有大小限制。

**Small Bin**    
small chunk 小于512字节，保存 small chunk 的 bin 称为 small bin。small bin 的分配与回收比 large bin 快，但比 fast bin 慢。它有以下特点：
>a）bin 的数量：总共有62个 small bin。    
b）循环双向链表：small bin 包含free chunk 的循环双向链表，双向链表的增加在表头，删除在末尾（FIFO）。    
c）Chunk Size：不同 bin 中 chunk 大小以8字节递增。同一个 small bin 里的 chunk 大小相同。例如，第一个 small bin（Bin 2. chunk 的大小为16字节；第二个 smallbin（Bin 3. chunk 的大小为24字节，以此类推。    
d）合并：两个相邻的 free chunk 会合并。合并可减少碎片，但会使 free 速度减慢。

**Large Bin**    
large chunk 的大小大于或等于 512，保存 large chunk 的 bin 称为 large bin。它有以下特点：
>a）bin 的数量：总共有63个 large bin。    
b）循环双向链表：large bin 包含一个 free chunk 的循环双向链表，chunk 的增加和删除可以在链表的任何位置。    
c）合并：两个相邻的 free chunk 会合并。

当空闲的 chunk 被链接到 bin 中时，malloc 会把表示该 chunk 是否处于使用中的标志 P 设为 0（该标志在下一个 chunk 的 size中），同时 malloc 还会检查它前后的 chunk 是否也是空闲的，如果是的话，malloc 会首先把它们合并为一个大的 chunk，然后将合并后的 chunk 放到 unstored bin 中。

# 0x02 内存分配
## malloc
当使用 malloc 申请内存时，malloc 的具体过程如下：

1. 获取一个未加锁的分配区，如果所有分配区都加了锁，ptmalloc 会开辟一个新的分配区。开辟新分配区时，会调用 mmap 创建一个 sub-heap，并设置好 top chunk。    
2. 将用户的请求大小转换为实际需要分配的 chunk 空间大小。       
3. 判断所需分配 chunk 的大小是否在 fast chunk 中。若是，则转下一步，否则跳到第 5 步。    
4）首先尝试在 fast bins 中取一个所需大小的 chunk 分配给用户。如果可以找到，则分配结束，否则转到下一步。    
5）判断所需大小是否处在 small  bins 中，若是，则转下一步，否则转到第 7 步。    
6）根据所需分配的 chunk 的大小，找到对应的 small bin，从该 bin 的尾部摘取一个恰好满足大小的 chunk。若成功，则分配结束，否则，转到下一步。    
7）首先将 fast bins 中的 chunk 合并，并且放入 unsorted bin 中。如果需要分配的 chunk 属于 small bins，unsorted bin 中只有一个 chunk，并且该 chunk 的大小大于等于需要分配的大小。此时将该 chunk 进行切割，分配结束。否则，将 unsorted bin 中的 chunk 放入 small bins 或者 large bins。进入下一步。    
8）从 large bins 中按照 “smallest-first，best-fit” 原则找一个合适的 chunk，从中划分一块所需大小的 chunk，并将剩下的部分链接回到 bins 中。若操作成功，则分配结束，否则转到下一步。    
9）判断 top chunk 大小能否满足所需 chunk 的大小，如果能，则从 top chunk 中分配内存。否则转到下一步。    
10）判断所需分配的 chunk 大小是否大于等于 mmap 分配阈值，如果是，则转下一步，调用 mmap 分配，否则跳到第 12 步。    
11. 使用 mmap 系统调用为程序的内存空间映射一块 chunk_size align 4kB 大小的空间。    
12. 如果是主分配区，调用 sbrk()，增加 top chunk 大小；如果是非主分配区，调用 mmap 来分配一个新的 sub-heap，增加 top chunk 大小。    

## 总结    
**1. 小内存**    
 [获取分配区(arena)并加锁] -> fast bins -> small bins -> 合并 fast bins 加入unsorted bins -> unsorted bins -> large bins -> 增大 top chunk（低于 mmap 阈值） -> mmap（高于 mmap 阈值）。

**2. 大内存**    
直接 mmap。

# 0x03 内存回收
## free
释放堆内存时根据 chunk 所处的位置和该 chunk 的大小采取不同的方法。free() 函数的具体步骤如下：    
1. 首先需要获取分配区的锁，保证线程安全。    
2. 判断传入的指针是否为 0，如果为 0，则直接 return。否则转下一步。    
3. 判断所需释放的 chunk 是否为 mmaped chunk，如果是，则调用 munmap() 释放，解除内存空间映射，该该空间不再有效。    
4）判断 chunk 的大小和所处的位置，若为 fast chunk，则转到下一步，否则跳到第 6 步。    
5）将 chunk 放到 fast bins 中，并且不修改该 chunk 使用状态位 P，也不与相邻的 chunk 进行合并。释放结束。    
6）判断前一个 chunk 的使用状态，如果是空闲块，则合并。并转下一步。    
7）判断当前释放 chunk 的下一个块是否为 top chunk，如果是，则转第 9 步，否则转下一步。    
8）判断下一个 chunk 的使用状态，如果是空闲块，则合并，并将合并后的 chunk 放到 unsorted bin 中。并转到第 10 步。    
9）释放的 chunk 与 top chunk 相邻，将它与 top chunk 合并，并更新 top chunk 的大小等信息。转下一步。    
10）判断合并后的 chunk 的大小是否大于 FASTBIN_CONSOLIDATION_THRESHOLD（默认64KB），如果是，则会触发 fast bins 的合并操作，fast bins 中的 chunk 将被遍历，并与相邻的空闲 chunk 进行合并，合并后的 chunk 会被放到 unsorted bin 中。操作完成后转下一步。    
11. 判断 top chunk 的大小是否大于 mmap 收缩阈值（默认为 128KB），如果是，对于主分配区，则会归还 top chunk 中的一部分给操作系统。但是会保留最先分配的 128KB 的空间，用于响应用户的分配请求；如果为非主分配区，会进行 sub-heap 收缩，将 top chunk 的一部分返回给操作系统，如果 top chunk 为整个 sub-heap，会把整个 sub-heap 还回给操作系统。释放结束，从 free() 函数退出。    

## 总结    
**1. 大内存**    
直接 munmap。

**2. 小内存**    
fast chunk：放入 fast bin -> top chunk 相邻：与 top chunk 合并 -> small chunk、large chunk：与前后的 free chunk 合并后放到 unsorted bin中 -> 如果合并后的 chunk 大于 64KB 则触发合并 fast bin 操作，合并fast bin放到 unsorted 中 -> top chunk 大小达到 mmap 收缩阈值，则将部分 top chunk 的内存归还给系统。
____
References:   
[1] glibc内存管理ptmalloc源代码分析     
[2] [深入理解glibc malloc](http://pwn4.fun/2016/04/11/%E6%B7%B1%E5%85%A5%E7%90%86%E8%A7%A3glibc-malloc/)    
[3] [glibc内存分配与回收过程图解](http://blog.csdn.net/maokelong95/article/details/52006379)    
[4] [Understanding glibc malloc](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/comment-page-1/?spm=a313e.7916648.0.0.123608f8erhuwJ)
