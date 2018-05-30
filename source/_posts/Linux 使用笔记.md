---
title: Linux 使用笔记
tags:
  - Linux
categories: Linux
keywords:
  - Linux 配置
  - 使用
translate_title: linux-usage-notes
date: 2017-10-28 21:45:08
---

# 0x01 基本命令
## 1. 使用终端模式登录
终端模式即命令行模式，Linux 系统默认提供6个终端（Teletype, tty1-tty6）；
```python
使用 Ctrl+Alt+F1 进入 tty1 、... 、Ctrl+Alt+F6 进入 tty6
使用 Ctrl+Alt+F7 回到桌面模式
```

## 2. 分页显示
终端模式下，输出的内容多于一屏时使用；
```python
cat file1 | less 或 less file1
cat file1 | more 或 more file1
```

## 3. 命令帮助
用于查看命令的使用说明；
```python
man ls
man -f reboot
man 2 reboot
```
输入”/string“，按回车，查找关键字 string，n 键向下查找，N 键向上查找；
![](http://ooyovxue7.bkt.clouddn.com/17-10-28/99556537.jpg)    
-f 用于查询命令说明存在于哪些 man 文档文件中；
查看 reboot 命令在 man 文档的第二章中的解释；

同样可用 info ls 查看命令说明文档。

## 4. 命令行快捷键
常用:
```bash
Ctrl L：清屏
Ctrl M：等效于回车
Ctrl C: 中断正在当前正在执行的程序
```
历史命令:
```bash
Ctrl P: 上一条命令，可以一直按表示一直往前翻
Ctrl N: 下一条命令
Ctrl R:再按历史命令中出现过的字符串：按字符串寻找历史命令（重度推荐）
```
命令行编辑:
```bash
Tab: 自动补齐
Ctrl A：移动光标到命令行首
Ctrl E: 移动光标到命令行尾
Ctrl B: 光标后退
Ctrl F: 光标前进
Alt F: 光标前进一个单词
Alt B: 光标后退一格单词
Ctrl H: 删除光标的前一个字符
Ctrl D: 删除当前光标所在字符
Alt D: 删除当前单词
Ctrl K：删除光标之后所有字符
Ctrl U: 清空当前键入的命令
Ctrl W: 删除光标前的单词(Word, 不包含空格的字符串)
Ctrl Y: 粘贴Ctrl W或Ctrl K删除的内容
Alt .: 粘贴上一条命令的最后一个参数（很有用）
Ctrl X Ctrl E: 调出系统默认编辑器编辑当前输入的命令，退出编辑器时，命令执行
```
其他:
```bash
Ctrl Z: 把当前进程放到后台（之后可用''fg''命令回到前台）
Ctrl PageUp: 屏幕输出向上翻页
Ctrl PageDown: 屏幕输出向下翻页
```

# 0x02 系统配置

## 1. 修改软件源
使用国内的 ubuntu 源速度会快很多。下面使用 ubuntu 16.04 的[科大源](https://mirrors.ustc.edu.cn/repogen/)，可以使用如下命令：
```
sudo sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
```
或者直接编辑 /etc/apt/sources.list 文件，在文件最前面添加以下条目：
```python
# 默认注释了源码镜像以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.ustc.edu.cn/ubuntu/ xenial main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial main main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-security main restricted universe multiverse
# 预发布软件源，不建议启用
# deb https://mirrors.ustc.edu.cn/ubuntu/ xenial-proposed main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ xenial-proposed main restricted universe multiverse
```

## 2. 添加 DNS 配置
直接修改 /etc/resolv.conf 重启会被覆盖，使用以下两种方法设置可避免该问题。    
**a）修改文件/etc/network/interfaces**
```python
# interfaces(5) file used by ifup(8) and ifdown(8)
# auto lo
# iface lo inet loopback

auto eth0    
iface eth0 inet static    
address 192.168.3.250    # IP    
netmask 255.255.255.0    # netmask    
gateway 192.168.3.1      # gateway    
dns-nameservers 8.8.8.8  # DNS
```
**b）修改文件 /etc/resolvconf/resolv.conf.d/base**
```python
nameserver 8.8.8.8
nameserver 223.5.5.5
```
## 3. 设置环境变量
**a）全局环境变量**    
全局环境变量，对所有用户都会生效。
- etc/profile: 此文件为系统的每个用户设置环境信息。当用户登录时，该文件被执行一次，并从 /etc/profile.d 目录的配置文件中搜集 shell 的设置。    
- /etc/bashrc: 当 bash shell 被打开时，该文件被读取。

**b）用户环境变量**
- ~/.bash_profile 或 ~/.profile: 只对单个用户生效，当用户登录时该文件执行一次。用户可使用该文件添加自己使用的 shell 变量信息。
- ~/.bashrc: 只对单个用户生效，当打开新的 shell 时，该文件被读取。

**c）系统环境变量**
 /etc/environment 设置的是整个系统的环境，而/etc/profile是设置所有用户的环境。
 使用 source /etc/environment 可以使变量设置在当前窗口立即生效

## 4. 设置代理
可在 /etc/environment 中添加以下环境变量。
```python
http_proxy="http://ip:port/"
https_proxy="https://ip:port/"
ftp_proxy="ftp://ip:port/"
socks_proxy="socks://ip:port/"
all_proxy="https://ip:port/"
```

# 0x03 工具

## 1）oh-my-zsh

## 2）tmux

## 3）ipython

____
References:   
[1] [Linux 命令行编辑快捷键](https://gist.github.com/zhulianhua/befb8f61db8c72b4763d)   
