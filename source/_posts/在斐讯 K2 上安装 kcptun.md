---
title: 在斐讯 K2 上部署 Shadowsocks+Kcptun
date: 2017-08-26 14:34:57
tags: [斐讯 K2,Shadowsocks,kcptun，IPv6 免流]
categories: Others
keywords: [斐讯 K2,Shadowsocks,Kcptun，IPv6 免流]
---

对于程序员来说，能顺畅使用互联网能够很大程度地提高工作效率。所以，通过 SS 来实现代理上网是一个很好的解决方案。此外，对于能使用校园网的学生党而言，还可以使用 SS + IPv6 来实现免流，这样就能把省下来的网费用来买VPS了。

然而，在 PC 上直接使用客户端软件代理上网有以下缺点：    
1）不能实现全局流量的代理功能，只有支持代理功能的应用才能通过 SS 代理上网。虽然有相关的软件可以实现全局流量代理，但这样就很不方便，为了代理上网要多开好几个应用。    
2）如果手机等其他设备也想使用代理，也必须得用客户端才能行。

为了能方便地在多个终端使用代理，可以在路由器上部署 SS 客户端，那么经过这台路由器的所有流量都能走代理，对于终端设备上的所有应用而言，代理是透明的。

###**0x01 前提条件**    
首先需要一台已部署好 Shadowsocks 和 Kcptun 的 VPS，服务器上安装 SS 和 Kcptun 相对要简单一些，可以在网络上能找到脚本实现一键安装。安装好之后在 PC 上安装相应的客户端软件，设置好参数并测试服务端能否正常使用。

下面是在斐讯 K2 上部署 SS 和 Kcptun 的过程。

###**0x02 部署 SS**    
####**1）安装软件包**    
透明代理使用 Shadowsocks-libev 和 ChinDNS 实现。使用 ssh 登陆路由器，安装相关软件包。
```
opkg update
opkg install shadowsocks-libev luci-app-shadowsocks ChinaDNS luci-app-chinadns --force-checksum
```
####**2）更新 chnroute 表**    
使用以下命令更新：
```
wget -O- 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | awk -F\| '/CN\|ipv4/ { printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > /etc/chnroute.txt
```
####**3）配置SS**    
首先根据 SS 服务器中已设参数配置好 SS 的全局设置，包括以下参数：
```
服务器地址：2607:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx  # 校园网 IPV6 免流
服务器端口: 443
密码：xxxxxx
加密方式：aes-256-cfb
```

配置透明代理：
```
端口：1081
忽略列表：/etc/chnroute.txt（如果使用全局代理则留空）
代理协议：TCP+UDP
```

配置UDP转发（ss-tunnel）：
```
UDP本地端口：1153
UDP转发地址：8.8.8.8:53
```

配置 ChinaDNS：
```
Enable Bidirectional Filter：启用
Enable DNS compression pointer：启用
本地端口：1053  //不能与ss-tunnel冲突
CHNRoute File：/etc/chnroute.txt
Upstream Servers：223.5.5.5,127.0.0.1:1153 //第一个是阿里DNS，第二个为 ss-tunnel 转发后的 Google DNS
```

配置DHCP/DNS：    
依次点击 `网络 -> DHCP/DNS -> 服务器设置` 进行设置。
```
一般配置
DNS转发：127.0.0.1#1053

HOSTS和解析文件
忽略解析文：启用
```
具体流程为， ss-tunnel 将 GoogleDNS(8.8.8.8:53) 转发到 127.0.0.1:1153 上，然后通过 ChinaDNS 与国内 DNS 组合成新的 127.0.0.1:1053，从而实现了国内外分流。

###**0x03 部署 Kcptun**    
Kcptun 部署需要确保服务端和客户端版本的一致性，只有版本一致才能正常使用。首先
在 [kcptun项目](https://github.com/xtaci/kcptun/releases) 中下载相应版本的客户端，这里下载 [kcptun-linux-mipsle-20170525.tar.gz](https://github.com/xtaci/kcptun/releases/download/v20170525/kcptun-linux-mipsle-20170525.tar.gz)，解压后将 client_linux_mipsle 上传至路由器中。
```
scp client_linux_mipsle root@192.168.1.1:/root/kcptun
```
修改 /etc/rc.local 设置 kcptun 为开机启动。
```
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

/root/kcptun/client_linux_mipsle -l 127.0.0.1:8388 -r xxx.xxx.xxx.xxx:9523 -key xxxxxx -mtu 1350 -sndwnd 512 -rcvwnd 512 -mode fast2 -crypt aes-192  > /root/kcptun/kcptun.log 2>&1 &

exit 0
```
注释：    
/root/kcptun/client_linux_mipsle：client_linux_mipsle的绝对路径    
-l：kcptun 本地监听的端口    
-r：kcptun 服务器地址（可设置为 IPv6）和端口    
-key：kcptun的通讯密钥

修改 SS 客户端服务器 IP 和端口，密码等其他参数仍为原 SS 的参数：
````
服务器地址：127.0.0.1
服务器端口: 8388
````
重启路由器后测试能否访问 Google。此外，还可以安装 [Kcptun 的 web 管理界面](https://blog.kuoruan.com/113.html)。
____
References:   
[1] [在openwrt上部署kcptun给搬瓦工加速看1080p](http://www.right.com.cn/forum/thread-202060-1-1.html)   
[2] [Pandorabox之透明代理](https://keyin.me/2017/02/07/Pandorabox-transparent-proxy/)    
[3] [Kcptun加速方案](https://blog.kuoruan.com/102.html)    
[4] [如何用Kcptun给Shadowsocks加速？](http://www.bwgcn.xyz/?p=159)    
[5] [OpenWrt 平台 Kcptun 管理界面 lui-app-kcptun](https://blog.kuoruan.com/113.html)    
[6] [Openwrt华硕固件Kcptun配置使用教程](http://aes.jypc.org/?p=19339)
