---
title: 在斐讯 K2 上部署 Shadowsocks 与 Kcptun
tags:
  - 斐讯 K2
  - Shadowsocks
  - kcptun，IPv6 免流
categories: Others
keywords:
  - 斐讯 K2
  - Shadowsocks
  - Kcptun，IPv6 免流
translate_title: deploy-shadowsocks-and-kcptun-on-fiers-k2
date: 2017-08-26 14:34:57
---

对于程序员来说，能顺畅使用互联网能够很大程度地提高工作效率。所以，通过 SS 来实现代理上网是一个很好的解决方案。此外，对于能使用校园网的学生党而言，还可以使用 SS + IPv6 来实现免流，这样就能把省下来的网费用来买VPS了。

然而，在 PC 上直接使用客户端软件代理上网有以下缺点：    
1）不能实现全局流量的代理功能，只有支持代理功能的应用才能通过 SS 代理上网。虽然有相关的软件可以实现全局流量代理，但这样就很不方便，为了代理上网要多开好几个应用。    
2）如果手机等其他设备也想使用代理，也必须得用客户端才能行。

为了能方便地在多个终端使用代理，可以在路由器上部署 SS 客户端，那么经过这台路由器的所有流量都能走代理，对于终端设备上的所有应用而言，代理是透明的。

# 0x01 前提条件    
首先需要一台已部署好 Shadowsocks 和 Kcptun 的 VPS，服务器上安装 SS 和 Kcptun 相对要简单一些，可以在网络上能找到脚本实现一键安装。安装好之后在 PC 上安装相应的客户端软件，设置好参数并测试服务端能否正常使用。

下面是在斐讯 K2 上部署 SS 和 Kcptun 的过程。

# 0x02 设置 NAT6
为了使内网端口能获取到 IPv6 地址，需要进行以下配置。

首先更改网络/接口设置。WAN 设置 PPPoE 拨号，WAN6 设置为 DHCPv6 客户端，强制请求 IPv6 地址并禁用请求指定长度的 IPv6 前缀。
## 1. 安装软件包
```python
opkg update && opkg install kmod-ipt-nat6
opkg install iputils-tracepath6
```

## 2. 修改前缀
把 IPv6 ULA 前缀改成 d 开头。
```python
uci set network.globals.ula_prefix="$(uci get network.globals.ula_prefix | sed 's/^./d/')"
uci commit network
```
## 3. 添加 nat6 
```python
touch /etc/init.d/nat6
vi /etc/init.d/nat6

#!/bin/sh /etc/rc.common
# NAT6 init script for OpenWrt // Depends on package: kmod-ipt-nat6

START=55

# Options
# -------

# Use temporary addresses (IPv6 privacy extensions) for outgoing connections? Yes: 1 / No: 0
PRIVACY=1

# Maximum number of attempts before this script will stop in case no IPv6 route is available
# This limits the execution time of the IPv6 route lookup to (MAX_TRIES+1)*(MAX_TRIES/2) seconds. The default (15) equals 120 seconds.
MAX_TRIES=15

# An initial delay (in seconds) helps to avoid looking for the IPv6 network too early. Ideally, the first probe is successful.
# This would be the case if the time passed between the system log messages "Probing IPv6 route" and "Setting up NAT6" is 1 second.
DELAY=5

# Logical interface name of outbound IPv6 connection
# There should be no need to modify this, unless you changed the default network interface names
# Edit by Vincent: I never changed my default network interface names, but still I have to change the WAN6_NAME to "wan" instead of "wan6"
WAN6_NAME="wan6"

# ---------------------------------------------------
# Options end here - no need to change anything below

boot() {
        [ $DELAY -gt 0 ] && sleep $DELAY
        logger -t NAT6 "Probing IPv6 route"
        PROBE=0
        COUNT=1
        while [ $PROBE -eq 0 ]
        do
                if [ $COUNT -gt $MAX_TRIES ]
                then
                        logger -t NAT6 "Fatal error: No IPv6 route found (reached retry limit)" && exit 1
                fi
                sleep $COUNT
                COUNT=$((COUNT+1))
                PROBE=$(route -A inet6 | grep -c '::/0')
        done

        logger -t NAT6 "Setting up NAT6"

        WAN6_INTERFACE=$(uci get "network.$WAN6_NAME.ifname")
        if [ -z "$WAN6_INTERFACE" ] || [ ! -e "/sys/class/net/$WAN6_INTERFACE/" ] ; then
                logger -t NAT6 "Fatal error: Lookup of $WAN6_NAME interface failed. Were the default interface names changed?" && exit 1
        fi
        WAN6_GATEWAY=$(route -A inet6 -e | grep "$WAN6_INTERFACE" | awk '/::\/0/{print $2; exit}')
        if [ -z "$WAN6_GATEWAY" ] ; then
                logger -t NAT6 "Fatal error: No IPv6 gateway for $WAN6_INTERFACE found" && exit 1
        fi
        LAN_ULA_PREFIX=$(uci get network.globals.ula_prefix)
        if [ $(echo "$LAN_ULA_PREFIX" | grep -c -E "^([0-9a-fA-F]{4}):([0-9a-fA-F]{0,4}):") -ne 1 ] ; then
                logger -t NAT6 "Fatal error: IPv6 ULA prefix $LAN_ULA_PREFIX seems invalid. Please verify that a prefix is set and valid." && exit 1
        fi

        ip6tables -t nat -I POSTROUTING -s "$LAN_ULA_PREFIX" -o "$WAN6_INTERFACE" -j MASQUERADE
        if [ $? -eq 0 ] ; then
                logger -t NAT6 "Added IPv6 masquerading rule to the firewall (Src: $LAN_ULA_PREFIX - Dst: $WAN6_INTERFACE)"
        else
                logger -t NAT6 "Fatal error: Failed to add IPv6 masquerading rule to the firewall (Src: $LAN_ULA_PREFIX - Dst: $WAN6_INTERFACE)" && exit 1
        fi

        route -A inet6 add 2000::/3 gw "$WAN6_GATEWAY" dev "$WAN6_INTERFACE"
        if [ $? -eq 0 ] ; then
                logger -t NAT6 "Added $WAN6_GATEWAY to routing table as gateway on $WAN6_INTERFACE for outgoing connections"
        else
                logger -t NAT6 "Error: Failed to add $WAN6_GATEWAY to routing table as gateway on $WAN6_INTERFACE for outgoing connections"
        fi

        if [ $PRIVACY -eq 1 ] ; then
                echo 2 > "/proc/sys/net/ipv6/conf/$WAN6_INTERFACE/accept_ra"
                if [ $? -eq 0 ] ; then
                        logger -t NAT6 "Accepting router advertisements on $WAN6_INTERFACE even if forwarding is enabled (required for temporary addresses)"
                else
                        logger -t NAT6 "Error: Failed to change router advertisements accept policy on $WAN6_INTERFACE (required for temporary addresses)"
                fi
                echo 2 > "/proc/sys/net/ipv6/conf/$WAN6_INTERFACE/use_tempaddr"
                if [ $? -eq 0 ] ; then
                        logger -t NAT6 "Using temporary addresses for outgoing connections on interface $WAN6_INTERFACE"
                else
                        logger -t NAT6 "Error: Failed to enable temporary addresses for outgoing connections on interface $WAN6_INTERFACE"
                fi
        fi

        exit 0
}
```

## 4. 修改 sysctl.conf
```python
vim /etc/sysctl.conf
net.ipv6.conf.default.forwarding=2
net.ipv6.conf.all.forwarding=2
net.ipv6.conf.default.accept_ra=2
net.ipv6.conf.all.accept_ra=2
```
## 5. 修改 DHCP
更改 DHCP 服务器的设置。
```python
vim /etc/config/dhcp
config dhcp lan
        option interface 'lan'                   
        option start '100'                       
        option limit '150'     
        option leasetime '12h'
        option dhcpv6 'server'
        option ra 'server'    
        option ra_management '1'      
        option ra_default '1'
```
## 6. 配置防火墙规则
```python
uci set firewall.@rule["$(uci show firewall | grep 'Allow-ICMPv6-Forward' | cut -d'[' -f2 | cut -d']' -f1)"].enabled='0'
uci commit firewall
vim /etc/firewall.user
ip6tables -t nat -I POSTROUTING -s $(uci get network.globals.ula_prefix) -j MASQUERADE
```
## 7. 重启
重启路由器，查看连接在该路由器上的设备是否成功获得 IPv6 地址。
```
reboot
```

# 0x03 部署 SS    
## 1. 安装软件包    
透明代理使用 Shadowsocks-libev 和 ChinDNS（可不配置） 实现。使用 ssh 登陆路由器，安装相关软件包。
```python
opkg update
opkg install shadowsocks-libev luci-app-shadowsocks ChinaDNS luci-app-chinadns --force-checksum
```
## 2. 更新 chnroute 表    
使用以下命令更新：
```bash
wget -O- 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | awk -F\| '/CN\|ipv4/ { printf("%s/%d\n", $4, 32-log($5)/log(2)) }' > /etc/chnroute.txt
```
## 3. 配置SS    
首先根据 SS 服务器中已设参数配置好 SS 的全局设置，包括以下参数：
```python
服务器地址：2607:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx  # 校园网 IPV6 免流
服务器端口: 443
密码：xxxxxx
加密方式：aes-256-cfb
```

配置透明代理：
```python
端口：1081
忽略列表：/etc/chnroute.txt（如果使用全局代理则留空）
代理协议：TCP+UDP
```

配置UDP转发（ss-tunnel）：
```python
UDP本地端口：1153
UDP转发地址：8.8.8.8:53
```

配置 ChinaDNS：
```python
Enable Bidirectional Filter：启用
Enable DNS compression pointer：启用
本地端口：1053  //不能与ss-tunnel冲突
CHNRoute File：/etc/chnroute.txt
Upstream Servers：223.5.5.5,127.0.0.1:1153 //第一个是阿里DNS，第二个为 ss-tunnel 转发后的 Google DNS
```

配置DHCP/DNS：    
依次点击 `网络 -> DHCP/DNS -> 服务器设置` 进行设置。
```python
一般配置
DNS转发：127.0.0.1#1053

HOSTS和解析文件
忽略解析文件：启用
```
具体流程为， ss-tunnel 将 GoogleDNS(8.8.8.8:53) 转发到 127.0.0.1:1153 上，然后通过 ChinaDNS 与国内 DNS 组合成新的 127.0.0.1:1053，从而实现了国内外分流。

# 0x04 部署 Kcptun  
## 1.  安装客户端
Kcptun 部署需要确保服务端和客户端版本的一致性，只有版本一致才能正常使用。首先
在 [kcptun项目](https://github.com/xtaci/kcptun/releases) 中下载相应版本的客户端，这里下载 [kcptun-linux-mipsle-20170525.tar.gz](https://github.com/xtaci/kcptun/releases/download/v20170525/kcptun-linux-mipsle-20170525.tar.gz)，解压后将 client_linux_mipsle 上传至路由器中。
```python
scp client_linux_mipsle root@192.168.1.1:/root/kcptun/client_linux_mipsle
```
若提示以下内存不足错误将导致传输失败，可使用`mtd -r erase rootfs_data`命令清除设备中的所有数据以腾出内存空间，**_但这样做会导致配置信息丢失_**。
```python
No space left on device openwrt
```
传输完成后修改 /etc/rc.local 设置 kcptun 为开机启动。
```python
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

# IPv4
/root/kcptun/client_linux_mipsle -l 127.0.0.1:8388 -r xxx.xxx.xxx.xxx:9523 -key xxxxxx -mtu 1350 -sndwnd 512 -rcvwnd 512 -mode fast2 -crypt aes-192 -nocomp true > /root/kcptun/kcptun.log 2>&1 &

# or IPv6
/root/kcptun/client_linux_mipsle -l 127.0.0.1:8388 -r [xx:xx:xx:xx:xx:xx:xx:xx]:9523 -key xxxxxx -mtu 1350 -sndwnd 512 -rcvwnd 512 -mode fast2 -crypt aes-192 -nocomp true > /root/kcptun/kcptun.log 2>&1 &

exit 0
```
注释：    
/root/kcptun/client_linux_mipsle：client_linux_mipsle的绝对路径    
-l：kcptun 本地监听的端口    
-r：kcptun 服务器地址（可设置为 IPv6）和端口    
-key：kcptun的通讯密钥

修改 SS 客户端服务器 IP 和端口，密码等其他参数仍为原 SS 的参数：
````python
服务器地址：127.0.0.1
服务器端口: 8388
````
重启路由器后测试能否访问 Google。

## 2. 安装 kcptun web 管理界面
此外，还可以安装 [Kcptun 的 web 管理界面](https://github.com/kuoruan/luci-app-kcptun)。

## 3. 附录 -- 配置信息
以下为 K2 路由器中的配置信息。
```python
# ipv6
/root/kcptun/client_linux_mipsle -l 127.0.0.1:8388 -r [xxxx:xxxx:xxxx:xxxx:16d7:3cd1:xxxx:xxxx]:9523 -key xxxx -mtu 1350 -sndwnd 512 -rcvwnd 512 -mode fast2 -crypt aes-192 -nocomp true > /root/kcptun/kcptun.log 2>&1 &

# ipv4
/root/kcptun/client_linux_mipsle -l 127.0.0.1:8388 -r xxx.xxx.xxx.xxx:9523 -key xxxx -mtu 1350 -sndwnd 512 -rcvwnd 512 -mode fast2 -crypt aes-192 -nocomp true > /root/kcptun/kcptun.log 2>&1 &
```

服务端配置如下：
```bash
# cat /usr/local/kcptun/server-config.json
[root@localhost kcptun]
{
  "listen": ":9523",
  "target": "127.0.0.1:443",
  "key": "xxxx",
  "crypt": "aes-192",
  "mode": "fast2",
  "mtu": 1350,
  "sndwnd": 512,
  "rcvwnd": 512,
  "datashard": 10,
  "parityshard": 3,
  "dscp": 0,
  "nocomp": true,
  "pprof": false,
  "acknodelay": false,
  "sockbuf": 4194304,
  "keepalive": 10
}
```
客户端可用以下配置：
```bash
{
  "localaddr": ":443",
  "remoteaddr": "xxx.xxx.xxx.xxx:9523",
  "key": "xxxx",
  "crypt": "aes-192",
  "mode": "fast2",
  "mtu": 1350,
  "sndwnd": 512,
  "rcvwnd": 512,
  "datashard": 10,
  "parityshard": 3,
  "dscp": 0,
  "nocomp": true,
  "acknodelay": false,
  "sockbuf": 4194304,
  "keepalive": 10
}
```
Android 中 kcptun 配置如下：
```bash
key=xxxx;mtu=1350;sndwnd=512;rcvwnd=512;mode=fast2;crypt=aes-192;nocomp=true
```
____
References:   
[1] [在openwrt上部署kcptun给搬瓦工加速看1080p](http://www.right.com.cn/forum/thread-202060-1-1.html)   
[2] [Pandorabox之透明代理](https://keyin.me/2017/02/07/Pandorabox-transparent-proxy/)    
[3] [Kcptun加速方案](https://blog.kuoruan.com/102.html)    
[4] [如何用Kcptun给Shadowsocks加速？](http://www.bwgcn.xyz/?p=159)    
[5] [OpenWrt 平台 Kcptun 管理界面 lui-app-kcptun](https://blog.kuoruan.com/113.html)    
[6] [Openwrt华硕固件Kcptun配置使用教程](http://aes.jypc.org/?p=19339)    
[7] [Lede 17.01 shadowsocks设置](http://phyer.click/zh/2017/08/28/lede-shadowsocks/)    
[8] [Shadowsocks + ChnRoute 实现 OpenWRT / LEDE 路由器自动翻墙](https://cokebar.info/archives/664)    
[9] [OpenWrt 路由器安装 KCPTun 客户端](https://cyhour.com/479/)
