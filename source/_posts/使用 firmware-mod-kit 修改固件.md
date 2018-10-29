---
title: 使用 firmware-mod-kit 修改固件
tags:
  - firmware-mod-kit
  - firmware
categories: Embedded
keywords:
  - firmware-mod-kit
  - 修改 firmware
translate_title: modify-firmware-using-firmwaremodkit
date: 2017-06-05 21:45:08
---

firmware-mod-kit 工具包可用于提取固件中的文件系统，然后对其进行修改，并重新打包成固件。我们可以使用它对固件做定制化的修改，但是也有可能被恶意地用于在固件中添加后门等，所以在下载固件时应到官方网站下载，并检查固件是否被修改过。

该工具包支持以下固件：
>DD-WRT v23	tested - versions v23 SP1 and later are compatible (soon older versions too).    
DD-WRT v24	tested   
OpenWrt White Russian	tested   
OpenWrt Kamikaze	untested (should work) - not really necessary, based on OpenWrt has its Image Builder.   
FreeWrt	untested - should work ok   
HyperWrt	untested   
Ewrt	untested   
Sveasoft Alchemy	untested   
Sveasoft Talisman	untested   
Linksys / other vendor	not supported by scripts yet - haven't added cramfs handling   
ASUS WL-330G	untested - should work ok   
ASUS WL-520G	untested - should work ok   
ASUS WL-530G	supported   
ASUS WL-550G	untested  - should work ok   
Trendnet TEW-632BRP	tested   
DLink DIR-615	untested   
many others*	untested

# 0x01 安装
可在 [google code](https://code.google.com/archive/p/firmware-mod-kit/) 下载	Firmware Mod Kit v0.99 安装包，然后解压安装，安装前需要先安装相应的依赖库。
```
For Ubuntu: $ sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic

cd firmware-mod-kit/src
./configure && make
```

# 0x02 使用
firmware-mod-kit 中包含以下几个工具脚本：
>extract-firmware.sh：解包固件   
build-firmware.sh：重新打包固件   
check_for_upgrade.sh：检查更新   
unsquashfs_all.sh：解包提取出来的 squashfs 文件

![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/78163658.jpg)

## 1.  解包固件
使用以下命令解包固件，firmware.bin 为需解包的固件，working_directory 为解包结果存储位置。    
```
$ ./extract_firmware.sh firmware.bin working_directory/
```
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/6411506.jpg)
## 2. 重新打包固件
修改完解包后的文件系统后，使用 build_firmware.sh 重新打包固件，新生成的固件将存在 output_directory 目录下。
```
$ ./build_firmware.sh output_directory/ working_directory/
```
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/10177238.jpg)

# 0x03 Directory Tree Diff && Fuzzy Hashing
当我们发现下载的固件是被修改过时，可以使用 [binwally](https://github.com/bmaia/binwally) 将修改过的固件与[原版固件](https://downloads.openwrt.org/whiterussian/0.9/default/openwrt-wrtsl54gs-squashfs.bin)对比，从而发现具体修改内容。
## 1. 解包固件
可以看到固件编译日期为 2007-02-03，而文件系统的创建实际为 2017-06-05,说明固件中的文件系统被修改过。
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/63948070.jpg)
## 2. 差异对比
google 查找发现 openwrt-wrtsl54gs-squashfs.bin 固件有三个版本，分别为：
 >https://downloads.openwrt.org/whiterussian/0.9/default/openwrt-wrtsl54gs-squashfs.bin    
 https://downloads.openwrt.org/whiterussian/0.9/micro/openwrt-wrtsl54gs-squashfs.bin    
 https://downloads.openwrt.org/whiterussian/0.9/pptp/openwrt-wrtsl54gs-squashfs.bin

使用 binwally 对比结果显示"default" 版本的相似性最高，可知，目标固件是 "default" 版本固件的修改版。
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/59066778.jpg)    
继续查看具体修改的文件为 /etc/profile 和 /bin/nc。
![](https://hexo-1253637093.cos.ap-guangzhou.myqcloud.com/17-6-5/31504566.jpg)

-----------
References：    
[1] [firmware-mod-kit - Documentation.wiki](https://code.google.com/archive/p/firmware-mod-kit/wikis/Documentation.wiki)   
[2] [Firmware Modification Kit](https://bitsum.com/firmware_mod_kit.htm)   
[3] [路由器逆向分析------firmware-mod-kit工具安装和使用说明](http://blog.csdn.net/qq1084283172/article/details/68061957)   
[4] [Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](https://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)