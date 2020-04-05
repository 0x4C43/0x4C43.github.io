---
title: VMWare 中扩展 ubuntu 磁盘空间
date: 2018-07-07 14:00:23
tags: [磁盘空间]
categories: Pro&Sol
keywords: [磁盘空间]
---

由于在 VMWare 系统中使用 ubuntu 时安装的软件过多，导致磁盘空间不够用。因此，需要扩展虚拟机的磁盘空间，依照网上找到的方法可完成该过程，便记录在此。

# 0x01 VMWare 设置
将需要扩展空间的虚拟机关机，并且需删除该虚拟机的快照。之后点击 `虚拟机/设置/硬盘/扩展`，设置扩展后的容量，这里从 20G 扩展到 40G。

设置完后，开启虚拟机，发现扩展的空间仍无法使用。
```bash
sudo fdisk -l
Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbaa4ad2e

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1  *        2048 33554431 33552384  16G 83 Linux
/dev/sda2       33556478 41940991  8384514   4G  5 Extended
/dev/sda5       33556480 41940991  8384512   4G 82 Linux swap / Solaris
```

# 0x02 重新分区
为了能正常使用增加的磁盘容量，需把分区删除，然后再重新进行分区。首先关闭交换分区：
```bash
ubuntu# swapoff -a
ubuntu# free -m
              total        used        free      shared  buff/cache   available
Mem:           3921         634        2414          11         872        2925
Swap:             0           0           0
```
删除 /dev/sda1 和 /dev/sda2 分区。
```bash
ubuntu# fdisk /dev/sda

Welcome to fdisk (util-linux 2.27.1).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Command (m for help): p
Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbaa4ad2e

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1  *        2048 33554431 33552384  16G 83 Linux
/dev/sda2       33556478 41940991  8384514   4G  5 Extended
/dev/sda5       33556480 41940991  8384512   4G 82 Linux swap / Solaris

Command (m for help): d
Partition number (1,2,5, default 5): 1

Partition 1 has been deleted.

Command (m for help): d
Partition number (2,5, default 5): 2

Partition 2 has been deleted.

Command (m for help): p
Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbaa4ad2e
```
删除分区后，重新进行分区。
```bash
Command (m for help): n
Partition type
   p   primary (0 primary, 0 extended, 4 free)
   e   extended (container for logical partitions)
Select (default p): p
Partition number (1-4, default 1): 1
First sector (2048-83886079, default 2048): 
Last sector, +sectors or +size{K,M,G,T,P} (2048-83886079, default 83886079): 75501568

Created a new partition 1 of type 'Linux' and of size 36 GiB.
```
First sector 使用默认值，Last sector 的值设置为 75501568，根据上面 `free -m` 输出的信息计算：
```bash
75501568 = 83886080(total sectors) - 8384512(swap sectors)
```
可以看到已经新建了一个 36G 的 /dev/sda1 分区。接着继续分区：
```bash
Command (m for help): n
Partition type
   p   primary (1 primary, 0 extended, 3 free)
   e   extended (container for logical partitions)
Select (default p): p
Partition number (2-4, default 2): 2
First sector (75501569-83886079, default 75503616): 
Last sector, +sectors or +size{K,M,G,T,P} (75503616-83886079, default 83886079): 

Created a new partition 2 of type 'Linux' and of size 4 GiB.

Command (m for help): p
Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xbaa4ad2e

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1           2048 75501568 75499521  36G 83 Linux
/dev/sda2       75503616 83886079  8382464   4G 83 Linux
```
到此，新建的 2 个分区的大小已经设置好了，还需要设置 ID，将 /dev/sda2 设置为 Linux swap 。
```bash
Command (m for help): t
Partition number (1,2, default 2): 2
Partition type (type L to list all types): 82

Changed type of partition 'Linux' to 'Linux swap / Solaris'.
```
最后使用 w 保存。
```bash
Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Re-reading the partition table failed.: Device or resource busy

The kernel still uses the old table. The new table will be used at the next reboot or after you run partprobe(8) or kpartx(8).
```
重启虚拟机，并设置交换分区的 UUID。
```bash
ubuntu# awk '/swap/ { print $1}' /etc/fstab
#
UUID=a3e89d30-b6b8-4131-9c0c-0c686a7ae1f7

ubuntu# dd if=/dev/zero of=/dev/sda2 
dd: writing to '/dev/sda2': No space left on device
8382465+0 records in
8382464+0 records out
4291821568 bytes (4.3 GB, 4.0 GiB) copied, 159.644 s, 26.9 MB/s
ubuntu# mkswap -U a3e89d30-b6b8-4131-9c0c-0c686a7ae1f7 /dev/sda2
Setting up swapspace version 1, size = 4 GiB (4291817472 bytes)
no label, UUID=a3e89d30-b6b8-4131-9c0c-0c686a7ae1f7
ubuntu# swapon -a
ubuntu# free -m
              total        used        free      shared  buff/cache   available
Mem:           3921         635        2766          11         519        2952
Swap:          4092           0        4092

ubuntu# resize2fs /dev/sda1
resize2fs 1.42.13 (17-May-2015)
Filesystem at /dev/sda1 is mounted on /; on-line resizing required
old_desc_blocks = 1, new_desc_blocks = 3
The filesystem on /dev/sda1 is now 9437440 (4k) blocks long.

ubuntu# df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           393M  6.2M  387M   2% /run
/dev/sda1        36G   12G   23G  35% /
tmpfs           2.0G  216K  2.0G   1% /dev/shm
tmpfs           5.0M  4.0K  5.0M   1% /run/lock
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
tmpfs           393M   72K  393M   1% /run/user/1000
```
到此已经完成所有配置，可以看到 /dev/sda1 的容量已经调整到 36G。
____
References:   
[1] [VMware下ubuntu扩展磁盘空间](https://blog.csdn.net/openrd/article/details/51405884)   
