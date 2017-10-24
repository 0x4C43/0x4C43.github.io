---
title: Docker 使用笔记
date: 2017-10-05 16:20:23
tags: [Docker]
categories: Linux
keywords: [Docker]
---

Docker是一个开源项目，诞生于 2013 年初，最初是 dotCloud 公司内部的一个业务项目。它基于 Google 公司推出的 Go 语言实现。项目后来加入 Linux 基金会，遵从了 Apache 2.0 协议，项目代码在 GitHub 上进行维护。

Docker 项目的目标是实现轻量级的操作系统虚拟化解决方案，Docker 的基础是 Linux 容器 (LXC) 等技术。在 LCX 的基础上 Docker 进行了进一步的封装，让用户不需要关心容器的管理，使得操作更为简便，用户操作 Docker 的容器就像操作一个快速轻量级的虚拟机一样。

以下为 Docker 的基本功能使用记录。

### **0x01 安装 Docker**
#### **1）安装**
在测试或开发环境中 Docker 官方为了简化安装流程，提供了一套便捷的安装脚本，Ubuntu 系统上可以使用这套脚本安装：
```python
$ curl -fsSL get.docker.com -o get-docker.sh
$ sudo sh get-docker.sh --mirror Aliyun
```

#### **2）镜像加速器**
国内访问 Docker Hub 有时会遇到困难，此时可以配置镜像加速器。使用国内云服务商 DaoCloud 提供的加速器服务。
```python
curl -sSL https://get.daocloud.io/daotools/set_mirror.sh | sh -s http://xxx.m.daocloud.io
```
该脚本可以将 --registry-mirror 加入到 Docker 配置文件 /etc/docker/daemon.json 中。适用于 Ubuntu14.04、Debian、CentOS6 、CentOS7、Fedora、Arch Linux、openSUSE Leap 42.1，其他版本可能有细微不同。    

重新启动服务。
```python
sudo service docker restart
```
配置完加速器需要检查是否生效，如果 Docker 版本大于 1.13 或 17.05.0-ce，可以使用以下命令检查。
```python
lc@ubuntu:~$ sudo docker info|grep "Registry Mirrors" -A 1
Registry Mirrors:
 http://xxx.m.daocloud.io/
WARNING: No swap limit support
```

### **0x02 镜像**
对于 Linux 而言，内核启动后，会挂载 root 文件系统为其提供用户空间支持。而 Docker 镜像（Image），就相当于是一个 root 文件系统。比如官方镜像 ubuntu:14.04 就包含了完整的一套 Ubuntu 14.04 最小系统的 root 文件系统。

Docker 镜像是一个特殊的文件系统，除了提供容器运行时所需的程序、库、资源、配置等文件外，还包含了一些为运行时准备的一些配置参数（如匿名卷、环境变量、用户等）。镜像不包含任何动态数据，其内容在构建之后也不会被改变。
#### **1）获取镜像**
从 Docker Registry 获取镜像的命令是 docker pull。其命令格式为：
```python
docker pull [选项] [Docker Registry地址]<仓库名>:<标签>
```
Docker Registry地址：地址的格式一般是 <域名/IP>[:端口号]。默认地址是 Docker Hub。
仓库名：仓库名是两段式名称，即 <用户名>/<软件名>。对于 Docker Hub，如果不给出用户名，则默认为 library，也就是官方镜像。如：
```python
lc@ubuntu:~$ sudo docker pull ubuntu:14.04                                                                                                        
14.04: Pulling from library/ubuntu
bae382666908: Pull complete
29ede3c02ff2: Pull complete
da4e69f33106: Pull complete
8d43e5f5d27f: Pull complete
b0de1abb17d6: Pull complete
Digest: sha256:6e3e3f3c5c36a91ba17ea002f63e5607ed6a8c8e5fbbddb31ad3e15638b51ebc
Status: Downloaded newer image for ubuntu:14.04
```
上面的命令中没有给出 Docker Registry 地址，而镜像名称是 ubuntu:14.04，因此将会获取官方镜像 library/ubuntu 仓库中标签为 14.04 的镜像。

#### **2）运行容器**
使用`docker run` 根据镜像新建并运行容器。
```python
lc@ubuntu:~$ sudo docker run -it ubuntu:14.04 bash                                                                                                
root@fd93decf46b8:/# cat /etc/os-release
NAME="Ubuntu"
VERSION="14.04.5 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.5 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
root@fd93decf46b8:/#
```
>-it：这是两个参数，-i 是交互式操作，-t 为交互式终端。
ubuntu:14.04：指用 ubuntu:14.04 镜像为基础来启动容器。
bash：放在镜像名后的是命令，运行bash 返回交互式 Shell。

进入容器后，可以在 Shell 下操作，执行任何所需的命令。最后可以通过 exit 退出容器。

退出容器后可以使用 `docker exec` 命令进入容器。
```python
lc@ubuntu:~$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
fd93decf46b8        ubuntu:14.04        "bash"              3 hours ago         Up About an hour                        practical_raman
lc@ubuntu:~$ sudo docker exec -it fd93decf46b8 bash
root@fd93decf46b8:/#
```

#### **3）列出镜像**
使用`docker images` 命令可以列出已经下载的镜像。
```python
lc@ubuntu:~$ sudo docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              14.04               dea1945146b9        2 weeks ago         188MB
```
列表包含了仓库名、标签、镜像 ID、创建时间以及所占用的空间。

#### **4）保存镜像**
当修改容器的文件后，可以使用命令`docker diff`查看具体的改动。
```python
lc@ubuntu:~$ sudo docker diff fd93decf46b8
C /root
A /root/.bash_history
```
在不使用卷的情况下运行一个容器时，任何文件修改都会被记录于容器存储层里。而 Docker 提供的 `docker commit` 命令可以将容器的存储层保存下来成为镜像，语法格式为：
```
docker commit [选项] <容器ID或容器名> [<仓库名>[:<标签>]]
```
用下面的命令将容器保存为镜像：
```python
lc@ubuntu:~$ sudo docker commit --author "0x4C43" --message "modify" fd93decf46b8 ubuntu:v2
sha256:011e54908d10c0f77efdc7ff4fe2c7ec61ba9e0a43d5e862264a914e74c5b0b0
lc@ubuntu:~$ sudo docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              v2                  011e54908d10        12 seconds ago      188MB
ubuntu              14.04               dea1945146b9        2 weeks ago         188MB
```
其中 --author 指定修改的作者，而 --message 记录本次修改的内容。

使用 `docker commit` 意味着所有对镜像的操作都是黑箱操作，生成的镜像也被称为黑箱镜像。在实际应用中使用 Dockerfile 来定制镜像。

#### **5）删除镜像**
如果要删除本地的镜像，可以使用 `docker	rmi` 命令。
```python
lc@ubuntu:~$ sudo docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2d696327ab2e        2 weeks ago         122MB
ubuntu              14.04               dea1945146b9        2 weeks ago         188MB
lc@ubuntu:~$ sudo docker rmi dea19
Untagged: ubuntu:14.04
Untagged: ubuntu@sha256:6e3e3f3c5c36a91ba17ea002f63e5607ed6a8c8e5fbbddb31ad3e15638b51ebc
Deleted: sha256:dea1945146b96542e6e20642830c78df702d524a113605a906397db1db022703
Deleted: sha256:6401e3024b4d4ef4c981cde2e830858eb790ee84284e1401cf569a6db8df51d9
Deleted: sha256:f12ee38eb7aa0ffdd43c657b433d91ac4c2930887c02eb638fd1518f374bc738
Deleted: sha256:9ac64e2751425199591402799079940629829c7c2fc0e083fb714e5dd94d70a9
Deleted: sha256:12a6279e654d2f23c2fa086bf2dcd82e1a2c82b01028379bbf2cde061d9235e6
Deleted: sha256:c47d9b229ca4eaf5d3b85b6fa7f794d00910a42634dd0fd5107a9a937b13b20f
```

### **0x03 容器**
镜像（Image）和容器（Container）的关系，就像是面向对象程序设计中的类和实例一样，镜像是静态的定义，容器是镜像运行时的实体。容器可以被创建、启动、停止、删除、暂停等。

容器的实质是进程，但与直接在宿主执行的进程不同，容器进程运行于属于自己的独立的 命名空间。因此容器可以拥有自己的 root 文件系统、自己的网络配置、自己的进程空间，甚至自己的用户 ID 空间。容器内的进程是运行在一个隔离的环境里，使用起来，就好像是在一个独立于宿主的系统下操作一样。这种特性使得容器封装的应用比直接在宿主运行更加安全。
#### **1）启动容器**
启动容器有两种方式，一种是基于镜像新建一个容器并启动，另外一个是将在终止状态（stopped）的容器重新启动。

**a. 新建并启动**
如 0x02 中所示，使用 `docker run` 启动一个容器。利用这种方式来创建容器时，Docker 在后台运行的标准操作包括：

>检查本地是否存在指定的镜像，不存在就从公有仓库下载    
利用镜像创建并启动一个容器    
分配一个文件系统，并在只读的镜像层外面挂载一层可读写层    
从宿主主机配置的网桥接口中桥接一个虚拟接口到容器中去    
从地址池配置一个 ip 地址给容器    
执行用户指定的应用程序    
执行完毕后容器被终止    

**b. 启动已终止容器**
可以利用`docker start` 命令，直接将一个已经终止的容器启动运行。
```python
lc@ubuntu:~$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                      PORTS               NAMES
57002ad935b0        ubuntu:latest       "/bin/echo 'Hello ..."   9 minutes ago       Exited (0) 12 seconds ago                       silly_gates
f636101c203a        2d696327ab2e        "bash"                   19 hours ago        Up 19 hours                                     ecstatic_morse
lc@ubuntu:~$ sudo docker start -i 5700
Hello World!
```

**c. 守护态运行**
更多的时候，需要让 Docker在后台运行而不是直接把执行命令的结果输出在当前宿主机下。此时，可以通过添加 -d 参数来实现。
```python
lc@ubuntu:~$ sudo docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2d696327ab2e        2 weeks ago         122MB
lc@ubuntu:~$ sudo docker run -it -d 2d696 bash
931a04d6ac702a478b4c994b7f756eddd4801144be10bc9c760437fd6c9a962f
lc@ubuntu:~$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
931a04d6ac70        2d696               "bash"              10 seconds ago      Up 9 seconds                            agitated_kepler
```

#### **2）终止容器**
可以使用 `docker stop` 来终止一个运行中的容器。

此外，当Docker容器中指定的应用终结时，容器也自动终止。 例如对于只启动了一个终端的容器，用户通过 exit 命令或 Ctrl+d 来退出终端时，所创建的容器立刻终止。

终止状态的容器可以用 docker ps -a 命令看到。
```python
lc@ubuntu:~$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                      PORTS               NAMES
4c95f2701cbd        2d696               "bash"                   4 minutes ago       Exited (0) 44 seconds ago                       vigilant_beaver
57002ad935b0        ubuntu:latest       "/bin/echo 'Hello ..."   About an hour ago   Exited (0) 5 minutes ago                        silly_gates
f636101c203a        2d696327ab2e        "bash"                   20 hours ago        Exited (0) 8 minutes ago                        ecstatic_morse
```

#### **3） 进入容器**
当需要进入在后台运行的容器时，可以使用`docker attach`命令进行操作。
```python
lc@ubuntu:~$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
931a04d6ac70        2d696               "bash"              10 seconds ago      Up 9 seconds                            agitated_kepler
lc@ubuntu:~$ sudo docker attach 931a
root@931a04d6ac70:/#
```
#### **4） 导出和导入容器**
使用 `docker export` 命令可以导出容器快照到本地文件。
```python
lc@ubuntu:~$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
931a04d6ac70        2d696               "bash"              45 minutes ago      Up 10 seconds                           agitated_kepler
lc@ubuntu:~$ sudo docker export 931a > ubuntu.tar
```
使用`docker import`可以将本地快照文件导入为镜像。
```python
lc@ubuntu:~$ cat ubuntu.tar | sudo docker import - ubuntu:v1                                                                                      
sha256:22e45fa74eac9efd1f3024044ef2e018495ae67efc67b7600b29f8fec88e57b2
lc@ubuntu:~$ sudo docker images                                                                                                                   
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              v1                  22e45fa74eac        5 seconds ago       98.2MB
ubuntu              latest              2d696327ab2e        2 weeks ago         122MB
```

#### **5）删除容器**
使用 `docker rm` 可以删除处于终止状态的容器。如果要删除一个运行中的容器，可以添加 -f 参数。
```python
lc@ubuntu:~$ sudo docker ps -a                                                                                                                    
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                      PORTS               NAMES
5bc510e165b4        22e45               "bash"              43 seconds ago      Exited (0) 32 seconds ago                       priceless_jackson
931a04d6ac70        2d696               "bash"              About an hour ago   Exited (0) 7 minutes ago                        agitated_kepler
lc@ubuntu:~$ sudo docker rm 5bc51
5bc51
lc@ubuntu:~$ sudo docker ps -a   
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                     PORTS               NAMES
931a04d6ac70        2d696               "bash"              About an hour ago   Exited (0) 7 minutes ago                       agitated_kepler
```

### **0x04 数据管理**
在容器中管理数据主要有两种方式：数据卷（Data volumes）和数据卷容器（Data volume containers）。
#### **1）数据卷**
数据卷是一个可供一个或多个容器使用的特殊目录，有以下特性：
>数据卷可以在容器之间共享和重用    
对数据卷的修改会立马生效    
对数据卷的更新，不会影响镜像    
数据卷默认会一直存在，即使容器被删除

**a. 创建数据卷**
在用 `docker run` 命令时，使用 -v 选项可创建一个数据卷并挂载到容器里。下面创建一个名为 testVolume 的容器，并加载一个数据卷到容器的 /Volume 目录。
```python
lc@ubuntu:~$ sudo docker run -it --name testVolume -v /Volume 2d696 bash
root@a48cd127e2e9:/# ls
Volume  bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

此外，可以指定挂载一个本地主机的目录到容器中去。本地目录的路径必须是绝对路径，如果目录不存在 Docker 会自动为你创建它。下面将本地主机的 localVolume 目录挂载到容器的 /testVolume 目录。
```python
lc@ubuntu:~$ sudo docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              v1                  22e45fa74eac        5 hours ago         98.2MB
ubuntu              latest              2d696327ab2e        2 weeks ago         122MB
lc@ubuntu:~$ sudo docker run -it -v /home/lc/localVolume:/testVolume 2d69 bash

root@f3f239c230b7:/#
root@f3f239c230b7:/# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  testVolume  tmp  usr  var
root@f3f239c230b7:/# cat testVolume/test
Hello World!!!
```
Docker 挂载数据卷的默认权限是读写，用户也可以通过 :ro 指定为只读。
```python
lc@ubuntu:~$ sudo docker run -it -v /home/lc/localVolume:/testVolume:ro 2d69 bash
root@d478e93818b6:/# ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  testVolume  tmp  usr  var
root@d478e93818b6:/# ls -l testVolume/
total 0
-rw-rw-r-- 1 1000 1000 0 Oct  4 14:55 hello
root@d478e93818b6:/# rm /testVolume/hello
rm: cannot remove '/testVolume/hello': Read-only file system
```

**b. 删除数据卷**
 数据卷是被设计用来持久化数据的，它的生命周期独立于容器，Docker不会在容器被删除后自动删除数据卷，并且也不存在垃圾回收这样的机制来处理没有任何容器引用的数据卷。

在删除容器的时候使用 `docker rm -v` 命令可以在删除容器的同时移除数据卷。

```python
lc@ubuntu:~$ sudo find / -name Volume
/var/lib/docker/aufs/diff/d067854784e90619885211e81920c13cc34d2320adacec7826faef5bc6819d27/Volume
/var/lib/docker/aufs/mnt/d067854784e90619885211e81920c13cc34d2320adacec7826faef5bc6819d27/Volume

lc@ubuntu:~$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                         PORTS               NAMES
a48cd127e2e9        2d696               "bash"              About an hour ago   Exited (0) 12 seconds ago                          testVolume
931a04d6ac70        2d696               "bash"              6 hours ago         Exited (0) About an hour ago                       agitated_kepler
lc@ubuntu:~$ sudo docker rm -v a48cd
a48cd

lc@ubuntu:~$ sudo find / -name Volume
lc@ubuntu:~$
```

**c. 查看数据卷信息**
使用`docker inspect` 命令可以查看容器的详细信息，找到其中有关数据卷的项：
```python
"Mounts": [
    {
        "Type": "bind",
        "Source": "/home/lc/localVolume",
        "Destination": "/testVolume",
        "Mode": "ro",
        "RW": false,
        "Propagation": "rprivate"
    }
],
```

#### **2）数据卷容器**
如果一些持续更新的数据需要在容器之间共享，可以创建数据卷容器。数据卷容器是一个正常的容器，提供数据卷供其它容器挂载。

首先，创建一个名为 dbdata 的数据卷容器：
```python
lc@ubuntu:~$ sudo docker run -v /dbdata --name dbdata 2d696 echo Data-only container for 2d696                                                  
Data-only container for 2d696
lc@ubuntu:~$ sudo docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                      PORTS               NAMES
ce22bb5c5b4d        2d696               "echo Data-only co..."   12 seconds ago      Exited (0) 10 seconds ago                       dbdata
931a04d6ac70        2d696               "bash"                   7 hours ago         Exited (0) 2 hours ago                          agitated_kepler
```
然后，在其他容器中使用 --volumes-from 来挂载 dbdata 容器中的数据卷。
```python
lc@ubuntu:~$ sudo docker run -it --volumes-from dbdata --name db1 2d696 bash                                                                      
root@1a40cd12ae27:/# cd dbdata/       
root@1a40cd12ae27:/dbdata# ls
root@1a40cd12ae27:/dbdata#

lc@ubuntu:~$ sudo docker run -it --volumes-from dbdata --name db2 2d696 bash
root@5d7f11a015f0:/# ls
bin  boot  dbdata  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@5d7f11a015f0:/# cd dbdata/
root@5d7f11a015f0:/dbdata# ls
root@5d7f11a015f0:/dbdata# mkdir testvolume

root@1a40cd12ae27:/dbdata# ls
testvolume
```
### **0x05 网络配置**
通过 -P 或 -p 参数进行端口映射可以在外部访问容器中的网络应用。当使用 -P 标记时，Docker 会随机映射一个 49000~49900 的端口到内部容器开放的网络端口。

-p 则可以指定要映射的端口，在一个指定端口上只可以绑定一个容器。
#### **1）端口映射**
使用 `hostPort:containerPort` 将本地的 6666 端口映射到容器的 6666 端口。此时默认会绑定本地所有接口上的所有地址。
```python
lc@ubuntu:~$ sudo docker run -it -d  -p 6666:6666 2d696 bash
d6112543fa80c1c939f3ef0653efb7c5c29a5ccccc4dcae8fc81c764e743d1ff
lc@ubuntu:~$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS                    NAMES
d6112543fa80        2d696               "bash"              4 seconds ago       Up 3 seconds        0.0.0.0:6666->6666/tcp   objective_lumiere
```
#### **2）查看映射端口**
使用 `docker port` 可查看当前映射的端口配置，也可以查看绑定的地址。
```python
lc@ubuntu:~$ sudo docker port d611
6666/tcp -> 0.0.0.0:6666
```

____
References:   
[1] [Docker — 从入门到实践](https://yeasy.gitbooks.io/docker_practice/content/)       
[2] [Docker 入门 & CI/CD实践](https://blog.kinpzz.com/2017/05/16/docker-ci-cd/)       
