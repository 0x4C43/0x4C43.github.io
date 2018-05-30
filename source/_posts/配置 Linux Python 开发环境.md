---
title: 配置 Linux Python 开发环境
tags:
  - Python
categories: Linux
keywords:
  - Python
  - PyCharm
  - virtualenv
translate_title: configure-the-linux-python-development-environment
date: 2018-03-16 19:55:21
---

环境：
```python
64bit Ubuntu 16.04.4 LTS (Xenial Xerus)
Python 2.7.12
```

# 0x01 安装
## 1. virtualenvwrapper
virtualenv 是一个可以在同一台计算机中隔离多个 Python 环境的工具。它能够用于创建独立的 Python 环境，使得多个 Python 环境互不影响。virtualenvwrapper 是 virtualenv 的扩展管理包，可以更方便地管理虚拟环境。

使用 pip 命令安装 virtualenvwrapper，默认安装在 /usr/local/bin 目录下。
```python
pip install virtualenvwrapper
```
配置环境变量 WORKON_HOME 指定虚拟环境管理目录，然后运行 virtualenvwrapper.sh 初始化配置。
```python
export WORKON_HOME=$HOME/Virtualenv
source /usr/local/bin/virtualenvwrapper.sh
```
为了避免每次使用前手动执行以上命令，可以将其写入 shell 配置文件 ~/.bashrc 或 ~/.zshrc 中。

**错误：**    
pip 安装依赖包出现以下错误：
```python
TypeError: unsupported operand type(s) for -=: 'Retry' and 'int'TypeError: unsupported operand type(s) for -=: 'Retry' and 'int'
```
出现该错误是因为使用的网络挂了代理，使用 pip 之前需要配置环境变量 http_proxy 到代理服务器的地址。可通过以下[两种方法解决](https://stackoverflow.com/a/39484683)。      
a）设置环境变量：
```python
export http_proxy="http://user:pass@my.site:port/"
```
b）使用 —proxy 选项：
```python
--proxy=[user:pass@]url:port
```
## 2. Pycharm
在[官网](https://www.jetbrains.com/pycharm/?fromMenu)下载软件包，然后解压到 /opt 目录下并安装。
```python
sudo tar xf pycharm-community-2017.3.4.tar.gz -C /opt/
cd /opt/PyCharm-community-2017.3.4/bin
./pycharm.sh
```
安装过程中可选择安装 IdeaVim 插件。

# 0x02 使用与配置

## 1. 创建虚拟环境
virtualenv 常用命令如下：   
>mkvirtualenv: Create a new virtualenv in $WORKON_HOME    
cdvirtualenv: change to the $VIRTUAL_ENV directory    
lsvirtualenv: list virtualenvs    
rmvirtualenv: Remove a virtualenv    
workon: list or change working virtualenvs    

在项目开发过程中需要安装不同的依赖库，为了使不同项目中使用的依赖库不会互相影响，可以为每个项目单独创建一个虚拟 python 运行环境。
```python
mkvirtualenv TestVirtualenv
```
可加上参数--no-site-packages，可以不复制已经安装到系统 Python 环境的所有第三方包，得到一个干净的 Python 运行环境。创建好后，进入该虚拟环境安装所需的依赖库。
```python
cdvirtualenv TestVirtualenv
pip install somepackages
```

## 2. Pycharm
Pycharm 已集成 virtualenv 功能，可以在新建项目时创建 virtualenv，也可以使用已有的 virtualenv。    
### 1） 创建新的 virtualenv
创建项目时新建一个 virtualenv。
```python
File -> New Project -> Project Interpreter -> New environment using Virtualenv

Location：指定 virtualenv 保存目录；
Base interpreter：选择接收器；
Inherit global site-packages：继承 Base interpreter 中安装的第三方库；
Make available to all projects：将此虚拟环境提供给其他项目使用。
```

### 2） 使用已有 virtualenv
创建项目时选择已有的 virtualenv 。
```python
File -> New Project -> Project Interpreter -> Existing Interpreter
-> Setting -> Add Local Python Interpreter
选择已有 virtualenv 所在目录中的解释器。
```
____
References:   
[1] [Pycharm Quick Start Guide](https://www.jetbrains.com/help/pycharm/quick-start-guide.html)   
