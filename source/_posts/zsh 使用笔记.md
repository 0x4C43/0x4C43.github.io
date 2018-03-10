---
title: zsh 使用笔记
date: 2018-03-10 22:20:17
tags: [zsh, oh-my-zsh]
categories: Linux
keywords: [zsh, oh-my-zsh]
---

Zsh 是一款功能强大终端（shell）软件，既可以作为交互式终端，也可以作为脚本解释器。它在兼容 Bash 的同时，还有提供了很多改进，例如：
>更高效    
更好的自动补全    
更好的文件名展开（通配符展开）    
可定制性高    

### **0x01 安装**

#### **1）安装 zsh**
首先安装 zsh，并设置 zsh 为系统默认 bash。
```python
sudo apt-get install Zsh
chsh -s $(which zsh)
```
注销（Log out）并重新进入系统，此时 shell 默认为 zsh。

#### **2）安装 oh-my-zsh**
由于 zsh 配置过于复杂，所以安装 oh-my-zsh 可简化 zsh 的配置。oh-my-zsh 有 200 多各插件和 140 多种主题。
```python
$ sudo sh -c "$(wget https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
```

### **0x02 配置**

#### **1）配置主题**
修改 ~/.zshrc 中的 ZSH_THEME 参数可配置不同样式的主题。
```python
ZSH_THEME="agnoster"
```
修改后发现主题中存在乱码，这是缺少 Powerline 字体导致的，所以需安装 Powerline 字体。
```python
git clone https://github.com/powerline/fonts  
cd fonts
./install.sh
```
安装完后设置终端字体，ubuntu 中通过以下方式设置。
```python
Edit -> Profile Preferences -> General -> Text Appearance -> Custom font
-> Ubuntu Mono derivative Powerline Regular
```
#### **2）隐藏用户名**
默认情况下，命令提示符前有固定的 “username@hostname” ，可在 .zshrc 中添加以下环境变量隐藏该信息。
```python
export DEFAULT_USER= "username "   # username 需替换为系统默认用户名
```

### **0x03 插件**
#### **1）帮助文档高亮**
colored-man-pages 插件可使 man 帮助文档高亮显示，该插件在 oh-my-zsh 中自带，只需在 .zshrc 中启用即可。
```python
plugins=(
  colored-man-pages
  ...
)
```
#### **2）历史记录补全**
zsh-autosuggestions 插件可根据历史记录自动补全命令，输入命令时会以暗色补全，按方向键右键完成输入。首先下载至 zsh 的 plugins 目录下，然后在 .zshrc 中启用。
```python
$ git clone https://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
```
#### **3）命令高亮**
zsh-syntax-highlighting 插件可使输入的命令根据主题自动高亮。输入正确的命令是黄色，输入错误的命令是红色。
```python
$ git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
```
#### **4）历史命令搜索**
history-substring-search 插件可进行历史命令搜索，如果和 zsh-syntax-highlighting 插件共用，要配置到语法高亮插件之后。
```python
git clone https://github.com/zsh-users/zsh-history-substring-search.git $ZSH_CUSTOM/plugins/history-substring-search
```
输入部分命令后，使用上下键查询可匹配的历史命令。

### **0x04 使用**
#### **1）命令补全**
按两下 tab 键可以触发 zsh 的补全，所有待补全项都可以通过键盘方向键或者 <Ctrl-n/p/f/b> 来选择。
#### **2）命令选项补全**
支持命令选项的补全。例如 ls -<TAB><TAB> 会直接列出所有 ls 的参数。
#### **3）命令参数补全**
支持命令参数的补全。例如 kill 进程名<TAB>，zsh 就会自动补全进程的 pid。
#### **4）快速目录切换**
zsh 会记住每一次切换的路径，然后通过 1 来切换到上一次访问的路径，2 切换到上上次，一直到 9，还可以通过 d 查看目录访问历史。




____
References:   
[1] [oh-my-zsh](https://github.com/robbyrussell/oh-my-zsh/wiki)   
