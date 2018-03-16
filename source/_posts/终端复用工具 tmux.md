---
title: 终端复用工具 tmux
date: 2017-10-28 22:57:21
tags: [tmux]
categories: Linux
keywords: [tmux]
---

### **0x01 简介**
tmux 是一款很好用的终端复用工具，主要有以下两个功能：    
>1）split 窗口。可以在一个 terminal 下打开多个终端，也可以对当前屏幕进行各种 split ，即可以同时打开多个显示范围更小的终端。    
2）在使用 SSH 的环境下，避免因网络不稳定而断开连接，导致工作现场的丢失。使用 tmux，重新连接以后，可以直接回到原来的工作环境，不但提高了工作 效率，还降低了风险，增加了安全性。

tmux主要包括以下几个模块：
>**session 会话：** 一个服务器可以包含多个会话；       
**window 窗口：** 一个会话可以包含多个窗口；    
**pane 面板：** 一个窗口可以包含多个面板。

以下为会话管理命令：
```
tmux [new -s 会话名 -n 窗口名]	# 启动新会话
tmux at [-t 会话名]		# 恢复会话
tmux ls				# 列出所有会话
tmux kill-session -t 会话名	# 关闭会话
```
### **0x02 安装与使用**
ubuntu 中使用以下命令安装 tmux。
```
sudo apt-get install tmux
```
#### **1）快捷键**
Pre 为前缀，默认为 Ctrl + b。

|  快捷键   |        功能        |      快捷键       |              功能              |
|:--------- |:------------------ | ----------------- | ------------------------------ |
| Pre Pgup  | 向上翻页           | Pre &             | 关闭当前窗口                   |
| Pre PgDn  | 向下翻页           | Pre Alt-[1-5]     | 切换面板的布局                 |
| Pre s     | 现有会话列表       | Pre Space         | 切换面板布局                   |
| Pre (     | 前一个会话         | Pre Ctl+o         | 顺序轮换面板                   |
| Pre )     | 后一个会话         | Pre Alt+o         | 逆序轮换面板                   |
| Pre c     | 新建窗口           | Pre {/}           | 上/下交换面板(swap-pane -U/-D) |
| Pre ,     | 改变窗口的名字     | Pre o             | 当前窗口中切换面板             |
| Pre $     | 改变会话的名字     | Pre l/r/u/d       | 切换当前面板                   |
| Pre c     | 创建新窗口         | Pre C-l/r/u/d     | 改变面板大小                   |
| Pre p     | 前一个窗口         | Pre L/R/U/D       | 改变面板大小                   |
| Pre n     | 后一个窗口         | Pre q             | 显示面板编号并选择             |
| Pre l     | 前后窗口间切换     | Pre x             | 关闭当前面板                   |
| Pre [0-9] | 选择窗口           | Pre %             | 纵向分隔窗口                   |
| Pre f     | 搜索窗口           | Pre “             | 横向分隔窗口                   |
| Pre w     | 列出所有窗口并选择 | Pre x             | 关闭面板                       |
| Pre .     | 移动窗口到新的编号 | Pre !             | 关闭所有小面板                 |
| Pre [     | 进入复制模式       | Pre b;Ctrl+方向键 | 调整面板大小                   |
| Pre ]     | 粘贴               | Pre z             | 最大化当前面板                 |

#### **2）修改配置**
在 home 目录下新建配置文件 .tmux.conf，设置以下参数使得操作更方便。
```python
#remap prefix from 'Ctr+b' to 'Ctr+a'
#unbind C-b
#set -g prefix C-a
#bind-key C-a send-prefix

#split panes using \and -
bind \ split-window -h
bind - split-window -v
unbind '"'
unbind %

#switch panes using Alt-arrow without prefix
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

#reload config file
bind r source-file ~/.tmux.conf

#set mouse on
set -g mouse on

#copy in vim mode
setw -g mode-keys vi

#reserve in current path in new window
bind c new-window -c "#{pane_current_path}"
```
可通过以下方式使配置文件生效：    
>a）新建一个 session，配置文件在新的 session 中生效。    
b）在当前 session 中，按 Pre + r 重新加载配置文件即可生效。


#### **3）复制粘贴**
**a）鼠标选中复制**    
在没有启动鼠标滚轮时，可以直接通过鼠标选中进行复制。如果启动滚轮，需要按下shift 键后使用鼠标选中要复制的内容。

**b）复制模式**    
tmux 支持两种快捷键模式：vim 和 Emacs，这里设置为 vim 快捷键模式，在上述配置文件中已添加 `setw -g mode-keys vi`，可用 j/k/h/l 移动光标。    
**复制：**    
>Pre + [ 进入复制模式；    
按下 Space 键开始复制；    
移动光标选中要复制的内容；    
按 Enter 键完成复制。

**粘贴**    
>光标移到到粘贴位置；    
按 Pre + ] 完成粘贴。


____
References:   
[1] [使用tmux](https://wiki.freebsdchina.org/software/t/tmux)   
