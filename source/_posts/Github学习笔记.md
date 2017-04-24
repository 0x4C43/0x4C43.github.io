---
title: Git 学习笔记
date: 2017-04-19 18:14:14
tags: [Github,jiaochen]
categories: Github
commends: true
---
## 0x00 前言
Git是一款免费、开源的分布式版本控制系统，他是由Linux发明者Linus Torvalds开发的。GitHub主要提供基于git的版本托管服务，是全球最大的开源社区。Git只是GitHub上用来管理项目的一个工具。

### 0x01 基本用法
**初始化git仓库**
新建仓库目录文件夹，执行`git status`查看仓库状态可以看到当前目录不是一个Git仓库。通过`git init`初始化仓库。

**查看commit记录**
`git log`，按q键退出该命令。

**文件操作**
![](index_files/_u56FE_u89E3Git.png)
在工作目录、暂存目录(也叫做索引)和仓库之间复制文件使用如下命令。
* `git add _files_` ：把当前文件放入暂存区域。
* `git commit` ：给暂存区域生成快照并提交。
* `git reset _files_` ：撤销最后一次`git add _files_`，也可以用`git reset` 撤销所有暂存区域文件。
* `git checkout _files_` ：把文件从暂存区域复制到工作目录，用来丢弃本地修改。

**提交代码的两种方式**
1. clone GitHub上已有项目
`git clone git@github.com:0x4C43/test.git`
这种方法直接将远程仓库复制到本地，不需要使用`git init`初始化，并且已和远称仓库建立关联，只需在项目目录下修改和添加文件，然后commit，执行`git push origin master`提交代码。
2. 将本地项目关联远程项目
当本地有一个完整的仓库，且已进行多次commit，那么第一种方法不适用。使用命令`git remote add origin git@github.com:0x4C43/test.git`将本地项目与远程项目建立关联，之后就可以通过`git push origin master`提交代码。

**注：**
- push前通常先pull，这是因为远程仓库与本地仓库不一致时会产生冲突导致push失败。
- git2.9以后的版本执行`git pull origin master`时可能出现错误：`fatal: refusing to merge unrelated histories`，添加可选项`--allow-unrelated-histories`可解决此问题。
- 提交代码前需设置用户名和邮箱。
`git config --global user.name "username"`
`git config --global user.name "email"`

**分支**
1. 新建分支
通过`git branch branch_a`建立分支，团队成员可在各分支下互不干扰地完成各自负责的模块。

2. 重命名本地分支
`git branch -m branch_old branch_new`

3. 查看分支
查看本地分支：`git branch`
查看远程分支：`git branch -r`
查看本地与远程分支：`git branch -a`

4. 合并分支
首先checkout到主分支master上，接着使用`git merge branch_a`将a分支的代码合并到master中。

5. 删除分支
删除本地分支：`git branch -D branch_a`
删除远程分支：`git push origin --delete branch_a`

**删除错误commit**
1. `git reset --mixed <commit_id>`：默认方式，回退到某个版本，保留源码，回退commit和index信息。
2. `git reset --soft <commit_id>`：回退到某个版本，只回退commit信息，index信息和源码不恢复，可使用commit重新提交。
3. `git reset --hard <commit_id>`：彻底回退到某个版本，本地源码也变为原来版本。

**另：**
- 使用`git push origin HEAD --force`可更新远程commit记录，HEAD指向的版本为当前版本。
- 通过`git log`可查看提交日志，以便确定要回退版本的commit_id。
- 通过`git reflog`可查看命令日志，以便确定要回到未来版本的commit_id。














------------

References:
https://marklodato.github.io/visual-git-guide/index-zh-cn.html
https://zhuanlan.zhihu.com/stormzhang?topic=GitHub
http://www.liaoxuefeng.com/wiki/0013739516305929606dd18361248578c67b8067c8c017b000


