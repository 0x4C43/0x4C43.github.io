---
title: VMware 与 Credential Guard 不兼容
tags:
  - Credential Guard
categories: Problems&Solutions
keywords:
  - Credential Guard
translate_title: vmware-is-not-compatible-with-credential-guard
date: 2018-06-15 18:31:34
---

# 0x01 Problem
每次更新完 Windows10 后，使用 VMware Workstation 时都会出现以下错误：
>VMware Workstation 与 Device/Credential Guard 不兼容。在禁用 Device/Credential Guard 后，可以运行 VMware Workstation。

# 0x02 Solution
使用以下方法关闭 Windows10 系统的  Device/Credential Guard 功能可解决该问题。
## 1. 组策略设置
在组策略中关闭 Credential Guard。
- 使用按键 win+r 打开运行窗口，输入 gpedit.msc 并回车打开本地组策略编辑器；
- 本地计算机策略 > 计算机配置 > 管理模板 > 系统 > Device Guard > 打开基于虚拟化的安全；
-  选择禁用。

## 2. 关闭 Hyper-V
在控制面板中关闭 Hyper-V 功能。
- 控制面板 > 卸载程序 > 启用或关闭 Windows 功能；
- 去除 Hyper-V 前的勾；
- 选择不重启。

## 3. 关闭 Device Guard 
- 以管理员权限打开 cmd，运行以下命令：
```bash
mountvol X: /s
copy %WINDIR%\System32\SecConfig.efi X:\EFI\Microsoft\Boot\SecConfig.efi /Y
bcdedit /create {0cb3b571-2f2e-4343-a879-d86a476d7215} /d "DebugTool" /application osloader
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} path "\EFI\Microsoft\Boot\SecConfig.efi"
bcdedit /set {bootmgr} bootsequence {0cb3b571-2f2e-4343-a879-d86a476d7215}
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} loadoptions DISABLE-LSA-ISO,DISABLE-VBS
bcdedit /set {0cb3b571-2f2e-4343-a879-d86a476d7215} device partition=X:
mountvol X: /d
```
- 重启计算机，按照系统引导时的提示关闭 Device Guard/Credential Guard。
 
____
References:   
[1] [Powering on a vm in VMware Workstation on Windows 10 host where Credential Guard/Device Guard is enabled fails with BSOD ](https://kb.vmware.com/s/article/2146361)   
